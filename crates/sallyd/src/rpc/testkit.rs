//! Test doubles shared by the socket servers' unit tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, Mutex};

use sally_core::audit::{AuditError, NewEntry};
use sally_core::manifest::AuditLevel;
use serde_json::Value;

use sally_proto::Stream;

use super::record::Recorder;
use crate::sandbox::AuditSink;
use crate::tools::ops::DISCONNECT;
use crate::tools::shell::{AttachIo, Chunk, Ran, Status, Streamer};

/// One recorded entry.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    pub event: String,
    pub decision: Option<String>,
    pub args: Value,
    /// The entry's `Debug` text (it names the session and the detail level).
    pub debug: String,
}

/// Records every entry; `fail` refuses every append.
#[derive(Default)]
pub struct Sink {
    rows: Mutex<Vec<Row>>,
    pub fail: std::sync::atomic::AtomicBool,
    /// Appends still to refuse before appends succeed again.
    pub fail_next: std::sync::atomic::AtomicUsize,
    /// When non-zero: every append fails once this many rows are recorded.
    pub fail_from: std::sync::atomic::AtomicUsize,
    /// While set, appends wait (an audit write that takes a while).
    held: Mutex<bool>,
    unheld: std::sync::Condvar,
}

impl AuditSink for Sink {
    fn append(&self, e: NewEntry, _: AuditLevel) -> Result<(), AuditError> {
        use std::sync::atomic::Ordering::SeqCst;
        let once = self
            .fail_next
            .try_update(SeqCst, SeqCst, |n| n.checked_sub(1))
            .is_ok();
        let mut held = self.held.lock().unwrap();
        while *held {
            held = self.unheld.wait(held).unwrap();
        }
        drop(held);
        let from = self.fail_from.load(SeqCst);
        let full = from > 0 && self.rows.lock().unwrap().len() >= from;
        if once || full || self.fail.load(SeqCst) {
            return Err(AuditError::InvalidEntry("fake failure"));
        }
        self.rows.lock().unwrap().push(Row {
            event: e.event().to_owned(),
            decision: e.decision_value().map(str::to_owned),
            args: e.arguments().clone(),
            debug: format!("{e:?}"),
        });
        Ok(())
    }
}

impl Sink {
    pub fn rows(&self) -> Vec<Row> {
        self.rows.lock().unwrap().clone()
    }

    pub fn events(&self) -> Vec<String> {
        self.rows().into_iter().map(|r| r.event).collect()
    }

    /// The arguments of the last entry named `event`.
    pub fn last(&self, event: &str) -> Value {
        let rows = self.rows();
        rows.iter()
            .rev()
            .find(|r| r.event == event)
            .map_or(Value::Null, |r| r.args.clone())
    }

    /// Makes appends wait (`true`) or lets them through (`false`).
    pub fn hold(&self, on: bool) {
        *self.held.lock().unwrap() = on;
        self.unheld.notify_all();
    }

    pub fn set_failing(&self, fail: bool) {
        self.fail.store(fail, std::sync::atomic::Ordering::SeqCst);
    }

    /// Holds appends until the guard is dropped, also when the test panics: a write blocked in
    /// the sink never outlives the test, whose runtime would wait for it.
    pub fn held(self: &Arc<Self>) -> Held {
        self.hold(true);
        Held(Arc::clone(self))
    }
}

/// See [`Sink::held`].
pub struct Held(Arc<Sink>);

impl Drop for Held {
    fn drop(&mut self) {
        self.0.hold(false);
    }
}

/// What the fake attached command does.
#[derive(Clone, Copy, Debug)]
pub enum Mode {
    /// Prints `hi\n` and exits with this code.
    Exit(i32),
    /// Echoes its input to stdout until the input ends, then exits 0.
    Echo,
    /// Never reads its input; runs until its connection is gone (`killed: disconnect`) or it
    /// is released (exits 0).
    Deaf,
    /// Prints `n` lines of 1 KiB, then exits 0.
    Lines(usize),
    /// Prints 1 KiB lines until its connection is gone (`killed: disconnect`); a full queue
    /// never delays that, as with the real runner.
    Flood,
    /// Takes one input and exits 0 at once, while its output and that input are still held
    /// for a moment (as by a reader or stdin writer not yet ended): `late\n` follows the exit
    /// and the input is never written.
    Late,
    /// `podman exec` could not be run.
    Fail,
}

/// A stand-in for the attached command's runner (`tools::exec::PodmanExec`).
pub struct FakeExec {
    pub mode: Mode,
    /// Each command's argv and directory.
    pub seen: Mutex<Vec<(Vec<String>, String)>>,
    /// Ends a [`Mode::Deaf`] command.
    pub release: tokio::sync::Notify,
}

impl FakeExec {
    pub fn new(mode: Mode) -> Arc<Self> {
        Arc::new(Self {
            mode,
            seen: Mutex::default(),
            release: tokio::sync::Notify::new(),
        })
    }
}

impl Streamer for Arc<FakeExec> {
    async fn attach(&self, argv: &[String], cwd: &str, mut io: AttachIo) -> Ran {
        self.seen
            .lock()
            .unwrap()
            .push((argv.to_vec(), cwd.to_owned()));
        let ran = |status, stdin, stdout| Ran {
            status,
            stdin,
            stdout,
            stderr: 0,
        };
        let say = |text: String| Chunk {
            stream: Stream::Stdout,
            text,
        };
        match self.mode {
            Mode::Exit(code) => {
                let _ = io.output.send(say("hi\n".into())).await;
                ran(Status::Exited(code), 0, 3)
            }
            Mode::Echo => {
                let mut n = 0u64;
                while let Some(i) = io.input.recv().await {
                    n += i.data.len() as u64;
                    let _ = io
                        .output
                        .send(say(String::from_utf8(i.data).unwrap()))
                        .await;
                    let _ = i.done.send(true);
                    if i.eof {
                        break;
                    }
                }
                ran(Status::Exited(0), n, n)
            }
            Mode::Deaf => {
                let gone = tokio::select! {
                    r = io.disconnect.wait_for(|g| *g) => {
                        drop(r);
                        true
                    }
                    () = self.release.notified() => false,
                };
                if !gone {
                    return ran(Status::Exited(0), 0, 0);
                }
                // A kill takes a moment, so a caller that does not wait for the result sees
                // it late.
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                ran(Status::Killed(DISCONNECT), 0, 0)
            }
            Mode::Lines(n) => {
                for i in 0..n {
                    let line = format!("{i:04}{}\n", "x".repeat(1019));
                    if io.output.send(say(line)).await.is_err() {
                        break;
                    }
                }
                ran(Status::Exited(0), 0, (n * 1024) as u64)
            }
            Mode::Flood => {
                let mut sent = 0u64;
                loop {
                    let line = say(format!("{}\n", "y".repeat(1023)));
                    tokio::select! {
                        biased;
                        _ = io.disconnect.wait_for(|g| *g) => {
                            return ran(Status::Killed(DISCONNECT), 0, sent);
                        }
                        r = io.output.send(line) => {
                            if r.is_err() {
                                return ran(Status::Exited(0), 0, sent);
                            }
                            sent += 1024;
                        }
                    }
                }
            }
            Mode::Late => {
                let input = io.input.recv().await;
                let output = io.output;
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
                    let _ = output.send(say("late\n".into())).await;
                    drop(input);
                });
                ran(Status::Exited(0), 0, 0)
            }
            Mode::Fail => ran(Status::Failed("podman exec: gone".into()), 0, 0),
        }
    }
}

/// A sink and a recorder for `session` writing into it.
pub fn recorder(session: &str) -> (Arc<Sink>, Recorder) {
    let sink = Arc::new(Sink::default());
    let r = Recorder::new(
        Arc::clone(&sink) as Arc<dyn AuditSink>,
        session.to_owned(),
        AuditLevel::Full,
    );
    (sink, r)
}
