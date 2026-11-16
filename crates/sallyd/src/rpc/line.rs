//! One session's line mode (architect Q101, Q146): its one attach at a time, the attached
//! command's audit entries and the task that runs it. The connection side is `control.rs`;
//! the runner is `tools/exec.rs`, the shell tool's own.
//!
//! An attach is started in this order: the session's attach claim (one at a time; freed when
//! the command's task ends), an operation of the session ([`Ops::enter`], refused
//! `session-stopping` once the stop began), `sandbox.exec` in the session's log, then the task,
//! spawned through the session's crash reporter. The task runs the command, writes
//! `sandbox.exec_result` as soon as the runner returns (never waiting for the client to take
//! output, so it lands within the stop's drain, before `session.stop`), and then ends its
//! operation. An entry that cannot be written means no command (for `sandbox.exec`) or no
//! reply (for `sandbox.exec_result`): the connection closes.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use sally_core::audit::Actor;
use tokio::sync::{mpsc, oneshot, watch};

use super::attach::{self, Ended, OUTPUT_QUEUE};
use super::record::Recorder;
use crate::approvals::Client;
use crate::daemon::crash::CrashReporter;
use crate::tools::args;
use crate::tools::ops::Ops;
use crate::tools::shell::{AttachIo, Chunk, Input, Streamer};

/// One session's line mode.
pub struct Line<E> {
    exec: E,
    record: Recorder,
    ops: Ops,
    crash: CrashReporter,
    /// The directory a command runs in when the attach names none: the shell tool's default.
    cwd: String,
    busy: Arc<AtomicBool>,
    execs: AtomicU64,
}

/// What a line is built from.
pub struct LineParts<E> {
    /// The runner, the shell tool's.
    pub exec: E,
    /// The session's one audit handle.
    pub record: Recorder,
    /// The session's operations.
    pub ops: Ops,
    /// The session's crash reporter: a panic in the command's task is the session's crash.
    pub crash: CrashReporter,
    /// The default working directory.
    pub cwd: String,
}

/// The attach claim of one session; dropping it frees the session for the next attach.
#[derive(Debug)]
pub struct Claim(Arc<AtomicBool>);

impl Drop for Claim {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// Why an attach did not start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotStarted {
    /// The session's stop began (`session-stopping`).
    Stopping,
    /// `sandbox.exec` could not be written: no command, no reply.
    Unaudited,
}

/// An attached command, as its connection holds it.
#[derive(Debug)]
pub struct Running {
    /// Its output, escaped, in order per stream; ends once both streams ended.
    pub output: mpsc::Receiver<Chunk>,
    /// Its standard input, one [`Input`] at a time.
    pub input: mpsc::Sender<Input>,
    /// Its end once `sandbox.exec_result` is written; `None` (or a dropped sender) if that
    /// entry could not be written or the task ended without one.
    pub done: oneshot::Receiver<Option<Ended>>,
    /// Dropped or set: the connection is gone and the command is killed `disconnect`.
    pub disconnect: watch::Sender<bool>,
}

impl<E: Streamer> Line<E> {
    /// A session's line mode over `p`.
    #[must_use]
    pub fn build(p: LineParts<E>) -> Arc<Self> {
        Arc::new(Self {
            exec: p.exec,
            record: p.record,
            ops: p.ops,
            crash: p.crash,
            cwd: p.cwd,
            busy: Arc::new(AtomicBool::new(false)),
            execs: AtomicU64::new(0),
        })
    }

    /// The session's attach claim; `None` while another attach holds it (`attach-busy`).
    #[must_use]
    pub fn claim(&self) -> Option<Claim> {
        self.busy
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
            .then(|| Claim(Arc::clone(&self.busy)))
    }

    /// The directory for `asked`, checked as the shell tool checks its `cwd`; none asked: the
    /// default.
    ///
    /// # Errors
    /// The shell tool's reason (`bad-arguments`).
    pub fn cwd(&self, asked: Option<&str>) -> Result<String, &'static str> {
        asked.map_or_else(|| Ok(self.cwd.clone()), args::cwd)
    }

    /// Whether the session's stop began.
    #[must_use]
    pub fn stopping(&self) -> bool {
        self.ops.is_closed()
    }

    /// Starts `argv` in `cwd` for `client`, on `claim`.
    ///
    /// # Errors
    /// [`NotStarted`].
    pub async fn start(
        self: &Arc<Self>,
        claim: Claim,
        argv: Vec<String>,
        cwd: String,
        client: Client,
    ) -> Result<Running, NotStarted> {
        let Some(op) = self.ops.enter() else {
            return Err(NotStarted::Stopping);
        };
        let exec = self.execs.fetch_add(1, Ordering::SeqCst).saturating_add(1);
        let entry = self
            .record
            .entry(Actor::User, "sandbox.exec", Some("allow"))
            .args(attach::exec_args(exec, &argv, &cwd, client));
        if !self.record.append(entry).await {
            return Err(NotStarted::Unaudited);
        }
        let (out_tx, output) = mpsc::channel(OUTPUT_QUEUE);
        let (input, in_rx) = mpsc::channel(1);
        let (disconnect, gone) = watch::channel(false);
        let (done_tx, done) = oneshot::channel();
        let me = Arc::clone(self);
        self.crash.spawn("sandbox.exec", async move {
            let io = AttachIo {
                input: in_rx,
                output: out_tx,
                disconnect: gone,
            };
            let ran = me.exec.attach(&argv, &cwd, io).await;
            let entry = me
                .record
                .entry(Actor::Sallyd, "sandbox.exec_result", None)
                .args(attach::result_args(exec, &ran));
            let written = me.record.append(entry).await;
            drop(op);
            drop(claim);
            let _ = done_tx.send(written.then(|| attach::ended(&ran.status)));
        });
        Ok(Running {
            output,
            input,
            done,
            disconnect,
        })
    }
}

#[cfg(test)]
#[path = "line_tests.rs"]
mod tests;
