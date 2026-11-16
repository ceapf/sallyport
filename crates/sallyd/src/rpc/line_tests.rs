#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::time::Duration;

use sally_proto::{Attached, KillReason};
use serde_json::json;

use super::*;
use crate::rpc::testkit::{FakeExec, Mode, Sink, recorder};

struct Fx {
    line: Arc<Line<Arc<FakeExec>>>,
    fake: Arc<FakeExec>,
    sink: Arc<Sink>,
    ops: Ops,
}

fn fx(mode: Mode) -> Fx {
    let (sink, record) = recorder("s1");
    let fake = FakeExec::new(mode);
    let ops = Ops::new();
    let (crash, _) = CrashReporter::channel();
    let line = Line::build(LineParts {
        exec: Arc::clone(&fake),
        record,
        ops: ops.clone(),
        crash,
        cwd: "/workspace/p".into(),
    });
    Fx {
        line,
        fake,
        sink,
        ops,
    }
}

const CLIENT: Client = Client { uid: 1000, pid: 7 };

async fn start(f: &Fx, argv: &[&str]) -> Result<Running, NotStarted> {
    let claim = f.line.claim().expect("free");
    let argv = argv.iter().map(|s| (*s).to_owned()).collect();
    f.line.start(claim, argv, "/w".into(), CLIENT).await
}

async fn end(r: Running) -> Option<Ended> {
    tokio::time::timeout(Duration::from_secs(10), r.done)
        .await
        .expect("the command did not end")
        .ok()
        .flatten()
}

/// Architect Q101, Q147: `sandbox.exec` (the user's) before the command, `sandbox.exec_result`
/// (sallyd's) after it, numbered per session; never the output.
#[tokio::test]
async fn an_attach_is_audited_before_and_after_and_numbered() {
    let f = fx(Mode::Exit(3));
    let mut r = start(&f, &["sh", "-c", "x"]).await.unwrap();
    assert_eq!(r.output.recv().await.unwrap().text, "hi\n");
    assert_eq!(
        end(r).await,
        Some(Ended::Reply(Attached::Exited { exit_code: 3 }))
    );
    let rows = f.sink.rows();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].event, "sandbox.exec");
    assert_eq!(rows[0].decision.as_deref(), Some("allow"));
    assert!(rows[0].debug.contains("User"), "{}", rows[0].debug);
    assert_eq!(
        rows[0].args,
        json!({"exec": 1, "argv": ["sh", "-c", "x"], "cwd": "/w",
               "client": {"uid": 1000, "pid": 7}})
    );
    assert_eq!(rows[1].event, "sandbox.exec_result");
    assert!(rows[1].debug.contains("Sallyd"), "{}", rows[1].debug);
    assert_eq!(
        rows[1].args,
        json!({"exec": 1, "exit_code": 3, "stdin_bytes": 0, "stdout_bytes": 3, "stderr_bytes": 0})
    );
    assert_eq!(f.fake.seen.lock().unwrap()[0].1, "/w");
    let r = start(&f, &["true"]).await.unwrap();
    end(r).await;
    assert_eq!(f.sink.last("sandbox.exec")["exec"], 2);
    assert_eq!(f.sink.last("sandbox.exec_result")["exec"], 2);
}

/// Architect Q101: one attach per session at a time; the claim is freed when the command's
/// task ends, after its result entry.
#[tokio::test]
async fn one_attach_per_session_at_a_time() {
    let f = fx(Mode::Deaf);
    let r = start(&f, &["sh"]).await.unwrap();
    assert!(f.line.claim().is_none(), "attach-busy while one runs");
    drop(r.disconnect);
    tokio::time::timeout(Duration::from_secs(10), r.done)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(f.sink.events().last().unwrap(), "sandbox.exec_result");
    assert!(f.line.claim().is_some(), "free once the command ended");
    // A claim not used frees the session too.
    let c = f.line.claim().unwrap();
    assert!(f.line.claim().is_none());
    drop(c);
    assert!(f.line.claim().is_some());
}

/// Architect Q146: the attach is an operation of the session from before `sandbox.exec` to
/// after `sandbox.exec_result`, so the stop's drain waits for its result.
#[tokio::test]
async fn the_command_is_an_operation_until_its_result_is_written() {
    let f = fx(Mode::Deaf);
    assert_eq!(f.ops.in_flight(), 0);
    let r = start(&f, &["sh"]).await.unwrap();
    assert_eq!(f.ops.in_flight(), 1);
    r.disconnect.send_replace(true);
    assert_eq!(
        end(r).await,
        Some(Ended::Reply(Attached::Killed {
            killed: KillReason::Disconnect
        }))
    );
    assert_eq!(f.ops.in_flight(), 0);
    assert_eq!(f.sink.last("sandbox.exec_result")["killed"], "disconnect");
}

/// Architect Q146: once the stop began nothing starts and nothing is written.
#[tokio::test]
async fn nothing_starts_once_the_session_is_stopping() {
    let f = fx(Mode::Exit(0));
    f.ops.close();
    assert!(f.line.stopping());
    assert_eq!(start(&f, &["sh"]).await.unwrap_err(), NotStarted::Stopping);
    assert!(f.sink.rows().is_empty());
    assert!(f.fake.seen.lock().unwrap().is_empty());
    assert!(f.line.claim().is_some(), "the claim went with the refusal");
}

/// Architect Q146: no `sandbox.exec`, no command; the operation ends with the refusal.
#[tokio::test]
async fn an_unwritable_exec_entry_runs_nothing() {
    let f = fx(Mode::Exit(0));
    f.sink.set_failing(true);
    assert_eq!(start(&f, &["sh"]).await.unwrap_err(), NotStarted::Unaudited);
    assert!(f.fake.seen.lock().unwrap().is_empty());
    assert_eq!(f.ops.in_flight(), 0);
}

/// Architect Q146: a result that cannot be written gets no reply.
#[tokio::test]
async fn an_unwritable_result_entry_has_no_reply() {
    let f = fx(Mode::Exit(0));
    f.sink
        .fail_from
        .store(1, std::sync::atomic::Ordering::SeqCst);
    let r = start(&f, &["sh"]).await.unwrap();
    assert_eq!(end(r).await, None);
    assert_eq!(f.sink.events(), ["sandbox.exec"]);
    assert_eq!(f.ops.in_flight(), 0);
}

/// Input reaches the command in order, each acknowledged after it was written.
#[tokio::test]
async fn inputs_reach_the_command_in_order() {
    let f = fx(Mode::Echo);
    let mut r = start(&f, &["cat"]).await.unwrap();
    for (data, eof) in [("ab", false), ("c\n", true)] {
        let (done, ack) = oneshot::channel();
        r.input
            .send(Input {
                data: data.as_bytes().to_vec(),
                eof,
                done,
            })
            .await
            .unwrap();
        assert!(ack.await.unwrap());
        assert_eq!(r.output.recv().await.unwrap().text, data);
    }
    end(r).await;
    assert_eq!(f.sink.last("sandbox.exec_result")["stdin_bytes"], 4);
}

/// Architect Q101: the shell tool's default directory, and its check of an asked one.
#[test]
fn the_directory_is_the_shell_tools() {
    let f = fx(Mode::Exit(0));
    assert_eq!(f.line.cwd(None), Ok("/workspace/p".into()));
    assert_eq!(f.line.cwd(Some("//w/./a/")), Ok("/w/a".into()));
    for bad in ["w", "/a/../b", "/a\u{1}"] {
        assert_eq!(f.line.cwd(Some(bad)), Err(args::BAD), "{bad:?}");
    }
}
