//! Line mode over the control socket (architect Q101, Q102, Q144–Q152): attach, input, output
//! and the sessions bound to a connection.

use crate::rpc::line::LineParts;
use crate::rpc::testkit::Mode;
use crate::tools::args::MAX_ARGV;
use crate::tools::ops::Ops;

use super::*;

/// Adds live session `id` with line mode over a fake command; its sink is the session's log.
fn lined(f: &Fx, id: &str, mode: Mode) -> (Arc<Sink>, Arc<FakeExec>, Ops) {
    f.fake.live.lock().unwrap().push((info(id), None));
    let (sink, record) = recorder(id);
    let exec = FakeExec::new(mode);
    let ops = Ops::new();
    let line = Line::build(LineParts {
        exec: Arc::clone(&exec),
        record,
        ops: ops.clone(),
        crash: crate::daemon::crash::CrashReporter::channel().0,
        cwd: "/workspace".into(),
    });
    f.fake.lines.lock().unwrap().insert(id.to_owned(), line);
    f.fake
        .logs
        .lock()
        .unwrap()
        .insert(id.to_owned(), Arc::clone(&sink));
    (sink, exec, ops)
}

fn attach(id: &str, argv: &[&str]) -> Value {
    json!({"id": id, "argv": argv})
}

/// Frames until the one with request id `id`; the notifications before it.
async fn until_reply(w: &mut Wire, id: i64) -> (Vec<Value>, Value) {
    let mut notes = Vec::new();
    loop {
        let f = w.frame().await.expect("the connection closed");
        if f.get("id") == Some(&json!(id)) {
            return (notes, f);
        }
        assert!(f.get("id").is_none(), "an unexpected reply: {f}");
        notes.push(f);
    }
}

fn texts(notes: &[Value]) -> String {
    notes
        .iter()
        .map(|n| {
            assert_eq!(n["method"], "session.output");
            n["params"]["text"].as_str().unwrap().to_owned()
        })
        .collect()
}

/// Architect Q101: the command's output comes as notifications, then the reply with its code;
/// the control log has the request, the session's log the command and its result.
#[tokio::test]
async fn an_attach_streams_its_output_then_replies_with_the_code() {
    let f = fx("line-exit");
    let (sink, exec, _) = lined(&f, "s-1", Mode::Exit(7));
    let mut w = f.connect();
    w.send("sessions.attach", attach("s-1", &["sh", "-c", "x"]))
        .await;
    let (notes, reply) = until_reply(&mut w, 1).await;
    assert_eq!(texts(&notes), "hi\n");
    assert_eq!(notes[0]["params"]["id"], "s-1");
    assert_eq!(notes[0]["params"]["stream"], "stdout");
    assert_eq!(reply["result"], json!({"exit_code": 7}));
    assert_eq!(f.sink.last("rpc.request")["method"], "sessions.attach");
    assert_eq!(f.sink.last("rpc.request")["id"], "s-1");
    assert_eq!(sink.events(), ["sandbox.exec", "sandbox.exec_result"]);
    assert_eq!(exec.seen.lock().unwrap()[0].1, "/workspace");
    // Unattached again: the connection is served as before.
    let r = w.call("sessions.list", json!({})).await;
    assert!(r.get("result").is_some(), "{r}");
}

/// Architect Q101: each input is acknowledged once written, in order; the end of the input
/// ends the command.
#[tokio::test]
async fn inputs_are_acknowledged_once_written() {
    let f = fx("line-echo");
    let (sink, _, _) = lined(&f, "s-1", Mode::Echo);
    let mut w = f.connect();
    w.send("sessions.attach", attach("s-1", &["cat"])).await;
    w.send("sessions.input", json!({"id": "s-1", "data": "ab\n"}))
        .await;
    let (notes, ack) = until_reply(&mut w, 2).await;
    assert_eq!(ack["result"], json!({}));
    w.send(
        "sessions.input",
        json!({"id": "s-1", "data": "c", "eof": true}),
    )
    .await;
    let (more, ack) = until_reply(&mut w, 3).await;
    assert_eq!(ack["result"], json!({}));
    let (rest, reply) = until_reply(&mut w, 1).await;
    let all = [notes, more, rest].concat();
    assert_eq!(texts(&all), "ab\nc");
    assert_eq!(reply["result"], json!({"exit_code": 0}));
    assert_eq!(sink.last("sandbox.exec_result")["stdin_bytes"], 4);
    let inputs: Vec<Value> = f
        .rows()
        .iter()
        .filter(|r| r.event == "rpc.request" && r.args["method"] == "sessions.input")
        .map(|r| r.args.clone())
        .collect();
    assert_eq!(inputs.len(), 2);
    assert_eq!(
        (&inputs[0]["bytes"], &inputs[0]["eof"], &inputs[1]["eof"]),
        (&json!(3), &json!(false), &json!(true))
    );
    assert!(inputs.iter().all(|a| a.get("data").is_none()));
}

/// Architect Q144: while attached only input is served; anything else is recorded and refused
/// `attached`, and the attach goes on.
#[tokio::test]
async fn an_attached_connection_is_served_input_only() {
    let f = fx("line-only");
    let (_, exec, _) = lined(&f, "s-1", Mode::Deaf);
    let mut w = f.connect();
    w.send("sessions.attach", attach("s-1", &["sh"])).await;
    // The refusal names the session a call names, and none for one that names none.
    for (method, params, named) in [
        ("sessions.list", json!({}), None),
        ("approvals.watch", json!({}), None),
        ("sessions.attach", attach("s-2", &["sh"]), Some("s-2")),
        ("sessions.stop", json!({"id": "s-1"}), Some("s-1")),
    ] {
        let r = w.call(method, params).await;
        assert_eq!(reason(&r), "attached", "{method}");
        let last = f.sink.last("session.refuse");
        assert_eq!(
            (last["method"].as_str(), last["reason"].as_str()),
            (Some(method), Some("attached"))
        );
        assert_eq!(last["id"].as_str(), named, "{method}");
    }
    assert!(f.fake.stopped.lock().unwrap().is_empty());
    exec.release.notify_one();
    let (_, reply) = until_reply(&mut w, 1).await;
    assert_eq!(reply["result"], json!({"exit_code": 0}));
}

/// Architect Q101, Q147: one attach per session (`attach-busy`); none on a watching
/// connection (`attach-watching`); input only on the attached connection, for its session.
#[tokio::test]
async fn attach_and_input_refusals() {
    let f = fx("line-refuse");
    let (_, exec, _) = lined(&f, "s-1", Mode::Deaf);
    let mut a = f.connect();
    a.send("sessions.attach", attach("s-1", &["sh"])).await;
    let mut b = f.connect();
    // `sessions.input` from a connection that is not attached.
    let r = b
        .call("sessions.input", json!({"id": "s-1", "data": "x"}))
        .await;
    assert_eq!(reason(&r), "not-attached");
    eventually(|| exec.seen.lock().unwrap().len() == 1).await;
    let r = b.call("sessions.attach", attach("s-1", &["sh"])).await;
    assert_eq!(reason(&r), "attach-busy");
    let r = b.call("approvals.watch", json!({})).await;
    assert!(r.get("result").is_some());
    lined(&f, "s-2", Mode::Exit(0));
    let r = b.call("sessions.attach", attach("s-2", &["sh"])).await;
    assert_eq!(reason(&r), "attach-watching");
    // On the attached connection: another session's id.
    let r = a
        .call("sessions.input", json!({"id": "s-2", "data": "x"}))
        .await;
    assert_eq!(reason(&r), "not-attached");
    let reasons: Vec<String> = f
        .rows()
        .iter()
        .filter(|r| r.event == "session.refuse")
        .map(|r| r.args["reason"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        reasons,
        [
            "not-attached",
            "attach-busy",
            "attach-watching",
            "not-attached"
        ]
    );
    exec.release.notify_one();
}

/// Architect Q101, Q152: one input at a time; one not written when the command ends is answered
/// `input-closed` before the attach's reply; nothing after the end of the input.
#[tokio::test]
async fn a_pending_input_is_answered_before_the_reply() {
    let f = fx("line-pending");
    let (_, exec, _) = lined(&f, "s-1", Mode::Deaf);
    let mut w = f.connect();
    w.send("sessions.attach", attach("s-1", &["sh"])).await;
    w.send("sessions.input", json!({"id": "s-1", "data": "x"}))
        .await;
    let r = w
        .call("sessions.input", json!({"id": "s-1", "data": "y"}))
        .await;
    assert_eq!(reason(&r), "input-pending");
    exec.release.notify_one();
    let pending = w.frame().await.unwrap();
    assert_eq!(pending["id"], 2);
    assert_eq!(reason(&pending), "input-closed");
    let (_, reply) = until_reply(&mut w, 1).await;
    assert_eq!(reply["result"], json!({"exit_code": 0}));

    let (_, _, _) = lined(&f, "s-2", Mode::Echo);
    w.send("sessions.attach", attach("s-2", &["cat"])).await;
    w.send(
        "sessions.input",
        json!({"id": "s-2", "data": "", "eof": true}),
    )
    .await;
    let (_, ack) = until_reply(&mut w, 5).await;
    assert_eq!(ack["result"], json!({}));
    let (_, reply) = until_reply(&mut w, 4).await;
    assert_eq!(reply["result"], json!({"exit_code": 0}));
}

/// Architect Q147: no input after the end of the input.
#[tokio::test]
async fn nothing_is_taken_after_the_end_of_the_input() {
    let f = fx("line-eof");
    let (_, exec, _) = lined(&f, "s-1", Mode::Deaf);
    let mut w = f.connect();
    w.send("sessions.attach", attach("s-1", &["sh"])).await;
    w.send(
        "sessions.input",
        json!({"id": "s-1", "data": "", "eof": true}),
    )
    .await;
    let r = w
        .call("sessions.input", json!({"id": "s-1", "data": "y"}))
        .await;
    // The first is still unwritten (the command never reads): the end wins.
    assert_eq!(reason(&r), "input-closed");
    exec.release.notify_one();
}

/// Architect Q101, Q147: the session and the command are checked before anything runs.
#[tokio::test]
async fn an_attach_is_refused_before_anything_runs() {
    let f = fx("line-pre");
    let (sink, exec, ops) = lined(&f, "s-1", Mode::Exit(0));
    let mut w = f.connect();
    let r = w.call("sessions.attach", attach("s-9", &["sh"])).await;
    assert_eq!(reason(&r), "unknown-session");
    let r = w
        .call(
            "sessions.attach",
            json!({"id": "s-1", "argv": ["sh"], "cwd": "/a/../b"}),
        )
        .await;
    assert_eq!(reason(&r), "bad-arguments");
    ops.close();
    let r = w.call("sessions.attach", attach("s-1", &["sh"])).await;
    assert_eq!(reason(&r), "session-stopping");
    assert!(exec.seen.lock().unwrap().is_empty());
    assert!(sink.rows().is_empty(), "nothing in the session's log");
}

/// Architect Q101: argv is 1 to 256 strings, the first not empty, none with a NUL; input data
/// is at most 64 KiB. Anything else is not admitted.
#[tokio::test]
async fn the_params_bounds() {
    let f = fx("line-bounds");
    lined(&f, "s-1", Mode::Echo);
    let mut w = f.connect();
    let many: Vec<String> = vec!["a".into(); MAX_ARGV + 1];
    for bad in [
        json!({"id": "s-1", "argv": []}),
        json!({"id": "s-1", "argv": [""]}),
        json!({"id": "s-1", "argv": ["sh", "a\u{0}b"]}),
        json!({"id": "s-1", "argv": many}),
        json!({"id": "S 1", "argv": ["sh"]}),
        json!({"id": "s-1", "argv": ["sh"], "env": {}}),
    ] {
        let r = w.call("sessions.attach", bad.clone()).await;
        assert_eq!(r["error"]["code"], -32602, "{bad}");
    }
    // At the bounds: attached (request 7), and a full input taken (request 9).
    w.send(
        "sessions.attach",
        json!({"id": "s-1", "argv": vec!["a"; MAX_ARGV]}),
    )
    .await;
    let big = "x".repeat(sally_proto::MAX_INPUT_BYTES + 1);
    let r = w
        .call("sessions.input", json!({"id": "s-1", "data": big}))
        .await;
    assert_eq!(r["id"], 8);
    assert_eq!(r["error"]["code"], -32602);
    let full = "x".repeat(sally_proto::MAX_INPUT_BYTES);
    w.send(
        "sessions.input",
        json!({"id": "s-1", "data": full, "eof": true}),
    )
    .await;
    let (_, ack) = until_reply(&mut w, 9).await;
    assert_eq!(ack["result"], json!({}));
    let (_, reply) = until_reply(&mut w, 7).await;
    assert_eq!(reply["result"], json!({"exit_code": 0}));
}

/// Architect Q147: a `podman exec` that could not run is `exec-failed`, never a code.
#[tokio::test]
async fn an_exec_that_could_not_run_is_refused() {
    let f = fx("line-fail");
    let (sink, _, _) = lined(&f, "s-1", Mode::Fail);
    let mut w = f.connect();
    let (_, r) = {
        w.send("sessions.attach", attach("s-1", &["sh"])).await;
        until_reply(&mut w, 1).await
    };
    assert_eq!(reason(&r), "exec-failed");
    assert_eq!(sink.last("sandbox.exec_result")["failed"], true);
    assert_eq!(f.sink.last("session.refuse")["reason"], "exec-failed");
}

/// Architect Q144: the connection's end kills the command (`disconnect`), its result written.
#[tokio::test]
async fn the_connections_end_kills_the_command() {
    let f = fx("line-gone");
    let (sink, _, _) = lined(&f, "s-1", Mode::Deaf);
    let mut w = f.connect();
    w.send("sessions.attach", attach("s-1", &["sh"])).await;
    eventually(|| sink.events().len() == 1).await;
    w.w.shutdown().await.unwrap();
    w.ended().await;
    assert_eq!(sink.events(), ["sandbox.exec", "sandbox.exec_result"]);
    assert_eq!(sink.last("sandbox.exec_result")["killed"], "disconnect");
}

/// Architect Q152: a client that stops reading stalls the command's output, never `sallyd`; a
/// write blocked for [`WRITE_TIMEOUT`](crate::rpc::agent::WRITE_TIMEOUT) drops the connection,
/// which kills the command (`disconnect`). Before that, nothing is killed.
#[tokio::test(start_paused = true)]
async fn a_reader_paused_past_the_write_timeout_gets_the_command_killed() {
    let f = fx("line-paused");
    let (sink, _, _) = lined(&f, "s-1", Mode::Flood);
    let mut w = f.connect();
    w.send("sessions.attach", attach("s-1", &["yes"])).await;
    let limit = crate::rpc::agent::WRITE_TIMEOUT;
    tokio::time::sleep(limit - Duration::from_secs(1)).await;
    assert_eq!(sink.events(), ["sandbox.exec"], "killed before the timeout");
    eventually(|| sink.events().len() == 2).await;
    assert_eq!(sink.last("sandbox.exec_result")["killed"], "disconnect");
    // The server's half is gone: what was buffered (its last frame cut by the timed-out write)
    // can still be read, then the end.
    w.w.shutdown().await.unwrap();
    let mut rest = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut w.r, &mut rest)
        .await
        .unwrap();
    assert!(!rest.is_empty());
    w.task.await.unwrap();
}

/// Architect Q144, Q152: output and an input still held when the command's end comes are
/// sent first, in that order: the output, then the input's answer (`input-closed`, it was
/// never written), then the reply.
#[tokio::test]
async fn what_outlives_the_command_comes_before_its_reply() {
    let f = fx("line-late");
    lined(&f, "s-1", Mode::Late);
    let mut w = f.connect();
    w.send("sessions.attach", attach("s-1", &["sh"])).await;
    w.send("sessions.input", json!({"id": "s-1", "data": "x"}))
        .await;
    let (notes, ack) = until_reply(&mut w, 2).await;
    assert_eq!(texts(&notes), "late\n");
    assert_eq!(reason(&ack), "input-closed");
    let (rest, reply) = until_reply(&mut w, 1).await;
    assert!(rest.is_empty(), "{rest:?}");
    assert_eq!(reply["result"], json!({"exit_code": 0}));
}

/// Architect Q144: all output comes before the reply, in order.
#[tokio::test]
async fn all_output_comes_before_the_reply() {
    let f = fx("line-order");
    lined(&f, "s-1", Mode::Lines(40));
    let mut w = f.connect();
    w.send("sessions.attach", attach("s-1", &["sh"])).await;
    let (notes, reply) = until_reply(&mut w, 1).await;
    assert_eq!(notes.len(), 40);
    for (i, n) in notes.iter().enumerate() {
        assert!(
            n["params"]["text"]
                .as_str()
                .unwrap()
                .starts_with(&format!("{i:04}"))
        );
    }
    assert_eq!(reply["result"], json!({"exit_code": 0}));
}

/// Architect Q102, Q150: a session created bound to its connection is stopped, `disconnect`,
/// when that connection ends, after its attach ended; one created without is not.
#[tokio::test]
async fn a_bound_session_stops_with_its_connection() {
    let f = fx("line-bound");
    let mut w = f.connect();
    let r = w
        .call(
            "sessions.create",
            json!({"manifest": MANIFEST, "lifetime": "connection"}),
        )
        .await;
    assert_eq!(r["result"]["id"], "s-new");
    assert_eq!(f.sink.last("rpc.request")["lifetime"], "connection");
    let (sink, _, _) = lined(&f, "s-new", Mode::Deaf);
    w.send("sessions.attach", attach("s-new", &["sh"])).await;
    eventually(|| sink.events().len() == 1).await;
    w.w.shutdown().await.unwrap();
    w.ended().await;
    eventually(|| !f.fake.disconnected.lock().unwrap().is_empty()).await;
    assert_eq!(*f.fake.disconnected.lock().unwrap(), ["s-new"]);
    assert_eq!(sink.last("sandbox.exec_result")["killed"], "disconnect");
    // The attach ended, its result written, before the bound stop began.
    assert_eq!(
        *f.fake.stop_saw.lock().unwrap(),
        [["sandbox.exec", "sandbox.exec_result"]]
    );
    assert_eq!(format!("{:?}", f.control.bind("s-x")), "Bound { .. }");

    let mut free = f.connect();
    let r = free
        .call("sessions.create", json!({"manifest": MANIFEST}))
        .await;
    assert!(r.get("result").is_some());
    assert!(f.sink.last("rpc.request").get("lifetime").is_none());
    free.w.shutdown().await.unwrap();
    free.ended().await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(f.fake.disconnected.lock().unwrap().len(), 1);
}

/// Architect Q150: a bound session whose stop fails is a `stop-failed` refusal in the control
/// log; `lifetime` is `connection` or absent.
#[tokio::test]
async fn a_bound_stop_that_fails_is_recorded() {
    let f = fx("line-bound-fail");
    *f.fake.stop_fails.lock().unwrap() = Some("still running".into());
    let mut w = f.connect();
    let r = w
        .call(
            "sessions.create",
            json!({"manifest": MANIFEST, "lifetime": "connection"}),
        )
        .await;
    assert!(r.get("result").is_some());
    f.fake.live.lock().unwrap().push((info("s-new"), None));
    let r = w
        .call(
            "sessions.create",
            json!({"manifest": MANIFEST, "lifetime": "session"}),
        )
        .await;
    assert_eq!(r["error"]["code"], -32602);
    w.w.shutdown().await.unwrap();
    w.ended().await;
    eventually(|| f.sink.last("session.refuse")["reason"] == "stop-failed").await;
    let last = f.sink.last("session.refuse");
    assert_eq!(last["id"], "s-new");
    assert_eq!(last["cause"], "disconnect");
    assert_eq!(last["detail"], "still running");
}
