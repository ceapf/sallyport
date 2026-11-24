//! `sessions.drive` and the model of `sessions.create` over the control socket (architect
//! Q117–Q122). Red-team rows: drive refused on a non-driven session; the driver cannot answer
//! an approval; one driver; the caller cannot choose a call; the script is data.

use std::sync::Mutex as Mx;

use super::*;
use crate::rpc::agent::Driven;
use crate::rpc::drive::CallFn;
use crate::rpc::mcp::ToolOutcome;

const TWO: &str =
    "{\"tool_calls\":[{\"name\":\"echo\",\"arguments\":{}}]}\n{\"content\":\"bye\"}\n";
/// Three turns: after two steps, one is left for a seat that is not gone to run.
const THREE: &str = "{\"tool_calls\":[{\"name\":\"echo\",\"arguments\":{}}]}\n\
    {\"tool_calls\":[{\"name\":\"echo\",\"arguments\":{}}]}\n{\"content\":\"bye\"}\n";

/// Adds session `id`, declared driven over `script`; every call it makes answers `ran <name>`
/// and is noted in the returned list. Its sink is the session's own log.
fn driven(f: &Fx, id: &str, script: &str) -> (Arc<Sink>, Arc<Mx<Vec<String>>>) {
    f.fake.live.lock().unwrap().push((info(id), None));
    let (sink, rec) = recorder(id);
    let calls: Arc<Mx<Vec<String>>> = Arc::default();
    let log = Arc::clone(&calls);
    let call: CallFn = Box::new(move |name, _| {
        log.lock().unwrap().push(name.clone());
        Box::pin(async move {
            Driven::Done(ToolOutcome {
                is_error: false,
                text: format!("ran {name}"),
            })
        })
    });
    let d = Driver::build(
        Script::parse(script).unwrap().turns,
        call,
        rec.driven(),
        crate::tools::ops::Ops::new(),
    );
    f.fake.drivers.lock().unwrap().insert(id.to_owned(), d);
    (sink, calls)
}

fn refused(f: &Fx, event: &str) -> Value {
    f.sink.last(event)
}

#[tokio::test]
async fn rt_drv_05_a_session_not_declared_driven_has_no_drive_methods() {
    let f = fx("drive-none");
    let own = f.session("s-1");
    let mut w = f.connect();
    // Control (#122, architect Q158, Q170), first: a session of the same fixture declared
    // driven is driven by the same call, and its own entries record the turn.
    let (theirs, calls) = driven(&f, "s-2", TWO);
    let r = w.call("sessions.drive", json!({"id": "s-2"})).await;
    assert_eq!(r["result"]["turn"], json!(1), "control: {r}");
    assert_eq!(theirs.events(), ["drive.turn"], "control: entries");
    assert_eq!(*calls.lock().unwrap(), ["echo"], "control: calls");
    let r = w.call("sessions.drive", json!({"id": "s-1"})).await;
    assert_eq!(r["error"]["code"], json!(REFUSED));
    assert_eq!(reason(&r), "not-driven");
    assert_eq!(f.events(), ["rpc.request", "rpc.request", "session.refuse"]);
    assert_eq!(
        refused(&f, "session.refuse"),
        json!({"method": "sessions.drive", "id": "s-1", "reason": "not-driven",
               "client": client()})
    );
    assert!(own.events().is_empty(), "nothing is written to the session");
    let r = w.call("sessions.drive", json!({"id": "s-9"})).await;
    assert_eq!(reason(&r), "unknown-session");
    // That refusal is in the control log too, with its own request entry.
    assert_eq!(
        f.events(),
        [
            "rpc.request",
            "rpc.request",
            "session.refuse",
            "rpc.request",
            "session.refuse"
        ]
    );
    assert_eq!(
        refused(&f, "session.refuse"),
        json!({"method": "sessions.drive", "id": "s-9", "reason": "unknown-session",
               "client": client()})
    );
}

#[tokio::test]
async fn a_drive_step_runs_one_scripted_turn_and_answers_with_it() {
    let f = fx("drive-run");
    let (own, calls) = driven(&f, "s-1", TWO);
    let mut w = f.connect();
    let r = w.call("sessions.drive", json!({"id": "s-1"})).await;
    assert_eq!(
        r["result"],
        json!({"turn": 1, "kind": "tool_calls", "done": false,
               "calls": [{"name": "echo", "result": "ran echo"}]})
    );
    let r = w.call("sessions.drive", json!({"id": "s-1"})).await;
    assert_eq!(
        r["result"],
        json!({"turn": 2, "kind": "content", "content": "bye", "done": true})
    );
    let r = w.call("sessions.drive", json!({"id": "s-1"})).await;
    assert_eq!(r["result"]["kind"], json!("end"));
    assert_eq!(*calls.lock().unwrap(), ["echo"]);
    assert_eq!(own.events(), ["drive.turn", "drive.turn"]);
    assert_eq!(f.events(), ["rpc.request", "rpc.request", "rpc.request"]);
}

#[tokio::test]
async fn rt_drv_06_a_second_connection_is_refused_and_a_closed_driver_leaves_the_seat_gone() {
    let f = fx("drive-seat");
    let (own, _) = driven(&f, "s-1", THREE);
    let mut first = f.connect();
    first.call("sessions.drive", json!({"id": "s-1"})).await;
    let r = f
        .connect()
        .call("sessions.drive", json!({"id": "s-1"}))
        .await;
    assert_eq!(reason(&r), "driver-busy");
    first.call("sessions.drive", json!({"id": "s-1"})).await;
    drop(first);
    let mut gone = false;
    for _ in 0..200 {
        let r = f
            .connect()
            .call("sessions.drive", json!({"id": "s-1"}))
            .await;
        if reason(&r) == "driver-gone" {
            gone = true;
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(gone, "the seat never became gone");
    assert_eq!(
        own.events(),
        ["drive.turn", "drive.turn"],
        "the cursor stayed"
    );
}

/// Sets its flag when dropped.
struct Dropped(Arc<std::sync::atomic::AtomicBool>);

impl Drop for Dropped {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Adds driven session `id` over [`TWO`] whose one call signals `began`, then waits for
/// `release` (forever, if it never comes); `dropped` is set when the call's future is dropped.
fn held(
    f: &Fx,
    id: &str,
) -> (
    Arc<tokio::sync::Notify>,
    Arc<tokio::sync::Notify>,
    Arc<std::sync::atomic::AtomicBool>,
) {
    f.fake.live.lock().unwrap().push((info(id), None));
    let (_, rec) = recorder(id);
    let began = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (b, r, d) = (
        Arc::clone(&began),
        Arc::clone(&release),
        Arc::clone(&dropped),
    );
    let call: CallFn = Box::new(move |name, _| {
        let guard = Dropped(Arc::clone(&d));
        let (b, r) = (Arc::clone(&b), Arc::clone(&r));
        Box::pin(async move {
            let _guard = guard;
            b.notify_one();
            r.notified().await;
            Driven::Done(ToolOutcome {
                is_error: false,
                text: format!("ran {name}"),
            })
        })
    });
    let driver = Driver::build(
        Script::parse(TWO).unwrap().turns,
        call,
        rec.driven(),
        crate::tools::ops::Ops::new(),
    );
    f.fake.drivers.lock().unwrap().insert(id.to_owned(), driver);
    (began, release, dropped)
}

/// Waits until the step [`held`] holds has begun, failing the test once [`WAIT`] passes (a
/// drive request nothing answers never begins one).
async fn begun(began: &tokio::sync::Notify) {
    tokio::time::timeout(WAIT, began.notified())
        .await
        .expect("the step never began");
}

/// A driver that closes while its step waits (on a prompt, say) drops the step at once, and the
/// seat is gone; it is not left held by a connection nobody reads. That a dropped driven call
/// withdraws its prompt is `agent_tests.rs`'s
/// `a_dropped_driven_call_runs_to_its_end_and_its_prompt_is_withdrawn`.
#[tokio::test]
async fn rt_drv_06_a_driver_that_closes_mid_step_drops_the_step_and_leaves_the_seat_gone() {
    let f = fx("drive-away");
    let (began, _release, dropped) = held(&f, "s-1");
    let mut seat = f.connect();
    seat.send("sessions.drive", json!({"id": "s-1"})).await;
    begun(&began).await;
    drop(seat);
    for _ in 0..200 {
        if dropped.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        dropped.load(std::sync::atomic::Ordering::SeqCst),
        "the step was kept"
    );
    let r = f
        .connect()
        .call("sessions.drive", json!({"id": "s-1"}))
        .await;
    assert_eq!(reason(&r), "driver-gone");
}

/// A driver that shuts its write side after the drive is a closed driver: the step is dropped
/// unanswered and the seat is gone (architect ruling on the H1 fix: half-close fails closed).
#[tokio::test]
async fn rt_drv_06_a_driver_that_half_closes_mid_step_is_a_closed_driver() {
    let f = fx("drive-half");
    let (began, _release, dropped) = held(&f, "s-1");
    let mut seat = f.connect();
    seat.send("sessions.drive", json!({"id": "s-1"})).await;
    begun(&began).await;
    seat.w.shutdown().await.unwrap();
    for _ in 0..200 {
        if dropped.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        dropped.load(std::sync::atomic::Ordering::SeqCst),
        "the step was kept"
    );
    assert!(
        seat.frame().await.is_none(),
        "a closed driver gets no reply"
    );
    let r = f
        .connect()
        .call("sessions.drive", json!({"id": "s-1"}))
        .await;
    assert_eq!(reason(&r), "driver-gone");
}

/// Bytes sent while a step runs are a next request, not a close: the step ends and both answer.
#[tokio::test]
async fn a_request_pipelined_behind_a_step_does_not_drop_it() {
    let f = fx("drive-pipelined");
    let (began, release, dropped) = held(&f, "s-1");
    let mut seat = f.connect();
    seat.send("sessions.drive", json!({"id": "s-1"})).await;
    begun(&began).await;
    seat.send("sessions.list", json!({})).await;
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    assert!(
        !dropped.load(std::sync::atomic::Ordering::SeqCst),
        "the step was dropped"
    );
    release.notify_one();
    let r = seat.frame().await.expect("the connection closed");
    assert_eq!(r["result"]["calls"][0]["result"], json!("ran echo"), "{r}");
    let r = seat.frame().await.expect("the connection closed");
    assert!(r["result"].is_object() || r["result"].is_array(), "{r}");
}

/// The seat of a session that stopped is let go at the connection's next request: the
/// connection is no driver any more, so it may watch (and decide) again.
#[tokio::test]
async fn a_seat_of_a_stopped_session_is_let_go() {
    let f = fx("drive-ended");
    f.fake.live.lock().unwrap().push((info("s-1"), None));
    let (own, rec) = recorder("s-1");
    let ops = crate::tools::ops::Ops::new();
    let call: CallFn = Box::new(|_, _| {
        Box::pin(async {
            Driven::Done(ToolOutcome {
                is_error: false,
                text: "ran".into(),
            })
        })
    });
    let d = Driver::build(
        Script::parse(TWO).unwrap().turns,
        call,
        rec.driven(),
        ops.clone(),
    );
    f.fake.drivers.lock().unwrap().insert("s-1".into(), d);
    let mut w = f.connect();
    w.call("sessions.drive", json!({"id": "s-1"})).await;
    let r = w.call("approvals.watch", json!({})).await;
    assert_eq!(reason(&r), "driver-seat");
    ops.close();
    let r = w.call("sessions.drive", json!({"id": "s-1"})).await;
    assert_eq!(reason(&r), "session-stopping");
    let r = w.call("approvals.watch", json!({})).await;
    assert!(r.get("error").is_none(), "{r}");
    assert_eq!(f.hub.count(), 1);
    assert_eq!(own.events(), ["drive.turn"], "nothing after the stop");
}

/// A stopping session refuses every drive `session-stopping`, also one from a connection
/// without its seat while another still holds it (not `driver-busy`).
#[tokio::test]
async fn a_stopping_session_refuses_a_drive_from_any_connection() {
    let f = fx("drive-stopping");
    f.fake.live.lock().unwrap().push((info("s-1"), None));
    let (own, rec) = recorder("s-1");
    let ops = crate::tools::ops::Ops::new();
    let call: CallFn = Box::new(|_, _| {
        Box::pin(async {
            Driven::Done(ToolOutcome {
                is_error: false,
                text: "ran".into(),
            })
        })
    });
    let turns = Script::parse(THREE).unwrap().turns;
    let d = Driver::build(turns, call, rec.driven(), ops.clone());
    f.fake.drivers.lock().unwrap().insert("s-1".into(), d);
    let mut holder = f.connect();
    holder.call("sessions.drive", json!({"id": "s-1"})).await;
    ops.close();
    let r = f
        .connect()
        .call("sessions.drive", json!({"id": "s-1"}))
        .await;
    assert_eq!(reason(&r), "session-stopping");
    assert_eq!(own.events(), ["drive.turn"]);
}

/// One connection may drive two sessions: each drive steps that session's own seat and script.
#[tokio::test]
async fn one_connection_drives_two_sessions_each_on_its_own_seat() {
    let f = fx("drive-two");
    let (one, _) = driven(&f, "s-1", THREE);
    let (two, calls) = driven(&f, "s-2", "{\"content\":\"only\"}\n");
    let mut w = f.connect();
    let r = w.call("sessions.drive", json!({"id": "s-1"})).await;
    assert_eq!(r["result"]["kind"], json!("tool_calls"));
    let r = w.call("sessions.drive", json!({"id": "s-2"})).await;
    assert_eq!(
        r["result"],
        json!({"turn": 1, "kind": "content", "content": "only", "done": true})
    );
    assert_eq!(one.events(), ["drive.turn"]);
    assert_eq!(two.events(), ["drive.turn"]);
    assert!(calls.lock().unwrap().is_empty());
}

/// A connection in the driver seat cannot attach a command (`driver-seat`, THREAT_MODEL's
/// attach row): first, as the control, a plain connection's attach to a lined session runs its
/// command; then the seat's attach is refused, logged, and the command runner sees nothing.
#[tokio::test]
async fn a_connection_in_the_driver_seat_cannot_attach() {
    use super::line_mode::{attach, lined, until_reply};
    use crate::rpc::testkit::Mode;
    let f = fx("drive-attach");
    driven(&f, "s-1", TWO);
    let (_, exec, _) = lined(&f, "s-2", Mode::Exit(0));
    let mut plain = f.connect();
    plain.send("sessions.attach", attach("s-2", &["sh"])).await;
    let (_, r) = until_reply(&mut plain, 1).await;
    assert_eq!(r["result"], json!({"exit_code": 0}), "control: {r}");
    assert_eq!(
        exec.seen.lock().unwrap().len(),
        1,
        "control: the command ran"
    );
    let mut seat = f.connect();
    let r = seat.call("sessions.drive", json!({"id": "s-1"})).await;
    assert_eq!(r["result"]["turn"], json!(1), "{r}");
    let r = seat.call("sessions.attach", attach("s-2", &["sh"])).await;
    assert_eq!(r["error"]["code"], json!(REFUSED));
    assert_eq!(reason(&r), "driver-seat");
    assert_eq!(
        refused(&f, "session.refuse"),
        json!({"method": "sessions.attach", "id": "s-2", "reason": "driver-seat",
               "client": client()})
    );
    assert_eq!(
        exec.seen.lock().unwrap().len(),
        1,
        "the seat's attach ran nothing"
    );
}

#[tokio::test]
async fn rt_drv_06_a_connection_that_watches_cannot_take_the_seat() {
    let f = fx("drive-watching");
    driven(&f, "s-1", TWO);
    let mut w = f.connect();
    w.call("approvals.watch", json!({})).await;
    let r = w.call("sessions.drive", json!({"id": "s-1"})).await;
    assert_eq!(reason(&r), "driver-watching");
}

/// The driver is never an approver: decide and watch on a seat connection are refused, the
/// prompt stays pending and its tool does not run.
#[tokio::test]
async fn rt_drv_04_a_connection_in_the_driver_seat_cannot_answer_an_approval() {
    let f = fx("drive-decide");
    f.session("s-2");
    driven(&f, "s-1", TWO);
    let mut approver = f.connect();
    approver.call("approvals.watch", json!({})).await;
    let asked = f.ask("s-2", 1, &["rm", "-rf", "x"]);
    let p = note(&mut approver).await["params"].clone();
    let mut seat = f.connect();
    seat.call("sessions.drive", json!({"id": "s-1"})).await;
    let r = seat
        .call(
            "approvals.decide",
            json!({"id": p["id"], "decision": "approve", "digest": p["digest"]}),
        )
        .await;
    assert_eq!(r["error"]["code"], json!(REFUSED));
    assert_eq!(reason(&r), "driver-seat");
    let row = f
        .rows()
        .into_iter()
        .rfind(|r| r.event == "approval.decide")
        .unwrap();
    assert_eq!(row.decision.as_deref(), Some("refuse"));
    assert!(row.debug.contains("User"), "{}", row.debug);
    assert_eq!(row.args["reason"], json!("driver-seat"));
    let r = seat.call("approvals.watch", json!({})).await;
    assert_eq!(reason(&r), "driver-seat");
    assert_eq!(f.hub.count(), 1, "only the real approver is attached");
    let listed = f.connect().call("approvals.list", json!({})).await;
    assert_eq!(listed["result"]["total"], json!(1), "the prompt is pending");
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    assert!(!asked.is_finished(), "the action was not approved");
    // Control (#122, architect Q168): the same decision from the real approver's connection
    // answers the same prompt, and the waiting action ends.
    let r = approver
        .call(
            "approvals.decide",
            json!({"id": p["id"], "decision": "approve", "digest": p["digest"]}),
        )
        .await;
    assert!(r.get("error").is_none(), "control: {r}");
    let ticket = tokio::time::timeout(std::time::Duration::from_secs(5), asked)
        .await
        .expect("control: the approved action ended")
        .unwrap();
    assert!(ticket.is_ok(), "control: approved: {ticket:?}");
}

#[tokio::test]
async fn rt_drv_07_drive_takes_a_session_id_and_nothing_else() {
    let f = fx("drive-params");
    let (own, calls) = driven(&f, "s-1", TWO);
    let mut w = f.connect();
    // Control (#122, architect Q158), first: the same method with only the id runs the turn's
    // call, recorded by the same `calls` and the session's own entries.
    let r = w.call("sessions.drive", json!({"id": "s-1"})).await;
    assert_eq!(r["result"]["turn"], json!(1), "control: {r}");
    assert_eq!(*calls.lock().unwrap(), ["echo"], "control: calls");
    assert_eq!(own.events(), ["drive.turn"], "control: entries");
    for extra in [
        json!({"id": "s-1", "name": "shell"}),
        json!({"id": "s-1", "arguments": {}}),
        json!({"id": "s-1", "tool_calls": []}),
        json!({"id": "s-1", "actor": "harness"}),
        json!({"id": "s-1", "origin": "agent"}),
        json!({}),
    ] {
        let r = w.call("sessions.drive", extra).await;
        assert_eq!(r["error"]["code"], json!(-32602));
    }
    assert_eq!(*calls.lock().unwrap(), ["echo"]);
    assert_eq!(own.events(), ["drive.turn"]);
}

/// Architect Q150: a bound session may be driven. A driven create binds like any other, the
/// connection that made it drives it, and that connection's end stops it, `disconnect`.
#[tokio::test]
async fn a_bound_session_may_be_driven() {
    let f = fx("drive-bound");
    let mut w = f.connect();
    let mut p = model(true, "scripted", TWO);
    p["lifetime"] = json!("connection");
    let r = w.call("sessions.create", p).await;
    assert_eq!(r["result"]["id"], "s-new", "{r}");
    assert_eq!(f.sink.last("rpc.request")["lifetime"], "connection");
    assert!(f.fake.scripts.lock().unwrap()[0].is_some());
    let (own, calls) = driven(&f, "s-new", TWO);
    let r = w.call("sessions.drive", json!({"id": "s-new"})).await;
    assert_eq!(r["result"]["turn"], 1, "{r}");
    assert_eq!(*calls.lock().unwrap(), ["echo"]);
    assert_eq!(own.events(), ["drive.turn"]);
    assert!(f.fake.disconnected.lock().unwrap().is_empty());
    w.w.shutdown().await.unwrap();
    w.ended().await;
    eventually(|| !f.fake.disconnected.lock().unwrap().is_empty()).await;
    assert_eq!(*f.fake.disconnected.lock().unwrap(), ["s-new"]);
}

fn model(driven: bool, kind: &str, script: &str) -> Value {
    json!({"manifest": MANIFEST, "model": {"kind": kind, "script": script, "driven": driven}})
}

#[tokio::test]
async fn rt_drv_08_a_model_is_refused_unless_scripted_declared_driven_with_a_good_script() {
    let f = fx("drive-create");
    let mut w = f.connect();
    // Control (#122, architect Q158), first: a good script declared driven starts, recorded by
    // the same fake launcher.
    let r = w
        .call("sessions.create", model(true, "scripted", TWO))
        .await;
    assert!(r.get("error").is_none(), "control: {r}");
    assert_eq!(
        f.fake.started.lock().unwrap().len(),
        1,
        "control: it started"
    );
    let control = f.events();
    for (p, why) in [
        (model(false, "scripted", TWO), "scripted-not-driven"),
        (model(true, "none", TWO), "model-invalid"),
        (model(true, "scripted", "{\"x\":1}"), "script-invalid"),
        (
            model(true, "scripted", "{\"fail\":true,\"fail\":true}"),
            "script-invalid",
        ),
        (
            model(true, "scripted", "{\"content\":\"hi\"}\n{\"fail\":true}\n"),
            "script-invalid",
        ),
    ] {
        let r = w.call("sessions.create", p).await;
        assert_eq!(r["error"]["code"], json!(REFUSED));
        assert_eq!(reason(&r), why);
    }
    assert_eq!(
        f.fake.started.lock().unwrap().len(),
        1,
        "nothing else started"
    );
    assert_eq!(
        f.events()[control.len()..],
        [
            "rpc.request",
            "session.refuse",
            "rpc.request",
            "session.refuse",
            "rpc.request",
            "session.refuse",
            "rpc.request",
            "session.refuse",
            "rpc.request",
            "session.refuse",
        ]
    );
    let last = f.sink.last("session.refuse");
    assert!(
        last["detail"].as_str().unwrap().contains("turn 2: follows"),
        "{last}"
    );
}

#[tokio::test]
async fn the_request_entry_has_the_scripts_size_and_hash_never_its_text() {
    let f = fx("drive-entry");
    let mut w = f.connect();
    let secret = "{\"content\":\"classified words\"}";
    let r = w
        .call("sessions.create", model(true, "scripted", secret))
        .await;
    assert_eq!(r["result"]["id"], json!("s-new"), "{r}");
    let args = f.rows()[0].args.clone();
    assert_eq!(args["script_bytes"], json!(secret.len()));
    assert_eq!(args["script_sha256"].as_str().unwrap().len(), 64);
    assert!(!args.to_string().contains("classified"), "{args}");
    let scripts = f.fake.scripts.lock().unwrap();
    assert_eq!(scripts.len(), 1);
    assert_eq!(scripts[0].as_ref().unwrap().turns.len(), 1);
}

#[tokio::test]
async fn a_create_without_a_model_starts_without_a_script() {
    let f = fx("drive-nomodel");
    let r = f
        .connect()
        .call("sessions.create", json!({"manifest": MANIFEST}))
        .await;
    assert_eq!(r["result"]["id"], json!("s-new"));
    assert_eq!(*f.fake.scripts.lock().unwrap(), [None]);
}
