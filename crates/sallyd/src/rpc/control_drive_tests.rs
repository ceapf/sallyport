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
async fn a_session_not_declared_driven_has_no_drive_methods() {
    let f = fx("drive-none");
    let own = f.session("s-1");
    let mut w = f.connect();
    let r = w.call("sessions.drive", json!({"id": "s-1"})).await;
    assert_eq!(r["error"]["code"], json!(REFUSED));
    assert_eq!(reason(&r), "not-driven");
    assert_eq!(f.events(), ["rpc.request", "session.refuse"]);
    assert_eq!(
        refused(&f, "session.refuse"),
        json!({"method": "sessions.drive", "id": "s-1", "reason": "not-driven",
               "client": client()})
    );
    assert!(own.events().is_empty(), "nothing is written to the session");
    let r = w.call("sessions.drive", json!({"id": "s-9"})).await;
    assert_eq!(reason(&r), "unknown-session");
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
async fn a_second_connection_is_refused_and_a_closed_driver_leaves_the_seat_gone() {
    let f = fx("drive-seat");
    let (own, _) = driven(&f, "s-1", TWO);
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

#[tokio::test]
async fn a_connection_that_watches_cannot_take_the_seat() {
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
async fn a_connection_in_the_driver_seat_cannot_answer_an_approval() {
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
}

#[tokio::test]
async fn drive_takes_a_session_id_and_nothing_else() {
    let f = fx("drive-params");
    let (own, calls) = driven(&f, "s-1", TWO);
    let mut w = f.connect();
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
    assert!(calls.lock().unwrap().is_empty() && own.events().is_empty());
}

fn model(driven: bool, kind: &str, script: &str) -> Value {
    json!({"manifest": MANIFEST, "model": {"kind": kind, "script": script, "driven": driven}})
}

#[tokio::test]
async fn a_model_is_refused_unless_it_is_a_scripted_one_declared_driven_with_a_good_script() {
    let f = fx("drive-create");
    let mut w = f.connect();
    for (p, why) in [
        (model(false, "scripted", TWO), "scripted-not-driven"),
        (model(true, "none", TWO), "model-invalid"),
        (model(true, "scripted", "{\"x\":1}"), "script-invalid"),
        (
            model(true, "scripted", "{\"fail\":true,\"fail\":true}"),
            "script-invalid",
        ),
    ] {
        let r = w.call("sessions.create", p).await;
        assert_eq!(r["error"]["code"], json!(REFUSED));
        assert_eq!(reason(&r), why);
    }
    assert!(f.fake.started.lock().unwrap().is_empty(), "nothing started");
    assert_eq!(
        f.events(),
        [
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
