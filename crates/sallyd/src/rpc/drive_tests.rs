#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use super::*;
use crate::rpc::mcp::ToolOutcome;
use crate::rpc::testkit::{Sink, recorder};

type Seen = Arc<Mutex<Vec<String>>>;

fn call(name: &str) -> Call {
    Call {
        name: name.into(),
        arguments: Map::new(),
    }
}

fn ok(text: &str) -> Driven {
    Driven::Done(ToolOutcome {
        is_error: false,
        text: text.into(),
    })
}

/// A driver over `turns` whose calls answer `answer(name)` and are logged, in order, together
/// with the entries the sink has by then (so a test sees what was written before each call).
fn driver_with(
    turns: Vec<Turn>,
    answer: impl Fn(&str) -> Driven + Send + Sync + 'static,
) -> (Arc<Driver>, Arc<Sink>, Seen, Ops) {
    let (sink, rec) = recorder("sess-a");
    let seen: Seen = Arc::default();
    let log = Arc::clone(&seen);
    let at = Arc::clone(&sink);
    let call: CallFn = Box::new(move |name, _| {
        let entries = at.events().join(",");
        log.lock()
            .unwrap()
            .push(format!("{name} after [{entries}]"));
        let r = answer(&name);
        Box::pin(async move { r })
    });
    let ops = Ops::new();
    let d = Driver::build(turns, call, rec.driven(), ops.clone());
    (d, sink, seen, ops)
}

fn driver(turns: Vec<Turn>) -> (Arc<Driver>, Arc<Sink>, Seen, Ops) {
    driver_with(turns, |n| ok(&format!("ran {n}")))
}

#[test]
fn the_seat_is_single_use() {
    let (d, ..) = driver(Vec::new());
    let first = d.claim().unwrap();
    assert_eq!(d.claim().err(), Some(SeatRefusal::Busy));
    drop(first);
    assert_eq!(d.claim().err(), Some(SeatRefusal::Gone));
    assert_eq!(SeatRefusal::Busy.reason(), "driver-busy");
    assert_eq!(SeatRefusal::Gone.reason(), "driver-gone");
}

#[tokio::test]
async fn a_tool_turn_writes_its_entry_before_the_first_call_and_runs_calls_in_order() {
    let (d, sink, seen, _) = driver(vec![
        Turn::ToolCalls(vec![call("a"), call("b")]),
        Turn::Content("done".into()),
    ]);
    let seat = d.claim().unwrap();
    let Stepped::Step(s) = seat.step().await else {
        panic!("not a step")
    };
    assert_eq!((s.turn, s.kind, s.done), (1, TurnKind::ToolCalls, false));
    let names: Vec<_> = s.calls.iter().map(|c| (&*c.name, &*c.result)).collect();
    assert_eq!(names, [("a", "ran a"), ("b", "ran b")]);
    assert_eq!(
        *seen.lock().unwrap(),
        ["a after [drive.turn]", "b after [drive.turn]"]
    );
    let row = &sink.rows()[0];
    assert_eq!(row.args["calls"], 2);
    assert!(row.debug.contains("actor: Driver"));
}

#[tokio::test]
async fn a_content_turn_ends_the_loop_and_its_entry_holds_a_hash_never_the_text() {
    let (d, sink, _, _) = driver(vec![Turn::Content("secret text".into()), Turn::Fail]);
    let seat = d.claim().unwrap();
    let Stepped::Step(s) = seat.step().await else {
        panic!()
    };
    assert_eq!(s.kind, TurnKind::Content);
    assert_eq!(s.content.as_deref(), Some("secret text"));
    assert!(s.done);
    let args = &sink.rows()[0].args;
    assert!(!args.to_string().contains("secret text"), "{args}");
    assert_eq!(args["content_bytes"], 11);
    // `printf 'secret text' | sha256sum`
    assert_eq!(
        args["content_sha256"],
        "486a2d2abec341f9a9513329e29ea386e98b2a280d38d12a0b4a53c92ad8b26b"
    );
}

#[tokio::test]
async fn a_fail_turn_and_the_end_of_the_script() {
    let (d, sink, _, _) = driver(vec![Turn::Fail]);
    let seat = d.claim().unwrap();
    let Stepped::Step(s) = seat.step().await else {
        panic!()
    };
    assert_eq!((s.turn, s.kind, s.done), (1, TurnKind::Fail, true));
    let Stepped::Step(end) = seat.step().await else {
        panic!()
    };
    assert_eq!((end.turn, end.kind, end.done), (0, TurnKind::End, true));
    assert_eq!(sink.events(), ["drive.turn"], "the end writes nothing");
}

#[tokio::test]
async fn the_last_tool_turn_is_done() {
    let (d, ..) = driver(vec![Turn::ToolCalls(vec![call("a")])]);
    let Stepped::Step(s) = d.claim().unwrap().step().await else {
        panic!()
    };
    assert!(s.done);
}

#[tokio::test]
async fn a_refused_call_ends_the_step_and_a_tools_own_denial_does_not() {
    let (d, _, seen, _) = driver_with(
        vec![
            Turn::ToolCalls(vec![call("a"), call("b"), call("c")]),
            Turn::Fail,
        ],
        |n| match n {
            "a" => Driven::Done(ToolOutcome {
                is_error: true,
                text: "denied: not_granted".into(),
            }),
            "b" => Driven::Denied("bad-params"),
            _ => ok("never"),
        },
    );
    let seat = d.claim().unwrap();
    let Stepped::Step(s) = seat.step().await else {
        panic!()
    };
    assert_eq!(s.calls.len(), 2);
    assert_eq!(s.calls[0].result, "denied: not_granted");
    assert_eq!(s.calls[1].result, "denied: bad-params");
    assert!(s.done);
    // A refusal ends the step, not the script: the next drive runs the next turn, and the
    // refused turn's later call never runs.
    let Stepped::Step(next) = seat.step().await else {
        panic!()
    };
    assert_eq!((next.turn, next.kind), (2, TurnKind::Fail));
    assert!(!seen.lock().unwrap().iter().any(|c| c.starts_with("c ")));
}

#[tokio::test]
async fn an_unrecorded_call_closes_the_connection() {
    let (d, ..) = driver_with(vec![Turn::ToolCalls(vec![call("a")])], |_| {
        Driven::Unrecorded
    });
    assert_eq!(d.claim().unwrap().step().await, Stepped::Close);
}

#[tokio::test]
async fn a_turn_entry_that_cannot_be_written_runs_nothing_and_does_not_advance() {
    let (d, sink, seen, _) = driver(vec![Turn::ToolCalls(vec![call("a")])]);
    let seat = d.claim().unwrap();
    sink.set_failing(true);
    assert_eq!(seat.step().await, Stepped::Close);
    assert!(seen.lock().unwrap().is_empty());
    sink.set_failing(false);
    let Stepped::Step(s) = seat.step().await else {
        panic!()
    };
    assert_eq!(s.turn, 1, "the cursor stayed");
}

#[tokio::test]
async fn once_the_session_stops_a_step_is_refused_and_writes_nothing() {
    let (d, sink, seen, ops) = driver(vec![Turn::ToolCalls(vec![call("a")])]);
    let seat = d.claim().unwrap();
    ops.close();
    assert_eq!(seat.step().await, Stepped::Refused("session-stopping"));
    assert!(sink.events().is_empty() && seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn texts_are_escaped_and_cut_at_their_named_caps() {
    let over = "a".repeat(RESULT_CHARS + 50);
    let (d, ..) = driver_with(
        vec![
            Turn::ToolCalls(vec![call("t\u{1b}[31m")]),
            Turn::Content("x\u{1b}[2Jy".into()),
        ],
        move |_| ok(&over),
    );
    let seat = d.claim().unwrap();
    let Stepped::Step(s) = seat.step().await else {
        panic!()
    };
    assert!(!s.calls[0].name.contains('\u{1b}'), "{}", s.calls[0].name);
    let marker = "...(+50 bytes)";
    assert!(s.calls[0].result.ends_with(marker));
    assert_eq!(s.calls[0].result.len(), RESULT_CHARS + marker.len());
    let Stepped::Step(c) = seat.step().await else {
        panic!()
    };
    assert!(!c.content.unwrap().contains('\u{1b}'));
}

/// The step reply at its worst, serialized: every text cut at its cap from input that escapes
/// to the most JSON (backslashes, each doubled again by JSON), and the most calls a turn has.
#[test]
fn the_largest_step_fits_the_reply_budget() {
    assert_eq!(
        (CONTENT_CHARS, RESULT_CHARS, NAME_CHARS),
        (16 * 1024, 16 * 1024, 64)
    );
    let worst = |cap: usize| escape_capped(&vec![b'\\'; cap * 4], cap);
    let call = StepCall {
        name: worst(NAME_CHARS),
        result: worst(RESULT_CHARS),
    };
    let step = Step {
        turn: u32::MAX,
        kind: TurnKind::ToolCalls,
        content: Some(worst(CONTENT_CHARS)),
        calls: vec![call; crate::llm::scripted::MAX_CALLS],
        done: true,
    };
    let bytes = serde_json::to_vec(&step).unwrap().len();
    assert!(
        bytes > 2 * (CONTENT_CHARS + RESULT_CHARS),
        "{bytes}: not the worst case"
    );
    assert!(bytes < crate::rpc::control_methods::REPLY_BYTES, "{bytes}");
}

/// A call left unrecorded because the session stopped while the step ran is a refusal, not a
/// broken connection; the step's `drive.turn` was written before the stop.
#[tokio::test]
async fn a_call_cut_off_by_the_stop_refuses_the_step() {
    let (sink, rec) = recorder("sess-a");
    let ops = Ops::new();
    let closing = ops.clone();
    let answer: CallFn = Box::new(move |_, _| {
        closing.close();
        Box::pin(async { Driven::Unrecorded })
    });
    let turns = vec![Turn::ToolCalls(vec![call("a")])];
    let d = Driver::build(turns, answer, rec.driven(), ops);
    let r = d.claim().unwrap().step().await;
    assert_eq!(r, Stepped::Refused("session-stopping"));
    assert_eq!(sink.events(), ["drive.turn"]);
}
