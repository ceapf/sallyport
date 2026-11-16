#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::UnixListener;
use std::thread::JoinHandle;

use serde_json::Value;

use super::*;
use crate::{EXIT_OK, EXIT_REFUSED};

/// A control socket that answers each request with the next of `replies` (a result, or an
/// error object), and records every request it read. A request past the replies is not
/// answered and the connection closes.
struct Fake {
    path: std::path::PathBuf,
    thread: Option<JoinHandle<Vec<Value>>>,
}

fn daemon(tag: &str, replies: Vec<Result<Value, Value>>) -> Fake {
    let path = std::env::temp_dir().join(format!("sp-cli-d-{tag}-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).unwrap();
    let thread = std::thread::spawn(move || {
        let (s, _) = listener.accept().unwrap();
        let mut w = s.try_clone().unwrap();
        let mut r = BufReader::new(s);
        let mut seen = Vec::new();
        for reply in replies {
            let mut line = String::new();
            if r.read_line(&mut line).unwrap() == 0 {
                break;
            }
            let req: Value = serde_json::from_str(&line).unwrap();
            let body = match reply {
                Ok(result) => json!({"jsonrpc": "2.0", "id": req["id"], "result": result}),
                Err(error) => json!({"jsonrpc": "2.0", "id": req["id"], "error": error}),
            };
            seen.push(req);
            writeln!(w, "{body}").unwrap();
        }
        seen
    });
    Fake {
        path,
        thread: Some(thread),
    }
}

impl Fake {
    fn requests(&mut self) -> Vec<Value> {
        self.thread.take().unwrap().join().unwrap()
    }
}

impl Drop for Fake {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn run(f: &Fake) -> (u8, String, String) {
    let mut c = Client::connect(&f.path).unwrap();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = {
        let mut o = Out {
            out: &mut out,
            err: &mut err,
        };
        session_drive(&mut c, "s-1", &mut o)
    };
    drop(c);
    (
        code,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

fn step(turn: u32, kind: &str, rest: Value) -> Result<Value, Value> {
    let mut v = json!({"turn": turn, "kind": kind, "done": false});
    for (k, x) in rest.as_object().unwrap() {
        v[k] = x.clone();
    }
    Ok(v)
}

#[test]
fn it_asks_until_done_and_sends_only_the_session_id() {
    let mut f = daemon(
        "run",
        vec![
            step(
                1,
                "tool_calls",
                json!({"calls": [{"name": "fs.read", "result": "ok"}]}),
            ),
            step(2, "content", json!({"content": "bye", "done": true})),
        ],
    );
    let (code, out, err) = run(&f);
    assert_eq!(code, EXIT_OK, "{err}");
    assert_eq!(out, "turn 1: call fs.read -> ok\nturn 2: model says: bye\n");
    let seen = f.requests();
    assert_eq!(seen.len(), 2);
    for req in seen {
        assert_eq!(req["method"], "sessions.drive");
        assert_eq!(req["params"], json!({"id": "s-1"}), "nothing else is sent");
    }
}

#[test]
fn the_other_kinds_each_have_their_line() {
    let f = daemon(
        "kinds",
        vec![
            step(1, "tool_calls", json!({})),
            step(2, "fail", json!({})),
            step(0, "end", json!({"done": true})),
        ],
    );
    let (code, out, _) = run(&f);
    assert_eq!(code, EXIT_OK);
    assert_eq!(
        out,
        "turn 1: no calls\nturn 2: the model failed\nend of script\n"
    );
}

#[test]
fn a_refusal_is_printed_and_stops_the_loop() {
    let mut f = daemon(
        "refused",
        vec![Err(
            json!({"code": -32000, "message": "x", "data": {"reason": "not-driven"}}),
        )],
    );
    let (code, out, err) = run(&f);
    assert_eq!(code, EXIT_REFUSED);
    assert!(out.is_empty());
    assert_eq!(err, "sally: refused: not-driven\n");
    assert_eq!(f.requests().len(), 1);
}

#[test]
fn text_that_fails_the_clean_check_is_escaped_and_the_exit_says_so() {
    let f = daemon(
        "dirty",
        vec![step(
            1,
            "content",
            json!({"content": "a\u{1b}[2Jb", "done": true}),
        )],
    );
    let (code, out, _) = run(&f);
    assert_eq!(code, EXIT_REFUSED);
    assert!(!out.contains('\u{1b}'), "{out:?}");
}

#[test]
fn the_longest_script_and_its_end_fit_in_the_steps() {
    let mut steps: Vec<_> = (1..=sally_proto::MAX_TURNS as u32)
        .map(|i| step(i, "tool_calls", json!({})))
        .collect();
    steps.push(step(0, "end", json!({"done": true})));
    let mut f = daemon("longest", steps);
    let (code, out, err) = run(&f);
    assert_eq!(code, 0, "{err}");
    assert!(out.ends_with("end of script\n"), "{out}");
    assert_eq!(f.requests().len(), sally_proto::MAX_TURNS + 1);
}

#[test]
fn a_daemon_that_never_says_done_is_cut_off() {
    let steps: Vec<_> = (0..=MAX_STEPS as u32)
        .map(|i| step(i + 1, "tool_calls", json!({})))
        .collect();
    let mut f = daemon("endless", steps);
    let (code, _, err) = run(&f);
    assert_eq!(code, EXIT_FAILED);
    assert!(err.contains("more steps than a script holds"), "{err}");
    assert_eq!(f.requests().len(), MAX_STEPS);
}
