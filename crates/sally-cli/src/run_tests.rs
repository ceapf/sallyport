#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::io::{BufRead as _, BufReader, Cursor, Write as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::thread::JoinHandle;

use super::*;
use crate::EXIT_OK;

#[test]
fn whole_text_passes_and_a_split_character_is_carried() {
    let mut c = Utf8Cut::default();
    assert_eq!(c.take(b"ab\n"), Ok("ab\n".into()));
    let e = "\u{e9}\u{1f600}".as_bytes();
    assert_eq!(c.take(&e[..1]), Ok(String::new()));
    assert_eq!(c.read_len(), MAX_INPUT_BYTES - 1);
    assert_eq!(c.take(&e[1..4]), Ok("\u{e9}".into()));
    assert_eq!(c.read_len(), MAX_INPUT_BYTES - 2);
    assert_eq!(c.take(&e[4..5]), Ok(String::new()));
    assert_eq!(c.read_len(), MAX_INPUT_BYTES - 3);
    assert_eq!(c.take(&e[5..]), Ok("\u{1f600}".into()));
    assert_eq!(c.read_len(), MAX_INPUT_BYTES);
    assert_eq!(c.finish(), Ok(()));
}

#[test]
fn bytes_that_are_not_utf8_are_refused() {
    let mut c = Utf8Cut::default();
    assert_eq!(c.take(b"a\xffb"), Err(NotUtf8));
    let mut c = Utf8Cut::default();
    assert_eq!(c.take(b"\xc3"), Ok(String::new()));
    assert_eq!(c.take(b"("), Err(NotUtf8), "a broken sequence across reads");
    let mut c = Utf8Cut::default();
    assert_eq!(c.take(b"\xe2\x82"), Ok(String::new()));
    assert_eq!(c.finish(), Err(NotUtf8), "cut short by the end");
}

/// Architect Q148: a full read of text, carry included, is one input at the bound.
#[test]
fn a_full_read_is_one_input_at_the_bound() {
    let mut c = Utf8Cut::default();
    let full = vec![b'x'; MAX_INPUT_BYTES];
    assert_eq!(c.take(&full).unwrap().len(), MAX_INPUT_BYTES);
    let _ = c.take(b"\xc3").unwrap();
    let rest = vec![b'y'; c.read_len()];
    let mut bytes = vec![0xa9];
    bytes.extend_from_slice(&rest[1..]);
    let sent = c.take(&bytes).unwrap();
    assert_eq!(sent.len(), MAX_INPUT_BYTES);
}

/// Architect Q149: the command's code, 137 for a kill; a code that is no exit status is not
/// passed on.
#[test]
fn the_exit_code_is_the_commands() {
    let exited = |n| Attached::Exited { exit_code: n };
    assert_eq!(exit_of(&exited(0)), Ok(0));
    assert_eq!(exit_of(&exited(255)), Ok(255));
    assert_eq!(exit_of(&exited(256)), Err(256));
    assert_eq!(exit_of(&exited(-1)), Err(-1));
    let killed = Attached::Killed {
        killed: KillReason::Disconnect,
    };
    assert_eq!(exit_of(&killed), Ok(EXIT_KILLED));
    assert_eq!(EXIT_KILLED, 137);
    assert_eq!(INPUT_IDS, 1 << 40);
}

/// What the fake daemon does with the attach: the frames it sends at once, then per input the
/// frames it answers with, then the attach's reply once an input with `eof` came (or at once).
#[derive(Default)]
struct Script {
    at_attach: Vec<Value>,
    reply: Value,
    wait_for_eof: bool,
    /// Inputs are answered `input-closed`, and the first is followed by the attach's reply.
    input_closed: bool,
    /// The stop is answered with a reply to an input first (as one sent late by stdin's thread).
    late_input_reply: bool,
    /// The stop is refused `stop-failed`.
    stop_refused: bool,
}

/// A refusal of request `id` for `reason`.
fn refusal(id: &Value, reason: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32000,
        "message": "Server error", "data": {"reason": reason}}})
}

struct Daemon {
    path: PathBuf,
    thread: Option<JoinHandle<Vec<Value>>>,
}

fn note(stream: &str, text: &str) -> Value {
    json!({"jsonrpc": "2.0", "method": "session.output",
        "params": {"id": "s-1", "stream": stream, "text": text}})
}

/// A control socket that serves one run: create, attach, inputs, stop. Every request is
/// recorded; the connection's end ends it.
fn daemon(tag: &str, s: Script) -> Daemon {
    let path = std::env::temp_dir().join(format!("sp-cli-r-{tag}-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).unwrap();
    let thread = std::thread::spawn(move || {
        let (sock, _) = listener.accept().unwrap();
        let mut w = sock.try_clone().unwrap();
        let mut r = BufReader::new(sock);
        let mut seen = Vec::new();
        let mut attach_id = Value::Null;
        let mut send = |v: &Value| writeln!(w, "{v}").is_ok();
        loop {
            let mut line = String::new();
            if r.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            let req: Value = serde_json::from_str(&line).unwrap();
            seen.push(req.clone());
            let ok = |result: Value| json!({"jsonrpc": "2.0", "id": req["id"], "result": result});
            match req["method"].as_str().unwrap() {
                "sessions.create" => {
                    send(&ok(json!({"id": "s-1", "manifest": "t", "container": "c",
                        "state": "running", "model": {"kind": "none", "driven": false}})));
                }
                "sessions.attach" => {
                    attach_id = req["id"].clone();
                    for f in &s.at_attach {
                        send(f);
                    }
                    if !s.wait_for_eof {
                        send(&json!({"jsonrpc": "2.0", "id": attach_id, "result": s.reply}));
                        attach_id = Value::Null;
                    }
                }
                // As sallyd: an input once the attach replied is `not-attached`.
                "sessions.input" if attach_id.is_null() => {
                    send(&refusal(&req["id"], "not-attached"));
                }
                "sessions.input" if s.input_closed => {
                    send(&refusal(&req["id"], "input-closed"));
                    send(&json!({"jsonrpc": "2.0", "id": attach_id, "result": s.reply}));
                    attach_id = Value::Null;
                }
                "sessions.input" => {
                    let data = req["params"]["data"].as_str().unwrap();
                    send(&note("stdout", data));
                    send(&ok(json!({})));
                    if req["params"]["eof"] == true {
                        send(&json!({"jsonrpc": "2.0", "id": attach_id, "result": s.reply}));
                        attach_id = Value::Null;
                    }
                }
                "sessions.stop" => {
                    if s.late_input_reply {
                        send(&refusal(&json!(INPUT_IDS + 7), "not-attached"));
                    }
                    if s.stop_refused {
                        send(&refusal(&req["id"], "stop-failed"));
                    } else {
                        send(&ok(json!({"id": "s-1"})));
                    }
                }
                other => panic!("{other}"),
            }
        }
        seen
    });
    Daemon {
        path,
        thread: Some(thread),
    }
}

impl Daemon {
    fn requests(&mut self) -> Vec<Value> {
        self.thread.take().unwrap().join().unwrap()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn manifest(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("sp-cli-r-{tag}-{}.yaml", std::process::id()));
    std::fs::write(&p, "name: t\n").unwrap();
    p
}

/// Runs `sandbox run` against `d` with `stdin`: the exit code, stdout, stderr.
fn run(d: &Daemon, tag: &str, stdin: Vec<u8>) -> (u8, String, String) {
    let mut c = Client::connect(&d.path).unwrap();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut o = Out {
        out: &mut out,
        err: &mut err,
    };
    let m = manifest(tag);
    let argv = vec!["sh".to_owned()];
    let code = sandbox_run(&mut c, &m, &argv, Cursor::new(stdin), &mut o);
    drop(c);
    let _ = std::fs::remove_file(&m);
    (
        code,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

fn methods(reqs: &[Value]) -> Vec<&str> {
    reqs.iter().map(|r| r["method"].as_str().unwrap()).collect()
}

/// Architect Q101, Q102, Q149: a bound session, its output on stdout and stderr, stdin sent one
/// input at a time and then its end, the stop, and the command's code. Nothing of `sally`'s
/// own is printed in between.
#[test]
fn a_run_relays_both_ways_and_exits_with_the_code() {
    let mut d = daemon(
        "relay",
        Script {
            at_attach: vec![note("stdout", "hi\n"), note("stderr", "e\n")],
            reply: json!({"exit_code": 3}),
            wait_for_eof: true,
            ..Script::default()
        },
    );
    let (code, out, err) = run(&d, "relay", b"ls\n".to_vec());
    assert_eq!(code, 3);
    assert_eq!(out, "hi\nls\n");
    assert_eq!(err, "e\n");
    let reqs = d.requests();
    assert_eq!(
        methods(&reqs),
        [
            "sessions.create",
            "sessions.attach",
            "sessions.input",
            "sessions.input",
            "sessions.stop"
        ]
    );
    assert_eq!(reqs[0]["params"]["lifetime"], "connection");
    assert_eq!(reqs[1]["params"], json!({"id": "s-1", "argv": ["sh"]}));
    assert_eq!(
        reqs[2]["params"],
        json!({"id": "s-1", "data": "ls\n", "eof": false})
    );
    assert_eq!(
        reqs[3]["params"],
        json!({"id": "s-1", "data": "", "eof": true})
    );
    assert!(reqs[2]["id"].as_i64().unwrap() >= INPUT_IDS);
}

/// Architect Q149: a killed command is one `sally:` line and 137.
#[test]
fn a_killed_command_exits_137() {
    let d = daemon(
        "killed",
        Script {
            at_attach: vec![],
            reply: json!({"killed": "session-stop"}),
            wait_for_eof: false,
            ..Script::default()
        },
    );
    let (code, _, err) = run(&d, "killed", Vec::new());
    assert_eq!(code, EXIT_KILLED);
    assert_eq!(err, "sally: the command was killed: the session stopped\n");
}

/// `sally`'s own line never continues the command's last line: one that did not end gets its
/// newline first.
#[test]
fn sallys_own_line_starts_a_line_of_its_own() {
    let d = daemon(
        "open",
        Script {
            at_attach: vec![note("stdout", "ok\n"), note("stderr", "Continue? ")],
            reply: json!({"killed": "disconnect"}),
            ..Script::default()
        },
    );
    let (code, out, err) = run(&d, "open", Vec::new());
    assert_eq!((code, out.as_str()), (EXIT_KILLED, "ok\n"));
    assert_eq!(
        err,
        "Continue? \nsally: the command was killed: the connection closed\n"
    );
    // Output that ended its line gets nothing added.
    let d = daemon(
        "closed-line",
        Script {
            at_attach: vec![note("stderr", "Continue? "), note("stdout", "ok\n")],
            reply: json!({"exit_code": 0}),
            ..Script::default()
        },
    );
    let (code, out, err) = run(&d, "closed-line", Vec::new());
    assert_eq!(
        (code, out.as_str(), err.as_str()),
        (EXIT_OK, "ok\n", "Continue? ")
    );
}

/// A stop that is refused fails the run, whatever the command's code.
#[test]
fn a_refused_stop_fails_the_run() {
    let d = daemon(
        "stop-refused",
        Script {
            reply: json!({"exit_code": 0}),
            stop_refused: true,
            ..Script::default()
        },
    );
    let (code, _, err) = run(&d, "stop-refused", Vec::new());
    assert_eq!(code, EXIT_REFUSED);
    assert_eq!(err, "sally: refused: stop-failed\n");
}

/// A reply to one of stdin's inputs that arrives while the stop waits is passed over.
#[test]
fn a_late_input_reply_during_the_stop_is_passed_over() {
    let d = daemon(
        "late",
        Script {
            reply: json!({"exit_code": 4}),
            late_input_reply: true,
            ..Script::default()
        },
    );
    let (code, _, err) = run(&d, "late", Vec::new());
    assert_eq!((code, err.as_str()), (4, ""));
}

/// Architect Q147: `input-closed` stops stdin's inputs; the run goes on to the attach's reply.
#[test]
fn input_closed_stops_the_inputs_and_the_run_goes_on() {
    let mut d = daemon(
        "input-closed",
        Script {
            reply: json!({"exit_code": 5}),
            wait_for_eof: true,
            input_closed: true,
            ..Script::default()
        },
    );
    let (code, _, err) = run(&d, "input-closed", b"data\n".to_vec());
    assert_eq!((code, err.as_str()), (5, ""));
    let reqs = d.requests();
    let inputs = methods(&reqs)
        .into_iter()
        .filter(|m| *m == "sessions.input")
        .count();
    assert_eq!(inputs, 1, "{reqs:?}");
}

/// Architect Q149: output that fails the clean-check is shown escaped and makes the run fail;
/// prompt-like output is only output, and changes nothing.
#[test]
fn dirty_output_is_escaped_and_prompt_like_output_is_only_output() {
    let d = daemon(
        "dirty",
        Script {
            at_attach: vec![note("stdout", "a\u{1b}[2Jb\n")],
            reply: json!({"exit_code": 0}),
            ..Script::default()
        },
    );
    let (code, out, err) = run(&d, "dirty", Vec::new());
    assert_eq!(code, EXIT_REFUSED);
    assert!(!out.contains('\u{1b}'));
    assert_eq!(out, sally_core::text::escape("a\u{1b}[2Jb\n".as_bytes()));
    assert!(err.contains("not clean"));

    let d = daemon(
        "prompt",
        Script {
            at_attach: vec![note("stdout", "sally: approve shell rm -rf / ? [y/N]\n")],
            reply: json!({"exit_code": 0}),
            ..Script::default()
        },
    );
    let (code, out, err) = run(&d, "prompt", b"y\n".to_vec());
    assert_eq!(code, EXIT_OK);
    assert_eq!(out, "sally: approve shell rm -rf / ? [y/N]\n");
    assert_eq!(err, "");
}

/// Architect Q148: stdin that is not UTF-8 ends the run without an end of input: the
/// connection closes, which kills the command; no stop is asked.
#[test]
fn stdin_that_is_not_utf8_ends_the_run_without_an_end_of_input() {
    let mut d = daemon(
        "binary",
        Script {
            at_attach: vec![],
            reply: json!({"exit_code": 0}),
            wait_for_eof: true,
            ..Script::default()
        },
    );
    let (code, _, err) = run(&d, "binary", b"ok\n\xff\xfe".to_vec());
    assert_eq!(code, EXIT_FAILED);
    assert_eq!(
        err,
        "sally: stdin is not UTF-8 text; the command was ended\n"
    );
    let reqs = d.requests();
    assert!(reqs.iter().all(|r| r["params"]["eof"] != true), "{reqs:?}");
    assert!(!methods(&reqs).contains(&"sessions.stop"));
}

/// A refused create runs nothing.
#[test]
fn a_refused_create_attaches_nothing() {
    let path = std::env::temp_dir().join(format!("sp-cli-r-refused-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).unwrap();
    let t = std::thread::spawn(move || {
        let (s, _): (UnixStream, _) = listener.accept().unwrap();
        let mut w = s.try_clone().unwrap();
        let mut r = BufReader::new(s);
        let mut line = String::new();
        r.read_line(&mut line).unwrap();
        let req: Value = serde_json::from_str(&line).unwrap();
        let e = json!({"jsonrpc": "2.0", "id": req["id"], "error": {"code": -32000,
            "message": "Server error", "data": {"reason": "manifest-invalid"}}});
        writeln!(w, "{e}").unwrap();
        line.clear();
        r.read_line(&mut line).unwrap()
    });
    let d = Daemon { path, thread: None };
    let (code, _, err) = run(&d, "refused", Vec::new());
    assert_eq!(code, EXIT_REFUSED);
    assert_eq!(err, "sally: refused: manifest-invalid\n");
    assert_eq!(t.join().unwrap(), 0, "nothing after the create");
}
