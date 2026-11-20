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
    /// The connection ends after the attach's frames, with no reply.
    close_at_attach: bool,
    /// Inputs are refused for this reason, and the first is followed by the attach's reply.
    input_refused: Option<&'static str>,
    /// Frames sent before the stop's answer.
    before_stop: Vec<Value>,
    /// The stop is refused `stop-failed`.
    stop_refused: bool,
    /// The attach's reply is a refusal for this reason instead of `reply`.
    attach_refused: Option<&'static str>,
}

/// A successful reply to request `id`.
fn reply_to(id: i64) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": {}})
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

/// How long a fake waits for the client's next request before it gives up and closes the
/// connection. A real request comes within milliseconds; a client that never sends one (an
/// input the pump never sends, say) then fails its test well inside cargo-mutants' 20 s minimum
/// timeout instead of hanging it.
const FAKE_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// Whether a read ended at [`FAKE_WAIT`] (Linux reports a socket read timeout as `WouldBlock`).
fn timed_out(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
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
        sock.set_read_timeout(Some(FAKE_WAIT)).unwrap();
        let mut w = sock.try_clone().unwrap();
        let mut r = BufReader::new(sock);
        let mut seen = Vec::new();
        let mut attach_id = Value::Null;
        let mut send = |v: &Value| writeln!(w, "{v}").is_ok();
        loop {
            let mut line = String::new();
            match r.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {}
                // The client neither sent nor went: `requests` fails the test.
                Err(e) if timed_out(&e) => panic!("the client neither sent nor went: {e}"),
                Err(_) => break,
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
                    if s.close_at_attach {
                        break;
                    }
                    if !s.wait_for_eof {
                        send(&match s.attach_refused {
                            Some(why) => refusal(&attach_id, why),
                            None => json!({"jsonrpc": "2.0", "id": attach_id, "result": s.reply}),
                        });
                        attach_id = Value::Null;
                    }
                }
                // As sallyd: an input once the attach replied is `not-attached`.
                "sessions.input" if attach_id.is_null() => {
                    send(&refusal(&req["id"], "not-attached"));
                }
                "sessions.input" if s.input_refused.is_some() => {
                    send(&refusal(&req["id"], s.input_refused.unwrap_or_default()));
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
                    for f in &s.before_stop {
                        send(f);
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
    /// A test that never asked for the requests still learns how its fake ended: a fake that
    /// gave up on a client which neither sent nor went fails it.
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        if let Some(t) = self.thread.take()
            && t.join().is_err()
            && !std::thread::panicking()
        {
            panic!("the fake daemon failed (see its panic above)");
        }
    }
}

/// The manifest text a run sends: the launch gate that reads and checks it is tested through the
/// binary (`tests/consent.rs`).
const MANIFEST: &str = "name: t\n";

/// Runs `sandbox run` against `d` with `stdin`: the exit code, stdout, stderr.
fn run(d: &Daemon, tag: &str, stdin: Vec<u8>) -> (u8, String, String) {
    run_with(d, tag, Cursor::new(stdin))
}

/// [`run`] with any stdin. `_tag` names the case at the call (it once named a manifest file).
fn run_with(d: &Daemon, _tag: &str, stdin: impl Read + Send + 'static) -> (u8, String, String) {
    let mut c = Client::connect(&d.path).unwrap();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut o = Out {
        out: &mut out,
        err: &mut err,
    };
    let argv = vec!["sh".to_owned()];
    let code = sandbox_run(&mut c, MANIFEST, &argv, stdin, &mut o);
    drop(c);
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
            before_stop: vec![refusal(&json!(INPUT_IDS + 7), "not-attached")],
            ..Script::default()
        },
    );
    let (code, _, err) = run(&d, "late", Vec::new());
    assert_eq!((code, err.as_str()), (4, ""));
}

/// A reply to no request of the run, during the attach or the stop, fails it: only stdin's
/// ids (from [`INPUT_IDS`]) are passed over.
#[test]
fn a_reply_to_no_request_fails_the_run() {
    let d = daemon(
        "stray-attach",
        Script {
            at_attach: vec![reply_to(INPUT_IDS - 1)],
            reply: json!({"exit_code": 0}),
            wait_for_eof: true,
            ..Script::default()
        },
    );
    let (code, _, err) = run(&d, "stray-attach", Vec::new());
    assert_eq!(code, EXIT_FAILED);
    assert_eq!(err, "sally: sallyd sent an unexpected frame\n");

    let d = daemon(
        "stray-stop",
        Script {
            reply: json!({"exit_code": 0}),
            before_stop: vec![reply_to(INPUT_IDS - 1)],
            ..Script::default()
        },
    );
    let (code, _, err) = run(&d, "stray-stop", Vec::new());
    assert_eq!(code, EXIT_REFUSED);
    assert_eq!(err, "sally: sallyd sent an unexpected frame\n");
}

/// A connection that ends during the attach is said to have closed, never blamed on stdin.
#[test]
fn a_connection_closed_during_the_attach_is_said_so() {
    let d = daemon(
        "closed",
        Script {
            close_at_attach: true,
            ..Script::default()
        },
    );
    let (code, _, err) = run(&d, "closed", Vec::new());
    assert_eq!(code, EXIT_FAILED);
    assert_eq!(err, "sally: sallyd closed the connection\n");
}

/// An input refused for any reason but `input-closed` fails the run.
#[test]
fn an_input_refused_otherwise_fails_the_run() {
    let d = daemon(
        "input-pending",
        Script {
            reply: json!({"exit_code": 0}),
            wait_for_eof: true,
            input_refused: Some("input-pending"),
            ..Script::default()
        },
    );
    let (code, _, err) = run(&d, "input-pending", b"x\n".to_vec());
    assert_eq!(code, EXIT_REFUSED);
    assert_eq!(err, "sally: refused: input-pending\n");
}

/// Stdin as a list of reads: bytes, or an error of a kind.
struct Reads(std::collections::VecDeque<Result<Vec<u8>, std::io::ErrorKind>>);

impl Read for Reads {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.0.pop_front() {
            None => Ok(0),
            Some(Err(kind)) => Err(kind.into()),
            Some(Ok(bytes)) => {
                buf[..bytes.len()].copy_from_slice(&bytes);
                Ok(bytes.len())
            }
        }
    }
}

/// The inputs a run sent, as `(data, eof)`.
fn inputs(reqs: &[Value]) -> Vec<(String, bool)> {
    reqs.iter()
        .filter(|r| r["method"] == "sessions.input")
        .map(|r| {
            let p = &r["params"];
            (p["data"].as_str().unwrap().to_owned(), p["eof"] == true)
        })
        .collect()
}

/// An interrupted read is tried again; any other read error ends stdin; a read that brings
/// only part of a character sends nothing until the rest comes.
#[test]
fn stdin_reads_retry_an_interrupt_end_at_an_error_and_wait_for_whole_characters() {
    use std::io::ErrorKind::{Interrupted, Other};
    let e = "\u{e9}".as_bytes().to_vec();
    let script = || Script {
        reply: json!({"exit_code": 0}),
        wait_for_eof: true,
        ..Script::default()
    };
    let mut d = daemon("reads", script());
    let reads = Reads(
        [
            Err(Interrupted),
            Ok(b"a".to_vec()),
            Ok(e[..1].to_vec()),
            Ok(e[1..].to_vec()),
            Err(Other),
            Ok(b"never".to_vec()),
        ]
        .into(),
    );
    // (The fake echoes the input as output, unescaped: only what was sent counts here.)
    let _ = run_with(&d, "reads", reads);
    assert_eq!(
        inputs(&d.requests()),
        [
            ("a".to_owned(), false),
            ("\u{e9}".to_owned(), false),
            (String::new(), true)
        ]
    );
}

/// Architect Q147: `input-closed` stops stdin's inputs; the run goes on to the attach's reply.
#[test]
fn input_closed_stops_the_inputs_and_the_run_goes_on() {
    let mut d = daemon(
        "input-closed",
        Script {
            reply: json!({"exit_code": 5}),
            wait_for_eof: true,
            input_refused: Some("input-closed"),
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

/// Output that fails the clean-check, and its clean twin.
const DIRTY: &str = "a\u{1b}[2Jb\n";
const CLEAN: &str = "ok\n";
/// `sally`'s line for dirty output.
const NOT_CLEAN: &str = "sally: some output was not clean; it is shown escaped\n";
/// What stderr starts with after [`DIRTY`]: shown escaped, its newline too, it does not end its
/// line, so `sally` ends it before its own lines.
const AFTER_DIRTY: &str = "\n";

/// One way a run can end after its output: the script after the output, the clean run's code
/// and own stderr, and whether the run asks for the stop.
struct End {
    tag: &'static str,
    script: fn(Vec<Value>) -> Script,
    code: u8,
    own: &'static str,
    stops: bool,
}

/// The attach sends `at_attach`, then replies `reply` at once.
fn replying(reply: Value, at_attach: Vec<Value>) -> Script {
    Script {
        at_attach,
        reply,
        ..Script::default()
    }
}

const ENDS: [End; 7] = [
    End {
        tag: "exit-3",
        script: |a| replying(json!({"exit_code": 3}), a),
        code: 3,
        own: "",
        stops: true,
    },
    End {
        tag: "exit-255",
        script: |a| replying(json!({"exit_code": 255}), a),
        code: 255,
        own: "",
        stops: true,
    },
    End {
        tag: "killed",
        script: |a| replying(json!({"killed": "session-stop"}), a),
        code: EXIT_KILLED,
        own: "sally: the command was killed: the session stopped\n",
        stops: true,
    },
    End {
        tag: "out-of-range",
        script: |a| replying(json!({"exit_code": 300}), a),
        code: EXIT_FAILED,
        own: "sally: sallyd sent an exit code out of range (300)\n",
        stops: false,
    },
    End {
        tag: "closed",
        script: |at_attach| Script {
            at_attach,
            close_at_attach: true,
            ..Script::default()
        },
        code: EXIT_FAILED,
        own: "sally: sallyd closed the connection\n",
        stops: false,
    },
    End {
        tag: "stray",
        script: |mut at_attach| {
            at_attach.push(reply_to(INPUT_IDS - 1));
            Script {
                at_attach,
                wait_for_eof: true,
                ..Script::default()
            }
        },
        code: EXIT_FAILED,
        own: "sally: sallyd sent an unexpected frame\n",
        stops: false,
    },
    End {
        tag: "attach-refused",
        script: |at_attach| Script {
            at_attach,
            attach_refused: Some("exec-failed"),
            ..Script::default()
        },
        code: EXIT_REFUSED,
        own: "sally: refused: exec-failed\n",
        stops: false,
    },
];

/// Architect Q149, Q204: dirty output exits `EXIT_REFUSED` however the run ended (the
/// command's code, a kill, a code out of range, a lost connection, a stray frame, a refused
/// attach). The run's own line comes first and the not-clean line last; a clean run keeps its
/// code and prints no not-clean line. Only a run that got its reply asks for the stop.
#[test]
fn dirty_output_exits_refused_however_the_run_ended() {
    for e in &ENDS {
        for (dirty, text) in [(true, DIRTY), (false, CLEAN)] {
            let tag = format!("{}-{dirty}", e.tag);
            let mut d = daemon(&tag, (e.script)(vec![note("stdout", text)]));
            // Stdin sends nothing until the run is over: an unread input at the fake's close
            // would reset the connection instead of ending it. Bounded, so a run that never
            // ends (a mutant that takes the stray reply as an input's) fails, never hangs.
            let (open, stdin) = UnixStream::pair().unwrap();
            stdin
                .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .unwrap();
            let (code, _, err) = run_with(&d, &tag, stdin);
            drop(open);
            let reqs = d.requests();
            if dirty {
                assert_eq!(code, EXIT_REFUSED, "{tag}");
                assert_eq!(err, format!("{AFTER_DIRTY}{}{NOT_CLEAN}", e.own), "{tag}");
            } else {
                assert_eq!(code, e.code, "{tag}");
                assert_eq!(err, e.own, "{tag}");
            }
            assert_eq!(
                methods(&reqs).contains(&"sessions.stop"),
                e.stops,
                "{tag}: {reqs:?}"
            );
        }
    }
}

/// Stdout that signals once something was written to it.
struct Signalling(Vec<u8>, mpsc::SyncSender<()>);

impl std::io::Write for Signalling {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.extend_from_slice(b);
        let _ = self.1.try_send(());
        Ok(b.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Stdin whose one read waits until the output was shown (at most 10 s, so a run that shows
/// nothing fails instead of hanging), then brings bytes that are not UTF-8.
struct AfterShown(mpsc::Receiver<()>);

impl Read for AfterShown {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let _ = self.0.recv_timeout(std::time::Duration::from_secs(10));
        buf[0] = 0xff;
        Ok(1)
    }
}

/// Architect Q148, Q204: stdin that turns out not to be UTF-8 after dirty output exits
/// `EXIT_REFUSED`, its own line first; after clean output, `EXIT_FAILED`. No stop is asked.
#[test]
fn dirty_output_then_stdin_not_utf8_exits_refused() {
    for (dirty, text) in [(true, DIRTY), (false, CLEAN)] {
        let tag = format!("binary-after-{dirty}");
        let mut d = daemon(
            &tag,
            Script {
                at_attach: vec![note("stdout", text)],
                reply: json!({"exit_code": 0}),
                wait_for_eof: true,
                ..Script::default()
            },
        );
        // Stdin turns invalid only once the output was written: `show` marks it dirty on the
        // same thread before the relay reads again.
        let (shown, wait) = mpsc::sync_channel(1);
        let mut c = Client::connect(&d.path).unwrap();
        let mut out = Signalling(Vec::new(), shown);
        let mut err = Vec::new();
        let code = sandbox_run(
            &mut c,
            MANIFEST,
            &["sh".to_owned()],
            AfterShown(wait),
            &mut Out {
                out: &mut out,
                err: &mut err,
            },
        );
        drop(c);
        let err = String::from_utf8(err).unwrap();
        let own = "sally: stdin is not UTF-8 text; the command was ended\n";
        if dirty {
            assert_eq!(
                (code, err),
                (EXIT_REFUSED, format!("{AFTER_DIRTY}{own}{NOT_CLEAN}"))
            );
        } else {
            assert_eq!((code, err.as_str()), (EXIT_FAILED, own));
        }
        assert!(!methods(&d.requests()).contains(&"sessions.stop"));
    }
}

/// A refused stop makes the code at least `EXIT_REFUSED`, and keeps a higher one.
#[test]
fn a_refused_stop_keeps_a_higher_code() {
    let d = daemon(
        "stop-refused-3",
        Script {
            reply: json!({"exit_code": 3}),
            stop_refused: true,
            ..Script::default()
        },
    );
    let (code, _, err) = run(&d, "stop-refused-3", Vec::new());
    assert_eq!((code, err.as_str()), (3, "sally: refused: stop-failed\n"));
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
        s.set_read_timeout(Some(FAKE_WAIT)).unwrap();
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
