#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::collections::VecDeque;
use std::io::{BufReader, Read};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::*;
use crate::client::{FRAME_QUEUE, Frame, spawn_reader};

/// Runs before a terminal read: frames it sends reach the client's queue at once, behind
/// whatever the reader already queued. `Send`, because `approve()` runs on a worker thread.
type Hook = Box<dyn FnMut(&SyncSender<Frame>) + Send>;

/// What the fake daemon answers one request with: frames to write, then whether to close (its
/// sending side: it still reads, so whatever the client sends after is kept).
type Handler = Box<dyn FnMut(&Value) -> (Vec<Value>, bool) + Send>;

/// How long the fake waits for the client's next request before it gives up and closes the
/// connection. A real request comes within milliseconds; a client that never sends one then fails
/// its test well inside cargo-mutants' 20 s minimum timeout instead of hanging it.
const FAKE_WAIT: Duration = Duration::from_secs(5);

/// How long a test waits for `approve()` to return. Above [`FAKE_WAIT`], so a fake that gives up
/// first fails the test with its own message; below cargo-mutants' 20 s minimum timeout, so a
/// mutant that makes `approve()` hang fails its test instead of timing it out.
const RUN_WAIT: Duration = Duration::from_secs(10);

/// Whether a read ended at [`FAKE_WAIT`] (Linux reports a socket read timeout as `WouldBlock`).
fn timed_out(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

/// A fake `sallyd` on a Unix socket: one connection, scripted replies, every request kept.
struct Fake {
    path: PathBuf,
    requests: Arc<Mutex<Vec<Value>>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Fake {
    fn new(tag: &str, mut handler: Handler) -> Self {
        let path = std::env::temp_dir().join(format!("sp-cli-{tag}-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let reqs = Arc::clone(&requests);
        let thread = std::thread::spawn(move || {
            let (s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(FAKE_WAIT)).unwrap();
            let mut w = s.try_clone().unwrap();
            for l in BufReader::new(s).lines() {
                let l = match l {
                    Ok(l) => l,
                    Err(e) => {
                        // A client that neither sends nor goes fails the test that joins this.
                        assert!(!timed_out(&e), "the client neither sent nor went: {e}");
                        return;
                    }
                };
                let req: Value = serde_json::from_str(&l).unwrap();
                reqs.lock().unwrap().push(req.clone());
                let (frames, close) = handler(&req);
                for f in frames {
                    let _ = writeln!(w, "{f}");
                }
                if close {
                    let _ = w.shutdown(std::net::Shutdown::Write);
                }
            }
        });
        Self {
            path,
            requests,
            thread: Some(thread),
        }
    }

    /// Waits until the client has gone and every request it sent is kept.
    fn join(&mut self) {
        if let Some(t) = self.thread.take() {
            t.join().unwrap();
        }
    }

    fn decides(&self) -> Vec<Value> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r["method"] == "approvals.decide")
            .map(|r| r["params"].clone())
            .collect()
    }

    fn methods(&self) -> Vec<String> {
        let reqs = self.requests.lock().unwrap();
        reqs.iter()
            .map(|r| r["method"].as_str().unwrap().to_owned())
            .collect()
    }
}

impl Drop for Fake {
    /// A test that never joined the fake still learns how it ended: a fake that gave up on a
    /// client which neither sent nor went fails it. A test already failing does not wait for the
    /// fake (its client may be held by an abandoned worker).
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        if std::thread::panicking() {
            return;
        }
        if let Some(t) = self.thread.take()
            && t.join().is_err()
        {
            panic!("the fake daemon failed (see its panic above)");
        }
    }
}

fn ok(req: &Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": req["id"], "result": result})
}

fn prompt(id: &str) -> Value {
    json!({
        "id": id, "session": "s-1", "digest": format!("d-{id}"), "truncated": false,
        "text": format!("approval {id}\n  action: run [\"ls\"]\n"),
    })
}

fn list(prompts: &[Value], complete: bool) -> Value {
    json!({"prompts": prompts, "complete": complete, "total": prompts.len() + usize::from(!complete)})
}

fn note(method: &str, params: Value) -> Value {
    json!({"jsonrpc": "2.0", "method": method, "params": params})
}

/// A daemon whose watch lists `first`; every decide is taken, and after `decides` of them the
/// connection closes (so the approver's wait for the next prompt ends).
fn daemon(tag: &str, first: Vec<Value>, decides: usize) -> Fake {
    let mut left = decides;
    Fake::new(
        tag,
        Box::new(move |req| match req["method"].as_str().unwrap() {
            "approvals.watch" => (vec![ok(req, list(&first, true))], false),
            "approvals.decide" => {
                left = left.saturating_sub(1);
                (vec![ok(req, json!({}))], left == 0)
            }
            _ => (vec![], true),
        }),
    )
}

/// A terminal that answers with `lines`, one per read, then reports end of input; `hook` runs
/// before the read it is keyed to (0 = the first).
struct Script {
    lines: VecDeque<String>,
    reads: usize,
    hook: Option<(usize, Hook)>,
    queue: SyncSender<Frame>,
}

impl Read for Script {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if let Some((at, h)) = &mut self.hook
            && *at == self.reads
        {
            h(&self.queue);
        }
        self.reads += 1;
        let Some(l) = self.lines.pop_front() else {
            return Ok(0);
        };
        let n = l.len().min(buf.len());
        buf[..n].copy_from_slice(&l.as_bytes()[..n]);
        Ok(n)
    }
}

struct Run {
    code: u8,
    shown: String,
    err: String,
    flushes: usize,
}

/// A client on `f` whose frame queue the hook can also feed.
fn client(f: &Fake) -> (Client, SyncSender<Frame>) {
    let s = UnixStream::connect(&f.path).unwrap();
    let (tx, rx) = mpsc::sync_channel(FRAME_QUEUE);
    spawn_reader(&s, tx.clone()).unwrap();
    (Client::from_parts(s, rx), tx)
}

fn run_with(f: &Fake, lines: &[&str], hook: Option<(usize, Hook)>) -> Run {
    run_bounded(client(f), lines, hook)
}

/// Runs `approve()` with the client `(c, queue)` on a terminal that types `lines`, on a worker
/// thread that owns the client, the terminal and the buffers, and waits at most [`RUN_WAIT`] for
/// it. An `approve()` that hangs (spinning without a read, or waiting on a frame queue whose
/// sender the test still holds) fails the test, and its worker is left behind.
/// `std::thread::scope` cannot bound it: a scope joins its threads before it returns, even while
/// unwinding, so it would hang with them.
fn run_bounded(x: (Client, SyncSender<Frame>), lines: &[&str], hook: Option<(usize, Hook)>) -> Run {
    run_flushing(x, lines, hook, true)
}

/// [`run_bounded`] on a terminal whose typed-ahead input can be discarded (`flush_ok`) or not.
fn run_flushing(
    (mut c, queue): (Client, SyncSender<Frame>),
    lines: &[&str],
    hook: Option<(usize, Hook)>,
    flush_ok: bool,
) -> Run {
    let lines: VecDeque<String> = lines.iter().map(|l| format!("{l}\n")).collect();
    let (done, result) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let script = Script {
            lines,
            reads: 0,
            hook,
            queue,
        };
        let mut input = BufReader::with_capacity(4096, script);
        let (mut shown, mut err, mut flushes) = (Vec::new(), Vec::new(), 0);
        let mut flush = || {
            flushes += 1;
            if flush_ok {
                Ok(())
            } else {
                Err(std::io::Error::other("tcflush failed"))
            }
        };
        let code = {
            let mut tty = Tty {
                input: &mut input,
                output: &mut shown,
                flush: &mut flush,
            };
            approve(&mut c, &mut tty, &mut err)
        };
        let _ = done.send(Run {
            code,
            shown: String::from_utf8(shown).unwrap(),
            err: String::from_utf8(err).unwrap(),
            flushes,
        });
    });
    match result.recv_timeout(RUN_WAIT) {
        // Joined, so the client is dropped (its connection shut) before the test goes on.
        Ok(run) => {
            worker.join().unwrap();
            run
        }
        Err(RecvTimeoutError::Timeout) => {
            panic!("approve() neither returned nor failed within RUN_WAIT ({RUN_WAIT:?})")
        }
        Err(RecvTimeoutError::Disconnected) => match worker.join() {
            Err(p) => std::panic::resume_unwind(p),
            Ok(()) => panic!("the approve() worker ended without its result"),
        },
    }
}

#[test]
fn answers_are_whole_words() {
    assert_eq!(parse_answer("approve\n", false), Some(Answer::Approve));
    assert_eq!(parse_answer("  deny ", false), Some(Answer::Deny));
    assert_eq!(parse_answer("deny-all", false), Some(Answer::DenyAll));
    for no in [
        "a",
        "y",
        "yes",
        "approved",
        "Approve",
        "deny all",
        "",
        "approve deny",
    ] {
        assert_eq!(parse_answer(no, false), None, "{no:?}");
    }
    assert_eq!(parse_answer("approve", true), None, "deny only");
    assert_eq!(parse_answer("deny", true), Some(Answer::Deny));
    assert_eq!(parse_answer("deny-all", true), Some(Answer::DenyAll));
}

/// Q80.4, Q80.5: `a` and `y` ask again; input is flushed before every read; the decision names
/// the prompt's id and digest.
#[test]
fn anything_but_an_answer_asks_again() {
    let f = daemon("reask", vec![prompt("p1")], 1);
    let r = run_with(&f, &["a", "y", "approve"], None);
    assert_eq!(r.code, EXIT_FAILED, "the daemon closed after the decision");
    assert_eq!(r.shown.matches("approval p1").count(), 1, "{}", r.shown);
    assert_eq!(r.shown.matches("approve, deny or deny-all? ").count(), 3);
    assert_eq!(r.flushes, 3);
    assert_eq!(
        f.decides(),
        [json!({"id": "p1", "decision": "approve", "digest": "d-p1", "full_shown": false})]
    );
}

/// Q80.3: the terminal closing denies the prompt on screen and exits non-zero.
#[test]
fn end_of_input_denies_the_prompt_on_screen() {
    let f = daemon("eof", vec![prompt("p1")], 9);
    let r = run_with(&f, &[], None);
    assert_eq!(r.code, EXIT_REFUSED);
    assert_eq!(
        f.decides(),
        [json!({"id": "p1", "decision": "deny", "digest": "d-p1", "full_shown": false})]
    );
    assert!(r.shown.contains("denied p1"), "{}", r.shown);
}

/// A terminal whose typed-ahead input cannot be discarded is not read: the `approve` it holds
/// could have been typed before the question, so the prompt on screen is denied.
#[test]
fn a_terminal_that_cannot_discard_typed_ahead_input_denies() {
    let f = daemon("noflush", vec![prompt("p1")], 9);
    let r = run_flushing(client(&f), &["approve"], None, false);
    assert_eq!(r.code, EXIT_REFUSED);
    assert_eq!(
        f.decides(),
        [json!({"id": "p1", "decision": "deny", "digest": "d-p1", "full_shown": false})]
    );
    assert!(r.shown.contains("denied p1"), "{}", r.shown);
    assert_eq!(r.flushes, 1);
}

fn queued(frame: &Value) -> Frame {
    Ok((frame.clone(), frame.to_string().len()))
}

/// Q80.6: a line typed while the prompt on screen closed is discarded: never sent for it, never
/// applied to the next prompt.
#[test]
fn a_line_for_a_closed_prompt_is_not_applied_to_the_next() {
    let f = daemon("closed", vec![prompt("p1")], 1);
    let hook: Hook = Box::new(|q| {
        q.send(queued(&note("approval.closed", json!({"id": "p1"}))))
            .unwrap();
        q.send(queued(&note("approval.requested", prompt("p2"))))
            .unwrap();
    });
    let r = run_with(&f, &["approve", "deny"], Some((0, hook)));
    assert_eq!(r.code, EXIT_FAILED, "the daemon closed after the decision");
    assert!(
        r.shown.contains("that prompt closed meanwhile"),
        "{}",
        r.shown
    );
    assert_eq!(
        f.decides(),
        [json!({"id": "p2", "decision": "deny", "digest": "d-p2", "full_shown": false})],
        "nothing for p1; the first line was not p2's"
    );
}

/// Q91: the connection ending while a question is shown sends nothing for the line typed,
/// says so in one line, and exits non-zero.
#[test]
fn a_lost_connection_sends_nothing_for_the_line_typed() {
    let f = daemon("lost", vec![prompt("p1")], 9);
    let hook: Hook = Box::new(|q| q.send(Err(Error::Closed)).unwrap());
    let r = run_with(&f, &["approve"], Some((0, hook)));
    assert_eq!(r.code, EXIT_FAILED);
    assert!(f.decides().is_empty(), "{:?}", f.decides());
    assert_eq!(r.err.lines().count(), 1, "{}", r.err);
    assert!(
        r.err.contains("prompts still pending are denied"),
        "{}",
        r.err
    );
}

/// Security re-review LOW1: an answer sent but never replied to may have been taken; the
/// approver says so instead of implying it was not.
#[test]
fn an_answer_lost_before_its_reply_may_have_been_taken() {
    let f = Fake::new(
        "unanswered",
        Box::new(|req| match req["method"].as_str().unwrap() {
            "approvals.watch" => (vec![ok(req, list(&[prompt("p1")], true))], false),
            _ => (vec![], true),
        }),
    );
    let r = run_with(&f, &["approve"], None);
    assert_eq!(r.code, EXIT_FAILED);
    assert_eq!(f.decides().len(), 1);
    assert!(
        r.shown
            .contains("the approve for p1 may have been taken (see the audit log)"),
        "{}",
        r.shown
    );
}

/// Q91: requested and closed prompts leave nothing behind but the one on screen.
#[test]
fn closed_prompts_leave_the_queue_empty() {
    let mut q = Queue::default();
    let mut out = Vec::new();
    q.on_screen = Some("p0".to_owned());
    for i in 0..1000 {
        let id = format!("p{i}");
        q.note(&note("approval.requested", prompt(&id)), &mut out);
        q.note(&note("approval.closed", json!({"id": id})), &mut out);
    }
    assert!(q.seen.is_empty() && q.waiting.is_empty());
    assert!(q.on_screen_closed, "the one on screen is known closed");
}

/// Rust review L3: a cut list is listed again only after something was answered or closed, not
/// in a loop when a new list brings nothing new.
#[test]
fn a_cut_list_is_listed_again_only_after_progress() {
    // The watch lists p1 of a cut list; the deny is not taken (p1 stays pending); the one
    // re-list brings only p1 again. The approver then waits for a note, which ends it once
    // that re-list is kept. A loop would have sent more lists by then.
    let mut f = Fake::new(
        "relist-progress",
        Box::new(move |req| match req["method"].as_str().unwrap() {
            "approvals.watch" => (vec![ok(req, list(&[prompt("p1")], false))], false),
            "approvals.decide" => {
                let refused = json!({"code": -32000, "message": "Server error",
                                     "data": {"reason": "digest-mismatch"}});
                let e = json!({"jsonrpc": "2.0", "id": req["id"], "error": refused});
                (vec![e], false)
            }
            _ => (vec![ok(req, list(&[prompt("p1")], false))], false),
        }),
    );
    let (c, queue) = client(&f);
    let (requests, end) = (Arc::clone(&f.requests), queue.clone());
    let ender = std::thread::spawn(move || {
        for _ in 0..500 {
            let listed = requests
                .lock()
                .unwrap()
                .iter()
                .any(|r| r["method"] == "approvals.list");
            if listed {
                std::thread::sleep(std::time::Duration::from_millis(50));
                let _ = end.send(Err(Error::Closed));
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("never listed again");
    });
    // The worker drops the client before run_bounded returns.
    let r = run_bounded((c, queue), &["deny"], None);
    ender.join().unwrap();
    f.join();
    assert_eq!(r.code, EXIT_FAILED);
    assert!(
        r.shown.contains("not taken: digest-mismatch"),
        "{}",
        r.shown
    );
    assert_eq!(
        f.methods(),
        ["approvals.watch", "approvals.decide", "approvals.list"],
        "listed again once, not in a loop"
    );
}

/// Q80.8: a cut prompt shows its full text before the question, and its approval says so.
#[test]
fn a_cut_prompt_shows_its_full_text_first() {
    let mut p = prompt("p1");
    p["truncated"] = json!(true);
    p["full"] = json!("FULL ACTION TEXT");
    let f = daemon("full", vec![p], 1);
    let r = run_with(&f, &["approve"], None);
    let full = r.shown.find("FULL ACTION TEXT").expect("the full text");
    let question = r.shown.find("approve, deny or deny-all? ").unwrap();
    assert!(full < question, "{}", r.shown);
    assert_eq!(f.decides()[0]["full_shown"], json!(true));
}

/// Q74b, Q80.8: a cut prompt whose full text could not be sent can only be denied.
#[test]
fn a_prompt_without_its_full_text_can_only_be_denied() {
    let mut p = prompt("p1");
    p["truncated"] = json!(true);
    p["full_unavailable"] = json!(true);
    let f = daemon("deny-only", vec![p], 1);
    let r = run_with(&f, &["approve", "deny"], None);
    assert_eq!(r.shown.matches("deny or deny-all? ").count(), 2);
    assert!(!r.shown.contains("approve, deny"));
    assert_eq!(
        f.decides(),
        [json!({"id": "p1", "decision": "deny", "digest": "d-p1", "full_shown": false})]
    );
}

/// A cut prompt can be approved only when its full text came and is clean: one marked
/// unavailable stays deny-only even if a full text came with it, and a dirty full text makes
/// it deny-only.
#[test]
fn a_cut_prompt_with_an_unusable_full_text_is_deny_only() {
    for (tag, unavailable, full) in [
        ("cut-unav", true, "FULL"),
        ("cut-dirty", false, "FULL\x1b[2J"),
    ] {
        let mut p = prompt("p1");
        p["truncated"] = json!(true);
        p["full"] = json!(full);
        p["full_unavailable"] = json!(unavailable);
        let f = daemon(tag, vec![p], 1);
        let r = run_with(&f, &["approve", "deny"], None);
        assert!(!r.shown.contains("approve, deny"), "{tag}: {}", r.shown);
        assert_eq!(f.decides()[0]["decision"], "deny", "{tag}");
    }
}

/// A flood notification is told, its session id clean.
#[test]
fn a_flood_is_told() {
    let mut q = Queue::default();
    let mut out = Vec::new();
    q.note(
        &note("approval.flood", json!({"session": "s-1\x1b"})),
        &mut out,
    );
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "session s-1\\x1b is asking too often: its prompts are denied for now\n"
    );
}

/// Q80 clean-check: prompt text that is not printable ASCII is shown escaped and can only be
/// denied.
#[test]
fn a_dirty_prompt_is_escaped_and_deny_only() {
    let mut p = prompt("p1");
    p["text"] = json!("approval p1\x1b[2J\n");
    let f = daemon("dirty", vec![p], 1);
    let r = run_with(&f, &["approve", "deny-all"], None);
    assert!(!r.shown.contains('\x1b'));
    assert!(r.shown.contains("\\x1b[2J"), "{}", r.shown);
    assert_eq!(f.decides()[0]["decision"], "deny_all_session");
}

/// Q73.4: a prompt is asked about once however often it arrives; one closed before it is shown
/// is never asked about.
#[test]
fn prompts_are_asked_once_and_never_after_they_close() {
    let f = Fake::new(
        "dedup",
        Box::new(|req| match req["method"].as_str().unwrap() {
            "approvals.watch" => (
                vec![
                    note("approval.requested", prompt("p2")),
                    note("approval.closed", json!({"id": "p1"})),
                    ok(req, list(&[prompt("p1"), prompt("p2")], true)),
                ],
                false,
            ),
            _ => (vec![ok(req, json!({}))], true),
        }),
    );
    let r = run_with(&f, &["deny"], None);
    assert!(!r.shown.contains("approval p1"), "{}", r.shown);
    assert_eq!(r.shown.matches("approval p2").count(), 1);
    assert_eq!(f.methods(), ["approvals.watch", "approvals.decide"]);
}

/// Q84: a cut list is listed again once the shown prompts are answered.
#[test]
fn a_cut_list_is_listed_again_when_empty() {
    let f = Fake::new(
        "relist",
        Box::new(|req| match req["method"].as_str().unwrap() {
            "approvals.watch" => (vec![ok(req, list(&[prompt("p1")], false))], false),
            "approvals.list" => (vec![ok(req, list(&[prompt("p2")], true))], false),
            "approvals.decide" if req["params"]["id"] == "p1" => (vec![ok(req, json!({}))], false),
            _ => (vec![ok(req, json!({}))], true),
        }),
    );
    let r = run_with(&f, &["deny", "deny"], None);
    assert_eq!(r.code, EXIT_FAILED);
    assert_eq!(
        f.methods(),
        [
            "approvals.watch",
            "approvals.decide",
            "approvals.list",
            "approvals.decide"
        ]
    );
}

/// Columns and rows of the screen RT-AG-04's padded case is judged on.
const SCREEN: (usize, usize) = (80, 24);
const APPROVE_QUESTION: &str = "approve, deny or deny-all? ";
const DENY_QUESTION: &str = "deny or deny-all? ";

/// The rows an 80-column terminal shows for `text`, counted here and by no product code: each
/// line wraps every 80 characters, an empty line is one row.
fn screen_rows(text: &str) -> Vec<String> {
    let mut rows = Vec::new();
    for line in text.split('\n') {
        let chars: Vec<char> = line.chars().collect();
        if chars.is_empty() {
            rows.push(String::new());
        }
        for row in chars.chunks(SCREEN.0) {
            rows.push(row.iter().collect());
        }
    }
    rows
}

/// For every question `shown` asks: whether it offers approve, and whether `marker` is in the
/// rows above it on the last screen (the question's own row is the screen's last).
fn questions(shown: &str, marker: &str) -> Vec<(bool, bool)> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(at) = shown.get(from..).and_then(|s| s.find(DENY_QUESTION)) {
        let at = from + at;
        let approvable = shown
            .get(..at + DENY_QUESTION.len())
            .is_some_and(|s| s.ends_with(APPROVE_QUESTION));
        let start = if approvable {
            at + DENY_QUESTION.len() - APPROVE_QUESTION.len()
        } else {
            at
        };
        let rows = screen_rows(shown.get(..start).unwrap_or_default());
        // The last row is the partial one the question is printed on.
        let above = rows.len().saturating_sub(SCREEN.1);
        let seen = rows
            .get(above..rows.len().saturating_sub(1))
            .is_some_and(|r| r.concat().contains(marker));
        out.push((approvable, seen));
        from = at + DENY_QUESTION.len();
    }
    out
}

/// About 100 KiB of words with no run of one character longer than 16.
fn unrun_padding() -> String {
    let mut s = String::new();
    let mut i = 0u32;
    while s.len() < 100 * 1024 {
        s.push_str(&format!("w{i} "));
        i += 1;
    }
    s
}

/// RT-AG-04, the padded case (#290), as the CLI shows it: a cut prompt whose full text is about
/// 100 KiB keeps its command in the last screen of 80 columns and 24 rows before every question,
/// a question asked again included, or the prompt can only be denied.
#[test]
fn rt_ag_04_a_padded_prompt_keeps_its_command_above_every_question() {
    let marker = "marker-cmd";
    let action = format!("run [\"{marker}\" \"w0 w1 w2\"]");
    let mut plain = prompt("p0");
    plain["text"] = json!(format!(
        "approval p0 (session s-1, call 3)\n  action: {action}\n"
    ));
    let f = daemon("padded-control", vec![plain], 1);
    let r = run_with(&f, &["maybe", "deny"], None);
    for (approvable, seen) in questions(&r.shown, marker) {
        assert!(
            approvable && seen,
            "control: the unpadded twin:\n{}",
            r.shown
        );
    }

    let full = format!(
        "run [\"{marker}\" \"{}\" \"tail\"] in \"/workspace/p\"",
        unrun_padding()
    );
    let cut: String = full.chars().take(2000).collect();
    let mut p = prompt("p1");
    p["truncated"] = json!(true);
    p["text"] = json!(format!(
        "approval p1 (session s-1, call 3)\n  action: {cut}... (+{} bytes)\n  \
         (cut: the full action must be shown before it can be approved)\n  digest: d-p1\n",
        full.len() - cut.len()
    ));
    p["full"] = json!(full);
    let f = daemon("padded", vec![p], 1);
    let r = run_with(&f, &["maybe", "deny"], None);
    let asked = questions(&r.shown, marker);
    assert_eq!(asked.len(), 2, "asked, then asked again");
    for (approvable, seen) in asked {
        let tail: String = r
            .shown
            .chars()
            .rev()
            .take(400)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        assert!(
            !approvable || seen,
            "approvable, and the last screen before the question does not hold the command: ...{tail}"
        );
    }
}
