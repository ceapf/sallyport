#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::collections::VecDeque;
use std::io::{BufReader, Read};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use super::*;
use crate::EXIT_FAILED;

/// What the fake daemon answers one request with: frames to write, then whether to close.
type Handler = Box<dyn FnMut(&Value) -> (Vec<Value>, bool) + Send>;

/// A fake `sallyd` on a Unix socket: one connection, scripted replies, every request kept.
struct Fake {
    path: PathBuf,
    requests: Arc<Mutex<Vec<Value>>>,
    stream: Arc<Mutex<Option<UnixStream>>>,
}

impl Fake {
    fn new(tag: &str, mut handler: Handler) -> Self {
        let path = std::env::temp_dir().join(format!("sp-cli-{tag}-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stream: Arc<Mutex<Option<UnixStream>>> = Arc::new(Mutex::new(None));
        let (reqs, out) = (Arc::clone(&requests), Arc::clone(&stream));
        std::thread::spawn(move || {
            let (s, _) = listener.accept().unwrap();
            *out.lock().unwrap() = Some(s.try_clone().unwrap());
            for l in BufReader::new(s).lines() {
                let Ok(l) = l else { return };
                let req: Value = serde_json::from_str(&l).unwrap();
                reqs.lock().unwrap().push(req.clone());
                let (frames, close) = handler(&req);
                let mut g = out.lock().unwrap();
                let w = g.as_mut().unwrap();
                for f in frames {
                    let _ = writeln!(w, "{f}");
                }
                if close {
                    let _ = w.shutdown(std::net::Shutdown::Both);
                    return;
                }
            }
        });
        Self {
            path,
            requests,
            stream,
        }
    }

    /// Writes `frame` now (a notification out of turn).
    fn push(&self, frame: &Value) {
        let mut g = self.stream.lock().unwrap();
        writeln!(g.as_mut().unwrap(), "{frame}").unwrap();
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
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
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
    hook: Option<(usize, Box<dyn FnMut()>)>,
}

impl Read for Script {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if let Some((at, h)) = &mut self.hook
            && *at == self.reads
        {
            h();
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
    flushes: usize,
}

fn run_with(f: &Fake, lines: &[&str], hook: Option<(usize, Box<dyn FnMut()>)>) -> Run {
    let mut c = Client::connect(&f.path).unwrap();
    let script = Script {
        lines: lines.iter().map(|l| format!("{l}\n")).collect(),
        reads: 0,
        hook,
    };
    let mut input = BufReader::with_capacity(4096, script);
    let mut shown = Vec::new();
    let mut flushes = 0;
    let mut flush = || flushes += 1;
    let mut err = Vec::new();
    let code = {
        let mut tty = Tty {
            input: &mut input,
            output: &mut shown,
            flush: &mut flush,
        };
        approve(&mut c, &mut tty, &mut err)
    };
    Run {
        code,
        shown: String::from_utf8(shown).unwrap(),
        flushes,
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

/// Q80.6: a line typed while the prompt on screen closed is never applied to the next prompt.
#[test]
fn a_line_for_a_closed_prompt_is_not_applied_to_the_next() {
    let f = Arc::new(Fake::new(
        "closed",
        Box::new(|req| match req["method"].as_str().unwrap() {
            "approvals.watch" => (vec![ok(req, list(&[prompt("p1")], true))], false),
            "approvals.decide" if req["params"]["id"] == "p1" => {
                let refused = json!({"code": -32000, "message": "Server error",
                                     "data": {"reason": "unknown-id"}});
                (
                    vec![json!({"jsonrpc": "2.0", "id": req["id"], "error": refused})],
                    false,
                )
            }
            _ => (vec![ok(req, json!({}))], true),
        }),
    ));
    let fake = Arc::clone(&f);
    let hook: Box<dyn FnMut()> = Box::new(move || {
        fake.push(&note("approval.closed", json!({"id": "p1"})));
        fake.push(&note("approval.requested", prompt("p2")));
    });
    let r = run_with(&f, &["approve", "deny"], Some((0, hook)));
    assert_eq!(r.code, EXIT_FAILED);
    let decides = f.decides();
    let for_p2: Vec<_> = decides.iter().filter(|d| d["id"] == "p2").collect();
    assert_eq!(for_p2.len(), 1, "{decides:?}");
    assert_eq!(
        for_p2[0]["decision"], "deny",
        "the first line went to p1 only"
    );
    assert!(
        decides
            .iter()
            .all(|d| d["id"] != "p2" || d["decision"] != "approve")
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
