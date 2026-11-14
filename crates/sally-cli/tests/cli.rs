//! The `sally` binary against a fake `sallyd` (architect Q79): what it prints, byte for byte,
//! and its exit codes. The fake listens where the binary looks, under a temporary
//! `$XDG_RUNTIME_DIR`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

/// A fake daemon answering each request with `reply(request)`, keeping every request.
struct Fake {
    runtime: PathBuf,
    requests: Arc<Mutex<Vec<Value>>>,
}

impl Fake {
    fn new(tag: &str, reply: impl Fn(&Value) -> String + Send + 'static) -> Self {
        // Short: the socket path below must fit SUN_LEN under a deep TMPDIR (the mutation runs'
        // target/mutants-tmp), so tags stay short too.
        let runtime = std::env::temp_dir().join(format!("sc-{tag}-{}", std::process::id()));
        assert!(tag.len() <= 8, "tag {tag:?}: keep it short");
        let _ = std::fs::remove_dir_all(&runtime);
        std::fs::create_dir_all(runtime.join("sallyport")).unwrap();
        let listener = UnixListener::bind(runtime.join("sallyport/control.sock")).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let reqs = Arc::clone(&requests);
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(s) = conn else { return };
                let mut w = s.try_clone().unwrap();
                for l in BufReader::new(s).lines() {
                    let Ok(l) = l else { break };
                    let req: Value = serde_json::from_str(&l).unwrap();
                    reqs.lock().unwrap().push(req.clone());
                    let _ = w.write_all(reply(&req).as_bytes());
                }
            }
        });
        Self { runtime, requests }
    }

    fn sally(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_sally"))
            .args(args)
            .env("XDG_RUNTIME_DIR", &self.runtime)
            .output()
            .unwrap()
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
        let _ = std::fs::remove_dir_all(&self.runtime);
    }
}

/// A result frame for `req`, as one line.
fn result(req: &Value, r: Value) -> String {
    format!(
        "{}\n",
        json!({"jsonrpc": "2.0", "id": req["id"], "result": r})
    )
}

fn stdout(o: &Output) -> String {
    String::from_utf8(o.stdout.clone()).unwrap()
}

fn stderr(o: &Output) -> String {
    String::from_utf8(o.stderr.clone()).unwrap()
}

/// RT-FS-15 (client side, architect Q79): a path `sallyd` escaped is printed exactly as sent.
/// Control: `sallyd`'s escaping (the daemon-side test, `rt_fs_15_…` in sallyd's tests).
#[test]
fn changes_print_escaped_paths_exactly() {
    let f = Fake::new("changes", |req| {
        result(
            req,
            json!({
                "changes": [
                    {"mount": 0, "kind": "written", "path": "a\\x0a\\x1b[2J\\xff"},
                    {"mount": 2, "kind": "deleted", "path": "gone.txt"},
                    {"mount": 2, "kind": "replaced", "path": "dir"},
                ],
                "complete": true, "total": 3,
            }),
        )
    });
    let o = f.sally(&["session", "changes", "s-1"]);
    assert_eq!(
        stdout(&o),
        "written mounts[0] a\\x0a\\x1b[2J\\xff\ndeleted mounts[2] gone.txt\nreplaced mounts[2] dir\n"
    );
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let sent = f.requests.lock().unwrap()[0].clone();
    assert_eq!(sent["method"], "sessions.changes");
    assert_eq!(sent["params"], json!({"id": "s-1"}));
}

/// RT-FS-15 (architect Q79): a hostile reply with a raw newline and escape sequence in a path is
/// escaped before it reaches the terminal, and the command fails. Control: the CLI's
/// clean-check (`clean::line` in `commands::Printer`). Named `rt_` so `make redteam` runs it
/// (architect Q92).
#[test]
fn rt_fs_15_a_raw_control_byte_from_the_daemon_is_escaped_and_fails() {
    let f = Fake::new("hostile", |req| {
        result(
            req,
            json!({
                "changes": [{"mount": 0, "kind": "written", "path": "a\n\u{1b}[2Jb"}],
                "complete": true, "total": 1,
            }),
        )
    });
    let o = f.sally(&["session", "changes", "s-1"]);
    assert_eq!(stdout(&o), "written mounts[0] a\\x0a\\x1b[2Jb\n");
    assert!(!o.stdout.contains(&0x1b));
    assert_eq!(o.status.code(), Some(1));
}

/// Architect Q75: a cut listing names how many changes are not shown and fails.
#[test]
fn a_cut_listing_says_how_many_are_not_shown() {
    let f = Fake::new("cut", |req| {
        result(
            req,
            json!({
                "changes": [{"mount": 0, "kind": "written", "path": "a"}],
                "complete": false, "total": 4,
            }),
        )
    });
    let o = f.sally(&["session", "changes", "s-1"]);
    assert_eq!(stdout(&o), "written mounts[0] a\n3 changes not shown\n");
    assert_eq!(o.status.code(), Some(1));
}

#[test]
fn a_refusal_is_printed_clean_with_its_detail_and_errors() {
    let f = Fake::new("refused", |req| {
        let err = json!({"code": -32000, "message": "Server error", "data": {
            "reason": "manifest-invalid", "detail": "d\u{1b}",
            "errors": ["error: name: empty [required]", "x\ny"],
        }});
        format!(
            "{}\n",
            json!({"jsonrpc": "2.0", "id": req["id"], "error": err})
        )
    });
    let o = f.sally(&["session", "stop", "s-1"]);
    assert_eq!(
        stderr(&o),
        "sally: refused: manifest-invalid: d\\x1b\n  error: name: empty [required]\n  x\\x0ay\n"
    );
    assert_eq!(stdout(&o), "");
    assert_eq!(o.status.code(), Some(1));
}

#[test]
fn start_sends_the_manifest_text_and_prints_the_session() {
    let f = Fake::new("start", |req| {
        let r = match req["method"].as_str().unwrap() {
            "sessions.create" | "sessions.list" => {
                let s = json!({"id": "s-1", "manifest": "t", "container": "sp-w-s-1",
                               "state": "running"});
                if req["method"] == "sessions.list" {
                    json!({"sessions": [s, {"id": "s-2", "manifest": "u",
                           "container": "sp-w-s-2", "state": "stop-failed"}]})
                } else {
                    s
                }
            }
            _ => json!({"id": "s-1"}),
        };
        result(req, r)
    });
    let manifest = f.runtime.join("m.yaml");
    std::fs::write(&manifest, "name: t\n").unwrap();
    let o = f.sally(&["session", "start", manifest.to_str().unwrap()]);
    assert_eq!(stdout(&o), "s-1  running  t  sp-w-s-1\n");
    assert_eq!(o.status.code(), Some(0));
    assert_eq!(
        f.requests.lock().unwrap()[0]["params"],
        json!({"manifest": "name: t\n"})
    );
    let o = f.sally(&["session", "list"]);
    assert_eq!(
        stdout(&o),
        "s-1  running  t  sp-w-s-1\ns-2  stop-failed  u  sp-w-s-2\n"
    );
    let o = f.sally(&["session", "stop", "s-1"]);
    assert_eq!(stdout(&o), "stopped s-1\n");
}

#[test]
fn a_manifest_over_the_cap_is_never_sent() {
    let f = Fake::new("big", |req| result(req, json!({})));
    let manifest = f.runtime.join("m.yaml");
    std::fs::write(
        &manifest,
        "a".repeat(sally_core::manifest::MAX_MANIFEST_BYTES + 1),
    )
    .unwrap();
    let o = f.sally(&["session", "start", manifest.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr(&o).contains("larger than"), "{}", stderr(&o));
    assert!(f.methods().is_empty());
}

/// A manifest of exactly the cap is read and sent.
#[test]
fn a_manifest_at_the_cap_is_sent() {
    let f = Fake::new("at-cap", |req| result(req, json!({})));
    let manifest = f.runtime.join("m.yaml");
    std::fs::write(
        &manifest,
        "a".repeat(sally_core::manifest::MAX_MANIFEST_BYTES),
    )
    .unwrap();
    let _ = f.sally(&["session", "start", manifest.to_str().unwrap()]);
    assert_eq!(f.methods(), ["sessions.create"]);
}

/// A complete, clean prompt list exits 0; one with a dirty prompt text is printed escaped and
/// exits 1.
#[test]
fn a_dirty_prompt_text_fails_the_listing() {
    for (tag, text, code) in [
        ("clean", "approval p1\n", 0),
        ("dirty", "approval p1\x1b[2J\n", 1),
    ] {
        let f = Fake::new(tag, move |req| {
            let p = json!({"id": "p1", "session": "s-1", "digest": "d", "truncated": false,
                           "text": text});
            result(req, json!({"prompts": [p], "complete": true, "total": 1}))
        });
        let o = f.sally(&["approvals"]);
        assert_eq!(o.status.code(), Some(code), "{tag}");
        assert!(!stdout(&o).contains('\x1b'), "{tag}");
    }
}

#[test]
fn approvals_lists_prompt_text_and_says_when_cut() {
    let f = Fake::new("prompts", |req| {
        let p = json!({"id": "p1", "session": "s-1", "digest": "d", "truncated": false,
                       "text": "approval p1\n  action: run [\"ls\"]\n"});
        result(req, json!({"prompts": [p], "complete": false, "total": 3}))
    });
    let o = f.sally(&["approvals"]);
    assert_eq!(
        stdout(&o),
        "approval p1\n  action: run [\"ls\"]\n2 more pending not shown; list again after answering these\n"
    );
    assert_eq!(o.status.code(), Some(1));
}

/// Architect Q80.2: with no terminal, `approve` exits non-zero before it watches.
#[test]
fn approve_without_a_terminal_exits_before_watching() {
    let f = Fake::new("no-tty", |req| result(req, json!({})));
    let o = Command::new("setsid")
        .arg("--wait")
        .arg(env!("CARGO_BIN_EXE_sally"))
        .arg("approve")
        .env("XDG_RUNTIME_DIR", &f.runtime)
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    assert!(stderr(&o).contains("needs a terminal"), "{}", stderr(&o));
    assert!(f.methods().is_empty(), "{:?}", f.methods());
}

/// Architect Q113: no parse error repeats an argument (one may be a secret value typed in the
/// wrong place). Each line fails before any daemon is contacted.
#[test]
fn a_command_line_that_does_not_parse_repeats_no_argument() {
    const MARK: &str = "MARKq7zX";
    let f = Fake::new("parse", |req| result(req, json!({})));
    let flag = format!("--{MARK}");
    let lines: [&[&str]; 7] = [
        &["session", "stop", "ID", MARK],
        &["session", "list", &flag],
        &["audit", "tail", "-n", MARK],
        &[MARK],
        &["manifest", MARK],
        &["approvals", MARK],
        &[&flag, "session", "list"],
    ];
    for args in lines {
        let o = f.sally(args);
        assert_eq!(o.status.code(), Some(2), "{args:?}");
        let all = format!("{}{}", stdout(&o), stderr(&o));
        assert!(!all.contains(MARK), "{args:?} printed it: {all}");
        assert!(stderr(&o).contains("run `sally --help`"), "{all}");
        assert!(!stderr(&o).contains("shell history"), "{all}");
    }
    assert!(f.methods().is_empty(), "{:?}", f.methods());
}

#[test]
fn help_and_version_still_print() {
    let f = Fake::new("help", |req| result(req, json!({})));
    let o = f.sally(&["--help"]);
    assert_eq!(o.status.code(), Some(0));
    assert!(stdout(&o).contains("Usage: sally"), "{}", stdout(&o));
    let o = f.sally(&["--version"]);
    assert_eq!(o.status.code(), Some(0));
    assert!(stdout(&o).starts_with("sally "), "{}", stdout(&o));
}

#[test]
fn no_daemon_and_bad_arguments_fail_cleanly() {
    let f = Fake::new("gone", |req| result(req, json!({})));
    std::fs::remove_file(f.runtime.join("sallyport/control.sock")).unwrap();
    let o = f.sally(&["session", "list"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr(&o).starts_with("sally: "), "{}", stderr(&o));
    let o = f.sally(&["session", "bogus\u{1b}"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(!o.stderr.contains(&0x1b), "{}", stderr(&o));
    let o = Command::new(env!("CARGO_BIN_EXE_sally"))
        .args(["session", "list"])
        .env_remove("XDG_RUNTIME_DIR")
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr(&o).contains("XDG_RUNTIME_DIR"), "{}", stderr(&o));
}
