//! The `sally` binary against a fake `sallyd` (architect Q79): what it prints, byte for byte,
//! and its exit codes. The fake listens where the binary looks, under a temporary
//! `$XDG_RUNTIME_DIR`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use std::process::Command;

use common::{Fake, result, stderr, stdout};
use serde_json::json;

/// A valid manifest with no warning and no acknowledged risk; a launch off a terminal still
/// needs its hash ([`accept`]).
const VALID: &str = "apiVersion: sallyport/v1\nkind: Manifest\nname: t\nmodel:\n  ref: any\n";

/// `--accept-manifest` with the hash of `text`: a launch's consent off a terminal.
fn accept(text: &str) -> [String; 2] {
    let hash = sally_cli::consent::digest(text).as_hex().to_owned();
    ["--accept-manifest".to_owned(), hash]
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
                let none = json!({"kind": "none", "driven": false});
                let s = json!({"id": "s-1", "manifest": "t", "container": "sp-w-s-1",
                               "state": "running", "model": none});
                if req["method"] == "sessions.list" {
                    json!({"sessions": [s, {"id": "s-2", "manifest": "u",
                           "container": "sp-w-s-2", "state": "stop-failed", "model": none}]})
                } else {
                    s
                }
            }
            _ => json!({"id": "s-1"}),
        };
        result(req, r)
    });
    let manifest = f.runtime.join("m.yaml");
    std::fs::write(&manifest, VALID).unwrap();
    let [flag, hash] = accept(VALID);
    let o = f.sally(&["session", "start", manifest.to_str().unwrap(), &flag, &hash]);
    assert_eq!(stdout(&o), "s-1  running  t  sp-w-s-1\n");
    assert_eq!(o.status.code(), Some(0));
    assert_eq!(
        f.requests.lock().unwrap()[0]["params"],
        json!({"manifest": VALID})
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

#[test]
fn a_script_is_sent_as_a_scripted_model_declared_driven() {
    let f = Fake::new("script", |req| {
        let model = json!({"kind": "scripted", "driven": true, "sha256": "ab", "turns": 1});
        let s = json!({"id": "s-1", "manifest": "t", "container": "sp-w-s-1",
                       "state": "running", "model": model});
        result(req, s)
    });
    let manifest = f.runtime.join("m.yaml");
    std::fs::write(&manifest, VALID).unwrap();
    let script = f.runtime.join("s.jsonl");
    std::fs::write(&script, "{\"fail\":true}\n").unwrap();
    let [flag, hash] = accept(VALID);
    let o = f.sally(&[
        "session",
        "start",
        manifest.to_str().unwrap(),
        "--script",
        script.to_str().unwrap(),
        &flag,
        &hash,
    ]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert_eq!(
        f.requests.lock().unwrap()[0]["params"],
        json!({"manifest": VALID,
               "model": {"kind": "scripted", "script": "{\"fail\":true}\n", "driven": true}})
    );
    // The hash sallyd computed is printed, so the user can match it to their file (Q103).
    assert_eq!(
        stdout(&o),
        "s-1  running  t  sp-w-s-1  scripted, driven, 1 turns, sha256 ab\n"
    );
}

#[test]
fn a_script_over_the_cap_is_never_sent() {
    let f = Fake::new("bigscr", |req| result(req, json!({})));
    let manifest = f.runtime.join("m.yaml");
    std::fs::write(&manifest, VALID).unwrap();
    let script = f.runtime.join("s.jsonl");
    std::fs::write(&script, "a".repeat(sally_proto::MAX_SCRIPT_BYTES + 1)).unwrap();
    let [flag, hash] = accept(VALID);
    let o = f.sally(&[
        "session",
        "start",
        manifest.to_str().unwrap(),
        "--script",
        script.to_str().unwrap(),
        &flag,
        &hash,
    ]);
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr(&o).contains("larger than"), "{}", stderr(&o));
    assert!(f.methods().is_empty());
}

#[test]
fn drive_runs_to_the_end_over_one_connection_and_sends_only_drive() {
    let f = Fake::new("drive", |req| {
        let done = req["id"] == 2;
        let step = if done {
            json!({"turn": 2, "kind": "content", "content": "bye", "done": true})
        } else {
            json!({"turn": 1, "kind": "tool_calls", "done": false,
                   "calls": [{"name": "echo", "result": "ran"}]})
        };
        result(req, step)
    });
    let o = f.sally(&["session", "drive", "s-1"]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert_eq!(
        stdout(&o),
        "turn 1: call echo -> ran\nturn 2: model says: bye\n"
    );
    assert_eq!(f.methods(), ["sessions.drive", "sessions.drive"]);
    for r in f.requests.lock().unwrap().iter() {
        assert_eq!(r["params"], json!({"id": "s-1"}));
    }
}

/// A manifest of exactly the cap is read and sent (a valid one, padded with a comment).
#[test]
fn a_manifest_at_the_cap_is_sent() {
    let f = Fake::new("at-cap", |req| result(req, json!({})));
    let manifest = f.runtime.join("m.yaml");
    let pad = sally_core::manifest::MAX_MANIFEST_BYTES - VALID.len() - 2;
    let text = format!("{VALID}#{}\n", "a".repeat(pad));
    assert_eq!(text.len(), sally_core::manifest::MAX_MANIFEST_BYTES);
    std::fs::write(&manifest, &text).unwrap();
    let [flag, hash] = accept(&text);
    let o = f.sally(&["session", "start", manifest.to_str().unwrap(), &flag, &hash]);
    assert_eq!(f.methods(), ["sessions.create"], "{}", stderr(&o));
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

/// `sandbox run` parse errors are the fixed texts, exit 2, and contact no daemon. There is no
/// terminal mode yet (TODO(#138)): `--tty` is an unknown flag, refused like any other and never
/// named back. Each line also carries a marker the output must not repeat.
#[test]
fn sandbox_run_parse_errors_are_fixed_texts_and_tty_is_unknown() {
    const MARK: &str = "MARKq7zX";
    const UNEXPECTED: &str =
        "sally: an argument was not expected; nothing was done (run `sally --help`)\n";
    const MISSING: &str = "sally: an argument is missing; nothing was done (run `sally --help`)\n";
    let f = Fake::new("runp", |req| result(req, json!({})));
    let flag = format!("--{MARK}");
    let lines: [(&[&str], &str); 6] = [
        (
            &["sandbox", "run", "--tty", "--manifest", MARK, "--", MARK],
            UNEXPECTED,
        ),
        (
            &["sandbox", "run", "--manifest", MARK, "--tty", "--", MARK],
            UNEXPECTED,
        ),
        (&["sandbox", "run", "--manifest", MARK, MARK], UNEXPECTED),
        (
            &["sandbox", "run", &flag, "--manifest", MARK, "--", MARK],
            UNEXPECTED,
        ),
        (&["sandbox", "run", "--manifest", MARK], MISSING),
        (&["sandbox", "run", "--", MARK], MISSING),
    ];
    for (args, text) in lines {
        let o = f.sally(args);
        assert_eq!(o.status.code(), Some(2), "{args:?}");
        assert_eq!(stderr(&o), text, "{args:?}");
        assert_eq!(stdout(&o), "", "{args:?}");
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
