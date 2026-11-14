#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use sally_core::audit::{Actor, AuditWriter, NewEntry, SystemClock};
use sally_core::manifest::{AuditLevel, MAX_MANIFEST_BYTES};
use serde_json::json;

use super::*;

const VALID: &str = "apiVersion: sallyport/v1\nkind: Manifest\nname: t\nmodel:\n  ref: any\n";

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let d = std::env::temp_dir().join(format!("sc-loc-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(d)
    }

    fn file(&self, name: &str, text: &str) -> PathBuf {
        let p = self.0.join(name);
        std::fs::write(&p, text).unwrap();
        p
    }

    fn audit(&self) -> PathBuf {
        self.0.join("audit")
    }

    /// A log with `n` entries whose `args.note` is `note`.
    fn log(&self, n: usize, note: &str) {
        let mut w = AuditWriter::open(&self.audit(), Box::new(SystemClock)).unwrap();
        for i in 0..n {
            let e = NewEntry::new(Actor::Sallyd, "tool.run").args(json!({"i": i, "note": note}));
            w.append(e, AuditLevel::Full).unwrap();
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run(f: impl FnOnce(&mut Out<'_>) -> u8) -> (u8, String, String) {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = f(&mut Out {
        out: &mut out,
        err: &mut err,
    });
    (
        code,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

#[test]
fn a_valid_manifest_is_valid_and_summarized() {
    let s = Scratch::new("valid");
    let m = s.file("m.yaml", VALID);
    let (code, out, err) = run(|o| manifest_validate(&m, o));
    assert_eq!(code, EXIT_OK, "{err}");
    assert!(
        out.ends_with("valid (sallyd checks again when a session starts)\n"),
        "{out}"
    );
    let (code, out, err) = run(|o| manifest_summary(&m, o));
    assert_eq!((code, err.as_str()), (EXIT_OK, ""));
    assert!(!out.is_empty() && out.ends_with('\n'));
}

#[test]
fn a_rejected_manifest_prints_its_errors_and_no_summary() {
    let s = Scratch::new("reject");
    let m = s.file("m.yaml", &format!("{VALID}bogus: 1\n"));
    let (code, out, err) = run(|o| manifest_validate(&m, o));
    assert_eq!((code, out.as_str()), (EXIT_REFUSED, ""));
    assert!(err.starts_with("error: "), "{err}");
    let (code, out, _) = run(|o| manifest_summary(&m, o));
    assert_eq!((code, out.as_str()), (EXIT_REFUSED, ""));
}

#[test]
fn a_secret_grant_is_refused_with_the_note_until_99() {
    let s = Scratch::new("secret");
    let m = s.file(
        "m.yaml",
        &format!(
            "{VALID}network:\n  mode: proxy\n  allow:\n    - host: api.github.com\nsecrets:\n  \
             - name: GH\n    inject:\n      host: api.github.com\n      header: \
             Authorization\n      format: \"Bearer {{value}}\"\n"
        ),
    );
    let (code, _, err) = run(|o| manifest_validate(&m, o));
    assert_eq!(code, EXIT_REFUSED, "{err}");
    assert!(err.contains("[secret-missing]"), "{err}");
    assert!(err.ends_with(&format!("{NOT_YET_USED}\n")), "{err}");
}

#[test]
fn an_unreadable_or_oversized_manifest_fails() {
    let s = Scratch::new("unread");
    let (code, _, err) = run(|o| manifest_validate(&s.0.join("absent.yaml"), o));
    assert_eq!(code, EXIT_FAILED, "{err}");
    let big = s.file("big.yaml", &"#".repeat(MAX_MANIFEST_BYTES + 1));
    let (code, _, err) = run(|o| manifest_summary(&big, o));
    assert_eq!(code, EXIT_FAILED);
    assert!(err.contains("larger than"), "{err}");
}

#[test]
fn verify_reports_a_good_log_and_names_a_bad_one() {
    let s = Scratch::new("verify");
    s.log(3, "x");
    let (code, out, _) = run(|o| audit_verify(&s.audit(), o));
    assert_eq!(code, EXIT_OK);
    assert_eq!(
        out,
        "ok: 3 entries in 1 file(s), last seq 3, head current\n"
    );
    let file = std::fs::read_dir(s.audit())
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|x| x == "jsonl"))
        .unwrap();
    let text = std::fs::read_to_string(&file).unwrap();
    std::fs::write(&file, text.replacen("\"i\":1", "\"i\":7", 1)).unwrap();
    let (code, out, err) = run(|o| audit_verify(&s.audit(), o));
    assert_eq!((code, out.as_str()), (EXIT_REFUSED, ""));
    assert!(err.contains("seq 2"), "{err}");
    let (code, _, _) = run(|o| audit_verify(&s.0.join("none"), o));
    assert_eq!(code, EXIT_REFUSED);
}

#[test]
fn tail_prints_the_newest_entries_escaped() {
    let s = Scratch::new("tail");
    s.log(4, "caf\u{e9}");
    let (code, out, err) = run(|o| audit_tail(&s.audit(), 2, o));
    assert_eq!((code, err.as_str()), (EXIT_OK, ""));
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 2);
    assert!(
        lines[0].contains("\"i\":2") && lines[1].contains("\"i\":3"),
        "{out}"
    );
    assert!(out.contains("caf\\u{e9}"), "{out}");
    assert!(
        out.bytes()
            .all(|b| (b' '..=b'~').contains(&b) || b == b'\n')
    );
}

#[test]
fn tail_counts_lines_that_are_not_entries_and_fails() {
    let s = Scratch::new("tailbad");
    s.log(1, "x");
    let file = std::fs::read_dir(s.audit())
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|x| x == "jsonl"))
        .unwrap();
    let mut text = std::fs::read_to_string(&file).unwrap();
    text.push_str("garbage\n");
    std::fs::write(&file, text).unwrap();
    let (code, out, err) = run(|o| audit_tail(&s.audit(), TAIL_DEFAULT, o));
    assert_eq!(code, EXIT_REFUSED);
    assert_eq!(out.lines().count(), 1);
    assert!(
        err.starts_with("sally: 1 line(s) are not audit entries"),
        "{err}"
    );
    let (code, _, _) = run(|o| audit_tail(&s.0.join("none"), 5, o));
    assert_eq!(code, EXIT_REFUSED);
}
