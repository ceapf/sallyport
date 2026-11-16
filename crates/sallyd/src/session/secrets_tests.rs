#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use sally_core::audit::{Actor, AuditWriter, NewEntry, SystemClock};
use sally_core::manifest::AuditLevel;
use sally_core::secrets::Secret;
use serde_json::json;

use super::*;

/// A target that keeps the last redactor it was given.
#[derive(Default)]
struct Latest(Mutex<Option<Redactor>>, AtomicUsize);

impl RedactorTarget for Latest {
    fn set_redactor(&self, redactor: Redactor) {
        *self.0.lock().unwrap() = Some(redactor);
        self.1.fetch_add(1, Ordering::SeqCst);
    }
}

impl Latest {
    /// `text` through the last redactor (unchanged before the first swap).
    fn redact(&self, text: &str) -> String {
        self.0
            .lock()
            .unwrap()
            .as_ref()
            .map_or(text.to_owned(), |r| r.redact_str(text).into_owned())
    }
}

/// A value assembled at runtime (no credential-shaped literal).
fn value(tag: &str) -> String {
    format!("sp-reg-{tag}-{}", "v".repeat(20))
}

fn forms(name: &str, v: &str) -> Arc<SessionForms> {
    let secret = Secret::new(v.to_owned());
    SessionForms::build([(name, &secret, vec![])])
}

fn two() -> (Arc<Latest>, Arc<Latest>, Redactors) {
    let (a, b) = (Arc::new(Latest::default()), Arc::new(Latest::default()));
    let r = Redactors::new(vec![
        Arc::clone(&a) as Arc<dyn RedactorTarget>,
        Arc::clone(&b) as Arc<dyn RedactorTarget>,
    ]);
    (a, b, r)
}

#[test]
fn a_registered_value_is_redacted_in_every_target_until_unregistered() {
    let (a, b, r) = two();
    let v = value("one");
    r.register("s1", forms("GITHUB_TOKEN", &v));
    for t in [&a, &b] {
        assert_eq!(t.redact(&format!("x {v} y")), "x [REDACTED:GITHUB_TOKEN] y");
    }
    assert_eq!(r.sessions(), ["s1"]);
    r.unregister("s1");
    for t in [&a, &b] {
        assert_eq!(t.redact(&v), v, "in the clear after unregister");
    }
    assert!(r.sessions().is_empty());
}

/// #85 (4): a value granted by another live session stays redacted until that one ends too.
#[test]
fn a_shared_value_stays_redacted_until_its_last_session_is_unregistered() {
    let (a, _, r) = two();
    let (shared, own) = (value("shared"), value("own"));
    r.register("s1", forms("A", &shared));
    let both = {
        let s = Secret::new(shared.clone());
        let o = Secret::new(own.clone());
        SessionForms::build([("B", &s, vec![]), ("C", &o, vec![])])
    };
    r.register("s2", both);
    r.unregister("s1");
    assert_eq!(a.redact(&shared), "[REDACTED:B]");
    assert_eq!(a.redact(&own), "[REDACTED:C]");
    r.unregister("s2");
    assert_eq!(
        a.redact(&format!("{shared} {own}")),
        format!("{shared} {own}")
    );
}

#[test]
fn registering_an_id_again_replaces_its_forms() {
    let (a, _, r) = two();
    let (old, new) = (value("old"), value("new"));
    r.register("s1", forms("N", &old));
    r.register("s1", forms("N", &new));
    assert_eq!(r.sessions(), ["s1"]);
    assert_eq!(a.redact(&old), old);
    assert_eq!(a.redact(&new), "[REDACTED:N]");
}

#[test]
fn unregistering_twice_or_an_unknown_id_changes_nothing() {
    let (a, _, r) = two();
    let v = value("kept");
    r.register("s1", forms("N", &v));
    r.unregister("s2");
    r.unregister("s2");
    assert_eq!(r.sessions(), ["s1"]);
    assert_eq!(a.redact(&v), "[REDACTED:N]");
}

/// Architect Q220: concurrent changes end with the exact union, in every target, one swap per
/// change. That the swap runs under the lock is covered by reading: a swap moved outside it
/// fails this test only when a stale union happens to land last.
#[test]
fn concurrent_changes_end_with_the_exact_union() {
    let (a, b, r) = two();
    let r = Arc::new(r);
    let values: Vec<String> = (0..16).map(|i| value(&i.to_string())).collect();
    let threads: Vec<_> = (0..16)
        .map(|i| {
            let (r, v) = (Arc::clone(&r), values[i].clone());
            std::thread::spawn(move || {
                let id = format!("s{i}");
                r.register(&id, forms(&format!("N{i}"), &v));
                if i % 2 == 1 {
                    r.unregister(&id);
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    let mut left = r.sessions();
    left.sort();
    let mut want: Vec<String> = (0..16).step_by(2).map(|i| format!("s{i}")).collect();
    want.sort();
    assert_eq!(left, want);
    for t in [&a, &b] {
        for (i, v) in values.iter().enumerate() {
            let want = if i % 2 == 0 {
                format!("[REDACTED:N{i}]")
            } else {
                v.clone()
            };
            assert_eq!(t.redact(v), want, "value {i}");
        }
    }
    // One swap per change, in each target.
    assert_eq!(a.1.load(Ordering::SeqCst), 24);
}

#[test]
fn debug_names_the_sessions_and_never_a_value() {
    let (_, _, r) = two();
    let v = value("dbg");
    r.register("s1", forms("GITHUB_TOKEN", &v));
    let d = format!("{r:?}");
    assert_eq!(d, "Redactors { sessions: [\"s1\"], targets: 2 }");
}

/// A fresh directory under `target/`.
fn scratch(name: &str) -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::SeqCst);
    let d = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/session-secrets-tests")
        .join(format!("{name}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Every file under `dir`, as text.
fn all_text(dir: &Path) -> String {
    let mut out = String::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            out.push_str(&all_text(&p));
        } else {
            out.push_str(&String::from_utf8_lossy(&std::fs::read(&p).unwrap()));
        }
    }
    out
}

/// #85 (2): the audit writer behind `SharedAudit` and the oplog are the production targets,
/// both wired by [`Redactors::for_logs`] (what `serve` calls); an entry and a line carrying a
/// registered value are redacted, and after unregister are not.
#[test]
fn the_audit_writer_and_the_oplog_redact_what_is_registered() {
    let dir = scratch("targets");
    let audit = Arc::new(SharedAudit(Mutex::new(
        AuditWriter::open(&dir.join("audit"), Box::new(SystemClock)).unwrap(),
    )));
    let lines = Lines::default();
    let oplog = Oplog::new(lines.clone());
    let r = Redactors::for_logs(&audit, &oplog);
    let v = value("prod");
    let write = |tag: &str| {
        let entry = NewEntry::new(Actor::Sallyd, "test.entry").args(json!({ "t": tag, "v": v }));
        audit
            .0
            .lock()
            .unwrap()
            .append(entry, AuditLevel::Full)
            .unwrap();
        oplog.info("test", "line", &[("t", tag), ("v", &v)]);
    };
    r.register("s1", forms("GITHUB_TOKEN", &v));
    write("mark-live");
    r.unregister("s1");
    write("mark-after");
    assert!(oplog.flush(std::time::Duration::from_secs(10)));
    for text in [all_text(&dir.join("audit")), lines.text()] {
        let mine: Vec<&str> = text.lines().filter(|l| l.contains("mark-")).collect();
        assert_eq!(mine.len(), 2, "{text}");
        assert!(mine[0].contains("[REDACTED:GITHUB_TOKEN]"), "{}", mine[0]);
        assert!(!mine[0].contains(&v), "{}", mine[0]);
        assert!(
            mine[1].contains(&v),
            "control: in the clear after unregister: {}",
            mine[1]
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Architect Q249: an egress entry written through a session's [`SessionRedacted`] sink is
/// redacted with that session's own forms even when the writer's redactor no longer holds them
/// (the state after the session's release): the sandbox-chosen `host` of `egress.allow` and
/// `egress.close` (a wildcard-allowed CONNECT host, which `audit_text` does not mask; Q266,
/// Q279) and `target` of `egress.request`, `egress.deny`, `egress.limit` and a dropped
/// `egress.response` hold no form. Control: the same entries appended to the writer directly
/// are in the clear.
#[test]
fn a_sessions_egress_entries_are_redacted_with_its_own_forms_after_the_release() {
    let dir = scratch("own-forms");
    let audit = Arc::new(SharedAudit(Mutex::new(
        AuditWriter::open(&dir.join("audit"), Box::new(SystemClock)).unwrap(),
    )));
    let v = value("own");
    let redaction = Redaction::of(forms("GITHUB_TOKEN", &v)).unwrap();
    let sink = SessionRedacted::over(
        Arc::clone(&audit) as Arc<dyn AuditSink>,
        Arc::new(redaction),
    );
    let entries = |mark: &str| {
        let target = format!("/x?t={v}&m={mark}");
        let host = format!("{v}.h.test");
        [
            (
                "egress.allow",
                json!({"host": host, "intercept": false, "m": mark}),
            ),
            ("egress.close", json!({"host": host, "m": mark})),
            (
                "egress.request",
                json!({"host": "h.test", "target": target}),
            ),
            (
                "egress.deny",
                json!({"host": format!("{v}.h.test"), "target": target}),
            ),
            ("egress.limit", json!({"target": target, "limit": "body"})),
            (
                "egress.response",
                json!({"target": target, "end": "dropped"}),
            ),
        ]
        .map(|(e, a)| NewEntry::new(Actor::Sallyd, e).session("s1").args(a))
    };
    for e in entries("mark-own") {
        sink.append(e, AuditLevel::Full).unwrap();
    }
    for e in entries("mark-raw") {
        audit.append(e, AuditLevel::Full).unwrap();
    }
    let text = all_text(&dir.join("audit"));
    let own: Vec<&str> = text.lines().filter(|l| l.contains("mark-own")).collect();
    assert_eq!(own.len(), 6, "{text}");
    for l in &own {
        assert!(!l.contains(&v), "{l}");
        assert!(l.contains("[REDACTED:GITHUB_TOKEN]"), "{l}");
    }
    for event in ["egress.allow", "egress.close"] {
        let tag = format!("\"event\":\"{event}\"");
        let l = own.iter().find(|l| l.contains(&tag)).unwrap();
        assert!(l.contains("[REDACTED:GITHUB_TOKEN].h.test"), "{l}");
    }
    let raw: Vec<&str> = text.lines().filter(|l| l.contains("mark-raw")).collect();
    assert_eq!(raw.len(), 6, "{text}");
    assert!(raw.iter().all(|l| l.contains(&v)), "control: {raw:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Architect Q266 (1): the wrapper alone, under a writer with no redactor, redacts a form of
/// the session's secrets wherever an entry holds it: in a string value, as an object key and as
/// a number. The entries are appended after the session's forms were registered with the logs'
/// redactors and unregistered again (the release), so the wrapper's forms outlive the release.
/// Control: the same entry appended to the writer directly holds all three.
#[test]
fn the_session_sink_redacts_a_form_in_a_value_a_key_and_a_number() {
    let dir = scratch("sink-alone");
    let audit = Arc::new(SharedAudit(Mutex::new(
        AuditWriter::open(&dir.join("audit"), Box::new(SystemClock)).unwrap(),
    )));
    let word = value("sink");
    let digits = "1357924680135792468";
    let (w, d) = (Secret::new(word.clone()), Secret::new(digits.to_owned()));
    let forms = SessionForms::build([("WORD", &w, vec![]), ("DIGITS", &d, vec![])]);
    let redaction = Arc::new(Redaction::of(forms).unwrap());
    let (_a, _b, redactors) = two();
    redactors.register("s1", Arc::clone(redaction.forms()));
    redactors.unregister("s1");
    assert!(redactors.sessions().is_empty());
    let sink = SessionRedacted::over(Arc::clone(&audit) as Arc<dyn AuditSink>, redaction);
    let entry = |mark: &str| {
        let args = json!({
            "host": format!("{word}.h.test"),
            word.clone(): "a key",
            "n": digits.parse::<u64>().unwrap(),
            "m": mark,
        });
        NewEntry::new(Actor::Sallyd, "egress.close")
            .session("s1")
            .args(args)
    };
    sink.append(entry("mark-own"), AuditLevel::Full).unwrap();
    audit.append(entry("mark-raw"), AuditLevel::Full).unwrap();
    let text = all_text(&dir.join("audit"));
    let line = |mark: &str| -> serde_json::Value {
        let l = text.lines().find(|l| l.contains(mark)).unwrap();
        serde_json::from_str(l).unwrap()
    };
    let own = line("mark-own").to_string();
    assert!(!own.contains(&word) && !own.contains(digits), "{own}");
    assert!(own.contains("[REDACTED:WORD].h.test"), "the value: {own}");
    let key = "\"[REDACTED:WORD]\":\"a key\"";
    assert!(own.contains(key), "the key: {own}");
    assert!(own.contains("[REDACTED:DIGITS]"), "the number: {own}");
    let raw = line("mark-raw").to_string();
    let host = format!("\"{word}.h.test\"");
    let key = format!("\"{word}\":\"a key\"");
    for want in [host.as_str(), key.as_str(), digits] {
        assert!(raw.contains(want), "control: {want} in {raw}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// An oplog writer the test reads back.
#[derive(Clone, Default)]
struct Lines(Arc<Mutex<Vec<u8>>>);

impl Lines {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

impl std::io::Write for Lines {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
