//! RT-AUD-01 through the `sally` binary (architect Q110): `sally audit verify` fails, naming the
//! first bad `seq`, for each tampering the row lists, and an untouched log verifies. The log is
//! at `$HOME/.local/share/sallyport/audit`, as `sallyd` writes it.
//! Control: `sally_core::audit::verify` (the chain check); `audit_verify` only reports it.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};

use jiff::Timestamp;
use sally_core::audit::{Actor, AuditWriter, Clock, NewEntry};
use sally_core::manifest::AuditLevel;
use serde_json::json;

const JAN: &str = "2026-01-15T10:00:00.123Z";
const FEB: &str = "2026-02-01T00:00:00.000Z";

#[derive(Clone)]
struct TestClock(Arc<Mutex<Timestamp>>);

impl Clock for TestClock {
    fn now(&self) -> Timestamp {
        *self.0.lock().unwrap()
    }
}

struct Home(PathBuf);

impl Home {
    fn new(tag: &str) -> Self {
        let d = std::env::temp_dir().join(format!("sc-aud-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Self(d)
    }

    fn audit(&self) -> PathBuf {
        self.0.join(".local/share/sallyport/audit")
    }

    /// `jan` entries in January, then `feb` in February.
    fn log(&self, jan: usize, feb: usize) {
        let clock = TestClock(Arc::new(Mutex::new(JAN.parse().unwrap())));
        let mut w = AuditWriter::open(&self.audit(), Box::new(clock.clone())).unwrap();
        for i in 0..jan + feb {
            if i == jan {
                *clock.0.lock().unwrap() = FEB.parse().unwrap();
            }
            let e = NewEntry::new(Actor::Sallyd, "tool.run").args(json!({"i": i}));
            w.append(e, AuditLevel::Full).unwrap();
        }
    }

    fn verify(&self) -> Output {
        Command::new(env!("CARGO_BIN_EXE_sally"))
            .args(["audit", "verify"])
            .env_clear()
            .env("HOME", &self.0)
            .output()
            .unwrap()
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn lines(p: &Path) -> Vec<String> {
    std::fs::read_to_string(p)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

fn write_lines(p: &Path, l: &[String]) {
    std::fs::write(p, format!("{}\n", l.join("\n"))).unwrap();
}

/// Exit 1, nothing on stdout, and stderr naming `seq <n>`.
fn fails_at(o: &Output, seq: u64) {
    let err = String::from_utf8_lossy(&o.stderr);
    assert_eq!(o.status.code(), Some(1), "{err}");
    assert!(
        o.stdout.is_empty(),
        "{}",
        String::from_utf8_lossy(&o.stdout)
    );
    assert!(err.contains(&format!("seq {seq}")), "{err}");
    assert!(!err.contains(&format!("seq {}", seq + 1)), "{err}");
}

#[test]
fn rt_aud_01_an_untouched_log_verifies() {
    let h = Home::new("ok");
    h.log(2, 2);
    let o = h.verify();
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&o.stdout),
        "ok: 4 entries in 2 file(s), last seq 4, head current\n"
    );
}

#[test]
fn rt_aud_01_a_flipped_byte_in_a_middle_entry_is_named() {
    let h = Home::new("flip");
    h.log(5, 0);
    let file = h.audit().join("audit-202601.jsonl");
    let mut l = lines(&file);
    l[2] = l[2].replacen("\"i\":2", "\"i\":3", 1);
    write_lines(&file, &l);
    fails_at(&h.verify(), 3);
}

#[test]
fn rt_aud_01_a_deleted_last_entry_is_named() {
    let h = Home::new("last");
    h.log(4, 0);
    let file = h.audit().join("audit-202601.jsonl");
    let mut l = lines(&file);
    l.pop();
    write_lines(&file, &l);
    fails_at(&h.verify(), 4);
}

#[test]
fn rt_aud_01_two_reordered_entries_are_named() {
    let h = Home::new("order");
    h.log(5, 0);
    let file = h.audit().join("audit-202601.jsonl");
    let mut l = lines(&file);
    l.swap(1, 2);
    write_lines(&file, &l);
    fails_at(&h.verify(), 2);
}

/// The chain across files: January's last entry cut while February stays. Caught by the
/// walk's seq/prev-hash link, not by the head (whose seq still matches the log's end).
#[test]
fn rt_aud_01_a_cut_across_a_rotation_boundary_is_named() {
    let h = Home::new("cross");
    h.log(3, 2);
    let jan = h.audit().join("audit-202601.jsonl");
    let mut l = lines(&jan);
    l.pop();
    write_lines(&jan, &l);
    fails_at(&h.verify(), 3);
}

#[test]
fn rt_aud_01_truncation_at_a_rotation_boundary_is_named() {
    let h = Home::new("rot");
    h.log(2, 1);
    std::fs::remove_file(h.audit().join("audit-202602.jsonl")).unwrap();
    fails_at(&h.verify(), 3);
}
