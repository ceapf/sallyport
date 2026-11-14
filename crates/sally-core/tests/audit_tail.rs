//! `sally_core::audit::tail` (architect Q110): the newest entries, read-only, bounded.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use jiff::Timestamp;
use sally_core::audit::{
    Actor, AuditWriter, Clock, MAX_LINE_BYTES, MAX_TAIL, NewEntry, Tail, parse_line, tail,
};
use sally_core::manifest::AuditLevel;
use serde_json::json;

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("sally-tail-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(d)
    }

    fn dir(&self) -> PathBuf {
        self.0.join("audit")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone)]
struct TestClock(Arc<Mutex<Timestamp>>);

impl Clock for TestClock {
    fn now(&self) -> Timestamp {
        *self.0.lock().unwrap()
    }
}

/// `jan` entries in January, then `feb` in February; `i` counts across both.
fn log(s: &Scratch, jan: usize, feb: usize) {
    let clock = TestClock(Arc::new(Mutex::new(
        "2026-01-15T10:00:00Z".parse().unwrap(),
    )));
    let mut w = AuditWriter::open(&s.dir(), Box::new(clock.clone())).unwrap();
    for i in 0..jan + feb {
        if i == jan {
            *clock.0.lock().unwrap() = "2026-02-01T00:00:00Z".parse().unwrap();
        }
        let e = NewEntry::new(Actor::Sallyd, "tool.run").args(json!({ "i": i }));
        w.append(e, AuditLevel::Full).unwrap();
    }
}

fn indices(t: &Tail) -> Vec<u64> {
    t.lines
        .iter()
        .map(|l| {
            parse_line(l.as_bytes()).unwrap().args["i"]
                .as_u64()
                .unwrap()
        })
        .collect()
}

fn feb_file(s: &Scratch) -> PathBuf {
    s.dir().join("audit-202602.jsonl")
}

#[test]
fn the_newest_entries_come_oldest_first_across_months() {
    let s = Scratch::new("months");
    log(&s, 3, 2);
    assert_eq!(indices(&tail(&s.dir(), 3).unwrap()), [2, 3, 4]);
    assert_eq!(indices(&tail(&s.dir(), 2).unwrap()), [3, 4]);
    assert_eq!(indices(&tail(&s.dir(), 10).unwrap()), [0, 1, 2, 3, 4]);
    assert_eq!(tail(&s.dir(), 0).unwrap(), Tail::default());
    assert_eq!(tail(&s.dir(), 3).unwrap().unparsed, 0);
}

#[test]
fn a_tail_is_capped() {
    let s = Scratch::new("cap");
    log(&s, 0, 1);
    let one = std::fs::read_to_string(feb_file(&s)).unwrap();
    std::fs::write(feb_file(&s), one.repeat(MAX_TAIL + 1)).unwrap();
    assert_eq!(tail(&s.dir(), usize::MAX).unwrap().lines.len(), MAX_TAIL);
    assert_eq!(tail(&s.dir(), MAX_TAIL).unwrap().lines.len(), MAX_TAIL);
}

#[test]
fn an_append_in_flight_is_skipped_and_bad_lines_are_counted() {
    let s = Scratch::new("bad");
    log(&s, 0, 2);
    let mut text = std::fs::read_to_string(feb_file(&s)).unwrap();
    let good = text.lines().last().unwrap().to_owned();
    // Malformed, then over the cap but newline-terminated, then over the cap and past the
    // reader's limit, each followed by a good line that must survive; then a torn tail.
    text.push_str("not json\n");
    text.push_str(&format!("{good}\n"));
    text.push_str(&format!("{}\n", "x".repeat(MAX_LINE_BYTES + 1)));
    text.push_str(&format!("{good}\n"));
    text.push_str(&format!("{}\n", "y".repeat(MAX_LINE_BYTES * 2)));
    text.push_str(&format!("{good}\n"));
    text.push_str(&good[..good.len() / 2]);
    std::fs::write(feb_file(&s), text).unwrap();
    let t = tail(&s.dir(), 10).unwrap();
    assert_eq!(indices(&t), [0, 1, 1, 1, 1]);
    assert_eq!(t.unparsed, 3);
}

#[test]
fn a_missing_log_is_an_error_and_nothing_is_created() {
    let s = Scratch::new("missing");
    let e = tail(&s.dir(), 5).unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
    assert!(!s.dir().exists());
}
