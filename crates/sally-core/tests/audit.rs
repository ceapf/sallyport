//! `sally-core::audit`: hash-chained NDJSON log, redaction, rotation, tamper detection
//! (SI-4; RT-AUD-01, RT-SEC-07 building blocks).
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use jiff::Timestamp;
use proptest::prelude::*;
use sally_core::audit::{
    Actor, Appended, AuditError, AuditWriter, Clock, Detail, Entry, GENESIS_HASH, MAX_ARGS_BYTES,
    MAX_LINE_BYTES, NewEntry, Redactor, VerifyErrorKind, parse_line, verify,
};
use sally_core::manifest::AuditLevel;
use serde_json::json;
use sha2::{Digest, Sha256};

// ---- fixtures -----------------------------------------------------------------------------

struct Scratch(PathBuf);

impl Scratch {
    /// A directory of its own: the counter keeps two tests that pick the same name from
    /// deleting each other's files when they run in parallel (a flaky failure there made
    /// equivalent mutants look caught).
    fn new(name: &str) -> Self {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("sally-audit-{}-{n}-{name}", std::process::id()));
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
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A clock the test moves by hand.
#[derive(Clone)]
struct TestClock(Arc<Mutex<Timestamp>>);

impl TestClock {
    fn at(ts: &str) -> Self {
        Self(Arc::new(Mutex::new(ts.parse().unwrap())))
    }
    fn set(&self, ts: &str) {
        *self.0.lock().unwrap() = ts.parse().unwrap();
    }
}

impl Clock for TestClock {
    fn now(&self) -> Timestamp {
        *self.0.lock().unwrap()
    }
}

const JAN: &str = "2026-01-15T10:00:00.123Z";
const FEB: &str = "2026-02-01T00:00:00.000Z";

fn open(s: &Scratch, clock: &TestClock) -> AuditWriter {
    AuditWriter::open(&s.dir(), Box::new(clock.clone())).unwrap()
}

fn note(event: &str) -> NewEntry {
    NewEntry::new(Actor::Sallyd, event)
}

/// `n` entries in January, returns the log file path.
fn filled(s: &Scratch, n: usize) -> PathBuf {
    let clock = TestClock::at(JAN);
    let mut w = open(s, &clock);
    for i in 0..n {
        w.append(
            note("tool.executed")
                .session("sess-1")
                .decision("allow")
                .args(json!({ "i": i, "cmd": "ls" })),
            AuditLevel::Full,
        )
        .unwrap();
    }
    s.dir().join("audit-202601.jsonl")
}

fn lines(p: &Path) -> Vec<String> {
    std::fs::read_to_string(p)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

fn write_lines(p: &Path, l: &[String]) {
    let mut text = l.join("\n");
    text.push('\n');
    std::fs::write(p, text).unwrap();
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

fn all_bytes_under(dir: &Path) -> Vec<u8> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        out.extend(std::fs::read(e.unwrap().path()).unwrap());
    }
    out
}

fn contains(hay: &[u8], needle: &str) -> bool {
    hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

// ---- format and chain ---------------------------------------------------------------------

#[test]
fn empty_log_verifies() {
    let s = Scratch::new("empty");
    let clock = TestClock::at(JAN);
    drop(open(&s, &clock));
    let report = verify(&s.dir()).unwrap();
    assert_eq!(report.entries, 0);
}

#[test]
fn entries_are_chained_from_the_genesis_hash() {
    let s = Scratch::new("chain");
    let log = filled(&s, 3);
    let l = lines(&log);
    assert_eq!(l.len(), 3);
    let mut prev = GENESIS_HASH.to_owned();
    for (i, line) in l.iter().enumerate() {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["seq"], i as u64 + 1);
        assert_eq!(v["prev_hash"], prev);
        prev = v["hash"].as_str().unwrap().to_owned();
    }
    let report = verify(&s.dir()).unwrap();
    assert_eq!(
        (report.entries, report.last_seq, report.last_hash),
        (3, 3, prev)
    );
}

/// A good entry, changed by `f`, then re-sealed: canonical, with a correct `hash`, so only the
/// field rules can refuse it. `args_sha256` is recomputed unless `stale_args`.
fn resealed(f: impl Fn(&mut Entry), stale_args: bool) -> Vec<u8> {
    let s = Scratch::new("reseal");
    let mut e = parse_line(lines(&filled(&s, 1))[0].as_bytes()).unwrap();
    f(&mut e);
    if !stale_args {
        e.args_sha256 = sha256_hex(serde_json::to_string(&e.args).unwrap().as_bytes());
    }
    e.hash = e.compute_hash();
    e.to_line().into_bytes()
}

/// Every field rule refuses on its own: a line that is canonical and correctly hashed is still
/// refused for one bad field, and accepted for an unusual but valid one.
#[test]
fn each_field_rule_refuses_a_correctly_hashed_line() {
    use VerifyErrorKind::{ArgsHashMismatch, Malformed};
    let ts_long = |e: &mut Entry| e.ts.push('0');
    let cases: Vec<(&str, Vec<u8>, Result<(), VerifyErrorKind>)> = vec![
        ("control", resealed(|_| {}, false), Ok(())),
        ("seq 0", resealed(|e| e.seq = 0, false), Err(Malformed)),
        (
            "ts not a time",
            resealed(|e| e.ts = "x".into(), false),
            Err(Malformed),
        ),
        (
            "ts one digit long",
            resealed(ts_long, false),
            Err(Malformed),
        ),
        (
            "decision with digits, _ . -",
            resealed(|e| e.decision = Some("deny_2.x-y".into()), false),
            Ok(()),
        ),
        // Two keys that are not the truncation marker: the args hash is still checked.
        (
            "not a marker",
            resealed(|e| e.args = json!({ "truncated": false, "bytes": 1 }), true),
            Err(ArgsHashMismatch),
        ),
    ];
    for (what, line, want) in cases {
        assert_eq!(parse_line(&line).map(|_| ()), want, "{what}");
    }
}

/// The line bound is inclusive and restated here: 8 KiB passes the length check (and fails
/// as JSON), one byte more is too long. Args are cut at 4 KiB.
#[test]
fn line_and_args_bounds_are_8_and_4_kib() {
    assert_eq!((MAX_LINE_BYTES, MAX_ARGS_BYTES), (8192, 4096));
    assert_eq!(
        parse_line(&[b'x'; 8192]).map(|_| ()),
        Err(VerifyErrorKind::Malformed)
    );
    assert_eq!(
        parse_line(&[b'x'; 8193]).map(|_| ()),
        Err(VerifyErrorKind::LineTooLong)
    );
}

#[test]
fn hash_is_sha256_of_prev_hash_then_canonical_json_without_hash() {
    let s = Scratch::new("hashdef");
    let log = filled(&s, 2);
    let l = lines(&log);
    let v: serde_json::Value = serde_json::from_str(&l[1]).unwrap();
    // `hash` is the last field, so the unhashed canonical form is the line minus that field.
    let suffix = format!(",\"hash\":\"{}\"}}", v["hash"].as_str().unwrap());
    let body = format!("{}}}", l[1].strip_suffix(&suffix).unwrap());
    let expect = sha256_hex(format!("{}{body}", v["prev_hash"].as_str().unwrap()).as_bytes());
    assert_eq!(v["hash"], expect);
}

#[test]
fn fields_are_in_the_documented_order_and_args_hash_is_present() {
    let s = Scratch::new("fields");
    let log = filled(&s, 1);
    let line = &lines(&log)[0];
    let keys = [
        "seq",
        "ts",
        "session",
        "actor",
        "event",
        "decision",
        "args",
        "args_sha256",
        "prev_hash",
        "hash",
    ];
    let mut at = 0;
    for k in keys {
        let found = line[at..]
            .find(&format!("\"{k}\":"))
            .unwrap_or_else(|| panic!("{k} in {line}"));
        at += found;
    }
    assert!(line.contains("\"ts\":\"2026-01-15T10:00:00.123Z\""));
    assert!(line.contains("\"actor\":\"sallyd\""));
}

#[test]
fn args_sha256_is_the_hash_of_the_canonical_args() {
    let s = Scratch::new("argshash");
    let log = filled(&s, 1);
    let v: serde_json::Value = serde_json::from_str(&lines(&log)[0]).unwrap();
    let canonical = serde_json::to_string(&v["args"]).unwrap();
    assert_eq!(v["args_sha256"], sha256_hex(canonical.as_bytes()));
}

#[test]
fn files_and_directory_are_private() {
    let s = Scratch::new("modes");
    let log = filled(&s, 1);
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mode(&s.dir()), 0o700);
    assert_eq!(mode(&log), 0o600);
    for e in std::fs::read_dir(s.dir()).unwrap() {
        assert_eq!(mode(&e.unwrap().path()) & 0o077, 0);
    }
}

#[test]
fn reopening_continues_the_chain() {
    let s = Scratch::new("reopen");
    filled(&s, 2);
    let clock = TestClock::at(JAN);
    let mut w = open(&s, &clock);
    assert_eq!(
        w.append(note("session.stop"), AuditLevel::Actions)
            .unwrap()
            .seq(),
        Some(3)
    );
    drop(w);
    assert_eq!(verify(&s.dir()).unwrap().entries, 3);
}

#[test]
fn second_writer_is_refused_while_the_first_is_alive() {
    let s = Scratch::new("lock");
    let clock = TestClock::at(JAN);
    let first = open(&s, &clock);
    let err = AuditWriter::open(&s.dir(), Box::new(clock.clone()))
        .err()
        .unwrap();
    assert!(matches!(err, AuditError::Locked { .. }), "{err:?}");
    drop(first);
    drop(open(&s, &clock));
}

#[test]
fn open_refuses_a_group_writable_directory() {
    let s = Scratch::new("badmode");
    std::fs::create_dir(s.dir()).unwrap();
    std::fs::set_permissions(s.dir(), std::fs::Permissions::from_mode(0o770)).unwrap();
    let clock = TestClock::at(JAN);
    let err = AuditWriter::open(&s.dir(), Box::new(clock)).err().unwrap();
    assert!(matches!(err, AuditError::Permissions { .. }), "{err:?}");
}

// ---- levels -------------------------------------------------------------------------------

#[test]
fn level_actions_drops_detail_but_never_a_decision() {
    let s = Scratch::new("levels");
    let clock = TestClock::at(JAN);
    let mut w = open(&s, &clock);
    let detail = note("egress.request").detail(Detail::Full);
    assert_eq!(
        w.append(detail.clone(), AuditLevel::Actions).unwrap(),
        Appended::Filtered
    );
    assert!(matches!(
        w.append(detail, AuditLevel::Full).unwrap(),
        Appended::Written { .. }
    ));
    assert!(matches!(
        w.append(note("egress.deny").decision("deny"), AuditLevel::Actions)
            .unwrap(),
        Appended::Written { .. }
    ));
    drop(w);
    let report = verify(&s.dir()).unwrap();
    assert_eq!(report.entries, 2);
}

// ---- validation ---------------------------------------------------------------------------

#[test]
fn malformed_event_session_and_decision_are_rejected_and_not_written() {
    let s = Scratch::new("invalid");
    let clock = TestClock::at(JAN);
    let mut w = open(&s, &clock);
    let long = "a".repeat(65);
    let bad = [
        note(""),
        note("Tool.Executed"),
        note("tool executed"),
        note("tool\nexecuted"),
        note(&long),
        note("ok.event").session("has space"),
        note("ok.event").session(&long),
        note("ok.event").decision("ALLOW"),
        note("ok.event").decision(""),
    ];
    for e in bad {
        let err = w.append(e, AuditLevel::Full).unwrap_err();
        assert!(matches!(err, AuditError::InvalidEntry(_)), "{err:?}");
    }
    drop(w);
    assert_eq!(verify(&s.dir()).unwrap().entries, 0);
}

// ---- redaction (RT-SEC-07 building blocks) ------------------------------------------------

fn token() -> String {
    common::fake_token(&["gh", "p_"], "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789")
}

#[test]
fn secret_values_never_reach_the_file_in_any_form() {
    let s = Scratch::new("redact");
    let secret = token();
    let password = "pa ss+word/with=special&chars";
    let clock = TestClock::at(JAN);
    let mut w = open(&s, &clock);
    w.set_redactor(Redactor::new([
        ("GITHUB_TOKEN", secret.as_str()),
        ("PASSWORD", password),
    ]));
    let b64 = |alphabet: &[u8; 64], data: &[u8]| -> String {
        // Independent encoder for the test: standard or url-safe, padded.
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let n = chunk
                .iter()
                .enumerate()
                .fold(0u32, |a, (i, b)| a | (u32::from(*b) << (16 - 8 * i)));
            for i in 0..4 {
                if i <= chunk.len() {
                    out.push(alphabet[((n >> (18 - 6 * i)) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    };
    let std_a = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let url_a = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let basic = b64(std_a, format!("x-access-token:{secret}").as_bytes());
    let pct = "pa%20ss%2Bword%2Fwith%3Dspecial%26chars";
    let form = "pa+ss%2Bword%2Fwith%3Dspecial%26chars";
    w.append(
        note("tool.executed").args(json!({
            "raw": secret,
            "nested": { "list": [format!("Bearer {secret}"), 1, null, true] },
            secret.clone(): "value under a secret key",
            "basic": basic,
            "std64": b64(std_a, secret.as_bytes()),
            "url64": b64(url_a, secret.as_bytes()),
            "pct": pct,
            "form": form,
            "plainpw": password,
            "padded": format!("xx{secret}yy"),
        })),
        AuditLevel::Full,
    )
    .unwrap();
    drop(w);
    let bytes = all_bytes_under(&s.dir());
    assert!(!contains(&bytes, &secret));
    for leaked in [
        b64(std_a, secret.as_bytes()),
        b64(url_a, secret.as_bytes()),
        basic,
        pct.to_owned(),
        form.to_owned(),
        password.to_owned(),
    ] {
        assert!(!contains(&bytes, &leaked), "form leaked: {leaked}");
    }
    assert!(contains(&bytes, "[REDACTED:GITHUB_TOKEN]"));
    assert!(contains(&bytes, "[REDACTED:PASSWORD]"));
    verify(&s.dir()).unwrap();
}

#[test]
fn args_hash_covers_the_redacted_args_not_the_raw_ones() {
    let s = Scratch::new("redacthash");
    let secret = token();
    let clock = TestClock::at(JAN);
    let mut w = open(&s, &clock);
    w.set_redactor(Redactor::new([("GITHUB_TOKEN", secret.as_str())]));
    w.append(
        note("tool.executed").args(json!({ "k": secret })),
        AuditLevel::Full,
    )
    .unwrap();
    drop(w);
    let line = &lines(&s.dir().join("audit-202601.jsonl"))[0];
    let v: serde_json::Value = serde_json::from_str(line).unwrap();
    let raw_hash = sha256_hex(
        serde_json::to_string(&json!({ "k": secret }))
            .unwrap()
            .as_bytes(),
    );
    assert_ne!(
        v["args_sha256"], raw_hash,
        "a hash of the raw args would let a short secret be brute-forced"
    );
    assert_eq!(
        v["args_sha256"],
        sha256_hex(serde_json::to_string(&v["args"]).unwrap().as_bytes())
    );
}

#[test]
fn redactor_debug_hides_values_and_patterns() {
    let secret = token();
    let r = Redactor::new([("GITHUB_TOKEN", secret.as_str())]);
    let shown = format!("{r:?}");
    assert!(!shown.contains(&secret));
    assert!(!shown.contains(&secret[..12]));
    // It still says what it holds: how many secrets, without them.
    assert!(shown.starts_with("Redactor {"), "{shown}");
    assert!(shown.contains("secrets: 1"), "{shown}");
}

/// Hits are merged only when they overlap: overlapping secrets go as one placeholder, adjacent
/// or separate ones keep their own.
#[test]
fn overlapping_hits_merge_and_adjacent_ones_do_not() {
    let r = Redactor::new([("A", "abcdef"), ("B", "defghi"), ("C", "uvw"), ("D", "xyz")]);
    let cases = [
        ("<abcdefghi>", "<[REDACTED:A]>"),
        ("<uvwxyz>", "<[REDACTED:C][REDACTED:D]>"),
        ("<uvw-xyz>", "<[REDACTED:C]-[REDACTED:D]>"),
        ("<abcdef-defghi>", "<[REDACTED:A]-[REDACTED:B]>"),
    ];
    for (input, want) in cases {
        assert_eq!(r.redact_str(input), want, "{input}");
    }
}

/// Nesting is cut at depth 32, in arrays and objects alike: a leaf at depth 32 is redacted
/// normally, one at depth 33 becomes the marker.
#[test]
fn values_are_kept_to_depth_32_and_cut_below() {
    let r = Redactor::new([("S", "hunter2hunter2")]);
    let nest = |depth: usize, object: bool| {
        (0..depth).fold(json!("leaf"), |v, _| {
            if object {
                json!({ "k": v })
            } else {
                json!([v])
            }
        })
    };
    for object in [false, true] {
        let kept = nest(32, object);
        assert_eq!(r.redact_value(&kept), kept, "object: {object}");
        let cut = r.redact_value(&nest(33, object));
        assert!(
            cut.to_string().contains("[REDACTED:too-deep]"),
            "object: {object}"
        );
        assert!(!cut.to_string().contains("leaf"), "object: {object}");
    }
}

#[test]
fn oversized_args_are_replaced_by_a_marker_and_a_hash_of_the_full_value() {
    let s = Scratch::new("big");
    let clock = TestClock::at(JAN);
    let mut w = open(&s, &clock);
    let big = "y".repeat(MAX_ARGS_BYTES * 4);
    w.append(
        note("tool.executed").args(json!({ "body": big })),
        AuditLevel::Full,
    )
    .unwrap();
    w.append(
        note("tool.executed").args(json!({ "body": "small" })),
        AuditLevel::Full,
    )
    .unwrap();
    drop(w);
    let l = lines(&s.dir().join("audit-202601.jsonl"));
    assert!(
        l[0].len() < 1024,
        "entry line must not carry the oversized args"
    );
    let v: serde_json::Value = serde_json::from_str(&l[0]).unwrap();
    assert_eq!(v["args"]["truncated"], true);
    assert!(v["args"]["bytes"].as_u64().unwrap() > MAX_ARGS_BYTES as u64);
    let full = serde_json::to_string(&json!({ "body": big })).unwrap();
    assert_eq!(v["args_sha256"], sha256_hex(full.as_bytes()));
    verify(&s.dir()).unwrap();
}

#[test]
fn args_exactly_at_the_limit_are_kept() {
    let s = Scratch::new("limit");
    let clock = TestClock::at(JAN);
    let mut w = open(&s, &clock);
    let overhead = serde_json::to_string(&json!({ "b": "" })).unwrap().len();
    let fit = "z".repeat(MAX_ARGS_BYTES - overhead);
    w.append(
        note("tool.executed").args(json!({ "b": fit })),
        AuditLevel::Full,
    )
    .unwrap();
    w.append(
        note("tool.executed").args(json!({ "b": format!("{fit}z") })),
        AuditLevel::Full,
    )
    .unwrap();
    drop(w);
    let l = lines(&s.dir().join("audit-202601.jsonl"));
    assert!(l[0].contains("zzzz"));
    assert!(!l[1].contains("zzzz"));
    verify(&s.dir()).unwrap();
}

proptest! {
    /// B1: the base64 of ANY string containing the secret is caught, in either alphabet, with
    /// or without padding.
    #[test]
    fn base64_of_any_string_containing_the_secret_is_redacted(
        secret in "[ -~]{16,40}",
        prefix in proptest::collection::vec(any::<u8>(), 0..7),
        suffix in proptest::collection::vec(any::<u8>(), 0..7),
        url_safe in any::<bool>(),
        padded in any::<bool>(),
    ) {
        let mut data = prefix;
        data.extend_from_slice(secret.as_bytes());
        data.extend_from_slice(&suffix);
        let alphabet: &[u8; 64] = if url_safe {
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        } else {
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        };
        let mut enc = String::new();
        for chunk in data.chunks(3) {
            let n = chunk.iter().enumerate().fold(0u32, |a, (i, b)| a | (u32::from(*b) << (16 - 8 * i)));
            for i in 0..4 {
                if i <= chunk.len() {
                    enc.push(alphabet[((n >> (18 - 6 * i)) & 63) as usize] as char);
                } else if padded {
                    enc.push('=');
                }
            }
        }
        let r = Redactor::new([("S", secret.as_str())]);
        let out = r.redact_str(&enc);
        prop_assert!(out.contains("[REDACTED:S]"), "{enc} -> {out}");
    }

    #[test]
    fn the_raw_secret_is_always_redacted(secret in "[ -~]{1,40}", pre in "[ -~]{0,10}", post in "[ -~]{0,10}") {
        prop_assume!(secret == secret.trim());
        let r = Redactor::new([("S", secret.as_str())]);
        let input = format!("{pre}{secret}{post}");
        let out = r.redact_str(&input);
        prop_assert!(out.contains("[REDACTED:S]"));
    }
}

// ---- rotation -----------------------------------------------------------------------------

#[test]
fn a_new_month_starts_a_new_file_that_continues_the_chain() {
    let s = Scratch::new("rotate");
    let clock = TestClock::at(JAN);
    let mut w = open(&s, &clock);
    w.append(note("a.one"), AuditLevel::Full).unwrap();
    clock.set(FEB);
    w.append(note("a.two"), AuditLevel::Full).unwrap();
    w.append(note("a.three"), AuditLevel::Full).unwrap();
    drop(w);
    let jan = lines(&s.dir().join("audit-202601.jsonl"));
    let feb = lines(&s.dir().join("audit-202602.jsonl"));
    assert_eq!((jan.len(), feb.len()), (1, 2));
    let last_jan: serde_json::Value = serde_json::from_str(&jan[0]).unwrap();
    let first_feb: serde_json::Value = serde_json::from_str(&feb[0]).unwrap();
    assert_eq!(first_feb["prev_hash"], last_jan["hash"]);
    assert_eq!(first_feb["seq"], 2);
    assert_eq!(verify(&s.dir()).unwrap().files, 2);
}

#[test]
fn a_clock_that_steps_back_never_rotates_backwards() {
    let s = Scratch::new("clockback");
    let clock = TestClock::at(FEB);
    let mut w = open(&s, &clock);
    w.append(note("a.one"), AuditLevel::Full).unwrap();
    clock.set(JAN);
    w.append(note("a.two"), AuditLevel::Full).unwrap();
    drop(w);
    assert!(!s.dir().join("audit-202601.jsonl").exists());
    assert_eq!(lines(&s.dir().join("audit-202602.jsonl")).len(), 2);
    verify(&s.dir()).unwrap();
}

#[test]
fn reopening_in_a_later_month_continues_across_files() {
    let s = Scratch::new("reopenrot");
    filled(&s, 2);
    let clock = TestClock::at(FEB);
    let mut w = open(&s, &clock);
    assert_eq!(
        w.append(note("a.next"), AuditLevel::Full).unwrap().seq(),
        Some(3)
    );
    drop(w);
    assert_eq!(verify(&s.dir()).unwrap().entries, 3);
}

// ---- tamper detection (RT-AUD-01) ---------------------------------------------------------

fn first_bad(s: &Scratch) -> (u64, VerifyErrorKind) {
    let e = verify(&s.dir()).unwrap_err();
    (e.seq, e.kind)
}

#[test]
fn flipping_any_byte_of_an_entry_fails_verification_at_that_seq() {
    let s = Scratch::new("flip");
    let log = filled(&s, 5);
    let original = std::fs::read(&log).unwrap();
    let l = lines(&log);
    let start: usize = l[..2].iter().map(|x| x.len() + 1).sum();
    let len = l[2].len();
    for off in 0..len {
        let mut data = original.clone();
        data[start + off] ^= 0x01;
        std::fs::write(&log, &data).unwrap();
        let err = verify(&s.dir()).unwrap_err();
        assert!(
            err.seq <= 3,
            "offset {off}: first bad seq {} must not come after the edited entry",
            err.seq
        );
        assert_eq!(err.seq, 3, "offset {off}: bad seq {}", err.seq);
    }
    std::fs::write(&log, &original).unwrap();
    verify(&s.dir()).unwrap();
}

#[test]
fn deleting_the_last_entry_is_detected() {
    let s = Scratch::new("droplast");
    let log = filled(&s, 4);
    let mut l = lines(&log);
    l.pop();
    write_lines(&log, &l);
    let (seq, kind) = first_bad(&s);
    assert_eq!(seq, 4);
    assert_eq!(kind, VerifyErrorKind::TailMissing);
}

#[test]
fn deleting_a_middle_entry_is_detected() {
    let s = Scratch::new("dropmid");
    let log = filled(&s, 5);
    let mut l = lines(&log);
    l.remove(2);
    write_lines(&log, &l);
    assert_eq!(first_bad(&s).0, 3);
}

#[test]
fn reordering_two_entries_is_detected() {
    let s = Scratch::new("reorder");
    let log = filled(&s, 5);
    let mut l = lines(&log);
    l.swap(1, 2);
    write_lines(&log, &l);
    assert_eq!(first_bad(&s).0, 2);
}

#[test]
fn deleting_the_first_entry_is_detected() {
    let s = Scratch::new("dropfirst");
    let log = filled(&s, 3);
    let mut l = lines(&log);
    l.remove(0);
    write_lines(&log, &l);
    assert_eq!(first_bad(&s).0, 1);
}

#[test]
fn truncating_at_a_rotation_boundary_is_detected() {
    let s = Scratch::new("rotboundary");
    let clock = TestClock::at(JAN);
    let mut w = open(&s, &clock);
    w.append(note("a.one"), AuditLevel::Full).unwrap();
    w.append(note("a.two"), AuditLevel::Full).unwrap();
    clock.set(FEB);
    w.append(note("a.three"), AuditLevel::Full).unwrap();
    drop(w);
    std::fs::remove_file(s.dir().join("audit-202602.jsonl")).unwrap();
    let (seq, kind) = first_bad(&s);
    assert_eq!((seq, kind), (3, VerifyErrorKind::TailMissing));
}

#[test]
fn removing_an_earlier_month_file_is_detected() {
    let s = Scratch::new("dropmonth");
    let clock = TestClock::at(JAN);
    let mut w = open(&s, &clock);
    w.append(note("a.one"), AuditLevel::Full).unwrap();
    clock.set(FEB);
    w.append(note("a.two"), AuditLevel::Full).unwrap();
    drop(w);
    std::fs::remove_file(s.dir().join("audit-202601.jsonl")).unwrap();
    assert_eq!(first_bad(&s).0, 1);
}

#[test]
fn a_missing_or_altered_head_with_a_longer_log_is_detected() {
    let s = Scratch::new("head");
    filled(&s, 3);
    let head = s.dir().join("audit.head");
    let good = std::fs::read(&head).unwrap();
    std::fs::remove_file(&head).unwrap();
    assert_eq!(first_bad(&s).1, VerifyErrorKind::HeadMissing);
    std::fs::write(&head, b"{\"seq\":3,\"hash\":\"00\"}\n").unwrap();
    assert!(verify(&s.dir()).is_err());
    std::fs::write(&head, b"not json").unwrap();
    assert!(verify(&s.dir()).is_err());
    std::fs::write(&head, &good).unwrap();
    verify(&s.dir()).unwrap();
}

#[test]
fn appended_junk_and_forged_entries_are_detected() {
    let s = Scratch::new("junk");
    let log = filled(&s, 3);
    let original = std::fs::read(&log).unwrap();
    let l = lines(&log);
    for extra in [
        "garbage".to_owned(),
        String::new(),
        "{}".to_owned(),
        // A syntactically valid entry cloned from line 2 with a new seq but no new hash.
        l[1].replacen("\"seq\":2", "\"seq\":4", 1),
    ] {
        let mut data = original.clone();
        data.extend_from_slice(extra.as_bytes());
        data.push(b'\n');
        std::fs::write(&log, &data).unwrap();
        assert!(verify(&s.dir()).is_err(), "{extra:?}");
    }
}

#[test]
fn non_canonical_but_equivalent_edits_are_detected() {
    let s = Scratch::new("canon");
    let log = filled(&s, 2);
    let mut l = lines(&log);
    l[0] = l[0].replacen("\"seq\":1,", "\"seq\": 1,", 1);
    write_lines(&log, &l);
    assert_eq!(first_bad(&s).0, 1);
}

#[test]
fn an_unknown_extra_field_is_detected() {
    let s = Scratch::new("extra");
    let log = filled(&s, 2);
    let mut l = lines(&log);
    l[1] = l[1].replacen("{\"seq\"", "{\"x\":1,\"seq\"", 1);
    write_lines(&log, &l);
    assert_eq!(first_bad(&s).0, 2);
}

#[test]
fn an_unterminated_final_line_is_detected_by_verify() {
    let s = Scratch::new("noeol");
    let log = filled(&s, 2);
    let data = std::fs::read(&log).unwrap();
    std::fs::write(&log, &data[..data.len() - 1]).unwrap();
    assert!(verify(&s.dir()).is_err());
}

#[test]
fn a_huge_line_is_refused_without_reading_it_all() {
    let s = Scratch::new("hugeline");
    let log = filled(&s, 1);
    let mut f = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
    std::io::Write::write_all(&mut f, &vec![b'a'; 4 * 1024 * 1024]).unwrap();
    let e = verify(&s.dir()).unwrap_err();
    assert_eq!(e.kind, VerifyErrorKind::LineTooLong);
}

#[test]
fn verify_errors_name_the_seq_and_never_echo_log_text() {
    let s = Scratch::new("noecho");
    let log = filled(&s, 3);
    let mut l = lines(&log);
    l[1] = l[1].replacen("\"cmd\":\"ls\"", "\"cmd\":\"canary-text-in-log\"", 1);
    write_lines(&log, &l);
    let e = verify(&s.dir()).unwrap_err();
    let shown = format!("{e} | {e:?}");
    assert!(shown.contains("seq 2"), "{shown}");
    assert!(!shown.contains("canary-text-in-log"));
    // The file and the 1-based line are named, so a person can find the entry.
    assert_eq!(e.line, Some(2));
    assert!(
        e.to_string()
            .starts_with("audit verification failed at seq 2 (audit-202601.jsonl line 2): "),
        "{e}"
    );
}

/// The line bound when reading is inclusive (8 KiB plus the newline is read whole and then
/// parsed), and an unterminated tail longer than the bound is too long, not torn.
#[test]
fn verify_reads_a_line_of_exactly_8_kib_and_refuses_a_longer_tail() {
    let cases: [(&[u8], VerifyErrorKind); 2] = [
        (
            &[b"x".repeat(8192).as_slice(), b"\n"].concat(),
            VerifyErrorKind::Malformed,
        ),
        (&b"x".repeat(9000), VerifyErrorKind::LineTooLong),
    ];
    for (tail, want) in cases {
        let s = Scratch::new("8kib");
        let log = filled(&s, 1);
        let mut f = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
        std::io::Write::write_all(&mut f, tail).unwrap();
        let e = verify(&s.dir()).unwrap_err();
        assert_eq!(
            (e.seq, e.kind, e.line),
            (2, want, Some(2)),
            "{} bytes",
            tail.len()
        );
    }
}

/// Only the newest file may end in a torn line; in an older one it is damage.
#[test]
fn an_unterminated_line_in_an_older_file_is_malformed() {
    let s = Scratch::new("torn-old");
    let clock = TestClock::at(JAN);
    let mut w = open(&s, &clock);
    w.append(note("a.one"), AuditLevel::Full).unwrap();
    w.append(note("a.two"), AuditLevel::Full).unwrap();
    clock.set(FEB);
    w.append(note("a.three"), AuditLevel::Full).unwrap();
    drop(w);
    let jan = s.dir().join("audit-202601.jsonl");
    let data = std::fs::read(&jan).unwrap();
    std::fs::write(&jan, &data[..data.len() - 1]).unwrap();
    let e = verify(&s.dir()).unwrap_err();
    assert_eq!(
        (e.seq, e.kind, e.location.as_str(), e.line),
        (2, VerifyErrorKind::Malformed, "audit-202601.jsonl", Some(2))
    );
}

// ---- recovery -----------------------------------------------------------------------------

#[test]
fn a_torn_final_line_is_dropped_on_open_and_recorded() {
    let s = Scratch::new("torn");
    let log = filled(&s, 2);
    let mut f = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
    std::io::Write::write_all(&mut f, b"{\"seq\":3,\"ts\":\"2026-01-15T10:0").unwrap();
    drop(f);
    let clock = TestClock::at(JAN);
    let mut w = open(&s, &clock);
    w.append(note("session.stop"), AuditLevel::Full).unwrap();
    drop(w);
    let l = lines(&log);
    assert_eq!(l.len(), 4);
    assert!(l[2].contains("\"event\":\"audit.recovered\""));
    assert!(l[2].contains("\"dropped_bytes\":"));
    verify(&s.dir()).unwrap();
}

#[test]
fn a_head_one_entry_behind_the_log_is_repaired() {
    let s = Scratch::new("headbehind");
    filled(&s, 3);
    let head = s.dir().join("audit.head");
    let log = s.dir().join("audit-202601.jsonl");
    let l = lines(&log);
    // Simulate a crash between the entry write and the head update: head still names entry 2.
    let second: serde_json::Value = serde_json::from_str(&l[1]).unwrap();
    std::fs::write(
        &head,
        format!(
            "{{\"seq\":2,\"hash\":\"{}\"}}\n",
            second["hash"].as_str().unwrap()
        ),
    )
    .unwrap();
    verify(&s.dir()).unwrap();
    let clock = TestClock::at(JAN);
    drop(open(&s, &clock));
    verify(&s.dir()).unwrap();
    let repaired = std::fs::read_to_string(&head).unwrap();
    assert!(repaired.contains("\"seq\":3"));
}

#[test]
fn open_refuses_a_log_whose_tail_is_missing() {
    let s = Scratch::new("opentail");
    let log = filled(&s, 3);
    let mut l = lines(&log);
    l.pop();
    write_lines(&log, &l);
    let clock = TestClock::at(JAN);
    let err = AuditWriter::open(&s.dir(), Box::new(clock)).err().unwrap();
    assert!(matches!(err, AuditError::TailMissing), "{err:?}");
    assert!(
        err.to_string().contains("move the audit directory aside"),
        "{err}"
    );
}

#[test]
fn open_refuses_a_log_whose_last_entry_is_forged() {
    let s = Scratch::new("openforged");
    let log = filled(&s, 3);
    let mut l = lines(&log);
    l[2] = l[2].replacen("\"cmd\":\"ls\"", "\"cmd\":\"rm\"", 1);
    write_lines(&log, &l);
    let clock = TestClock::at(JAN);
    assert!(AuditWriter::open(&s.dir(), Box::new(clock)).is_err());
}

/// Replays the fuzz corpus through the fuzz target's invariants, so a regression shows up in
/// `make test` and not only in the 60 s CI fuzz run. The valid seed was built independently
/// (Python `hashlib`), so it also pins the canonical form and the hash definition.
#[test]
fn fuzz_corpus_satisfies_the_parser_invariants() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus/audit_line");
    let mut accepted = 0;
    let mut seen = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let data = std::fs::read(&path).unwrap();
        seen += 1;
        if let Ok((seq, hash)) = sally_core::audit::parse_head(&data) {
            assert_eq!(
                format!("{{\"seq\":{seq},\"hash\":\"{hash}\"}}\n").as_bytes(),
                data.as_slice()
            );
            continue;
        }
        if let Ok(e) = sally_core::audit::parse_line(&data) {
            accepted += 1;
            assert_eq!(e.to_line().as_bytes(), data.as_slice());
            assert_eq!(e.compute_hash(), e.hash);
        } else {
            assert_ne!(
                path.file_name().unwrap(),
                "seed-valid",
                "the valid seed must parse"
            );
        }
    }
    assert!(seen >= 7, "corpus went missing");
    assert_eq!(accepted, 1, "exactly the valid seed parses");
}

// ---- review round: head reconciliation, splices, symlinks, redaction gaps -------------------

fn hash_of(line: &str) -> String {
    serde_json::from_str::<serde_json::Value>(line).unwrap()["hash"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn set_head(s: &Scratch, seq: u64, hash: &str) {
    std::fs::write(
        s.dir().join("audit.head"),
        format!("{{\"seq\":{seq},\"hash\":\"{hash}\"}}\n"),
    )
    .unwrap();
}

fn open_err(s: &Scratch) -> AuditError {
    AuditWriter::open(&s.dir(), Box::new(TestClock::at(JAN)))
        .err()
        .unwrap()
}

const A64: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn open_refuses_when_every_log_file_is_gone_but_the_head_remains() {
    let s = Scratch::new("alllogsgone");
    let log = filled(&s, 2);
    std::fs::remove_file(log).unwrap();
    assert!(matches!(open_err(&s), AuditError::TailMissing));
}

#[test]
fn open_refuses_a_multi_entry_log_without_a_head() {
    let s = Scratch::new("nohead");
    filled(&s, 3);
    std::fs::remove_file(s.dir().join("audit.head")).unwrap();
    assert!(matches!(open_err(&s), AuditError::HeadMissing));
}

#[test]
fn open_adopts_a_lone_first_entry_without_a_head() {
    let s = Scratch::new("firstnohead");
    filled(&s, 1);
    std::fs::remove_file(s.dir().join("audit.head")).unwrap();
    drop(open(&s, &TestClock::at(JAN)));
    assert_eq!(
        verify(&s.dir()).unwrap().head,
        sally_core::audit::HeadStatus::Current
    );
}

#[test]
fn open_refuses_heads_that_disagree_with_the_log() {
    let s = Scratch::new("headdisagree");
    let log = filled(&s, 3);
    let l = lines(&log);
    // Same seq, different hash.
    set_head(&s, 3, A64);
    assert!(matches!(open_err(&s), AuditError::Corrupt { .. }));
    // One behind, but not this log's entry.
    set_head(&s, 2, A64);
    assert!(
        matches!(open_err(&s), AuditError::Corrupt { .. }),
        "a forged extension must not be adopted"
    );
    // Two behind: never produced by a crash.
    set_head(&s, 1, &hash_of(&l[0]));
    assert!(matches!(open_err(&s), AuditError::Corrupt { .. }));
}

#[test]
fn verify_distinguishes_a_wrong_head_from_a_lagging_one() {
    let s = Scratch::new("verifyhead");
    let log = filled(&s, 4);
    let l = lines(&log);
    set_head(&s, 4, A64);
    assert_eq!(
        verify(&s.dir()).unwrap_err().kind,
        VerifyErrorKind::HeadMismatch
    );
    set_head(&s, 2, A64);
    assert_eq!(
        verify(&s.dir()).unwrap_err().kind,
        VerifyErrorKind::HeadMismatch
    );
    // A writer may be a few entries ahead of the head while verify runs.
    set_head(&s, 2, &hash_of(&l[1]));
    assert_eq!(
        verify(&s.dir()).unwrap().head,
        sally_core::audit::HeadStatus::LogAhead
    );
}

#[test]
fn malformed_heads_are_invalid() {
    let s = Scratch::new("badheads");
    let log = filled(&s, 2);
    let h = hash_of(&lines(&log)[1]);
    let head = s.dir().join("audit.head");
    for text in [
        format!("{{\"seq\": 2,\"hash\":\"{h}\"}}\n"),
        format!("{{\"seq\":0,\"hash\":\"{h}\"}}\n"),
        format!("{{\"seq\":2,\"hash\":\"{h}\",\"x\":1}}\n"),
        format!("{{\"seq\":2,\"hash\":\"{h}\"}}"),
        format!("{{\"seq\":2,\"hash\":\"{}\"}}\n", h.to_uppercase()),
    ] {
        std::fs::write(&head, text).unwrap();
        assert_eq!(
            verify(&s.dir()).unwrap_err().kind,
            VerifyErrorKind::HeadInvalid
        );
        assert!(AuditWriter::open(&s.dir(), Box::new(TestClock::at(JAN))).is_err());
    }
}

#[test]
fn a_huge_sparse_head_is_refused_without_reading_it() {
    let s = Scratch::new("hugehead");
    filled(&s, 2);
    let head = s.dir().join("audit.head");
    let f = std::fs::File::create(&head).unwrap();
    f.set_len(200 * 1024 * 1024).unwrap();
    drop(f);
    std::fs::set_permissions(&head, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        verify(&s.dir()).unwrap_err().kind,
        VerifyErrorKind::HeadInvalid
    );
}

#[test]
fn a_head_that_is_a_symlink_or_fifo_is_refused_without_following_it() {
    let s = Scratch::new("headlink");
    filled(&s, 2);
    let head = s.dir().join("audit.head");
    // A link to a copy of the valid head: only O_NOFOLLOW refuses it.
    let copy = s.0.join("copy.head");
    std::fs::copy(&head, &copy).unwrap();
    std::fs::remove_file(&head).unwrap();
    symlink(&copy, &head).unwrap();
    assert_eq!(
        verify(&s.dir()).unwrap_err().kind,
        VerifyErrorKind::Unreadable
    );
    std::fs::remove_file(&head).unwrap();
    symlink("/dev/zero", &head).unwrap();
    assert_eq!(
        verify(&s.dir()).unwrap_err().kind,
        VerifyErrorKind::Unreadable
    );
    assert!(AuditWriter::open(&s.dir(), Box::new(TestClock::at(JAN))).is_err());
    std::fs::remove_file(&head).unwrap();
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &head,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    assert_eq!(
        verify(&s.dir()).unwrap_err().kind,
        VerifyErrorKind::Unreadable
    );
}

#[test]
fn a_planted_symlink_at_the_head_temp_name_is_not_followed() {
    let s = Scratch::new("tmplink");
    filled(&s, 1);
    let victim = s.0.join("victim.txt");
    std::fs::write(&victim, "keep me").unwrap();
    symlink(&victim, s.dir().join("audit.head.tmp")).unwrap();
    let mut w = open(&s, &TestClock::at(JAN));
    w.append(note("a.next"), AuditLevel::Full).unwrap();
    drop(w);
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep me");
    let head = s.dir().join("audit.head");
    assert!(
        !std::fs::symlink_metadata(&head)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        std::fs::metadata(&head).unwrap().permissions().mode() & 0o777,
        0o600
    );
    verify(&s.dir()).unwrap();
}

#[test]
fn a_symlinked_or_loosely_permissioned_log_file_is_refused() {
    let s = Scratch::new("loglink");
    let log = filled(&s, 2);
    let real = s.dir().join("real.jsonl");
    std::fs::rename(&log, &real).unwrap();
    symlink(&real, &log).unwrap();
    assert_eq!(
        verify(&s.dir()).unwrap_err().kind,
        VerifyErrorKind::Unreadable
    );
    assert!(AuditWriter::open(&s.dir(), Box::new(TestClock::at(JAN))).is_err());
    std::fs::remove_file(&log).unwrap();
    std::fs::rename(&real, &log).unwrap();
    std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(open_err(&s), AuditError::Permissions { .. }));
}

#[test]
fn an_entry_whose_args_were_edited_and_rehashed_still_fails_the_args_check() {
    let s = Scratch::new("argsedit");
    let log = filled(&s, 1);
    let line = lines(&log).remove(0);
    let v: serde_json::Value = serde_json::from_str(&line).unwrap();
    let suffix = format!(",\"hash\":\"{}\"}}", v["hash"].as_str().unwrap());
    let body = format!("{}}}", line.strip_suffix(&suffix).unwrap())
        .replace("\"cmd\":\"ls\"", "\"cmd\":\"rm\"");
    let new_hash = sha256_hex(format!("{}{body}", v["prev_hash"].as_str().unwrap()).as_bytes());
    let forged = format!(
        "{},\"hash\":\"{new_hash}\"}}",
        body.strip_suffix('}').unwrap()
    );
    write_lines(&log, &[forged]);
    assert_eq!(
        verify(&s.dir()).unwrap_err().kind,
        VerifyErrorKind::ArgsHashMismatch
    );
}

#[test]
fn splicing_in_an_entry_from_another_chain_is_a_broken_link() {
    let a = Scratch::new("spliceA");
    let b = Scratch::new("spliceB");
    let la = filled(&a, 3);
    let lb = {
        let clock = TestClock::at(JAN);
        let mut w = open(&b, &clock);
        for i in 0..3 {
            w.append(
                note("other.event").args(json!({ "n": i })),
                AuditLevel::Full,
            )
            .unwrap();
        }
        b.dir().join("audit-202601.jsonl")
    };
    let mut l = lines(&la);
    l[1] = lines(&lb)[1].clone();
    write_lines(&la, &l);
    assert_eq!(
        verify(&a.dir()).unwrap_err().kind,
        VerifyErrorKind::ChainBroken
    );
}

#[test]
fn middle_deletion_and_reordering_are_sequence_errors() {
    let s = Scratch::new("seqkinds");
    let log = filled(&s, 5);
    let original = lines(&log);
    let mut l = original.clone();
    l.remove(2);
    write_lines(&log, &l);
    assert_eq!(verify(&s.dir()).unwrap_err().kind, VerifyErrorKind::SeqGap);
    let mut l = original;
    l.swap(1, 2);
    write_lines(&log, &l);
    assert_eq!(verify(&s.dir()).unwrap_err().kind, VerifyErrorKind::SeqGap);
}

#[test]
fn a_torn_tail_that_the_head_says_was_complete_is_kept_as_evidence() {
    let s = Scratch::new("tornevidence");
    let log = filled(&s, 3);
    let before = std::fs::read(&log).unwrap();
    std::fs::write(&log, &before[..before.len() - 1]).unwrap();
    let damaged = std::fs::read(&log).unwrap();
    assert!(matches!(open_err(&s), AuditError::TailMissing));
    assert_eq!(
        std::fs::read(&log).unwrap(),
        damaged,
        "open must not cut a tail the head vouches for"
    );
}

#[test]
fn verify_tolerates_an_append_in_flight() {
    let s = Scratch::new("inflight");
    let log = filled(&s, 2);
    let mut f = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
    std::io::Write::write_all(&mut f, b"{\"seq\":3,\"ts\":\"2026-01-1").unwrap();
    drop(f);
    let report = verify(&s.dir()).unwrap();
    assert!(report.torn_tail);
    assert_eq!(
        (report.entries, report.head),
        (2, sally_core::audit::HeadStatus::Current)
    );
}

#[test]
fn new_entry_debug_does_not_print_args() {
    let secret = token();
    let shown = format!(
        "{:?}",
        note("tool.executed").args(json!({ "token": secret }))
    );
    assert!(!shown.contains(&secret));
    assert!(shown.contains("tool.executed"));
}

#[test]
fn overlapping_secrets_are_both_removed_whole() {
    let a = "AAAAAAAAAAAA1234567890";
    let b = "1234567890ZZZZZZZZZZ";
    let r = Redactor::new([("A", a), ("B", b)]);
    let out = r.redact_str("x AAAAAAAAAAAA1234567890ZZZZZZZZZZ y");
    assert!(!out.contains("AAAAAA") && !out.contains("ZZZZZ"), "{out}");
    assert!(
        out.starts_with("x [REDACTED:") && out.ends_with(" y"),
        "{out}"
    );
}

#[test]
fn partially_encoded_and_json_escaped_secrets_are_redacted() {
    let pw = "pa ss+word/with=special&chars";
    let r = Redactor::new([("PASSWORD", pw)]);
    for form in [
        "pa%20ss%2Bword/with%3Dspecial%26chars",
        "pa%20ss%2Bword%2Fwith%3Dspecial%26chars",
        "pa+ss%2Bword%2Fwith%3Dspecial%26chars",
        "pa%20ss%2bword%2fwith%3dspecial%26chars",
    ] {
        assert!(r.redact_str(form).contains("[REDACTED:PASSWORD]"), "{form}");
    }
    let tricky = "pa\"ss\\word-with-quotes";
    let r = Redactor::new([("PW", tricky)]);
    let embedded = serde_json::to_string(&json!({ "pw": tricky })).unwrap();
    assert!(
        r.redact_str(&embedded).contains("[REDACTED:PW]"),
        "{embedded}"
    );
    let args = r.redact_value(&json!({ "body": embedded }));
    assert!(!args.to_string().contains("word-with-quotes"));
}

/// Task 9a-3 (architect D3): the token proxy redacts exactly the audit redactor's forms.
#[test]
fn secret_forms_are_the_forms_the_redactor_replaces_each_once() {
    let pw = "pa ss+word/with=special&chars";
    let forms: Vec<String> = sally_core::audit::secret_forms(pw)
        .iter()
        .map(|f| f.expose().clone())
        .collect();
    let r = Redactor::new([("PW", pw)]);
    for f in &forms {
        assert_eq!(r.redact_str(f), "[REDACTED:PW]", "{f}");
    }
    let unique: std::collections::BTreeSet<&String> = forms.iter().collect();
    assert_eq!(unique.len(), forms.len());
    assert_eq!(forms.first().map(String::as_str), Some(pw));
    for expected in [
        "pa%20ss%2Bword%2Fwith%3Dspecial%26chars",
        "pa+ss%2bword/with%3dspecial%26chars",
        "pa ss+word/with=special&chars",
    ] {
        assert!(forms.iter().any(|f| f == expected), "{expected}");
    }
    // Base64 forms of both alphabets: "~~~" is "fn5+" in the standard one, "fn5-" URL-safe.
    let tildes = sally_core::audit::secret_forms("~~~~~~~~~~~~~~~~~~");
    assert!(
        tildes
            .iter()
            .any(|f| f.expose().starts_with("fn5+fn5+fn5+"))
    );
    assert!(
        tildes
            .iter()
            .any(|f| f.expose().starts_with("fn5-fn5-fn5-"))
    );
    assert!(sally_core::audit::secret_forms("").is_empty());
    // A short value keeps its raw and percent forms but no base64 form under 12 characters.
    let short = sally_core::audit::secret_forms("abcdefgh");
    assert!(short.iter().all(|f| f.expose().len() >= 8));
    assert!(short.iter().any(|f| f.expose() == "abcdefgh"));
}

#[test]
fn keys_that_redact_to_the_same_text_keep_both_values() {
    let r = Redactor::new([("S", "supersecretvalue1234")]);
    let out = r.redact_value(&json!({ "supersecretvalue1234": 1, "[REDACTED:S]": 2 }));
    assert_eq!(out.as_object().unwrap().len(), 2, "{out}");
}

#[test]
fn object_keys_are_written_in_sorted_order() {
    let s = Scratch::new("sortedkeys");
    let clock = TestClock::at(JAN);
    let mut w = open(&s, &clock);
    w.append(
        note("a.b").args(json!({ "zeta": 1, "alpha": { "y": 1, "b": 2 } })),
        AuditLevel::Full,
    )
    .unwrap();
    drop(w);
    let line = &lines(&s.dir().join("audit-202601.jsonl"))[0];
    assert!(
        line.contains("\"args\":{\"alpha\":{\"b\":2,\"y\":1},\"zeta\":1}"),
        "{line}"
    );
}

// ---- writer: accessors, tip and open-time checks ------------------------------------------

#[test]
fn system_clock_reads_the_real_time() {
    let drift = Timestamp::now().as_second() - sally_core::audit::SystemClock.now().as_second();
    assert!(drift.abs() <= 5, "{drift}");
}

#[test]
fn new_entry_exposes_its_event_and_unredacted_args() {
    let e = note("tool.executed").args(json!({ "cmd": "ls" }));
    assert_eq!(e.event(), "tool.executed");
    assert_eq!(e.arguments(), &json!({ "cmd": "ls" }));
}

/// `tip` names the newest entry, and a clean reopen appends nothing (no recovery record).
#[test]
fn tip_is_the_newest_entry_and_a_clean_reopen_writes_nothing() {
    let s = Scratch::new("tip");
    let clock = TestClock::at(JAN);
    let w = open(&s, &clock);
    assert_eq!(w.tip(), (0, GENESIS_HASH));
    let shown = format!("{w:?}");
    assert!(
        shown.starts_with("AuditWriter {") && shown.contains("tip_seq: 0"),
        "{shown}"
    );
    drop(w);
    let log = filled(&s, 2);
    let last: serde_json::Value = serde_json::from_str(&lines(&log)[1]).unwrap();
    let w = open(&s, &clock);
    assert_eq!(w.tip(), (2, last["hash"].as_str().unwrap()));
    drop(w);
    assert_eq!(lines(&log).len(), 2);
}

/// The lock file and the log files are never opened through a symlink.
#[test]
fn open_refuses_a_symlinked_lock_or_log_file() {
    for name in ["audit.lock", "audit-202601.jsonl"] {
        let s = Scratch::new("symlinked");
        let log = filled(&s, 1);
        let target = s.dir().join("elsewhere");
        let p = s.dir().join(name);
        std::fs::rename(if name == "audit.lock" { &p } else { &log }, &target).unwrap();
        symlink(&target, &p).unwrap();
        let clock = TestClock::at(JAN);
        assert!(
            AuditWriter::open(&s.dir(), Box::new(clock)).is_err(),
            "{name}"
        );
    }
}

fn corrupt_msg(s: &Scratch) -> &'static str {
    match AuditWriter::open(&s.dir(), Box::new(TestClock::at(JAN))) {
        Err(AuditError::Corrupt { msg, .. }) => msg,
        other => panic!("{other:?}"),
    }
}

/// The tail scan reads at most two line bounds plus two bytes (16386) from the end: a torn tail
/// that fits with the newline before it is dropped; a longer one, or a complete last line over
/// the bound, is refused as corrupt.
#[test]
fn the_tail_scan_is_bounded_at_two_lines() {
    for (torn, ok) in [(16_385, true), (20_000, false)] {
        let s = Scratch::new("tornlen");
        let log = filled(&s, 3);
        let mut f = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
        std::io::Write::write_all(&mut f, &vec![b'x'; torn]).unwrap();
        drop(f);
        if ok {
            drop(open(&s, &TestClock::at(JAN)));
            verify(&s.dir()).unwrap();
        } else {
            assert_eq!(corrupt_msg(&s), "has a torn line longer than the limit");
        }
    }
    let s = Scratch::new("longline");
    let log = filled(&s, 1);
    let mut f = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
    std::io::Write::write_all(&mut f, &[vec![b'x'; 20_000], vec![b'\n']].concat()).unwrap();
    drop(f);
    assert_eq!(corrupt_msg(&s), "has a line longer than the limit");
    // A log far larger than the scan window reopens normally.
    let s = Scratch::new("biglog");
    filled(&s, 200);
    let mut w = open(&s, &TestClock::at(JAN));
    assert_eq!(w.tip().0, 200);
    w.append(note("a.b"), AuditLevel::Full).unwrap();
}

/// A first write torn before any newline leaves no entry: the file is all torn bytes.
#[test]
fn a_file_holding_only_a_torn_first_entry_opens_empty() {
    let s = Scratch::new("tornfirst");
    drop(open(&s, &TestClock::at(JAN)));
    let log = s.dir().join("audit-202601.jsonl");
    std::fs::write(&log, b"{\"seq\":1,\"ts\":").unwrap();
    std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o600)).unwrap();
    let w = open(&s, &TestClock::at(JAN));
    // No entry survives the tear: whatever is written next starts the chain at genesis.
    let mut w = w;
    w.append(note("a.b"), AuditLevel::Full).unwrap();
    drop(w);
    let first: serde_json::Value = serde_json::from_str(&lines(&log)[0]).unwrap();
    assert_eq!(
        (first["seq"].as_u64(), first["prev_hash"].as_str()),
        (Some(1), Some(GENESIS_HASH))
    );
    verify(&s.dir()).unwrap();
}

/// Only the newest file may end torn; an older one read because the newest is empty may not.
#[test]
fn an_older_file_ending_torn_is_corrupt_on_open() {
    let s = Scratch::new("oldtorn");
    let clock = TestClock::at(JAN);
    let mut w = open(&s, &clock);
    w.append(note("a.one"), AuditLevel::Full).unwrap();
    w.append(note("a.two"), AuditLevel::Full).unwrap();
    drop(w);
    let jan = s.dir().join("audit-202601.jsonl");
    let data = std::fs::read(&jan).unwrap();
    std::fs::write(&jan, &data[..data.len() - 1]).unwrap();
    let feb = s.dir().join("audit-202602.jsonl");
    std::fs::write(&feb, b"").unwrap();
    std::fs::set_permissions(&feb, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(corrupt_msg(&s), "does not end with a complete entry");
}

/// A missing head is recreated only for a log that is exactly one genesis entry: seq 1 that
/// does not start from the genesis hash is a cut log.
#[test]
fn a_missing_head_is_recreated_only_for_a_genesis_entry() {
    let s = Scratch::new("nohead");
    let log = filled(&s, 1);
    let mut e = parse_line(lines(&log)[0].as_bytes()).unwrap();
    e.prev_hash = "1".repeat(64);
    e.hash = e.compute_hash();
    write_lines(&log, &[e.to_line()]);
    std::fs::remove_file(s.dir().join("audit.head")).unwrap();
    let r = AuditWriter::open(&s.dir(), Box::new(TestClock::at(JAN)));
    assert!(matches!(r, Err(AuditError::HeadMissing)), "{r:?}");
}
