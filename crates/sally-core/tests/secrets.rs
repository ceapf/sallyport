//! `sally-core::secrets`: the 0600 store and `Secret<T>` (SI-3; RT-SEC-01/02/07 building blocks).
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use proptest::prelude::*;
use sally_core::manifest::SecretCatalog;
use sally_core::secrets::{
    MAX_SECRETS, MAX_STORE_BYTES, MAX_VALUE_BYTES, SHORT_SECRET_BYTES, Secret, SecretStore,
    SecretsError, is_secret_name,
};
use zeroize::Zeroize;

/// A scratch dir under the target dir, restored to 0700 and removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("sally-secrets-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(d)
    }

    fn store_path(&self) -> PathBuf {
        self.0.join("secrets.toml")
    }

    fn write(&self, text: &str, mode: u32) -> PathBuf {
        let p = self.store_path();
        std::fs::write(&p, text).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        p
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn mode_of(p: &Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o7777
}

fn long(body: &str) -> String {
    // Over SHORT_SECRET_BYTES so no warning noise in tests that are about something else.
    common::fake_token(
        &["gh", "p_"],
        &format!("{body}{}", "x".repeat(SHORT_SECRET_BYTES)),
    )
}

// ---- Secret<T> ----------------------------------------------------------------------------

#[test]
fn secret_debug_is_redacted() {
    let value = long("debugcheck");
    let s = Secret::new(value.clone());
    assert!(!format!("{s:?}").contains(&value));
    assert!(!format!("{s:#?}").contains(&value));
    assert!(format!("{s:?}").contains("redacted"));
    // Embedded in a derived Debug of something larger.
    #[derive(Debug)]
    #[allow(dead_code)]
    struct Holder {
        s: Secret<String>,
    }
    let h = Holder { s };
    assert!(!format!("{h:?}").contains(&value));
}

#[test]
fn secret_expose_returns_the_value() {
    let s = Secret::new("abc".to_owned());
    assert_eq!(s.expose(), "abc");
}

struct Flag(Arc<AtomicBool>);

impl Zeroize for Flag {
    fn zeroize(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[test]
fn secret_is_zeroized_on_drop() {
    let flag = Arc::new(AtomicBool::new(false));
    let s = Secret::new(Flag(flag.clone()));
    assert!(!flag.load(Ordering::SeqCst));
    drop(s);
    assert!(flag.load(Ordering::SeqCst));
}

// ---- names and values ---------------------------------------------------------------------

#[test]
fn name_grammar() {
    for ok in ["A", "GITHUB_TOKEN", "A1_B2", &"A".repeat(64)] {
        assert!(is_secret_name(ok), "{ok}");
    }
    for bad in [
        "",
        "a",
        "1A",
        "_A",
        "A-B",
        "A B",
        "Ab",
        &"A".repeat(65),
        "É",
    ] {
        assert!(!is_secret_name(bad), "{bad:?}");
    }
}

#[test]
fn set_rejects_bad_names_without_echoing_them() {
    let mut store = SecretStore::empty(PathBuf::from("/nonexistent/secrets.toml"));
    // A pasted credential in the name position must not come back in the error text.
    let pasted = long("pasted");
    let err = store.set(&pasted, long("v")).unwrap_err();
    assert!(matches!(err, SecretsError::InvalidName), "{err:?}");
    assert!(!err.to_string().contains(&pasted));
    assert!(!format!("{err:?}").contains(&pasted));
}

#[test]
fn set_rejects_bad_values_without_echoing_them() {
    let mut store = SecretStore::empty(PathBuf::from("/nonexistent/secrets.toml"));
    let cases = [
        String::new(),
        "line1\nline2".to_owned(),
        "has\rcr".to_owned(),
        "nul\0byte".to_owned(),
        "del\x7fchar".to_owned(),
        "tab\tchar".to_owned(),
        " leading".to_owned(),
        "trailing ".to_owned(),
        "non-ascii-é".to_owned(),
        "x".repeat(MAX_VALUE_BYTES + 1),
    ];
    for v in cases {
        let err = store.set("TOKEN", v.clone()).unwrap_err();
        assert!(
            matches!(err, SecretsError::InvalidValue(_)),
            "{v:?}: {err:?}"
        );
        if v.len() > 3 {
            assert!(!err.to_string().contains(&v), "{v:?}");
            assert!(!format!("{err:?}").contains(&v), "{v:?}");
        }
    }
    assert_eq!(store.names().count(), 0);
}

#[test]
fn value_length_limit_is_inclusive() {
    let mut store = SecretStore::empty(PathBuf::from("/nonexistent/secrets.toml"));
    store.set("TOKEN", "x".repeat(MAX_VALUE_BYTES)).unwrap();
}

/// The documented bounds, restated: the tests above use the constants, so a changed constant
/// would pass them.
#[test]
fn bounds_are_the_documented_values() {
    assert_eq!(
        (
            MAX_STORE_BYTES,
            MAX_SECRETS,
            MAX_VALUE_BYTES,
            SHORT_SECRET_BYTES
        ),
        (1024 * 1024, 256, 8 * 1024, 16)
    );
}

/// The file bounds are inclusive on the read path too: exactly 1 MiB and exactly 256 secrets
/// open; one more of either is refused.
#[test]
fn a_file_exactly_at_the_bounds_opens() {
    let s = Scratch::new("bounds");
    let p = s.store_path();
    let comments = "#".repeat(MAX_STORE_BYTES);
    s.write(&comments, 0o600);
    assert_eq!(SecretStore::open(&p).unwrap().names().count(), 0);
    SecretStore::from_bytes(p.clone(), comments.as_bytes()).unwrap();
    let many = |n: usize| -> String {
        (0..n)
            .map(|i| format!("S{i} = \"{}\"\n", long("v")))
            .collect()
    };
    let full = SecretStore::from_bytes(p.clone(), many(MAX_SECRETS).as_bytes()).unwrap();
    assert_eq!(full.names().count(), MAX_SECRETS);
    assert!(matches!(
        SecretStore::from_bytes(p, many(MAX_SECRETS + 1).as_bytes()),
        Err(SecretsError::TooMany)
    ));
}

/// The sweep removes only stale temporary files of this store: `.<name>.*.tmp`. A backup that
/// shares the prefix, or another `.tmp` file, is the user's and stays; so does a symlink with a
/// temporary's name (only regular files are swept).
#[test]
fn save_sweeps_only_this_stores_stale_temporaries() {
    let s = Scratch::new("sweep");
    let stale = s.0.join(".secrets.toml.1.0.tmp");
    let keep = [s.0.join(".secrets.toml.bak"), s.0.join("other.tmp")];
    for p in keep.iter().chain([&stale]) {
        std::fs::write(p, "x").unwrap();
    }
    let link = s.0.join(".secrets.toml.1.1.tmp");
    std::os::unix::fs::symlink(&keep[0], &link).unwrap();
    let mut store = SecretStore::open(&s.store_path()).unwrap();
    store.set("TOKEN", long("v")).unwrap();
    store.save().unwrap();
    assert!(!stale.exists(), "stale temporary");
    for p in &keep {
        assert!(p.exists(), "{}", p.display());
    }
    assert!(link.symlink_metadata().is_ok(), "symlink kept");
}

#[test]
fn interior_spaces_are_allowed() {
    let mut store = SecretStore::empty(PathBuf::from("/nonexistent/secrets.toml"));
    store
        .set("PASSWORD", "correct horse battery staple".to_owned())
        .unwrap();
}

#[test]
fn short_values_are_flagged_but_stored() {
    let mut store = SecretStore::empty(PathBuf::from("/nonexistent/secrets.toml"));
    let short = store.set("A", "x".repeat(SHORT_SECRET_BYTES - 1)).unwrap();
    assert!(short.short);
    let exact = store.set("B", "x".repeat(SHORT_SECRET_BYTES)).unwrap();
    assert!(!exact.short);
    assert!(store.contains("A"));
}

#[test]
fn secret_count_is_bounded() {
    let mut store = SecretStore::empty(PathBuf::from("/nonexistent/secrets.toml"));
    for i in 0..MAX_SECRETS {
        store.set(&format!("S{i}"), long("v")).unwrap();
    }
    assert!(matches!(
        store.set("ONE_TOO_MANY", long("v")),
        Err(SecretsError::TooMany)
    ));
    // Replacing an existing one is still fine at the limit.
    store.set("S0", long("w")).unwrap();
}

// ---- store: api ---------------------------------------------------------------------------

#[test]
fn missing_file_opens_as_empty_store() {
    let s = Scratch::new("missing");
    let store = SecretStore::open(&s.store_path()).unwrap();
    assert_eq!(store.names().count(), 0);
    assert!(!store.contains("ANY"));
}

#[test]
fn set_save_reopen_round_trips_and_names_are_sorted() {
    let s = Scratch::new("roundtrip");
    let mut store = SecretStore::open(&s.store_path()).unwrap();
    let (a, b) = (long("a"), long("b"));
    store.set("ZED", b.clone()).unwrap();
    store.set("ALPHA", a.clone()).unwrap();
    store.save().unwrap();

    let again = SecretStore::open(&s.store_path()).unwrap();
    assert_eq!(again.names().collect::<Vec<_>>(), ["ALPHA", "ZED"]);
    assert_eq!(again.get("ALPHA").unwrap().expose(), &a);
    assert_eq!(again.get("ZED").unwrap().expose(), &b);
    assert!(again.get("NOPE").is_none());
}

#[test]
fn set_replaces_and_remove_deletes() {
    let s = Scratch::new("replace");
    let mut store = SecretStore::open(&s.store_path()).unwrap();
    store.set("TOKEN", long("one")).unwrap();
    let second = long("two");
    store.set("TOKEN", second.clone()).unwrap();
    assert_eq!(store.get("TOKEN").unwrap().expose(), &second);
    assert!(store.remove("TOKEN"));
    assert!(!store.remove("TOKEN"));
    store.save().unwrap();
    assert_eq!(
        SecretStore::open(&s.store_path()).unwrap().names().count(),
        0
    );
}

#[test]
fn store_debug_shows_names_only() {
    let mut store = SecretStore::empty(PathBuf::from("/nonexistent/secrets.toml"));
    let v = long("storedebug");
    store.set("GITHUB_TOKEN", v.clone()).unwrap();
    let d = format!("{store:?}");
    assert!(d.contains("GITHUB_TOKEN"));
    assert!(!d.contains(&v));
}

#[test]
fn store_is_a_name_only_catalog_for_the_manifest_validator() {
    let mut store = SecretStore::empty(PathBuf::from("/nonexistent/secrets.toml"));
    store.set("GITHUB_TOKEN", long("v")).unwrap();
    let catalog: &dyn SecretCatalog = &store;
    assert!(catalog.contains("GITHUB_TOKEN"));
    assert!(!catalog.contains("OTHER"));
}

// ---- store: files and permissions ---------------------------------------------------------

#[test]
fn save_creates_missing_dir_0700_and_file_0600() {
    let s = Scratch::new("create");
    let path = s.0.join("cfg/sallyport/secrets.toml");
    let mut store = SecretStore::open(&path).unwrap();
    store.set("TOKEN", long("v")).unwrap();
    store.save().unwrap();
    assert_eq!(mode_of(&path), 0o600);
    assert_eq!(mode_of(path.parent().unwrap()), 0o700);
}

#[test]
fn save_leaves_no_temporary_files() {
    let s = Scratch::new("notmp");
    let mut store = SecretStore::open(&s.store_path()).unwrap();
    store.set("TOKEN", long("v")).unwrap();
    store.save().unwrap();
    store.save().unwrap();
    let names: Vec<_> = std::fs::read_dir(&s.0)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names, ["secrets.toml"]);
}

#[test]
fn save_keeps_0600_when_replacing_a_file() {
    let s = Scratch::new("resave");
    let mut store = SecretStore::open(&s.store_path()).unwrap();
    store.set("TOKEN", long("v")).unwrap();
    store.save().unwrap();
    store.set("OTHER", long("w")).unwrap();
    store.save().unwrap();
    assert_eq!(mode_of(&s.store_path()), 0o600);
}

#[test]
fn open_refuses_any_group_or_other_access() {
    for mode in [0o644, 0o640, 0o604, 0o602, 0o660, 0o666, 0o601, 0o610] {
        let s = Scratch::new(&format!("mode{mode:o}"));
        s.write("TOKEN = \"abcdefghijklmnopqrstuvwx\"\n", mode);
        let err = SecretStore::open(&s.store_path()).unwrap_err();
        assert!(
            matches!(err, SecretsError::Permissions { .. }),
            "{mode:o}: {err:?}"
        );
        assert!(err.to_string().contains("0600"), "{err}");
        assert!(!err.to_string().contains("abcdefgh"));
    }
}

#[test]
fn open_accepts_0600_and_stricter() {
    for mode in [0o600, 0o400] {
        let s = Scratch::new(&format!("ok{mode:o}"));
        s.write("TOKEN = \"abcdefghijklmnopqrstuvwx\"\n", mode);
        let store = SecretStore::open(&s.store_path()).unwrap();
        assert!(store.contains("TOKEN"));
    }
}

#[test]
fn open_refuses_a_symlink_even_to_a_good_file() {
    let s = Scratch::new("symlink");
    let target = s.0.join("real.toml");
    std::fs::write(&target, "TOKEN = \"abcdefghijklmnopqrstuvwx\"\n").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&target, s.store_path()).unwrap();
    let err = SecretStore::open(&s.store_path()).unwrap_err();
    assert!(matches!(err, SecretsError::Permissions { .. }), "{err:?}");
}

#[test]
fn open_refuses_a_directory() {
    let s = Scratch::new("notfile");
    std::fs::create_dir(s.store_path()).unwrap();
    let err = SecretStore::open(&s.store_path()).unwrap_err();
    assert!(matches!(err, SecretsError::Permissions { .. }), "{err:?}");
}

#[test]
fn open_and_save_refuse_a_group_or_world_writable_parent() {
    let s = Scratch::new("badparent");
    let dir = s.0.join("loose");
    std::fs::create_dir(&dir).unwrap();
    for mode in [0o770, 0o707, 0o777, 0o720] {
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
        let err = SecretStore::open(&dir.join("secrets.toml")).unwrap_err();
        assert!(
            matches!(err, SecretsError::Permissions { .. }),
            "{mode:o}: {err:?}"
        );

        let store = SecretStore::empty(dir.join("secrets.toml"));
        let err = store.save().unwrap_err();
        assert!(
            matches!(err, SecretsError::Permissions { .. }),
            "{mode:o}: {err:?}"
        );
    }
    assert!(!dir.join("secrets.toml").exists());
}

#[test]
fn open_refuses_an_oversized_file_before_parsing() {
    let s = Scratch::new("big");
    let p = s.write("", 0o600);
    std::fs::write(&p, vec![b'#'; MAX_STORE_BYTES + 1]).unwrap();
    assert!(matches!(SecretStore::open(&p), Err(SecretsError::TooLarge)));
}

// ---- store: parsing -----------------------------------------------------------------------

#[test]
fn parse_errors_never_contain_the_secret_text() {
    let secret = long("parseleak");
    let cases = [
        // Not a string.
        format!("TOKEN = 12345678901234567890\nOTHER = \"{secret}\"\n"),
        // Syntax error on the line holding a value.
        format!("TOKEN = \"{secret}\" trailing\n"),
        // Unterminated string.
        format!("TOKEN = \"{secret}\n"),
        // Nested table.
        format!("[TOKEN]\nINNER = \"{secret}\"\n"),
        // Duplicate key.
        format!("TOKEN = \"{secret}\"\nTOKEN = \"{secret}\"\n"),
        // Bad name with the value next to it.
        format!("lower = \"{secret}\"\n"),
        // Bad value.
        format!("TOKEN = \"{secret}\\n\"\n"),
    ];
    for (i, text) in cases.iter().enumerate() {
        let s = Scratch::new(&format!("leak{i}"));
        s.write(text, 0o600);
        let err = SecretStore::open(&s.store_path()).unwrap_err();
        let shown = format!("{err} | {err:?}");
        assert!(!shown.contains(&secret), "case {i}: {shown}");
        assert!(!shown.contains("parseleak"), "case {i}: {shown}");
    }
}

#[test]
fn parse_error_reports_a_line_number() {
    let s = Scratch::new("line");
    s.write("A = \"x\"\nB = \"y\"\nC = =\n", 0o600);
    let err = SecretStore::open(&s.store_path()).unwrap_err();
    assert!(
        matches!(err, SecretsError::Parse { line: Some(3) }),
        "{err:?}"
    );
    assert!(err.to_string().contains("line 3"), "{err}");
}

#[test]
fn open_rejects_non_string_values_and_tables() {
    for text in [
        "TOKEN = 1\n",
        "TOKEN = [\"a\"]\n",
        "[T]\nA = \"b\"\n",
        "TOKEN = true\n",
    ] {
        let s = Scratch::new("shape");
        s.write(text, 0o600);
        assert!(SecretStore::open(&s.store_path()).is_err(), "{text}");
    }
}

#[test]
fn open_applies_the_same_name_and_value_rules_as_set() {
    let cases = [
        "lower = \"abcdefghijklmnopqrstuvwx\"\n",
        "TOKEN = \"\"\n",
        "TOKEN = \"a\\nb\"\n",
        "TOKEN = \" padded \"\n",
    ];
    for text in cases {
        let s = Scratch::new("rules");
        s.write(text, 0o600);
        assert!(SecretStore::open(&s.store_path()).is_err(), "{text}");
    }
}

#[test]
fn open_accepts_a_quoted_key_spelling() {
    // A quoted key spelled differently is still the same key; a valid quoted key is fine.
    let s = Scratch::new("quotedkey");
    s.write("\"TOKEN\" = \"abcdefghijklmnopqrstuvwx\"\n", 0o600);
    assert!(
        SecretStore::open(&s.store_path())
            .unwrap()
            .contains("TOKEN")
    );
}

#[test]
fn open_accepts_comments_and_literal_strings() {
    let s = Scratch::new("comments");
    s.write("# mine\nTOKEN = 'abcdefghijklmnopqrstuvwx' # why\n", 0o600);
    let store = SecretStore::open(&s.store_path()).unwrap();
    assert_eq!(
        store.get("TOKEN").unwrap().expose(),
        "abcdefghijklmnopqrstuvwx"
    );
}

#[test]
fn saved_file_is_one_sorted_name_equals_string_per_line() {
    let s = Scratch::new("format");
    let mut store = SecretStore::open(&s.store_path()).unwrap();
    store
        .set("B", "value with \"quotes\" and \\ and # hash".to_owned())
        .unwrap();
    store.set("A", "plain".to_owned()).unwrap();
    store.save().unwrap();
    let text = std::fs::read_to_string(s.store_path()).unwrap();
    assert_eq!(
        text,
        "A = \"plain\"\nB = \"value with \\\"quotes\\\" and \\\\ and # hash\"\n"
    );
}

proptest! {
    #[test]
    fn any_valid_value_round_trips(value in "[ -~]{1,200}") {
        prop_assume!(value == value.trim());
        let s = Scratch::new(&format!("prop{}", value.len()));
        let mut store = SecretStore::open(&s.store_path()).unwrap();
        store.set("TOKEN", value.clone()).unwrap();
        store.save().unwrap();
        let again = SecretStore::open(&s.store_path()).unwrap();
        prop_assert_eq!(again.get("TOKEN").unwrap().expose(), &value);
    }

    #[test]
    fn arbitrary_file_text_never_leaks_into_errors(text in "\\PC{0,200}") {
        let s = Scratch::new("fuzzleak");
        s.write(&text, 0o600);
        if let Err(e) = SecretStore::open(&s.store_path()) {
            let shown = format!("{e} | {e:?}");
            // Every run of 8+ non-space chars from the input must be absent from the error.
            let vocab = vocabulary();
            for word in text.split(|c: char| !c.is_ascii_alphanumeric()).filter(|w| w.len() >= 8 && !vocab.iter().any(|m| m.contains(*w))) {
                prop_assert!(!shown.contains(word), "{shown}");
            }
        }
    }
}

/// The store's fixed error messages: errors carry only static text and a line number,
/// so a mutated input that happens to spell the message must not count as a leak.
fn vocabulary() -> Vec<String> {
    let path = || PathBuf::from("/x/secrets.toml");
    let mut shown: Vec<String> = Vec::new();
    let many: String = (0..=MAX_SECRETS)
        .map(|i| format!("S{i} = \"x\"\n"))
        .collect();
    for bytes in [&b"="[..], &b"\xff"[..], many.as_bytes()] {
        shown.push(
            SecretStore::from_bytes(path(), bytes)
                .unwrap_err()
                .to_string(),
        );
    }
    shown.push(
        SecretStore::from_bytes(path(), &vec![b'#'; MAX_STORE_BYTES + 1])
            .unwrap_err()
            .to_string(),
    );
    let mut store = SecretStore::empty(path());
    let long = "x".repeat(MAX_VALUE_BYTES + 1);
    for (name, value) in [
        ("a", "x"),
        ("A", ""),
        ("A", "\n"),
        ("A", " x"),
        ("A", long.as_str()),
    ] {
        shown.push(store.set(name, value.to_owned()).unwrap_err().to_string());
    }
    shown
}

#[test]
fn the_error_vocabulary_oracle_exempts_message_text_but_not_values() {
    let vocab = vocabulary();
    assert!(vocab.iter().any(|m| m.contains("unexpect")));
    assert!(!vocab.iter().any(|m| m.contains("canaryvalue")));
}

// ---- review follow-ups --------------------------------------------------------------------

fn mkfifo(p: &Path) {
    rustix::fs::mknodat(
        rustix::fs::CWD,
        p,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
}

/// `f`'s result, or a failure (not a hang) if it takes more than 5 s.
fn within_5s<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(std::time::Duration::from_secs(5))
        .expect("blocked for more than 5 s")
}

#[test]
fn open_refuses_a_fifo_without_blocking() {
    let s = Scratch::new("fifo");
    mkfifo(&s.store_path());
    let p = s.store_path();
    let err = within_5s(move || SecretStore::open(&p).map(|_| ())).unwrap_err();
    assert!(matches!(err, SecretsError::Permissions { .. }), "{err:?}");
}

#[test]
fn open_refuses_a_parent_that_is_not_a_directory() {
    let s = Scratch::new("parentfile");
    std::fs::write(s.0.join("file"), "x").unwrap();
    let err = SecretStore::open(&s.0.join("file/secrets.toml")).unwrap_err();
    assert!(matches!(err, SecretsError::Permissions { .. }), "{err:?}");
}

#[test]
fn duplicate_key_in_different_spellings_is_rejected() {
    let s = Scratch::new("dupquoted");
    s.write(
        "TOKEN = \"abcdefghijklmnopqrstuvwx\"\n\"TOKEN\" = \"zzzzzzzzzzzzzzzzzzzzzzzz\"\n",
        0o600,
    );
    let err = SecretStore::open(&s.store_path()).unwrap_err();
    assert!(matches!(err, SecretsError::Parse { .. }), "{err:?}");
    assert!(!err.to_string().contains("abcdefgh"));
}

#[test]
fn too_many_entries_in_a_file_is_refused_without_echo() {
    let s = Scratch::new("toomanyfile");
    let mut text = String::new();
    for i in 0..=MAX_SECRETS {
        text.push_str(&format!("S{i} = \"canaryvalue{i:04}xxxx\"\n"));
    }
    s.write(&text, 0o600);
    let err = SecretStore::open(&s.store_path()).unwrap_err();
    assert!(matches!(err, SecretsError::TooMany), "{err:?}");
    assert!(!format!("{err} {err:?}").contains("canaryvalue"));
}

#[test]
fn invalid_utf8_is_a_parse_error_without_a_line() {
    let s = Scratch::new("utf8");
    let p = s.write("", 0o600);
    std::fs::write(&p, b"TOKEN = \"abc\xff\xfedefghijklmnop\"\n").unwrap();
    let err = SecretStore::open(&p).unwrap_err();
    assert!(matches!(err, SecretsError::Parse { line: None }), "{err:?}");
}

#[test]
fn a_value_of_exactly_the_maximum_length_loads_from_a_file() {
    let s = Scratch::new("maxfile");
    s.write(
        &format!("TOKEN = \"{}\"\n", "x".repeat(MAX_VALUE_BYTES)),
        0o600,
    );
    let store = SecretStore::open(&s.store_path()).unwrap();
    assert_eq!(store.get("TOKEN").unwrap().expose().len(), MAX_VALUE_BYTES);
}

#[test]
fn from_bytes_applies_the_size_limit() {
    let big = vec![b'#'; MAX_STORE_BYTES + 1];
    assert!(matches!(
        SecretStore::from_bytes(PathBuf::from("/x/secrets.toml"), &big),
        Err(SecretsError::TooLarge)
    ));
}

#[test]
fn save_removes_stale_temporary_files_from_a_crashed_save() {
    let s = Scratch::new("stale");
    let stale = s.0.join(".secrets.toml.999999.0.tmp");
    std::fs::write(&stale, "OLD = \"removed-credential-value\"\n").unwrap();
    std::fs::set_permissions(&stale, std::fs::Permissions::from_mode(0o600)).unwrap();
    let unrelated = s.0.join(".other.toml.1.0.tmp");
    std::fs::write(&unrelated, "x").unwrap();
    let mut store = SecretStore::open(&s.store_path()).unwrap();
    store.set("TOKEN", long("v")).unwrap();
    store.save().unwrap();
    assert!(!stale.exists());
    assert!(
        unrelated.exists(),
        "only this store's temporary files are swept"
    );
}

#[test]
fn concurrent_saves_from_threads_do_not_clobber_each_others_temp_files() {
    let s = Scratch::new("threads");
    let mut store = SecretStore::open(&s.store_path()).unwrap();
    store.set("TOKEN", long("v")).unwrap();
    let store = Arc::new(store);
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let st = Arc::clone(&store);
            std::thread::spawn(move || st.save())
        })
        .collect();
    for h in handles {
        // A sweep from another thread must never delete this process's own temp files.
        h.join().unwrap().unwrap();
    }
    assert!(
        SecretStore::open(&s.store_path())
            .unwrap()
            .contains("TOKEN")
    );
}

proptest! {
    /// Structured files: valid and invalid names and values, in valid and broken syntax. No
    /// outcome may echo any value-like word of the input.
    #[test]
    fn structured_files_never_leak_into_errors(
        lines in proptest::collection::vec(
            ("[A-Za-z_][A-Za-z0-9_]{0,70}", "[ -~\\t\\n]{0,40}", 0u8..4),
            0..6,
        )
    ) {
        let mut text = String::new();
        for (name, value, shape) in &lines {
            match shape {
                0 => text.push_str(&format!("{name} = \"{value}\"\n")),
                1 => text.push_str(&format!("{name} = '{value}'\n")),
                2 => text.push_str(&format!("{name} = {value}\n")),
                _ => text.push_str(&format!("[{name}]\n{value}\n")),
            }
        }
        let r = SecretStore::from_bytes(PathBuf::from("/x/secrets.toml"), text.as_bytes());
        if let Err(e) = r {
            let shown = format!("{e} | {e:?}");
            let vocab = vocabulary();
            for word in text.split(|c: char| !c.is_ascii_alphanumeric()).filter(|w| w.len() >= 8 && !vocab.iter().any(|m| m.contains(*w))) {
                prop_assert!(!shown.contains(word), "{shown}");
            }
        }
    }
}

/// Replays the fuzz corpus (seeds and past crashes) through the fuzz target's oracle, so a
/// regression shows up in `make test`, not only in the 60 s CI fuzz run.
#[test]
fn fuzz_corpus_satisfies_the_no_leak_oracle() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus/secrets");
    let vocab = vocabulary();
    let mut seen = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let data = std::fs::read(entry.unwrap().path()).unwrap();
        seen += 1;
        if let Err(e) = SecretStore::from_bytes(PathBuf::from("/x/secrets.toml"), &data) {
            let shown = format!("{e} | {e:?}");
            let text = String::from_utf8_lossy(&data);
            for word in text.split(|c: char| !c.is_ascii_alphanumeric()) {
                assert!(
                    word.len() < 8
                        || vocab.iter().any(|m| m.contains(word))
                        || !shown.contains(word),
                    "{shown}"
                );
            }
        }
    }
    assert!(seen >= 3, "corpus went missing");
}

// ---- the writers' lock (architect Q108) ---------------------------------------------------

/// Two editors, one holding the lock while the other starts: both changes survive. Without the
/// lock the second opens the old snapshot, and the first's save (which comes last) drops the
/// second's change.
#[test]
fn two_interleaved_edits_both_survive() {
    let s = Scratch::new("lock-edits");
    let path = s.store_path();
    let held = SecretStore::lock(&path).unwrap();
    let mut first = SecretStore::open(&path).unwrap();
    first.set("FIRST", long("a")).unwrap();
    let p2 = path.clone();
    let second = std::thread::spawn(move || {
        let _lock = SecretStore::lock(&p2).unwrap();
        let mut st = SecretStore::open(&p2).unwrap();
        st.set("SECOND", long("b")).unwrap();
        st.save().unwrap();
    });
    // The second editor is blocked meanwhile; give it time to have opened if it were not.
    std::thread::sleep(std::time::Duration::from_millis(300));
    first.save().unwrap();
    drop(held);
    second.join().unwrap();
    let st = SecretStore::open(&path).unwrap();
    assert!(st.contains("FIRST") && st.contains("SECOND"));
}

/// A lock another writer keeps is not waited on forever (maintainer, 2026-11-14): after the
/// wait, a clear error naming the lock file and saying nothing changed.
#[test]
fn a_held_lock_times_out_with_a_clear_message() {
    let s = Scratch::new("lock-held");
    let path = s.store_path();
    let held = SecretStore::lock(&path).unwrap();
    let wait = std::time::Duration::from_millis(200);
    let start = std::time::Instant::now();
    let e = SecretStore::lock_within(&path, wait).unwrap_err();
    let took = start.elapsed();
    assert!(matches!(e, SecretsError::LockHeld { .. }), "{e:?}");
    assert!(took >= wait, "gave up after {took:?}");
    assert!(took < std::time::Duration::from_secs(5), "{took:?}");
    let msg = e.to_string();
    for needle in ["secrets.lock", "another", "nothing changed", "0.2 s"] {
        assert!(msg.contains(needle), "{needle:?} not in {msg}");
    }
    drop(held);
    assert!(
        SecretStore::lock_within(&path, wait).is_ok(),
        "free once released"
    );
}

/// A lock released during the wait is taken; a free lock is taken even with no wait at all.
#[test]
fn a_lock_released_within_the_wait_is_taken() {
    let s = Scratch::new("lock-wait");
    let path = s.store_path();
    assert!(SecretStore::lock_within(&path, std::time::Duration::ZERO).is_ok());
    let held = SecretStore::lock(&path).unwrap();
    let release = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(150));
        drop(held);
    });
    let start = std::time::Instant::now();
    let got = SecretStore::lock_within(&path, std::time::Duration::from_secs(5));
    assert!(got.is_ok(), "{got:?}");
    assert!(start.elapsed() >= std::time::Duration::from_millis(150));
    release.join().unwrap();
}

/// With no wait, a held lock is refused after one try.
#[test]
fn a_held_lock_with_no_wait_is_refused_at_once() {
    let s = Scratch::new("lock-zero");
    let path = s.store_path();
    let _held = SecretStore::lock(&path).unwrap();
    let start = std::time::Instant::now();
    let e = SecretStore::lock_within(&path, std::time::Duration::ZERO).unwrap_err();
    assert!(matches!(e, SecretsError::LockHeld { .. }), "{e:?}");
    assert!(start.elapsed() < std::time::Duration::from_secs(1));
}

/// A FIFO planted as the lock is refused, not opened (which would block past any timeout).
#[test]
fn a_fifo_lock_is_refused_without_blocking() {
    let s = Scratch::new("lock-fifo");
    mkfifo(&s.0.join("secrets.lock"));
    let p = s.store_path();
    let e = within_5s(move || SecretStore::lock(&p).map(|_| ())).unwrap_err();
    assert!(matches!(e, SecretsError::Permissions { .. }), "{e:?}");
}

/// A lock someone made readable to others is set back to 0600; a directory is refused.
#[test]
fn an_open_lock_file_is_made_private_and_a_directory_is_refused() {
    let s = Scratch::new("lock-mode");
    let lock = s.0.join("secrets.lock");
    std::fs::write(&lock, "").unwrap();
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o644)).unwrap();
    drop(SecretStore::lock(&s.store_path()).unwrap());
    assert_eq!(mode_of(&lock), 0o600);
    std::fs::remove_file(&lock).unwrap();
    std::fs::create_dir(&lock).unwrap();
    assert!(matches!(
        SecretStore::lock(&s.store_path()),
        Err(SecretsError::Permissions { .. } | SecretsError::Io { .. })
    ));
}

#[test]
fn the_default_lock_wait_is_ten_seconds() {
    assert_eq!(
        sally_core::secrets::LOCK_WAIT,
        std::time::Duration::from_secs(10)
    );
}

#[test]
fn the_lock_is_a_private_file_beside_the_store_and_creates_its_directory() {
    let s = Scratch::new("lock-file");
    let path = s.0.join("sub/secrets.toml");
    let lock = SecretStore::lock(&path).unwrap();
    assert_eq!(mode_of(&s.0.join("sub/secrets.lock")), 0o600);
    assert_eq!(mode_of(&s.0.join("sub")), 0o700);
    assert!(!path.exists(), "the lock creates no store");
    drop(lock);
}

#[test]
fn a_symlinked_lock_or_an_open_directory_is_refused() {
    let s = Scratch::new("lock-refuse");
    let path = s.store_path();
    symlink(s.0.join("elsewhere"), s.0.join("secrets.lock")).unwrap();
    assert!(matches!(
        SecretStore::lock(&path),
        Err(SecretsError::Permissions { .. })
    ));
    assert!(!s.0.join("elsewhere").exists());
    std::fs::remove_file(s.0.join("secrets.lock")).unwrap();
    std::fs::set_permissions(&s.0, std::fs::Permissions::from_mode(0o770)).unwrap();
    assert!(matches!(
        SecretStore::lock(&path),
        Err(SecretsError::Permissions { .. })
    ));
}
