#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use sally_core::secrets::SHORT_SECRET_BYTES;

use super::*;

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let d = std::env::temp_dir().join(format!("sc-sec-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(d)
    }

    fn store(&self) -> PathBuf {
        self.0.join("secrets.toml")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Runs `f` with fresh writers; returns its code, stdout and stderr.
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

fn value(len: usize) -> String {
    "v".repeat(len)
}

fn piped(bytes: &[u8]) -> Result<String, ValueError> {
    read_piped(&mut &bytes[..]).map(|v| v.to_string())
}

#[test]
fn a_piped_value_loses_exactly_one_trailing_newline() {
    assert_eq!(piped(b"abc\n").unwrap(), "abc");
    assert_eq!(piped(b"abc").unwrap(), "abc");
    assert_eq!(piped(b"abc\n\n").unwrap(), "abc\n");
    assert_eq!(piped(b"a\nb").unwrap(), "a\nb");
}

#[test]
fn a_piped_value_is_bounded_non_empty_and_utf8() {
    let max = value(MAX_VALUE_BYTES);
    assert_eq!(piped(max.as_bytes()).unwrap(), max);
    assert_eq!(piped(format!("{max}\n").as_bytes()).unwrap(), max);
    let over = value(MAX_VALUE_BYTES + 1);
    assert_eq!(piped(over.as_bytes()), Err(ValueError::TooLong));
    assert_eq!(
        piped(format!("{over}\n").as_bytes()),
        Err(ValueError::TooLong)
    );
    let far = value(MAX_VALUE_BYTES * 3);
    assert_eq!(piped(far.as_bytes()), Err(ValueError::TooLong));
    assert_eq!(piped(b""), Err(ValueError::Empty));
    assert_eq!(piped(b"\n"), Err(ValueError::Empty));
    assert_eq!(piped(b"\xff\xfe"), Err(ValueError::NotUtf8));
}

#[test]
fn a_terminal_line_ends_at_its_newline() {
    let mut r = &b"first\nsecond\n"[..];
    assert_eq!(read_line(&mut r).unwrap().as_str(), "first");
    assert_eq!(read_line(&mut r).unwrap().as_str(), "second");
    assert_eq!(read_line(&mut r), Err(ValueError::Empty));
    let over = format!("{}\n", value(MAX_VALUE_BYTES + 1));
    assert_eq!(read_line(&mut over.as_bytes()), Err(ValueError::TooLong));
}

#[test]
fn set_stores_the_value_and_says_sessions_cannot_use_it_yet() {
    let s = Scratch::new("set");
    let secret = value(SHORT_SECRET_BYTES + 8);
    let given = secret.clone();
    let mut read = move || Ok(Zeroizing::new(given.clone()));
    let (code, out, err) = run(|o| set(&s.store(), "API_KEY", &mut read, o));
    assert_eq!(code, EXIT_OK);
    assert_eq!(out, "");
    assert_eq!(err, format!("{NOT_YET_USED}\n"));
    let store = SecretStore::open(&s.store()).unwrap();
    assert_eq!(store.get("API_KEY").unwrap().expose(), &secret);
    assert!(s.0.join("secrets.lock").exists(), "set takes the lock");
}

#[test]
fn a_short_value_is_stored_with_a_warning() {
    let s = Scratch::new("short");
    let mut read = || Ok(Zeroizing::new("abc".to_owned()));
    let (code, _, err) = run(|o| set(&s.store(), "SHORT", &mut read, o));
    assert_eq!(code, EXIT_OK);
    assert!(err.starts_with("warning: the value is short"), "{err}");
    assert!(!err.contains("abc") && !err.contains("SHORT"), "{err}");
}

#[test]
fn an_illegal_name_is_a_usage_error_before_any_value_is_read() {
    let s = Scratch::new("name");
    let mut asked = false;
    let mut read = || {
        asked = true;
        Ok(Zeroizing::new(value(32)))
    };
    let (code, _, err) = run(|o| set(&s.store(), "lower", &mut read, o));
    assert_eq!(code, EXIT_FAILED);
    assert!(!asked);
    assert!(!err.contains("lower"), "{err}");
    assert!(err.ends_with(&format!("{ARGV_WARNING}\n")), "{err}");
    assert!(!s.store().exists());
    let (code, _, err) = run(|o| rm(&s.store(), "lower", o));
    assert_eq!(code, EXIT_FAILED);
    assert!(!err.contains("lower"), "{err}");
    assert!(err.ends_with(&format!("{ARGV_WARNING}\n")), "{err}");
}

#[test]
fn a_command_line_naming_secrets_in_any_case_is_matched() {
    let args = |a: &[&str]| -> Vec<std::ffi::OsString> { a.iter().map(Into::into).collect() };
    assert!(names_secrets(&args(&["secrets", "set", "A", "B"])));
    assert!(names_secrets(&args(&["--x", "Secret"])));
    assert!(names_secrets(&args(&["session", "my-SECRET.toml"])));
    assert!(names_secrets(&args(&["secret"])));
    assert!(!names_secrets(&args(&[
        "secre",
        "t",
        "session",
        "secr\u{e9}t"
    ])));
    assert!(!names_secrets(&args(&[])));
}

#[test]
fn the_argv_warning_names_history_rotation_and_both_ways_in() {
    for needle in ["shell history", "rotate", "sally secrets set NAME", "stdin"] {
        assert!(ARGV_WARNING.contains(needle), "{needle}");
    }
}

#[test]
fn a_value_that_cannot_be_read_or_stored_is_refused_without_echo() {
    let s = Scratch::new("refuse");
    let mut read = || Err(ValueError::Empty);
    let (code, _, err) = run(|o| set(&s.store(), "A", &mut read, o));
    assert_eq!(
        (code, err.as_str()),
        (EXIT_REFUSED, "sally: no value was given\n")
    );
    // The store refuses a value with a control character.
    let mut read = || Ok(Zeroizing::new(format!("{}\u{7}", value(32))));
    let (code, _, err) = run(|o| set(&s.store(), "A", &mut read, o));
    assert_eq!(code, EXIT_REFUSED, "{err}");
    assert!(!err.contains("vvvv"), "{err}");
    assert!(!s.store().exists());
}

#[test]
fn a_store_that_cannot_be_used_fails() {
    let s = Scratch::new("perm");
    std::fs::set_permissions(&s.0, std::fs::Permissions::from_mode(0o770)).unwrap();
    let mut read = || Ok(Zeroizing::new(value(32)));
    let (code, _, err) = run(|o| set(&s.store(), "A", &mut read, o));
    assert_eq!(code, EXIT_FAILED, "{err}");
    assert_eq!(run(|o| list(&s.store(), o)).0, EXIT_FAILED);
    assert_eq!(run(|o| rm(&s.store(), "A", o)).0, EXIT_FAILED);
}

#[test]
fn list_prints_names_and_rm_removes_one() {
    let s = Scratch::new("list");
    for name in ["B_KEY", "A_KEY"] {
        let mut read = || Ok(Zeroizing::new(value(32)));
        assert_eq!(run(|o| set(&s.store(), name, &mut read, o)).0, EXIT_OK);
    }
    assert_eq!(
        run(|o| list(&s.store(), o)),
        (EXIT_OK, "A_KEY\nB_KEY\n".into(), String::new())
    );
    assert_eq!(run(|o| rm(&s.store(), "A_KEY", o)).0, EXIT_OK);
    assert_eq!(run(|o| list(&s.store(), o)).1, "B_KEY\n");
}

#[test]
fn removing_an_absent_name_saves_nothing() {
    let s = Scratch::new("absent");
    let (code, _, err) = run(|o| rm(&s.store(), "NOPE", o));
    assert_eq!(
        (code, err.as_str()),
        (EXIT_REFUSED, "sally: no secret by that name\n")
    );
    assert!(!s.store().exists());
    assert_eq!(
        run(|o| list(&s.store(), o)),
        (EXIT_OK, String::new(), String::new())
    );
}
