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

/// A pseudo-terminal: (controller, terminal).
fn pty() -> (std::fs::File, std::fs::File) {
    use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
    use std::os::unix::fs::OpenOptionsExt;
    let controller = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
    grantpt(&controller).unwrap();
    unlockpt(&controller).unwrap();
    let name = ptsname(&controller, Vec::new()).unwrap();
    let terminal = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(rustix::fs::OFlags::NOCTTY.bits().cast_signed())
        .open(name.to_str().unwrap())
        .unwrap();
    (std::fs::File::from(controller), terminal)
}

/// Types `value` on the controller when the prompt is written, that is after echo is off.
struct TypeAfterPrompt<'a> {
    controller: &'a mut std::fs::File,
    value: &'a [u8],
    prompt: Vec<u8>,
}

impl Write for TypeAfterPrompt<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.prompt.is_empty() {
            self.controller.write_all(self.value)?;
        }
        self.prompt.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_terminal_value_is_read_without_echo_and_echo_comes_back() {
    use rustix::termios::{LocalModes, tcgetattr};
    let (mut controller, terminal) = pty();
    assert!(
        tcgetattr(&terminal)
            .unwrap()
            .local_modes
            .contains(LocalModes::ECHO)
    );
    let mut err = TypeAfterPrompt {
        controller: &mut controller,
        value: b"s3cret-typed-value\n",
        prompt: Vec::new(),
    };
    let got = read_terminal(&terminal, "value: ", &mut err).unwrap();
    assert_eq!(got.as_str(), "s3cret-typed-value");
    assert!(err.prompt.starts_with(b"value: "), "{:?}", err.prompt);
    let modes = tcgetattr(&terminal).unwrap().local_modes;
    assert!(modes.contains(LocalModes::ECHO), "echo was not restored");
    assert!(modes.contains(LocalModes::ICANON | LocalModes::ISIG));
    // What the terminal showed: nothing of the value. Closing the terminal ends the
    // controller's stream (EIO) once what is buffered has been read.
    drop(terminal);
    let mut shown = Vec::new();
    let mut chunk = [0_u8; 256];
    while let Ok(n @ 1..) = controller.read(&mut chunk) {
        shown.extend_from_slice(&chunk[..n]);
    }
    assert!(
        !shown.windows(6).any(|w| w == b"s3cret"),
        "echoed: {shown:?}"
    );
}

#[test]
fn a_file_that_is_not_a_terminal_reads_nothing_and_prompts_nothing() {
    let s = Scratch::new("notty");
    let f = s.0.join("f");
    std::fs::write(&f, "typed\n").unwrap();
    let file = std::fs::File::open(&f).unwrap();
    let mut err = Vec::new();
    let got = read_terminal(&file, "value: ", &mut err);
    assert!(matches!(got, Err(ValueError::Terminal(_))), "{got:?}");
    assert!(err.is_empty());
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

/// Another writer's lock outlasting the wait fails the command (2) with the store's message.
#[test]
fn a_held_lock_fails_with_its_message_and_no_name() {
    let e = SecretsError::LockHeld {
        path: "/s/secrets.lock".into(),
        waited: std::time::Duration::from_secs(10),
    };
    let (code, out, err) = run(|o| store_error(o, &e));
    assert_eq!((code, out.as_str()), (EXIT_FAILED, ""));
    assert_eq!(err, format!("sally: {e}\n"));
    assert!(err.contains("nothing changed"), "{err}");
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
