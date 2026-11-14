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
fn a_terminal_line_ends_at_its_newline_or_eof() {
    let mut r = &b"first\nsecond\nlast"[..];
    assert_eq!(read_line(&mut r, None).unwrap().as_str(), "first");
    assert_eq!(read_line(&mut r, None).unwrap().as_str(), "second");
    assert_eq!(read_line(&mut r, None).unwrap().as_str(), "last");
    assert_eq!(read_line(&mut r, None), Err(ValueError::Empty));
}

#[test]
fn a_terminal_line_stops_at_the_cancel_byte() {
    let mut r = &b"part\x03ial\n"[..];
    assert_eq!(read_line(&mut r, Some(3)), Err(ValueError::Cancelled));
    let mut r = &b"part\x03ial\n"[..];
    assert!(read_line(&mut r, None).is_ok(), "no cancel byte, no cancel");
}

#[test]
fn a_terminal_line_is_capped_below_the_kernel_line() {
    let at = format!("{}\n", value(TTY_MAX_VALUE_BYTES));
    assert_eq!(read_line(&mut at.as_bytes(), None).unwrap().len(), 4094);
    let over = format!("{}\n", value(TTY_MAX_VALUE_BYTES + 1));
    assert_eq!(
        read_line(&mut over.as_bytes(), None),
        Err(ValueError::TooLongForTerminal)
    );
}

#[test]
fn value_errors_exit_2_only_when_nothing_could_be_read() {
    for e in [
        ValueError::Terminal(String::new()),
        ValueError::Read(String::new()),
    ] {
        assert_eq!(e.exit_code(), EXIT_FAILED, "{e:?}");
    }
    for e in [
        ValueError::TooLong,
        ValueError::NotUtf8,
        ValueError::Empty,
        ValueError::Cancelled,
        ValueError::TooLongForTerminal,
    ] {
        assert_eq!(e.exit_code(), EXIT_REFUSED, "{e:?}");
    }
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

/// Types `typed` on the controller when the prompt is written, that is after echo is off, and
/// records the terminal's settings at that moment.
struct TypeAfterPrompt {
    controller: std::fs::File,
    terminal: std::fs::File,
    typed: Vec<u8>,
    prompt: Vec<u8>,
    during: Option<rustix::termios::Termios>,
}

impl Write for TypeAfterPrompt {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.prompt.is_empty() {
            self.during = rustix::termios::tcgetattr(&self.terminal).ok();
            self.controller.write_all(&self.typed)?;
        }
        self.prompt.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// What one prompt on a fresh pty did.
struct Typed {
    got: Result<String, ValueError>,
    before: rustix::termios::Termios,
    during: rustix::termios::Termios,
    after: rustix::termios::Termios,
    /// What the terminal displayed.
    shown: Vec<u8>,
    /// Input still unread after the prompt returned.
    left: Vec<u8>,
}

/// `read_terminal` on a fresh pty with `typed` typed at the prompt; bounded at 10 s so a
/// terminal that never ends the line fails the test instead of hanging it.
fn type_at_prompt(typed: &[u8]) -> Typed {
    let typed = typed.to_vec();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        use rustix::termios::tcgetattr;
        let (mut controller, terminal) = pty();
        let before = tcgetattr(&terminal).unwrap();
        let mut err = TypeAfterPrompt {
            controller: controller.try_clone().unwrap(),
            terminal: terminal.try_clone().unwrap(),
            typed,
            prompt: Vec::new(),
            during: None,
        };
        let got = read_terminal(&terminal, "value: ", &mut err).map(|v| v.to_string());
        assert!(err.prompt.starts_with(b"value: "), "{:?}", err.prompt);
        let after = tcgetattr(&terminal).unwrap();
        rustix::fs::fcntl_setfl(&terminal, rustix::fs::OFlags::NONBLOCK).unwrap();
        let mut left = Vec::new();
        let _ = (&terminal).read_to_end(&mut left);
        // Closing every handle on the terminal ends the controller's stream (EIO) once what
        // is buffered has been read.
        drop((terminal, err.terminal));
        let mut shown = Vec::new();
        let mut chunk = [0_u8; 256];
        while let Ok(n @ 1..) = controller.read(&mut chunk) {
            shown.extend_from_slice(&chunk[..n]);
        }
        let during = err.during.unwrap();
        let _ = tx.send(Typed {
            got,
            before,
            during,
            after,
            shown,
            left,
        });
    });
    rx.recv_timeout(std::time::Duration::from_secs(10))
        .expect("the prompt did not return within 10 s")
}

fn shown_contains(t: &Typed, needle: &[u8]) -> bool {
    t.shown.windows(needle.len()).any(|w| w == needle)
}

/// Everything the prompt changed is back: echo, signals, the line-end character.
fn restored(t: &Typed) {
    use rustix::termios::{LocalModes, SpecialCodeIndex};
    let modes = t.after.local_modes;
    assert!(modes.contains(LocalModes::ECHO), "echo was not restored");
    assert!(modes.contains(LocalModes::ICANON | LocalModes::ISIG));
    let veol = SpecialCodeIndex::VEOL;
    assert_eq!(t.after.special_codes[veol], t.before.special_codes[veol]);
}

#[test]
fn a_terminal_value_is_read_without_echo_or_signals_and_all_comes_back() {
    use rustix::termios::{LocalModes, SpecialCodeIndex};
    let t = type_at_prompt(b"s3cret-typed-value\n");
    assert_eq!(t.got.as_deref(), Ok("s3cret-typed-value"));
    assert!(!shown_contains(&t, b"s3cret"), "echoed: {:?}", t.shown);
    assert!(!t.during.local_modes.contains(LocalModes::ECHO));
    assert!(!t.during.local_modes.contains(LocalModes::ISIG));
    assert!(t.during.local_modes.contains(LocalModes::ICANON));
    let intr = t.before.special_codes[SpecialCodeIndex::VINTR];
    assert_ne!(intr, 0);
    assert_eq!(t.during.special_codes[SpecialCodeIndex::VEOL], intr);
    restored(&t);
}

/// Architect Q112: Ctrl-C cancels the prompt (no signal), shows nothing, and restores all.
#[test]
fn ctrl_c_at_the_prompt_cancels_and_restores_echo() {
    let t = type_at_prompt(b"partial\x03");
    assert_eq!(t.got, Err(ValueError::Cancelled));
    assert!(!shown_contains(&t, b"partial"), "echoed: {:?}", t.shown);
    restored(&t);
}

#[test]
fn an_empty_line_is_refused_and_echo_comes_back() {
    let t = type_at_prompt(b"\n");
    assert_eq!(t.got, Err(ValueError::Empty));
    restored(&t);
}

/// The rest of a multi-line paste is discarded, never left for the shell to read and echo.
#[test]
fn the_rest_of_a_pasted_block_is_discarded() {
    let t = type_at_prompt(b"first-line\nsecond-line\n");
    assert_eq!(t.got.as_deref(), Ok("first-line"));
    assert!(t.left.is_empty(), "left for the shell: {:?}", t.left);
    restored(&t);
}

/// Architect Q114, probed: the kernel keeps 4095 bytes of a longer line, so 4094 is the most
/// the prompt accepts; longer is refused, never stored cut.
#[test]
fn the_prompt_takes_4094_bytes_and_refuses_more() {
    let at = type_at_prompt(format!("{}\n", "k".repeat(4094)).as_bytes());
    assert_eq!(at.got, Ok("k".repeat(4094)));
    for len in [4095, 5000, 8192] {
        let t = type_at_prompt(format!("{}\n", "k".repeat(len)).as_bytes());
        assert_eq!(t.got, Err(ValueError::TooLongForTerminal), "{len}");
        restored(&t);
    }
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
fn a_value_that_was_not_given_is_refused() {
    let s = Scratch::new("refuse");
    let mut read = || Err(ValueError::Empty);
    let (code, _, err) = run(|o| set(&s.store(), "A", &mut read, o));
    assert_eq!(
        (code, err.as_str()),
        (EXIT_REFUSED, "sally: no value was given\n")
    );
    assert!(!s.store().exists());
}

/// Architect Q115: a terminal or stdin that cannot be read fails (2), nothing stored.
#[test]
fn a_value_that_could_not_be_read_fails() {
    let s = Scratch::new("readfail");
    let mut read = || Err(ValueError::Read("broken pipe".into()));
    let (code, _, err) = run(|o| set(&s.store(), "A", &mut read, o));
    assert_eq!(
        (code, err.as_str()),
        (EXIT_FAILED, "sally: stdin: broken pipe\n")
    );
    assert!(!s.store().exists());
}

#[test]
fn a_value_the_store_refuses_is_refused_without_echo() {
    let s = Scratch::new("refuse-store");
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
