//! `sally secrets …` error paths through the binary (maintainer ruling 2026-11-14): no message
//! repeats an argument, since one may be a secret value typed where it does not belong. A
//! command line that names the secrets command and does not parse, or that gives an illegal
//! name, says the value may now be in shell history, should be rotated, and how to enter one.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::io::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

/// Stands in for a secret value typed on the command line; it must never be printed.
const VALUE: &str = "VALUEzq7Kp";
/// A legal name; it must never be printed either.
const NAME: &str = "NAMEXJW";

/// A throwaway `$HOME`; the store is `$HOME/.config/sallyport/secrets.toml`.
struct Home(PathBuf);

impl Home {
    fn new(tag: &str) -> Self {
        let d = std::env::temp_dir().join(format!("sc-sa-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Self(d)
    }

    fn store(&self) -> PathBuf {
        self.0.join(".config/sallyport/secrets.toml")
    }

    fn sally(&self, args: &[&str], stdin: &[u8]) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_sally"))
            .args(args)
            .env_clear()
            .env("HOME", &self.0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // A write error is fine: the binary may exit before it reads stdin.
        let _ = child.stdin.take().unwrap().write_all(stdin);
        child.wait_with_output().unwrap()
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

/// Neither stream holds any of `args` except the command words (and their typos, which the
/// fixed message contains).
fn echoes_nothing(o: &Output, args: &[&str]) {
    let all = text(o);
    for a in args {
        if ["secrets", "secret", "Secrets", "set", "list", "rm", "--"].contains(a) {
            continue;
        }
        assert!(!all.contains(a), "{a:?} was printed: {all}");
    }
}

/// A command line that did not parse: exit 2, nothing on stdout, the guidance on stderr,
/// no argument repeated, nothing stored.
fn argv_refused(tag: &str, args: &[&str]) {
    let h = Home::new(tag);
    let o = h.sally(args, b"");
    assert_eq!(o.status.code(), Some(2), "{args:?}: {}", text(&o));
    assert!(o.stdout.is_empty(), "{args:?}: {}", text(&o));
    guidance(&o);
    echoes_nothing(&o, args);
    assert!(!h.store().exists(), "{args:?} stored something");
}

/// The shell-history warning and the right way to enter a value.
fn guidance(o: &Output) {
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains("shell history"), "{err}");
    assert!(err.contains("rotate"), "{err}");
    assert!(err.contains("sally secrets set NAME"), "{err}");
    assert!(err.contains("stdin"), "{err}");
}

#[test]
fn set_with_a_value_argument_is_refused_without_echo() {
    argv_refused("s-extra", &["secrets", "set", NAME, VALUE]);
}

#[test]
fn set_after_a_double_dash_is_refused_without_echo() {
    argv_refused("s-dash", &["secrets", "set", "--", NAME, VALUE]);
}

#[test]
fn set_with_an_unknown_option_is_refused_without_echo() {
    argv_refused(
        "s-opt",
        &["secrets", "set", &format!("--value={VALUE}"), NAME],
    );
}

#[test]
fn set_without_a_name_is_refused() {
    argv_refused("s-none", &["secrets", "set"]);
}

#[test]
fn list_with_an_argument_is_refused_without_echo() {
    argv_refused("l-extra", &["secrets", "list", VALUE]);
}

#[test]
fn list_with_an_unknown_option_is_refused_without_echo() {
    argv_refused("l-opt", &["secrets", "list", &format!("--{VALUE}")]);
}

#[test]
fn rm_with_a_second_argument_is_refused_without_echo() {
    argv_refused("r-extra", &["secrets", "rm", NAME, VALUE]);
}

#[test]
fn rm_with_an_unknown_option_is_refused_without_echo() {
    argv_refused("r-opt", &["secrets", "rm", &format!("-{VALUE}"), NAME]);
}

#[test]
fn rm_without_a_name_is_refused() {
    argv_refused("r-none", &["secrets", "rm"]);
}

#[test]
fn an_unknown_secrets_subcommand_is_refused_without_echo() {
    argv_refused("sub", &["secrets", VALUE]);
}

#[test]
fn secrets_without_a_subcommand_is_refused() {
    argv_refused("bare", &["secrets"]);
}

#[test]
fn a_mistyped_secrets_command_is_refused_without_echo() {
    argv_refused("typo", &["secret", "set", NAME, VALUE]);
    argv_refused("case", &["Secrets", "set", NAME, VALUE]);
}

#[test]
fn an_option_before_secrets_is_refused_without_echo() {
    argv_refused("pre", &[&format!("--{VALUE}"), "secrets", "set", NAME]);
}

#[test]
fn help_is_still_help() {
    let h = Home::new("help");
    let o = h.sally(&["secrets", "set", "--help"], b"");
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    assert!(String::from_utf8_lossy(&o.stdout).contains("stty echo"));
}

/// An illegal name may be a value typed where the name goes: the same guidance, exit 2.
#[test]
fn set_with_an_illegal_name_is_refused_without_echo() {
    let h = Home::new("s-name");
    let o = h.sally(&["secrets", "set", "valuezq7kp"], b"never read\n");
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    guidance(&o);
    echoes_nothing(&o, &["valuezq7kp", "never read"]);
    assert!(!h.store().exists());
}

#[test]
fn rm_with_an_illegal_name_is_refused_without_echo() {
    let h = Home::new("r-name");
    let o = h.sally(&["secrets", "rm", "valuezq7kp"], b"");
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    guidance(&o);
    echoes_nothing(&o, &["valuezq7kp"]);
}

/// The value-read errors (exit 1): none prints the name or what was read.
#[test]
fn set_with_an_empty_value_is_refused_without_echo() {
    let h = Home::new("s-empty");
    let o = h.sally(&["secrets", "set", NAME], b"\n");
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    echoes_nothing(&o, &[NAME]);
    assert!(!h.store().exists());
}

#[test]
fn set_with_a_value_over_the_cap_is_refused_without_echo() {
    let h = Home::new("s-long");
    let long = "Q".repeat(sally_core::secrets::MAX_VALUE_BYTES + 1);
    let o = h.sally(&["secrets", "set", NAME], long.as_bytes());
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    echoes_nothing(&o, &[NAME, "QQQQ"]);
    assert!(!h.store().exists());
}

#[test]
fn set_with_a_non_utf8_value_is_refused_without_echo() {
    let h = Home::new("s-utf8");
    let o = h.sally(&["secrets", "set", NAME], b"VALUEzq7\xff\xfe");
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    echoes_nothing(&o, &[NAME, "VALUEzq7"]);
    assert!(!h.store().exists());
}

#[test]
fn set_with_a_value_the_store_refuses_is_refused_without_echo() {
    let h = Home::new("s-ctl");
    let o = h.sally(&["secrets", "set", NAME], b"VALUEzq7Kp-long-enough\x07");
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    echoes_nothing(&o, &[NAME, VALUE]);
    assert!(!h.store().exists());
}

#[test]
fn rm_of_an_absent_name_is_refused_without_echo() {
    let h = Home::new("r-absent");
    let o = h.sally(&["secrets", "rm", NAME], b"");
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    echoes_nothing(&o, &[NAME]);
}

/// A store directory that is group-writable cannot be used: set, list and rm fail (exit 2)
/// without printing the name or the value.
#[test]
fn an_unusable_store_fails_every_subcommand_without_echo() {
    let h = Home::new("bad");
    let dir = h.store().parent().unwrap().to_owned();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o770)).unwrap();
    let o = h.sally(
        &["secrets", "set", NAME],
        format!("{VALUE}-long-enough\n").as_bytes(),
    );
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    echoes_nothing(&o, &[NAME, VALUE]);
    let o = h.sally(&["secrets", "list"], b"");
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    let o = h.sally(&["secrets", "rm", NAME], b"");
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    echoes_nothing(&o, &[NAME]);
}

/// Core dumps are off while `pid` runs: polled from its `/proc/<pid>/limits` (mode 0444),
/// since the process sets them itself a moment after it starts.
fn core_dumps_off(pid: u32) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        let limits = std::fs::read_to_string(format!("/proc/{pid}/limits")).unwrap_or_default();
        if limits.lines().any(|l| {
            l.starts_with("Max core file size")
                && l.split_whitespace().nth(4) == Some("0")
                && l.split_whitespace().nth(5) == Some("0")
        }) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    false
}

/// Security review MEDIUM-1: every secrets subcommand turns core dumps off before it holds
/// plaintext. `set` is caught waiting for its value, `rm` waiting for a held lock.
#[test]
fn secrets_commands_run_with_core_dumps_off() {
    let h = Home::new("harden");
    let spawn = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_sally"))
            .args(args)
            .env_clear()
            .env("HOME", &h.0)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    };
    let mut set = spawn(&["secrets", "set", NAME]);
    let off = core_dumps_off(set.id());
    drop(set.stdin.take());
    let _ = set.wait();
    assert!(off, "set: core dumps were not turned off");
    let lock = sally_core::secrets::SecretStore::lock(&h.store()).unwrap();
    let mut rm = spawn(&["secrets", "rm", NAME]);
    let off = core_dumps_off(rm.id());
    drop(lock);
    let _ = rm.wait();
    assert!(off, "rm: core dumps were not turned off");
}

/// The piped form end to end: the value is read from fd 0, stored, and only the name listed.
#[test]
fn a_piped_value_is_stored_and_only_its_name_listed() {
    let h = Home::new("piped");
    let o = h.sally(
        &["secrets", "set", NAME],
        format!("{VALUE}-long-enough\n").as_bytes(),
    );
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    echoes_nothing(&o, &[NAME, VALUE]);
    let store = sally_core::secrets::SecretStore::open(&h.store()).unwrap();
    assert_eq!(
        store.get(NAME).unwrap().expose(),
        &format!("{VALUE}-long-enough")
    );
    let o = h.sally(&["secrets", "list"], b"");
    assert_eq!(
        (o.status.code(), String::from_utf8_lossy(&o.stdout).as_ref()),
        (Some(0), format!("{NAME}\n").as_str())
    );
}

/// `$HOME` unset: the paths cannot be derived (exit 2), and nothing is echoed.
#[test]
fn set_without_a_home_fails_without_echo() {
    let o = Command::new(env!("CARGO_BIN_EXE_sally"))
        .args(["secrets", "set", NAME])
        .env_clear()
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    echoes_nothing(&o, &[NAME]);
}
