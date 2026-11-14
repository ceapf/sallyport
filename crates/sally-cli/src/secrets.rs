//! `sally secrets set|list|rm` (architect Q52, Q108): the CLI edits the 0600 store directly,
//! through [`SecretStore`] only, holding the writers' lock across open, change and save.
//!
//! A value never comes from argv or the environment (SI-3). Piped stdin is one bounded read
//! with one trailing newline removed; a terminal gets a prompt with echo off, restored on every
//! return, Ctrl-C included: it cancels the prompt instead of killing the process (architect
//! Q112). A signal from outside the terminal (SIGTERM, SIGHUP) still ends it with echo off;
//! `stty echo` turns it back on. The value is read before the lock is taken, so no lock is
//! held across a prompt. Messages never name the secret or show its value.

use std::io::{Read, Write};
use std::path::Path;

use sally_core::secrets::{MAX_VALUE_BYTES, SecretStore, SecretsError, is_secret_name};
use zeroize::Zeroizing;

use crate::commands::Out;
use crate::{EXIT_FAILED, EXIT_OK, EXIT_REFUSED, clean};

/// What stored secrets are for until #99: printed by `set` and by a rejected manifest that
/// grants one. TODO(#99): remove once sallyd reads the store.
pub const NOT_YET_USED: &str = "note: sessions cannot use stored secrets yet (#99); a manifest that \
                                grants one is refused until then";

/// Printed after a secrets command line that was not understood, or that gave an illegal name
/// (maintainer ruling, 2026-11-14). It repeats no argument: a value typed where it does not
/// belong is already in argv and may be in shell history, and must not reach the terminal or a
/// log too.
pub const ARGV_WARNING: &str = "\
If a secret value was on that command line, it may now be in your shell history: rotate the \
secret.\nA value is never an argument. Run `sally secrets set NAME` and type it at the prompt \
(not shown), or pipe it on stdin: `sally secrets set NAME < file`.\nusage: sally secrets set \
NAME | sally secrets list | sally secrets rm NAME";

/// Whether a command line that did not parse also gets [`ARGV_WARNING`] after the fixed parse
/// error ([`crate::usage::parse_error`], architect Q113): any argument holding `secret` in any
/// case, so `secret` and `Secrets` typos count too. A false match only adds the warning.
#[must_use]
pub fn names_secrets(args: &[std::ffi::OsString]) -> bool {
    args.iter().any(|a| {
        a.as_encoded_bytes()
            .windows(b"secret".len())
            .any(|w| w.eq_ignore_ascii_case(b"secret"))
    })
}

/// The longest value typed at the prompt (architect Q114). A canonical-mode terminal line holds
/// at most 4095 bytes and the kernel drops the rest without an error, so a line of 4095 cannot
/// be told from a cut one (probed: PROBE_NOTES). Longer values come on stdin.
pub const TTY_MAX_VALUE_BYTES: usize = 4094;

/// Why no value was read.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ValueError {
    /// Over [`MAX_VALUE_BYTES`].
    #[error("the value is longer than {MAX_VALUE_BYTES} bytes")]
    TooLong,
    /// Not UTF-8.
    #[error("the value is not UTF-8")]
    NotUtf8,
    /// Nothing was entered.
    #[error("no value was given")]
    Empty,
    /// The terminal could not be set up or read; nothing was read with echo on.
    #[error("the terminal: {0}")]
    Terminal(String),
    /// Reading stdin failed.
    #[error("stdin: {0}")]
    Read(String),
    /// The interrupt character (Ctrl-C) was typed at the prompt.
    #[error("cancelled; nothing stored")]
    Cancelled,
    /// Over [`TTY_MAX_VALUE_BYTES`] at the prompt.
    #[error(
        "the value is too long to type at the prompt (over {TTY_MAX_VALUE_BYTES} bytes); pipe it \
         on stdin: `sally secrets set NAME < file`"
    )]
    TooLongForTerminal,
}

impl ValueError {
    /// The exit code (architect Q115): 2 when the terminal or stdin could not be read, 1 when
    /// what was given was refused or the prompt was cancelled.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Terminal(_) | Self::Read(_) => EXIT_FAILED,
            Self::TooLong
            | Self::NotUtf8
            | Self::Empty
            | Self::Cancelled
            | Self::TooLongForTerminal => EXIT_REFUSED,
        }
    }
}

/// Piped input: everything up to EOF (at most [`MAX_VALUE_BYTES`] plus a newline), with one
/// trailing `\n` removed.
///
/// # Errors
/// [`ValueError`].
pub fn read_piped(r: &mut dyn Read) -> Result<Zeroizing<String>, ValueError> {
    let mut buf = Zeroizing::new(Vec::with_capacity(MAX_VALUE_BYTES.saturating_add(2)));
    let cap = u64::try_from(MAX_VALUE_BYTES.saturating_add(2)).unwrap_or(u64::MAX);
    r.take(cap)
        .read_to_end(&mut buf)
        .map_err(|e| ValueError::Read(e.to_string()))?;
    finish(buf)
}

/// One line typed at a terminal (architect Q112, Q114), read a byte at a time into wiped
/// buffers: up to `\n` (removed) or EOF. The `cancel` byte ends it with
/// [`ValueError::Cancelled`]; more than [`TTY_MAX_VALUE_BYTES`] is
/// [`ValueError::TooLongForTerminal`], since the kernel would have cut the line silently.
///
/// # Errors
/// [`ValueError`].
pub fn read_line(r: &mut dyn Read, cancel: Option<u8>) -> Result<Zeroizing<String>, ValueError> {
    let mut buf = Zeroizing::new(Vec::with_capacity(TTY_MAX_VALUE_BYTES.saturating_add(1)));
    let mut byte = Zeroizing::new([0_u8; 1]);
    loop {
        match r.read(&mut *byte) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(ValueError::Read(e.to_string())),
        }
        let [b] = *byte;
        if Some(b) == cancel {
            return Err(ValueError::Cancelled);
        }
        if b == b'\n' {
            break;
        }
        buf.push(b);
        if buf.len() > TTY_MAX_VALUE_BYTES {
            return Err(ValueError::TooLongForTerminal);
        }
    }
    finish(buf)
}

fn finish(mut buf: Zeroizing<Vec<u8>>) -> Result<Zeroizing<String>, ValueError> {
    if buf.last() == Some(&b'\n') {
        buf.pop();
    }
    if buf.len() > MAX_VALUE_BYTES {
        return Err(ValueError::TooLong);
    }
    if buf.is_empty() {
        return Err(ValueError::Empty);
    }
    let bytes = std::mem::take(&mut *buf);
    match String::from_utf8(bytes) {
        Ok(s) => Ok(Zeroizing::new(s)),
        Err(e) => {
            // The rejected bytes are wiped too.
            drop(Zeroizing::new(e.into_bytes()));
            Err(ValueError::NotUtf8)
        }
    }
}

/// One line from the terminal `tty` with echo off, after `prompt` on `err` (architect Q108,
/// Q112). Line editing stays on. The terminal's interrupt character (Ctrl-C) ends the line as a
/// cancel instead of a signal, so echo comes back after it too. On every return the saved
/// settings are restored and unread input is discarded (the rest of a multi-line paste never
/// reaches the shell). If the terminal cannot be set up, nothing is read.
///
/// # Errors
/// [`ValueError`].
pub fn read_terminal(
    tty: &std::fs::File,
    prompt: &str,
    err: &mut dyn Write,
) -> Result<Zeroizing<String>, ValueError> {
    use rustix::termios::{LocalModes, OptionalActions, SpecialCodeIndex, tcgetattr, tcsetattr};
    struct Restore<'a>(&'a std::fs::File, rustix::termios::Termios);
    impl Drop for Restore<'_> {
        fn drop(&mut self) {
            let _ = tcsetattr(self.0, OptionalActions::Flush, &self.1);
        }
    }
    let term = |e: rustix::io::Errno| ValueError::Terminal(e.to_string());
    let saved = tcgetattr(tty).map_err(term)?;
    let mut quiet = saved.clone();
    quiet.local_modes.remove(LocalModes::ECHO);
    // 0 is `_POSIX_VDISABLE` on Linux: no interrupt character, so signals stay as they are.
    let cancel = Some(saved.special_codes[SpecialCodeIndex::VINTR]).filter(|c| *c != 0);
    if let Some(c) = cancel {
        quiet.local_modes.remove(LocalModes::ISIG);
        quiet.special_codes[SpecialCodeIndex::VEOL] = c;
    }
    // Flush: input typed before the prompt (already shown with echo on) is discarded, never
    // taken as the value (as glibc's getpass).
    tcsetattr(tty, OptionalActions::Flush, &quiet).map_err(term)?;
    let _restore = Restore(tty, saved);
    let _ = write!(err, "{prompt}");
    let _ = err.flush();
    let mut reader = tty;
    let value = read_line(&mut reader, cancel);
    let _ = writeln!(err);
    value
}

/// Core dumps off and the process non-dumpable before a plaintext value is read (as `sallyd`'s
/// `process::harden`).
///
/// # Errors
/// The `errno` of the call that failed.
pub fn harden() -> rustix::io::Result<()> {
    let none = rustix::process::Rlimit {
        current: Some(0),
        maximum: Some(0),
    };
    rustix::process::setrlimit(rustix::process::Resource::Core, none)?;
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
}

/// `sally secrets set NAME`: `read` supplies the value (it is called only for a legal name).
pub fn set(
    path: &Path,
    name: &str,
    read: &mut dyn FnMut() -> Result<Zeroizing<String>, ValueError>,
    o: &mut Out<'_>,
) -> u8 {
    if !is_secret_name(name) {
        return usage(o, &SecretsError::InvalidName.to_string());
    }
    let mut value = match read() {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(o.err, "sally: {}", clean::line(&e.to_string()).text);
            return e.exit_code();
        }
    };
    let mut edit = || -> Result<bool, SecretsError> {
        let _lock = SecretStore::lock(path)?;
        let mut store = SecretStore::open(path)?;
        // Moved, not copied: the store owns (and wipes) the one plaintext copy from here.
        let short = store.set(name, std::mem::take(&mut *value))?.short;
        store.save()?;
        Ok(short)
    };
    match edit() {
        Ok(short) => {
            if short {
                let _ = writeln!(
                    o.err,
                    "warning: the value is short; a short value is redacted from responses less \
                     reliably"
                );
            }
            let _ = writeln!(o.err, "{NOT_YET_USED}");
            EXIT_OK
        }
        Err(e) => store_error(o, &e),
    }
}

/// `sally secrets list`: the names, one per line. Takes no lock.
pub fn list(path: &Path, o: &mut Out<'_>) -> u8 {
    match SecretStore::open(path) {
        Ok(store) => {
            for n in store.names() {
                let _ = writeln!(o.out, "{}", clean::line(n).text);
            }
            EXIT_OK
        }
        Err(e) => store_error(o, &e),
    }
}

/// `sally secrets rm NAME`: an absent name is exit 1 with nothing saved.
pub fn rm(path: &Path, name: &str, o: &mut Out<'_>) -> u8 {
    if !is_secret_name(name) {
        return usage(o, &SecretsError::InvalidName.to_string());
    }
    let edit = || -> Result<bool, SecretsError> {
        let _lock = SecretStore::lock(path)?;
        let mut store = SecretStore::open(path)?;
        if !store.remove(name) {
            return Ok(false);
        }
        store.save()?;
        Ok(true)
    };
    match edit() {
        Ok(true) => EXIT_OK,
        Ok(false) => refused(o, "no secret by that name"),
        Err(e) => store_error(o, &e),
    }
}

/// An illegal name may be a value typed where the name goes: the shell-history warning too.
fn usage(o: &mut Out<'_>, msg: &str) -> u8 {
    let _ = writeln!(o.err, "sally: {}\n{ARGV_WARNING}", clean::line(msg).text);
    EXIT_FAILED
}

fn refused(o: &mut Out<'_>, msg: &str) -> u8 {
    let _ = writeln!(o.err, "sally: {}", clean::line(msg).text);
    EXIT_REFUSED
}

/// An invalid value is refused (1); a store that cannot be read or written fails (2).
fn store_error(o: &mut Out<'_>, e: &SecretsError) -> u8 {
    let refusal = matches!(
        e,
        SecretsError::InvalidName | SecretsError::InvalidValue(_) | SecretsError::TooMany
    );
    let _ = writeln!(o.err, "sally: {}", clean::line(&e.to_string()).text);
    if refusal { EXIT_REFUSED } else { EXIT_FAILED }
}

#[cfg(test)]
#[path = "secrets_tests.rs"]
mod tests;
