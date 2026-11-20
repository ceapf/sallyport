//! The launch gate of `sally session start` and `sally sandbox run` (SI-5): a launch sends the
//! text it read once, from a place it checked first, after showing what that text grants.
//!
//! 1. A malformed `--accept-manifest` value fails (2) before anything is read.
//! 2. The manifest's place is inspected (`ManifestPlace`) and the file it resolves to is read
//!    once. That text is validated here as `sally manifest validate` does it; a rejected
//!    manifest prints every diagnostic (1). `sallyd` validates the same text again.
//! 3. A manifest kept inside one of its own `rw` or `brokered` mounts is refused (1).
//! 4. The block (the summary, each warning, each acknowledged risk) is shown on the terminal the
//!    answer is read from when a question follows, and on stderr otherwise. A block line that
//!    fails the clean-check refuses the launch (1), naming the first such line, escaped.
//! 5. A given `--accept-manifest` must name the SHA-256 of the text read (1 otherwise). No
//!    launch output prints the hash of what was read.
//! 6. A manifest with any warning or acknowledged risk needs consent. On a terminal (stdin is
//!    one and `/dev/tty` opens) that is exactly `yes` typed after the question, with typed-ahead
//!    input discarded (if it cannot be, nothing is read: 1), whether or not the flag is given.
//!    Off a terminal it is the flag, and then every mount host must be written as the folder it
//!    resolved to (1 otherwise): the hash names the text, not the folders.
//!
//! TODO(#255): the summary shown comes from this validation, under the CLI's own host facts;
//! `sallyd` launches from its own.

use std::io::{BufRead, Read, Write};
use std::path::Path;

use sally_core::manifest::{HostEnv, ManifestPlace, Validated, summary};
use sally_core::model::hash::{Digest, Hasher};

use crate::approve::Tty;
use crate::commands::read_manifest;
use crate::local::validated_text;
use crate::{EXIT_FAILED, EXIT_REFUSED, clean};

/// The question asked on a terminal.
pub const QUESTION: &str = "Start a session with this manifest? Type yes to start: ";

/// The longest answer read, in bytes; a longer line refuses.
pub const MAX_ANSWER: u64 = 64;

/// What a launch was given besides the manifest's name.
pub struct Gate<'a, 't> {
    /// The secrets store whose names the validation reads.
    pub store: &'a Path,
    /// `--accept-manifest`, as typed.
    pub accept: Option<&'a str>,
    /// The terminal, when stdin is one and `/dev/tty` opened.
    pub terminal: Option<&'a mut Tty<'t>>,
}

/// The text to send for the manifest named `manifest`, once every check passed; otherwise the
/// exit code, with its reason already on `err`.
///
/// # Errors
/// The exit code: 2 for a malformed flag or a manifest that cannot be read or inspected, 1 for
/// a refusal.
pub fn launch_text(manifest: &Path, g: Gate<'_, '_>, err: &mut dyn Write) -> Result<String, u8> {
    let accept = parse_accept(g.accept, err)?;
    let (text, v) = read_checked(manifest, g.store, err)?;
    let lines = block(&v).map_err(|dirty| {
        let _ = writeln!(
            err,
            "sally: the manifest's summary holds text that cannot be shown, first: {dirty}; \
             not started"
        );
        EXIT_REFUSED
    })?;
    let needs = needs_consent(&v);
    let mut terminal = g.terminal.filter(|_| needs);
    {
        let shown: &mut dyn Write = match terminal.as_mut() {
            Some(t) => &mut *t.output,
            None => &mut *err,
        };
        for l in &lines {
            let _ = writeln!(shown, "{l}");
        }
        let _ = shown.flush();
    }
    let matches = accept.map(|d| d == digest(&text));
    match decide(needs, terminal.is_some(), matches) {
        Verdict::Send => Ok(text),
        // TODO(#255): sallyd resolves the hosts again after this check, `~` follows this
        // process's HOME, and a folder replaced at the same path is not seen here. HOME is
        // taken as given: where its own path goes through a link, every `~` host is refused
        // here (write the realpath, or answer on a terminal).
        Verdict::ByHash => {
            let home = HostEnv::from_process().map(|env| env.home).map_err(|e| {
                let _ = writeln!(err, "sally: {}", clean::line(&e.to_string()).text);
                EXIT_FAILED
            })?;
            match v.manifest.check_hosts_as_written(&home) {
                Ok(()) => Ok(text),
                Err(e) => {
                    let _ = writeln!(err, "sally: {}", clean::line(&e.to_string()).text);
                    Err(EXIT_REFUSED)
                }
            }
        }
        Verdict::Ask => {
            if terminal.is_some_and(asked_yes) {
                Ok(text)
            } else {
                let _ = writeln!(err, "sally: not started");
                Err(EXIT_REFUSED)
            }
        }
        Verdict::Mismatch => {
            let _ = writeln!(
                err,
                "sally: the manifest is not the text --accept-manifest names (it changed, or the \
                 hash is another's); review it with `sally manifest summary`"
            );
            Err(EXIT_REFUSED)
        }
        Verdict::NeedsFlag => {
            let _ = writeln!(
                err,
                "sally: this manifest has warnings or acknowledged risks; off a terminal, pass \
                 --accept-manifest with the hash `sally manifest summary` prints last"
            );
            Err(EXIT_REFUSED)
        }
    }
}

/// What a launch does once its block is shown ([`decide`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Send the text.
    Send,
    /// The right hash is the consent: send once each mount host is written as the folder it is
    /// (`check_hosts_as_written`), since the hash names the text, not the folders.
    ByHash,
    /// Ask on the terminal: only `yes` sends.
    Ask,
    /// Refuse: the flag names another text.
    Mismatch,
    /// Refuse: off a terminal, consent is the flag, and none was given.
    NeedsFlag,
}

/// The consent rule, pure: `needs` is [`needs_consent`], `on_terminal` whether the question can
/// be asked, `matches` whether a given `--accept-manifest` names the text read (`None`: not
/// given). A given hash is always checked. A manifest that needs consent is asked on a terminal
/// even with the right hash; off one, the right hash is its consent ([`Verdict::ByHash`]).
#[must_use]
pub fn decide(needs: bool, on_terminal: bool, matches: Option<bool>) -> Verdict {
    match (needs, on_terminal, matches) {
        (_, _, Some(false)) => Verdict::Mismatch,
        (false, _, _) => Verdict::Send,
        (true, true, _) => Verdict::Ask,
        (true, false, Some(true)) => Verdict::ByHash,
        (true, false, None) => Verdict::NeedsFlag,
    }
}

/// `--accept-manifest`, parsed; a malformed value is a fixed text (never echoed) and 2.
fn parse_accept(accept: Option<&str>, err: &mut dyn Write) -> Result<Option<Digest>, u8> {
    match accept.map(Digest::parse) {
        None => Ok(None),
        Some(Ok(d)) => Ok(Some(d)),
        Some(Err(_)) => {
            let _ = writeln!(
                err,
                "sally: --accept-manifest takes the 64 lowercase hex digits that `sally manifest \
                 summary` prints last"
            );
            Err(EXIT_FAILED)
        }
    }
}

/// The manifest's place inspected, its file read once, the text validated and its place
/// checked: the text and its verdict, or the exit code with its reason on `err`.
fn read_checked(
    manifest: &Path,
    store: &Path,
    err: &mut dyn Write,
) -> Result<(String, Validated), u8> {
    let place = ManifestPlace::inspect(manifest).map_err(|e| {
        let _ = writeln!(err, "sally: {}", clean::line(&e.to_string()).text);
        EXIT_FAILED
    })?;
    // TODO(#254): read by path after the inspection; one open by descriptor with a
    // regular-file check and an identity compare comes with the hop-by-hop resolution.
    let text = read_manifest(place.file()).map_err(|e| {
        let msg = clean::line(&format!("{}: {e}", place.file().display())).text;
        let _ = writeln!(err, "sally: {msg}");
        EXIT_FAILED
    })?;
    let v = validated_text(&text, store, err)?;
    if let Err(e) = v.manifest.check_place(&place) {
        let _ = writeln!(err, "sally: {}", clean::line(&e.to_string()).text);
        return Err(EXIT_REFUSED);
    }
    Ok((text, v))
}

/// Whether a launch of `v` needs consent: any warning or acknowledged risk.
#[must_use]
pub fn needs_consent(v: &Validated) -> bool {
    !v.warnings.is_empty() || !v.manifest.acknowledged_risks().is_empty()
}

/// The lines shown after the summary: each warning, then each acknowledged risk.
#[must_use]
pub fn besides_summary(v: &Validated) -> Vec<String> {
    let warned = v.warnings.iter().map(ToString::to_string);
    let acks = v
        .manifest
        .acknowledged_risks()
        .iter()
        .map(|r| format!("acknowledged: {r}"));
    warned.chain(acks).collect()
}

/// The lines shown before a launch of `v`: the summary's, then [`besides_summary`].
///
/// TODO(#257): a manifest whose shown lines hold non-ASCII text, which the spec accepts, cannot
/// be launched from the CLI.
///
/// # Errors
/// The first line that fails the clean-check, escaped (printable ASCII): such a manifest starts
/// nothing, and `sally manifest summary` prints no hash for it.
pub fn block(v: &Validated) -> Result<Vec<String>, String> {
    let s = summary(&v.manifest);
    s.lines()
        .map(ToOwned::to_owned)
        .chain(besides_summary(v))
        .map(|l| {
            let c = clean::line(&l);
            if c.clean { Ok(c.text) } else { Err(c.text) }
        })
        .collect()
}

/// The SHA-256 of `text`, as `--accept-manifest` names it.
#[must_use]
pub fn digest(text: &str) -> Digest {
    let mut h = Hasher::default();
    h.update(text.as_bytes());
    h.finish()
}

/// Asks [`QUESTION`] on `t`, typed-ahead input discarded first: `true` only for a line that is
/// exactly `yes` after trimming. Typed-ahead input that cannot be discarded (nothing is read
/// then), the end of input, a failed read and a line over [`MAX_ANSWER`] bytes are `false`.
/// After any answer but `yes`, what is left of the input is discarded too, so a refused paste
/// does not reach the shell after `sally` exits.
pub fn asked_yes(t: &mut Tty<'_>) -> bool {
    let _ = write!(t.output, "{QUESTION}");
    let _ = t.output.flush();
    let mut line = Vec::new();
    let read = (t.flush)().and_then(|()| {
        (&mut *t.input)
            .take(MAX_ANSWER.saturating_add(1))
            .read_until(b'\n', &mut line)
    });
    let yes = match read {
        Ok(_) if line.ends_with(b"\n") => String::from_utf8(line).is_ok_and(|s| s.trim() == "yes"),
        _ => false,
    };
    if !yes {
        let _ = (t.flush)();
    }
    yes
}

#[cfg(test)]
#[path = "consent_tests.rs"]
mod tests;
