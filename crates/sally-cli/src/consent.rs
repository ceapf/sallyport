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
//!    fails the clean-check refuses the launch (1).
//! 5. A given `--accept-manifest` must name the SHA-256 of the text read (1 otherwise). No
//!    launch output prints the hash of what was read.
//! 6. A manifest with any warning or acknowledged risk needs consent. On a terminal (stdin is
//!    one and `/dev/tty` opens) that is exactly `yes` typed after the question, with typed-ahead
//!    input discarded, whether or not the flag is given. Off a terminal it is the flag.
//!
//! TODO(#255): the summary shown comes from this validation, under the CLI's own host facts;
//! `sallyd` launches from its own.

use std::io::{BufRead, Read, Write};
use std::path::Path;

use sally_core::manifest::{ManifestPlace, Validated, summary};
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
    let accept = match g.accept.map(Digest::parse) {
        None => None,
        Some(Ok(d)) => Some(d),
        Some(Err(_)) => {
            let _ = writeln!(
                err,
                "sally: --accept-manifest takes the 64 lowercase hex digits that `sally manifest \
                 summary` prints last"
            );
            return Err(EXIT_FAILED);
        }
    };
    let place = ManifestPlace::inspect(manifest).map_err(|e| {
        let _ = writeln!(err, "sally: {}", clean::line(&e.to_string()).text);
        EXIT_FAILED
    })?;
    let text = read_manifest(place.file()).map_err(|e| {
        let msg = clean::line(&format!("{}: {e}", place.file().display())).text;
        let _ = writeln!(err, "sally: {msg}");
        EXIT_FAILED
    })?;
    let v = validated_text(&text, g.store, err)?;
    if let Err(e) = v.manifest.check_place(&place) {
        let _ = writeln!(err, "sally: {}", clean::line(&e.to_string()).text);
        return Err(EXIT_REFUSED);
    }
    let Some(lines) = block(&v) else {
        let _ = writeln!(
            err,
            "sally: the manifest's summary holds text that cannot be shown; not started"
        );
        return Err(EXIT_REFUSED);
    };
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
    if accept.as_ref().is_some_and(|d| *d != digest(&text)) {
        let _ = writeln!(
            err,
            "sally: the manifest is not the text --accept-manifest names (it changed, or the \
             hash is another's); review it with `sally manifest summary`"
        );
        return Err(EXIT_REFUSED);
    }
    match (needs, terminal, accept) {
        (false, _, _) | (true, None, Some(_)) => Ok(text),
        (true, Some(t), _) => {
            if asked_yes(t) {
                Ok(text)
            } else {
                let _ = writeln!(err, "sally: not started");
                Err(EXIT_REFUSED)
            }
        }
        (true, None, None) => {
            let _ = writeln!(
                err,
                "sally: this manifest has warnings or acknowledged risks; off a terminal, pass \
                 --accept-manifest with the hash `sally manifest summary` prints last"
            );
            Err(EXIT_REFUSED)
        }
    }
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

/// The lines shown before a launch of `v`: the summary's, then [`besides_summary`]; `None` when
/// any of them fails the clean-check.
#[must_use]
pub fn block(v: &Validated) -> Option<Vec<String>> {
    let s = summary(&v.manifest);
    s.lines()
        .map(ToOwned::to_owned)
        .chain(besides_summary(v))
        .map(|l| {
            let c = clean::line(&l);
            c.clean.then_some(c.text)
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
/// exactly `yes` after trimming. The end of input, a failed read and a line over
/// [`MAX_ANSWER`] bytes are `false`.
pub fn asked_yes(t: &mut Tty<'_>) -> bool {
    let _ = write!(t.output, "{QUESTION}");
    let _ = t.output.flush();
    (t.flush)();
    let mut line = Vec::new();
    let read = (&mut *t.input)
        .take(MAX_ANSWER.saturating_add(1))
        .read_until(b'\n', &mut line);
    match read {
        Ok(_) if line.ends_with(b"\n") => String::from_utf8(line).is_ok_and(|s| s.trim() == "yes"),
        _ => false,
    }
}

#[cfg(test)]
#[path = "consent_tests.rs"]
mod tests;
