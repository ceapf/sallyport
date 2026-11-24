//! The commands that need no daemon (architect Q52, Q109, Q110): `manifest validate|summary`
//! and `audit verify|tail`. They read files of the user's own (the secrets store's names too,
//! when a manifest names a secret); nothing here writes.
//!
//! A local manifest verdict is advisory for `manifest validate|summary`: `sallyd` validates
//! again, against the host facts it read at start, when a session starts. At a launch the same
//! validation ([`validated_text`]) is a gate that can only refuse ([`crate::consent`]).

use std::path::Path;

use sally_core::audit::{HeadStatus, VerifyErrorKind, VerifyReport, tail, verify};
use sally_core::config::read_config;
use sally_core::manifest::{HostEnv, Rejected, Validated, load, summary};
use sally_core::secrets::StoreNames;

use crate::commands::{Out, Printer, read_manifest};
use crate::consent;
use crate::{EXIT_FAILED, EXIT_OK, EXIT_REFUSED, clean};

/// The default and the most entries `audit tail` prints.
pub const TAIL_DEFAULT: usize = 20;

/// The user's own files a local validation reads besides the manifest.
#[derive(Debug, Clone, Copy)]
pub struct Files<'a> {
    /// The secrets store, for its names.
    pub store: &'a Path,
    /// `config.toml`, for the binaries it names (their folders are denylist rules).
    pub config: &'a Path,
}

/// Loads `path` as `sallyd` does: the CLI's host facts and the names in the secrets store,
/// read through the same catalog type, only if the manifest names a secret (architect Q221). A
/// store that cannot be read is a failure to read (2), never a missing name.
fn validated(
    path: &Path,
    files: Files<'_>,
    o: &mut Out<'_>,
) -> Result<(String, Validated, HostEnv), u8> {
    let text = read_manifest(path).map_err(|e| {
        let msg = clean::line(&format!("{}: {e}", path.display())).text;
        let _ = writeln!(o.err, "sally: {msg}");
        EXIT_FAILED
    })?;
    let (v, env) = validated_text(&text, files, o.err)?;
    Ok((text, v, env))
}

/// Validates `text` as [`validated`] does, its reasons on `err`: rejected 1; the host facts,
/// `config.toml` or the store unreadable 2. Returns the host facts it validated under, read
/// once. A launch calls it on the text it read once, before anything is shown.
pub(crate) fn validated_text(
    text: &str,
    files: Files<'_>,
    err: &mut dyn std::io::Write,
) -> Result<(Validated, HostEnv), u8> {
    let fail = |e: &dyn std::fmt::Display, err: &mut dyn std::io::Write| {
        let _ = writeln!(err, "sally: {}", clean::line(&e.to_string()).text);
        EXIT_FAILED
    };
    // The file sallyd reads at its start, through the same reader. TODO(#255): sallyd's copy
    // is read at another time, so a folder rule may differ (it only ever adds a refusal).
    let config = read_config(files.config).map_err(|e| fail(&e, err))?;
    let env = HostEnv::from_process(&config).map_err(|e| fail(&e, err))?;
    let names = StoreNames::new(files.store.to_owned());
    let verdict = load(text, &env, &names);
    if let Some(e) = names.failed() {
        return Err(fail(&e, err));
    }
    verdict.map(|v| (v, env)).map_err(|r| rejected(&r, err))
}

/// Prints every error and warning of a rejected manifest (checked) to `err`. A missing secret's
/// error names the `sally secrets set` line that stores it.
fn rejected(r: &Rejected, err: &mut dyn std::io::Write) -> u8 {
    for d in r.errors.iter().chain(&r.warnings) {
        let _ = writeln!(err, "{}", clean::line(&d.to_string()).text);
    }
    EXIT_REFUSED
}

/// `sally manifest validate FILE`: 0 valid (its warnings, then the `valid` line, on `out`; 1
/// instead when one of them fails the clean-check, or when a launch could not show its block,
/// which [`unshowable`] names on `err`), 1 rejected (errors and warnings on `err`), 2
/// unreadable (the manifest, the host facts, `config.toml`, or the secrets store when the
/// manifest names a secret).
pub fn manifest_validate(path: &Path, files: Files<'_>, o: &mut Out<'_>) -> u8 {
    let (_, v, _) = match validated(path, files, o) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let mut p = Printer::new(o);
    for w in &v.warnings {
        p.line(&[&w.to_string()]);
    }
    p.line(&["valid (sallyd checks again when a session starts)"]);
    match consent::block(&v) {
        Ok(_) => p.code(),
        Err(dirty) => unshowable(p.o.err, &dirty),
    }
}

/// Says on `err` that a launch cannot show `dirty` (a line of its block, escaped, with the
/// reason), so it starts nothing; 1.
fn unshowable(err: &mut dyn std::io::Write, dirty: &str) -> u8 {
    let _ = writeln!(
        err,
        "sally: a launch cannot show this line, so it starts nothing: {dirty}"
    );
    EXIT_REFUSED
}

/// `sally manifest summary FILE`: the plain-English summary of a valid manifest only, validated
/// against the same files as `manifest validate` is, then a last line
/// `sha256 <hex>`: the hash of the text read, which a launch's `--accept-manifest` names. The
/// warnings and acknowledged risks a launch shows go to `err`, so a review sees everything the
/// hash accepts, and so does a mount host not written as the folder it is (a launch accepted by
/// the hash alone refuses it). A manifest whose launch block holds a line that cannot be shown
/// starts nothing: no hash for it, and 1.
pub fn manifest_summary(path: &Path, files: Files<'_>, o: &mut Out<'_>) -> u8 {
    let (text, v, env) = match validated(path, files, o) {
        Ok(v) => v,
        Err(code) => return code,
    };
    for l in consent::besides_summary(&v) {
        let _ = writeln!(o.err, "{}", clean::line(&l).text);
    }
    if let Err(e) = v.manifest.check_hosts_as_written(&env.home) {
        let _ = writeln!(o.err, "{}", clean::line(&e.to_string()).text);
    }
    let shown = consent::block(&v);
    let mut p = Printer::new(o);
    p.text(&summary(&v.manifest));
    match shown {
        Ok(_) => {
            p.line(&["sha256 ", consent::digest(&text).as_hex()]);
            p.code()
        }
        Err(dirty) => unshowable(p.o.err, &dirty),
    }
}

/// `sally audit verify` (architect Q115): 0 verified; 1 the log failed verification (the first
/// bad `seq` is named); 2 the log could not be read (a missing directory, a file that cannot be
/// opened, or one replaced by a directory or symlink). Scripts treat any non-zero as not
/// verified.
pub fn audit_verify(dir: &Path, o: &mut Out<'_>) -> u8 {
    match verify(dir) {
        Ok(r) => {
            let _ = writeln!(o.out, "{}", report(&r));
            EXIT_OK
        }
        Err(e) => {
            let _ = writeln!(o.err, "sally: {}", clean::line(&e.to_string()).text);
            if e.kind == VerifyErrorKind::Unreadable {
                EXIT_FAILED
            } else {
                EXIT_REFUSED
            }
        }
    }
}

fn report(r: &VerifyReport) -> String {
    let head = match r.head {
        HeadStatus::Current => "current",
        HeadStatus::LogAhead => "behind the log (an append in flight)",
        HeadStatus::Absent => "absent",
    };
    let torn = if r.torn_tail {
        "; an unterminated last line was ignored"
    } else {
        ""
    };
    format!(
        "ok: {} entries in {} file(s), last seq {}, head {head}{torn}",
        r.entries, r.files, r.last_seq
    )
}

/// `sally audit tail [-n N]`: the newest entries, one line each, escaped (it does not verify).
/// TODO(#120): `--follow` across rotation, and `--session`/`--event` filters.
/// 1 when a line in the files read was not an entry; 2 when the log could not be read
/// (architect Q115).
pub fn audit_tail(dir: &Path, n: usize, o: &mut Out<'_>) -> u8 {
    let t = match tail(dir, n) {
        Ok(t) => t,
        Err(e) => {
            let _ = writeln!(o.err, "sally: {}", clean::line(&e.to_string()).text);
            return EXIT_FAILED;
        }
    };
    for l in &t.lines {
        // Escaped, not clean-checked: these bytes come from disk, not from a reply `sallyd`
        // promised clean, so an escape here is no sign of a fault and does not change the code.
        let _ = writeln!(o.out, "{}", sally_core::text::escape(l.as_bytes()));
    }
    if t.unparsed > 0 {
        let _ = writeln!(
            o.err,
            "sally: {} line(s) are not audit entries and were not shown; run `sally audit \
             verify`",
            t.unparsed
        );
        return EXIT_REFUSED;
    }
    EXIT_OK
}

#[cfg(test)]
#[path = "local_tests.rs"]
mod tests;
