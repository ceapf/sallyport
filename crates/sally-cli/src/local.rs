//! The commands that need no daemon (architect Q52, Q109, Q110): `manifest validate|summary`
//! and `audit verify|tail`. They read files of the user's own (the secrets store's names too,
//! when a manifest names a secret); nothing here writes.
//!
//! A local manifest verdict is advisory for `manifest validate|summary`: `sallyd` validates
//! again, against the host facts it read at start, when a session starts. At a launch the same
//! validation ([`validated_text`]) is a gate that can only refuse ([`crate::consent`]).

use std::path::Path;

use sally_core::audit::{HeadStatus, VerifyErrorKind, VerifyReport, tail, verify};
use sally_core::manifest::{HostEnv, Rejected, Validated, load, summary};
use sally_core::secrets::StoreNames;

use crate::commands::{Out, Printer, read_manifest};
use crate::consent;
use crate::{EXIT_FAILED, EXIT_OK, EXIT_REFUSED, clean};

/// The default and the most entries `audit tail` prints.
pub const TAIL_DEFAULT: usize = 20;

/// Loads `path` as `sallyd` does: the CLI's host facts and the names in the secrets store at
/// `store`, read through the same catalog type, only if the manifest names a secret (architect
/// Q221). A store that cannot be read is a failure to read (2), never a missing name.
fn validated(path: &Path, store: &Path, o: &mut Out<'_>) -> Result<(String, Validated), u8> {
    let text = read_manifest(path).map_err(|e| {
        let msg = clean::line(&format!("{}: {e}", path.display())).text;
        let _ = writeln!(o.err, "sally: {msg}");
        EXIT_FAILED
    })?;
    let v = validated_text(&text, store, o.err)?;
    Ok((text, v))
}

/// Validates `text` as [`validated`] does, its reasons on `err`: rejected 1, the host facts or
/// the store unreadable 2. A launch calls it on the text it read once.
pub(crate) fn validated_text(
    text: &str,
    store: &Path,
    err: &mut dyn std::io::Write,
) -> Result<Validated, u8> {
    let env = HostEnv::from_process().map_err(|e| {
        let _ = writeln!(err, "sally: {}", clean::line(&e.to_string()).text);
        EXIT_FAILED
    })?;
    let names = StoreNames::new(store.to_owned());
    let verdict = load(text, &env, &names);
    if let Some(e) = names.failed() {
        let _ = writeln!(err, "sally: {}", clean::line(&e.to_string()).text);
        return Err(EXIT_FAILED);
    }
    verdict.map_err(|r| rejected(&r, err))
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
/// instead when one of them fails the clean-check), 1 rejected (errors and warnings on `err`), 2
/// unreadable (the manifest, the host facts, or the secrets store at `store` when the manifest
/// names a secret).
pub fn manifest_validate(path: &Path, store: &Path, o: &mut Out<'_>) -> u8 {
    let (_, v) = match validated(path, store, o) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let mut p = Printer::new(o);
    for w in &v.warnings {
        p.line(&[&w.to_string()]);
    }
    p.line(&["valid (sallyd checks again when a session starts)"]);
    p.code()
}

/// `sally manifest summary FILE`: the plain-English summary of a valid manifest only, validated
/// against the secrets store at `store` as `manifest validate` is, then a last line
/// `sha256 <hex>`: the hash of the text read, which a launch's `--accept-manifest` names. The
/// warnings and acknowledged risks a launch shows go to `err`, so a review sees everything the
/// hash accepts, and so does a mount host not written as the folder it is (a launch accepted by
/// the hash alone refuses it). A manifest whose launch block holds a line that cannot be shown
/// starts nothing: no hash for it, and 1.
pub fn manifest_summary(path: &Path, store: &Path, o: &mut Out<'_>) -> u8 {
    let (text, v) = match validated(path, store, o) {
        Ok(v) => v,
        Err(code) => return code,
    };
    for l in consent::besides_summary(&v) {
        let _ = writeln!(o.err, "{}", clean::line(&l).text);
    }
    if let Err(e) = HostEnv::from_process()
        .map_err(|e| e.to_string())
        .and_then(|env| {
            v.manifest
                .check_hosts_as_written(&env.home)
                .map_err(|e| e.to_string())
        })
    {
        let _ = writeln!(o.err, "{}", clean::line(&e).text);
    }
    let shown = consent::block(&v);
    let mut p = Printer::new(o);
    p.text(&summary(&v.manifest));
    match shown {
        Ok(_) => {
            p.line(&["sha256 ", consent::digest(&text).as_hex()]);
            p.code()
        }
        Err(dirty) => {
            let _ = writeln!(
                p.o.err,
                "sally: a launch cannot show this line, so it starts nothing: {dirty}"
            );
            EXIT_REFUSED
        }
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
