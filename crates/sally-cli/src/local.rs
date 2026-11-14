//! The commands that need no daemon (architect Q52, Q109, Q110): `manifest validate|summary`
//! and `audit verify|tail`. They read files of the user's own; nothing here writes.
//!
//! A local manifest verdict is advisory: `sallyd` validates again, against the host facts it
//! read at start, when a session starts.

use std::path::Path;

use sally_core::audit::{HeadStatus, VerifyReport, tail, verify};
use sally_core::manifest::{Code, HostEnv, Rejected, Validated, load, summary};

use crate::commands::{Out, Printer, read_manifest};
use crate::secrets::NOT_YET_USED;
use crate::{EXIT_FAILED, EXIT_OK, EXIT_REFUSED, clean};

/// The default and the most entries `audit tail` prints.
pub const TAIL_DEFAULT: usize = 20;

/// Loads `path` as `sallyd` would today: the CLI's host facts and an empty secrets catalog,
/// because `sallyd` knows no secret names until #99. TODO(#99): both switch to the store's
/// names together.
fn validated(path: &Path, o: &mut Out<'_>) -> Result<Validated, u8> {
    let text = read_manifest(path).map_err(|e| {
        let msg = clean::line(&format!("{}: {e}", path.display())).text;
        let _ = writeln!(o.err, "sally: {msg}");
        EXIT_FAILED
    })?;
    let env = HostEnv::from_process().map_err(|e| {
        let _ = writeln!(o.err, "sally: {}", clean::line(&e.to_string()).text);
        EXIT_FAILED
    })?;
    let none: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    load(&text, &env, &none).map_err(|r| rejected(&r, o))
}

/// Prints every error and warning of a rejected manifest (checked) to `err`.
fn rejected(r: &Rejected, o: &mut Out<'_>) -> u8 {
    for d in r.errors.iter().chain(&r.warnings) {
        let _ = writeln!(o.err, "{}", clean::line(&d.to_string()).text);
    }
    if r.errors.iter().any(|d| d.code == Code::SecretMissing) {
        let _ = writeln!(o.err, "{NOT_YET_USED}");
    }
    EXIT_REFUSED
}

/// `sally manifest validate FILE`: 0 valid (warnings on `err`), 1 rejected, 2 unreadable.
pub fn manifest_validate(path: &Path, o: &mut Out<'_>) -> u8 {
    let v = match validated(path, o) {
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

/// `sally manifest summary FILE`: the plain-English summary of a valid manifest only.
pub fn manifest_summary(path: &Path, o: &mut Out<'_>) -> u8 {
    let v = match validated(path, o) {
        Ok(v) => v,
        Err(code) => return code,
    };
    let mut p = Printer::new(o);
    p.text(&summary(&v.manifest));
    p.code()
}

/// `sally audit verify`: 0 when the chain holds, 1 with the first bad `seq` otherwise.
pub fn audit_verify(dir: &Path, o: &mut Out<'_>) -> u8 {
    match verify(dir) {
        Ok(r) => {
            let _ = writeln!(o.out, "{}", report(&r));
            EXIT_OK
        }
        Err(e) => {
            let _ = writeln!(o.err, "sally: {}", clean::line(&e.to_string()).text);
            EXIT_REFUSED
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
/// 1 when a line in the files read was not an entry, or the log could not be read.
pub fn audit_tail(dir: &Path, n: usize, o: &mut Out<'_>) -> u8 {
    let t = match tail(dir, n) {
        Ok(t) => t,
        Err(e) => {
            let msg = clean::line(&format!("{}: {e}", dir.display())).text;
            let _ = writeln!(o.err, "sally: {msg}");
            return EXIT_REFUSED;
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
