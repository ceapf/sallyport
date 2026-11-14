//! The commands besides `approve`: one call each, its result printed after the clean-check.
//! Each returns the process's exit code ([`EXIT_OK`](crate::EXIT_OK) and the others).

use std::io::{Read as _, Write};
use std::path::Path;

use sally_core::manifest::MAX_MANIFEST_BYTES;
use sally_proto::{Changes, ErrorData, Prompts, Session, SessionState, Sessions, Stopped, method};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::clean;
use crate::client::{Client, Error};
use crate::{EXIT_FAILED, EXIT_OK, EXIT_REFUSED};

/// Where a command prints: results to `out`, everything else to `err`.
pub struct Out<'a> {
    /// Standard output.
    pub out: &'a mut dyn Write,
    /// Standard error.
    pub err: &'a mut dyn Write,
}

/// Collects what a command printed and whether all of it passed the clean-check.
pub(crate) struct Printer<'a, 'b> {
    pub(crate) o: &'a mut Out<'b>,
    dirty: bool,
}

impl<'a, 'b> Printer<'a, 'b> {
    pub(crate) fn new(o: &'a mut Out<'b>) -> Self {
        Self { o, dirty: false }
    }

    /// One line built from `parts`, each checked.
    pub(crate) fn line(&mut self, parts: &[&str]) {
        let mut s = String::new();
        for p in parts {
            let c = clean::line(p);
            self.dirty |= !c.clean;
            s.push_str(&c.text);
        }
        let _ = writeln!(self.o.out, "{s}");
    }

    /// Multi-line text, checked.
    pub(crate) fn text(&mut self, t: &str) {
        let c = clean::text(t);
        self.dirty |= !c.clean;
        let _ = write!(self.o.out, "{}", c.text);
        if !c.text.ends_with('\n') {
            let _ = writeln!(self.o.out);
        }
    }

    /// `EXIT_OK`, or `EXIT_REFUSED` when something printed was not clean.
    pub(crate) fn code(&self) -> u8 {
        if self.dirty { EXIT_REFUSED } else { EXIT_OK }
    }
}

/// Prints a failed call to `err`: the reason, its detail and a rejected manifest's errors, each
/// checked. The exit code for it.
pub fn failed(e: &Error, err: &mut dyn Write) -> u8 {
    match e {
        Error::Refused(data) => {
            print_refusal(data, err);
            EXIT_REFUSED
        }
        other => {
            let msg = clean::line(&other.to_string()).text;
            let _ = writeln!(err, "sally: {msg}");
            EXIT_FAILED
        }
    }
}

fn print_refusal(d: &ErrorData, err: &mut dyn Write) {
    let reason = clean::line(&d.reason).text;
    match &d.detail {
        Some(detail) => {
            let detail = clean::line(detail).text;
            let _ = writeln!(err, "sally: refused: {reason}: {detail}");
        }
        None => {
            let _ = writeln!(err, "sally: refused: {reason}");
        }
    }
    for e in &d.errors {
        let _ = writeln!(err, "  {}", clean::line(e).text);
    }
}

/// Calls `method` and decodes its result as `T`.
fn call<T: DeserializeOwned>(c: &mut Client, method: &str, params: Value) -> Result<T, Error> {
    let v = c.call(method, params)?;
    serde_json::from_value(v).map_err(|_| Error::Unexpected)
}

fn session_line(p: &mut Printer<'_, '_>, s: &Session) {
    let state = match s.state {
        SessionState::Running => "running",
        SessionState::StopFailed => "stop-failed",
    };
    p.line(&[&s.id, "  ", state, "  ", &s.manifest, "  ", &s.container]);
}

/// `sally session start <manifest>`: sends the manifest's text; prints the session.
pub fn session_start(c: &mut Client, manifest: &Path, o: &mut Out<'_>) -> u8 {
    let text = match read_manifest(manifest) {
        Ok(t) => t,
        Err(msg) => {
            let _ = writeln!(
                o.err,
                "sally: {}: {}",
                clean::line(&manifest.display().to_string()).text,
                msg
            );
            return EXIT_FAILED;
        }
    };
    match call::<Session>(c, method::SESSIONS_CREATE, json!({"manifest": text})) {
        Ok(s) => {
            let mut p = Printer::new(o);
            session_line(&mut p, &s);
            p.code()
        }
        Err(e) => failed(&e, o.err),
    }
}

/// The manifest's text, at most [`MAX_MANIFEST_BYTES`].
pub(crate) fn read_manifest(path: &Path) -> Result<String, String> {
    let f = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let cap = u64::try_from(MAX_MANIFEST_BYTES)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::new();
    f.take(cap)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(format!("larger than {MAX_MANIFEST_BYTES} bytes"));
    }
    String::from_utf8(bytes).map_err(|_| "not UTF-8".to_owned())
}

/// `sally session list`.
pub fn session_list(c: &mut Client, o: &mut Out<'_>) -> u8 {
    match call::<Sessions>(c, method::SESSIONS_LIST, json!({})) {
        Ok(all) => {
            let mut p = Printer::new(o);
            for s in &all.sessions {
                session_line(&mut p, s);
            }
            p.code()
        }
        Err(e) => failed(&e, o.err),
    }
}

/// `sally session stop <id>`.
pub fn session_stop(c: &mut Client, id: &str, o: &mut Out<'_>) -> u8 {
    match call::<Stopped>(c, method::SESSIONS_STOP, json!({"id": id})) {
        Ok(s) => {
            let mut p = Printer::new(o);
            p.line(&["stopped ", &s.id]);
            p.code()
        }
        Err(e) => failed(&e, o.err),
    }
}

/// `sally session changes <id>`: `<kind> mounts[<n>] <path>` per change (architect Q75); a cut
/// list ends with a line naming how many are not shown, and exits non-zero.
pub fn session_changes(c: &mut Client, id: &str, o: &mut Out<'_>) -> u8 {
    let all = match call::<Changes>(c, method::SESSIONS_CHANGES, json!({"id": id})) {
        Ok(all) => all,
        Err(e) => return failed(&e, o.err),
    };
    let mut p = Printer::new(o);
    for ch in &all.changes {
        let kind = match ch.kind {
            sally_proto::ChangeKind::Written => "written",
            sally_proto::ChangeKind::Deleted => "deleted",
            sally_proto::ChangeKind::Replaced => "replaced",
        };
        let mount = format!(" mounts[{}] ", ch.mount);
        p.line(&[kind, &mount, &ch.path]);
    }
    let code = p.code();
    if all.complete {
        return code;
    }
    let rest = all.total.saturating_sub(all.changes.len());
    let _ = writeln!(p.o.out, "{rest} changes not shown");
    EXIT_REFUSED
}

/// `sally approvals`: every waiting prompt, as the approver would show it.
pub fn approvals(c: &mut Client, o: &mut Out<'_>) -> u8 {
    let all = match call::<Prompts>(c, method::APPROVALS_LIST, json!({})) {
        Ok(all) => all,
        Err(e) => return failed(&e, o.err),
    };
    let mut p = Printer::new(o);
    for prompt in &all.prompts {
        p.text(&prompt.text);
    }
    let code = p.code();
    if all.complete {
        return code;
    }
    let rest = all.total.saturating_sub(all.prompts.len());
    let _ = writeln!(
        p.o.out,
        "{rest} more pending not shown; list again after answering these"
    );
    EXIT_REFUSED
}
