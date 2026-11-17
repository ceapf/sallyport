//! The control methods' wire helpers: refusals and their failure texts, a rejected manifest's
//! error lines, the fitted listings, and the session, change, prompt and decision forms on the
//! wire. The methods themselves are in `control_methods.rs`, which re-exports these; the bounds
//! they apply (`DETAIL_CHARS`, `MAX_ERROR_LINES`) stay there beside the other reply limits.

use sally_core::audit::NewEntry;
use sally_core::text::{Quote, Style, escape_capped};
use sally_proto::{
    Change as WireChange, ChangeKind as WireKind, Decision as WireDecision, ErrorData,
    Prompt as WirePrompt, Session, SessionState as WireState,
};
use serde::Serialize;
use serde_json::Value;

use super::control_methods::{DETAIL_CHARS, MAX_ERROR_LINES};
use crate::approvals::Decision;
use crate::approvals::render::{self, Prompt};
use crate::sandbox::{Change, ChangeKind};
use crate::session::{SessionInfo, SessionState};

pub(crate) fn refusal(reason: &str, detail: Option<String>, errors: Vec<String>) -> ErrorData {
    ErrorData {
        reason: reason.to_owned(),
        detail,
        errors,
    }
}

/// How a refusal's failure text is written: [`escape_capped`]'s format at [`DETAIL_CHARS`].
///
/// The texts declared in it, and their largest raw length (architect Q304, Q305), all under
/// 1276 bytes (4 × `NAME_MAX` + 256):
/// - a stop's failure: fixed text, a `usize` count and one [`SessionId`] (at most 64 bytes);
/// - a listing's failure ([`ChangesError`]'s text): fixed text, the host libc's errno text,
///   numbers from the walk's bounds, a mount index, and at most one `stage/` name escaped four
///   characters a byte (`NAME_MAX`, 255 bytes, so 1020).
///
/// Tested at that size in `control_tests.rs`
/// (`a_refusal_text_at_its_bound_is_masked_before_its_cut`).
///
/// [`SessionId`]: crate::sandbox::SessionId
/// [`ChangesError`]: crate::sandbox::ChangesError
pub const REFUSAL_STYLE: Style = Style::Text {
    max: DETAIL_CHARS,
    quote: Quote::None,
};

/// `entry` with `args` and the failure text `raw` as the arg `key`, declared (architect Q288
/// (8), Q305): no stop or listing failure holds a byte a sandbox chose today, but the text
/// stays declared so that a path a listing names later (TODO(#28)) is masked whole before it
/// is escaped and cut in [`REFUSAL_STYLE`]. The reply carries its own escaped copy: it goes to
/// the host client, not to a log.
pub(crate) fn refusal_entry(
    entry: NewEntry,
    args: Value,
    key: &'static str,
    raw: &str,
) -> NewEntry {
    entry.args(args).text(key, raw, REFUSAL_STYLE)
}

/// A rejected manifest's errors for the reply: each escaped and capped, at most
/// [`MAX_ERROR_LINES`], then one line counting the rest.
pub(crate) fn error_lines(lines: &[String]) -> Vec<String> {
    let mut out: Vec<String> = lines
        .iter()
        .take(MAX_ERROR_LINES)
        .map(|l| escape_capped(l.as_bytes(), DETAIL_CHARS))
        .collect();
    let rest = lines.len().saturating_sub(MAX_ERROR_LINES);
    if rest > 0 {
        out.push(format!("... {rest} more"));
    }
    out
}

/// The leading `items` whose serialized size (plus a separator each) fits `budget`; whether
/// that is all of them; how many there are. Nothing after the first that does not fit is kept,
/// so the kept ones are always a prefix.
pub(crate) fn fit<T: Serialize>(
    items: impl IntoIterator<Item = T>,
    budget: usize,
) -> (Vec<T>, bool, usize) {
    let mut kept = Vec::new();
    let mut used = 0usize;
    let mut total = 0usize;
    let mut complete = true;
    for item in items {
        total = total.saturating_add(1);
        if !complete {
            continue;
        }
        let cost = serde_json::to_vec(&item)
            .map_or(usize::MAX, |v| v.len())
            .saturating_add(1);
        match used.checked_add(cost) {
            Some(n) if n <= budget => {
                used = n;
                kept.push(item);
            }
            _ => complete = false,
        }
    }
    (kept, complete, total)
}

pub(crate) fn value<T: Serialize>(t: &T) -> Value {
    // The wire types are plain structs of strings, numbers and lists: serializing them cannot
    // fail, so the `Null` is never sent.
    serde_json::to_value(t).unwrap_or(Value::Null)
}

pub(crate) fn session(s: &SessionInfo) -> Session {
    Session {
        id: s.id.clone(),
        manifest: s.manifest.clone(),
        container: s.container.clone(),
        state: match s.state {
            SessionState::Running => WireState::Running,
            SessionState::StopFailed => WireState::StopFailed,
        },
        model: s.model.clone(),
    }
}

/// A staged change on the wire: its path escaped at the source (architect Q75).
pub(crate) fn change(c: &Change) -> WireChange {
    use std::os::unix::ffi::OsStrExt as _;
    WireChange {
        mount: c.mount,
        kind: match c.kind {
            ChangeKind::Written => WireKind::Written,
            ChangeKind::Deleted => WireKind::Deleted,
            ChangeKind::Replaced => WireKind::Replaced,
        },
        path: sally_core::text::escape(c.path.as_os_str().as_bytes()),
    }
}

/// A prompt on the wire (architect Q74): the terminal text, and for a cut prompt its full text
/// when it fits the wire, else `full_unavailable` (the prompt can then only be denied;
/// TODO(#108): a way to review and approve such an action).
pub(crate) fn prompt(p: &Prompt) -> WirePrompt {
    let full = if p.truncated { p.full_on_wire() } else { None };
    WirePrompt {
        id: p.id.clone(),
        session: p.session.clone(),
        digest: p.digest.clone(),
        truncated: p.truncated,
        text: render::terminal(p),
        full: full.map(str::to_owned),
        full_unavailable: p.truncated && full.is_none(),
    }
}

pub(super) fn decision(d: WireDecision) -> Decision {
    match d {
        WireDecision::Approve => Decision::Approve,
        WireDecision::Deny => Decision::Deny,
        WireDecision::DenyAllSession => Decision::DenyAllSession,
    }
}
