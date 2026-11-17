//! The audit fields of the queue's entries: the bounded action [`Fields`] of a bound action
//! (architect rulings Q24, Q288, Q291), the `tool.deny` of a call that is no action, and the
//! deciding client as audited.

use std::sync::Arc;

use sally_core::audit::{NewEntry, Piece};
use serde_json::{Value, json};

use super::Client;
use crate::approvals::action::Bound;
use crate::approvals::render;
use crate::rpc::record::SHORT_STYLE;

/// Characters of action text in an audit entry: escaped ASCII doubles at most in JSON, so the
/// entry stays under the writer's 4 KiB (architect ruling Q24).
pub const AUDIT_ACTION_CHARS: usize = 1024;

/// The bounded action fields of an audit entry (architect rulings Q24, Q288), from a bound
/// action; the tools' own entries (`tool.run`, `tool.read`, `tool.result`) start from them too.
/// The call and the digest are plain args; the tool's name and the action are declared texts,
/// kept raw until the writer masks every raw part whole, then cuts and escapes the name in
/// [`SHORT_STYLE`] and escapes, assembles and cuts the action at [`AUDIT_ACTION_CHARS`].
#[derive(Clone)]
pub(crate) struct Fields {
    /// The plain args (`call`, `action_sha256`); a caller adds its own beside them.
    pub(crate) args: Value,
    tool: Arc<str>,
    pieces: Vec<Piece>,
}

impl Fields {
    /// The fields of `b`.
    pub(crate) fn of(b: &Bound) -> Self {
        Self {
            args: json!({"call": b.call, "action_sha256": b.digest()}),
            tool: Arc::from(b.action.tool()),
            pieces: render::action_pieces(&b.action),
        }
    }

    /// `entry` with these fields: the args, the declared tool and the declared action.
    pub(crate) fn on(self, entry: NewEntry) -> NewEntry {
        entry
            .args(self.args)
            .text("tool", self.tool, SHORT_STYLE)
            .pieces("action", self.pieces, AUDIT_ACTION_CHARS)
    }
}

/// The `tool.deny` of a call the executor could not turn into an action: the tool's name is
/// the harness's, so it is declared (architect Q288 f, Q291) and masked before its cut.
pub(super) fn call_denied(entry: NewEntry, call: u64, tool: &str, code: &str) -> NewEntry {
    entry
        .args(json!({"call": call, "code": code}))
        .text("tool", tool, SHORT_STYLE)
}

pub(super) fn add(v: &mut Value, key: &str, value: Value) {
    if let Some(o) = v.as_object_mut() {
        o.insert(key.to_owned(), value);
    }
}

/// A deciding client as audited: `{uid, pid}`.
pub(crate) fn who(c: Client) -> Value {
    json!({"uid": c.uid, "pid": c.pid})
}
