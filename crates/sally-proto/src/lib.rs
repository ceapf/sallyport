//! Shared JSON-RPC request/response types for `sallyd` clients.
//!
//! The control socket's wire types (ARCHITECTURE §4.1; architect Q78): params, results and
//! notifications, shared by `sallyd` and the `sally` CLI. Types only, no logic. Every params
//! type refuses unknown fields, so a field the daemon does not know (a `client`, a `model` before
//! PR C) is `invalid-params`, never ignored. Text a sandbox chose (paths, prompt text) arrives
//! already escaped by `sallyd`; a client still checks it before printing.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};

/// The control methods, exactly what `control.sock` serves (architect Q72).
pub mod method {
    /// Start a session from a manifest's text.
    pub const SESSIONS_CREATE: &str = "sessions.create";
    /// The live sessions.
    pub const SESSIONS_LIST: &str = "sessions.list";
    /// Stop a session.
    pub const SESSIONS_STOP: &str = "sessions.stop";
    /// A session's staged changes, live or stopped.
    pub const SESSIONS_CHANGES: &str = "sessions.changes";
    /// The prompts waiting for an answer.
    pub const APPROVALS_LIST: &str = "approvals.list";
    /// Answer one prompt.
    pub const APPROVALS_DECIDE: &str = "approvals.decide";
    /// Attach this connection as an approver.
    pub const APPROVALS_WATCH: &str = "approvals.watch";
    /// Every method, in the order above.
    pub const ALL: [&str; 7] = [
        SESSIONS_CREATE,
        SESSIONS_LIST,
        SESSIONS_STOP,
        SESSIONS_CHANGES,
        APPROVALS_LIST,
        APPROVALS_DECIDE,
        APPROVALS_WATCH,
    ];
}

/// The notifications a watching connection receives.
pub mod notification {
    /// A prompt is waiting: params [`Prompt`](super::Prompt).
    pub const APPROVAL_REQUESTED: &str = "approval.requested";
    /// A session started a flood episode: params [`Flood`](super::Flood).
    pub const APPROVAL_FLOOD: &str = "approval.flood";
    /// A shown prompt is gone: params [`Closed`](super::Closed).
    pub const APPROVAL_CLOSED: &str = "approval.closed";
}

/// `sessions.create` params.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateParams {
    /// The manifest's YAML text (its host paths are absolute or `~`-prefixed).
    pub manifest: String,
}

/// `sessions.stop` and `sessions.changes` params.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionParams {
    /// The session id.
    pub id: String,
}

/// Params of a method that takes none (`sessions.list`, `approvals.list`, `approvals.watch`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoParams {}

/// A human's answer (ARCHITECTURE §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// Run this one action, once.
    Approve,
    /// Deny this one action.
    Deny,
    /// Deny this one, every pending one and every later prompt of the session.
    DenyAllSession,
}

/// `approvals.decide` params. The deciding client is read from the socket, never sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecideParams {
    /// The prompt's id.
    pub id: String,
    /// The answer.
    pub decision: Decision,
    /// The digest of the prompt shown; an approve with another is refused.
    pub digest: String,
    /// The full text of a cut prompt was shown; an approve of a cut prompt needs it.
    #[serde(default)]
    pub full_shown: bool,
}

/// Where a session is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SessionState {
    /// Started and not yet stopping.
    Running,
    /// Its container could not be confirmed gone; a stop retries.
    StopFailed,
}

/// A live session (`sessions.create` result, `sessions.list` entries).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    /// The session id.
    pub id: String,
    /// The manifest's `name`.
    pub manifest: String,
    /// The workspace container's name.
    pub container: String,
    /// Where it is.
    pub state: SessionState,
}

/// `sessions.list` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sessions {
    /// The live sessions, by id.
    pub sessions: Vec<Session>,
}

/// `sessions.stop` result: the container is gone and the session released.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stopped {
    /// The session id.
    pub id: String,
}

/// What happened to one staged path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    /// Created or modified.
    Written,
    /// Deleted.
    Deleted,
    /// A directory replaced as a whole.
    Replaced,
}

/// One staged change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    /// Manifest index of the staged mount (`filesystem.mounts[n]`).
    pub mount: usize,
    /// What happened.
    pub kind: ChangeKind,
    /// The path relative to the mount, escaped by `sallyd` (printable ASCII; `\` as `\\`).
    pub path: String,
}

/// `sessions.changes` result (architect Q75).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Changes {
    /// The changes listed, by mount, then path.
    pub changes: Vec<Change>,
    /// Whether `changes` holds every change; `false` when the reply's byte budget cut it.
    pub complete: bool,
    /// How many changes the session has, listed or not.
    pub total: usize,
}

/// One approval prompt as a client shows it (`approval.requested` params, `approvals.list`
/// and `approvals.watch` entries; architect Q74).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prompt {
    /// The approval id (single use).
    pub id: String,
    /// The session.
    pub session: String,
    /// The digest an approve must name.
    pub digest: String,
    /// Whether the action text in `text` was cut.
    pub truncated: bool,
    /// The broker-built prompt, for a terminal: escaped ASCII lines.
    pub text: String,
    /// The full action text, sent only for a cut prompt and only up to the wire cap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full: Option<String>,
    /// The cut prompt's full text is over the wire cap: it can only be denied.
    #[serde(default, skip_serializing_if = "is_false")]
    pub full_unavailable: bool,
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's skip_serializing_if passes a reference.
fn is_false(b: &bool) -> bool {
    !*b
}

/// `approvals.list` and `approvals.watch` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prompts {
    /// The prompts waiting, oldest first.
    pub prompts: Vec<Prompt>,
}

/// `approval.flood` params.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Flood {
    /// The session.
    pub session: String,
}

/// `approval.closed` params.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Closed {
    /// The prompt that is gone.
    pub id: String,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use serde_json::{from_value, json, to_value};

    #[test]
    fn params_refuse_unknown_fields() {
        assert!(from_value::<CreateParams>(json!({"manifest": "x", "model": "m"})).is_err());
        assert!(from_value::<SessionParams>(json!({"id": "a", "x": 1})).is_err());
        assert!(from_value::<NoParams>(json!({"x": 1})).is_err());
        let client = json!({"id": "a", "decision": "approve", "digest": "d", "client": {}});
        assert!(from_value::<DecideParams>(client).is_err());
    }

    #[test]
    fn decide_params_in_wire_form() {
        let p: DecideParams =
            from_value(json!({"id": "a", "decision": "deny_all_session", "digest": "d"})).unwrap();
        assert_eq!(p.decision, Decision::DenyAllSession);
        assert!(!p.full_shown);
        assert!(from_value::<DecideParams>(json!({"id": "a", "decision": "allow"})).is_err());
    }

    #[test]
    fn results_in_wire_form() {
        let s = Session {
            id: "s1".into(),
            manifest: "m".into(),
            container: "sp-w-s1".into(),
            state: SessionState::StopFailed,
        };
        assert_eq!(to_value(&s).unwrap()["state"], "stop-failed");
        let c = Change {
            mount: 0,
            kind: ChangeKind::Replaced,
            path: "a\\x0ab".into(),
        };
        assert_eq!(
            to_value(&c).unwrap(),
            json!({"mount": 0, "kind": "replaced", "path": "a\\x0ab"})
        );
        let whole = Prompt {
            id: "p".into(),
            session: "s1".into(),
            digest: "d".into(),
            truncated: false,
            text: "t".into(),
            full: None,
            full_unavailable: false,
        };
        let v = to_value(&whole).unwrap();
        assert!(v.get("full").is_none() && v.get("full_unavailable").is_none());
        let deny_only = Prompt {
            truncated: true,
            full_unavailable: true,
            ..whole
        };
        assert_eq!(to_value(&deny_only).unwrap()["full_unavailable"], true);
    }

    #[test]
    fn the_method_list_is_the_seven_names() {
        assert_eq!(
            method::ALL,
            [
                "sessions.create",
                "sessions.list",
                "sessions.stop",
                "sessions.changes",
                "approvals.list",
                "approvals.decide",
                "approvals.watch",
            ]
        );
    }
}
