//! Shared JSON-RPC request/response types for `sallyd` clients.
//!
//! The control socket's wire types (ARCHITECTURE §4.1; architect Q78): params, results and
//! notifications, shared by `sallyd` and the `sally` CLI. Types only, no logic. Every params
//! type refuses unknown fields, so a field the daemon does not know (a `client`, a `model` before
//! PR C) is `invalid-params`, never ignored. Text a sandbox chose (paths, prompt text) arrives
//! already escaped by `sallyd`; a client still checks it before printing.
//!
//! TODO(#109): TypeScript types for the M5 UI bridge, generated from these with ts-rs.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};

/// Largest frame either side of `control.sock` reads (ARCHITECTURE §4: 1 MiB). `sallyd` refuses
/// a longer request; a client treats a longer reply or notification as fatal (architect Q78).
pub const MAX_FRAME: usize = 1024 * 1024;

/// Bytes of a model script at most (architect Q103). `sallyd` refuses a longer one; the CLI
/// does not send it.
pub const MAX_SCRIPT_BYTES: usize = 256 * 1024;

/// Turns of a model script at most: a driven session answers at most this many steps with a
/// turn, then one `end` step.
pub const MAX_TURNS: usize = 1024;

/// Strings of an attach's argv at most (architect Q101); at least one.
pub const MAX_ARGV: usize = 256;

/// Bytes of one `sessions.input` at most (architect Q101).
pub const MAX_INPUT_BYTES: usize = 64 * 1024;

/// Bytes of sandbox output, before escaping, in one `session.output` at most (architect Q101).
pub const MAX_OUTPUT_CHUNK: usize = 16 * 1024;

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
    /// Run the next scripted turn of a driven session.
    pub const SESSIONS_DRIVE: &str = "sessions.drive";
    /// Run a command in a session's workspace, its output streamed to this connection.
    pub const SESSIONS_ATTACH: &str = "sessions.attach";
    /// Write to the standard input of this connection's attached command.
    pub const SESSIONS_INPUT: &str = "sessions.input";
    /// The prompts waiting for an answer.
    pub const APPROVALS_LIST: &str = "approvals.list";
    /// Answer one prompt.
    pub const APPROVALS_DECIDE: &str = "approvals.decide";
    /// Attach this connection as an approver.
    pub const APPROVALS_WATCH: &str = "approvals.watch";
    /// Every method, in the order above.
    pub const ALL: [&str; 10] = [
        SESSIONS_CREATE,
        SESSIONS_LIST,
        SESSIONS_STOP,
        SESSIONS_CHANGES,
        SESSIONS_DRIVE,
        SESSIONS_ATTACH,
        SESSIONS_INPUT,
        APPROVALS_LIST,
        APPROVALS_DECIDE,
        APPROVALS_WATCH,
    ];
}

/// The notifications a watching or attached connection receives.
pub mod notification {
    /// Output of the attached command: params [`Output`](super::Output).
    pub const SESSION_OUTPUT: &str = "session.output";
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
    /// The session's model; absent means none (architect Q119).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<ModelParams>,
    /// What the session lives as long as; absent: until it is stopped (architect Q102).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifetime: Option<Lifetime>,
}

/// A session's lifetime other than the default one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lifetime {
    /// Stopped (reason `disconnect`) when the connection that created it closes.
    Connection,
}

/// `sessions.attach` params (architect Q101).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachParams {
    /// The session.
    pub id: String,
    /// The command and its arguments: 1 to [`MAX_ARGV`] strings, none with a NUL.
    pub argv: Vec<String>,
    /// The guest working directory; absent: the shell tool's default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
}

/// `sessions.input` params (architect Q101).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputParams {
    /// The session.
    pub id: String,
    /// Bytes for the command's standard input, at most [`MAX_INPUT_BYTES`].
    pub data: String,
    /// The input ends after `data`.
    #[serde(default)]
    pub eof: bool,
}

/// Why `sallyd` killed an attached command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KillReason {
    /// The session stopped.
    SessionStop,
    /// The attached connection closed.
    Disconnect,
    /// The started process was not found in time.
    StartTimeout,
}

/// `sessions.attach` result: sent once both output streams are drained (architect Q101).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum Attached {
    /// The command ended: `podman exec`'s code (128+N for a signal).
    Exited {
        /// The exit code.
        exit_code: i32,
    },
    /// `sallyd` killed it.
    Killed {
        /// Why.
        killed: KillReason,
    },
}

/// Which output stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stream {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
}

/// `session.output` params: at most [`MAX_OUTPUT_CHUNK`] bytes of one stream, escaped by
/// `sallyd` to printable ASCII and newline (architect Q100).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Output {
    /// The session.
    pub id: String,
    /// The stream.
    pub stream: Stream,
    /// The escaped text.
    pub text: String,
}

/// The kinds of model a session can have.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelKind {
    /// No model.
    None,
    /// A script of turns, answered by `sallyd` (data, never code).
    Scripted,
}

/// A session's requested model (architect Q119): strict, `driven` required.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelParams {
    /// Only [`ModelKind::Scripted`] is accepted.
    pub kind: ModelKind,
    /// The script's JSON Lines text (at most 256 KiB).
    pub script: String,
    /// Declared driven: the host drives the session and no harness socket is served.
    pub driven: bool,
}

/// A session's model as `sessions.list` shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionModel {
    /// The kind.
    pub kind: ModelKind,
    /// Whether the session is driven.
    pub driven: bool,
    /// The script's SHA-256 (hex), for a scripted model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// The script's turns, for a scripted model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turns: Option<u32>,
}

impl SessionModel {
    /// The model of a session without one.
    #[must_use]
    pub fn none() -> Self {
        Self {
            kind: ModelKind::None,
            driven: false,
            sha256: None,
            turns: None,
        }
    }
}

/// What a drive step's turn was.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TurnKind {
    /// An assistant message.
    Content,
    /// Tool calls, made in order.
    ToolCalls,
    /// The scripted backend failure.
    Fail,
    /// The script has no turn left.
    End,
}

/// One tool call a drive step made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepCall {
    /// The tool name, escaped by `sallyd`.
    pub name: String,
    /// The result text, escaped and cut by `sallyd`.
    pub result: String,
}

/// `sessions.drive` result: one scripted turn (architect Q117). Text arrives escaped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    /// The turn's 1-based number; 0 once the script has ended.
    pub turn: u32,
    /// What it was.
    pub kind: TurnKind,
    /// The assistant message of a content turn.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    /// The calls of a tool-call turn, with their results.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub calls: Vec<StepCall>,
    /// The driver stops here: this was a content or fail turn (a driven script ends at its
    /// first), the script's last turn, the `end` step, or a turn whose call was refused before
    /// its tool ran (that call's result is `denied: <reason>`; later calls of the turn did not
    /// run).
    pub done: bool,
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
    /// Its model.
    pub model: SessionModel,
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
    /// The broker's call number.
    pub call: u64,
    /// The digest an approve must name.
    pub digest: String,
    /// The action text, escaped ASCII from the request, runs of one unit marked (`\{N}`),
    /// cut at the broker's bound with an explicit tail when `truncated`. A client shows it apart
    /// from its own lines (RT-AG-04).
    pub action: String,
    /// Whether `action` was cut.
    pub truncated: bool,
    /// The agent's note, quoted and escaped: untrusted text, never the action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Risk tags (`destructive`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub risk_tags: Vec<String>,
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
    /// The prompts waiting, by session id, then oldest first.
    pub prompts: Vec<Prompt>,
    /// Whether `prompts` holds every waiting prompt; `false` when the reply's byte budget cut
    /// it (architect Q84). Prompts cut from a watch result are not notified later: a client
    /// lists again once it has answered the ones it holds.
    pub complete: bool,
    /// How many prompts are waiting, listed or not.
    pub total: usize,
}

/// The `data` of every control error reply (architect Q88).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorData {
    /// The reason code (`unknown-session`, `manifest-invalid`, ...).
    pub reason: String,
    /// One line of detail, escaped: the refusal text `sallyd` audited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// A rejected manifest's errors, one escaped line each.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
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
            model: SessionModel::none(),
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
            call: 3,
            digest: "d".into(),
            action: "a".into(),
            truncated: false,
            note: None,
            risk_tags: vec![],
            full: None,
            full_unavailable: false,
        };
        let v = to_value(&whole).unwrap();
        assert!(v.get("full").is_none() && v.get("full_unavailable").is_none());
        assert!(v.get("note").is_none() && v.get("risk_tags").is_none());
        assert_eq!(
            (v["call"].as_u64(), v["action"].as_str()),
            (Some(3), Some("a"))
        );
        assert!(v.get("text").is_none());
        let noted = Prompt {
            note: Some("n".into()),
            risk_tags: vec!["destructive".into()],
            ..whole.clone()
        };
        let v = to_value(&noted).unwrap();
        assert_eq!(
            (v["note"].as_str(), v["risk_tags"][0].as_str()),
            (Some("n"), Some("destructive"))
        );
        let deny_only = Prompt {
            truncated: true,
            full_unavailable: true,
            ..whole
        };
        assert_eq!(to_value(&deny_only).unwrap()["full_unavailable"], true);
    }

    /// Architect Q84: a prompt list says whether the reply's budget cut it.
    #[test]
    fn a_prompt_list_says_if_it_was_cut() {
        let p: Prompts = from_value(json!({"prompts": [], "complete": false, "total": 3})).unwrap();
        assert!(!p.complete);
        assert_eq!(p.total, 3);
    }

    /// Architect Q88: the error data of every control reply; `detail` and `errors` only when
    /// there are some.
    #[test]
    fn error_data_in_wire_form() {
        let bare = ErrorData {
            reason: "unknown-session".into(),
            detail: None,
            errors: Vec::new(),
        };
        assert_eq!(
            to_value(&bare).unwrap(),
            json!({"reason": "unknown-session"})
        );
        let full = ErrorData {
            reason: "manifest-invalid".into(),
            detail: Some("d".into()),
            errors: vec!["error: name: empty [required]".into()],
        };
        let v = to_value(&full).unwrap();
        assert_eq!(v["detail"], "d");
        assert_eq!(v["errors"][0], "error: name: empty [required]");
        assert_eq!(from_value::<ErrorData>(v).unwrap(), full);
        assert_eq!(
            from_value::<ErrorData>(json!({"reason": "r"})).unwrap(),
            bare_with("r")
        );
    }

    fn bare_with(reason: &str) -> ErrorData {
        ErrorData {
            reason: reason.into(),
            detail: None,
            errors: Vec::new(),
        }
    }

    #[test]
    fn frames_are_capped_at_1_mib() {
        assert_eq!(MAX_FRAME, 1_048_576);
    }

    #[test]
    fn the_method_list_is_the_ten_names() {
        assert_eq!(
            method::ALL,
            [
                "sessions.create",
                "sessions.list",
                "sessions.stop",
                "sessions.changes",
                "sessions.drive",
                "sessions.attach",
                "sessions.input",
                "approvals.list",
                "approvals.decide",
                "approvals.watch",
            ]
        );
    }

    #[test]
    fn create_params_carry_a_strict_optional_model() {
        let bare: CreateParams = from_value(json!({"manifest": "x"})).unwrap();
        assert_eq!(bare.model, None);
        assert!(to_value(&bare).unwrap().get("model").is_none());
        let m: CreateParams = from_value(
            json!({"manifest": "x", "model": {"kind": "scripted", "script": "s", "driven": true}}),
        )
        .unwrap();
        assert_eq!(
            m.model,
            Some(ModelParams {
                kind: ModelKind::Scripted,
                script: "s".into(),
                driven: true,
            })
        );
        for bad in [
            json!({"kind": "scripted", "script": "s"}),
            json!({"kind": "scripted", "script": "s", "driven": true, "x": 1}),
            json!({"kind": "llama", "script": "s", "driven": true}),
        ] {
            assert!(from_value::<CreateParams>(json!({"manifest": "x", "model": bad})).is_err());
        }
    }

    #[test]
    fn the_session_names_its_model() {
        let none = SessionModel::none();
        assert_eq!(
            to_value(&none).unwrap(),
            json!({"kind": "none", "driven": false})
        );
        let s = SessionModel {
            kind: ModelKind::Scripted,
            driven: true,
            sha256: Some("ab".into()),
            turns: Some(3),
        };
        assert_eq!(
            to_value(&s).unwrap(),
            json!({"kind": "scripted", "driven": true, "sha256": "ab", "turns": 3})
        );
    }

    /// Architect Q101: attach takes an argv of 1–256 strings and an optional cwd, strictly.
    #[test]
    fn attach_params_are_strict() {
        let p: AttachParams = from_value(json!({"id": "a", "argv": ["sh"]})).unwrap();
        assert_eq!(p.argv, ["sh"]);
        assert_eq!(p.cwd, None);
        let p: AttachParams =
            from_value(json!({"id": "a", "argv": ["ls", "-l"], "cwd": "/workspace"})).unwrap();
        assert_eq!(p.cwd.as_deref(), Some("/workspace"));
        for bad in [
            json!({"id": "a"}),
            json!({"id": "a", "argv": "sh"}),
            json!({"id": "a", "argv": ["sh"], "env": {}}),
            json!({"argv": ["sh"]}),
        ] {
            assert!(from_value::<AttachParams>(bad).is_err());
        }
    }

    /// Architect Q101: input is data with an optional end of input, strictly.
    #[test]
    fn input_params_are_strict() {
        let p: InputParams = from_value(json!({"id": "a", "data": "ls\n"})).unwrap();
        assert_eq!(p.data, "ls\n");
        assert!(!p.eof);
        let p: InputParams = from_value(json!({"id": "a", "data": "", "eof": true})).unwrap();
        assert!(p.eof);
        assert!(from_value::<InputParams>(json!({"id": "a"})).is_err());
        assert!(from_value::<InputParams>(json!({"id": "a", "data": "", "x": 1})).is_err());
    }

    /// Architect Q101: an attach ends with the exit code or why it was killed, never both.
    #[test]
    fn an_attach_result_in_wire_form() {
        let code = Attached::Exited { exit_code: 3 };
        assert_eq!(to_value(&code).unwrap(), json!({"exit_code": 3}));
        let killed = Attached::Killed {
            killed: KillReason::Disconnect,
        };
        assert_eq!(to_value(&killed).unwrap(), json!({"killed": "disconnect"}));
        for (r, s) in [
            (KillReason::SessionStop, "session-stop"),
            (KillReason::Disconnect, "disconnect"),
            (KillReason::StartTimeout, "start-timeout"),
        ] {
            assert_eq!(to_value(r).unwrap(), json!(s));
            assert_eq!(from_value::<KillReason>(json!(s)).unwrap(), r);
        }
        assert_eq!(
            from_value::<Attached>(json!({"exit_code": 0})).unwrap(),
            Attached::Exited { exit_code: 0 }
        );
        assert!(from_value::<Attached>(json!({"killed": "timeout"})).is_err());
        assert!(
            from_value::<Attached>(json!({"exit_code": 0, "killed": "disconnect"})).is_err(),
            "a result with both fields is refused, not read as either variant"
        );
    }

    /// Architect Q101: one output notification names its stream.
    #[test]
    fn an_output_notification_in_wire_form() {
        let o = Output {
            id: "s1".into(),
            stream: Stream::Stderr,
            text: "a\\x1bb".into(),
        };
        assert_eq!(
            to_value(&o).unwrap(),
            json!({"id": "s1", "stream": "stderr", "text": "a\\x1bb"})
        );
        assert_eq!(notification::SESSION_OUTPUT, "session.output");
    }

    /// Architect Q102: a session bound to its connection says so; absent is today's.
    #[test]
    fn create_params_take_a_connection_lifetime() {
        let bare: CreateParams = from_value(json!({"manifest": "x"})).unwrap();
        assert_eq!(bare.lifetime, None);
        assert!(to_value(&bare).unwrap().get("lifetime").is_none());
        let bound: CreateParams =
            from_value(json!({"manifest": "x", "lifetime": "connection"})).unwrap();
        assert_eq!(bound.lifetime, Some(Lifetime::Connection));
        assert!(
            from_value::<CreateParams>(json!({"manifest": "x", "lifetime": "forever"})).is_err()
        );
    }

    #[test]
    fn the_line_mode_bounds_are_the_ruled_numbers() {
        assert_eq!(MAX_ARGV, 256);
        assert_eq!(MAX_INPUT_BYTES, 64 * 1024);
        assert_eq!(MAX_OUTPUT_CHUNK, 16 * 1024);
    }

    #[test]
    fn a_drive_step_in_wire_form() {
        let step = Step {
            turn: 2,
            kind: TurnKind::ToolCalls,
            content: None,
            calls: vec![StepCall {
                name: "fs.read".into(),
                result: "ok".into(),
            }],
            done: false,
        };
        assert_eq!(
            to_value(&step).unwrap(),
            json!({"turn": 2, "kind": "tool_calls", "calls": [{"name": "fs.read", "result": "ok"}],
                   "done": false})
        );
        assert!(from_value::<SessionParams>(json!({"id": "a"})).is_ok());
    }
}
