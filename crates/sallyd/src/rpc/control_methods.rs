//! The control socket's methods (architect Q71–Q89): their parameters, what each does, what it
//! audits and what it answers. The serve loop and the request entry are in `control.rs`.
//!
//! Every reply that lists (`sessions.changes`, `approvals.list`, `approvals.watch`) is held to
//! [`REPLY_BYTES`] of serialized items, so it fits the client's frame cap
//! ([`sally_proto::MAX_FRAME`]); a cut list says so (`complete: false`, `total`).

use std::future::Future;
use std::os::fd::AsFd;
use std::sync::Arc;

use sally_core::audit::Actor;
use sally_core::manifest::{ValidatedManifest, load};
use sally_core::text::escape_capped;
use sally_proto::method;
use sally_proto::{
    Change as WireChange, ChangeKind as WireKind, Changes, CreateParams, DecideParams,
    Decision as WireDecision, ErrorData, NoParams, Prompt as WirePrompt, Prompts, Session,
    SessionParams, SessionState as WireState, Sessions, Stopped,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};

use super::control::{Conn, Control};
use crate::approvals::queue::who;
use crate::approvals::render::{self, Prompt};
use crate::approvals::{Client, Decision, Desk, Seen};
use crate::sandbox::{Change, ChangeKind, ChangesError, SessionId, session_changes};
use crate::session::{SessionInfo, SessionState, StartError, StopOutcome};

/// `sessions.list`, `sessions.changes` and `approvals.list` per second, daemon-wide (architect
/// Q77). Tunable: high enough for a UI refreshing a few views, low enough that a loop of them
/// cannot keep `sallyd` busy.
pub const READ_RATE: u32 = 20;
/// Of those, how many may come at once.
pub const READ_BURST: u32 = 40;
/// Most bytes of serialized items in one listing reply (architect Q75, Q84). One prompt at its
/// largest fits (see the relation test), and the reply's envelope stays under the client's
/// frame cap. TODO(#107): paging, and fair order across sessions for prompts.
pub const REPLY_BYTES: usize = 768 * 1024;
/// Most characters of one detail or error line in a reply or an entry.
pub const DETAIL_CHARS: usize = 1024;
/// Most error lines of a rejected manifest in a reply; the rest are counted.
pub const MAX_ERROR_LINES: usize = 32;
/// Most characters of an unknown approval id in an entry.
pub const ID_CHARS: usize = 128;
/// The JSON-RPC code of a refused control request (implementation-defined server error).
pub const REFUSED: i64 = -32000;

/// The sessions the control socket acts on: the daemon's [`Registry`](crate::session::Registry)
/// (its implementation is pure delegation), or a test double. Sessions need containers, so
/// this seam keeps the methods unit-testable (architect Q86).
pub trait SessionSet: Send + Sync + 'static {
    /// The live sessions, by id.
    fn list(&self) -> Vec<SessionInfo>;
    /// Session `id`'s approvals desk.
    fn desk(&self, id: &str) -> Option<Desk>;
    /// Starts a session for `manifest`.
    fn start(
        &self,
        manifest: Arc<ValidatedManifest>,
    ) -> impl Future<Output = Result<SessionInfo, StartError>> + Send;
    /// Stops session `id` (a client's request); `None`: no such session.
    fn stop(&self, id: &str) -> impl Future<Output = Option<StopOutcome>> + Send;
}

/// One admitted control request.
#[derive(Debug)]
pub(crate) enum Call {
    Create(CreateParams),
    List,
    Stop(SessionId),
    Changes(SessionId),
    Approvals,
    Decide(DecideParams),
    Watch,
}

/// Why a request was not admitted (`rpc.deny`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NotAdmitted {
    MethodNotFound,
    InvalidParams,
}

impl Call {
    /// The call for `method` with `params`, strictly parsed.
    pub(crate) fn parse(method: &str, params: Map<String, Value>) -> Result<Self, NotAdmitted> {
        match method {
            method::SESSIONS_CREATE => Ok(Self::Create(params_of(params)?)),
            method::SESSIONS_LIST => params_of::<NoParams>(params).map(|_| Self::List),
            method::SESSIONS_STOP => Ok(Self::Stop(session_id(params)?)),
            method::SESSIONS_CHANGES => Ok(Self::Changes(session_id(params)?)),
            method::APPROVALS_LIST => params_of::<NoParams>(params).map(|_| Self::Approvals),
            method::APPROVALS_DECIDE => Ok(Self::Decide(params_of(params)?)),
            method::APPROVALS_WATCH => params_of::<NoParams>(params).map(|_| Self::Watch),
            _ => Err(NotAdmitted::MethodNotFound),
        }
    }

    /// The method name, from the fixed table.
    pub(crate) fn method(&self) -> &'static str {
        match self {
            Self::Create(_) => method::SESSIONS_CREATE,
            Self::List => method::SESSIONS_LIST,
            Self::Stop(_) => method::SESSIONS_STOP,
            Self::Changes(_) => method::SESSIONS_CHANGES,
            Self::Approvals => method::APPROVALS_LIST,
            Self::Decide(_) => method::APPROVALS_DECIDE,
            Self::Watch => method::APPROVALS_WATCH,
        }
    }

    /// Whether it draws on the daemon-wide read rate (architect Q77).
    pub(crate) fn rated(&self) -> bool {
        matches!(self, Self::List | Self::Changes(_) | Self::Approvals)
    }

    /// What `rpc.request` records besides the socket, method and client: for a create, the
    /// manifest's size and hash, never its text (architect Q71).
    pub(crate) fn request_args(&self) -> Map<String, Value> {
        let mut m = Map::new();
        if let Self::Create(p) = self {
            use sha2::Digest as _;
            let sha = crate::approvals::action::hex(&sha2::Sha256::digest(p.manifest.as_bytes()));
            m.insert("manifest_bytes".into(), Value::from(p.manifest.len()));
            m.insert("manifest_sha256".into(), Value::from(sha));
        }
        m
    }
}

fn params_of<T: DeserializeOwned>(params: Map<String, Value>) -> Result<T, NotAdmitted> {
    serde_json::from_value(Value::Object(params)).map_err(|_| NotAdmitted::InvalidParams)
}

fn session_id(params: Map<String, Value>) -> Result<SessionId, NotAdmitted> {
    let p: SessionParams = params_of(params)?;
    SessionId::parse(&p.id).map_err(|_| NotAdmitted::InvalidParams)
}

/// How a method ended.
#[derive(Debug)]
pub(crate) enum Done {
    /// The result.
    Ok(Value),
    /// Refused, with what the client is told (its entry, if any, is written).
    Refused(ErrorData),
    /// An entry could not be written: no effect, no reply, the connection closes.
    Close,
}

impl<S: SessionSet> Control<S> {
    /// Runs one admitted call (its `rpc.request` is written).
    pub(crate) async fn run(&self, call: Call, conn: &mut Conn) -> Done {
        match call {
            Call::Create(p) => self.create(p, conn.client).await,
            Call::List => {
                let sessions = self.p.sessions.list().iter().map(session).collect();
                Done::Ok(value(&Sessions { sessions }))
            }
            Call::Stop(id) => self.stop(&id, conn.client).await,
            Call::Changes(id) => self.changes(id, conn.client).await,
            Call::Approvals => Done::Ok(value(&self.prompts())),
            Call::Decide(p) => self.decide(p, conn.client).await,
            Call::Watch => {
                // Attached first, then listed: no prompt falls between (architect Q73.4). A
                // second watch on the connection lists again and keeps its one watcher.
                if conn.watch.is_none() {
                    conn.watch = Some(self.p.hub.watch());
                }
                Done::Ok(value(&self.prompts()))
            }
        }
    }

    /// Writes a refusal entry, then refuses; `Close` if the entry failed.
    async fn refuse(&self, actor: Actor, event: &str, args: Value, data: ErrorData) -> Done {
        let entry = self.p.record.entry(actor, event, Some("refuse")).args(args);
        if self.p.record.append(entry).await {
            Done::Refused(data)
        } else {
            Done::Close
        }
    }

    async fn create(&self, p: CreateParams, client: Client) -> Done {
        let env = Arc::clone(&self.p.env);
        let catalog = Arc::clone(&self.p.catalog);
        let loaded = blocking(move || load(&p.manifest, &env, &*catalog)).await;
        let validated = match loaded {
            Some(Ok(v)) => v,
            Some(Err(rejected)) => {
                let lines: Vec<String> = rejected.errors.iter().map(ToString::to_string).collect();
                let error = escape_capped(lines.join("; ").as_bytes(), DETAIL_CHARS);
                let data = refusal("manifest-invalid", None, error_lines(&lines));
                let args = json!({"error": error});
                return self
                    .refuse(Actor::Sallyd, "manifest.refuse", args, data)
                    .await;
            }
            None => return Done::Close,
        };
        match self.p.sessions.start(Arc::new(validated.manifest)).await {
            Ok(info) => Done::Ok(value(&session(&info))),
            // The launcher audited its `sandbox.refuse` with this reason and detail.
            Err(StartError::Launch(e)) => Done::Refused(refusal(
                e.reason(),
                Some(escape_capped(e.detail().as_bytes(), DETAIL_CHARS)),
                Vec::new(),
            )),
            Err(e) => {
                let reason = match e {
                    StartError::ShuttingDown => "shutting-down",
                    _ => "start-failed",
                };
                let detail = escape_capped(e.to_string().as_bytes(), DETAIL_CHARS);
                let args = json!({
                    "method": method::SESSIONS_CREATE, "reason": reason, "detail": detail,
                    "client": who(client),
                });
                let data = refusal(reason, Some(detail), Vec::new());
                self.refuse(Actor::Sallyd, "session.refuse", args, data)
                    .await
            }
        }
    }

    async fn stop(&self, id: &SessionId, client: Client) -> Done {
        match self.p.sessions.stop(id.as_str()).await {
            Some(StopOutcome::Stopped) => Done::Ok(value(&Stopped {
                id: id.as_str().to_owned(),
            })),
            Some(StopOutcome::Failed(why)) => Done::Refused(refusal(
                "stop-failed",
                Some(escape_capped(why.as_bytes(), DETAIL_CHARS)),
                Vec::new(),
            )),
            None => {
                self.unknown_session(method::SESSIONS_STOP, id, client)
                    .await
            }
        }
    }

    async fn unknown_session(&self, method: &str, id: &SessionId, client: Client) -> Done {
        let args = json!({
            "method": method, "id": id.as_str(), "reason": "unknown-session",
            "client": who(client),
        });
        let data = refusal("unknown-session", None, Vec::new());
        self.refuse(Actor::Sallyd, "session.refuse", args, data)
            .await
    }

    async fn changes(&self, id: SessionId, client: Client) -> Done {
        let dir = Arc::clone(&self.p.sessions_dir);
        let sid = id.clone();
        let listed = blocking(move || session_changes(dir.as_fd(), &sid)).await;
        match listed {
            Some(Ok(all)) => {
                let (changes, complete, total) = fit(all.iter().map(change), REPLY_BYTES);
                Done::Ok(value(&Changes {
                    changes,
                    complete,
                    total,
                }))
            }
            Some(Err(ChangesError::UnknownSession)) => {
                self.unknown_session(method::SESSIONS_CHANGES, &id, client)
                    .await
            }
            Some(Err(e)) => {
                let error = escape_capped(e.to_string().as_bytes(), DETAIL_CHARS);
                let args = json!({
                    "method": method::SESSIONS_CHANGES, "id": id.as_str(),
                    "reason": "listing-failed", "error": error, "client": who(client),
                });
                let data = refusal("listing-failed", Some(error), Vec::new());
                self.refuse(Actor::Sallyd, "session.refuse", args, data)
                    .await
            }
            None => Done::Close,
        }
    }

    /// Every waiting prompt of every live session, by session id, then queue order, within
    /// [`REPLY_BYTES`].
    pub(crate) fn prompts(&self) -> Prompts {
        let all: Vec<WirePrompt> = self
            .desks()
            .iter()
            .flat_map(Desk::list)
            .map(|p| prompt(&p))
            .collect();
        let (prompts, complete, total) = fit(all, REPLY_BYTES);
        Prompts {
            prompts,
            complete,
            total,
        }
    }

    fn desks(&self) -> Vec<Desk> {
        let live = self.p.sessions.list();
        live.iter()
            .filter_map(|s| self.p.sessions.desk(&s.id))
            .collect()
    }

    /// Decides on the desk whose session holds the prompt (architect Q85). No lock is held
    /// across the decision; a prompt that closes in between is the desk's `unknown-id`.
    async fn decide(&self, p: DecideParams, client: Client) -> Done {
        let found = self
            .desks()
            .into_iter()
            .find(|d| d.list().iter().any(|q| q.id == p.id));
        let Some(desk) = found else {
            let args = json!({
                "id": escape_capped(p.id.as_bytes(), ID_CHARS), "reason": "unknown-id",
                "client": who(client),
            });
            let data = refusal("unknown-id", None, Vec::new());
            return self
                .refuse(Actor::User, "approval.decide", args, data)
                .await;
        };
        let seen = Seen {
            digest: &p.digest,
            full_shown: p.full_shown,
        };
        match desk.decide(&p.id, decision(p.decision), client, seen).await {
            Ok(()) => Done::Ok(json!({})),
            // The desk audited it.
            Err(e) => Done::Refused(refusal(&e.to_string(), None, Vec::new())),
        }
    }
}

/// Runs blocking work off the runtime. A panic in it is the connection's (it reaches the
/// daemon's crash reporter); `None` if the task was cancelled (the runtime is shutting down).
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    match tokio::task::spawn_blocking(f).await {
        Ok(t) => Some(t),
        Err(e) => match e.try_into_panic() {
            Ok(panic) => std::panic::resume_unwind(panic),
            Err(_) => None,
        },
    }
}

pub(crate) fn refusal(reason: &str, detail: Option<String>, errors: Vec<String>) -> ErrorData {
    ErrorData {
        reason: reason.to_owned(),
        detail,
        errors,
    }
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

fn decision(d: WireDecision) -> Decision {
    match d {
        WireDecision::Approve => Decision::Approve,
        WireDecision::Deny => Decision::Deny,
        WireDecision::DenyAllSession => Decision::DenyAllSession,
    }
}
