//! The control socket's methods (architect Q71–Q89): their parameters, what each does, what it
//! audits and what it answers. The serve loop and the request entry are in `control.rs`.
//!
//! Every reply that lists (`sessions.changes`, `approvals.list`, `approvals.watch`) is held to
//! [`REPLY_BYTES`] of serialized items, so it fits the client's frame cap
//! ([`sally_proto::MAX_FRAME`]); a cut list says so (`complete: false`, `total`).

use std::future::Future;
use std::os::fd::AsFd;
use std::sync::Arc;

use sally_core::audit::{Actor, NewEntry};
use sally_core::manifest::{ValidatedManifest, load};
use sally_core::secrets::StoreNames;
use sally_core::text::{Quote, Style, escape_capped};
use sally_proto::ModelKind;
use sally_proto::method;
use sally_proto::{
    Change as WireChange, ChangeKind as WireKind, Changes, CreateParams, DecideParams,
    Decision as WireDecision, ErrorData, Lifetime, NoParams, Prompt as WirePrompt, Prompts,
    Session, SessionParams, SessionState as WireState, Sessions, Stopped,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};

use super::attach::{self, Asked, ConnState};
pub use super::attach::{AttachCall, InputCall};
use super::control::{Conn, Control};
use super::drive::{Driver, Stepped};
use super::line::Line;
use super::message::Id;
use crate::approvals::queue::who;
use crate::approvals::render::{self, Prompt};
use crate::approvals::{Client, Decision, Desk, Seen};
use crate::llm::scripted::Script;
use crate::sandbox::{Change, ChangeKind, ChangesError, LaunchError, SessionId, session_changes};
use crate::session::{SessionInfo, SessionState, StartError, StopOutcome};
use crate::tools::shell::Streamer;

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
pub trait SessionSet: Clone + Send + Sync + 'static {
    /// The runner of an attached command.
    type Exec: Streamer;
    /// The live sessions, by id.
    fn list(&self) -> Vec<SessionInfo>;
    /// Session `id`'s line mode (architect Q101).
    fn line(&self, id: &str) -> Option<Arc<Line<Self::Exec>>>;
    /// Stops session `id` because the connection it was bound to closed (architect Q102,
    /// Q150): reason `disconnect`; `None`: no such session (already stopped).
    fn stop_disconnected(&self, id: &str) -> impl Future<Output = Option<StopOutcome>> + Send;
    /// Session `id`'s approvals desk.
    fn desk(&self, id: &str) -> Option<Desk>;
    /// Session `id`'s drive handle: only a session declared driven at start has one.
    fn driver(&self, id: &str) -> Option<Arc<Driver>>;
    /// Starts a session for `manifest`; with a `script`, declared driven (architect Q119).
    fn start(
        &self,
        manifest: Arc<ValidatedManifest>,
        script: Option<Script>,
    ) -> impl Future<Output = Result<SessionInfo, StartError>> + Send;
    /// Stops session `id` (a client's request); `None`: no such session.
    fn stop(&self, id: &str) -> impl Future<Output = Option<StopOutcome>> + Send;
}

/// One admitted control request: the method with its strictly parsed params. Public for the
/// `jsonrpc_message` fuzz target (architect Q96).
#[derive(Debug)]
pub enum Call {
    /// `sessions.create`.
    Create(CreateParams),
    /// `sessions.list`.
    List,
    /// `sessions.stop`, its id already canonical.
    Stop(SessionId),
    /// `sessions.changes`, its id already canonical.
    Changes(SessionId),
    /// `sessions.drive`, its id already canonical. It carries nothing else: the script held by
    /// `sallyd` is the only source of a driven call (architect Q117).
    Drive(SessionId),
    /// `sessions.attach` ([`AttachCall::admit`]).
    Attach(AttachCall),
    /// `sessions.input` ([`InputCall::admit`]).
    Input(InputCall),
    /// `approvals.list`.
    Approvals,
    /// `approvals.decide`.
    Decide(DecideParams),
    /// `approvals.watch`.
    Watch,
}

/// Why a request was not admitted (`rpc.deny`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotAdmitted {
    /// Not one of [`CONTROL_METHODS`](super::mcp::CONTROL_METHODS).
    MethodNotFound,
    /// Params with an unknown, missing or ill-typed field, or a session id that is not
    /// canonical.
    InvalidParams,
}

impl Call {
    /// The call for `method` with `params`, strictly parsed.
    ///
    /// # Errors
    /// [`NotAdmitted`].
    pub fn parse(method: &str, params: Map<String, Value>) -> Result<Self, NotAdmitted> {
        match method {
            method::SESSIONS_CREATE => Ok(Self::Create(params_of(params)?)),
            method::SESSIONS_LIST => params_of::<NoParams>(params).map(|_| Self::List),
            method::SESSIONS_STOP => Ok(Self::Stop(session_id(params)?)),
            method::SESSIONS_CHANGES => Ok(Self::Changes(session_id(params)?)),
            method::SESSIONS_DRIVE => Ok(Self::Drive(session_id(params)?)),
            method::SESSIONS_ATTACH => AttachCall::admit(params_of(params)?).map(Self::Attach),
            method::SESSIONS_INPUT => InputCall::admit(params_of(params)?).map(Self::Input),
            method::APPROVALS_LIST => params_of::<NoParams>(params).map(|_| Self::Approvals),
            method::APPROVALS_DECIDE => Ok(Self::Decide(params_of(params)?)),
            method::APPROVALS_WATCH => params_of::<NoParams>(params).map(|_| Self::Watch),
            _ => Err(NotAdmitted::MethodNotFound),
        }
    }

    /// The method name, from the fixed table.
    #[must_use]
    pub fn method(&self) -> &'static str {
        match self {
            Self::Create(_) => method::SESSIONS_CREATE,
            Self::List => method::SESSIONS_LIST,
            Self::Stop(_) => method::SESSIONS_STOP,
            Self::Changes(_) => method::SESSIONS_CHANGES,
            Self::Drive(_) => method::SESSIONS_DRIVE,
            Self::Attach(_) => method::SESSIONS_ATTACH,
            Self::Input(_) => method::SESSIONS_INPUT,
            Self::Approvals => method::APPROVALS_LIST,
            Self::Decide(_) => method::APPROVALS_DECIDE,
            Self::Watch => method::APPROVALS_WATCH,
        }
    }

    /// Whether it draws on the daemon-wide read rate (architect Q77): the reads, and a watch on
    /// a connection that already `watching`, which only lists again (Q94). A first watch never
    /// waits, so attaching an approver is never delayed. TODO(#142): refusals of the unrated
    /// methods are entries too, with no rate.
    pub(crate) fn rated(&self, watching: bool) -> bool {
        match self {
            Self::List | Self::Changes(_) | Self::Approvals => true,
            Self::Watch => watching,
            Self::Create(_)
            | Self::Stop(_)
            | Self::Decide(_)
            | Self::Drive(_)
            | Self::Attach(_)
            | Self::Input(_) => false,
        }
    }

    /// The method as the connection-state gate sees it (architect Q144).
    pub(crate) fn asked(&self) -> Asked {
        match self {
            Self::Attach(_) => Asked::Attach,
            Self::Input(_) => Asked::Input,
            Self::Create(_)
            | Self::List
            | Self::Stop(_)
            | Self::Changes(_)
            | Self::Drive(_)
            | Self::Approvals
            | Self::Decide(_)
            | Self::Watch => Asked::Other,
        }
    }

    /// The session id the call names, for a refusal's entry.
    fn id(&self) -> Option<&SessionId> {
        match self {
            Self::Stop(id) | Self::Changes(id) | Self::Drive(id) => Some(id),
            Self::Attach(a) => Some(&a.id),
            Self::Input(i) => Some(&i.id),
            Self::Create(_) | Self::List | Self::Approvals | Self::Decide(_) | Self::Watch => None,
        }
    }

    /// What `rpc.request` records besides the socket, method and client: for a create, the
    /// manifest's size and hash, never its text (architect Q71); for a stop or a listing, the
    /// session id, canonical once parsed (Q95).
    pub(crate) fn request_args(&self) -> Map<String, Value> {
        let mut m = Map::new();
        match self {
            Self::Create(p) => {
                use sha2::Digest as _;
                let sha =
                    crate::approvals::action::hex(&sha2::Sha256::digest(p.manifest.as_bytes()));
                m.insert("manifest_bytes".into(), Value::from(p.manifest.len()));
                m.insert("manifest_sha256".into(), Value::from(sha));
                // The script's size and hash, never its text (architect Q119).
                if let Some(model) = &p.model {
                    let sha = crate::approvals::action::hex(&sha2::Sha256::digest(
                        model.script.as_bytes(),
                    ));
                    m.insert("script_bytes".into(), Value::from(model.script.len()));
                    m.insert("script_sha256".into(), Value::from(sha));
                }
                if let Some(l) = p.lifetime {
                    m.insert("lifetime".into(), json!(l));
                }
            }
            Self::Stop(id) | Self::Changes(id) | Self::Drive(id) => {
                m.insert("id".into(), Value::from(id.as_str()));
            }
            // The command is `sandbox.exec`'s, in the session's log.
            Self::Attach(a) => {
                m.insert("id".into(), Value::from(a.id.as_str()));
            }
            // Its size and whether it ends the input, never its bytes (architect Q147).
            Self::Input(i) => {
                m.insert("id".into(), Value::from(i.id.as_str()));
                m.insert("bytes".into(), Value::from(i.data.len()));
                m.insert("eof".into(), Value::from(i.eof));
            }
            Self::List | Self::Approvals | Self::Decide(_) | Self::Watch => {}
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
    /// Answered later by the serve loop: an attach when its command ended, an input once it was
    /// written (architect Q144).
    Deferred,
}

impl<S: SessionSet> Control<S> {
    /// Runs one admitted call (its `rpc.request` is written); `id` is its request id, for a
    /// reply the serve loop sends later.
    pub(crate) async fn run(&self, call: Call, conn: &mut Conn, id: &Id) -> Done {
        // Seats of sessions that stopped are let go: they drive nothing, and a connection that
        // only holds those is no driver (Q121's refusals are for a live seat).
        conn.seats.retain(|s| !s.ended());
        let state = ConnState::of(conn.watch.is_some(), conn.drives(), conn.attach.is_some());
        if let Err(why) = attach::gate(state, call.asked()) {
            return self
                .driver_refused(call.method(), call.id(), why, conn.client)
                .await;
        }
        match call {
            Call::Create(p) => self.create(p, conn).await,
            Call::Attach(a) => self.attach(a, conn, id).await,
            Call::Input(i) => self.input(i, conn, id).await,
            Call::List => {
                let sessions = self.p.sessions.list().iter().map(session).collect();
                Done::Ok(value(&Sessions { sessions }))
            }
            Call::Stop(id) => self.stop(&id, conn.client).await,
            Call::Changes(id) => self.changes(id, conn.client).await,
            Call::Drive(id) => self.drive(id, conn).await,
            Call::Approvals => Done::Ok(value(&self.prompts())),
            Call::Decide(p) if conn.drives() => self.driver_decides(&p.id, conn.client).await,
            Call::Decide(p) => self.decide(p, conn.client).await,
            Call::Watch if conn.drives() => {
                let method = method::APPROVALS_WATCH;
                self.driver_refused(method, None, "driver-seat", conn.client)
                    .await
            }
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
        let entry = self.refusal(actor, event).args(args);
        self.refused(entry, data).await
    }

    /// A refusal entry named `event`, to fill.
    fn refusal(&self, actor: Actor, event: &str) -> NewEntry {
        self.p.record.entry(actor, event, Some("refuse"))
    }

    /// Writes the refusal `entry`; the reply once it is written, else the connection closes.
    async fn refused(&self, entry: NewEntry, data: ErrorData) -> Done {
        if self.p.record.append(entry).await {
            Done::Refused(data)
        } else {
            Done::Close
        }
    }

    /// `sessions.drive`: one scripted turn of a driven session, on the seat of this connection
    /// (architect Q117, Q121). Every refusal is an entry of the control log, none of the
    /// session's: a refused drive writes nothing to the session.
    async fn drive(&self, id: SessionId, conn: &mut Conn) -> Done {
        let client = conn.client;
        let method = method::SESSIONS_DRIVE;
        let Some(driver) = self.p.sessions.driver(id.as_str()) else {
            // A live session without a drive handle was not declared driven.
            let live = self.p.sessions.list().iter().any(|s| s.id == id.as_str());
            return if live {
                self.driver_refused(method, Some(&id), "not-driven", client)
                    .await
            } else {
                self.unknown_session(method, &id, client).await
            };
        };
        if driver.ended() {
            let why = crate::tools::STOPPING;
            return self.driver_refused(method, Some(&id), why, client).await;
        }
        if !conn.holds(&driver) {
            if conn.watch.is_some() {
                let why = "driver-watching";
                return self.driver_refused(method, Some(&id), why, client).await;
            }
            match driver.claim() {
                Ok(seat) => conn.seats.push(seat),
                Err(r) => {
                    return self
                        .driver_refused(method, Some(&id), r.reason(), client)
                        .await;
                }
            }
        }
        let Some(seat) = conn.seat_of(&driver) else {
            return Done::Close;
        };
        match seat.step().await {
            Stepped::Step(step) => Done::Ok(value(&step)),
            Stepped::Refused(why) => self.driver_refused(method, Some(&id), why, client).await,
            Stepped::Close => Done::Close,
        }
    }

    /// A refusal of a connection's or a session's rules (the drive seat's, line mode's):
    /// `session.refuse` in the control log, nothing in the session's.
    pub(crate) async fn driver_refused(
        &self,
        method: &str,
        id: Option<&SessionId>,
        reason: &str,
        client: Client,
    ) -> Done {
        let args = json!({
            "method": method, "id": id.map(SessionId::as_str), "reason": reason,
            "client": who(client),
        });
        let data = refusal(reason, None, Vec::new());
        self.refuse(Actor::Sallyd, "session.refuse", args, data)
            .await
    }

    /// `approvals.decide` on a connection that holds a drive seat: refused for any prompt, which
    /// stays pending (architect Q121). The driver is never an approver.
    async fn driver_decides(&self, id: &str, client: Client) -> Done {
        let args = json!({
            "id": escape_capped(id.as_bytes(), ID_CHARS), "reason": "driver-seat",
            "client": who(client),
        });
        let data = refusal("driver-seat", None, Vec::new());
        self.refuse(Actor::User, "approval.decide", args, data)
            .await
    }

    /// The script of a create's `model`, parsed whole before anything launches (architect Q119):
    /// `Ok(None)` without a model. Only a scripted model declared driven starts, in this task,
    /// and its script ends at its first content or fail turn ([`Script::driven`]). The parse
    /// runs off the runtime: a script is up to [`sally_proto::MAX_SCRIPT_BYTES`].
    /// TODO(#53): `driven: false` waits for the `llm.sock` backend (Task 13).
    async fn script_of(&self, p: &CreateParams, client: Client) -> Result<Option<Script>, Done> {
        let Some(m) = &p.model else {
            return Ok(None);
        };
        let (reason, detail) = if m.kind != ModelKind::Scripted {
            (
                "model-invalid",
                "model.kind: only scripted is accepted".to_owned(),
            )
        } else if !m.driven {
            (
                "scripted-not-driven",
                "model.driven: a scripted model is served to a driver only".to_owned(),
            )
        } else {
            let text = m.script.clone();
            let parsed =
                blocking(move || Script::parse(&text).and_then(|s| s.driven().map(|()| s)));
            match parsed.await {
                Some(Ok(s)) => return Ok(Some(s)),
                Some(Err(e)) => ("script-invalid", e.to_string()),
                None => return Err(Done::Close),
            }
        };
        Err(self.refuse_create(reason, &detail, client).await)
    }

    /// A `sessions.create` refused before validation's verdict: `session.refuse` with `reason`
    /// and `detail` (escaped, capped), and the same in the reply.
    async fn refuse_create(&self, reason: &str, detail: &str, client: Client) -> Done {
        let detail = escape_capped(detail.as_bytes(), DETAIL_CHARS);
        let args = json!({
            "method": method::SESSIONS_CREATE, "reason": reason, "detail": detail,
            "client": who(client),
        });
        let data = refusal(reason, Some(detail), Vec::new());
        self.refuse(Actor::Sallyd, "session.refuse", args, data)
            .await
    }

    async fn create(&self, p: CreateParams, conn: &mut Conn) -> Done {
        let client = conn.client;
        let bound = p.lifetime == Some(Lifetime::Connection);
        let script = match self.script_of(&p, client).await {
            Ok(s) => s,
            Err(done) => return done,
        };
        let env = Arc::clone(&self.p.env);
        let store = Arc::clone(&self.p.secrets);
        // A fresh catalog per validation, opened only if the manifest names a secret (Q221).
        let loaded = blocking(move || {
            let names = StoreNames::new(store.to_path_buf());
            let verdict = load(&p.manifest, &env, &names);
            (verdict, names.failed().map(ToString::to_string))
        })
        .await;
        let validated = match loaded {
            // The store could not be read: a store fault, not a manifest fault (Q221).
            Some((_, Some(store))) => {
                return self.refuse_create("secret-store", &store, client).await;
            }
            Some((Ok(v), None)) => v,
            Some((Err(rejected), None)) => {
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
        match self
            .p
            .sessions
            .start(Arc::new(validated.manifest), script)
            .await
        {
            Ok(info) => {
                // Bound before the reply is written: a connection gone by then stops it at
                // once (architect Q150).
                if bound {
                    conn.bound.push(self.bind(&info.id));
                }
                Done::Ok(value(&session(&info)))
            }
            // Its `sandbox.refuse` could not be written: no reply without an entry (Q93).
            Err(StartError::Launch(LaunchError::Unaudited { .. })) => Done::Close,
            // The launch task ended without a result: no launcher entry, so this one (Q98).
            Err(StartError::Launch(LaunchError::Lost(sid))) => self.lost(sid, client).await,
            // The launcher audited its `sandbox.refuse` with this reason and detail.
            Err(StartError::Launch(e)) => Done::Refused(refusal(
                e.reason(),
                Some(escape_capped(e.detail().as_bytes(), DETAIL_CHARS)),
                Vec::new(),
            )),
            Err(e) => {
                let reason = start_reason(&e);
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

    /// A launch of session `sid` whose task ended without a result: the launcher wrote no
    /// entry, so this `session.refuse` is the refusal's own (architect Q98).
    async fn lost(&self, sid: SessionId, client: Client) -> Done {
        let id = sid.as_str().to_owned();
        let e = LaunchError::Lost(sid);
        let detail = escape_capped(e.detail().as_bytes(), DETAIL_CHARS);
        let args = json!({
            "method": method::SESSIONS_CREATE, "id": id, "reason": e.reason(),
            "detail": detail, "client": who(client),
        });
        let data = refusal(e.reason(), Some(detail), Vec::new());
        self.refuse(Actor::Sallyd, "session.refuse", args, data)
            .await
    }

    async fn stop(&self, id: &SessionId, client: Client) -> Done {
        match self.p.sessions.stop(id.as_str()).await {
            Some(StopOutcome::Stopped) => Done::Ok(value(&Stopped {
                id: id.as_str().to_owned(),
            })),
            // The session's own log is sealed by now: the control log has the entry (Q95).
            Some(StopOutcome::Failed(why)) => {
                let args = json!({
                    "method": method::SESSIONS_STOP, "id": id.as_str(), "reason": "stop-failed",
                    "client": who(client),
                });
                let entry = self.refusal(Actor::Sallyd, "session.refuse");
                let entry = refusal_entry(entry, args, "detail", &why);
                let detail = escape_capped(why.as_bytes(), DETAIL_CHARS);
                let data = refusal("stop-failed", Some(detail), Vec::new());
                self.refused(entry, data).await
            }
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
                let why = e.to_string();
                let args = json!({
                    "method": method::SESSIONS_CHANGES, "id": id.as_str(),
                    "reason": "listing-failed", "client": who(client),
                });
                let entry = self.refusal(Actor::Sallyd, "session.refuse");
                let entry = refusal_entry(entry, args, "error", &why);
                let error = escape_capped(why.as_bytes(), DETAIL_CHARS);
                let data = refusal("listing-failed", Some(error), Vec::new());
                self.refused(entry, data).await
            }
            None => Done::Close,
        }
    }

    /// Every waiting prompt of every live session, by session id, then queue order, within
    /// [`REPLY_BYTES`].
    pub(crate) fn prompts(&self) -> Prompts {
        let desks = self.desks();
        let all = desks.iter().flat_map(Desk::list).map(|p| prompt(&p));
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
            // The desk audited it, except `audit-failed` (its entry could not be written): the
            // one reply without an entry, by the maintainer's Task 11 rule. Nothing was
            // approved and a `deny_all_session` latch stays (architect Q93 ii).
            Err(e) => Done::Refused(refusal(&e.to_string(), None, Vec::new())),
        }
    }
}

/// The refusal reason of a start failure other than a launch refusal (architect Q88 iii);
/// listed in full so a new kind of failure is named here, not swept into one.
fn start_reason(e: &StartError) -> &'static str {
    match e {
        StartError::ShuttingDown => "shutting-down",
        StartError::Launch(l) => l.reason(),
        StartError::Id(_)
        | StartError::Paths(_)
        | StartError::Exited(_)
        | StartError::Audit(_)
        | StartError::Socket(_)
        | StartError::Join(_)
        | StartError::Task(_) => "start-failed",
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

/// How a refusal's failure text is written: [`escape_capped`]'s format at [`DETAIL_CHARS`].
pub const REFUSAL_STYLE: Style = Style::Text {
    max: DETAIL_CHARS,
    quote: Quote::None,
};

/// `entry` with `args` and the failure text `raw` as the arg `key`, declared (architect Q288
/// (8)): a stop's or a listing's failure can name what a sandbox wrote, so the writer masks it
/// whole before it escapes and cuts it in [`REFUSAL_STYLE`]. The reply carries its own escaped
/// copy: it goes to the host client, not to a log.
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

fn decision(d: WireDecision) -> Decision {
    match d {
        WireDecision::Approve => Decision::Approve,
        WireDecision::Deny => Decision::Deny,
        WireDecision::DenyAllSession => Decision::DenyAllSession,
    }
}
