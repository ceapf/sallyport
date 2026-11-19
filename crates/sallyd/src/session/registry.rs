//! The session registry (Task 12, architect Q57): it starts sessions in a fixed order, supervises
//! each one in its own task ([`super::supervise`]), and ends it exactly once.
//!
//! Start: `launch_workspace` (overlap and fd budget reserved, `sandbox.launch` audited) → the
//! init's exit watch → approvals, tools and the agent server built in memory → audit
//! `session.start {model:{kind:"none"}}` → bind `agent.sock` (0600) in the session's harness
//! socket directory → listen. A failed launch is the launcher's `sandbox.refuse` only; a failed
//! `session.start` append binds nothing, writes a best-effort `session.stop` (`start-failed`: the
//! entry may have reached the log) and stops the workspace; any failure after it ends the session
//! with `start-failed`. Every `session.start` gets exactly one `session.stop`. A start runs in its
//! own task: a caller that goes away mid-start leaves nothing half-made.
//!
//! A workspace that cannot be confirmed gone, whether its session started or not, stays listed
//! as stop-failed, keeping its claims and its disk watchdog; a later stop request or
//! [`Registry::shutdown`] retries it, and shutdown counts what is still unconfirmed.

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use sally_core::audit::{Actor, AuditError, NewEntry};
use sally_core::manifest::{AuditLevel, ValidatedManifest};
use sally_proto::{ModelKind, SessionModel};
use serde_json::json;
use tokio::sync::RwLock;
use tokio::sync::{mpsc, oneshot};

use super::exit::Exit;
use super::supervise::{Request, Supervised};
use super::types::{StopReason, fresh_id};
use crate::approvals::Gated;
use crate::approvals::policy::Policy;
use crate::approvals::queue::{self, Approver, Desk, Limits};
use crate::daemon::crash::CrashReporter;
use crate::egress::net::bind;
use crate::llm::scripted::Script;
use crate::oplog::Oplog;
use crate::rpc::agent::Agent;
use crate::rpc::drive::{CallFn, Driver};
use crate::rpc::line::{Line, LineParts};
use crate::rpc::record::Recorder;
use crate::sandbox::{
    ArgvError, AuditSink, ImageRef, LaunchError, Launcher, Podman, Running, SessionPaths, UserIds,
    WorkspaceRequest,
};
use crate::tools::exec::PodmanExec;
use crate::tools::ops::Ops;
use crate::tools::{self, FetchParts, Parts, Tools};

/// The session's tool socket in its harness socket directory.
pub const AGENT_SOCK: &str = "agent.sock";
/// Stop requests queued per session.
const REQUESTS: usize = 16;
/// The oplog component.
pub(super) const LOG: &str = "session";

/// What the registry is built from.
pub struct RegistryParts {
    /// The sandbox launcher.
    pub launcher: Arc<Launcher>,
    /// The audit log (the launcher's own sink).
    pub audit: Arc<dyn AuditSink>,
    /// Hermetic podman, for the `shell` tool.
    pub podman: Podman,
    /// The host user: the workspace's `--user`, and the only peer `agent.sock` accepts.
    pub ids: UserIds,
    /// `$XDG_RUNTIME_DIR/sallyport`.
    pub sockets: PathBuf,
    /// `~/.local/share/sallyport`.
    pub data: PathBuf,
    /// The bundled workspace image; `None` until one is installed (architect Q58, TODO(#88)):
    /// the launcher then refuses a manifest without `runtime.image`.
    pub default_image: Option<ImageRef>,
    /// The operational log.
    pub oplog: Oplog,
    /// Where every session's prompts go: the daemon's one [`Hub`](crate::approvals::hub::Hub)
    /// (architect Q73). With no client attached to it, prompts are denied `no-approver`.
    pub approver: Arc<dyn Approver>,
    /// The daemon's crash reporter: a panic in a supervisor is not a session's, so `sallyd`
    /// stops every session and exits (architect Q47).
    pub crash: CrashReporter,
    /// Prefix of every session id (`<scope>-<hex>`); empty in production. Test fixtures scope
    /// their sessions as they scope `Launcher::remove_orphans`.
    pub scope: String,
}

/// Where a session is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Started and not yet stopping.
    Running,
    /// Its container could not be confirmed gone (or operations of it were still running); a
    /// stop request retries.
    StopFailed,
}

/// A live session, as `sessions.list` shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
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

/// Why a session did not start.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StartError {
    /// `sallyd` is shutting down.
    #[error("sallyd is shutting down")]
    ShuttingDown,
    /// No session id could be drawn.
    #[error("session id: {0}")]
    Id(#[source] io::Error),
    /// The session's paths could not be formed.
    #[error("session paths: {0}")]
    Paths(#[source] ArgvError),
    /// The workspace was refused (`sandbox.refuse` is audited).
    #[error(transparent)]
    Launch(#[from] LaunchError),
    /// The container ended before the session started.
    #[error("the container ended before the session started: {0}")]
    Exited(#[source] io::Error),
    /// `session.start` could not be audited; nothing was bound and the workspace was stopped.
    #[error("audit: session.start: {0}")]
    Audit(#[source] AuditError),
    /// `agent.sock` could not be bound; the session ended `start-failed`.
    #[error("{AGENT_SOCK}: {0}")]
    Socket(#[source] io::Error),
    /// An audit append's task failed: a daemon-chosen text, never tokio's, which quotes the
    /// panic message escaped before any mask (architect Q297).
    #[error("audit task: {0}")]
    Join(&'static str),
    /// The start's own task ended without an answer (it panicked; `sallyd` is stopping).
    #[error("the start task ended: {0}")]
    Task(#[source] oneshot::error::RecvError),
}

/// How a stop ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopOutcome {
    /// The container is gone and the session released.
    Stopped,
    /// The container could not be confirmed gone, or operations of the session still run; the
    /// session stays listed as stop-failed.
    Failed(String),
}

pub(super) type Reply = oneshot::Sender<StopOutcome>;

pub(super) struct Live {
    pub(super) info: SessionInfo,
    /// `None` for a workspace whose session never started.
    desk: Option<Desk>,
    crash: Option<CrashReporter>,
    /// The drive handle of a driven session (architect Q117).
    driver: Option<Arc<Driver>>,
    /// Its line mode; `None` for a workspace whose session never started.
    line: Option<Arc<Line<PodmanExec>>>,
    requests: mpsc::Sender<Request>,
}

/// A stop request on its way: the session id and where its answer comes.
struct Asked {
    id: String,
    done: oneshot::Receiver<StopOutcome>,
}

/// Every live session of one `sallyd`. Shared as `Arc<Registry>`.
pub struct Registry {
    pub(super) p: RegistryParts,
    live: Mutex<HashMap<String, Live>>,
    closing: AtomicBool,
    /// Held shared by every start from before its `closing` check to its insertion, and once
    /// exclusively by [`Registry::shutdown`] after setting `closing`: no start slips past it.
    starts: RwLock<()>,
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registry").finish_non_exhaustive()
    }
}

impl Registry {
    /// A registry with no sessions.
    #[must_use]
    pub fn new(p: RegistryParts) -> Arc<Self> {
        Arc::new(Self {
            p,
            live: Mutex::new(HashMap::new()),
            closing: AtomicBool::new(false),
            starts: RwLock::new(()),
        })
    }

    pub(super) fn live(&self) -> std::sync::MutexGuard<'_, HashMap<String, Live>> {
        self.live.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The live sessions, by id.
    #[must_use]
    pub fn list(&self) -> Vec<SessionInfo> {
        let mut all: Vec<_> = self.live().values().map(|l| l.info.clone()).collect();
        all.sort_by(|a, b| a.id.cmp(&b.id));
        all
    }

    /// The approvals desk of session `id`, for control-side clients.
    #[must_use]
    pub fn desk(&self, id: &str) -> Option<Desk> {
        self.live().get(id).and_then(|l| l.desk.clone())
    }

    /// The drive handle of session `id`: only a session declared driven at start has one.
    #[must_use]
    pub fn driver(&self, id: &str) -> Option<Arc<Driver>> {
        self.live().get(id).and_then(|l| l.driver.clone())
    }

    /// The crash reporter of session `id`, for a session task started after the session (the
    /// `llm.sock` listener): a panic it reports ends the session `crash`.
    #[must_use]
    pub fn reporter(&self, id: &str) -> Option<CrashReporter> {
        self.live().get(id).and_then(|l| l.crash.clone())
    }

    pub(super) async fn audit(&self, entry: NewEntry, level: AuditLevel) -> Result<(), StartError> {
        let sink = Arc::clone(&self.p.audit);
        tokio::task::spawn_blocking(move || sink.append(entry, level))
            .await
            .map_err(|e| StartError::Join(crate::daemon::crash::join_text(&e)))?
            .map_err(StartError::Audit)
    }

    /// Starts a session for `manifest` and returns it once `agent.sock` is served. The start
    /// runs in a task of its own: dropping this future does not interrupt it.
    ///
    /// # Errors
    /// [`StartError`]. Nothing of the session is left running, except a container that could not
    /// be confirmed gone (listed as stop-failed).
    pub async fn start(
        self: &Arc<Self>,
        manifest: Arc<ValidatedManifest>,
    ) -> Result<SessionInfo, StartError> {
        self.start_with(manifest, None).await
    }

    /// [`start`](Self::start), declared driven when there is a `script` (architect Q119).
    ///
    /// # Errors
    /// [`StartError`], as for [`start`](Self::start).
    pub async fn start_with(
        self: &Arc<Self>,
        manifest: Arc<ValidatedManifest>,
        script: Option<Script>,
    ) -> Result<SessionInfo, StartError> {
        let this = Arc::clone(self);
        let (tx, rx) = oneshot::channel();
        self.p.crash.spawn("session", async move {
            let _ = tx.send(this.start_owned(manifest, script).await);
        });
        rx.await.map_err(StartError::Task)?
    }

    /// `script`: the session is declared driven (architect Q119): it serves no socket of the
    /// harness's, its recorder writes the harness's entries as the driver's, and a
    /// [`Driver`] answers `sessions.drive`.
    async fn start_owned(
        self: Arc<Self>,
        manifest: Arc<ValidatedManifest>,
        script: Option<Script>,
    ) -> Result<SessionInfo, StartError> {
        let _start = self.starts.read().await;
        if self.closing.load(Ordering::SeqCst) {
            return Err(StartError::ShuttingDown);
        }
        let id = fresh_id(&self.p.scope).map_err(StartError::Id)?;
        let sid = id.as_str().to_owned();
        let paths =
            SessionPaths::new(id, &self.p.sockets, &self.p.data).map_err(StartError::Paths)?;
        let (crash, crashes) = CrashReporter::channel();
        let running = self
            .p
            .launcher
            .launch_workspace(WorkspaceRequest {
                paths,
                manifest: Arc::clone(&manifest),
                default_image: self.p.default_image.clone(),
                crash: crash.clone(),
            })
            .await?;
        let v = manifest.manifest();
        let exit = match Exit::watch(running.init_dir()) {
            Ok(x) => x,
            Err(e) => {
                self.discard(running, &v.name).await;
                return Err(StartError::Exited(e));
            }
        };
        let level = v.audit.level;
        let ops = Ops::new();
        // The session's one audit handle (ruling 1, Q63): its stop seals it with `session.stop`.
        // TODO(#28): the `llm.sock` server (PR C) takes a clone of it.
        let record = Recorder::new(Arc::clone(&self.p.audit), sid.clone(), level)
            .logging(self.p.oplog.clone());
        let record = if script.is_some() {
            record.driven()
        } else {
            record
        };
        let (agent, desk) = self.agent(&manifest, &running, &record, &ops, &crash);
        // Line mode: the shell tool's runner, its default directory, the session's one audit
        // handle and operations (architect Q101, Q146).
        let line = Line::build(LineParts {
            exec: PodmanExec::new(self.p.podman.clone(), &running, ops.clone()),
            record: record.clone(),
            ops: ops.clone(),
            crash: crash.clone(),
            cwd: tools::default_cwd(&tools::exec::session_mounts(&manifest, &running)),
        });
        let model = model_of(script.as_ref());
        let start = NewEntry::new(Actor::Sallyd, "session.start")
            .session(&sid)
            .decision("allow")
            .args(json!({
                "manifest": v.name,
                "container": running.name(),
                "model": json!(model),
            }));
        if let Err(e) = self.audit(start, level).await {
            self.p
                .oplog
                .error(LOG, "session.start not audited", &[("session", &sid)]);
            // The entry may have reached the log before the error (L6): close it, best effort,
            // through the seal, `session.stop`'s one writer. Nothing of the session runs yet.
            let stop = NewEntry::new(Actor::Sallyd, "session.stop")
                .session(&sid)
                .args(json!({"reason": StopReason::StartFailed.as_str(), "in_flight": 0}));
            let _ = record.seal(stop, Duration::ZERO).await;
            self.discard(running, &v.name).await;
            return Err(e);
        }
        let sock = running.paths().harness_sockets().join(AGENT_SOCK);
        // A driven session binds nothing: the harness has no socket to reach it by (Q119).
        let driver = script.map(|s| driver_of(s, &agent, &record, &ops));
        let (handle, first, failed) = if driver.is_some() {
            (None, None, None)
        } else {
            match bind(&sock) {
                Ok(l) => (Some(agent.listen(l, self.p.ids.uid)), None, None),
                Err(e) => (None, Some(StopReason::StartFailed), Some(e)),
            }
        };
        let info = SessionInfo {
            id: sid.clone(),
            manifest: v.name.clone(),
            container: running.name().to_owned(),
            state: SessionState::Running,
            model,
        };
        let (tx, rx) = mpsc::channel(REQUESTS);
        self.live().insert(
            sid.clone(),
            Live {
                info: info.clone(),
                desk: Some(desk.clone()),
                crash: Some(crash.clone()),
                driver,
                line: Some(line),
                requests: tx.clone(),
            },
        );
        let s = Supervised {
            sid: sid.clone(),
            record,
            timeout: Duration::from_secs(v.runtime.timeout.as_secs()),
            running,
            agent: handle,
            desk,
            ops,
            exit,
            crash,
            crashes,
            requests: rx,
            first,
        };
        let this = Arc::clone(&self);
        self.p
            .crash
            .spawn("session", async move { this.supervise(s).await });
        if let Some(e) = failed {
            let (reply, done) = oneshot::channel();
            if tx
                .send((StopReason::StartFailed, Some(reply)))
                .await
                .is_ok()
            {
                let _ = done.await;
            }
            return Err(StartError::Socket(e));
        }
        self.p
            .oplog
            .info(LOG, "session started", &[("session", &sid)]);
        Ok(info)
    }

    /// The session's agent server and approvals desk, built in memory.
    fn agent(
        &self,
        manifest: &Arc<ValidatedManifest>,
        running: &Running,
        rec: &Recorder,
        ops: &Ops,
        crash: &CrashReporter,
    ) -> (Arc<Agent<Gated<Tools<PodmanExec>>>>, Desk) {
        let v = manifest.manifest();
        let sid = running.paths().id().as_str();
        let (gate, desk) = queue::new(
            sid.to_owned(),
            Policy::from_manifest(manifest),
            Limits::from_manifest(&v.approvals),
            rec.clone(),
            Some(Arc::clone(&self.p.approver)),
        );
        let tools = Tools::new(Parts {
            builtin: v.tools.builtin.clone(),
            mounts: tools::exec::session_mounts(manifest, running),
            record: rec.clone(),
            exec_gate: running.exec_gate(),
            ops: ops.clone(),
            crash: crash.clone(),
            ids: self.p.ids,
            shell: PodmanExec::new(self.p.podman.clone(), running, ops.clone()),
            // No connector (no proxy, or no trust roots): a granted fetch stays unlisted and
            // `tool_unavailable` (architect ruling Q8). Caps as the session proxy's (#103).
            fetch: running.fetch_connector().map(|connector| FetchParts {
                connector,
                max_request: v.network.max_request_bytes.bytes(),
                max_response: v.network.max_response_bytes.bytes(),
            }),
        });
        (
            Arc::new(Agent::new(
                Gated::new(gate, tools),
                rec.clone(),
                crash.clone(),
            )),
            desk,
        )
    }

    /// Stops a workspace whose session never started (no `session.start`, so no
    /// `session.stop`). One that cannot be confirmed gone stays listed as stop-failed, under a
    /// supervisor that retries it on request (and at shutdown).
    async fn discard(self: &Arc<Self>, running: Running, manifest: &str) {
        let sid = running.paths().id().as_str().to_owned();
        let r = match self.stop_bounded(running).await {
            Ok(done) => {
                // It is gone: `session.closed`, then its forms leave the redactors (#94,
                // architect Q219, Q245, Q252).
                self.p.launcher.close(done, StopReason::StartFailed).await;
                return;
            }
            Err(r) => r,
        };
        self.p.oplog.error(
            LOG,
            "workspace of a failed start not confirmed gone",
            &[("session", &sid)],
        );
        let (tx, rx) = mpsc::channel(REQUESTS);
        self.live().insert(
            sid.clone(),
            Live {
                info: SessionInfo {
                    id: sid.clone(),
                    manifest: manifest.to_owned(),
                    container: r.name().to_owned(),
                    state: SessionState::StopFailed,
                    model: SessionModel::none(),
                },
                desk: None,
                crash: None,
                driver: None,
                line: None,
                requests: tx,
            },
        );
        let this = Arc::clone(self);
        self.p.crash.spawn("session", async move {
            // Its bounded round has just failed: the next one waits for a request (R6).
            let mut rx = rx;
            let replies: Vec<Reply> = match rx.recv().await {
                Some((_, reply)) => reply.into_iter().collect(),
                None => Vec::new(),
            };
            this.retry_stop(sid, *r, replies, rx, StopReason::StartFailed, None)
                .await;
        });
    }

    /// Sends a stop request to session `id`. `Err`: the outcome is already known (`None`: no
    /// such session).
    async fn ask(&self, id: &str, reason: StopReason) -> Result<Asked, Option<StopOutcome>> {
        let requests = self
            .live()
            .get(id)
            .map(|l| l.requests.clone())
            .ok_or(None)?;
        let (reply, done) = oneshot::channel();
        if requests.send((reason, Some(reply))).await.is_err() {
            return Err(Some(self.supervisor_gone(id)));
        }
        Ok(Asked {
            id: id.to_owned(),
            done,
        })
    }

    /// The answer to a request.
    async fn answer(&self, asked: Asked) -> StopOutcome {
        match asked.done.await {
            Ok(o) => o,
            Err(_) => self.supervisor_gone(&asked.id),
        }
    }

    /// No supervisor answers for `id`. It removed its entry when the session ended (then the
    /// session is stopped); an entry still there means the supervisor died with it.
    fn supervisor_gone(&self, id: &str) -> StopOutcome {
        let outcome = unanswered(&mut self.live(), id);
        if outcome != StopOutcome::Stopped {
            self.p
                .oplog
                .error(LOG, "session supervisor ended", &[("session", id)]);
        }
        outcome
    }

    /// Asks session `id` to stop and waits for the outcome. `None`: no such session.
    pub async fn stop(&self, id: &str, reason: StopReason) -> Option<StopOutcome> {
        match self.ask(id, reason).await {
            Ok(asked) => Some(self.answer(asked).await),
            Err(known) => known,
        }
    }

    /// Stops session `id`, `disconnect`: the connection it was bound to closed (architect
    /// Q150). No client is told; a failed stop is an oplog line here, and the control socket
    /// writes its `session.refuse`.
    pub async fn stop_disconnected(&self, id: &str) -> Option<StopOutcome> {
        let outcome = self.stop(id, StopReason::Disconnect).await;
        if matches!(outcome, Some(StopOutcome::Failed(_))) {
            self.p
                .oplog
                .error(LOG, "bound session not stopped", &[("session", id)]);
        }
        outcome
    }

    /// Session `id`'s line mode (architect Q101).
    #[must_use]
    pub fn line(&self, id: &str) -> Option<Arc<Line<PodmanExec>>> {
        self.live().get(id).and_then(|l| l.line.clone())
    }

    /// Refuses new sessions and stops every live one (`shutdown`), all at once: each session is
    /// asked in a task of its own, so one with a full request queue delays no other (R7). The
    /// ids of sessions whose container could not be confirmed gone; `sallyd` then exits
    /// non-zero.
    pub async fn shutdown(self: &Arc<Self>) -> Vec<String> {
        self.closing.store(true, Ordering::SeqCst);
        // Waits out every start already past its check; later ones see `closing`.
        drop(self.starts.write().await);
        let ids: Vec<String> = self.live().keys().cloned().collect();
        let mut asks = tokio::task::JoinSet::new();
        let mut names = HashMap::new();
        for id in ids {
            let this = Arc::clone(self);
            let sid = id.clone();
            let task = asks.spawn(async move { this.stop(&sid, StopReason::Shutdown).await });
            names.insert(task.id(), id);
        }
        let mut unconfirmed = Vec::new();
        while let Some(done) = asks.join_next_with_id().await {
            let (task, confirmed) = match done {
                Ok((task, outcome)) => (task, !matches!(outcome, Some(StopOutcome::Failed(_)))),
                Err(e) => (e.id(), false),
            };
            if !confirmed {
                unconfirmed.extend(names.remove(&task));
            }
        }
        unconfirmed.sort();
        unconfirmed
    }
}

/// The control socket's sessions (architect Q86): pure delegation, proved by the container
/// tests in `tests/control.rs`.
impl crate::rpc::control_methods::SessionSet for Arc<Registry> {
    type Exec = PodmanExec;

    fn list(&self) -> Vec<SessionInfo> {
        Registry::list(self)
    }

    fn line(&self, id: &str) -> Option<Arc<Line<PodmanExec>>> {
        Registry::line(self, id)
    }

    fn stop_disconnected(
        &self,
        id: &str,
    ) -> impl std::future::Future<Output = Option<StopOutcome>> + Send {
        Registry::stop_disconnected(self, id)
    }

    fn desk(&self, id: &str) -> Option<Desk> {
        Registry::desk(self, id)
    }

    fn driver(&self, id: &str) -> Option<Arc<Driver>> {
        Registry::driver(self, id)
    }

    fn start(
        &self,
        manifest: Arc<ValidatedManifest>,
        script: Option<Script>,
    ) -> impl std::future::Future<Output = Result<SessionInfo, StartError>> + Send {
        Registry::start_with(self, manifest, script)
    }

    fn stop(&self, id: &str) -> impl std::future::Future<Output = Option<StopOutcome>> + Send {
        Registry::stop(self, id, StopReason::Request)
    }
}

/// The model a session is started with, as listed and as `session.start` records it.
fn model_of(script: Option<&Script>) -> SessionModel {
    script.map_or_else(SessionModel::none, |s| SessionModel {
        kind: ModelKind::Scripted,
        driven: true,
        sha256: Some(s.sha256.clone()),
        turns: u32::try_from(s.turns.len()).ok(),
    })
}

/// The drive handle of a driven session: its tool calls go to the session's own agent server,
/// the one gate the harness's calls meet (architect Q117).
fn driver_of(
    script: Script,
    agent: &Arc<Agent<Gated<Tools<PodmanExec>>>>,
    record: &Recorder,
    ops: &Ops,
) -> Arc<Driver> {
    let agent = Arc::clone(agent);
    let call: CallFn = Box::new(move |name, arguments| {
        let agent = Arc::clone(&agent);
        Box::pin(async move { agent.drive_call(name, arguments).await })
    });
    Driver::build(script.turns, call, record.clone(), ops.clone())
}

/// What a stop of `id` answers when no supervisor took or answered the request. A supervisor
/// removes its entry when its session ends, so no entry means stopped; an entry still listed
/// means the supervisor died with the session (rust review M4): it is dropped from the listing
/// and the stop fails, never reported `Stopped`.
fn unanswered(live: &mut HashMap<String, Live>, id: &str) -> StopOutcome {
    if live.remove(id).is_none() {
        return StopOutcome::Stopped;
    }
    StopOutcome::Failed(format!("the supervisor of session {id} ended"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Architect Q297: an audit append's task that panicked is a fixed text, never tokio's
    /// (the panic message escaped, before any mask: `session.refuse` carries this text).
    #[tokio::test]
    async fn a_panicked_audit_task_is_a_fixed_text() {
        let h = tokio::task::spawn_blocking(|| panic!("sp-q\"uote-vvvvvvvvvvvv"));
        let e = StartError::Join(crate::daemon::crash::join_text(&h.await.unwrap_err()));
        assert_eq!(
            e.to_string(),
            format!("audit task: {}", crate::daemon::crash::JOIN_PANICKED)
        );
    }

    #[test]
    fn a_session_whose_supervisor_died_fails_its_stop_once() {
        let (requests, _) = mpsc::channel(1);
        let mut live = HashMap::from([(
            "s-1".to_owned(),
            Live {
                info: SessionInfo {
                    id: "s-1".into(),
                    manifest: "m".into(),
                    container: "c".into(),
                    state: SessionState::Running,
                    model: SessionModel::none(),
                },
                desk: None,
                crash: None,
                driver: None,
                line: None,
                requests,
            },
        )]);
        assert_eq!(
            unanswered(&mut live, "s-1"),
            StopOutcome::Failed("the supervisor of session s-1 ended".into())
        );
        assert!(live.is_empty());
        assert_eq!(unanswered(&mut live, "s-1"), StopOutcome::Stopped);
    }
}
