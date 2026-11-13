//! The session registry (Task 12, architect Q57): it starts sessions in a fixed order, supervises
//! each one in its own task, and ends it exactly once.
//!
//! Start: `launch_workspace` (overlap and fd budget reserved, `sandbox.launch` audited) → the
//! init's exit watch → approvals, tools and the agent server built in memory → audit
//! `session.start {model:{kind:"none"}}` → bind `agent.sock` (0600) in the session's harness
//! socket directory → listen. A failed launch is the launcher's `sandbox.refuse` only; a failed
//! `session.start` append binds nothing and stops the workspace; any failure after it ends the
//! session with `start-failed`. Every `session.start` gets exactly one `session.stop`.
//!
//! Stop ([`StopReason`]): `session.timeout` (timeout) or `session.crash` (crash) first, then
//! `session.stop`, then the agent listener is shut down (calls still waiting on an approval are
//! dropped, which denies them), then `Launcher::stop`, retried a bounded number of times. A
//! session whose container could not be confirmed gone stays listed as stop-failed, keeping its
//! claims and its disk watchdog, and a later stop request or [`Registry::shutdown`] retries it.
//! A failed entry still tears down; the oplog records it.

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use sally_core::audit::{Actor, AuditError, NewEntry};
use sally_core::manifest::{AuditLevel, ValidatedManifest};
use serde_json::json;
use tokio::sync::RwLock;
use tokio::sync::{mpsc, oneshot};

use super::exit::Exit;
use super::types::{StopReason, fresh_id};
use crate::approvals::Gated;
use crate::approvals::policy::Policy;
use crate::approvals::queue::{self, Desk, Limits};
use crate::daemon::crash::{Crash, CrashReceiver, CrashReporter};
use crate::egress::net::bind;
use crate::oplog::Oplog;
use crate::rpc::agent::Agent;
use crate::rpc::listen::Handle;
use crate::rpc::record::Recorder;
use crate::sandbox::{
    AuditSink, ImageRef, LaunchError, Launcher, Podman, Running, SessionPaths, UserIds,
    WorkspaceRequest,
};
use crate::tools::exec::PodmanExec;
use crate::tools::{self, Parts, Tools};

/// The session's tool socket in its harness socket directory.
pub const AGENT_SOCK: &str = "agent.sock";
/// `Launcher::stop` attempts per stop before the session is left stop-failed.
const STOP_ATTEMPTS: u32 = 3;
/// Pause between two `Launcher::stop` attempts.
const STOP_RETRY: Duration = Duration::from_secs(2);
/// Stop requests queued per session.
const REQUESTS: usize = 16;
/// The oplog component.
const LOG: &str = "session";

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
    /// The bundled workspace image.
    pub default_image: ImageRef,
    /// The operational log.
    pub oplog: Oplog,
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
    /// Its container could not be confirmed gone; a stop request retries.
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
    /// A background task failed.
    #[error("internal: {0}")]
    Internal(String),
}

/// How a stop ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopOutcome {
    /// The container is gone and the session released.
    Stopped,
    /// The container could not be confirmed gone; the session stays listed as stop-failed.
    Failed(String),
}

type Reply = oneshot::Sender<StopOutcome>;

struct Live {
    info: SessionInfo,
    desk: Desk,
    crash: CrashReporter,
    requests: mpsc::Sender<(StopReason, Option<Reply>)>,
}

/// What a session's supervisor owns.
struct Supervised {
    sid: String,
    level: AuditLevel,
    timeout: Duration,
    running: Running,
    agent: Option<Handle>,
    exit: Exit,
    crashes: CrashReceiver,
    requests: mpsc::Receiver<(StopReason, Option<Reply>)>,
    /// Set when the session must end at once (`start-failed`).
    first: Option<StopReason>,
}

/// Every live session of one `sallyd`. Shared as `Arc<Registry>`.
pub struct Registry {
    p: RegistryParts,
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

    fn live(&self) -> std::sync::MutexGuard<'_, HashMap<String, Live>> {
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
        self.live().get(id).map(|l| l.desk.clone())
    }

    /// The crash reporter of session `id`, for a session task started after the session (the
    /// `llm.sock` listener): a panic it reports ends the session `crash`.
    #[must_use]
    pub fn reporter(&self, id: &str) -> Option<CrashReporter> {
        self.live().get(id).map(|l| l.crash.clone())
    }

    async fn audit(&self, entry: NewEntry, level: AuditLevel) -> Result<(), StartError> {
        let sink = Arc::clone(&self.p.audit);
        tokio::task::spawn_blocking(move || sink.append(entry, level))
            .await
            .map_err(|e| StartError::Internal(e.to_string()))?
            .map_err(StartError::Audit)
    }

    /// Starts a session for `manifest` and returns it once `agent.sock` is served.
    ///
    /// # Errors
    /// [`StartError`]. Nothing of the session is left running, except a container that could not
    /// be confirmed gone after a failure past `session.start` (listed as stop-failed).
    pub async fn start(
        self: &Arc<Self>,
        manifest: Arc<ValidatedManifest>,
    ) -> Result<SessionInfo, StartError> {
        let _start = self.starts.read().await;
        if self.closing.load(Ordering::SeqCst) {
            return Err(StartError::ShuttingDown);
        }
        let id = fresh_id(&self.p.scope).map_err(StartError::Id)?;
        let sid = id.as_str().to_owned();
        let paths = SessionPaths::new(id, &self.p.sockets, &self.p.data)
            .map_err(|e| StartError::Internal(e.to_string()))?;
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
        let exit = match Exit::watch(running.init_dir()) {
            Ok(x) => x,
            Err(e) => {
                self.discard(running).await;
                return Err(StartError::Exited(e));
            }
        };
        let v = manifest.manifest();
        let level = v.audit.level;
        let agent = self.agent(&manifest, &running, &sid, level);
        let start = NewEntry::new(Actor::Sallyd, "session.start")
            .session(&sid)
            .decision("allow")
            .args(json!({
                "manifest": v.name,
                "container": running.name(),
                "model": {"kind": "none"},
            }));
        if let Err(e) = self.audit(start, level).await {
            self.p
                .oplog
                .error(LOG, "session.start not audited", &[("session", &sid)]);
            self.discard(running).await;
            return Err(e);
        }
        let sock = running.paths().harness_sockets().join(AGENT_SOCK);
        let (handle, first, failed) = match bind(&sock) {
            Ok(l) => (
                Some(agent.0.listen(l, self.p.ids.uid, crash.clone())),
                None,
                None,
            ),
            Err(e) => (None, Some(StopReason::StartFailed), Some(e)),
        };
        let info = SessionInfo {
            id: sid.clone(),
            manifest: v.name.clone(),
            container: running.name().to_owned(),
            state: SessionState::Running,
        };
        let (tx, rx) = mpsc::channel(REQUESTS);
        self.live().insert(
            sid.clone(),
            Live {
                info: info.clone(),
                desk: agent.1,
                crash,
                requests: tx.clone(),
            },
        );
        let s = Supervised {
            sid: sid.clone(),
            level,
            timeout: Duration::from_secs(v.runtime.timeout.as_secs()),
            running,
            agent: handle,
            exit,
            crashes,
            requests: rx,
            first,
        };
        let this = Arc::clone(self);
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
        sid: &str,
        level: AuditLevel,
    ) -> (Arc<Agent<Gated<Tools<PodmanExec>>>>, Desk) {
        let v = manifest.manifest();
        let rec = Recorder::new(Arc::clone(&self.p.audit), sid.to_owned(), level);
        // TODO(#65): PR B gives the desk an approver that notifies control-side clients.
        let (gate, desk) = queue::new(
            sid.to_owned(),
            Policy::from_manifest(manifest),
            Limits::from_manifest(&v.approvals),
            rec.clone(),
            None,
        );
        let tools = Tools::new(Parts {
            builtin: v.tools.builtin.clone(),
            mounts: tools::mounts(manifest, &running.init_dir()),
            record: rec.clone(),
            exec_gate: running.exec_gate(),
            ids: self.p.ids,
            shell: PodmanExec::new(self.p.podman.clone(), running),
        });
        (Arc::new(Agent::new(Gated::new(gate, tools), rec)), desk)
    }

    /// Stops a workspace whose session never started (no `session.start`, so no `session.stop`).
    async fn discard(&self, running: Running) {
        let sid = running.paths().id().as_str().to_owned();
        if let Err(r) = self.stop_bounded(running).await {
            // Nobody holds the session: keep retrying, as an unreceived launch does.
            self.p.oplog.error(
                LOG,
                "workspace of a failed start not confirmed gone",
                &[("session", &sid)],
            );
            let launcher = Arc::clone(&self.p.launcher);
            let mut r = *r;
            self.p.crash.spawn("session", async move {
                loop {
                    tokio::time::sleep(STOP_RETRY).await;
                    match launcher.stop(r).await {
                        Ok(()) => return,
                        Err(e) => r = e.running,
                    }
                }
            });
        }
    }

    /// `Launcher::stop`, at most [`STOP_ATTEMPTS`] times.
    async fn stop_bounded(&self, running: Running) -> Result<(), Box<Running>> {
        let mut r = running;
        for attempt in 1..=STOP_ATTEMPTS {
            match self.p.launcher.stop(r).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    let detail = e.error.to_string();
                    self.p.oplog.warn(
                        LOG,
                        "workspace stop failed",
                        &[
                            ("session", e.running.paths().id().as_str()),
                            ("attempt", &attempt.to_string()),
                            ("detail", &detail),
                        ],
                    );
                    r = e.running;
                }
            }
            if attempt < STOP_ATTEMPTS {
                tokio::time::sleep(STOP_RETRY).await;
            }
        }
        Err(Box::new(r))
    }

    /// Asks session `id` to stop and waits for the outcome. `None`: no such session.
    pub async fn stop(&self, id: &str, reason: StopReason) -> Option<StopOutcome> {
        let requests = self.live().get(id).map(|l| l.requests.clone())?;
        let (reply, done) = oneshot::channel();
        if requests.send((reason, Some(reply))).await.is_err() {
            // The supervisor ended between the lookup and the send: the session is gone.
            return Some(StopOutcome::Stopped);
        }
        Some(done.await.unwrap_or(StopOutcome::Stopped))
    }

    /// Refuses new sessions and stops every live one (`shutdown`). The ids of sessions whose
    /// container could not be confirmed gone; `sallyd` then exits non-zero.
    pub async fn shutdown(&self) -> Vec<String> {
        self.closing.store(true, Ordering::SeqCst);
        // Waits out every start already past its check; later ones see `closing`.
        drop(self.starts.write().await);
        let ids: Vec<String> = self.live().keys().cloned().collect();
        let mut unconfirmed = Vec::new();
        for id in ids {
            if let Some(StopOutcome::Failed(_)) = self.stop(&id, StopReason::Shutdown).await {
                unconfirmed.push(id);
            }
        }
        unconfirmed
    }

    /// One session's life after its start: wait for a reason, end it once, then retry a failed
    /// stop on request.
    async fn supervise(self: Arc<Self>, s: Supervised) {
        let Supervised {
            sid,
            level,
            timeout,
            running,
            agent,
            exit,
            mut crashes,
            mut requests,
            first,
        } = s;
        let mut replies = Vec::new();
        let reason = match first {
            Some(r) => r,
            None => {
                tokio::select! {
                    r = requests.recv() => match r {
                        Some((r, reply)) => {
                            replies.extend(reply);
                            r
                        }
                        None => StopReason::Shutdown,
                    },
                    () = tokio::time::sleep(timeout) => StopReason::Timeout,
                    Some(c) = crashes.recv() => {
                        self.crashed(&sid, level, &c).await;
                        StopReason::Crash
                    }
                    () = exit.exited() => StopReason::Exited,
                }
            }
        };
        self.ending(&sid, level, reason, timeout).await;
        if let Some(h) = agent {
            h.shutdown().await;
        }
        let mut running = running;
        loop {
            match self.stop_bounded(running).await {
                Ok(()) => {
                    self.live().remove(&sid);
                    requests.close();
                    while let Ok((_, reply)) = requests.try_recv() {
                        replies.extend(reply);
                    }
                    for r in replies.drain(..) {
                        let _ = r.send(StopOutcome::Stopped);
                    }
                    self.p.oplog.info(
                        LOG,
                        "session stopped",
                        &[("session", &sid), ("reason", reason.as_str())],
                    );
                    return;
                }
                Err(r) => {
                    running = *r;
                    self.p.oplog.error(
                        LOG,
                        "session container not confirmed gone",
                        &[("session", &sid)],
                    );
                    if let Some(l) = self.live().get_mut(&sid) {
                        l.info.state = SessionState::StopFailed;
                    }
                    let why = format!("the container of session {sid} could not be confirmed gone");
                    for r in replies.drain(..) {
                        let _ = r.send(StopOutcome::Failed(why.clone()));
                    }
                    match requests.recv().await {
                        Some((_, reply)) => replies.extend(reply),
                        // Unreachable while the registry holds the sender; retry anyway.
                        None => tokio::time::sleep(STOP_RETRY).await,
                    }
                }
            }
        }
    }

    /// Q47: the oplog line, then `session.crash`. A failed append still ends the session.
    async fn crashed(&self, sid: &str, level: AuditLevel, c: &Crash) {
        self.p.oplog.error(
            LOG,
            "session task panicked",
            &[("session", sid), ("task", c.task), ("payload", &c.payload)],
        );
        let entry = NewEntry::new(Actor::Sallyd, "session.crash")
            .session(sid)
            .decision("deny")
            .args(json!({"task": c.task, "reason": "panic", "payload": c.payload}));
        if self.audit(entry, level).await.is_err() {
            self.p
                .oplog
                .error(LOG, "session.crash not audited", &[("session", sid)]);
        }
    }

    /// `session.timeout` (timeout only), then the one `session.stop`.
    async fn ending(&self, sid: &str, level: AuditLevel, reason: StopReason, timeout: Duration) {
        if reason == StopReason::Timeout {
            let entry = NewEntry::new(Actor::Sallyd, "session.timeout")
                .session(sid)
                .decision("deny")
                .args(json!({"timeout_secs": timeout.as_secs()}));
            if self.audit(entry, level).await.is_err() {
                self.p
                    .oplog
                    .error(LOG, "session.timeout not audited", &[("session", sid)]);
            }
        }
        let entry = NewEntry::new(Actor::Sallyd, "session.stop")
            .session(sid)
            .args(json!({"reason": reason.as_str()}));
        if self.audit(entry, level).await.is_err() {
            self.p
                .oplog
                .error(LOG, "session.stop not audited", &[("session", sid)]);
        }
    }
}
