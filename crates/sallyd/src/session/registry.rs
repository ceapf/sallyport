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
use serde_json::json;
use tokio::sync::RwLock;
use tokio::sync::{mpsc, oneshot};

use super::exit::Exit;
use super::supervise::{Request, Supervised};
use super::types::{StopReason, fresh_id};
use crate::approvals::Gated;
use crate::approvals::policy::Policy;
use crate::approvals::queue::{self, Desk, Limits};
use crate::daemon::crash::CrashReporter;
use crate::egress::net::bind;
use crate::oplog::Oplog;
use crate::rpc::agent::Agent;
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
    /// An audit append's task failed.
    #[error("audit task: {0}")]
    Join(#[source] tokio::task::JoinError),
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
            .map_err(StartError::Join)?
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
        let this = Arc::clone(self);
        let (tx, rx) = oneshot::channel();
        self.p.crash.spawn("session", async move {
            let _ = tx.send(this.start_owned(manifest).await);
        });
        rx.await.map_err(StartError::Task)?
    }

    async fn start_owned(
        self: Arc<Self>,
        manifest: Arc<ValidatedManifest>,
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
        let (agent, desk) = self.agent(&manifest, &running, &record, &ops, &crash);
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
        let (handle, first, failed) = match bind(&sock) {
            Ok(l) => (
                Some(agent.listen(l, self.p.ids.uid, crash.clone())),
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
                desk: Some(desk.clone()),
                crash: Some(crash.clone()),
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
            Arc::new(Agent::new(Gated::new(gate, tools), rec.clone())),
            desk,
        )
    }

    /// Stops a workspace whose session never started (no `session.start`, so no
    /// `session.stop`). One that cannot be confirmed gone stays listed as stop-failed, under a
    /// supervisor that retries it on request (and at shutdown).
    async fn discard(self: &Arc<Self>, running: Running, manifest: &str) {
        let Err(r) = self.stop_bounded(running).await else {
            return;
        };
        let sid = r.paths().id().as_str().to_owned();
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
                },
                desk: None,
                crash: None,
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
            this.retry_stop(sid, *r, replies, rx, StopReason::StartFailed)
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
                },
                desk: None,
                crash: None,
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
