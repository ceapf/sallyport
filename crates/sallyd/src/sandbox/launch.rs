//! Launch and teardown of the sandboxes (Task 6b, #123; ARCHITECTURE §3.5). Every role
//! (workspace, harness, CPU inference) goes through one launch path (`launch/start.rs`,
//! architect Q129): its refusals that need nothing made and its claim, the hermetic podman and
//! runtime re-check, the role's preparation (this file for the workspace, `launch/harness.rs`,
//! `launch/inference.rs`), then the one start path. For the workspace, order matters:
//!
//! 1. reserve the session's mounts against every live session (B4 overlap rule, by path and by
//!    identity);
//! 2. re-check hermetic podman and the runtime; scan every mount (sockets, `.git` shields,
//!    pins);
//! 3. create the 0700 session directories and write the seccomp profiles; build and check the
//!    argv (`create`, never `run`); with `network.mode: proxy`, bind the session's `net.sock`
//!    (0600) in the workspace socket directory and start its egress listener (Task 8, architect
//!    Q7; `none` binds nothing). The listener lives in [`Running`]: `stop` shuts it down after
//!    the container is gone, and a failed launch drops it;
//! 4. to 7. the one start path (`launch/start.rs`): audit `sandbox.launch`, the mount-link probe
//!    (`mount_probe.rs`: a link at or above a mount destination in the image refuses the launch
//!    before the runtime places any of the session container's mounts), `podman create` and its
//!    image id compared with the probe's, the host re-check, `podman init`, the in-container pin
//!    check (`sandbox.mount_mismatch` on a difference), the OCI config verifier (Task 14,
//!    `sandbox.config_mismatch`), `podman start` and the running check.
//!
//! A session whose sandbox can write to the host disk (`staged` mounts, `.git` overlays) gets a
//! watchdog that kills it when those writes exceed `runtime.stage_size` (#14; `watchdog.rs`).
//!
//! The launch runs in its own task: a caller that goes away (a closed connection, an outer
//! timeout) cannot leave a half-built session. A started container always has an owner: a
//! finished launch nobody receives, and a handle dropped without a stop, are stopped by the
//! launcher until confirmed gone, their claims held meanwhile (RT-AG-08b).
//! A failure removes the container by its name (even when `create` printed no id), removes only
//! the directories this launch created, and keeps the session's overlap claims while a container
//! might still exist.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sally_core::audit::{Actor, AuditError, AuditWriter, NewEntry};
use sally_core::manifest::{AuditLevel, MountMode, NetworkMode, ValidatedManifest};
use sally_core::text::Style;
use serde_json::json;

use crate::egress::local::Connector;
use crate::egress::net::{EgressError, EgressHandle, EgressStarter, NET_SOCK, SessionEgress};

use super::argv::workspace_build;
use super::budget::session_cost;
use super::dirs::{SessionDirs, staged_indices};
use super::disk::DiskFloor;
use super::oci::intent::Built;
use super::overlap::{Sessions, claims};
use super::podman::Podman;
use super::scan::{LaunchScan, ScanLimits, scan_mounts};
use super::types::{CheckedRuntime, ImageRef, Installation, Role, SessionPaths, UserIds};
use super::watchdog::{Target, WatchPlan, Watchdog, watch_plan};
use crate::daemon::crash::CrashReporter;
use crate::oplog::Oplog;
use crate::session::secrets::{Redactors, SessionRedacted};
use crate::session::types::StopReason;

mod error;
mod harness;
mod inference;
mod parts;
mod start;
mod teardown;
mod verify;

use error::join_err;
pub use error::{LaunchError, RoleStopError, StopError};
pub(crate) use error::{stderr_text, stdout_text};
pub use harness::HarnessRequest;
pub use inference::InferenceRequest;
pub use parts::{CLEANUP_TRIES, CleanupSchedule, PinError};
use parts::{OnDrop, Owner, Subject, on_drop};
pub use start::RoleRunning;
use start::{Extra, Launched, Prepared, Recheck, Request};
pub use teardown::Sweep;

/// Longest free-text value in an audit entry (CLAUDE.md: nothing above 4 KiB is logged).
const AUDIT_TEXT_CAP: usize = 4096;
/// The style of a launch or teardown `detail` in an audit entry (architect Q288 (7, 8)): cut at
/// [`AUDIT_TEXT_CAP`] on a character boundary, unescaped, as [`capped`]. Podman's and the
/// kernel's messages can name what the sandbox wrote, so an entry declares its detail raw and
/// the writer masks it whole before the cut. The largest raw detail is a [`LaunchError`]'s
/// text over a failed command's stderr, held whole up to `OUTPUT_CAP` (64 KiB) and withheld
/// whole past it, never cut (architect Q294 c, Q295).
pub(crate) const DETAIL_STYLE: Style = Style::Plain {
    max: AUDIT_TEXT_CAP,
};
/// How long after `podman start` the container must still be running. An entry point that
/// cannot run (a missing interpreter, a crash at startup) exits well within it; a later exit is
/// the session's business (Task 12).
pub(crate) const START_GRACE: Duration = Duration::from_millis(250);

/// Where audit entries go. Appends are blocking file I/O; the launcher calls them from
/// `spawn_blocking`.
pub trait AuditSink: Send + Sync {
    /// Appends one entry at the session's audit level.
    ///
    /// # Errors
    /// The writer's error; the launcher then refuses to continue (fail closed).
    fn append(&self, entry: NewEntry, level: AuditLevel) -> Result<(), AuditError>;
}

/// The audit log shared by the broker.
#[derive(Debug)]
pub struct SharedAudit(pub Mutex<AuditWriter>);

impl AuditSink for SharedAudit {
    fn append(&self, entry: NewEntry, level: AuditLevel) -> Result<(), AuditError> {
        let mut w = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        w.append(entry, level).map(|_| ())
    }
}

/// Runs blocking work off the async runtime.
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, LaunchError> + Send + 'static,
) -> Result<T, LaunchError> {
    tokio::task::spawn_blocking(f).await.map_err(join_err)?
}

/// Cuts free text at a character boundary, as [`DETAIL_STYLE`]: for text that is not an audit
/// entry's (a control client's error message).
pub(super) fn capped(s: &str) -> String {
    sally_core::text::plain_capped(s, AUDIT_TEXT_CAP)
}

fn mode_str(m: MountMode) -> &'static str {
    match m {
        MountMode::Ro => "ro",
        MountMode::Rw => "rw",
        MountMode::Brokered => "brokered",
        MountMode::Staged => "staged",
    }
}

/// A started workspace container. Only [`Launcher::launch_workspace`] makes one.
/// [`Launcher::stop`] ends it; a handle dropped without a confirmed stop hands its container,
/// watchdog and egress listener to the launcher, which stops it in the background until it is
/// confirmed gone, holding its claims and slot meanwhile (RT-AG-08b).
#[derive(Debug)]
pub struct Running {
    container: String,
    name: String,
    paths: SessionPaths,
    level: AuditLevel,
    /// The watchdog (the cgroup observer, and the disk tasks if the sandbox can write to the
    /// host disk), set once the launch returns; stopped on drop.
    watchdog: Option<Watchdog>,
    /// The egress listener (`network.mode: proxy`); aborted on drop.
    egress: Option<EgressHandle>,
    exec_gate: Arc<tokio::sync::Mutex<()>>,
    /// The container's init: its pid and its `/proc/<pid>` directory, opened right after the
    /// mount check on that pid. Lookups through the fd fail once that process is gone, even if
    /// the pid is reused (architect ruling Q29).
    init_pid: u32,
    init_dir: Arc<rustix::fd::OwnedFd>,
    /// The launcher's free-space floor, which the file tools' own writes are held to.
    disk_floor: DiskFloor,
    /// A stop wrote its `sandbox.stop` entry: a retry does not write another.
    stop_audited: bool,
    /// Who stops it ([`Owner`]): what a drop does.
    owner: Owner,
    /// The launcher that stops it when it is dropped.
    launcher: Stopper,
}

impl Drop for Running {
    /// RT-AG-08b: a caller's handle dropped without a
    /// confirmed stop (a launch result nobody received, a lost owner) is handed whole, its
    /// watchdog and egress listener still running, to a launcher task that stops it until
    /// confirmed gone; a launcher's stop that is itself dropped is reported, never spawned
    /// again. The session's forms are not released here: they stay masked until `sallyd`
    /// exits, as a received session may still have writers (fails safe).
    fn drop(&mut self) {
        let runtime = tokio::runtime::Handle::try_current().is_ok();
        let id = self.paths.id().as_str().to_owned();
        let launcher = Arc::clone(&self.launcher.0);
        // TODO(#157): a handle `stop` handed back after removing its container (its scratch
        // removal failed) is still recorded as unconfirmed when dropped with no runtime: a
        // false unclean exit, never a missed one.
        match on_drop(self.owner, runtime) {
            OnDrop::Nothing => {}
            OnDrop::Stop => {
                let handle = self.hand_over();
                launcher.dropped(Role::Workspace, &id, &handle.name, true);
                let stopper = Arc::clone(&launcher);
                launcher.crash.spawn("sandbox.stop", async move {
                    stopper.stop_unreceived(handle).await;
                });
            }
            OnDrop::Report => launcher.left_running(Role::Workspace, &id, &self.name, true),
        }
    }
}

impl Running {
    /// Everything of this handle, moved into a new one the launcher owns; this one is ended
    /// (documentation only: it is being dropped).
    fn hand_over(&mut self) -> Self {
        self.owner = Owner::Ended;
        Self {
            container: std::mem::take(&mut self.container),
            name: std::mem::take(&mut self.name),
            paths: self.paths.clone(),
            level: self.level,
            watchdog: self.watchdog.take(),
            egress: self.egress.take(),
            exec_gate: Arc::clone(&self.exec_gate),
            init_pid: self.init_pid,
            init_dir: Arc::clone(&self.init_dir),
            disk_floor: self.disk_floor,
            stop_audited: self.stop_audited,
            owner: Owner::Launcher,
            launcher: Stopper(Arc::clone(&self.launcher.0)),
        }
    }
}

/// A handle's launcher. Its `Debug` names it only: the launcher's own `Debug` holds podman's
/// configuration text, which has no place in every stop error's `Debug`.
pub(super) struct Stopper(pub(super) Arc<Launcher>);

impl std::fmt::Debug for Stopper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Launcher")
    }
}

impl Running {
    /// The launcher's free-space floor: the one the watchdog kills at, and the one the file
    /// tools' own writes are held to (`tools::exec::session_mounts`).
    #[must_use]
    pub(crate) fn disk_floor(&self) -> DiskFloor {
        self.disk_floor
    }

    /// The container init's host pid.
    #[must_use]
    pub fn init_pid(&self) -> u32 {
        self.init_pid
    }

    /// The container init's `/proc/<pid>` directory (`O_PATH`), for the tools' view of the
    /// workspace (`tools::fs`, `tools::exec`).
    #[must_use]
    pub fn init_dir(&self) -> Arc<rustix::fd::OwnedFd> {
        Arc::clone(&self.init_dir)
    }

    /// The session's exec gate. The disk watchdog holds it while the container is frozen for a
    /// measurement, so a new `podman exec` never meets a paused container. An exec holds it only
    /// while starting: a running exec process is in the container's cgroup and freezes with it.
    /// `tools::exec` follows that contract (#24; RT-AG-09 in `tests/tools.rs`); the file tools
    /// hold it for a whole write or delete in the workspace's view (architect ruling Q29).
    #[must_use]
    pub fn exec_gate(&self) -> Arc<tokio::sync::Mutex<()>> {
        Arc::clone(&self.exec_gate)
    }

    /// The session proxy's connector for the `fetch` tool: `Some` only for a proxy-mode session
    /// whose listener loaded upstream trust roots ([`EgressHandle::connector`], architect ruling
    /// Q2). It hands out the connector only; the handle, and its shutdown, stay here (#103).
    #[must_use]
    pub fn fetch_connector(&self) -> Option<Arc<dyn Connector>> {
        self.egress.as_ref().and_then(EgressHandle::connector)
    }

    /// Podman's container id (64 hex digits).
    #[must_use]
    pub fn container(&self) -> &str {
        &self.container
    }

    /// The container name, `sp-ws-<session id>`.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The session's directories.
    #[must_use]
    pub fn paths(&self) -> &SessionPaths {
        &self.paths
    }
}

/// Proof that a workspace's stop succeeded: its container confirmed gone, its tunnels closed,
/// its scratch removed and its claims released. Only [`Launcher::stop`] makes one, on its Ok
/// path, and only [`Launcher::close`] takes it, so a received session's `session.closed` and
/// the release of its forms follow a confirmed stop by construction (#94, architect Q252). No
/// `Clone` and no public constructor.
#[derive(Debug)]
#[must_use = "dropping it skips the session's `session.closed` and the release of its forms"]
pub struct Confirmed {
    id: String,
    level: AuditLevel,
}

/// What a workspace launch needs.
#[derive(Debug, Clone)]
pub struct WorkspaceRequest {
    /// The session's directories.
    pub paths: SessionPaths,
    /// The validated manifest.
    pub manifest: Arc<ValidatedManifest>,
    /// The bundled workspace image, used when the manifest names none. `None` while no bundled
    /// image is installed: such a launch is refused `no-default-image` before anything is
    /// reserved (architect Q58; TODO(#88)).
    pub default_image: Option<ImageRef>,
    /// The session's crash reporter: a panic in its disk watchdog is reported here (architect
    /// Q47).
    pub crash: CrashReporter,
}

/// Where a launcher's collaborators come from.
pub struct LauncherParts {
    /// Hermetic podman.
    pub podman: Podman,
    /// The checked runtime.
    pub runtime: CheckedRuntime,
    /// The host user.
    pub ids: UserIds,
    /// `$XDG_RUNTIME_DIR`.
    pub xdg_runtime_dir: PathBuf,
    /// Sallyport's data root, `~/.local/share/sallyport`: an inference instance's profiles go
    /// under `infer/<id>` in it (architect Q140).
    pub data_dir: PathBuf,
    /// Live sessions.
    pub sessions: Arc<Sessions>,
    /// The audit log.
    pub audit: Arc<dyn AuditSink>,
    /// Scan bounds.
    pub limits: ScanLimits,
    /// The free-space floor (`DiskFloor::default()` unless configured).
    pub disk_floor: DiskFloor,
    /// Starts each proxy-mode session's egress listener ([`crate::session::lookup::SharedEgress`]
    /// in production; tests pass fakes through the same field).
    pub egress: Arc<dyn EgressStarter>,
    /// The live sessions' secrets, for the audit and operational logs' redactors: a session's
    /// forms are registered as soon as its egress has loaded them (architect Q219).
    pub redactors: Arc<Redactors>,
    /// The operational log: an audit entry that cannot be written while the launcher acts
    /// anyway (a kill, a retried stop) gets an error line here (architect Q43).
    pub oplog: Oplog,
    /// This installation's id (`daemon::install`): the label of every container this launcher
    /// creates, and the only one its orphan sweeps remove (Q64).
    pub installation: Installation,
    /// The daemon's crash reporter: a failed launch's cleanup retried in its own task, and the
    /// stop of a container whose handle was dropped (task `sandbox.stop`), report a panic
    /// there, which stops the daemon. Not a session's: a refused session has no reporter left.
    pub crash: CrashReporter,
    /// The pauses of a failed launch's cleanup retries, and of the stops that retry until
    /// confirmed (their last pause repeating): `sallyd` passes [`CleanupSchedule::PRODUCTION`].
    pub cleanup: CleanupSchedule,
}

/// Launches and tears down sandboxes for one `sallyd`. Shared as `Arc<Launcher>`.
pub struct Launcher {
    pub(super) podman: Podman,
    runtime: CheckedRuntime,
    ids: UserIds,
    xdg_runtime_dir: PathBuf,
    data_dir: PathBuf,
    sessions: Arc<Sessions>,
    audit: Arc<dyn AuditSink>,
    limits: ScanLimits,
    pub(super) disk_floor: DiskFloor,
    egress: Arc<dyn EgressStarter>,
    redactors: Arc<Redactors>,
    oplog: Oplog,
    pub(super) installation: Installation,
    crash: CrashReporter,
    cleanup: CleanupSchedule,
    /// By role and id (a workspace and a harness share their session's id), the containers
    /// this launcher is removing and has not confirmed gone: a failed launch's probe or
    /// container (in before the first cleanup try, out once both are confirmed gone, never at
    /// the cleanup's cap), and a started container nobody holds (a dropped handle, a launch
    /// result nobody received: in before its stop, out once it is confirmed gone). Shutdown
    /// reads it ([`Self::unconfirmed_containers`]) and waits for none.
    unfinished: Mutex<BTreeSet<(&'static str, String)>>,
    /// One stage walk at a time across all sessions, so a sandbox with a huge or deep tree
    /// cannot multiply `sallyd`'s open fds or blocking threads (6c-1 review M2/M3).
    pub(super) walks: Arc<tokio::sync::Semaphore>,
}

impl std::fmt::Debug for Launcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Launcher")
            .field("podman", &self.podman)
            .field("runtime", &self.runtime)
            .finish_non_exhaustive()
    }
}

/// How far a failed launch got, so cleanup removes exactly what it made.
#[derive(Debug, Default)]
struct Progress {
    /// The directories this launch may create: cleanup refuses to remove any other.
    owned: Vec<PathBuf>,
    /// Directories this launch created (and only those).
    dirs: Vec<PathBuf>,
    /// The mount-link probe's name, recorded before its `create` and cleared once it is
    /// confirmed gone, so a failed launch removes it too.
    probe: Option<String>,
    container: Option<String>,
}

impl Launcher {
    /// A launcher.
    #[must_use]
    pub fn new(p: LauncherParts) -> Arc<Self> {
        Arc::new(Self {
            podman: p.podman,
            runtime: p.runtime,
            ids: p.ids,
            xdg_runtime_dir: p.xdg_runtime_dir,
            data_dir: p.data_dir,
            sessions: p.sessions,
            audit: p.audit,
            limits: p.limits,
            disk_floor: p.disk_floor,
            egress: p.egress,
            redactors: p.redactors,
            oplog: p.oplog,
            installation: p.installation,
            crash: p.crash,
            cleanup: p.cleanup,
            unfinished: Mutex::new(BTreeSet::new()),
            walks: Arc::new(tokio::sync::Semaphore::new(1)),
        })
    }

    /// The ids whose containers this launcher is removing and has not confirmed gone now: a
    /// failed launch's cleanup still retrying or abandoned at its cap, and the stop of a
    /// started container nobody holds. Sorted. Shutdown reports these as not stopped cleanly,
    /// without waiting for any (THREAT_MODEL #239 row; RT-AG-08b).
    #[must_use]
    pub fn unconfirmed_containers(&self) -> Vec<String> {
        let ids: BTreeSet<String> = lock(&self.unfinished)
            .iter()
            .map(|(_, id)| id.clone())
            .collect();
        ids.into_iter().collect()
    }

    /// The launcher begins removing `role`'s container of `id` (a failed launch's cleanup, or
    /// the stop of one nobody holds): it may be left behind. Idempotent.
    fn cleanup_begins(&self, role: Role, id: &str) {
        lock(&self.unfinished).insert((role.as_str(), id.to_owned()));
    }

    /// `role`'s container of `id` (and a failed launch's probe) is confirmed gone.
    fn cleanup_confirmed(&self, role: Role, id: &str) {
        lock(&self.unfinished).remove(&(role.as_str(), id.to_owned()));
    }

    /// A caller's handle of `role`'s container of `id` was dropped without a confirmed stop
    /// (RT-AG-08b): one oplog line, and, while the container `may_exist` (not removed by an
    /// earlier stop), the id joins the unconfirmed containers before the launcher's stop is
    /// spawned.
    fn dropped(&self, role: Role, id: &str, container: &str, may_exist: bool) {
        self.oplog.warn(
            "sandbox",
            "a container's handle was dropped without a stop; the launcher stops it",
            &[
                ("role", role.as_str()),
                ("id", id),
                ("container", container),
            ],
        );
        if may_exist {
            self.cleanup_begins(role, id);
        }
    }

    /// A handle of `role`'s container of `id` was dropped with no stop to come: no runtime to
    /// spawn one on, or the launcher's own stop cut short (a runtime shutting down). One oplog
    /// error line; while the container `may_exist`, the id stays among the unconfirmed
    /// containers.
    fn left_running(&self, role: Role, id: &str, container: &str, may_exist: bool) {
        let fields = [
            ("role", role.as_str()),
            ("id", id),
            ("container", container),
        ];
        if may_exist {
            self.oplog.error(
                "sandbox",
                "container not confirmed gone, left to the next start's sweep",
                &fields,
            );
            self.cleanup_begins(role, id);
        } else {
            // An earlier stop removed it: only its entry or directories were left to do.
            self.oplog.warn(
                "sandbox",
                "a removed container's stop left unfinished (entry or directories)",
                &fields,
            );
        }
    }

    /// The pause after failed round `round` of a stop that retries until its container is
    /// confirmed gone: the launcher's cleanup schedule, its last pause repeating (RT-AUD-03).
    #[must_use]
    pub(crate) fn stop_pause(&self, round: u32) -> Duration {
        self.cleanup.stop_pause(round)
    }
}

/// A set guarded by a mutex, poisoned or not: a panic elsewhere must not hide what is left.
fn lock<V>(m: &Mutex<V>) -> std::sync::MutexGuard<'_, V> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Launcher {
    /// The session's last entry, `session.closed {reason}`, written once its teardown has
    /// finished, which `done` proves (#94, architect Q242, Q245, Q252). Then its secrets leave
    /// the logs' redactors (Q219). The registry calls it once per `Running` it received; a
    /// launch the launcher refused or stopped itself gets none. A refused append is an oplog
    /// line naming only the session and the event, and the forms are released anyway: the
    /// stop is done (Q243). RT-AUD-03 (`tests/closed.rs`).
    pub async fn close(&self, done: Confirmed, reason: StopReason) {
        let Confirmed { id, level } = done;
        let entry = NewEntry::new(Actor::Sallyd, "session.closed")
            .session(&id)
            .args(json!({"reason": reason.as_str()}));
        if self.audit(entry, level).await.is_err() {
            self.unaudited("session.closed", &id);
        }
        self.release_secrets(&id).await;
    }

    /// Drops session `id`'s secrets from the logs' redactors, once its last entry is written:
    /// after `sandbox.refuse` for a refused launch (after `sandbox.cleaned` or
    /// `sandbox.cleanup_abandoned` when its cleanup was retried), after `session.closed`
    /// ([`Self::close`]) for a session (architect Q219). Safe to call more than once. Off the
    /// runtime: the swap takes the audit writer's lock, which an append holds through its fsync.
    async fn release_secrets(&self, id: &str) {
        let redactors = Arc::clone(&self.redactors);
        let owned = id.to_owned();
        if tokio::task::spawn_blocking(move || redactors.unregister(&owned))
            .await
            .is_err()
        {
            // A panic or a runtime shutdown: the values stay redacted (fails safe).
            self.oplog.error(
                "sandbox",
                "a session's secrets release did not finish",
                &[("session", id)],
            );
        }
    }

    /// The oplog line for a session's cgroup event files that stopped being readable, which
    /// they do once the container has ended (the observer stops; architect Q48).
    pub(super) fn events_unreadable(&self, sid: &str, detail: &str) {
        self.oplog.info(
            "sandbox",
            "cgroup events no longer readable",
            &[("session", sid), ("detail", detail)],
        );
    }

    /// The oplog line for an audit entry that could not be written while the launcher went on
    /// (the action is still taken: a kill, a stop retry).
    pub(super) fn unaudited(&self, event: &str, sid: &str) {
        self.oplog.error(
            "sandbox",
            "audit entry not written",
            &[("event", event), ("session", sid)],
        );
    }

    pub(super) async fn audit(
        &self,
        entry: NewEntry,
        level: AuditLevel,
    ) -> Result<(), LaunchError> {
        let sink = Arc::clone(&self.audit);
        tokio::task::spawn_blocking(move || sink.append(entry, level))
            .await
            .map_err(join_err)?
            .map_err(LaunchError::Audit)
    }

    /// Launches the workspace container of a session and starts it once every check passed.
    /// The work runs in its own task: dropping the returned future does not interrupt it, and a
    /// launch that finishes after its caller went away is stopped again.
    ///
    /// # Errors
    /// [`LaunchError`]; what was created is removed and `sandbox.refuse` (or
    /// `sandbox.mount_mismatch`) is audited. The one exception is [`LaunchError::Lost`] (the
    /// launch task ended without a result): it has no launcher entry, so its caller writes one
    /// (architect Q98).
    pub async fn launch_workspace(
        self: &Arc<Self>,
        req: WorkspaceRequest,
    ) -> Result<Running, LaunchError> {
        let sid = req.paths.id().clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let this = Arc::clone(self);
        let crash = req.crash.clone();
        tokio::spawn(async move {
            let req = Request::Workspace(req);
            let result = match this.launch_role(&req).await {
                Ok(Launched::Workspace(w)) => {
                    let (mut r, watch) = *w;
                    let target = Target {
                        sid: r.paths.id().as_str().to_owned(),
                        container: r.container.clone(),
                        level: r.level,
                        exec_gate: Arc::clone(&r.exec_gate),
                    };
                    r.watchdog = Some(Watchdog::spawn(
                        &this,
                        target,
                        watch.plan,
                        watch.observed,
                        &crash,
                    ));
                    Ok(r)
                }
                Ok(Launched::Role(r)) => {
                    this.stop_role_unreceived(r).await;
                    Err(this.wrong_handle(&req).await)
                }
                Err(e) => Err(e),
            };
            if let Err(Ok(orphan)) = tx.send(result) {
                let id = orphan.paths.id().as_str().to_owned();
                this.stop_unreceived(orphan).await;
                this.release_secrets(&id).await;
            }
        });
        // A result sent but never received is stopped by its handle's drop (RT-AG-08b); its
        // forms stay registered until `sallyd` exits (fails safe).
        // TODO(#113): a panic in the launch task before its handle exists (between `podman
        // create` and the handle) leaves its container, claim and live id to the next start.
        error::received(rx, sid).await
    }

    /// The workspace's step 0 and step 1: the image (architect Q58), before anything is
    /// reserved or created; then the session's mounts and descriptors, reserved.
    async fn admit_workspace(&self, req: &WorkspaceRequest) -> Result<ImageRef, LaunchError> {
        let image = req.image()?;
        let v = Arc::clone(&req.manifest);
        let fds = session_cost(req.manifest.manifest().network.max_connections);
        let c = blocking(move || claims(&v).map_err(LaunchError::Claims)).await?;
        self.sessions.reserve(req.paths.id().as_str(), c, fds)?;
        Ok(image)
    }

    /// Audits a refusal; returns the error to report (the original, or both when the audit
    /// entry fails too).
    async fn refused(
        &self,
        subject: &Subject,
        role: Role,
        e: LaunchError,
        level: AuditLevel,
        cleanup: String,
    ) -> LaunchError {
        let entry = subject
            .entry(e.event(), role, [("reason", e.reason().into())])
            .text("detail", e.to_string(), DETAIL_STYLE)
            .text("cleanup", cleanup, DETAIL_STYLE)
            .decision("deny");
        match self.audit(entry, level).await {
            Ok(()) => e,
            Err(a) => LaunchError::Unaudited {
                original: Box::new(e),
                audit: Box::new(a),
            },
        }
    }

    /// Steps 2 and 3 of the workspace (module docs), after the shared re-check of podman and
    /// the runtime.
    async fn prepare_workspace(
        &self,
        req: &WorkspaceRequest,
        image: &ImageRef,
        runtime: CheckedRuntime,
        progress: &mut Progress,
    ) -> Result<(Prepared, Extra), LaunchError> {
        let (scan, plan) = self.scan(req).await?;
        let image = self.image_present(image).await?;
        let built = self.dirs_and_argv(req, runtime, &scan, progress).await?;
        let egress = self.start_egress(req).await?;
        let mounts: Vec<_> = req
            .manifest
            .mounts()
            .iter()
            .map(|x| json!({"guest": x.guest, "mode": mode_str(x.mode)}))
            .collect();
        let shields: usize = scan
            .git()
            .iter()
            .map(|g| g.dirs().len() + g.files().len())
            .sum();
        let sid = req.paths.id();
        let prepared = Prepared {
            subject: Subject::Session(sid.clone()),
            level: req.manifest.manifest().audit.level,
            name: format!("sp-ws-{}", sid.as_str()),
            launch_args: vec![
                ("image", image.as_str().into()),
                ("mounts", mounts.into()),
                ("git_shields", shields.into()),
            ],
            image,
            built,
            recheck: Recheck::Scan(scan, Arc::clone(&req.manifest)),
        };
        let extra = Extra::Workspace {
            egress,
            plan,
            paths: req.paths.clone(),
        };
        Ok((prepared, extra))
    }

    /// Step 3a: the session's egress listener on `net.sock`, for `network.mode: proxy` only. A
    /// session with secret grants first gets its session CA and the two CA files (off the
    /// runtime: the trust roots are read from disk), before the container exists.
    async fn start_egress(
        &self,
        req: &WorkspaceRequest,
    ) -> Result<Option<EgressHandle>, LaunchError> {
        if req.manifest.manifest().network.mode != NetworkMode::Proxy {
            return Ok(None);
        }
        let dir = req.paths.workspace_sockets();
        let sock = dir.join(NET_SOCK);
        let s = SessionEgress::from_manifest(
            &req.manifest,
            req.paths.id().as_str(),
            Arc::clone(&self.audit),
        );
        let egress = Arc::clone(&self.egress);
        let (redactors, id) = (
            Arc::clone(&self.redactors),
            req.paths.id().as_str().to_owned(),
        );
        // The forms are registered in the same closure that loaded them: no await point between,
        // and before `net.sock` is bound or the container exists (architect Q219). The session's
        // egress entries are redacted with its own forms too, so one that lands after the
        // release is still redacted (Q249, Q278).
        let s = blocking(move || {
            let mut s = egress.prepare(&dir, s).map_err(LaunchError::Egress)?;
            if let Some(i) = &s.interception {
                let redaction = Arc::clone(i.credentials().redaction());
                redactors.register(&id, Arc::clone(redaction.forms()));
                s.audit = Arc::new(SessionRedacted::over(s.audit, redaction));
            }
            Ok(s)
        })
        .await?;
        self.egress
            .start(&sock, s)
            .map(Some)
            .map_err(|e| LaunchError::Egress(EgressError::Listener(e)))
    }

    /// Step 2, after the shared re-check of podman and the runtime: the launch scan, then the
    /// free-space check of every filesystem the sandbox could write to (`disk.rs`).
    async fn scan(
        &self,
        req: &WorkspaceRequest,
    ) -> Result<(LaunchScan, Option<WatchPlan>), LaunchError> {
        let (limits, floor) = (self.limits, self.disk_floor);
        let (v, paths) = (Arc::clone(&req.manifest), req.paths.clone());
        blocking(move || {
            let scan = scan_mounts(&v, &limits)?;
            let plan = watch_plan(&v, &paths, &scan, &floor)?;
            Ok((scan, plan))
        })
        .await
    }

    /// Step 3. Records in `progress` whether directories were created, so a failure removes
    /// them and never a stopped session's kept data.
    async fn dirs_and_argv(
        &self,
        req: &WorkspaceRequest,
        runtime: CheckedRuntime,
        scan: &LaunchScan,
        progress: &mut Progress,
    ) -> Result<Built, LaunchError> {
        let staged = staged_indices(&req.manifest);
        let overlays = scan.git().iter().map(|g| g.dirs().len()).sum();
        let (paths, xdg) = (req.paths.clone(), self.xdg_runtime_dir.clone());
        let created =
            blocking(move || Ok(SessionDirs::create(&paths, &xdg, &staged, overlays))).await?;
        progress.dirs = match &created {
            Ok(_) => vec![
                req.paths.socket_root().to_owned(),
                req.paths.data_root().to_owned(),
            ],
            Err(e) => e.created.clone(),
        };
        let dirs = created?;
        let common = self.common_args(runtime, dirs.profiles().to_owned());
        Ok(workspace_build(
            &common,
            &req.paths,
            &req.manifest,
            scan,
            req.default_image.as_ref(),
        )?)
    }
}

#[cfg(test)]
mod tests;
