//! Launch and teardown of the workspace container (Task 6b; ARCHITECTURE §3.5). Order matters:
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
//! 4. audit `sandbox.launch` (SI-4: before anything is visible);
//! 5. `podman create`; re-check every pin on the host; `podman init` (the runtime builds the
//!    mounts but runs nothing);
//! 6. compare every bind pin inside the container's mount namespace (B4); on a mismatch remove the
//!    container and audit `sandbox.mount_mismatch`;
//! 7. `podman start`, then confirm after a short grace that the container is running with the
//!    pid that was checked (`start` succeeds even when the entry point exits at once).
//!
//! A session whose sandbox can write to the host disk (`staged` mounts, `.git` overlays) gets a
//! watchdog that kills it when those writes exceed `runtime.stage_size` (#14; `watchdog.rs`).
//!
//! The launch runs in its own task: a caller that goes away (a closed connection, an outer
//! timeout) cannot leave a half-built session, and a finished launch nobody receives is stopped.
//! A failure removes the container by its name (even when `create` printed no id), removes only
//! the directories this launch created, and keeps the session's overlap claims while a container
//! might still exist. TODO(#15): the OCI config verifier runs between 6 and 7 (Task 14).

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sally_core::audit::{Actor, AuditError, AuditWriter, NewEntry};
use sally_core::manifest::{AuditLevel, MountMode, NetworkMode, ValidatedManifest};
use serde_json::json;

use crate::egress::net::{EgressError, EgressHandle, EgressStarter, NET_SOCK, SessionEgress};

use super::argv::workspace_argv;
use super::commands::container_id;
use super::dirs::SessionDirs;
use super::disk::DiskFloor;
use super::inside::{Expect, check_in_container};
use super::overlap::{Sessions, claims};
use super::podman::{Podman, PodmanError};
use super::scan::{LaunchScan, PinKind, ScanLimits, scan_mounts};
use super::types::{CheckedRuntime, CommonArgs, ImageRef, SessionPaths, UserIds};
use super::watchdog::{Target, WatchPlan, Watchdog, watch_plan};

mod error;
mod teardown;

use error::join_err;
pub use error::{LaunchError, StopError};

/// Longest free-text value in an audit entry (CLAUDE.md: nothing above 4 KiB is logged).
const AUDIT_TEXT_CAP: usize = 4096;
/// How long after `podman start` the container must still be running. An entry point that
/// cannot run (a missing interpreter, a crash at startup) exits well within it; a later exit is
/// the session's business (Task 12).
const START_GRACE: Duration = Duration::from_millis(250);
/// How often a launch nobody received retries its `stop`.
const STOP_RETRY: Duration = Duration::from_secs(2);
/// Container name prefixes of the session roles this launcher creates.
const SESSION_PREFIXES: [&str; 2] = ["sp-ws-", "sp-h-"];

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

/// Cuts free text for an audit entry at a character boundary.
pub(super) fn capped(s: &str) -> String {
    if s.len() <= AUDIT_TEXT_CAP {
        return s.to_owned();
    }
    let mut end = AUDIT_TEXT_CAP;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", s.get(..end).unwrap_or_default())
}

fn mode_str(m: MountMode) -> &'static str {
    match m {
        MountMode::Ro => "ro",
        MountMode::Rw => "rw",
        MountMode::Brokered => "brokered",
        MountMode::Staged => "staged",
    }
}

/// A started workspace container. Only [`Launcher::launch_workspace`] makes one, and only
/// [`Launcher::stop`] ends it.
#[derive(Debug)]
pub struct Running {
    container: String,
    name: String,
    paths: SessionPaths,
    level: AuditLevel,
    /// The disk watchdog, if the sandbox can write to the host disk; stopped on drop.
    watchdog: Option<Watchdog>,
    /// The egress listener (`network.mode: proxy`); aborted on drop.
    egress: Option<EgressHandle>,
    exec_gate: Arc<tokio::sync::Mutex<()>>,
}

impl Running {
    /// The session's exec gate. The disk watchdog holds it while the container is frozen for a
    /// measurement, so a new `podman exec` never meets a paused container. An exec holds it only
    /// while starting: a running exec process is in the container's cgroup and freezes with it.
    /// TODO(#24): the shell tool (Task 11) follows that contract and gets an RT case.
    #[must_use]
    pub fn exec_gate(&self) -> Arc<tokio::sync::Mutex<()>> {
        Arc::clone(&self.exec_gate)
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

/// What a workspace launch needs.
#[derive(Debug, Clone)]
pub struct WorkspaceRequest {
    /// The session's directories.
    pub paths: SessionPaths,
    /// The validated manifest.
    pub manifest: Arc<ValidatedManifest>,
    /// The bundled workspace image, used when the manifest names none.
    pub default_image: ImageRef,
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
    /// Live sessions.
    pub sessions: Arc<Sessions>,
    /// The audit log.
    pub audit: Arc<dyn AuditSink>,
    /// Scan bounds.
    pub limits: ScanLimits,
    /// The free-space floor (`DiskFloor::default()` unless configured).
    pub disk_floor: DiskFloor,
    /// Starts each proxy-mode session's egress listener ([`crate::egress::net::SystemEgress`] in
    /// production; tests pass fakes through the same field).
    pub egress: Arc<dyn EgressStarter>,
}

/// Launches and tears down sandboxes for one `sallyd`. Shared as `Arc<Launcher>`.
pub struct Launcher {
    pub(super) podman: Podman,
    runtime: CheckedRuntime,
    ids: UserIds,
    xdg_runtime_dir: PathBuf,
    sessions: Arc<Sessions>,
    audit: Arc<dyn AuditSink>,
    limits: ScanLimits,
    pub(super) disk_floor: DiskFloor,
    egress: Arc<dyn EgressStarter>,
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
    /// Session directories this launch created (and only those).
    dirs: Vec<PathBuf>,
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
            sessions: p.sessions,
            audit: p.audit,
            limits: p.limits,
            disk_floor: p.disk_floor,
            egress: p.egress,
            walks: Arc::new(tokio::sync::Semaphore::new(1)),
        })
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
    /// `sandbox.mount_mismatch`) is audited.
    pub async fn launch_workspace(
        self: &Arc<Self>,
        req: WorkspaceRequest,
    ) -> Result<Running, LaunchError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let result = this.launch(req).await.map(|(mut r, plan)| {
                r.watchdog = plan.map(|plan| {
                    let target = Target {
                        sid: r.paths.id().as_str().to_owned(),
                        container: r.container.clone(),
                        level: r.level,
                        exec_gate: Arc::clone(&r.exec_gate),
                    };
                    Watchdog::spawn(&this, target, plan)
                });
                r
            });
            if let Err(Ok(orphan)) = tx.send(result) {
                this.stop_unreceived(orphan).await;
            }
        });
        rx.await
            .map_err(|_| LaunchError::Internal("the launch task ended without a result".into()))?
    }

    async fn launch(
        &self,
        req: WorkspaceRequest,
    ) -> Result<(Running, Option<WatchPlan>), LaunchError> {
        let level = req.manifest.manifest().audit.level;
        let sid = req.paths.id().as_str().to_owned();
        let v = Arc::clone(&req.manifest);
        let reserved = match blocking(move || claims(&v).map_err(LaunchError::Claims)).await {
            Ok(c) => self.sessions.reserve(&sid, c).map_err(LaunchError::from),
            Err(e) => Err(e),
        };
        if let Err(e) = reserved {
            return Err(self
                .refused(&sid, e, level, "nothing to clean up".into())
                .await);
        }
        let mut progress = Progress::default();
        match self.launch_reserved(&req, level, &mut progress).await {
            Ok(r) => Ok(r),
            Err(e) => {
                let cleanup = self.clean_failed(&req.paths, &progress).await;
                let outcome = match &cleanup {
                    Ok(()) => "removed".to_owned(),
                    Err(c) => format!("incomplete, the session stays reserved: {c}"),
                };
                if cleanup.is_ok() {
                    self.sessions.release(&sid);
                }
                Err(self.refused(&sid, e, level, outcome).await)
            }
        }
    }

    /// Audits a refusal; returns the error to report (the original, or both when the audit
    /// entry fails too).
    async fn refused(
        &self,
        sid: &str,
        e: LaunchError,
        level: AuditLevel,
        cleanup: String,
    ) -> LaunchError {
        let event = if matches!(e, LaunchError::MountMismatch(_)) {
            "sandbox.mount_mismatch"
        } else {
            "sandbox.refuse"
        };
        let entry = NewEntry::new(Actor::Sallyd, event)
            .session(sid)
            .decision("deny")
            .args(json!({
                "role": "workspace",
                "reason": e.reason(),
                "detail": capped(&e.to_string()),
                "cleanup": capped(&cleanup),
            }));
        match self.audit(entry, level).await {
            Ok(()) => e,
            Err(a) => LaunchError::Unaudited {
                original: Box::new(e),
                audit: Box::new(a),
            },
        }
    }

    async fn launch_reserved(
        &self,
        req: &WorkspaceRequest,
        level: AuditLevel,
        progress: &mut Progress,
    ) -> Result<(Running, Option<WatchPlan>), LaunchError> {
        let (runtime, scan, plan) = self.check_and_scan(req).await?;
        let image = req.image();
        self.image_present(image).await?;
        let argv = self.dirs_and_argv(req, runtime, &scan, progress).await?;
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
        self.audit(
            NewEntry::new(Actor::Sallyd, "sandbox.launch")
                .session(req.paths.id().as_str())
                .decision("allow")
                .args(json!({
                    "role": "workspace",
                    "image": image,
                    "mounts": mounts,
                    "git_shields": shields,
                })),
            level,
        )
        .await?;
        let name = format!("sp-ws-{}", req.paths.id().as_str());
        progress.container = Some(name.clone());
        let out = self
            .run("create", argv.into_iter().map(OsString::from))
            .await?;
        let container = container_id(&out)?;
        if let Err(e) = self.checked_start(req, scan, &container).await {
            // The container may have run long enough to open a tunnel: stop the listener in
            // order, so every `egress.allow` gets its `egress.close`.
            if let Some(h) = egress {
                h.shutdown().await;
            }
            return Err(e);
        }
        let running = Running {
            container,
            name,
            paths: req.paths.clone(),
            level,
            watchdog: None,
            egress,
            exec_gate: Arc::new(tokio::sync::Mutex::new(())),
        };
        Ok((running, plan))
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
        let s = blocking(move || egress.prepare(&dir, s).map_err(LaunchError::Egress)).await?;
        self.egress
            .start(&sock, s)
            .map(Some)
            .map_err(|e| LaunchError::Egress(EgressError::Listener(e)))
    }

    /// Step 2: hermetic podman and the runtime re-checked, then the launch scan, then the
    /// free-space check of every filesystem the sandbox could write to (`disk.rs`).
    async fn check_and_scan(
        &self,
        req: &WorkspaceRequest,
    ) -> Result<(CheckedRuntime, LaunchScan, Option<WatchPlan>), LaunchError> {
        let podman = self.podman.clone();
        let runtime = self.runtime.path().to_owned();
        let (limits, floor) = (self.limits, self.disk_floor);
        let (v, paths) = (Arc::clone(&req.manifest), req.paths.clone());
        blocking(move || {
            podman.recheck()?;
            let runtime = CheckedRuntime::check(&runtime)
                .map_err(|e| LaunchError::Podman(PodmanError::Binary(e)))?;
            let scan = scan_mounts(&v, &limits)?;
            let plan = watch_plan(&v, &paths, &scan, &floor)?;
            Ok((runtime, scan, plan))
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
    ) -> Result<Vec<String>, LaunchError> {
        let staged: Vec<usize> = req
            .manifest
            .mounts()
            .iter()
            .enumerate()
            .filter(|(_, m)| m.mode == MountMode::Staged)
            .map(|(i, _)| i)
            .collect();
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
        let common = CommonArgs {
            runtime,
            ids: self.ids,
            profiles: dirs.profiles().to_owned(),
            hooks_dir: self.podman.hooks_dir(),
            mounts_file: self.podman.mounts_file(),
        };
        Ok(workspace_argv(
            &common,
            &req.paths,
            &req.manifest,
            scan,
            &req.default_image,
        )?)
    }

    /// Steps 5 (after create) to 7.
    async fn checked_start(
        &self,
        req: &WorkspaceRequest,
        scan: LaunchScan,
        container: &str,
    ) -> Result<(), LaunchError> {
        let v = Arc::clone(&req.manifest);
        let expect: Vec<Expect> = scan
            .pins()
            .iter()
            .filter(|p| p.kind == PinKind::Bind)
            .map(|p| Expect {
                guest: p.guest.clone(),
                dev: p.dev,
                ino: p.ino,
            })
            .collect();
        blocking(move || Ok(scan.recheck_host(&v)?)).await?;
        self.run("init", [OsString::from("init"), container.into()])
            .await?;
        let pid = self.init_pid(container).await?;
        blocking(move || check_in_container(pid, &expect).map_err(LaunchError::MountMismatch))
            .await?;
        self.run("start", [OsString::from("start"), container.into()])
            .await?;
        tokio::time::sleep(START_GRACE).await;
        self.confirm_running(container, pid).await
    }

    /// Step 7: the container still runs, as the process whose mounts were checked. A container
    /// that exited is already gone (`--rm`), so a failed inspect means "not running" too.
    async fn confirm_running(&self, container: &str, pid: u32) -> Result<(), LaunchError> {
        let state = self
            .run(
                "inspect",
                [
                    "inspect".into(),
                    "--format".into(),
                    "{{.State.Running}} {{.State.Pid}}".into(),
                    container.into(),
                ],
            )
            .await
            .map_err(|e| LaunchError::NotRunning(e.to_string()))?;
        running_as(&state, pid)
    }

    async fn init_pid(&self, container: &str) -> Result<u32, LaunchError> {
        let out = self
            .run(
                "inspect",
                [
                    "inspect".into(),
                    "--format".into(),
                    "{{.State.Pid}}".into(),
                    container.into(),
                ],
            )
            .await?;
        match out.trim().parse::<u32>() {
            Ok(pid) if pid > 1 => Ok(pid),
            _ => Err(LaunchError::Command {
                verb: "inspect",
                msg: format!("unexpected pid {:?}", out.trim()),
            }),
        }
    }
}

/// `podman inspect` printed `true <pid>` with the pid checked after `init`.
fn running_as(state: &str, pid: u32) -> Result<(), LaunchError> {
    if state.trim() == format!("true {pid}") {
        Ok(())
    } else {
        Err(LaunchError::NotRunning(format!(
            "state {:?}, expected running as pid {pid}",
            capped(state.trim())
        )))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn audit_text_is_capped_at_a_character_boundary() {
        assert_eq!(capped("short"), "short");
        let long = "é".repeat(AUDIT_TEXT_CAP);
        let c = capped(&long);
        assert!(c.len() <= AUDIT_TEXT_CAP + "…".len());
        assert!(c.ends_with('…'));
    }

    #[test]
    fn only_running_as_the_checked_pid_counts() {
        assert!(running_as("true 42\n", 42).is_ok());
        for bad in ["false 0", "true 43", "true 42 x", "", "TRUE 42"] {
            let e = running_as(bad, 42).unwrap_err();
            assert!(matches!(e, LaunchError::NotRunning(_)), "{bad:?}");
            assert_eq!(e.reason(), "not-running");
        }
    }

    #[test]
    fn a_listener_failure_has_its_own_reason() {
        let e = LaunchError::Egress(EgressError::Listener(std::io::ErrorKind::AddrInUse.into()));
        assert_eq!(e.reason(), "egress-listener");
        assert!(e.to_string().starts_with("network: net.sock: "), "{e}");
    }

    #[test]
    fn missing_trust_roots_and_a_failed_session_ca_have_their_own_reasons() {
        use crate::egress::ca::CaError;
        use crate::egress::roots::RootsError;
        let roots = LaunchError::Egress(RootsError::NotFound("/x".into()).into());
        assert_eq!(roots.reason(), "trust-roots");
        assert!(
            roots.to_string().starts_with("network: trust roots: "),
            "{roots}"
        );
        let ca = LaunchError::Egress(CaError::NoHosts.into());
        assert_eq!(ca.reason(), "session-ca");
        let files =
            LaunchError::Egress(EgressError::Files(std::io::ErrorKind::AlreadyExists.into()));
        assert_eq!(files.reason(), "session-ca");
        assert!(
            files.to_string().starts_with("network: CA files: "),
            "{files}"
        );
    }
}
