//! Launch and teardown of the workspace container (Task 6b). Order matters:
//!
//! 1. reserve the session's mounts against every live session (B4 overlap rule);
//! 2. re-check the runtime and the empty hooks directory; scan every mount (sockets, `.git`
//!    shields, pins); create the 0700 session directories and write the seccomp profiles;
//! 3. build and check the argv (`create`, never `run`);
//! 4. audit `sandbox.launch` (SI-4: before anything is visible);
//! 5. `podman create`; re-check every pin on the host; `podman init` (the runtime builds the
//!    mounts but runs nothing);
//! 6. compare every bind pin inside the container's mount namespace (B4); on a mismatch remove the
//!    container and audit `sandbox.mount_mismatch`;
//! 7. `podman start`.
//!
//! Any failure after step 1 removes what was created and audits `sandbox.refuse`. TODO(#15): the
//! OCI config verifier runs between 6 and 7 (Task 14).

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sally_core::audit::{Actor, AuditError, AuditWriter, NewEntry};
use sally_core::manifest::{AuditLevel, MountMode, ValidatedManifest};
use serde_json::json;
use tokio::io::{AsyncRead, AsyncReadExt as _};

use super::argv::{path_arg, workspace_argv};
use super::dirs::{DirError, SessionDirs};
use super::inside::{Expect, Mismatch, check_in_container};
use super::overlap::{ReserveError, Sessions, claims};
use super::podman::{Podman, PodmanError};
use super::scan::{LaunchScan, PinKind, ScanError, ScanLimits, scan_mounts};
use super::types::{ArgvError, CheckedRuntime, CommonArgs, ImageRef, SessionPaths, UserIds};

/// Bytes of podman's stdout and stderr kept per command; the rest is read and dropped.
const OUTPUT_CAP: usize = 64 * 1024;
/// A podman command that takes longer is killed.
const PODMAN_TIMEOUT: Duration = Duration::from_secs(120);

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

/// Why a launch failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LaunchError {
    /// The launch scan refused a mount.
    #[error(transparent)]
    Scan(#[from] ScanError),
    /// The overlap rule refused the session.
    #[error(transparent)]
    Overlap(#[from] ReserveError),
    /// A session directory could not be prepared.
    #[error(transparent)]
    Dirs(#[from] DirError),
    /// The argv could not be built or failed its check.
    #[error(transparent)]
    Argv(#[from] ArgvError),
    /// Hermetic podman or the runtime failed a check.
    #[error(transparent)]
    Podman(#[from] PodmanError),
    /// A mount inside the container is not the pinned object.
    #[error("sandbox.mount_mismatch: {0}")]
    MountMismatch(Mismatch),
    /// A podman command failed.
    #[error("podman {verb}: {msg}")]
    Command {
        /// The podman verb.
        verb: &'static str,
        /// Exit status and stderr (capped).
        msg: String,
    },
    /// The audit log could not be written; nothing is launched without it (SI-4).
    #[error("audit: {0}")]
    Audit(String),
    /// A background task failed.
    #[error("internal: {0}")]
    Internal(String),
}

impl LaunchError {
    /// A short reason for the `sandbox.refuse` audit entry.
    fn reason(&self) -> &'static str {
        match self {
            Self::Scan(ScanError::SocketInMount { .. }) => "socket-in-mount",
            Self::Scan(ScanError::TooManyShields { .. } | ScanError::Limit { .. }) => "scan-limit",
            Self::Scan(_) => "mount-changed",
            Self::Overlap(_) => "overlap",
            Self::Dirs(_) => "session-dir",
            Self::Argv(_) => "argv",
            Self::Podman(_) => "podman-config",
            Self::MountMismatch(_) => "mount-mismatch",
            Self::Command { .. } => "podman",
            Self::Audit(_) => "audit",
            Self::Internal(_) => "internal",
        }
    }
}

fn join_err(e: tokio::task::JoinError) -> LaunchError {
    LaunchError::Internal(e.to_string())
}

/// A started workspace container.
#[derive(Debug)]
pub struct Running {
    /// Podman's container id (64 hex digits).
    pub container: String,
    /// The session's paths.
    pub paths: SessionPaths,
    /// The session's audit level.
    level: AuditLevel,
}

/// What a workspace launch needs.
#[derive(Debug, Clone)]
pub struct WorkspaceRequest {
    /// The session's directories.
    pub paths: SessionPaths,
    /// The validated manifest.
    pub manifest: ValidatedManifest,
    /// The bundled workspace image, used when the manifest names none.
    pub default_image: ImageRef,
}

/// Launches and tears down sandboxes for one `sallyd`.
pub struct Launcher {
    podman: Podman,
    runtime: CheckedRuntime,
    ids: UserIds,
    xdg_runtime_dir: PathBuf,
    sessions: Arc<Sessions>,
    audit: Arc<dyn AuditSink>,
    limits: ScanLimits,
}

impl std::fmt::Debug for Launcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Launcher")
            .field("podman", &self.podman)
            .field("runtime", &self.runtime)
            .finish_non_exhaustive()
    }
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
}

impl Launcher {
    /// A launcher.
    #[must_use]
    pub fn new(p: LauncherParts) -> Self {
        Self {
            podman: p.podman,
            runtime: p.runtime,
            ids: p.ids,
            xdg_runtime_dir: p.xdg_runtime_dir,
            sessions: p.sessions,
            audit: p.audit,
            limits: p.limits,
        }
    }

    async fn audit(&self, entry: NewEntry, level: AuditLevel) -> Result<(), LaunchError> {
        let sink = Arc::clone(&self.audit);
        tokio::task::spawn_blocking(move || sink.append(entry, level))
            .await
            .map_err(join_err)?
            .map_err(|e| LaunchError::Audit(e.to_string()))
    }

    /// Launches the workspace container of a session and starts it once every check passed.
    ///
    /// # Errors
    /// [`LaunchError`]; everything created on the way is removed and `sandbox.refuse` (or
    /// `sandbox.mount_mismatch`) is audited.
    pub async fn launch_workspace(&self, req: WorkspaceRequest) -> Result<Running, LaunchError> {
        let level = req.manifest.manifest().audit.level;
        let sid = req.paths.id().as_str().to_owned();
        if let Err(e) = self.sessions.reserve(&sid, claims(&req.manifest)) {
            let e = LaunchError::from(e);
            self.refused(&sid, &e, level).await?;
            return Err(e);
        }
        match self.launch_reserved(&req, level).await {
            Ok(r) => Ok(r),
            Err(e) => {
                let _ = self.remove_dirs(&req.paths, false).await;
                self.sessions.release(&sid);
                self.refused(&sid, &e, level).await?;
                Err(e)
            }
        }
    }

    async fn refused(
        &self,
        sid: &str,
        e: &LaunchError,
        level: AuditLevel,
    ) -> Result<(), LaunchError> {
        let event = if matches!(e, LaunchError::MountMismatch(_)) {
            "sandbox.mount_mismatch"
        } else {
            "sandbox.refuse"
        };
        self.audit(
            NewEntry::new(Actor::Sallyd, event)
                .session(sid)
                .decision("deny")
                .args(json!({"role": "workspace", "reason": e.reason(), "detail": e.to_string()})),
            level,
        )
        .await
    }

    async fn launch_reserved(
        &self,
        req: &WorkspaceRequest,
        level: AuditLevel,
    ) -> Result<Running, LaunchError> {
        let (scan, argv) = self.prepare(req).await?;
        let m = req.manifest.manifest();
        let mounts: Vec<_> = req
            .manifest
            .mounts()
            .iter()
            .map(|x| json!({"guest": x.guest, "mode": format!("{:?}", x.mode).to_lowercase()}))
            .collect();
        self.audit(
            NewEntry::new(Actor::Sallyd, "sandbox.launch")
                .session(req.paths.id().as_str())
                .decision("allow")
                .args(json!({
                    "role": "workspace",
                    "image": m.runtime.image.as_deref().unwrap_or(req.default_image.as_str()),
                    "mounts": mounts,
                    "git_shields": scan.git().iter().map(|g| g.dirs().len() + g.files().len()).sum::<usize>(),
                })),
            level,
        )
        .await?;
        let out = self.run("create", argv.iter().map(OsString::from)).await?;
        let container = container_id(&out)?;
        if let Err(e) = self.checked_start(req, &scan, &container).await {
            let _ = self.run("rm", rm_args(&container)).await;
            return Err(e);
        }
        Ok(Running {
            container,
            paths: req.paths.clone(),
            level,
        })
    }

    /// Steps 2 and 3, on the blocking pool.
    async fn prepare(
        &self,
        req: &WorkspaceRequest,
    ) -> Result<(LaunchScan, Vec<String>), LaunchError> {
        let podman = self.podman.clone();
        let runtime = self.runtime.clone();
        let ids = self.ids;
        let limits = self.limits;
        let xdg = self.xdg_runtime_dir.clone();
        let req = req.clone();
        tokio::task::spawn_blocking(move || -> Result<_, LaunchError> {
            podman.recheck()?;
            let runtime = CheckedRuntime::check(runtime.path())
                .map_err(|e| LaunchError::Podman(PodmanError::Binary(e)))?;
            let scan = scan_mounts(&req.manifest, &limits)?;
            let staged: Vec<usize> = req
                .manifest
                .mounts()
                .iter()
                .enumerate()
                .filter(|(_, m)| m.mode == MountMode::Staged)
                .map(|(i, _)| i)
                .collect();
            let overlays = scan.git().iter().map(|g| g.dirs().len()).sum();
            let dirs = SessionDirs::create(&req.paths, &xdg, &staged, overlays)?;
            let common = CommonArgs {
                runtime,
                ids,
                profiles: dirs.profiles().to_owned(),
                hooks_dir: podman.hooks_dir().to_owned(),
            };
            let argv = workspace_argv(
                &common,
                &req.paths,
                &req.manifest,
                &scan,
                &req.default_image,
            )?;
            Ok((scan, argv))
        })
        .await
        .map_err(join_err)?
    }

    /// Steps 5 (after create) to 7.
    async fn checked_start(
        &self,
        req: &WorkspaceRequest,
        scan: &LaunchScan,
        container: &str,
    ) -> Result<(), LaunchError> {
        let (v, s) = (req.manifest.clone(), scan.clone());
        tokio::task::spawn_blocking(move || s.recheck_host(&v))
            .await
            .map_err(join_err)??;
        self.run("init", [OsString::from("init"), container.into()])
            .await?;
        let pid = self.init_pid(container).await?;
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
        tokio::task::spawn_blocking(move || check_in_container(pid, &expect))
            .await
            .map_err(join_err)?
            .map_err(LaunchError::MountMismatch)?;
        self.run("start", [OsString::from("start"), container.into()])
            .await?;
        Ok(())
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

    /// Stops and removes the container, discards the `.git` overlays, the profiles and the
    /// socket directory, keeps the `staged` upper directories, and releases the session's
    /// mounts. Audits `sandbox.stop` first.
    ///
    /// # Errors
    /// [`LaunchError`] if a step fails; the later steps still run and the session is released.
    pub async fn stop(&self, r: Running) -> Result<(), LaunchError> {
        let sid = r.paths.id().as_str().to_owned();
        let audited = self
            .audit(
                NewEntry::new(Actor::Sallyd, "sandbox.stop")
                    .session(&sid)
                    .args(json!({"role": "workspace"})),
                r.level,
            )
            .await;
        let removed = self.run("rm", rm_args(&r.container)).await.map(|_| ());
        let cleaned = self.remove_dirs(&r.paths, true).await;
        self.sessions.release(&sid);
        audited.and(removed).and(cleaned)
    }

    /// Removes the session's scratch. Files in overlay work directories belong to the
    /// container's user namespace, so removal runs through `podman unshare`.
    async fn remove_dirs(&self, paths: &SessionPaths, keep_stage: bool) -> Result<(), LaunchError> {
        let data = paths.data_root();
        let targets: Vec<PathBuf> = if keep_stage {
            vec![data.join("git"), data.join("profiles")]
        } else {
            vec![data.to_owned()]
        };
        for t in targets.iter().filter(|t| t.exists()) {
            let t = path_arg(t, "session scratch")?;
            self.run(
                "unshare",
                [
                    "unshare".into(),
                    "rm".into(),
                    "-rf".into(),
                    "--".into(),
                    t.into(),
                ],
            )
            .await?;
        }
        let sockets = paths.socket_root().to_owned();
        tokio::task::spawn_blocking(move || match std::fs::remove_dir_all(&sockets) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(LaunchError::Internal(format!("{}: {e}", sockets.display()))),
        })
        .await
        .map_err(join_err)?
    }

    /// Runs one hermetic podman command; stdout on success.
    async fn run(
        &self,
        verb: &'static str,
        args: impl IntoIterator<Item = OsString>,
    ) -> Result<String, LaunchError> {
        let fail = |msg: String| LaunchError::Command { verb, msg };
        let mut child = self
            .podman
            .command()
            .args(args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| fail(e.to_string()))?;
        let (Some(out), Some(err)) = (child.stdout.take(), child.stderr.take()) else {
            return Err(fail("no pipes".into()));
        };
        let work = async {
            let (out, err) = tokio::join!(read_capped(out), read_capped(err));
            let status = child.wait().await;
            (out, err, status)
        };
        let (out, err, status) = tokio::time::timeout(PODMAN_TIMEOUT, work)
            .await
            .map_err(|_| fail(format!("timed out after {}s", PODMAN_TIMEOUT.as_secs())))?;
        let status = status.map_err(|e| fail(e.to_string()))?;
        if status.success() {
            Ok(String::from_utf8_lossy(&out).into_owned())
        } else {
            Err(fail(format!(
                "{status}: {}",
                String::from_utf8_lossy(&err).trim()
            )))
        }
    }
}

fn rm_args(container: &str) -> [OsString; 5] {
    [
        "rm".into(),
        "--force".into(),
        "--time".into(),
        "0".into(),
        container.into(),
    ]
}

/// The id `podman create` prints: 64 lowercase hex digits on the last line.
fn container_id(out: &str) -> Result<String, LaunchError> {
    let id = out.trim().lines().last().unwrap_or_default();
    if id.len() == 64
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(id.to_owned())
    } else {
        Err(LaunchError::Command {
            verb: "create",
            msg: "did not print a container id".into(),
        })
    }
}

/// Reads everything, keeps the first [`OUTPUT_CAP`] bytes, so a chatty process never blocks on
/// a full pipe and never grows memory without bound.
async fn read_capped(mut r: impl AsyncRead + Unpin) -> Vec<u8> {
    let mut kept = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match r.read(&mut buf).await {
            Ok(0) | Err(_) => return kept,
            Ok(n) => {
                let room = OUTPUT_CAP.saturating_sub(kept.len());
                kept.extend_from_slice(buf.get(..n.min(room)).unwrap_or_default());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn container_ids_are_exactly_64_lowercase_hex() {
        let id = "a".repeat(64);
        assert_eq!(container_id(&format!("{id}\n")).unwrap(), id);
        assert_eq!(container_id(&format!("warning\n{id}\n")).unwrap(), id);
        for bad in [
            "",
            "abc",
            &"A".repeat(64),
            &"a".repeat(65),
            &format!("{}-", "a".repeat(63)),
        ] {
            assert!(container_id(bad).is_err(), "{bad:?}");
        }
    }

    #[tokio::test]
    async fn output_is_capped_but_fully_drained() {
        let data = vec![b'x'; OUTPUT_CAP * 3 + 17];
        let kept = read_capped(data.as_slice()).await;
        assert_eq!(kept.len(), OUTPUT_CAP);
    }
}
