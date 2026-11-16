//! The one start path of every role (#123; architect Q129): each role's launch prepares a
//! [`Prepared`] value, and this file takes it from the `sandbox.launch` entry to a running
//! container:
//!
//! 1. audit `sandbox.launch` (SI-4: before anything is visible);
//! 2. `podman create` (the container name is recorded first, so a failed launch removes it even
//!    when `create` printed no id);
//! 3. re-check every pin on the host;
//! 4. `podman init` with Sallyport's empty mounts file ([`Podman::spec_args`]): the runtime builds
//!    the mounts but runs nothing;
//! 5. compare every bind pin inside the container's mount namespace (B4);
//! 6. the OCI config verifier (Task 14, RT-SUP-04), last before start, so the config read is the
//!    one started;
//! 7. `podman start` with the empty mounts file, then confirm after a short grace that the
//!    container runs as the pid that was checked.
//!
//! `create`, `init`, `start`, [`Podman::spec_args`] and [`Launcher::verify_config`] are called
//! from here only, and every podman command runs through hermetic podman (its private `HOME`),
//! so no role can launch without the private `HOME`, the empty mounts file or the verifier.
//!
//! [`Podman::spec_args`]: crate::sandbox::Podman::spec_args

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;

use sally_core::manifest::{AuditLevel, ValidatedManifest};
use serde_json::Value;

use super::error::{cpu_only, running_as};
use super::parts::{HostPin, Subject};
use super::{
    HarnessRequest, InferenceRequest, LaunchError, Launcher, Progress, Running, START_GRACE,
    WorkspaceRequest, blocking,
};
use crate::egress::net::EgressHandle;
use crate::sandbox::commands::container_id;
use crate::sandbox::images::PresentImage;
use crate::sandbox::inside::{Expect, check_in_container};
use crate::sandbox::oci::intent::Built;
use crate::sandbox::scan::LaunchScan;
use crate::sandbox::types::{
    CheckedRuntime, CommonArgs, ImageRef, InstancePaths, Role, SessionPaths,
};
use crate::sandbox::watchdog::{Observed, Watch, WatchPlan};

/// What a launch pinned: re-checked on the host after `podman create`, and every bind pin
/// compared inside the container after `init`. One list serves both, so no pin can be left out
/// of either (security review M2).
pub(super) enum Recheck {
    /// The workspace's launch scan (mount roots, `.git` shields and their parents).
    Scan(LaunchScan, Arc<ValidatedManifest>),
    /// The objects a harness or inference launch binds (its socket directory, the model blob).
    Pins(Vec<HostPin>),
}

impl Recheck {
    /// Every bind pin, as the container must show it after `init`.
    fn expect(&self) -> Vec<Expect> {
        match self {
            Self::Scan(scan, _) => scan.bind_expects(),
            Self::Pins(pins) => pins.iter().map(HostPin::expect).collect(),
        }
    }
}

/// One role's launch, ready to start.
pub(super) struct Prepared {
    /// Who it is for.
    pub(super) subject: Subject,
    /// The audit level of its entries.
    pub(super) level: AuditLevel,
    /// The container name.
    pub(super) name: String,
    /// The image, as found in local storage; must be the argv's (architect Q143).
    pub(super) image: PresentImage,
    /// The checked argv and its intent.
    pub(super) built: Built,
    /// What the host re-checks after `create`, and the container shows after `init`.
    pub(super) recheck: Recheck,
    /// The role's own args of `sandbox.launch` (the role is added).
    pub(super) launch_args: Vec<(&'static str, Value)>,
}

/// A started container.
pub(super) struct Started {
    /// Podman's container id.
    pub(super) container: String,
    /// The container init's host pid.
    pub(super) init_pid: u32,
    /// Its `/proc/<pid>` directory, opened right after the mount check on that pid.
    pub(super) init_dir: rustix::fd::OwnedFd,
    /// The cgroup event files, opened at launch (workspace only: its watchdog reads them).
    pub(super) observed: Option<Observed>,
}

/// A started harness or inference container. Only [`Launcher::launch_harness`] and
/// [`Launcher::launch_inference`] make one, and only [`Launcher::stop_role`] ends it.
#[derive(Debug)]
#[must_use = "dropping it leaves the container running; call Launcher::stop_role"]
pub struct RoleRunning {
    pub(super) container: String,
    pub(super) name: String,
    pub(super) role: Role,
    pub(super) subject: Subject,
    pub(super) level: AuditLevel,
    /// The directories the launch created and the stop removes (an inference instance's; a
    /// harness uses its session's and removes none).
    pub(super) dirs: Vec<std::path::PathBuf>,
    pub(super) init_pid: u32,
    /// A stop wrote its `sandbox.stop` entry: a retry does not write another.
    pub(super) stop_audited: bool,
    /// A stop confirmed the container gone and freed the claim: a retry touches neither (a new
    /// harness of the session may hold both by then).
    pub(super) removed: bool,
}

impl RoleRunning {
    /// Podman's container id (64 hex digits).
    #[must_use]
    pub fn container(&self) -> &str {
        &self.container
    }

    /// The container name: `sp-h-<session id>` or `sp-infer-<instance id>`.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The role.
    #[must_use]
    pub fn role(&self) -> Role {
        self.role
    }

    /// The session or instance id.
    #[must_use]
    pub fn id(&self) -> &str {
        self.subject.id().as_str()
    }

    /// The container init's host pid.
    #[must_use]
    pub fn init_pid(&self) -> u32 {
        self.init_pid
    }
}

/// A launch of any role (architect Q129: an enum over the roles, not a trait). An inference
/// launch carries its instance's directories, which the launcher derives (Q140).
pub(super) enum Request {
    Workspace(WorkspaceRequest),
    Harness(HarnessRequest),
    Inference(InferenceRequest, InstancePaths),
}

/// What a role's preparation hands on to its handle.
pub(super) enum Extra {
    /// The workspace's egress listener and disk watch plan, and its session's directories.
    Workspace {
        egress: Option<EgressHandle>,
        plan: Option<WatchPlan>,
        paths: SessionPaths,
    },
    /// A harness (no directories of its own) or an inference instance (its two directories).
    Role { dirs: Vec<PathBuf> },
}

/// A launched container's handle.
pub(super) enum Launched {
    Workspace(Box<(Running, Watch)>),
    Role(RoleRunning),
}

impl Request {
    fn subject(&self) -> Subject {
        match self {
            Self::Workspace(r) => Subject::Session(r.paths.id().clone()),
            Self::Harness(r) => Subject::Session(r.paths.id().clone()),
            Self::Inference(_, p) => Subject::Instance(p.id().clone()),
        }
    }

    fn role(&self) -> Role {
        match self {
            Self::Workspace(_) => Role::Workspace,
            Self::Harness(_) => Role::Harness,
            Self::Inference(..) => Role::Inference,
        }
    }

    fn level(&self) -> AuditLevel {
        match self {
            Self::Workspace(r) => r.manifest.manifest().audit.level,
            Self::Harness(r) => r.manifest.manifest().audit.level,
            Self::Inference(r, _) => r.level,
        }
    }

    /// The only directories a failed launch may remove: what it can have created.
    fn owned(&self) -> Vec<PathBuf> {
        match self {
            Self::Workspace(r) => r.paths.created_dirs(),
            // The session's directories are the workspace's: never removed here.
            Self::Harness(_) => Vec::new(),
            Self::Inference(_, p) => p.created_dirs(),
        }
    }
}

impl Launcher {
    /// Runs `req` in its own task: dropping the returned future does not interrupt it, and a
    /// launch that finishes after its caller went away is stopped again.
    pub(super) async fn spawn_role(
        self: &Arc<Self>,
        req: Request,
    ) -> Result<RoleRunning, LaunchError> {
        let id = req.subject().id().clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let result = match this.launch_role(&req).await {
                Ok(Launched::Role(r)) => Ok(r),
                Ok(Launched::Workspace(w)) => {
                    let (r, _) = *w;
                    this.stop_unreceived(r).await;
                    Err(this.wrong_handle(&req).await)
                }
                Err(e) => Err(e),
            };
            if let Err(Ok(orphan)) = tx.send(result) {
                this.stop_role_unreceived(orphan).await;
            }
        });
        // TODO(#113): what a panicked launch task leaves behind.
        super::error::received(rx, id).await
    }

    /// A launch handed back another role's handle (a bug that `prepare_and_start` already
    /// refuses before `create`): its caller has stopped that handle with the stop that retries
    /// until the container is gone. What the request itself made is then cleaned up as after
    /// any failed launch (its directories, then its claim), and the launch is refused
    /// `internal`.
    pub(super) async fn wrong_handle(&self, req: &Request) -> LaunchError {
        let owned = req.owned();
        let progress = Progress {
            dirs: owned.clone(),
            owned,
            ..Progress::default()
        };
        let cleanup = self.clean_failed(&progress).await;
        let outcome = match &cleanup {
            Ok(()) => "stopped, removed".to_owned(),
            Err(c) => format!("stopped, incomplete, kept: {c}"),
        };
        if cleanup.is_ok() {
            self.unclaim(req);
        }
        let e = LaunchError::Internal("the launch made another role's handle".into());
        self.refused(&req.subject(), req.role(), e, req.level(), outcome)
            .await
    }

    /// The one launch path (architect Q129). Every `Err` it returns went through `refused()`:
    /// audited, or `Unaudited` (architect Q98).
    pub(super) async fn launch_role(&self, req: &Request) -> Result<Launched, LaunchError> {
        let (subject, role, level) = (req.subject(), req.role(), req.level());
        let image = match self.admit(req).await {
            Ok(i) => i,
            Err(e) => {
                return Err(self
                    .refused(&subject, role, e, level, "nothing to clean up".into())
                    .await);
            }
        };
        let mut progress = Progress {
            owned: req.owned(),
            ..Progress::default()
        };
        match self.prepare_and_start(req, &image, &mut progress).await {
            Ok(l) => Ok(l),
            Err(e) => {
                let cleanup = self.clean_failed(&progress).await;
                let outcome = match &cleanup {
                    Ok(()) => "removed".to_owned(),
                    Err(c) => format!("incomplete, kept: {c}"),
                };
                if cleanup.is_ok() {
                    self.unclaim(req);
                }
                Err(self.refused(&subject, role, e, level, outcome).await)
            }
        }
    }

    /// Step 0: the refusals that need nothing made, and the role's claim. The image to run.
    async fn admit(&self, req: &Request) -> Result<ImageRef, LaunchError> {
        match req {
            Request::Workspace(r) => self.admit_workspace(r).await,
            Request::Harness(r) => self.admit_harness(r).await,
            Request::Inference(r, _) => {
                cpu_only(r.gpu)?;
                Ok(r.image.clone())
            }
        }
    }

    /// Frees what [`Self::admit`] claimed, once a failed launch's cleanup removed everything.
    fn unclaim(&self, req: &Request) {
        match req {
            Request::Workspace(r) => self.sessions.release(r.paths.id().as_str()),
            Request::Harness(r) => self.sessions.free_harness(r.paths.id().as_str()),
            // Its fresh directories were its claim, and the cleanup removed them.
            Request::Inference(..) => {}
        }
    }

    async fn prepare_and_start(
        &self,
        req: &Request,
        image: &ImageRef,
        progress: &mut Progress,
    ) -> Result<Launched, LaunchError> {
        let runtime = self.checked_runtime().await?;
        let (prepared, extra) = match req {
            Request::Workspace(r) => self.prepare_workspace(r, image, runtime, progress).await?,
            Request::Harness(r) => self.prepare_harness(r, image, runtime).await?,
            Request::Inference(r, p) => {
                self.prepare_inference(r, p, image, runtime, progress)
                    .await?
            }
        };
        let role = prepared.built.intent.role;
        if role != req.role() || !extra.fits(role) {
            // A bug, caught before anything is created: the one cleanup path runs.
            extra.shut_down().await;
            return Err(LaunchError::Internal(format!(
                "a {} launch prepared another role's container",
                req.role().as_str()
            )));
        }
        let (subject, level, name) = (
            prepared.subject.clone(),
            prepared.level,
            prepared.name.clone(),
        );
        match self.start_prepared(prepared, progress).await {
            Ok(started) => finish(extra, started, name, subject, level, role).await,
            Err(e) => {
                extra.shut_down().await;
                Err(e)
            }
        }
    }

    /// The common argv inputs, with the role's profiles directory.
    pub(super) fn common_args(&self, runtime: CheckedRuntime, profiles: PathBuf) -> CommonArgs {
        CommonArgs {
            runtime,
            ids: self.ids,
            profiles,
            hooks_dir: self.podman.hooks_dir(),
            mounts_file: self.podman.mounts_file(),
            installation: self.installation.clone(),
        }
    }

    /// Hermetic podman and the runtime, re-checked (architect Q143 (f)): the first step of every
    /// role's preparation, before anything touches the filesystem.
    pub(super) async fn checked_runtime(&self) -> Result<CheckedRuntime, LaunchError> {
        let podman = self.podman.clone();
        let runtime = self.runtime.path().to_owned();
        blocking(move || {
            podman.recheck()?;
            CheckedRuntime::check(&runtime)
                .map_err(|e| LaunchError::Podman(crate::sandbox::podman::PodmanError::Binary(e)))
        })
        .await
    }

    /// Steps 1 to 7 (module docs). Records the container name in `progress` before `create`.
    pub(super) async fn start_prepared(
        &self,
        p: Prepared,
        progress: &mut Progress,
    ) -> Result<Started, LaunchError> {
        let Prepared {
            subject,
            level,
            name,
            image,
            built,
            recheck,
            launch_args,
        } = p;
        image.matches(&built.intent.image)?;
        let role = built.intent.role;
        let expect = recheck.expect();
        self.audit(
            subject
                .entry("sandbox.launch", role, launch_args)
                .decision("allow"),
            level,
        )
        .await?;
        progress.container = Some(name);
        let out = self
            .run("create", built.argv.into_iter().map(OsString::from))
            .await?;
        let container = container_id(&out)?;
        blocking(move || match recheck {
            Recheck::Scan(scan, v) => Ok(scan.recheck_host(&v)?),
            Recheck::Pins(pins) => Ok(pins.iter().try_for_each(HostPin::recheck)?),
        })
        .await?;
        self.run("init", self.podman.spec_args("init", &container))
            .await?;
        let pid = self.init_pid(&container).await?;
        let (init_dir, observed) = blocking(move || inside(pid, &expect, role)).await?;
        self.verify_config(&container, &built.intent).await?;
        self.run("start", self.podman.spec_args("start", &container))
            .await?;
        tokio::time::sleep(START_GRACE).await;
        self.confirm_running(&container, pid).await?;
        Ok(Started {
            container,
            init_pid: pid,
            init_dir,
            observed,
        })
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

impl Extra {
    /// Whether this preparation's handle is `role`'s.
    fn fits(&self, role: Role) -> bool {
        match self {
            Self::Workspace { .. } => role == Role::Workspace,
            Self::Role { .. } => role != Role::Workspace,
        }
    }

    /// A failed launch's preparation: the egress listener stopped in order (the container may
    /// have run long enough to open a tunnel, so every `egress.allow` gets its `egress.close`).
    async fn shut_down(self) {
        if let Self::Workspace {
            egress: Some(h), ..
        } = self
        {
            h.shutdown().await;
        }
    }
}

/// The handle of a started container. An `Err` here comes back through the one cleanup path.
async fn finish(
    extra: Extra,
    started: Started,
    name: String,
    subject: Subject,
    level: AuditLevel,
    role: Role,
) -> Result<Launched, LaunchError> {
    let Started {
        container,
        init_pid,
        init_dir,
        observed,
    } = started;
    match (extra, observed) {
        (
            Extra::Workspace {
                egress,
                plan,
                paths,
            },
            Some(observed),
        ) => Ok(Launched::Workspace(Box::new((
            Running {
                container,
                name,
                paths,
                level,
                watchdog: None,
                egress,
                exec_gate: Arc::new(tokio::sync::Mutex::new(())),
                init_pid,
                init_dir: Arc::new(init_dir),
            },
            Watch { plan, observed },
        )))),
        (extra @ Extra::Workspace { .. }, None) => {
            extra.shut_down().await;
            Err(LaunchError::Internal(
                "the workspace started without its cgroup events".into(),
            ))
        }
        (Extra::Role { dirs }, _) => Ok(Launched::Role(RoleRunning {
            container,
            name,
            role,
            subject,
            level,
            dirs,
            init_pid,
            stop_audited: false,
            removed: false,
        })),
    }
}

/// Step 5, blocking: opens `/proc/<pid>` (the fd then names the process whose mounts are checked
/// next), compares every pin inside, and for the workspace opens its cgroup event files.
fn inside(
    pid: u32,
    expect: &[Expect],
    role: Role,
) -> Result<(rustix::fd::OwnedFd, Option<Observed>), LaunchError> {
    let p = format!("/proc/{pid}");
    let dir = sally_core::fd::open(
        p.as_str(),
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY,
        rustix::fs::Mode::empty(),
    )
    .map_err(|e| LaunchError::Command {
        verb: "init",
        msg: format!("cannot open {p}: {e}"),
    })?;
    check_in_container(&dir, expect).map_err(LaunchError::MountMismatch)?;
    let observed = match role {
        Role::Workspace => Some(Observed::at_launch(&dir).map_err(LaunchError::CgroupEvents)?),
        // TODO(#132): the harness and inference cgroup events are not watched yet.
        Role::Harness | Role::Inference => None,
    };
    Ok((dir, observed))
}
