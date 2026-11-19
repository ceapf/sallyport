//! The one start path of every role (#123; architect Q129): each role's launch prepares a
//! [`Prepared`] value, and this file takes it from the `sandbox.launch` entry to a running
//! container:
//!
//! 1. audit `sandbox.launch` (SI-4: before anything is visible);
//! 2. the mount-link probe (security review, `sandbox/mount_probe.rs`): a container of the same
//!    image from the checked probe argv (no bind, overlay or GPU device; its name recorded
//!    first), `create` and `init`, its pid and image id read, every mount destination of the
//!    launch walked inside its root filesystem with no link allowed, then removed and confirmed
//!    gone whatever the walk found. Any failure refuses the launch;
//! 3. `podman create` (the container name is recorded first, so a failed launch removes it even
//!    when `create` printed no id), and its image id compared with the probe's;
//! 4. re-check every pin on the host;
//! 5. `podman init` with Sallyport's empty mounts file ([`Podman::spec_args`]): the runtime builds
//!    the mounts but runs nothing;
//! 6. compare every bind pin inside the container's mount namespace (B4);
//! 7. the OCI config verifier (Task 14, RT-SUP-04), last before start, so the config read is the
//!    one started;
//! 8. `podman start` with the empty mounts file, then confirm after a short grace that the
//!    container runs as the pid that was checked.
//!
//! `create`, `init`, `start`, [`Podman::spec_args`] and [`Launcher::verify_config`] are called
//! from here only, and every podman command runs through hermetic podman (its private `HOME`),
//! so no role can launch without the private `HOME`, the empty mounts file, the probe or the
//! verifier.
//!
//! [`Podman::spec_args`]: crate::sandbox::Podman::spec_args

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;

use sally_core::manifest::{AuditLevel, ValidatedManifest};
use serde_json::Value;

use super::error::{cpu_only, running_as};
use super::parts::{CleanupTries, HostPin, Made, Subject};
use super::{
    HarnessRequest, InferenceRequest, LaunchError, Launcher, Progress, Running, START_GRACE,
    WorkspaceRequest, blocking,
};
use crate::egress::net::EgressHandle;
use crate::sandbox::commands::container_id;
use crate::sandbox::disk::DiskFloor;
use crate::sandbox::images::PresentImage;
use crate::sandbox::inside::{Expect, check_in_container};
use crate::sandbox::mount_probe::{
    IMAGE_FORMAT, PID_IMAGE_FORMAT, WalkError, parse_image, parse_pid_image, walk_in,
};
use crate::sandbox::oci::intent::Built;
use crate::sandbox::oci::mounts::destinations;
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

/// What a failed launch holds until its cleanup ends (its claim; a workspace's forms too), and
/// how its entries name it: owned, so a cleanup retried in its own task outlives the request.
#[derive(Debug, Clone)]
pub(super) struct Held {
    subject: Subject,
    role: Role,
    level: AuditLevel,
}

impl Held {
    /// Who the launch was for.
    pub(super) fn subject(&self) -> Subject {
        self.subject.clone()
    }

    /// Its role.
    pub(super) fn role(&self) -> Role {
        self.role
    }

    /// Its session's (or instance's) audit level.
    pub(super) fn level(&self) -> AuditLevel {
        self.level
    }
}

impl Request {
    fn held(&self) -> Held {
        Held {
            subject: self.subject(),
            role: self.role(),
            level: self.level(),
        }
    }

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
    pub(super) async fn wrong_handle(self: &Arc<Self>, req: &Request) -> LaunchError {
        let owned = req.owned();
        let progress = Progress {
            dirs: owned.clone(),
            owned,
            ..Progress::default()
        };
        let e = LaunchError::Internal("the launch made another role's handle".into());
        self.failed(req, progress, e, "stopped, ").await
    }

    /// The one launch path (architect Q129). Every `Err` it returns went through `refused()`:
    /// audited, or `Unaudited` (architect Q98).
    pub(super) async fn launch_role(
        self: &Arc<Self>,
        req: &Request,
    ) -> Result<Launched, LaunchError> {
        let image = match self.admit(req).await {
            Ok(i) => i,
            Err(e) => {
                let (subject, role, level) = (req.subject(), req.role(), req.level());
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
            Err(e) => Err(self.failed(req, progress, e, "").await),
        }
    }

    /// A failed launch (or one that made another role's handle): its cleanup, then
    /// `sandbox.refuse` naming the cleanup's outcome after `stopped` (`""`, or `"stopped, "`
    /// when the caller stopped a handle first). When the cleanup removed everything the claim
    /// is freed before the entry and the forms released after it. Otherwise the rest of the
    /// cleanup goes on in its own task on the daemon's crash reporter, which writes
    /// `sandbox.cleaned` and only then frees the claim and releases the forms: the session stays
    /// live while a container may exist (ARCHITECTURE §3.5).
    async fn failed(
        self: &Arc<Self>,
        req: &Request,
        mut progress: Progress,
        e: LaunchError,
        stopped: &str,
    ) -> LaunchError {
        let held = req.held();
        let made = Made {
            probe: progress.probe.clone(),
            container: progress.container.clone(),
        };
        let cleanup = self.clean_failed(&mut progress).await;
        let outcome = match &cleanup {
            Ok(()) => format!("{stopped}removed"),
            Err(c) => format!("{stopped}incomplete, kept: {c}"),
        };
        if cleanup.is_ok() {
            self.unclaim(&held);
        }
        let refused = self
            .refused(&held.subject, held.role, e, held.level, outcome)
            .await;
        match cleanup {
            Ok(()) => self.forget(&held).await,
            Err(first) => {
                let mut tries = CleanupTries::default();
                let gone = progress.probe.is_none() && progress.container.is_none();
                // The first try failed, so it never ends the cleanup here.
                let _ = tries.record(gone, false);
                let this = Arc::clone(self);
                let _ = self.crash.spawn("sandbox.cleanup", async move {
                    this.finish_failed(held, made, progress, tries, first).await;
                });
            }
        }
        refused
    }

    /// After a refused workspace's last entry (`sandbox.refuse`, or `sandbox.cleaned` after a
    /// retried cleanup), its secrets leave the logs' redactors (architect Q219). A harness
    /// shares its session's id, so only a workspace releases them.
    pub(super) async fn forget(&self, held: &Held) {
        if held.role == Role::Workspace {
            self.release_secrets(held.subject.id().as_str()).await;
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
    pub(super) fn unclaim(&self, held: &Held) {
        let id = held.subject.id().as_str();
        match held.role {
            Role::Workspace => self.sessions.release(id),
            Role::Harness => self.sessions.free_harness(id),
            // Its fresh directories were its claim, and the cleanup removed or gave them up.
            Role::Inference => {}
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
            Ok(started) => {
                finish(extra, started, name, subject, level, role, self.disk_floor).await
            }
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

    /// Steps 1 to 8 (module docs). Records the probe's name in `progress` before its `create`,
    /// clears it once the probe is confirmed gone, and records the container name before
    /// `create`.
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
        progress.probe = Some(built.probe.name.clone());
        let probe_image = self.probe(&built).await?;
        progress.probe = None;
        progress.container = Some(name);
        let out = self
            .run("create", built.argv.into_iter().map(OsString::from))
            .await?;
        let container = container_id(&out)?;
        self.same_image(&container, &probe_image).await?;
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

    /// Step 2 (security review): the mount-link probe, created, inited, read, walked and then
    /// removed, whatever the walk found; any failure refuses the launch. Returns the image id the
    /// probe ran.
    async fn probe(&self, built: &Built) -> Result<String, LaunchError> {
        let walked = self.probe_walk(built).await;
        let removed = self
            .remove_container(&built.probe.name)
            .await
            .map_err(probe_err("rm"));
        let image = walked?;
        removed?;
        Ok(image)
    }

    /// The probe's `create`, `init`, inspect (its pid and image id), the walk of every
    /// destination of the launch under its held `/proc/<pid>` directory, and a second inspect
    /// while that directory is held, which must show the same pid and image.
    async fn probe_walk(&self, built: &Built) -> Result<String, LaunchError> {
        let p = &built.probe;
        self.run("create", p.argv.iter().map(OsString::from))
            .await
            .map_err(probe_err("create"))?;
        self.run("init", self.podman.spec_args("init", &p.name))
            .await
            .map_err(probe_err("init"))?;
        let out = self
            .run("inspect", inspect_args(PID_IMAGE_FORMAT, &p.name))
            .await
            .map_err(probe_err("inspect"))?;
        let (pid, image) = parse_pid_image(&out).ok_or_else(|| LaunchError::Probe {
            step: "inspect",
            msg: format!("unexpected {:?}", out.trim()),
        })?;
        let dests = destinations(&built.intent);
        let dir = blocking(move || {
            let dir = open_proc(pid).map_err(|msg| LaunchError::Probe { step: "walk", msg })?;
            walk_in(&dir, &dests).map_err(|e| match e {
                WalkError::Link(r) => LaunchError::MountLink(r),
                e @ WalkError::Root(_) => LaunchError::Probe {
                    step: "walk",
                    msg: e.to_string(),
                },
            })?;
            Ok(dir)
        })
        .await?;
        // While the `/proc/<pid>` fd is held, the probe still shows the pid and image it was
        // read with: the walk ran in its root, not in a process that reused the pid in between.
        let again = self
            .run("inspect", inspect_args(PID_IMAGE_FORMAT, &p.name))
            .await
            .map_err(probe_err("inspect"))?;
        drop(dir);
        if parse_pid_image(&again) != Some((pid, image.clone())) {
            return Err(LaunchError::Probe {
                step: "walk",
                msg: format!("the probe is no longer pid {pid}: {:?}", again.trim()),
            });
        }
        Ok(image)
    }

    /// The created container runs the image the probe walked: compared before `init`.
    async fn same_image(&self, container: &str, probe: &str) -> Result<(), LaunchError> {
        let out = self
            .run("inspect", inspect_args(IMAGE_FORMAT, container))
            .await
            .map_err(probe_err("image"))?;
        match parse_image(&out) {
            Some(image) if image == probe => Ok(()),
            got => Err(LaunchError::Probe {
                step: "image",
                msg: format!("the container's image {got:?} is not the probe's {probe}"),
            }),
        }
    }

    /// Step 8: the container still runs, as the process whose mounts were checked. A container
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
/// A workspace's `Running` carries the launcher's free-space floor (`floor`) for the file tools.
async fn finish(
    extra: Extra,
    started: Started,
    name: String,
    subject: Subject,
    level: AuditLevel,
    role: Role,
    floor: DiskFloor,
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
                disk_floor: floor,
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

/// Step 6, blocking: opens `/proc/<pid>` (the fd then names the process whose mounts are checked
/// next), compares every pin inside, and for the workspace opens its cgroup event files.
fn inside(
    pid: u32,
    expect: &[Expect],
    role: Role,
) -> Result<(rustix::fd::OwnedFd, Option<Observed>), LaunchError> {
    let dir = open_proc(pid).map_err(|msg| LaunchError::Command { verb: "init", msg })?;
    check_in_container(&dir, expect).map_err(LaunchError::MountMismatch)?;
    let observed = match role {
        Role::Workspace => Some(Observed::at_launch(&dir).map_err(LaunchError::CgroupEvents)?),
        // TODO(#132): the harness and inference cgroup events are not watched yet.
        Role::Harness | Role::Inference => None,
    };
    Ok((dir, observed))
}

/// Blocking: opens `/proc/<pid>`, so the fd names that process from then on.
fn open_proc(pid: u32) -> Result<rustix::fd::OwnedFd, String> {
    let p = format!("/proc/{pid}");
    sally_core::fd::open(
        p.as_str(),
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY,
        rustix::fs::Mode::empty(),
    )
    .map_err(|e| format!("cannot open {p}: {e}"))
}

/// `podman inspect --format <format> <container>`.
fn inspect_args(format: &str, container: &str) -> [OsString; 4] {
    [
        "inspect".into(),
        "--format".into(),
        format.into(),
        container.into(),
    ]
}

/// A failed podman step of the mount-link probe, as a probe refusal (podman's text as `run`
/// bounded it).
fn probe_err(step: &'static str) -> impl Fn(LaunchError) -> LaunchError {
    move |e| LaunchError::Probe {
        step,
        msg: e.to_string(),
    }
}
