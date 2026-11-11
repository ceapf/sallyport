//! A session's disk watchdog (#14; maintainer design after the 6c-1 reviews). Two tasks per
//! session:
//!
//! - **Floor** (the hard guarantee, `disk.rs`): every [`FLOOR_POLL`] it reads the free space of
//!   every filesystem the sandbox can write to and kills the session when one is below the floor.
//!   It never waits for a walk, the walk permit or the exec gate, so another session's slow tree
//!   cannot delay it.
//! - **Stage** (`runtime.stage_size`, a soft limit): it has no periodic walk. The floor task tracks
//!   the state filesystem's used bytes; only when they have grown past the session's remaining
//!   headroom since the last accurate measurement does it wake the stage task. That task takes
//!   the global walk permit and the session's exec gate, freezes the container (`podman pause`),
//!   walks its upper directories with a deadline, and unfreezes it. Over the limit, past the
//!   deadline or unmeasurable: that session only is killed.
//!
//! Freezing is guarded: unless the session is being killed, the container is unpaused on every
//! path, panics included, and a failed unpause kills it. A pause that fails because the container
//! is gone ends the watchdog. A kill audits `session.resource_limit` first (SI-4), then kills and
//! removes the container until it is confirmed gone, auditing `session.kill_failed` once if the
//! first attempt fails. The kill happens even when an audit entry cannot be written; TODO(#17):
//! Task 12 gives `sallyd` a logger, and that failure gets an error line.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sally_core::audit::{Actor, NewEntry};
use sally_core::manifest::{AuditLevel, ByteSize, MountMode, ValidatedManifest};
use serde_json::{Value, json};

use super::disk::{DiskFloor, Space, Watched, admits, below, watch};
use super::launch::{LaunchError, Launcher, capped};
use super::scan::LaunchScan;
use super::stage::{Area, StageBounds, Verdict, measure};
use super::types::SessionPaths;

/// How often the floor task reads free space.
pub(super) const FLOOR_POLL: Duration = Duration::from_millis(250);
/// A `statfs` that takes longer fails closed (a hung network filesystem under an `rw` mount).
const STATFS_TIMEOUT: Duration = Duration::from_secs(5);
/// The shortest time between two walks of a session; a walk that took longer waits
/// [`WALK_SPACING`] times its own duration. Also the kill retry interval.
const MIN_GAP: Duration = Duration::from_secs(2);
const WALK_SPACING: u32 = 4;

/// What a session's stage task measures.
#[derive(Debug, Clone)]
pub(super) struct StageWatch {
    areas: Vec<Area>,
    /// `runtime.stage_size` in bytes.
    limit: u64,
}

impl StageWatch {
    /// Every staged upper directory and every `.git` overlay upper directory of the session, in
    /// the order the argv numbers them, or `None` when the sandbox has neither.
    pub(super) fn of(
        v: &ValidatedManifest,
        paths: &SessionPaths,
        scan: &LaunchScan,
    ) -> Option<Self> {
        let mut areas: Vec<Area> = v
            .mounts()
            .iter()
            .enumerate()
            .filter(|(_, m)| m.mode == MountMode::Staged)
            .map(|(i, _)| Area {
                label: format!("filesystem.mounts[{i}]"),
                upper: paths.stage(i).upper,
            })
            .collect();
        let mut scans: Vec<_> = scan.git().iter().collect();
        scans.sort_by_key(|g| g.mount());
        let dirs = scans
            .iter()
            .flat_map(|g| (0..g.dirs().len()).map(move |j| (g.mount(), j)));
        for (k, (mount, j)) in dirs.enumerate() {
            areas.push(Area {
                label: format!("filesystem.mounts[{mount}].git[{j}]"),
                upper: paths.git_overlay(k).upper,
            });
        }
        (!areas.is_empty()).then(|| Self {
            areas,
            limit: v.manifest().runtime.stage_size.bytes(),
        })
    }

    #[cfg(test)]
    fn uppers(&self) -> Vec<(&str, &std::path::Path)> {
        self.areas
            .iter()
            .map(|a| (a.label.as_str(), a.upper.as_path()))
            .collect()
    }
}

/// What the launcher prepared for a session's watchdog.
#[derive(Debug)]
pub(super) struct WatchPlan {
    /// The filesystems the sandbox can write to (`disk::watch`).
    pub watched: Vec<Watched>,
    /// The stage areas, if any, and the state filesystem's used bytes at launch.
    pub stage: Option<(StageWatch, u64)>,
}

/// Prepares the watchdog of a launch, or refuses it: every filesystem the sandbox could write to
/// must have the floor free, plus `runtime.stage_size` on the state filesystem. `None` when the
/// sandbox cannot write to any host filesystem. Blocking.
///
/// # Errors
/// [`LaunchError::DiskSpace`].
pub(super) fn watch_plan(
    v: &ValidatedManifest,
    paths: &SessionPaths,
    scan: &LaunchScan,
    floor: &DiskFloor,
) -> Result<Option<WatchPlan>, LaunchError> {
    let stage = StageWatch::of(v, paths, scan);
    let rw: Vec<(usize, &std::path::Path)> = v
        .mounts()
        .iter()
        .enumerate()
        .filter(|(_, m)| m.mode == MountMode::Rw)
        .map(|(i, m)| (i, m.host.as_path()))
        .collect();
    let watched = watch(paths.data_root(), stage.is_some(), &rw).map_err(LaunchError::DiskSpace)?;
    if watched.is_empty() {
        return Ok(None);
    }
    let mut state_used = 0;
    for w in &watched {
        let space = w
            .space()
            .map_err(|e| LaunchError::DiskSpace(format!("{}: {e}", w.label)))?;
        let extra = match &stage {
            Some(s) if w.state => s.limit,
            _ => 0,
        };
        if !admits(space, floor, extra) {
            let need = floor.bytes(space.total).saturating_add(extra);
            let show = |b| ByteSize::from_bytes(b).to_string();
            return Err(LaunchError::DiskSpace(format!(
                "{}: {} free, the launch needs {} (the floor plus runtime.stage_size)",
                w.label,
                show(space.free),
                show(need)
            )));
        }
        if w.state {
            state_used = space.used;
        }
    }
    Ok(Some(WatchPlan {
        watched,
        stage: stage.map(|s| (s, state_used)),
    }))
}

/// The session a watchdog belongs to.
#[derive(Debug, Clone)]
pub(super) struct Target {
    pub sid: String,
    pub container: String,
    pub level: AuditLevel,
    /// Held around every `podman exec` into the session, and by the stage task while frozen.
    pub exec_gate: Arc<tokio::sync::Mutex<()>>,
}

/// Bytes accounted at the last accurate measurement.
#[derive(Debug)]
struct Account {
    /// The state filesystem's used bytes then (lowered when it shrinks: conservative).
    baseline: u64,
    /// The session's measured bytes then.
    measured: u64,
}

struct Shared {
    launcher: Arc<Launcher>,
    target: Target,
    /// Set once: the session is being killed, or is gone.
    ended: AtomicBool,
    /// Set when the handle is dropped; stops a walk in progress.
    cancel: Arc<AtomicBool>,
    wake: tokio::sync::Notify,
    stage: Option<(StageWatch, Mutex<Account>)>,
}

impl Shared {
    fn ended(&self) -> bool {
        self.ended.load(Ordering::Relaxed)
    }

    /// The floor task saw the state filesystem at `used` bytes: wake the stage task when growth
    /// since the last measurement exceeds the session's headroom.
    fn note_used(&self, used: u64) {
        let Some((watch, account)) = &self.stage else {
            return;
        };
        let mut a = account
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        a.baseline = a.baseline.min(used);
        if used - a.baseline > watch.limit.saturating_sub(a.measured) {
            self.wake.notify_one();
        }
    }

    /// Audits `session.resource_limit` with `args`, then kills the container. Only the first
    /// caller acts.
    async fn enforce(&self, args: Value) {
        if self.ended.swap(true, Ordering::Relaxed) {
            return;
        }
        let entry = NewEntry::new(Actor::Sallyd, "session.resource_limit")
            .session(&self.target.sid)
            .decision("deny")
            .args(args);
        let _ = self.launcher.audit(entry, self.target.level).await;
        kill(&self.launcher, &self.target).await;
    }
}

/// A running watchdog. Dropping it stops both tasks and any walk in progress.
#[derive(Debug)]
pub(super) struct Watchdog {
    tasks: Vec<tokio::task::JoinHandle<()>>,
    cancel: Arc<AtomicBool>,
}

impl Watchdog {
    /// Starts the watchdog of a started session.
    pub(super) fn spawn(launcher: &Arc<Launcher>, target: Target, plan: WatchPlan) -> Self {
        let cancel = Arc::new(AtomicBool::new(false));
        let shared = Arc::new(Shared {
            launcher: Arc::clone(launcher),
            target,
            ended: AtomicBool::new(false),
            cancel: Arc::clone(&cancel),
            wake: tokio::sync::Notify::new(),
            stage: plan.stage.map(|(watch, used)| {
                let account = Account {
                    baseline: used,
                    measured: 0,
                };
                (watch, Mutex::new(account))
            }),
        });
        let mut tasks = vec![tokio::spawn(floor_task(
            Arc::clone(&shared),
            Arc::new(plan.watched),
        ))];
        if shared.stage.is_some() {
            tasks.push(tokio::spawn(stage_task(shared)));
        }
        Self { tasks, cancel }
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
        for t in &self.tasks {
            t.abort();
        }
    }
}

/// Reads every watched filesystem, off the runtime, with a timeout.
async fn spaces(watched: &Arc<Vec<Watched>>) -> Result<Vec<Space>, String> {
    let w = Arc::clone(watched);
    let read = tokio::task::spawn_blocking(move || {
        w.iter()
            .map(|x| x.space().map_err(|e| format!("{}: {e}", x.label)))
            .collect::<Result<Vec<_>, _>>()
    });
    match tokio::time::timeout(STATFS_TIMEOUT, read).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err(format!(
            "statfs took longer than {} s",
            STATFS_TIMEOUT.as_secs()
        )),
    }
}

// TODO(#26): kebab-case the reason values here and in `stage_task` (`disk-floor`, …).
async fn floor_task(s: Arc<Shared>, watched: Arc<Vec<Watched>>) {
    let floor = s.launcher.disk_floor;
    let mut tick = tokio::time::interval(FLOOR_POLL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        if s.ended() {
            return;
        }
        let read = match spaces(&watched).await {
            Ok(r) => r,
            Err(detail) => {
                let args = json!({"role": "workspace", "resource": "disk",
                    "reason": "disk_floor", "detail": capped(&detail)});
                return s.enforce(args).await;
            }
        };
        for (w, space) in watched.iter().zip(read) {
            if below(space, &floor) {
                let args = json!({"role": "workspace", "resource": "disk",
                    "reason": "disk_floor", "filesystem": w.label, "free": space.free,
                    "floor": floor.bytes(space.total)});
                return s.enforce(args).await;
            }
            if w.state {
                s.note_used(space.used);
            }
        }
    }
}

/// `podman pause`, undone on drop unless [`Paused::keep`] was called.
struct Paused {
    launcher: Arc<Launcher>,
    container: String,
    armed: bool,
}

enum PauseError {
    /// The container no longer exists: the session is over.
    Gone,
    Failed(String),
}

impl Paused {
    async fn pause(launcher: &Arc<Launcher>, container: &str) -> Result<Self, PauseError> {
        match launcher
            .run("pause", ["pause".into(), container.into()])
            .await
        {
            Ok(_) => Ok(Self {
                launcher: Arc::clone(launcher),
                container: container.to_owned(),
                armed: true,
            }),
            Err(e) => match launcher.container_exists(container).await {
                Ok(false) => Err(PauseError::Gone),
                _ => Err(PauseError::Failed(e.to_string())),
            },
        }
    }

    /// Unfreezes the container.
    async fn resume(mut self) -> Result<(), String> {
        self.armed = false;
        let args = ["unpause".into(), self.container.as_str().into()];
        self.launcher
            .run("unpause", args)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Leaves the container frozen: it is about to be killed.
    fn keep(mut self) {
        self.armed = false;
    }
}

impl Drop for Paused {
    /// Any other way out (a panic, a cancelled task): unpause in the background, and remove the
    /// container if that fails.
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let Ok(rt) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let (launcher, container) = (Arc::clone(&self.launcher), self.container.clone());
        rt.spawn(async move {
            let args = ["unpause".into(), container.as_str().into()];
            if launcher.run("unpause", args).await.is_err() {
                let _ = launcher.remove_container(&container).await;
            }
        });
    }
}

async fn stage_task(s: Arc<Shared>) {
    let Some((watch, account)) = &s.stage else {
        return;
    };
    let mut next = Instant::now();
    loop {
        s.wake.notified().await;
        tokio::time::sleep_until(next.into()).await;
        if s.ended() {
            return;
        }
        // The global permit first, then the session's gate (held by an exec only while it
        // starts): a session waiting for other sessions' walks must not block its own execs
        // meanwhile (re-review L2).
        let Ok(permit) = Arc::clone(&s.launcher.walks).acquire_owned().await else {
            return;
        };
        // Released before any kill, so `stop` (which takes the gate) never waits on a kill loop.
        let gate = s.target.exec_gate.lock().await;
        let paused = match Paused::pause(&s.launcher, &s.target.container).await {
            Ok(p) => p,
            Err(PauseError::Gone) => {
                s.ended.store(true, Ordering::Relaxed);
                return;
            }
            Err(PauseError::Failed(detail)) => {
                drop(gate);
                return s
                    .enforce(stage_args(watch, None, "pause_failed", &detail))
                    .await;
            }
        };
        let started = Instant::now();
        let (areas, limit, cancel) = (watch.areas.clone(), watch.limit, Arc::clone(&s.cancel));
        // The permit moves into the walk, so it is released only when the walk has stopped.
        let verdict = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            measure(&areas, limit, StageBounds::default(), &cancel)
        })
        .await
        .unwrap_or_else(|e| Verdict::Unmeasurable {
            area: "watchdog".into(),
            reason: e.to_string(),
        });
        next = Instant::now() + MIN_GAP.max(started.elapsed().saturating_mul(WALK_SPACING));
        match verdict {
            Verdict::Within { bytes } => {
                let used = s.stage_used().await;
                if let Some(used) = used {
                    let mut a = account
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    *a = Account {
                        baseline: used,
                        measured: bytes,
                    };
                }
                if let Err(detail) = paused.resume().await {
                    drop(gate);
                    return s
                        .enforce(stage_args(watch, None, "unpause_failed", &detail))
                        .await;
                }
            }
            Verdict::Cancelled => return,
            Verdict::Over { bytes, largest } => {
                paused.keep();
                drop(gate);
                let mut args = stage_args(watch, Some(bytes), "stage_size", "");
                args["area"] = json!(largest);
                return s.enforce(args).await;
            }
            Verdict::Unmeasurable { area, reason } => {
                paused.keep();
                drop(gate);
                let mut args = stage_args(watch, None, "unmeasurable", &reason);
                args["area"] = json!(area);
                return s.enforce(args).await;
            }
        }
    }
}

impl Shared {
    /// The state filesystem's used bytes now (the sandbox is frozen), if readable.
    async fn stage_used(&self) -> Option<u64> {
        // The floor task owns the watched fds; the state filesystem is re-read through the first
        // area's upper directory, which lives on it.
        let (watch, _) = self.stage.as_ref()?;
        let dir = watch.areas.first()?.upper.clone();
        tokio::task::spawn_blocking(move || rustix::fs::statvfs(&dir).ok())
            .await
            .ok()
            .flatten()
            .map(|s| {
                s.f_blocks
                    .saturating_sub(s.f_bfree)
                    .saturating_mul(s.f_frsize)
            })
    }
}

fn stage_args(watch: &StageWatch, measured: Option<u64>, reason: &str, detail: &str) -> Value {
    json!({
        "role": "workspace",
        "resource": "stage_size",
        "reason": reason,
        "limit": watch.limit,
        "measured": measured,
        "detail": capped(detail),
    })
}

/// Kills and removes the container until it is confirmed gone.
async fn kill(launcher: &Launcher, t: &Target) {
    let mut reported = false;
    loop {
        let signal = [
            "kill".into(),
            "--signal".into(),
            "KILL".into(),
            t.container.as_str().into(),
        ];
        let killed = launcher.run("kill", signal).await;
        let removed = launcher.remove_container(&t.container).await;
        let Err(error) = removed else { return };
        if !reported {
            reported = true;
            let detail = match killed {
                Ok(_) => error.to_string(),
                Err(k) => format!("{k}; {error}"),
            };
            let entry = NewEntry::new(Actor::Sallyd, "session.kill_failed")
                .session(&t.sid)
                .decision("deny")
                .args(json!({
                    "container": t.container,
                    "detail": capped(&detail),
                }));
            let _ = launcher.audit(entry, t.level).await;
        }
        tokio::time::sleep(MIN_GAP).await;
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// Review H2 (6c-1): the `.git` overlays of `rw` mounts are watched too, numbered as the argv
    /// numbers them (by mount, then by directory), and a session with neither gets no stage
    /// watch. Labels never contain a host path (re-review L2).
    #[test]
    fn staged_mounts_and_git_overlays_are_watched() {
        use sally_core::manifest::{HostEnv, load};
        let dir = std::env::current_dir()
            .unwrap()
            .join("../../target/watchdog-unit")
            .join(std::process::id().to_string());
        let _ = std::fs::remove_dir_all(&dir);
        let home = dir.join("home");
        for d in ["a/x/.git", "a/.git", "b", "c/.git", "d"] {
            std::fs::create_dir_all(home.join(d)).unwrap();
        }
        let home = std::fs::canonicalize(&home).unwrap();
        let env = HostEnv {
            home: home.clone(),
            other_homes: Vec::new(),
            xdg_config_home: None,
            xdg_data_home: None,
            xdg_runtime_dir: None,
            podman_storage: Vec::new(),
            nproc: 8,
            mem_bytes: 16 << 30,
        };
        let manifest = |mounts: &str| {
            let body = format!(
                "apiVersion: sallyport/v1\nkind: Manifest\nname: t\nmodel:\n  ref: any\n\
                 filesystem:\n  mounts:\n{mounts}"
            );
            load(&body, &env, &std::collections::BTreeSet::new())
                .unwrap()
                .manifest
        };
        let v = manifest(
            "    - {host: \"~/c\", guest: /workspace/c, mode: rw}\n\
             \x20   - {host: \"~/b\", guest: /workspace/b, mode: staged}\n\
             \x20   - {host: \"~/a\", guest: /workspace/a, mode: rw}\n",
        );
        let scan = super::super::scan::scan_mounts(&v, &super::super::scan::ScanLimits::default())
            .unwrap();
        let paths = SessionPaths::new(
            super::super::types::SessionId::parse("s").unwrap(),
            &dir.join("run"),
            &dir.join("data"),
        )
        .unwrap();
        let w = StageWatch::of(&v, &paths, &scan).unwrap();
        let got = w.uppers();
        let want_labels = [
            "filesystem.mounts[1]",
            "filesystem.mounts[0].git[0]",
            "filesystem.mounts[2].git[0]",
            "filesystem.mounts[2].git[1]",
        ];
        assert_eq!(got.iter().map(|(l, _)| *l).collect::<Vec<_>>(), want_labels);
        assert_eq!(got[0].1, paths.stage(1).upper);
        for k in 0..3 {
            assert_eq!(got[k + 1].1, paths.git_overlay(k).upper);
        }
        let plain = manifest("    - {host: \"~/d\", guest: /workspace/d, mode: rw}\n");
        let scan = super::super::scan::scan_mounts(&plain, &Default::default()).unwrap();
        assert!(StageWatch::of(&plain, &paths, &scan).is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
