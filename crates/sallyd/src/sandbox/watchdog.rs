//! The `runtime.stage_size` watchdog task (#14; measuring is in `stage.rs`).
//!
//! A session gets one when its sandbox can write to the host disk: through a `staged` mount, or
//! through a `.git` overlay of an `rw` mount. The task measures every upper directory. It uses
//! one walk at a time across all sessions and waits at least [`STAGE_POLL`] between walks, or
//! [`WALK_SPACING`] times the last walk's duration if that is longer. When the session is over
//! its limit, or a tree cannot be measured, the task:
//! 1. audits `session.resource_limit` (SI-4: before the kill);
//! 2. kills and removes the container, retrying every [`STAGE_POLL`] until it is confirmed gone;
//! 3. audits `session.kill_failed` once if the first attempt failed.
//!
//! The kill happens even when an audit entry cannot be written: it is enforcement, not an action
//! on the harness's behalf. TODO(#17): Task 12 gives `sallyd` a logger, and that failure gets an
//! error line. Teardown stays with `Launcher::stop`, which keeps the staged data.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use sally_core::audit::{Actor, NewEntry};
use sally_core::manifest::{AuditLevel, MountMode, ValidatedManifest};
use serde_json::json;

use super::launch::{Launcher, capped};
use super::scan::LaunchScan;
use super::stage::{Area, STAGE_POLL, StageBounds, Verdict, WALK_SPACING, measure};
use super::types::SessionPaths;

/// What one session's watchdog measures.
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
            .flat_map(|g| g.dirs().iter().map(move |d| (g.mount(), d)));
        for (k, (mount, rel)) in dirs.enumerate() {
            areas.push(Area {
                label: format!("filesystem.mounts[{mount}]/{}", rel.display()),
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

/// A running watchdog. Dropping it cancels the task and any walk in progress.
#[derive(Debug)]
pub(super) struct Watchdog {
    task: tokio::task::JoinHandle<()>,
    cancel: Arc<AtomicBool>,
    armed: bool,
}

impl Watchdog {
    /// Starts the watchdog of the started container `container` of session `sid`.
    pub(super) fn spawn(
        launcher: &Arc<Launcher>,
        sid: String,
        container: String,
        level: AuditLevel,
        w: StageWatch,
    ) -> Self {
        let cancel = Arc::new(AtomicBool::new(false));
        let task = tokio::spawn(watch(
            Arc::clone(launcher),
            Session {
                sid,
                container,
                level,
            },
            w,
            Arc::clone(&cancel),
        ));
        Self {
            task,
            cancel,
            armed: true,
        }
    }

    /// Lets the task run on with nobody holding the session: a launch nobody received, whose
    /// container could not be stopped, must stay bounded.
    pub(super) fn detach(mut self) {
        self.armed = false;
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        if self.armed {
            self.cancel.store(true, Ordering::Relaxed);
            self.task.abort();
        }
    }
}

struct Session {
    sid: String,
    container: String,
    level: AuditLevel,
}

async fn watch(launcher: Arc<Launcher>, s: Session, w: StageWatch, cancel: Arc<AtomicBool>) {
    let mut wait = STAGE_POLL;
    let (measured, area, detail) = loop {
        tokio::time::sleep(wait).await;
        let Ok(_permit) = launcher.walks.acquire().await else {
            return;
        };
        let started = Instant::now();
        let (areas, flag) = (w.areas.clone(), Arc::clone(&cancel));
        let verdict = tokio::task::spawn_blocking(move || {
            measure(&areas, w.limit, StageBounds::default(), &flag)
        })
        .await
        .unwrap_or_else(|e| Verdict::Unmeasurable {
            area: "watchdog".into(),
            reason: e.to_string(),
        });
        wait = STAGE_POLL.max(started.elapsed().saturating_mul(WALK_SPACING));
        match verdict {
            Verdict::Within { .. } => {}
            Verdict::Cancelled => return,
            Verdict::Over { bytes, largest } => break (Some(bytes), largest, None),
            Verdict::Unmeasurable { area, reason } => break (None, area, Some(reason)),
        }
    };
    let entry = NewEntry::new(Actor::Sallyd, "session.resource_limit")
        .session(&s.sid)
        .decision("deny")
        .args(json!({
            "role": "workspace",
            "resource": "stage_size",
            "limit": w.limit,
            "measured": measured,
            "area": capped(&area),
            "detail": detail.as_deref().map(capped),
        }));
    let _ = launcher.audit(entry, s.level).await;
    kill(&launcher, &s).await;
}

/// Kills and removes the container until it is confirmed gone.
async fn kill(launcher: &Launcher, s: &Session) {
    let mut reported = false;
    loop {
        let signal = [
            "kill".into(),
            "--signal".into(),
            "KILL".into(),
            s.container.as_str().into(),
        ];
        let killed = launcher.run("kill", signal).await;
        let removed = launcher.remove_container(&s.container).await;
        let Err(error) = removed else { return };
        if !reported {
            reported = true;
            let detail = match killed {
                Ok(_) => error.to_string(),
                Err(k) => format!("{k}; {error}"),
            };
            let entry = NewEntry::new(Actor::Sallyd, "session.kill_failed")
                .session(&s.sid)
                .decision("deny")
                .args(json!({
                    "container": s.container,
                    "detail": capped(&detail),
                }));
            let _ = launcher.audit(entry, s.level).await;
        }
        tokio::time::sleep(STAGE_POLL).await;
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// Review H2 (6c-1): the `.git` overlays of `rw` mounts are watched too, numbered as the argv
    /// numbers them (by mount, then by directory), and a session with neither gets no watchdog.
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
            "filesystem.mounts[0]/.git",
            "filesystem.mounts[2]/.git",
            "filesystem.mounts[2]/x/.git",
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
