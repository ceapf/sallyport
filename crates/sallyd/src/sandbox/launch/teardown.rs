//! Teardown: stopping a session, cleaning up after a failed launch, and removing orphans.

use std::sync::Arc;

use sally_core::audit::{Actor, NewEntry};
use sally_core::manifest::AuditLevel;
use serde_json::json;

use super::{
    LaunchError, Launcher, Progress, RoleRunning, RoleStopError, Running, STOP_RETRY, StopError,
    blocking, capped,
};
use crate::sandbox::commands::rm_args;
use crate::sandbox::orphans::{Orphan, orphans, ps_args};
use crate::sandbox::types::{Role, SessionPaths};

/// How many more times a stop nobody received retries once its container is gone (for an
/// instance's directories), [`STOP_RETRY`] apart.
const STOP_RETRIES_AFTER_REMOVAL: u32 = 3;

/// Which orphan sweep runs (architect Q61), named in each `sandbox.orphan_removed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sweep {
    /// Once, under the single-instance lock, before `control.sock` is bound.
    Startup,
    /// Every `daemon::sweep::ORPHAN_SWEEP` after that.
    Periodic,
}

impl Sweep {
    /// The wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::Periodic => "periodic",
        }
    }
}

impl Launcher {
    /// Removes this installation's session containers that no live session of this launcher
    /// owns (`sp-ws-<scope>[-…]`, `sp-h-<scope>[-…]`, labelled with this installation's id:
    /// [`crate::sandbox::orphans`], architect Q64), so the overlap rule starts from what is
    /// really running. A container without that label (another daemon's, a test run's) is never
    /// removed. `sallyd` (`daemon::serve`) calls it with an empty scope while it holds the
    /// single-instance lock (the `flock` on its runtime directory, `daemon::startup`) and before
    /// it binds `control.sock`, then periodically (`daemon::sweep`, architect Q61): a `podman
    /// create` a killed `sallyd` of this installation left running can make its container after
    /// the startup sweep. A launch reserves its id before it creates anything and keeps it until
    /// its container is confirmed gone, and ids are never reused, so no sweep removes a launch in
    /// progress. A container that a stop removes between the listing and the liveness check is
    /// no longer listed by the second look, so it is neither audited nor removed (S7). Audits
    /// each removal before it.
    ///
    /// # Errors
    /// [`LaunchError`] if podman cannot list or remove them, or a listing line is malformed.
    pub async fn remove_orphans(
        &self,
        scope: &str,
        sweep: Sweep,
    ) -> Result<Vec<String>, LaunchError> {
        let found = self.list_orphans(scope).await?;
        if found.is_empty() {
            return Ok(Vec::new());
        }
        // Not live now and still there: an orphan, since a stopped session's id stays live until
        // its container is confirmed gone.
        let still = self.list_orphans(scope).await?;
        let mut removed = Vec::new();
        for o in found.into_iter().filter(|o| still.contains(o)) {
            self.audit(
                NewEntry::new(Actor::Sallyd, "sandbox.orphan_removed")
                    .decision("deny")
                    .args(json!({"container": o.name, "id": o.container, "sweep": sweep.as_str()})),
                AuditLevel::default(),
            )
            .await?;
            // By ID: a name re-used since the listing is another container (PS-L5).
            self.run("rm", rm_args(&o.container)).await?;
            removed.push(o.name);
        }
        Ok(removed)
    }

    /// This installation's containers in `scope` that no live session owns.
    async fn list_orphans(&self, scope: &str) -> Result<Vec<Orphan>, LaunchError> {
        let out = self.run("ps", ps_args(&self.installation)).await?;
        orphans(&out, &self.installation, scope, |id| {
            self.sessions.is_live(id)
        })
        .map_err(|msg| LaunchError::Command { verb: "ps", msg })
    }

    /// Stops a launch nobody received, retrying until the container is gone. Meanwhile the
    /// handle keeps its disk watchdog, so the session stays bounded (6c-1 re-review M2). The
    /// first failure is audited as `sandbox.stop_failed`.
    pub(super) async fn stop_unreceived(&self, mut running: Running) {
        let mut reported = false;
        loop {
            let e = match self.stop(running).await {
                Ok(()) => return,
                Err(e) => e,
            };
            if !reported {
                reported = true;
                let entry = NewEntry::new(Actor::Sallyd, "sandbox.stop_failed")
                    .session(e.running.paths.id().as_str())
                    .decision("deny")
                    .args(json!({
                        "container": e.running.name,
                        "detail": capped(&e.error.to_string()),
                    }));
                if self.audit(entry, e.running.level).await.is_err() {
                    self.unaudited("sandbox.stop_failed", e.running.paths.id().as_str());
                }
            }
            // `stop` also fails after the container is gone (scratch removal): nothing runs.
            if matches!(self.container_exists(&e.running.name).await, Ok(false)) {
                return;
            }
            running = e.running;
            tokio::time::sleep(STOP_RETRY).await;
        }
    }

    /// Cleanup after a failed launch: the container by name if `create` was attempted (it may
    /// exist without a printed id), then the directories this launch created.
    pub(super) async fn clean_failed(&self, p: &Progress) -> Result<(), LaunchError> {
        if let Some(name) = &p.container {
            self.remove_container(name).await?;
        }
        for d in &p.dirs {
            // Only what this role's launch can create (`sessions/<id>` or `infer/<id>` under
            // either root).
            if !p.owned.contains(d) {
                return Err(LaunchError::Internal(format!(
                    "refusing to remove {}",
                    d.display()
                )));
            }
            self.unshare_rm(d).await?;
        }
        Ok(())
    }

    /// Stops and removes a harness or inference container, then the directories its launch
    /// created (an instance's; a harness has none, its session's directories stay). Audits
    /// `sandbox.stop` {role} first ({role, instance} for an instance), and frees the harness
    /// claim once the container is gone (architect Q130, Q139).
    ///
    /// A retry with the returned handle does only what is left: the entry if it failed, the
    /// container (by its id, never its name: a harness name is reused within a live session
    /// once the claim is free) and the claim only until they are confirmed gone and freed, once.
    ///
    /// # Errors
    /// [`RoleStopError`] carrying the handle back, when the container cannot be confirmed gone
    /// (the claim is kept), the entry cannot be written, or its directories cannot be removed.
    pub async fn stop_role(&self, mut r: RoleRunning) -> Result<(), Box<RoleStopError>> {
        let audited = if r.stop_audited {
            Ok(())
        } else {
            let a = self
                .audit(r.subject.entry("sandbox.stop", r.role, []), r.level)
                .await;
            r.stop_audited = a.is_ok();
            a
        };
        if !r.removed {
            if let Err(error) = self.remove_container(&r.container).await {
                return Err(Box::new(RoleStopError { running: r, error }));
            }
            r.removed = true;
            match r.role {
                Role::Harness => self.sessions.free_harness(r.subject.id().as_str()),
                Role::Workspace | Role::Inference => {}
            }
        }
        let mut cleaned = Ok(());
        for d in &r.dirs {
            if let Err(e) = self.unshare_rm(d).await {
                cleaned = Err(e);
                break;
            }
        }
        audited
            .and(cleaned)
            .map_err(|error| Box::new(RoleStopError { running: r, error }))
    }

    /// [`Self::stop_role`] for a launch nobody received, retried until the container is gone;
    /// the first failure is audited as `sandbox.stop_failed`. TODO(#135): one loop with
    /// [`Self::stop_unreceived`].
    pub(super) async fn stop_role_unreceived(&self, mut running: RoleRunning) {
        let mut reported = false;
        let mut after_removal = 0_u32;
        loop {
            let e = match self.stop_role(running).await {
                Ok(()) => return,
                Err(e) => e,
            };
            if !reported {
                reported = true;
                let r = &e.running;
                let entry = r
                    .subject
                    .entry(
                        "sandbox.stop_failed",
                        r.role,
                        [
                            ("container", r.name.clone().into()),
                            ("detail", capped(&e.error.to_string()).into()),
                        ],
                    )
                    .decision("deny");
                if self.audit(entry, r.level).await.is_err() {
                    self.oplog.error(
                        "sandbox",
                        "audit entry not written",
                        &[
                            ("event", "sandbox.stop_failed"),
                            (r.subject.kind(), r.subject.id().as_str()),
                        ],
                    );
                }
            }
            // `stop_role` also fails after the container is gone (the entry, the directories):
            // nothing runs any more, so only a bounded number of retries remain, for what the
            // retry still does (an instance's directories, which no sweep removes). Checked by
            // id, as it was removed.
            if e.running.removed {
                if after_removal >= STOP_RETRIES_AFTER_REMOVAL {
                    return;
                }
                after_removal += 1;
            } else if matches!(self.container_exists(&e.running.container).await, Ok(false)) {
                return;
            }
            running = e.running;
            tokio::time::sleep(STOP_RETRY).await;
        }
    }

    /// Stops and removes the container, discards the `.git` overlays, the profiles and the
    /// socket directory, keeps the `staged` upper directories, and releases the session's
    /// mounts. Audits `sandbox.stop` first.
    ///
    /// # Errors
    /// [`StopError`] when the container cannot be confirmed gone: the session keeps its claims
    /// and the error carries the handle back for a retry. A failure after that (scratch
    /// removal) is reported too, but the session is released.
    pub async fn stop(&self, mut r: Running) -> Result<(), Box<StopError>> {
        let sid = r.paths.id().as_str().to_owned();
        if let Some(w) = &r.watchdog {
            w.last_reading().await;
        }
        let audited = self
            .audit(
                NewEntry::new(Actor::Sallyd, "sandbox.stop")
                    .session(&sid)
                    .args(json!({"role": "workspace"})),
                r.level,
            )
            .await;
        // Holding the exec gate waits out a walk in progress (which holds it while the container
        // is frozen) and keeps a new one from freezing the container during removal.
        let gate = Arc::clone(&r.exec_gate);
        let held = gate.lock().await;
        let removed = self.remove_container(&r.name).await;
        drop(held);
        if let Err(error) = removed {
            return Err(Box::new(StopError { running: r, error }));
        }
        // The container is gone: nothing left to watch, and no client left for the proxy. Its
        // open tunnels end with `session-stopped` before the socket directory goes. Until here a
        // failed stop hands the handle back alive, so the policy holds while the container may
        // still exist (architect Q7).
        drop(r.watchdog.take());
        if let Some(egress) = r.egress.take() {
            egress.shutdown().await;
        }
        let cleaned = self.remove_dirs(&r.paths, true).await;
        self.sessions.release(&sid);
        audited
            .and(cleaned)
            .map_err(|error| Box::new(StopError { running: r, error }))
    }

    /// Removes the session's scratch. Files in overlay work directories belong to the
    /// container's user namespace, so removal runs through `podman unshare`.
    async fn remove_dirs(&self, paths: &SessionPaths, keep_stage: bool) -> Result<(), LaunchError> {
        let data = paths.data_root().to_owned();
        let targets = blocking(move || {
            let all = if keep_stage {
                vec![data.join("git"), data.join("profiles")]
            } else {
                vec![data]
            };
            Ok(all
                .into_iter()
                .filter(|t| std::fs::symlink_metadata(t).is_ok())
                .collect::<Vec<_>>())
        })
        .await?;
        for t in &targets {
            self.unshare_rm(t).await?;
        }
        let sockets = paths.socket_root().to_owned();
        blocking(move || match std::fs::remove_dir_all(&sockets) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(LaunchError::Internal(format!("{}: {e}", sockets.display()))),
        })
        .await
    }
}
