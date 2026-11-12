//! Teardown: stopping a session, cleaning up after a failed launch, and removing orphans.

use std::sync::Arc;

use sally_core::audit::{Actor, NewEntry};
use sally_core::manifest::AuditLevel;
use serde_json::json;

use super::{
    LaunchError, Launcher, Progress, Running, SESSION_PREFIXES, STOP_RETRY, StopError, blocking,
    capped,
};
use crate::sandbox::commands::rm_args;
use crate::sandbox::types::SessionPaths;

impl Launcher {
    /// Removes session containers a previous `sallyd` left behind (`sp-ws-<scope>[-…]`,
    /// `sp-h-<scope>[-…]`), never a session live in this launcher, so the overlap rule starts
    /// from what is really running. `sallyd` calls it with an empty scope before it accepts the
    /// first launch. Audits each removal. TODO(#17): the single-instance lock that makes "a
    /// previous sallyd" exact arrives with the control socket (Task 12).
    ///
    /// # Errors
    /// [`LaunchError`] if podman cannot list or remove them.
    pub async fn remove_orphans(&self, scope: &str) -> Result<Vec<String>, LaunchError> {
        let out = self
            .run(
                "ps",
                [
                    "ps".into(),
                    "--all".into(),
                    "--format".into(),
                    "{{.Names}}".into(),
                ],
            )
            .await?;
        let mut removed = Vec::new();
        for name in out.lines().map(str::trim) {
            let Some(id) = SESSION_PREFIXES
                .iter()
                .find_map(|p| name.strip_prefix(p))
                .filter(|id| plain_name(id) && in_scope(id, scope))
            else {
                continue;
            };
            if self.sessions.is_live(id) {
                continue;
            }
            self.audit(
                NewEntry::new(Actor::Sallyd, "sandbox.orphan_removed")
                    .decision("deny")
                    .args(json!({"container": name})),
                AuditLevel::default(),
            )
            .await?;
            self.run("rm", rm_args(name)).await?;
            removed.push(name.to_owned());
        }
        Ok(removed)
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
                let _ = self.audit(entry, e.running.level).await;
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
    pub(super) async fn clean_failed(
        &self,
        paths: &SessionPaths,
        p: &Progress,
    ) -> Result<(), LaunchError> {
        if let Some(name) = &p.container {
            self.remove_container(name).await?;
        }
        for d in &p.dirs {
            // Only `sessions/<id>` under either root: what this launch created.
            if d != paths.socket_root() && d != paths.data_root() {
                return Err(LaunchError::Internal(format!(
                    "refusing to remove {}",
                    d.display()
                )));
            }
            self.unshare_rm(d).await?;
        }
        Ok(())
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

/// `id` is `scope` itself or starts with `scope-`; an empty scope covers every id.
fn in_scope(id: &str, scope: &str) -> bool {
    scope.is_empty() || id == scope || id.strip_prefix(scope).is_some_and(|r| r.starts_with('-'))
}

/// `[a-z0-9-]`, as session ids are.
fn plain_name(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orphan_scope_ends_at_a_dash() {
        assert!(in_scope("t1-1-a", "t1-1"));
        assert!(in_scope("t1-1", "t1-1"));
        assert!(in_scope("anything", ""));
        assert!(!in_scope("t1-10-a", "t1-1"));
        assert!(!in_scope("t1-1a", "t1-1"));
    }

    #[test]
    fn orphan_names_are_plain() {
        assert!(plain_name("t1-0-a"));
        for bad in ["", "A", "a b", "a/b", "a;b"] {
            assert!(!plain_name(bad), "{bad:?}");
        }
    }
}
