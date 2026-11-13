//! The periodic orphan sweep (architect Q61; security review M4).
//!
//! A `sallyd` killed with SIGKILL cannot stop the `podman create` it had started, so that
//! container can appear after the next `sallyd`'s startup sweep: unsupervised, holding mounts
//! the overlap rule does not know. Every [`ORPHAN_SWEEP`] the daemon removes this installation's
//! session containers that no live session owns (`Launcher::remove_orphans`, matched on the
//! installation label, never by name alone: architect Q64; each removal audited
//! `sandbox.orphan_removed` with `sweep: periodic` before it). A container without the label is
//! never removed. A failed sweep is an oplog line and is tried again at the next tick; only the
//! startup sweep refuses to start. The task's first act is the oplog line `orphan sweep started`,
//! which `tests/daemon.rs` reads to prove `serve` starts it.

use std::sync::Arc;
use std::time::Duration;

use crate::oplog::Oplog;
use crate::sandbox::{Launcher, Sweep};

/// The period of the sweep.
pub const ORPHAN_SWEEP: Duration = Duration::from_secs(60);
/// The oplog component.
const LOG: &str = "sweep";

/// Sweeps `scope` (empty: every session container) every `period`, the first time one period
/// from now; runs until dropped.
pub async fn every(launcher: Arc<Launcher>, scope: String, period: Duration, log: Oplog) {
    // First, inside the task: the daemon test reads it to prove the sweep was started (S3).
    log.info(
        LOG,
        "orphan sweep started",
        &[("period_secs", &period.as_secs().to_string())],
    );
    let start = tokio::time::Instant::now() + period;
    let mut tick = tokio::time::interval_at(start, period);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        match launcher.remove_orphans(&scope, Sweep::Periodic).await {
            Ok(removed) if removed.is_empty() => {}
            Ok(removed) => log.warn(
                LOG,
                "orphaned containers removed",
                &[("count", &removed.len().to_string())],
            ),
            Err(e) => log.error(LOG, "orphan sweep failed", &[("detail", &e.to_string())]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sweep_runs_every_minute() {
        assert_eq!(ORPHAN_SWEEP, Duration::from_secs(60));
    }
}
