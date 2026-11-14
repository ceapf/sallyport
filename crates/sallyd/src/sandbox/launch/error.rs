//! Launch and stop errors, and the reason codes of `sandbox.refuse`.

use sally_core::audit::AuditError;

use super::Running;
use crate::egress::inject::CredentialsError;
use crate::egress::net::EgressError;
use crate::sandbox::dirs::DirError;
use crate::sandbox::inside::Mismatch;
use crate::sandbox::overlap::ReserveError;
use crate::sandbox::podman::PodmanError;
use crate::sandbox::scan::ScanError;
use crate::sandbox::types::{ArgvError, SessionId};

/// Why a launch failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LaunchError {
    /// The launch scan refused a mount.
    #[error(transparent)]
    Scan(#[from] ScanError),
    /// A mount root's identity chain could not be read.
    #[error("filesystem.mounts: {0}")]
    Claims(#[source] std::io::Error),
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
    /// The OCI config podman generated is not what the argv intended (Task 14, RT-SUP-04): the
    /// first differing field, never the config.
    #[error("sandbox.config_mismatch: {0}")]
    ConfigMismatch(crate::sandbox::oci::Mismatch),
    /// The container was not running, with the checked pid, after `podman start`.
    #[error("the container is not running after start: {0}")]
    NotRunning(String),
    /// A filesystem the sandbox could write to lacks the free-space floor (plus
    /// `runtime.stage_size` on the state filesystem).
    #[error("not enough free disk space: {0}")]
    DiskSpace(String),
    /// The container cgroup's `pids.events` or `memory.events` could not be opened or read
    /// (architect Q48, Q105: fail closed, the detail names the step).
    #[error("cgroup events: {0}")]
    CgroupEvents(String),
    /// The pinned image is not in local storage (`images.rs`).
    #[error("runtime.image: {0}")]
    ImageMissing(String),
    /// The manifest names no `runtime.image` and no bundled workspace image is installed
    /// (architect Q58). TODO(#88): the bundled image and its digest source.
    #[error(
        "runtime.image: no bundled workspace image is installed; the manifest must name a \
         digest-pinned image"
    )]
    NoDefaultImage,
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
    Audit(#[source] AuditError),
    /// The launch failed, and then its refusal could not be audited either.
    #[error("{original} (and the refusal could not be audited: {audit})")]
    Unaudited {
        /// Why the launch failed.
        original: Box<LaunchError>,
        /// Why the audit entry failed.
        audit: Box<LaunchError>,
    },
    /// A background task failed.
    #[error("internal: {0}")]
    Internal(String),
    /// The launch task of this session ended without a result (it panicked, or was cancelled at
    /// shutdown). The one launch error with no `sandbox.refuse` of its own: whoever reports it
    /// writes the entry (architect Q98).
    #[error("the launch task ended without a result")]
    Lost(SessionId),
    /// The session's egress could not be set up: trust roots, session CA, CA files, or the
    /// `net.sock` listener.
    #[error("network: {0}")]
    Egress(#[source] EgressError),
}

impl LaunchError {
    /// The `detail` of the `sandbox.refuse` entry: the error, capped. A control client is told
    /// exactly this, escaped (architect Q88).
    #[must_use]
    pub(crate) fn detail(&self) -> String {
        super::capped(&self.to_string())
    }

    /// The event of the refusal's audit entry: a mismatch found in the created container has
    /// its own, every other refusal is `sandbox.refuse`.
    #[must_use]
    pub(crate) fn event(&self) -> &'static str {
        match self {
            Self::MountMismatch(_) => "sandbox.mount_mismatch",
            Self::ConfigMismatch(_) => "sandbox.config_mismatch",
            Self::Scan(_)
            | Self::Claims(_)
            | Self::Overlap(_)
            | Self::Dirs(_)
            | Self::Argv(_)
            | Self::Podman(_)
            | Self::NotRunning(_)
            | Self::DiskSpace(_)
            | Self::CgroupEvents(_)
            | Self::ImageMissing(_)
            | Self::NoDefaultImage
            | Self::Command { .. }
            | Self::Audit(_)
            | Self::Unaudited { .. }
            | Self::Internal(_)
            | Self::Lost(_)
            | Self::Egress(_) => "sandbox.refuse",
        }
    }

    /// A short reason for the `sandbox.refuse` audit entry, and the control reply's reason.
    #[must_use]
    pub(crate) fn reason(&self) -> &'static str {
        match self {
            Self::Scan(ScanError::SocketInMount { .. }) => "socket-in-mount",
            Self::Scan(ScanError::TooManyShields { .. } | ScanError::Limit { .. }) => "scan-limit",
            Self::Scan(_) | Self::Claims(_) => "mount-changed",
            Self::Overlap(ReserveError::FdBudget(_)) => "fd-budget",
            Self::Overlap(_) => "overlap",
            Self::Dirs(_) => "session-dir",
            Self::Argv(_) => "argv",
            Self::Podman(_) => "podman-config",
            Self::MountMismatch(_) => "mount-mismatch",
            Self::ConfigMismatch(_) => "config-mismatch",
            Self::NotRunning(_) => "not-running",
            Self::DiskSpace(_) => "disk-floor",
            Self::CgroupEvents(_) => "cgroup-events",
            Self::ImageMissing(_) => "digest-mismatch",
            Self::NoDefaultImage => "no-default-image",
            Self::Command { .. } => "podman",
            Self::Audit(_) | Self::Unaudited { .. } => "audit",
            Self::Internal(_) => "internal",
            Self::Lost(_) => "start-failed",
            Self::Egress(EgressError::Listener(_)) => "egress-listener",
            Self::Egress(EgressError::Roots(_)) => "trust-roots",
            Self::Egress(EgressError::Ca(_) | EgressError::Files(_)) => "session-ca",
            Self::Egress(EgressError::Store(_)) => "secret-store",
            Self::Egress(EgressError::Credentials(CredentialsError::Missing(_))) => {
                "secret-missing"
            }
            Self::Egress(EgressError::Credentials(CredentialsError::NoFiller)) => "secret-filler",
            Self::Egress(EgressError::Credentials(
                CredentialsError::Format(_)
                | CredentialsError::Duplicate { .. }
                | CredentialsError::Header(_)
                | CredentialsError::TooLong(_),
            )) => "secret-grant",
        }
    }
}

/// [`Launcher::stop`](super::Launcher::stop) could not confirm the container is gone; the session
/// keeps its overlap claims and the caller keeps the handle to retry.
#[derive(Debug, thiserror::Error)]
#[error("stop {}: {error}", running.name)]
pub struct StopError {
    /// The session, still live.
    pub running: Running,
    /// What failed.
    pub error: LaunchError,
}

pub(super) fn join_err(e: tokio::task::JoinError) -> LaunchError {
    LaunchError::Internal(e.to_string())
}

/// The result the launch task of session `sid` sent; [`LaunchError::Lost`] if it sent none.
pub(super) async fn received<T>(
    rx: tokio::sync::oneshot::Receiver<Result<T, LaunchError>>,
    sid: SessionId,
) -> Result<T, LaunchError> {
    rx.await.unwrap_or(Err(LaunchError::Lost(sid)))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn sid() -> SessionId {
        SessionId::parse("s-1").unwrap()
    }

    /// Architect Q98: a launch task that ends without sending is `Lost`, naming its session; a
    /// sent result passes through unchanged.
    #[tokio::test]
    async fn a_launch_that_sent_nothing_is_lost_and_names_its_session() {
        let (tx, rx) = tokio::sync::oneshot::channel::<Result<u8, LaunchError>>();
        drop(tx);
        match received(rx, sid()).await {
            Err(LaunchError::Lost(s)) => assert_eq!(s.as_str(), "s-1"),
            other => panic!("{other:?}"),
        }
        let (tx, rx) = tokio::sync::oneshot::channel();
        tx.send(Ok(7u8)).unwrap();
        assert_eq!(received(rx, sid()).await.unwrap(), 7);
        let (tx, rx) = tokio::sync::oneshot::channel::<Result<u8, LaunchError>>();
        tx.send(Err(LaunchError::NoDefaultImage)).unwrap();
        assert!(matches!(
            received(rx, sid()).await,
            Err(LaunchError::NoDefaultImage)
        ));
    }

    #[test]
    fn a_config_mismatch_has_its_own_event_and_reason() {
        let e = LaunchError::ConfigMismatch(crate::sandbox::oci::Mismatch::new(
            "process.capabilities.bounding",
            "not empty",
        ));
        assert_eq!(e.event(), "sandbox.config_mismatch");
        assert_eq!(e.reason(), "config-mismatch");
        assert_eq!(
            e.detail(),
            "sandbox.config_mismatch: process.capabilities.bounding: not empty"
        );
        let m = LaunchError::MountMismatch(crate::sandbox::inside::Mismatch {
            guest: "/w".into(),
            why: "moved".into(),
        });
        assert_eq!(m.event(), "sandbox.mount_mismatch");
        assert_eq!(LaunchError::NoDefaultImage.event(), "sandbox.refuse");
    }

    #[test]
    fn a_lost_launch_is_start_failed_with_a_fixed_detail() {
        let e = LaunchError::Lost(sid());
        assert_eq!(e.reason(), "start-failed");
        assert_eq!(e.detail(), "the launch task ended without a result");
    }

    /// Architect Q105: a launch whose cgroup event files cannot be opened is refused
    /// `cgroup-events`, and the detail names the step that failed.
    #[test]
    fn unopenable_cgroup_events_refuse_naming_the_step() {
        let e = LaunchError::CgroupEvents("memory.events: No such file or directory".into());
        assert_eq!(e.reason(), "cgroup-events");
        assert_eq!(
            e.detail(),
            "cgroup events: memory.events: No such file or directory"
        );
    }
}
