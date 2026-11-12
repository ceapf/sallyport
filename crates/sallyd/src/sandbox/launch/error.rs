//! Launch and stop errors, and the reason codes of `sandbox.refuse`.

use sally_core::audit::AuditError;

use super::Running;
use crate::egress::net::EgressError;
use crate::sandbox::dirs::DirError;
use crate::sandbox::inside::Mismatch;
use crate::sandbox::overlap::ReserveError;
use crate::sandbox::podman::PodmanError;
use crate::sandbox::scan::ScanError;
use crate::sandbox::types::ArgvError;

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
    /// The container was not running, with the checked pid, after `podman start`.
    #[error("the container is not running after start: {0}")]
    NotRunning(String),
    /// A filesystem the sandbox could write to lacks the free-space floor (plus
    /// `runtime.stage_size` on the state filesystem).
    #[error("not enough free disk space: {0}")]
    DiskSpace(String),
    /// The pinned image is not in local storage (`images.rs`).
    #[error("runtime.image: {0}")]
    ImageMissing(String),
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
    /// The session's egress could not be set up: trust roots, session CA, CA files, or the
    /// `net.sock` listener.
    #[error("network: {0}")]
    Egress(#[source] EgressError),
}

impl LaunchError {
    /// A short reason for the `sandbox.refuse` audit entry.
    pub(super) fn reason(&self) -> &'static str {
        match self {
            Self::Scan(ScanError::SocketInMount { .. }) => "socket-in-mount",
            Self::Scan(ScanError::TooManyShields { .. } | ScanError::Limit { .. }) => "scan-limit",
            Self::Scan(_) | Self::Claims(_) => "mount-changed",
            Self::Overlap(_) => "overlap",
            Self::Dirs(_) => "session-dir",
            Self::Argv(_) => "argv",
            Self::Podman(_) => "podman-config",
            Self::MountMismatch(_) => "mount-mismatch",
            Self::NotRunning(_) => "not-running",
            Self::DiskSpace(_) => "disk-floor",
            Self::ImageMissing(_) => "digest-mismatch",
            Self::Command { .. } => "podman",
            Self::Audit(_) | Self::Unaudited { .. } => "audit",
            Self::Internal(_) => "internal",
            Self::Egress(EgressError::Listener(_)) => "egress-listener",
            Self::Egress(EgressError::Roots(_)) => "trust-roots",
            Self::Egress(EgressError::Ca(_) | EgressError::Files(_)) => "session-ca",
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
