//! Launch and stop errors, and the reason codes of `sandbox.refuse`.

use sally_core::audit::AuditError;

use super::parts::PinError;
use super::{RoleRunning, Running};
use crate::egress::inject::CredentialsError;
use crate::egress::net::EgressError;
use crate::sandbox::dirs::DirError;
use crate::sandbox::inside::Mismatch;
use crate::sandbox::overlap::{HarnessClaimError, ReserveError};
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
    /// The manifest names no `harness.image` and no bundled harness image is installed
    /// (architect Q142). TODO(#88): the bundled image and its digest source.
    #[error(
        "harness.image: no bundled harness image is installed; the manifest must name a \
         digest-pinned image"
    )]
    NoHarnessImage,
    /// The harness's session is not live, or its harness is already claimed (architect Q139).
    #[error(transparent)]
    Harness(#[from] HarnessClaimError),
    /// A directory the harness's session should have made is missing or not private (Q142).
    #[error("session directory: {0}")]
    NoSession(#[source] DirError),
    /// GPU inference is refused until M3 (TODO(#116)): only CPU inference launches.
    #[error("gpu: GPU inference is not supported yet; only CPU inference launches")]
    GpuUnsupported,
    /// A host object a harness or inference launch pinned changed before `podman init`.
    #[error("pinned path: {0}")]
    Pin(#[from] PinError),
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
    /// TODO(#135): an inference launch's id is an instance's, not a session's; carry the
    /// subject.
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
            | Self::NoHarnessImage
            | Self::Harness(_)
            | Self::NoSession(_)
            | Self::GpuUnsupported
            | Self::Pin(_)
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
            Self::Overlap(ReserveError::SessionLimit(_)) => "session-limit",
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
            Self::NoDefaultImage | Self::NoHarnessImage => "no-default-image",
            Self::Harness(HarnessClaimError::NotLive(_)) | Self::NoSession(_) => "no-session",
            Self::Harness(HarnessClaimError::Claimed(_)) => "overlap",
            Self::GpuUnsupported => "gpu-unsupported",
            Self::Pin(_) => "mount-changed",
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

/// [`Launcher::stop_role`](super::Launcher::stop_role) could not confirm the container is gone,
/// or could not remove the directories after; the error carries the handle back for a retry.
#[derive(Debug, thiserror::Error)]
#[error("stop {}: {error}", running.name)]
pub struct RoleStopError {
    /// The container's handle.
    pub running: RoleRunning,
    /// What failed.
    pub error: LaunchError,
}

/// GPU inference stays refused until M3 (architect Q131, TODO(#116)): the first check of an
/// inference launch.
pub(super) fn cpu_only(gpu: bool) -> Result<(), LaunchError> {
    if gpu {
        Err(LaunchError::GpuUnsupported)
    } else {
        Ok(())
    }
}

/// `podman inspect` printed `true <pid>` with the pid checked after `init`.
pub(super) fn running_as(state: &str, pid: u32) -> Result<(), LaunchError> {
    if state.trim() == format!("true {pid}") {
        Ok(())
    } else {
        Err(LaunchError::NotRunning(format!(
            "state {:?}, expected running as pid {pid}",
            super::capped(state.trim())
        )))
    }
}

/// A failed podman command's stderr as its error text (architect Q295): whole, trimmed, up to
/// `max` bytes; a longer one withheld whole, never cut. The text can name what a sandbox
/// wrote, and the logs mask it before they cut it: a cut here, before the mask, could leave a
/// partial form that masking the rest brings inside their cut.
pub(crate) fn stderr_text(err: &[u8], max: usize) -> String {
    if err.len() <= max {
        String::from_utf8_lossy(err).trim().to_owned()
    } else {
        format!("stderr withheld: over {max} bytes")
    }
}

/// A successful podman command's stdout, read with `max + 1` bytes kept (#173, architect Q295
/// (5)): whole up to `max` bytes; a longer one is refused with a daemon-chosen text, never cut.
/// Stdout is parsed, so a cut on a line boundary would read as a shorter, well-formed answer
/// (an orphan sweep missing the containers past it), and an in-band literal could be parsed as
/// output (Q295 (4)).
pub(crate) fn stdout_text(
    verb: &'static str,
    out: &[u8],
    max: usize,
) -> Result<String, LaunchError> {
    if out.len() <= max {
        Ok(String::from_utf8_lossy(out).into_owned())
    } else {
        Err(LaunchError::Command {
            verb,
            msg: format!("stdout refused: over {max} bytes"),
        })
    }
}

/// A launch task that did not finish: `internal`, with a daemon-chosen detail, never tokio's
/// text (architect Q297).
pub(super) fn join_err(e: tokio::task::JoinError) -> LaunchError {
    LaunchError::Internal(crate::daemon::crash::join_text(&e).into())
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
    use crate::daemon::crash::JOIN_PANICKED;

    /// Architect Q295: a failed command's stderr is its error text whole (trimmed) up to the
    /// bound, and withheld whole past it: no byte of it, never a cut that a mask could miss.
    #[test]
    fn stderr_is_whole_up_to_the_bound_and_withheld_past_it() {
        let max = 24;
        assert_eq!(
            stderr_text(b"  no such container\n", max),
            "no such container"
        );
        let at = "z".repeat(max);
        assert_eq!(stderr_text(at.as_bytes(), max), at);
        let over = "z".repeat(max + 1);
        let withheld = stderr_text(over.as_bytes(), max);
        assert_eq!(withheld, "stderr withheld: over 24 bytes");
        assert!(!withheld.contains('z'));
        assert_eq!(stderr_text(&[0xff, b'a'], max), "\u{fffd}a");
    }

    /// #173 (architect Q295 (4), (5)): a successful command's stdout is parsed, so it is kept
    /// whole and untrimmed up to the bound and refused past it, with a constant text that holds
    /// no byte of it.
    #[test]
    fn stdout_is_whole_up_to_the_bound_and_refused_past_it() {
        let max = 24;
        assert_eq!(stdout_text("ps", b" a\n", max).unwrap(), " a\n");
        let at = "z".repeat(max);
        assert_eq!(stdout_text("ps", at.as_bytes(), max).unwrap(), at);
        let over = "z".repeat(max + 1);
        match stdout_text("ps", over.as_bytes(), max) {
            Err(e @ LaunchError::Command { verb: "ps", .. }) => {
                let text = e.to_string();
                assert_eq!(text, "podman ps: stdout refused: over 24 bytes");
                assert!(!text.contains('z'));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(stdout_text("ps", &[0xff, b'a'], max).unwrap(), "\u{fffd}a");
    }

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
    fn only_running_as_the_checked_pid_counts() {
        assert!(running_as("true 42\n", 42).is_ok());
        for bad in ["false 0", "true 43", "true 42 x", "", "TRUE 42"] {
            let e = running_as(bad, 42).unwrap_err();
            assert!(matches!(e, LaunchError::NotRunning(_)), "{bad:?}");
            assert_eq!(e.reason(), "not-running");
            assert!(e.to_string().contains("expected running as pid 42"), "{e}");
        }
    }

    /// Architect Q142: a harness with no image to run names the harness field, with the
    /// workspace's reason.
    #[test]
    fn a_missing_harness_image_names_its_field() {
        let e = LaunchError::NoHarnessImage;
        assert_eq!(e.reason(), "no-default-image");
        assert_eq!(e.event(), "sandbox.refuse");
        assert_eq!(
            e.to_string(),
            "harness.image: no bundled harness image is installed; the manifest must name a \
             digest-pinned image"
        );
    }

    /// Architect Q139, Q142, Q131: a harness outside a live session, or without its
    /// directories, is `no-session`; a second harness is `overlap`; GPU inference and a changed
    /// pin each have their own reason.
    #[test]
    fn role_refusals_have_their_own_reasons() {
        let not_live = LaunchError::from(HarnessClaimError::NotLive("s".into()));
        assert_eq!(not_live.reason(), "no-session");
        assert_eq!(not_live.event(), "sandbox.refuse");
        let claimed = LaunchError::from(HarnessClaimError::Claimed("s".into()));
        assert_eq!(claimed.reason(), "overlap");
        assert_eq!(claimed.detail(), "session s already has a harness (sp-h-s)");
        let dirs = LaunchError::NoSession(DirError {
            path: "/d".into(),
            msg: "gone".into(),
            reused: false,
            created: Vec::new(),
        });
        assert_eq!(dirs.reason(), "no-session");
        assert_eq!(dirs.detail(), "session directory: /d: gone");
        assert!(cpu_only(false).is_ok());
        assert!(matches!(cpu_only(true), Err(LaunchError::GpuUnsupported)));
        assert_eq!(LaunchError::GpuUnsupported.reason(), "gpu-unsupported");
        assert_eq!(LaunchError::GpuUnsupported.event(), "sandbox.refuse");
        let pin = LaunchError::from(PinError {
            path: "/p".into(),
            msg: "moved".into(),
        });
        assert_eq!(pin.reason(), "mount-changed");
        assert_eq!(pin.event(), "sandbox.refuse");
        assert_eq!(pin.detail(), "pinned path: /p: moved");
    }

    #[test]
    fn a_lost_launch_is_start_failed_with_a_fixed_detail() {
        let e = LaunchError::Lost(sid());
        assert_eq!(e.reason(), "start-failed");
        assert_eq!(e.detail(), "the launch task ended without a result");
    }

    /// Architect Q297: a launch task that panicked is refused `internal` with a fixed detail,
    /// never tokio's text (the panic message escaped, before the writer's mask).
    #[tokio::test]
    async fn a_panicked_launch_task_is_internal_with_a_fixed_detail() {
        let h = tokio::task::spawn_blocking(|| panic!("sp-q\"uote-vvvvvvvvvvvv"));
        let e = join_err(h.await.unwrap_err());
        assert_eq!(e.reason(), "internal");
        assert_eq!(e.detail(), format!("internal: {JOIN_PANICKED}"));
        assert_eq!(e.to_string(), format!("internal: {JOIN_PANICKED}"));
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
