//! The post-init mount check (AMENDMENTS-02 B4). After `podman init` the runtime has built the
//! container's mounts but has not started its process. From the host, `/proc/<init-pid>/root`
//! shows that mount namespace; every bind-mounted pin (mount roots, `.git` parent self-binds,
//! `.git` pointer files, the model blob) must show the pinned `st_dev:st_ino` at its guest path.
//! A mismatch means something was swapped between the scan and the mount (the 6a re-review's H1
//! race): the launcher removes the container and audits `sandbox.mount_mismatch`.
//!
//! Overlay lower layers cannot be compared this way (an overlay reports its own device); they are
//! re-checked on the host just before `podman create` ([`super::LaunchScan::recheck_host`]), and
//! the overlap rule keeps every other live sandbox from writing there. Blocking I/O.
//! TODO(#17): a launcher-level `sandbox.mount_mismatch` test (Task 6c if cheap, else Task 13).

use rustix::fd::AsFd;
use rustix::fs::{Mode, OFlags, ResolveFlags};

/// What must be at a guest path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expect {
    /// Absolute guest path.
    pub guest: String,
    /// `st_dev`.
    pub dev: u64,
    /// `st_ino`.
    pub ino: u64,
}

/// A guest path that does not show the pinned object.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{guest}: {why}")]
pub struct Mismatch {
    /// Absolute guest path.
    pub guest: String,
    /// What was found instead.
    pub why: String,
}

/// Checks every expectation inside the mount namespace of the process whose `/proc/<pid>`
/// directory is `proc_dir` (held, so a pid reused after the open names nothing: the open of
/// `root` fails instead of reaching another process).
///
/// # Errors
/// [`Mismatch`] for the first guest path that does not show its pinned object, or cannot be
/// opened.
pub fn check_in_container(proc_dir: impl AsFd, expect: &[Expect]) -> Result<(), Mismatch> {
    let root = sally_core::fd::openat(
        proc_dir,
        "root",
        OFlags::PATH | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map_err(|e| Mismatch {
        guest: "/".into(),
        why: format!("cannot open the init's root: {e}"),
    })?;
    for x in expect {
        let rel = x.guest.trim_start_matches('/');
        let st = sally_core::fd::openat2(
            &root,
            rel,
            OFlags::PATH | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::IN_ROOT | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .and_then(rustix::fs::fstat)
        .map_err(|e| Mismatch {
            guest: x.guest.clone(),
            why: format!("cannot be opened in the container: {e}"),
        })?;
        if (st.st_dev, st.st_ino) != (x.dev, x.ino) {
            return Err(Mismatch {
                guest: x.guest.clone(),
                why: format!(
                    "shows {}:{}, pinned {}:{}",
                    st.st_dev, st.st_ino, x.dev, x.ino
                ),
            });
        }
    }
    Ok(())
}
