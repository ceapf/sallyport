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

use std::path::Path;

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

/// Checks every expectation inside the mount namespace of `pid`.
///
/// # Errors
/// [`Mismatch`] for the first guest path that does not show its pinned object, or cannot be
/// opened.
pub fn check_in_container(pid: u32, expect: &[Expect]) -> Result<(), Mismatch> {
    let proc_root = format!("/proc/{pid}/root");
    let root = rustix::fs::open(
        Path::new(&proc_root),
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| Mismatch {
        guest: "/".into(),
        why: format!("cannot open {proc_root}: {e}"),
    })?;
    for x in expect {
        let rel = x.guest.trim_start_matches('/');
        let st = rustix::fs::openat2(
            &root,
            rel,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
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
