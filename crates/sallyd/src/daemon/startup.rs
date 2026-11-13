//! The daemon's startup steps that run before anything else exists (architect Q42): process
//! hardening, the identity checks, and the single-instance lock on the runtime directory.
//!
//! The decisions are pure functions ([`check_ids`], [`check_state_dir`], [`nofile_target`]),
//! unit-tested here with the lock. The calls that change this process for good (umask, limits,
//! dumpable) are in `process.rs`: a test cannot make them without breaking the test process, so
//! the `sallyd` binary's tests cover them.

use std::os::fd::OwnedFd;
use std::path::Path;

use rustix::fs::{FileType, FlockOperation, Mode, OFlags};

/// The directory under `$XDG_RUNTIME_DIR` that holds `control.sock` and the session socket
/// directories, and whose fd carries the single-instance lock.
pub const STATE_DIR: &str = "sallyport";
/// `NOFILE` is never raised past this, even under an unlimited hard limit (the kernel's default
/// `fs.nr_open`).
pub const NOFILE_CEILING: u64 = 1 << 20;

/// Why `sallyd` refused to start.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StartError {
    /// `sallyd` never runs as root.
    #[error("sallyd refuses to run as root (euid 0); run it as the desktop user")]
    Root,
    /// A set-id launch: the real and effective ids differ.
    #[error("sallyd refuses to run set-id ({what} {real} differs from effective {effective})")]
    SetId {
        /// `uid` or `gid`.
        what: &'static str,
        /// Real id.
        real: u32,
        /// Effective id.
        effective: u32,
    },
    /// The runtime directory failed a check.
    #[error("{path}: {why}")]
    StateDir {
        /// The directory.
        path: String,
        /// The failed check.
        why: String,
    },
    /// Another `sallyd` of this user holds the lock.
    #[error("sallyd is already running ({0} is locked)")]
    AlreadyRunning(String),
    /// A hardening call failed.
    #[error("{what}: {source}")]
    Harden {
        /// The call.
        what: &'static str,
        /// Its error.
        #[source]
        source: std::io::Error,
    },
}

/// Refuses euid 0 and any set-id launch.
///
/// # Errors
/// [`StartError::Root`] or [`StartError::SetId`].
pub fn check_ids(uid: u32, euid: u32, gid: u32, egid: u32) -> Result<(), StartError> {
    if euid == 0 {
        return Err(StartError::Root);
    }
    if uid != euid {
        return Err(StartError::SetId {
            what: "uid",
            real: uid,
            effective: euid,
        });
    }
    if gid != egid {
        return Err(StartError::SetId {
            what: "gid",
            real: gid,
            effective: egid,
        });
    }
    Ok(())
}

/// The opened state directory must be a directory owned by `euid` with mode exactly 0700.
///
/// # Errors
/// The failed check, as text.
pub fn check_state_dir(mode: u32, owner: u32, euid: u32) -> Result<(), &'static str> {
    if FileType::from_raw_mode(mode) != FileType::Directory {
        return Err("is not a directory");
    }
    if owner != euid {
        return Err("is not owned by the current user");
    }
    if mode & 0o7777 != 0o700 {
        return Err("must be mode 0700 exactly");
    }
    Ok(())
}

/// The soft `NOFILE` to set: the hard limit (`None`: unlimited), never past [`NOFILE_CEILING`],
/// never below the current soft limit.
#[must_use]
pub fn nofile_target(soft: Option<u64>, hard: Option<u64>) -> u64 {
    let cap = hard.unwrap_or(NOFILE_CEILING).min(NOFILE_CEILING);
    cap.max(soft.unwrap_or(0).min(cap))
}

/// Step 4–5: creates `<runtime>/sallyport` (0700; an existing one is fine), opens it without
/// following a symlink, checks the opened directory, and takes the single-instance lock on that
/// fd. The returned fd holds the lock for as long as it lives (close-on-exec: no child inherits
/// it).
///
/// # Errors
/// [`StartError::StateDir`], or [`StartError::AlreadyRunning`] when another `sallyd` holds it.
pub fn open_and_lock(runtime: &Path) -> Result<OwnedFd, StartError> {
    let path = runtime.join(STATE_DIR);
    let shown = path.display().to_string();
    let fail = |why: String| StartError::StateDir {
        path: shown.clone(),
        why,
    };
    match rustix::fs::mkdir(&path, Mode::from_raw_mode(0o700)) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => {}
        Err(e) => return Err(fail(format!("mkdir: {e}"))),
    }
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let dir = sally_core::fd::open(&path, flags, Mode::empty())
        .map_err(|e| fail(format!("open: {e}")))?;
    let st = rustix::fs::fstat(&dir).map_err(|e| fail(format!("fstat: {e}")))?;
    check_state_dir(st.st_mode, st.st_uid, rustix::process::geteuid().as_raw())
        .map_err(|why| fail(why.to_owned()))?;
    match rustix::fs::flock(&dir, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(dir),
        Err(rustix::io::Errno::WOULDBLOCK) => Err(StartError::AlreadyRunning(shown)),
        Err(e) => Err(fail(format!("flock: {e}"))),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const DIR: u32 = 0o040_000;

    #[test]
    fn root_and_set_id_launches_are_refused() {
        assert!(check_ids(1000, 1000, 1000, 1000).is_ok());
        assert!(matches!(check_ids(0, 0, 0, 0), Err(StartError::Root)));
        assert!(matches!(
            check_ids(1000, 0, 1000, 1000),
            Err(StartError::Root)
        ));
        let e = check_ids(1000, 1001, 1000, 1000).unwrap_err();
        assert!(matches!(e, StartError::SetId { what: "uid", .. }), "{e}");
        let e = check_ids(1000, 1000, 1000, 1001).unwrap_err();
        assert!(matches!(e, StartError::SetId { what: "gid", .. }), "{e}");
        assert!(e.to_string().contains("1000") && e.to_string().contains("1001"));
    }

    #[test]
    fn the_state_dir_must_be_an_owned_0700_directory() {
        assert_eq!(check_state_dir(DIR | 0o700, 7, 7), Ok(()));
        assert!(check_state_dir(DIR | 0o700, 8, 7).is_err());
        for m in [0o750, 0o701, 0o710, 0o600, 0o1700, 0o4700, 0o500, 0o770] {
            assert!(check_state_dir(DIR | m, 7, 7).is_err(), "{m:o}");
        }
        assert!(check_state_dir(0o100_000 | 0o700, 7, 7).is_err(), "a file");
        assert!(
            check_state_dir(0o120_000 | 0o700, 7, 7).is_err(),
            "a symlink"
        );
    }

    #[test]
    fn nofile_goes_to_the_hard_limit_within_the_ceiling() {
        assert_eq!(nofile_target(Some(1024), Some(4096)), 4096);
        assert_eq!(nofile_target(Some(1024), Some(1024)), 1024);
        assert_eq!(nofile_target(Some(1024), None), NOFILE_CEILING);
        assert_eq!(nofile_target(None, None), NOFILE_CEILING);
        assert_eq!(
            nofile_target(Some(1024), Some(NOFILE_CEILING + 1)),
            NOFILE_CEILING
        );
        // Never lowered below the soft limit already in force, within the hard limit.
        assert_eq!(nofile_target(Some(9000), Some(4096)), 4096);
        assert_eq!(
            nofile_target(Some(NOFILE_CEILING * 2), None),
            NOFILE_CEILING
        );
    }

    fn scratch(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("sp-startup-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir(&d).unwrap();
        d
    }

    #[test]
    fn the_lock_is_exclusive_and_ends_with_its_fd() {
        let rt = scratch("lock");
        let held = open_and_lock(&rt).unwrap();
        let mode = std::fs::metadata(rt.join(STATE_DIR))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o7777, 0o700);
        let e = open_and_lock(&rt).unwrap_err();
        assert!(matches!(e, StartError::AlreadyRunning(_)), "{e}");
        assert!(
            e.to_string().starts_with("sallyd is already running"),
            "{e}"
        );
        drop(held);
        drop(open_and_lock(&rt).unwrap());
        std::fs::remove_dir_all(&rt).unwrap();
    }

    #[test]
    fn the_lock_fd_is_close_on_exec() {
        let rt = scratch("cloexec");
        let fd = open_and_lock(&rt).unwrap();
        let flags = rustix::io::fcntl_getfd(&fd).unwrap();
        assert!(flags.contains(rustix::io::FdFlags::CLOEXEC));
        drop(fd);
        std::fs::remove_dir_all(&rt).unwrap();
    }

    #[test]
    fn a_loose_or_symlinked_state_dir_is_refused() {
        let rt = scratch("loose");
        let dir = rt.join(STATE_DIR);
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o750)).unwrap();
        let e = open_and_lock(&rt).unwrap_err();
        assert!(e.to_string().contains("0700"), "{e}");
        std::fs::remove_dir(&dir).unwrap();
        let target = rt.join("elsewhere");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(&target, &dir).unwrap();
        let e = open_and_lock(&rt).unwrap_err();
        assert!(matches!(e, StartError::StateDir { .. }), "{e}");
        std::fs::remove_dir_all(&rt).unwrap();
    }
}
