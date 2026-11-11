//! The one place Sallyport opens a file descriptor with `rustix`: each wrapper adds `O_CLOEXEC`
//! to the caller's flags, so no broker descriptor (the secrets store, the audit log, a session
//! dir, a mount pin) survives the `exec` of Podman or a container's entry process.
//!
//! `clippy.toml` disallows `rustix::fs::{open, openat, openat2}` everywhere else; a call site
//! passes only the flags it needs, and a mutant that drops one of them can no longer drop
//! `O_CLOEXEC` with it. `std::fs` already opens with `O_CLOEXEC`.

use rustix::fd::{AsFd, OwnedFd};
use rustix::fs::{Mode, OFlags, ResolveFlags};
use rustix::path::Arg;

/// `open(2)` of `path` with `flags | O_CLOEXEC`.
///
/// # Errors
/// The `errno` of the open, unchanged, so callers can still match on it.
#[allow(clippy::disallowed_methods)] // The wrapper itself.
pub fn open<P: Arg>(path: P, flags: OFlags, mode: Mode) -> rustix::io::Result<OwnedFd> {
    rustix::fs::open(path, flags.union(OFlags::CLOEXEC), mode)
}

/// `openat(2)` of `path` beneath `dir` with `flags | O_CLOEXEC`.
///
/// # Errors
/// The `errno` of the open, unchanged.
#[allow(clippy::disallowed_methods)] // The wrapper itself.
pub fn openat<D: AsFd, P: Arg>(
    dir: D,
    path: P,
    flags: OFlags,
    mode: Mode,
) -> rustix::io::Result<OwnedFd> {
    rustix::fs::openat(dir, path, flags.union(OFlags::CLOEXEC), mode)
}

/// `openat2(2)` of `path` beneath `dir` with `flags | O_CLOEXEC` and the given resolve flags.
///
/// # Errors
/// The `errno` of the open, unchanged.
#[allow(clippy::disallowed_methods)] // The wrapper itself.
pub fn openat2<D: AsFd, P: Arg>(
    dir: D,
    path: P,
    flags: OFlags,
    mode: Mode,
    resolve: ResolveFlags,
) -> rustix::io::Result<OwnedFd> {
    rustix::fs::openat2(dir, path, flags.union(OFlags::CLOEXEC), mode, resolve)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::io::{FdFlags, fcntl_getfd};

    fn cloexec(fd: &OwnedFd) -> bool {
        fcntl_getfd(fd).unwrap().contains(FdFlags::CLOEXEC)
    }

    // Each wrapper, called without O_CLOEXEC in its flags, returns a close-on-exec descriptor.
    #[test]
    fn every_wrapper_adds_cloexec() {
        let flags = OFlags::PATH | OFlags::DIRECTORY;
        let root = open("/", flags, Mode::empty()).unwrap();
        let at = openat(&root, "dev", flags, Mode::empty()).unwrap();
        let at2 = openat2(&root, "dev", flags, Mode::empty(), ResolveFlags::BENEATH).unwrap();
        for (name, fd) in [("open", &root), ("openat", &at), ("openat2", &at2)] {
            assert!(
                cloexec(fd),
                "{name} returned a descriptor without FD_CLOEXEC"
            );
        }
    }

    // The caller's flags still reach the kernel: O_DIRECTORY refuses a file in every wrapper.
    #[test]
    fn caller_flags_still_apply() {
        let root = open("/", OFlags::PATH | OFlags::DIRECTORY, Mode::empty()).unwrap();
        let dir = OFlags::RDONLY | OFlags::DIRECTORY;
        assert_eq!(
            open("/dev/null", dir, Mode::empty()).err(),
            Some(rustix::io::Errno::NOTDIR)
        );
        assert_eq!(
            openat(&root, "dev/null", dir, Mode::empty()).err(),
            Some(rustix::io::Errno::NOTDIR)
        );
        assert_eq!(
            openat2(&root, "dev/null", dir, Mode::empty(), ResolveFlags::BENEATH).err(),
            Some(rustix::io::Errno::NOTDIR)
        );
    }
}
