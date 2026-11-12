//! The file tools' effects, confined by `openat2` beneath a pinned mount root (SI-8; ARCHITECTURE
//! §4.3; maintainer's Task 11 decisions 1–2; architect rulings Q29, Q30, Q35 and Q37). Blocking:
//! callers run these from `spawn_blocking`.
//!
//! Where a mount's files are reached ([`RootSource`]):
//! - `brokered` and `ro`: the host folder, opened by its realpath without following a symlink and
//!   compared with the launch pin (`dev:ino`), on every call; a mismatch is `mount-changed`.
//!   Resolution adds `RESOLVE_NO_XDEV`: a file system mounted inside the folder on the host is
//!   invisible in the sandbox (RT-FS-16), so the tools do not reach it either.
//! - `rw` and `staged`: the workspace's own view, through `/proc/<init>/root` of the container's
//!   init (a `/proc/<pid>` directory fd taken at launch, so a dead or reused pid fails the open
//!   and nothing resolves on the host root). The guest root of an `rw` mount must show the pin;
//!   a `staged` one must be a mount root on overlayfs. A write there lands where an in-container
//!   write would: the host folder for `rw` (with the `.git` shields of the launch), the session's
//!   upper directory for `staged`; the host folder of a staged mount is never written.
//!
//! Every path resolves with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS` from
//! that root: a `..`, a symlink anywhere (the last component too) or a magic link is
//! `path_escapes_mount`. Files open `O_NOFOLLOW | O_NONBLOCK` and must be regular after `fstat`
//! (a FIFO or device is never read from or written to); a write opens without `O_TRUNC` and
//! truncates only after that check. On `brokered` mounts a regular file with more than one link
//! is refused (`hard-link`): the broker would write through to a file outside the mount. Every
//! check is repeated at run time from the pinned root (the window between prepare and run can
//! last `approvals.timeout`).

use std::ffi::CStr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustix::fd::{AsFd, OwnedFd};
use rustix::fs::{AtFlags, FileType, Mode, OFlags, ResolveFlags, StatxAttributes, StatxFlags};
use rustix::io::Errno;
use sally_core::fd;

/// `OVERLAYFS_SUPER_MAGIC` (`linux/magic.h`).
const OVERLAYFS_MAGIC: i64 = 0x794c_7630;
/// Most entries one `fs_list` returns.
pub const MAX_ENTRIES: usize = 1000;
/// Mode a new file is created with (the broker's umask may narrow it).
pub const NEW_FILE_MODE: u32 = 0o644;

/// How a mount's root is found and checked.
#[derive(Debug, Clone)]
pub enum RootSource {
    /// `brokered` and `ro`: the host realpath, which must still be the pinned directory.
    Host {
        /// Host realpath of the mount root.
        path: PathBuf,
        /// Pinned `st_dev`.
        dev: u64,
        /// Pinned `st_ino`.
        ino: u64,
    },
    /// `rw`: the guest root in the container, which must show the pinned directory.
    Bind {
        /// `/proc/<init pid>` of the workspace container (taken at launch).
        proc_dir: Arc<OwnedFd>,
        /// Absolute guest root.
        guest: String,
        /// Pinned `st_dev`.
        dev: u64,
        /// Pinned `st_ino`.
        ino: u64,
    },
    /// `staged`: the guest root in the container, which must be an overlay mount root.
    Overlay {
        /// `/proc/<init pid>` of the workspace container (taken at launch).
        proc_dir: Arc<OwnedFd>,
        /// Absolute guest root.
        guest: String,
    },
}

/// Why a file operation did not happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsError {
    /// A `..`, symlink, magic link or mount crossing on the way.
    Escapes,
    /// Nothing there (or a parent is missing).
    NotFound,
    /// Not a regular file (a directory, FIFO, device or socket).
    NotAFile,
    /// Not a directory.
    NotADir,
    /// A regular file with more than one link, on a `brokered` mount.
    HardLink,
    /// A directory that is not empty (delete).
    NotEmpty,
    /// A read-only file system.
    ReadOnly,
    /// The mount root is no longer the pinned directory.
    MountChanged,
    /// The workspace container is gone.
    ContainerGone,
    /// Out of space or quota.
    NoSpace,
    /// The file system refused access.
    Permission,
    /// Any other error.
    Io(Errno),
}

impl FsError {
    /// The `denied: <code>` text.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Escapes => "path_escapes_mount",
            Self::NotFound => "not-found",
            Self::NotAFile => "not-a-file",
            Self::NotADir => "not-a-directory",
            Self::HardLink => "hard-link",
            Self::NotEmpty => "not-empty",
            Self::ReadOnly => "read-only",
            Self::MountChanged => "mount-changed",
            Self::ContainerGone => "container-gone",
            Self::NoSpace => "no-space",
            Self::Permission => "permission",
            Self::Io(_) => "io-error",
        }
    }

    fn from_errno(e: Errno) -> Self {
        match e {
            Errno::LOOP | Errno::XDEV => Self::Escapes,
            Errno::NOENT => Self::NotFound,
            Errno::ISDIR | Errno::NXIO => Self::NotAFile,
            Errno::NOTDIR => Self::NotADir,
            Errno::NOTEMPTY => Self::NotEmpty,
            Errno::ROFS => Self::ReadOnly,
            Errno::NOSPC | Errno::DQUOT => Self::NoSpace,
            Errno::ACCESS | Errno::PERM => Self::Permission,
            other => Self::Io(other),
        }
    }
}

/// An opened, checked mount root.
#[derive(Debug)]
pub struct Root {
    fd: OwnedFd,
    host_side: bool,
}

impl Root {
    fn resolve(&self) -> ResolveFlags {
        let base = ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS;
        if self.host_side {
            base | ResolveFlags::NO_XDEV
        } else {
            base
        }
    }

    fn open(&self, rel: &str, flags: OFlags, mode: Mode) -> Result<OwnedFd, FsError> {
        let rel = if rel.is_empty() { "." } else { rel };
        fd::openat2(&self.fd, rel, flags, mode, self.resolve()).map_err(FsError::from_errno)
    }

    /// The parent directory of `rel` (a canonical, non-empty path) and its last component.
    fn parent<'a>(&self, rel: &'a str) -> Result<(OwnedFd, &'a str), FsError> {
        let (dir, name) = rel.rsplit_once('/').unwrap_or(("", rel));
        let parent = self.open(dir, OFlags::PATH | OFlags::DIRECTORY, Mode::empty())?;
        Ok((parent, name))
    }
}

impl RootSource {
    /// Opens and checks the mount root.
    ///
    /// # Errors
    /// `mount-changed`, `container-gone`, or the open's error.
    pub fn open(&self) -> Result<Root, FsError> {
        match self {
            Self::Host { path, dev, ino } => {
                let fd = fd::openat2(
                    rustix::fs::CWD,
                    path.as_path(),
                    OFlags::PATH | OFlags::DIRECTORY,
                    Mode::empty(),
                    ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
                )
                .map_err(|_| FsError::MountChanged)?;
                same(&fd, *dev, *ino)?;
                Ok(Root {
                    fd,
                    host_side: true,
                })
            }
            Self::Bind {
                proc_dir,
                guest,
                dev,
                ino,
            } => {
                let fd = in_container(proc_dir, guest)?;
                same(&fd, *dev, *ino)?;
                Ok(Root {
                    fd,
                    host_side: false,
                })
            }
            Self::Overlay { proc_dir, guest } => {
                let fd = in_container(proc_dir, guest)?;
                overlay_root(&fd)?;
                Ok(Root {
                    fd,
                    host_side: false,
                })
            }
        }
    }
}

/// The guest directory `guest` in the container whose `/proc/<pid>` is `proc_dir`; the init
/// process must still be alive after the open, so the fd is that container's.
fn in_container(proc_dir: &OwnedFd, guest: &str) -> Result<OwnedFd, FsError> {
    let root = container_root(proc_dir)?;
    let rel = guest.trim_start_matches('/');
    let rel = if rel.is_empty() { "." } else { rel };
    let fd = fd::openat2(
        &root,
        rel,
        OFlags::PATH | OFlags::DIRECTORY,
        Mode::empty(),
        ResolveFlags::IN_ROOT | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| FsError::MountChanged)?;
    container_root(proc_dir)?;
    Ok(fd)
}

/// `/proc/<pid>/root` through the pid's directory fd: fails once that process is gone, even if
/// its pid was reused.
fn container_root(proc_dir: &OwnedFd) -> Result<OwnedFd, FsError> {
    fd::openat(
        proc_dir,
        "root",
        OFlags::PATH | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map_err(|_| FsError::ContainerGone)
}

fn same(fd: &OwnedFd, dev: u64, ino: u64) -> Result<(), FsError> {
    let st = rustix::fs::fstat(fd).map_err(|_| FsError::MountChanged)?;
    if (st.st_dev, st.st_ino) == (dev, ino) {
        Ok(())
    } else {
        Err(FsError::MountChanged)
    }
}

/// A mount root on overlayfs (`STATX_ATTR_MOUNT_ROOT`, `OVERLAYFS_SUPER_MAGIC`).
fn overlay_root(fd: &OwnedFd) -> Result<(), FsError> {
    let sx = rustix::fs::statx(fd, "", AtFlags::EMPTY_PATH, StatxFlags::BASIC_STATS)
        .map_err(|_| FsError::MountChanged)?;
    // A kernel without the attribute (before 5.8) never sets it: the check then refuses.
    let root = sx.stx_attributes.contains(StatxAttributes::MOUNT_ROOT);
    let fs = rustix::fs::fstatfs(fd).map_err(|_| FsError::MountChanged)?;
    if root && fs.f_type == OVERLAYFS_MAGIC {
        Ok(())
    } else {
        Err(FsError::MountChanged)
    }
}

/// What a read returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadOut {
    /// The file's size.
    pub size: u64,
    /// The bytes read (at most the `len` asked for).
    pub bytes: Vec<u8>,
}

/// Reads at most `len` bytes of the regular file `rel` from `offset`.
///
/// # Errors
/// [`FsError`].
pub fn read(root: &Root, rel: &str, offset: u64, len: u64) -> Result<ReadOut, FsError> {
    let f = root.open(
        rel,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )?;
    let st = regular(&f)?;
    let size = u64::try_from(st.st_size).unwrap_or(0);
    let want = usize::try_from(len.min(size.saturating_sub(offset))).unwrap_or(0);
    let mut bytes = vec![0u8; want];
    let mut got = 0usize;
    while let Some(rest) = bytes.get_mut(got..).filter(|r| !r.is_empty()) {
        let at = offset.saturating_add(u64::try_from(got).unwrap_or(u64::MAX));
        match rustix::io::pread(&f, rest, at) {
            Ok(0) => break,
            Ok(n) => got = got.saturating_add(n),
            Err(Errno::INTR) => {}
            Err(e) => return Err(FsError::from_errno(e)),
        }
    }
    bytes.truncate(got);
    Ok(ReadOut { size, bytes })
}

/// One directory entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Its name.
    pub name: String,
    /// `file`, `dir`, `symlink` or `other`.
    pub kind: &'static str,
    /// Its size (`lstat`), 0 if it vanished meanwhile.
    pub size: u64,
}

/// A directory listing.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Listing {
    /// At most [`MAX_ENTRIES`] entries, sorted by name.
    pub entries: Vec<Entry>,
    /// Whether entries were left out past [`MAX_ENTRIES`].
    pub truncated: bool,
    /// Entries whose names are not UTF-8: counted, never shown lossy.
    pub unlisted: u64,
}

/// Lists the directory `rel` (empty: the mount root).
///
/// # Errors
/// [`FsError`].
pub fn list(root: &Root, rel: &str) -> Result<Listing, FsError> {
    let dir = root.open(rel, OFlags::PATH | OFlags::DIRECTORY, Mode::empty())?;
    let reader = fd::openat(
        &dir,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(FsError::from_errno)?;
    let entries = rustix::fs::Dir::new(reader).map_err(FsError::from_errno)?;
    let mut out = Listing::default();
    for e in entries {
        let e = e.map_err(FsError::from_errno)?;
        let name = e.file_name();
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        let Ok(text) = name.to_str() else {
            out.unlisted = out.unlisted.saturating_add(1);
            continue;
        };
        if out.entries.len() == MAX_ENTRIES {
            out.truncated = true;
            break;
        }
        out.entries.push(entry(&dir, name, text, e.file_type()));
    }
    out.entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

fn entry(dir: &OwnedFd, name: &CStr, text: &str, t: FileType) -> Entry {
    let st = rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW).ok();
    let t = st
        .as_ref()
        .map_or(t, |s| FileType::from_raw_mode(s.st_mode));
    let kind = match t {
        FileType::RegularFile => "file",
        FileType::Directory => "dir",
        FileType::Symlink => "symlink",
        _ => "other",
    };
    let size = st.map_or(0, |s| u64::try_from(s.st_size).unwrap_or(0));
    Entry {
        name: text.to_owned(),
        kind,
        size,
    }
}

/// Checks that `rel` is a regular file beneath the root, as [`read`] opens it. No effect.
///
/// # Errors
/// [`FsError`].
pub fn check_read(root: &Root, rel: &str) -> Result<(), FsError> {
    let f = root.open(
        rel,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )?;
    regular(&f).map(|_| ())
}

/// Checks that `rel` (empty: the root) is a directory beneath the root. No effect.
///
/// # Errors
/// [`FsError`].
pub fn check_list(root: &Root, rel: &str) -> Result<(), FsError> {
    root.open(rel, OFlags::PATH | OFlags::DIRECTORY, Mode::empty())
        .map(|_| ())
}

/// Checks that `rel` can be written: its parent is a directory beneath the root, and the target
/// is absent or a regular file (with one link on a `brokered` mount). No effect.
///
/// # Errors
/// [`FsError`].
pub fn check_write(root: &Root, rel: &str, brokered: bool) -> Result<(), FsError> {
    let (parent, name) = root.parent(rel)?;
    match rustix::fs::statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(Errno::NOENT) => Ok(()),
        Err(e) => Err(FsError::from_errno(e)),
        Ok(st) => kind_ok(&st, brokered),
    }
}

/// Writes `bytes` to `rel`, creating it (mode [`NEW_FILE_MODE`]) or replacing its content.
///
/// # Errors
/// [`FsError`]; nothing was truncated unless the target was a regular file that passed.
pub fn write(root: &Root, rel: &str, bytes: &[u8], brokered: bool) -> Result<(), FsError> {
    let f = root.open(
        rel,
        OFlags::WRONLY | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::from_raw_mode(NEW_FILE_MODE),
    )?;
    let st = rustix::fs::fstat(&f).map_err(FsError::from_errno)?;
    kind_ok(&st, brokered)?;
    rustix::fs::ftruncate(&f, 0).map_err(FsError::from_errno)?;
    let mut done = 0usize;
    while let Some(rest) = bytes.get(done..).filter(|r| !r.is_empty()) {
        match rustix::io::write(&f, rest) {
            Ok(n) => done = done.saturating_add(n),
            Err(Errno::INTR) => {}
            Err(e) => return Err(FsError::from_errno(e)),
        }
    }
    Ok(())
}

/// Checks that `rel` can be deleted: a regular file or an empty-looking directory beneath the
/// root (emptiness is the kernel's to say at run time). No effect.
///
/// # Errors
/// [`FsError`].
pub fn check_delete(root: &Root, rel: &str) -> Result<(), FsError> {
    let (parent, name) = root.parent(rel)?;
    deletable(&parent, name).map(|_| ())
}

/// Deletes the regular file or empty directory `rel`, by name on its parent's fd.
///
/// # Errors
/// [`FsError`].
pub fn delete(root: &Root, rel: &str) -> Result<(), FsError> {
    let (parent, name) = root.parent(rel)?;
    let flags = deletable(&parent, name)?;
    rustix::fs::unlinkat(&parent, name, flags).map_err(FsError::from_errno)
}

/// The `unlinkat` flags for `name` in `parent`: a regular file or a directory; a symlink escapes,
/// anything else is not a file.
fn deletable(parent: &OwnedFd, name: &str) -> Result<AtFlags, FsError> {
    let st =
        rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(FsError::from_errno)?;
    match FileType::from_raw_mode(st.st_mode) {
        FileType::RegularFile => Ok(AtFlags::empty()),
        FileType::Directory => Ok(AtFlags::REMOVEDIR),
        FileType::Symlink => Err(FsError::Escapes),
        _ => Err(FsError::NotAFile),
    }
}

fn regular(f: &impl AsFd) -> Result<rustix::fs::Stat, FsError> {
    let st = rustix::fs::fstat(f).map_err(FsError::from_errno)?;
    if FileType::from_raw_mode(st.st_mode) == FileType::RegularFile {
        Ok(st)
    } else {
        Err(FsError::NotAFile)
    }
}

fn kind_ok(st: &rustix::fs::Stat, brokered: bool) -> Result<(), FsError> {
    match FileType::from_raw_mode(st.st_mode) {
        FileType::RegularFile if brokered && st.st_nlink > 1 => Err(FsError::HardLink),
        FileType::RegularFile => Ok(()),
        FileType::Symlink => Err(FsError::Escapes),
        _ => Err(FsError::NotAFile),
    }
}

/// The host path of `rel` on a mount whose host root is `root` (for the action and the audit).
#[must_use]
pub fn host_path(root: &Path, rel: &str) -> String {
    if rel.is_empty() {
        root.display().to_string()
    } else {
        root.join(rel).display().to_string()
    }
}

#[cfg(test)]
#[path = "fs_tests.rs"]
mod tests;
