//! The file tools' effects, confined by `openat2` beneath a pinned mount root (SI-8; ARCHITECTURE
//! §4.3; maintainer's Task 11 decisions 1–2; architect rulings Q29, Q30, Q35, Q37 and Q39).
//! Blocking: callers run these from `spawn_blocking`.
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
//! A path is walked one component at a time from the root, each opened from the previous fd
//! with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`: a `..`, a symlink
//! anywhere (the last component too) or a magic link is `path_escapes_mount`. Every object met
//! is judged by the sandbox's own identity before the next step ([`super::dac`], ruling Q39):
//! search on each directory (the root included), read on a file read, read and search on a
//! directory listed, write on a file written, write and search on the parent of a file created
//! or deleted; a refusal is `permission`, whether or not anything lies deeper. A file's last
//! component is first reached `O_PATH`, checked regular and judged on that fd; only then is the
//! same inode opened for I/O through `/proc/self/fd`, so a FIFO or device is never opened, read
//! from or written to. That open is `O_NONBLOCK`, so a file another process holds a lease on
//! fails at once instead of stalling the call (ruling Q40). An existing file is opened without
//! `O_TRUNC` and
//! truncated only after the checks; a new one is created `O_EXCL`, so the case judged is the
//! case that happened. On
//! `brokered` mounts a regular file with more than one link is refused (`hard-link`): the broker
//! would write through to a file outside the mount. Every check is repeated at run time from the
//! pinned root (the window between prepare and run can last `approvals.timeout`).

use std::ffi::CStr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustix::fd::{AsFd, AsRawFd as _, OwnedFd};
use rustix::fs::{AtFlags, FileType, Mode, OFlags, ResolveFlags, StatxAttributes, StatxFlags};
use rustix::io::Errno;
use sally_core::fd;

use super::dac::{self, Object, R, W, WX, X};
use crate::sandbox::UserIds;

/// `OVERLAYFS_SUPER_MAGIC` (`linux/magic.h`).
const OVERLAYFS_MAGIC: i64 = 0x794c_7630;
/// Most entries one `fs_list` returns.
pub const MAX_ENTRIES: usize = 1000;
/// Most directory entries one `fs_list` reads, listed or not (`.` and `..` included).
/// Ten times [`MAX_ENTRIES`].
pub const MAX_SCANNED: usize = 10_000;
/// Mode a new file is created with (the broker's umask may narrow it).
pub const NEW_FILE_MODE: u32 = 0o644;
/// The access ACL's extended attribute.
const ACL_XATTR: &str = "system.posix_acl_access";

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

/// Why a file operation did not happen. It displays as its `denied:`/`failed:` code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
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
    /// The sandbox's identity may not do this (or the file system refused it).
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

// The flag sets, one per function, so each `|` is checked by the disjoint-flags proof
// (`crates/sally-core/tests/mutants_config.rs`).

fn beneath() -> ResolveFlags {
    ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS
}

fn beneath_same_fs() -> ResolveFlags {
    ResolveFlags::BENEATH
        | ResolveFlags::NO_SYMLINKS
        | ResolveFlags::NO_MAGICLINKS
        | ResolveFlags::NO_XDEV
}

fn no_links() -> ResolveFlags {
    ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS
}

fn in_root() -> ResolveFlags {
    ResolveFlags::IN_ROOT | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS
}

fn dir_path() -> OFlags {
    OFlags::PATH | OFlags::DIRECTORY
}

// The two reopen sets follow the `/proc/self/fd` magic link (no `O_NOFOLLOW`) to an inode
// already checked regular (`reopen`): a type never changes, so `O_NOCTTY` could not matter.
// `O_NONBLOCK` still does: a lease another process holds fails the open at once instead of
// stalling it until the lease breaks.
fn read_file() -> OFlags {
    OFlags::RDONLY | OFlags::NONBLOCK
}

fn write_existing() -> OFlags {
    OFlags::WRONLY | OFlags::NONBLOCK
}

// `O_CREAT | O_EXCL` never follows a symlink and only ever makes a new regular file, so no
// `O_NOFOLLOW`, `O_NONBLOCK` or `O_NOCTTY` could change what it opens.
fn write_new() -> OFlags {
    OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL
}

/// An opened, checked mount root, and the sandbox identity objects are judged by.
#[derive(Debug)]
pub struct Root {
    fd: OwnedFd,
    host_side: bool,
    ids: UserIds,
}

impl Root {
    fn resolve(&self) -> ResolveFlags {
        if self.host_side {
            beneath_same_fs()
        } else {
            beneath()
        }
    }

    /// One path component `name` beneath `dir`.
    fn step(
        &self,
        dir: &OwnedFd,
        name: &str,
        flags: OFlags,
        mode: Mode,
    ) -> Result<OwnedFd, FsError> {
        fd::openat2(dir, name, flags, mode, self.resolve()).map_err(FsError::from_errno)
    }

    /// Judges `f` by the sandbox's identity for `want`; its `fstat`.
    fn judge(&self, f: &OwnedFd, want: u32) -> Result<rustix::fs::Stat, FsError> {
        let st = rustix::fs::fstat(f).map_err(FsError::from_errno)?;
        let o = Object {
            uid: st.st_uid,
            gid: st.st_gid,
            mode: st.st_mode,
            acl: has_acl(f),
        };
        if dac::allows(o, self.ids, want) {
            Ok(st)
        } else {
            Err(FsError::Permission)
        }
    }

    /// The directory `rel` (empty: the root), each directory on the way, the root and it
    /// included, judged searchable.
    fn dir(&self, rel: &str) -> Result<OwnedFd, FsError> {
        // `path.rs` gives relative paths only; an absolute one is never walked as relative.
        if rel.starts_with('/') {
            return Err(FsError::Escapes);
        }
        let mut at = self.step(&self.fd, ".", dir_path(), Mode::empty())?;
        self.judge(&at, X)?;
        for name in rel.split('/').filter(|s| !s.is_empty()) {
            at = self.step(&at, name, dir_path(), Mode::empty())?;
            self.judge(&at, X)?;
        }
        Ok(at)
    }

    /// The parent directory of `rel` (a canonical, non-empty path), judged searchable on the
    /// way, and its last component.
    fn parent<'a>(&self, rel: &'a str) -> Result<(OwnedFd, &'a str), FsError> {
        let (dir, name) = rel.rsplit_once('/').unwrap_or(("", rel));
        Ok((self.dir(dir)?, name))
    }
}

/// Whether `f` carries an access ACL, read through `/proc/self/fd/<n>` (an `O_PATH` fd refuses
/// `fgetxattr`; the magic link names this fd's object, never the guest path again). "No such
/// attribute" or "not supported" is no ACL; any other answer counts as one (ruling Q39).
fn has_acl(f: &OwnedFd) -> bool {
    let link = format!("/proc/self/fd/{}", f.as_raw_fd());
    let none: &mut [u8] = &mut [];
    match rustix::fs::getxattr(link.as_str(), ACL_XATTR, none) {
        Err(Errno::NODATA | Errno::NOTSUP) => false,
        Ok(_) | Err(_) => true,
    }
}

impl RootSource {
    /// Opens and checks the mount root; objects beneath it are judged as `ids`.
    ///
    /// # Errors
    /// `mount-changed`, `container-gone`, or the open's error.
    pub fn open(&self, ids: UserIds) -> Result<Root, FsError> {
        let (fd, host_side) = match self {
            Self::Host { path, dev, ino } => {
                let fd = fd::openat2(
                    rustix::fs::CWD,
                    path.as_path(),
                    dir_path(),
                    Mode::empty(),
                    no_links(),
                )
                .map_err(|_| FsError::MountChanged)?;
                same(&fd, *dev, *ino)?;
                (fd, true)
            }
            Self::Bind {
                proc_dir,
                guest,
                dev,
                ino,
            } => {
                let fd = in_container(proc_dir, guest)?;
                same(&fd, *dev, *ino)?;
                (fd, false)
            }
            Self::Overlay { proc_dir, guest } => {
                let fd = in_container(proc_dir, guest)?;
                overlay_root(&fd)?;
                (fd, false)
            }
        };
        Ok(Root { fd, host_side, ids })
    }
}

/// The guest directory `guest` in the container whose `/proc/<pid>` is `proc_dir`; the init
/// process must still be alive after the open, so the fd is that container's.
fn in_container(proc_dir: &OwnedFd, guest: &str) -> Result<OwnedFd, FsError> {
    let root = container_root(proc_dir)?;
    let rel = guest.trim_start_matches('/');
    let rel = if rel.is_empty() { "." } else { rel };
    let fd = fd::openat2(&root, rel, dir_path(), Mode::empty(), in_root())
        .map_err(|_| FsError::MountChanged)?;
    // Rule (ii), a race no test can force: the init dying between the two opens.
    container_root(proc_dir)?;
    Ok(fd)
}

/// `/proc/<pid>/root` through the pid's directory fd: fails once that process is gone, even if
/// its pid was reused.
fn container_root(proc_dir: &OwnedFd) -> Result<OwnedFd, FsError> {
    fd::openat(proc_dir, "root", dir_path(), Mode::empty()).map_err(|_| FsError::ContainerGone)
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

/// The regular file `rel`, judged readable, as an `O_PATH` fd: nothing is opened for I/O yet.
fn readable(root: &Root, rel: &str) -> Result<(OwnedFd, rustix::fs::Stat), FsError> {
    let (parent, name) = root.parent(rel)?;
    let p = root.step(&parent, name, OFlags::PATH, Mode::empty())?;
    regular(&p)?;
    let st = root.judge(&p, R)?;
    Ok((p, st))
}

/// Opens the object `p` (an `O_PATH` fd, already typed and judged) for I/O through its
/// `/proc/self/fd` magic link: the same inode, with the kernel's own access check and the
/// mount's flags, never a path resolved again. Opening is the first act on the object, so it
/// comes only after the type and the sandbox's identity were judged (security re-review
/// MEDIUM-1: opening a device node can act on its own).
fn reopen(p: &OwnedFd, flags: OFlags) -> Result<OwnedFd, FsError> {
    let link = format!("/proc/self/fd/{}", p.as_raw_fd());
    fd::open(link.as_str(), flags, Mode::empty()).map_err(FsError::from_errno)
}

/// Reads at most `len` bytes of the regular file `rel` from `offset`.
///
/// # Errors
/// [`FsError`].
pub fn read(root: &Root, rel: &str, offset: u64, len: u64) -> Result<ReadOut, FsError> {
    let (p, st) = readable(root, rel)?;
    let f = reopen(&p, read_file())?;
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

/// Checks that `rel` is a regular file the sandbox could read, as [`read`] opens it. No effect.
///
/// # Errors
/// [`FsError`].
pub fn check_read(root: &Root, rel: &str) -> Result<(), FsError> {
    readable(root, rel).map(|_| ())
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
    /// Whether entries were left out past [`MAX_ENTRIES`] or [`MAX_SCANNED`].
    pub truncated: bool,
    /// Entries whose names are not UTF-8: counted, never shown lossy.
    pub unlisted: u64,
}

/// The directory `rel`, judged readable and searchable (the listing stats its entries).
fn listable(root: &Root, rel: &str) -> Result<OwnedFd, FsError> {
    let dir = root.dir(rel)?;
    root.judge(&dir, R)?;
    Ok(dir)
}

/// Lists the directory `rel` (empty: the mount root).
///
/// # Errors
/// [`FsError`].
pub fn list(root: &Root, rel: &str) -> Result<Listing, FsError> {
    let dir = listable(root, rel)?;
    // `.` of the judged directory fd is that directory: nothing to follow, nothing else to open.
    let reader =
        fd::openat(&dir, ".", OFlags::RDONLY, Mode::empty()).map_err(FsError::from_errno)?;
    let entries = rustix::fs::Dir::new(reader).map_err(FsError::from_errno)?;
    let mut out = Listing::default();
    for (seen, e) in entries.enumerate() {
        // Unlisted names count too: a directory of millions of them is not read whole
        // (security review LOW-4).
        if seen >= MAX_SCANNED {
            out.truncated = true;
            break;
        }
        let e = e.map_err(FsError::from_errno)?;
        let name = e.file_name();
        if is_dot(name) {
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

/// Checks that `rel` (empty: the root) is a directory the sandbox could list. No effect.
///
/// # Errors
/// [`FsError`].
pub fn check_list(root: &Root, rel: &str) -> Result<(), FsError> {
    listable(root, rel).map(|_| ())
}

fn is_dot(name: &CStr) -> bool {
    matches!(name.to_bytes(), b"." | b"..")
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

/// Checks that `rel` can be written: an existing target is a regular file (with one link on a
/// `brokered` mount) the sandbox could write; an absent one has a parent the sandbox could
/// write. No effect.
///
/// # Errors
/// [`FsError`].
pub fn check_write(root: &Root, rel: &str, brokered: bool) -> Result<(), FsError> {
    let (parent, name) = root.parent(rel)?;
    match root.step(&parent, name, OFlags::PATH, Mode::empty()) {
        Ok(f) => {
            let st = rustix::fs::fstat(&f).map_err(FsError::from_errno)?;
            kind_ok(&st, brokered)?;
            root.judge(&f, W).map(|_| ())
        }
        Err(FsError::NotFound) => root.judge(&parent, WX).map(|_| ()),
        Err(e) => Err(e),
    }
}

/// Writes `bytes` to `rel`, replacing an existing file's content or creating it (mode
/// [`NEW_FILE_MODE`], `O_EXCL`).
///
/// # Errors
/// [`FsError`]; nothing was truncated unless the target was a regular file that passed.
pub fn write(root: &Root, rel: &str, bytes: &[u8], brokered: bool) -> Result<(), FsError> {
    let (parent, name) = root.parent(rel)?;
    let f = match root.step(&parent, name, OFlags::PATH, Mode::empty()) {
        Ok(p) => {
            let st = rustix::fs::fstat(&p).map_err(FsError::from_errno)?;
            kind_ok(&st, brokered)?;
            root.judge(&p, W)?;
            let f = reopen(&p, write_existing())?;
            rustix::fs::ftruncate(&f, 0).map_err(FsError::from_errno)?;
            f
        }
        Err(FsError::NotFound) => {
            root.judge(&parent, WX)?;
            let mode = Mode::from_raw_mode(NEW_FILE_MODE);
            root.step(&parent, name, write_new(), mode)
                .map_err(create_error)?
        }
        Err(e) => return Err(e),
    };
    let mut done = 0usize;
    while let Some(rest) = bytes.get(done..).filter(|r| !r.is_empty()) {
        match rustix::io::write(&f, rest) {
            // No progress on a non-empty buffer: stop rather than spin (rust review LOW 1).
            Ok(0) => return Err(FsError::Io(Errno::IO)),
            Ok(n) => done = done.saturating_add(n),
            Err(Errno::INTR) => {}
            Err(e) => return Err(FsError::from_errno(e)),
        }
    }
    Ok(())
}

/// Checks that `rel` can be deleted: its parent is one the sandbox could write, and it is a
/// regular file or a directory (emptiness is the kernel's to say at run time). No effect.
///
/// # Errors
/// [`FsError`].
pub fn check_delete(root: &Root, rel: &str) -> Result<(), FsError> {
    let (parent, name) = root.parent(rel)?;
    root.judge(&parent, WX)?;
    deletable(&parent, name).map(|_| ())
}

/// Deletes the regular file or empty directory `rel`, by name on its parent's fd.
///
/// # Errors
/// [`FsError`].
pub fn delete(root: &Root, rel: &str) -> Result<(), FsError> {
    let (parent, name) = root.parent(rel)?;
    root.judge(&parent, WX)?;
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

/// A failed `O_EXCL` create's error: a name created by someone else since the probe is refused
/// (`permission`), never judged as the wrong case; every other error is the create's own.
fn create_error(e: FsError) -> FsError {
    if e == FsError::Io(Errno::EXIST) {
        FsError::Permission
    } else {
        e
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
