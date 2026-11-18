//! The library's directories: created at 0700 when missing, each opened beneath its parent's
//! descriptor and checked on that descriptor (a directory of the current user, mode exactly
//! 0700). A directory found with another mode is refused, never repaired.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use rustix::fd::OwnedFd;
use rustix::fs::{FileType, Mode, OFlags};
use rustix::io::Errno;

use super::{LibraryError, RESOLVE};
use crate::fsutil::{FsIssue, check_private_dir};

/// The library directory's name under the data directory.
const LIBRARY: &str = "library";
/// The only mode a library directory may have.
const DIR_MODE: u32 = 0o700;
/// Group or other write bit.
const GROUP_OTHER_WRITE: u32 = 0o022;

/// The pinned directory descriptors of an open library.
pub(super) struct Dirs {
    /// `library/`.
    pub(super) lib: OwnedFd,
    /// `library/blobs/sha256/`.
    pub(super) blobs: OwnedFd,
    /// `library/quarantine/`.
    pub(super) quarantine: OwnedFd,
}

/// Checks the data directory, then creates or opens the library tree beneath it. Returns the
/// descriptors and the library directory's path (for the index, the one path-based open).
pub(super) fn open(data_dir: &Path) -> Result<(Dirs, PathBuf), LibraryError> {
    if !data_dir.is_absolute() {
        return Err(not_private(data_dir, "must be an absolute path"));
    }
    if !check_private_dir(data_dir).map_err(from_issue)? {
        return Err(LibraryError::io(
            "open the data directory",
            std::io::Error::from(std::io::ErrorKind::NotFound),
        ));
    }
    let root = crate::fd::open(
        data_dir,
        OFlags::RDONLY.union(OFlags::DIRECTORY),
        Mode::empty(),
    )
    .map_err(|e| LibraryError::io("open the data directory", e))?;
    // The path was checked above; check the descriptor too, by the same rule.
    let st =
        rustix::fs::fstat(&root).map_err(|e| LibraryError::io("stat the data directory", e))?;
    if !data_dir_ok(st.st_mode, st.st_uid, rustix::process::geteuid().as_raw()) {
        return Err(not_private(
            data_dir,
            "must be a directory owned by the current user or root, not writable by group or \
             others",
        ));
    }
    let lib_path = data_dir.join(LIBRARY);
    let lib = ensure_dir(&root, LIBRARY, &lib_path)?;
    let blobs_parent = ensure_dir(&lib, "blobs", &lib_path.join("blobs"))?;
    let blobs = ensure_dir(&blobs_parent, "sha256", &lib_path.join("blobs/sha256"))?;
    let quarantine = ensure_dir(&lib, "quarantine", &lib_path.join("quarantine"))?;
    Ok((
        Dirs {
            lib,
            blobs,
            quarantine,
        },
        lib_path,
    ))
}

/// Creates `name` under `parent` at 0700 if missing, opens it beneath `parent` and checks it.
/// `shown` is its host path, for messages.
pub(super) fn ensure_dir(
    parent: &OwnedFd,
    name: &str,
    shown: &Path,
) -> Result<OwnedFd, LibraryError> {
    match rustix::fs::mkdirat(parent, name, Mode::from_raw_mode(DIR_MODE)) {
        Ok(()) | Err(Errno::EXIST) => {}
        Err(e) => return Err(LibraryError::io("create a library directory", e)),
    }
    open_private_dir(parent, name, shown)
}

/// Opens the directory `name` beneath `parent` and checks it on the descriptor.
pub(super) fn open_private_dir(
    parent: &OwnedFd,
    name: &str,
    shown: &Path,
) -> Result<OwnedFd, LibraryError> {
    let flags = OFlags::RDONLY.union(OFlags::DIRECTORY);
    let dir = match crate::fd::openat2(parent, name, flags, Mode::empty(), RESOLVE) {
        Ok(dir) => dir,
        Err(Errno::LOOP | Errno::NOTDIR) => {
            return Err(not_private(
                shown,
                "must be a directory, not a symlink or a file",
            ));
        }
        Err(e) => return Err(LibraryError::io("open a library directory", e)),
    };
    let st =
        rustix::fs::fstat(&dir).map_err(|e| LibraryError::io("stat a library directory", e))?;
    if !private_dir(st.st_mode, st.st_uid, rustix::process::geteuid().as_raw()) {
        return Err(LibraryError::NotPrivate {
            path: shown.display().to_string(),
            msg: format!(
                "must be a directory owned by the current user with mode 0700 (mode is {:04o}; \
                 chmod 700)",
                st.st_mode & 0o7777
            ),
        });
    }
    Ok(dir)
}

/// A directory of `euid` with mode exactly 0700.
pub(super) fn private_dir(st_mode: u32, uid: u32, euid: u32) -> bool {
    FileType::from_raw_mode(st_mode) == FileType::Directory
        && uid == euid
        && st_mode & 0o7777 == DIR_MODE
}

/// The data directory's rule, as [`check_private_dir`] applies it to the path: a directory of
/// `euid` or root, not writable by group or others.
pub(super) fn data_dir_ok(st_mode: u32, uid: u32, euid: u32) -> bool {
    FileType::from_raw_mode(st_mode) == FileType::Directory
        && (uid == euid || uid == 0)
        && st_mode & GROUP_OTHER_WRITE == 0
}

/// Whether two `(st_dev, st_ino)` pairs name the same object.
pub(super) fn same_object(a: (u64, u64), b: (u64, u64)) -> bool {
    a == b
}

/// Checks that `path` (followed as SQLite would follow it) names the object `fd` holds.
pub(super) fn path_is_fd(path: &Path, fd: &OwnedFd) -> Result<(), LibraryError> {
    let by_path =
        std::fs::metadata(path).map_err(|e| LibraryError::io("stat a library path", e))?;
    let by_fd = rustix::fs::fstat(fd).map_err(|e| LibraryError::io("stat a library path", e))?;
    if same_object((by_path.dev(), by_path.ino()), (by_fd.st_dev, by_fd.st_ino)) {
        Ok(())
    } else {
        Err(not_private(
            path,
            "changed while the library was being opened; open it again",
        ))
    }
}

fn not_private(path: &Path, msg: &str) -> LibraryError {
    LibraryError::NotPrivate {
        path: path.display().to_string(),
        msg: msg.to_owned(),
    }
}

/// A failed [`check_private_dir`] as a library error.
pub(super) fn from_issue(issue: FsIssue) -> LibraryError {
    match issue {
        FsIssue::Permissions { path, msg } => LibraryError::NotPrivate { path, msg },
        FsIssue::Io { source, .. } => LibraryError::io("check the data directory", source),
    }
}

#[cfg(test)]
#[path = "dirs_tests.rs"]
mod tests;
