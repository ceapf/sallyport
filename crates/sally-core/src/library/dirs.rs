//! The library's directories: created at 0700 when missing, each opened beneath its parent's
//! descriptor and checked on that descriptor (a directory of the current user, mode exactly
//! 0700). A directory found with another mode is refused, never repaired.

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
    let dir = crate::fd::openat2(
        parent,
        name,
        OFlags::RDONLY.union(OFlags::DIRECTORY),
        Mode::empty(),
        RESOLVE,
    )
    .map_err(|e| LibraryError::io("open a library directory", e))?;
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
