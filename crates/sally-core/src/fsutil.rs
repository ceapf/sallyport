//! Small filesystem checks shared by the 0600 secrets store and the audit log: both live in a
//! directory only the owner may change, and both refuse to run otherwise.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

/// Group or other write bit.
const GROUP_OTHER_WRITE: u32 = 0o022;

/// Why a directory or file check failed. Callers map this into their own error enum.
#[derive(Debug)]
pub(crate) enum FsIssue {
    /// Not private enough, or not what it should be.
    Permissions {
        /// Host path.
        path: String,
        /// What is wrong and how to fix it.
        msg: String,
    },
    /// An I/O error.
    Io {
        /// Host path.
        path: String,
        /// The underlying error.
        source: std::io::Error,
    },
}

pub(crate) fn perm(path: &Path, msg: &str) -> FsIssue {
    FsIssue::Permissions {
        path: path.display().to_string(),
        msg: msg.to_owned(),
    }
}

/// Checks a directory that holds private files: owned by the current user or root, and not
/// writable by group or others (whoever can rename inside it can swap what it holds).
/// `Ok(false)` if it does not exist yet.
pub(crate) fn check_private_dir(dir: &Path) -> Result<bool, FsIssue> {
    let meta = match std::fs::metadata(dir) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => {
            return Err(FsIssue::Io {
                path: dir.display().to_string(),
                source: e,
            });
        }
    };
    let euid = rustix::process::geteuid().as_raw();
    if !meta.is_dir() {
        return Err(perm(dir, "is not a directory"));
    }
    if meta.uid() != euid && meta.uid() != 0 {
        return Err(perm(dir, "is not owned by the current user or root"));
    }
    let mode = meta.permissions().mode() & 0o7777;
    if mode & GROUP_OTHER_WRITE != 0 {
        return Err(perm(
            dir,
            &format!(
                "mode is {mode:04o}; the directory must not be writable by group or others; run chmod go-w"
            ),
        ));
    }
    Ok(true)
}
