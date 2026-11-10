//! The session's host directories (#10). `sessions/<id>` under the socket root and under the data
//! root are created fresh with mode 0700: kept `staged` upper directories may hold set-id files
//! that name the user's own uid, so no other local user may traverse to them. The seccomp
//! profiles are written into the session's own `profiles/` directory, so no file outside
//! Sallyport's control decides what a sandbox may call.
//!
//! Neither root is reachable from a sandbox: `~/.local/share/sallyport` and `$XDG_RUNTIME_DIR`
//! are on the built-in mount denylist (SI-7), and a sandbox sees only its own socket directory,
//! read-only. Blocking I/O; call from `spawn_blocking`.

use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use super::profiles::write_profiles;
use super::types::{OverlayDirs, SessionPaths};

/// Why a session directory could not be prepared.
#[derive(Debug, thiserror::Error)]
#[error("{path}: {msg}")]
pub struct DirError {
    /// Host path.
    pub path: String,
    /// What is wrong.
    pub msg: String,
    /// The session's directories already existed and nothing was created: whatever is there
    /// (a stopped session's kept `staged` changes) must not be removed.
    pub reused: bool,
}

fn fail<T>(path: &Path, msg: impl Into<String>) -> Result<T, DirError> {
    Err(DirError {
        path: path.display().to_string(),
        msg: msg.into(),
        reused: false,
    })
}

fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// `$XDG_RUNTIME_DIR` must be a real directory owned by the current user with no group or other
/// access (the logind default, 0700): sockets and the session's socket directories live in it.
///
/// # Errors
/// [`DirError`] naming the check that failed.
pub fn check_runtime_dir(dir: &Path) -> Result<(), DirError> {
    let meta = std::fs::symlink_metadata(dir).or_else(|e| fail(dir, e.to_string()))?;
    if !meta.is_dir() {
        return fail(dir, "XDG_RUNTIME_DIR is not a directory (or is a symlink)");
    }
    if meta.uid() != euid() {
        return fail(dir, "XDG_RUNTIME_DIR is not owned by the current user");
    }
    if meta.permissions().mode() & 0o077 != 0 {
        return fail(dir, "XDG_RUNTIME_DIR must be mode 0700");
    }
    Ok(())
}

/// A directory Sallyport already uses (a root): a real directory owned by the current user and
/// not writable by group or others. Created 0700 if missing.
fn root_dir(dir: &Path) -> Result<(), DirError> {
    match std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
    {
        Ok(()) => {}
        Err(e) => return fail(dir, e.to_string()),
    }
    let meta = std::fs::symlink_metadata(dir).or_else(|e| fail(dir, e.to_string()))?;
    if !meta.is_dir() || meta.uid() != euid() || meta.permissions().mode() & 0o022 != 0 {
        return fail(
            dir,
            "must be a directory owned by the current user and not writable by group or others",
        );
    }
    Ok(())
}

/// Creates `dir` with mode 0700 and checks the result: a directory, not a symlink, owned by the
/// current user, exactly 0700. With `fresh`, an existing entry is an error.
fn private(dir: &Path, fresh: bool) -> Result<(), DirError> {
    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(e) if !fresh && e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return fail(dir, "already exists; a session id is never reused");
        }
        Err(e) => return fail(dir, e.to_string()),
    }
    let meta = std::fs::symlink_metadata(dir).or_else(|e| fail(dir, e.to_string()))?;
    if !meta.is_dir() || meta.uid() != euid() || meta.permissions().mode() & 0o777 != 0o700 {
        return fail(
            dir,
            "must be a directory owned by the current user with mode 0700",
        );
    }
    Ok(())
}

fn overlay(dirs: &OverlayDirs) -> Result<(), DirError> {
    for d in [&dirs.upper, &dirs.work] {
        let Some(parent) = d.parent() else {
            return fail(d, "has no parent");
        };
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .or_else(|e| fail(parent, e.to_string()))?;
        private(parent, false)?;
        private(d, true)?;
    }
    Ok(())
}

/// The prepared directories of one session.
#[derive(Debug)]
pub struct SessionDirs {
    profiles: PathBuf,
}

impl SessionDirs {
    /// Creates `sessions/<id>` (fresh, 0700) under both roots of `paths`, the role socket
    /// directories, `profiles/` with the embedded seccomp profiles, and the upper and work
    /// directories of `staged` mounts (`stage`) and `.git` overlays (`git_overlays`).
    ///
    /// # Errors
    /// [`DirError`] if a root is not private, the session directory exists, or I/O fails.
    pub fn create(
        paths: &SessionPaths,
        xdg_runtime_dir: &Path,
        staged: &[usize],
        git_overlays: usize,
    ) -> Result<Self, DirError> {
        check_runtime_dir(xdg_runtime_dir)?;
        // Refuse a used id before creating anything, so the caller's cleanup never touches a
        // stopped session's kept data.
        for session in [paths.socket_root(), paths.data_root()] {
            if std::fs::symlink_metadata(session).is_ok() {
                return Err(DirError {
                    path: session.display().to_string(),
                    msg: "already exists; a session id is never reused".into(),
                    reused: true,
                });
            }
        }
        for session in [paths.socket_root(), paths.data_root()] {
            let Some(sessions) = session.parent() else {
                return fail(session, "has no parent");
            };
            let Some(root) = sessions.parent() else {
                return fail(sessions, "has no parent");
            };
            root_dir(root)?;
            private(sessions, false)?;
            private(session, true)?;
        }
        private(&paths.workspace_sockets(), true)?;
        private(&paths.harness_sockets(), true)?;
        let profiles = paths.data_root().join("profiles");
        private(&profiles, true)?;
        let fd = std::fs::File::open(&profiles).or_else(|e| fail(&profiles, e.to_string()))?;
        write_profiles(&fd).or_else(|e| fail(&profiles, e.to_string()))?;
        for &n in staged {
            overlay(&paths.stage(n))?;
        }
        for k in 0..git_overlays {
            overlay(&paths.git_overlay(k))?;
        }
        Ok(Self { profiles })
    }

    /// The directory holding `seccomp-<role>.json` for this session.
    #[must_use]
    pub fn profiles(&self) -> &Path {
        &self.profiles
    }
}
