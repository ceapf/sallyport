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

use sally_core::manifest::{MountMode, ValidatedManifest};

use super::profiles::write_profiles;
use super::types::{OverlayDirs, SessionPaths};

/// The manifest indices of `v`'s `staged` mounts: the only `stage/<n>` directories a session
/// gets. The staged-changes listing trusts that set (architect Q83), so this is where "only
/// staged mounts are listed" holds.
#[must_use]
pub fn staged_indices(v: &ValidatedManifest) -> Vec<usize> {
    v.mounts()
        .iter()
        .enumerate()
        .filter(|(_, m)| m.mode == MountMode::Staged)
        .map(|(i, _)| i)
        .collect()
}

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
    /// The session directories this call created before it failed, and only those: the
    /// caller's cleanup removes exactly these (6b re-review M-1).
    pub created: Vec<PathBuf>,
}

fn fail<T>(path: &Path, msg: impl Into<String>) -> Result<T, DirError> {
    Err(DirError {
        path: path.display().to_string(),
        msg: msg.into(),
        reused: false,
        created: Vec::new(),
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
        // Refuse a used id first, before any other check can fail and before anything is
        // created, so the caller's cleanup never touches a stopped session's kept data.
        for session in [paths.socket_root(), paths.data_root()] {
            if std::fs::symlink_metadata(session).is_ok() {
                return Err(DirError {
                    path: session.display().to_string(),
                    msg: "already exists; a session id is never reused".into(),
                    reused: true,
                    created: Vec::new(),
                });
            }
        }
        check_runtime_dir(xdg_runtime_dir)?;
        let mut created = Vec::new();
        Self::create_fresh(paths, staged, git_overlays, &mut created).map_err(|mut e| {
            e.created = created;
            e
        })
    }

    fn create_fresh(
        paths: &SessionPaths,
        staged: &[usize],
        git_overlays: usize,
        created: &mut Vec<PathBuf>,
    ) -> Result<Self, DirError> {
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
            created.push(session.to_owned());
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("sp-dirs-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
            Self(p)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn msg<T: std::fmt::Debug>(r: Result<T, DirError>) -> String {
        r.unwrap_err().msg
    }

    /// A manifest with `modes[i]` for mount `~/m<i>`. Under target/: the denylist refuses `/tmp`.
    fn manifest(tag: &str, modes: &[&str]) -> ValidatedManifest {
        use sally_core::manifest::{HostEnv, load};
        let home = std::env::current_dir()
            .unwrap()
            .join("../../target/dirs-unit")
            .join(format!("{}-{tag}", std::process::id()));
        let mut body = String::from(
            "apiVersion: sallyport/v1\nkind: Manifest\nname: t\nmodel:\n  ref: any\n\
             filesystem:\n  mounts:\n",
        );
        for (i, mode) in modes.iter().enumerate() {
            std::fs::create_dir_all(home.join(format!("m{i}"))).unwrap();
            body.push_str(&format!(
                "    - {{host: \"~/m{i}\", guest: /workspace/m{i}, mode: {mode}}}\n"
            ));
        }
        let env = HostEnv {
            home: home.clone(),
            other_homes: Vec::new(),
            xdg_config_home: None,
            xdg_data_home: None,
            xdg_runtime_dir: None,
            podman_storage: Vec::new(),
            nproc: 8,
            mem_bytes: 16 << 30,
        };
        let v = load(&body, &env, &std::collections::BTreeSet::new())
            .unwrap()
            .manifest;
        let _ = std::fs::remove_dir_all(&home);
        v
    }

    #[test]
    fn only_staged_mounts_get_a_stage_index() {
        let v = manifest("mixed", &["rw", "staged", "ro", "staged"]);
        assert_eq!(staged_indices(&v), [1, 3]);
        let v = manifest("none", &["rw", "ro"]);
        assert_eq!(staged_indices(&v), Vec::<usize>::new());
    }

    /// Each check of `private`, alone: an existing entry with and without `fresh`, and an
    /// error other than "exists" reported as itself.
    #[test]
    fn private_dirs_are_fresh_when_asked_and_report_their_own_error() {
        let s = Scratch::new("private");
        let d = s.0.join("d");
        private(&d, true).unwrap();
        private(&d, false).unwrap();
        assert_eq!(
            msg(private(&d, true)),
            "already exists; a session id is never reused"
        );
        if rustix::process::geteuid().is_root() {
            return;
        }
        std::fs::set_permissions(&s.0, std::fs::Permissions::from_mode(0o500)).unwrap();
        for fresh in [false, true] {
            let m = msg(private(&s.0.join("new"), fresh));
            assert!(m.contains("Permission denied"), "fresh={fresh}: {m}");
        }
    }

    /// Owned by another user is refused on its own, with every other check passing: `/` is
    /// root's and 0755 (a root), `/root` is root's and 0700 (a private directory).
    #[test]
    fn directories_of_another_user_are_refused() {
        if rustix::process::geteuid().is_root() {
            return;
        }
        let slash = std::fs::metadata("/").unwrap();
        assert_eq!((slash.uid(), slash.permissions().mode() & 0o022), (0, 0));
        assert!(msg(root_dir(Path::new("/"))).contains("owned by the current user"));
        let root_home = std::fs::symlink_metadata("/root").unwrap();
        assert_eq!(
            (root_home.uid(), root_home.permissions().mode() & 0o777),
            (0, 0o700)
        );
        assert!(msg(private(Path::new("/root"), false)).contains("owned by the current user"));
    }

    #[test]
    fn a_root_must_not_be_writable_by_others_and_is_created_0700() {
        let s = Scratch::new("root");
        let r = s.0.join("a/b");
        root_dir(&r).unwrap();
        let mode = std::fs::metadata(&r).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        std::fs::set_permissions(&r, std::fs::Permissions::from_mode(0o720)).unwrap();
        assert!(msg(root_dir(&r)).contains("not writable by group or others"));
    }
}
