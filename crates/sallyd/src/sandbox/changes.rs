//! The changes a session staged (RT-FS-15): what `sally session changes` lists (#20, Task 12).
//!
//! A `staged` mount is an overlay over the host directory, whose upper directory in Sallyport's
//! state keeps everything the sandbox wrote (SI-11: staged data is inert). The listing reads only
//! that upper directory, never the host directory:
//! - a non-directory entry is a path the sandbox created or modified (`Written`);
//! - a 0/0 character device is an overlay whiteout: a deleted path (`Deleted`);
//! - a directory marked opaque (`trusted.overlay.opaque` or, rootless, `user.overlay.opaque`) was
//!   replaced as a whole: nothing of the host directory below it shows (`Replaced`).
//!
//! Other directories are only the parents of changes and are not listed (an empty directory
//! the sandbox created is therefore not listed either). The tree is the sandbox's, so the walk
//! goes through directory fds, never follows a symlink, and is bounded like the stage walk. The
//! session may still be running: an entry that vanishes during the walk is skipped. The listing
//! also keeps at most `MAX_LISTING_BYTES` of paths in memory.
//!
//! This reads the kernel overlay's format, which rootless Podman 4.9 uses for `:O` mounts
//! (whiteout devices, opaque xattrs). fuse-overlayfs (`.wh.` files), redirect and metacopy are
//! not interpreted: Sallyport does not configure them.

use std::ffi::{CStr, OsStr};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Instant;

use rustix::fd::AsFd;
use rustix::fs::{AtFlags, FileType};
use rustix::io::Errno;
use sally_core::manifest::{MountMode, ValidatedManifest};

use super::stage::{StageBounds, open_dir};
use super::types::SessionPaths;

/// What happened to one path of a staged mount.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChangeKind {
    /// Created or modified: a file, symlink or other non-directory.
    Written,
    /// Deleted: an overlay whiteout.
    Deleted,
    /// A directory replaced as a whole (opaque): nothing of the host directory below it shows.
    Replaced,
}

/// One staged change.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Change {
    /// Manifest index of the staged mount (`filesystem.mounts[n]`).
    pub mount: usize,
    /// Path relative to the mount root.
    pub path: PathBuf,
    /// What happened to it.
    pub kind: ChangeKind,
}

/// The listing failed; nothing is listed for the session.
#[derive(Debug, thiserror::Error)]
#[error("filesystem.mounts[{mount}]: staged changes: {reason}")]
pub struct ChangesError {
    /// Manifest index of the staged mount.
    pub mount: usize,
    /// Why.
    pub reason: String,
}

/// Lists the changes of every `staged` mount of `v` in the session at `paths`, sorted by mount,
/// then path. Blocking.
///
/// # Errors
/// [`ChangesError`] when an upper directory cannot be read, or a walk exceeds its bounds.
pub fn staged_changes(
    v: &ValidatedManifest,
    paths: &SessionPaths,
) -> Result<Vec<Change>, ChangesError> {
    let mut walk = Walk::new(StageBounds::default());
    let mut out = Vec::new();
    for (mount, m) in v.mounts().iter().enumerate() {
        if m.mode != MountMode::Staged {
            continue;
        }
        let found = list_upper(&paths.stage(mount).upper, &mut walk)
            .map_err(|reason| ChangesError { mount, reason })?;
        out.extend(
            found
                .into_iter()
                .map(|(path, kind)| Change { mount, path, kind }),
        );
    }
    out.sort();
    Ok(out)
}

/// Most bytes one listing keeps in memory (path bytes plus a fixed per-entry cost): the sandbox
/// chooses the names, and empty files cost almost nothing against `stage_size`, so the entry
/// bound alone does not bound the memory.
const MAX_LISTING_BYTES: u64 = 16 << 20;

/// Entry count, listing size and deadline across all mounts of one listing.
struct Walk {
    bounds: StageBounds,
    entries: u64,
    bytes: u64,
    max_bytes: u64,
    until: Instant,
}

impl Walk {
    fn new(bounds: StageBounds) -> Self {
        Self {
            bounds,
            entries: 0,
            bytes: 0,
            max_bytes: MAX_LISTING_BYTES,
            until: Instant::now() + bounds.deadline,
        }
    }

    /// Accounts for one listed path, plus a fixed cost for its `Change` and allocation; fails
    /// closed past `max_bytes`.
    fn keep(&mut self, path: &Path) -> Result<(), String> {
        const PER_ENTRY: u64 = 64;
        let len = u64::try_from(path.as_os_str().len())
            .unwrap_or(u64::MAX)
            .saturating_add(PER_ENTRY);
        self.bytes = self.bytes.saturating_add(len);
        if self.bytes > self.max_bytes {
            return Err(format!(
                "the listing exceeds {} bytes of paths",
                self.max_bytes
            ));
        }
        Ok(())
    }

    fn step(&mut self) -> Result<(), String> {
        if Instant::now() > self.until {
            let secs = self.bounds.deadline.as_secs();
            return Err(format!("the walk took longer than {secs} s"));
        }
        self.entries = self.entries.saturating_add(1);
        if self.entries > self.bounds.max_entries {
            return Err(format!("more than {} entries", self.bounds.max_entries));
        }
        Ok(())
    }
}

/// Whether the directory `fd` carries an overlay opaque marker (the value `y`). An absent
/// attribute (ENODATA), a longer value (ERANGE: not `y`) or a filesystem without that namespace
/// (EOPNOTSUPP) is not opaque; any other error fails the listing rather than hide a replacement.
fn opaque(fd: impl AsFd) -> Result<bool, String> {
    for name in [c"trusted.overlay.opaque", c"user.overlay.opaque"] {
        let mut buf = [0u8; 1];
        match rustix::fs::fgetxattr(&fd, name, &mut buf) {
            Ok(1) if buf == *b"y" => return Ok(true),
            Ok(_) | Err(Errno::NODATA | Errno::RANGE | Errno::OPNOTSUPP) => {}
            Err(e) => return Err(format!("cannot read {name:?}: {e}")),
        }
    }
    Ok(false)
}

/// The changes under one upper directory, depth-first with one open directory per level.
/// TODO(#28): share one walker with `stage::measure`; name the relative path in errors.
fn list_upper(upper: &Path, walk: &mut Walk) -> Result<Vec<(PathBuf, ChangeKind)>, String> {
    let root = std::ffi::CString::new(upper.as_os_str().as_bytes())
        .map_err(|_| "the upper directory path contains a NUL byte".to_owned())?;
    let first = match open_dir(rustix::fs::CWD, &root) {
        Ok(d) => d,
        // The sandbox has written nothing yet.
        Err(Errno::NOENT) => return Ok(Vec::new()),
        Err(e) => return Err(format!("cannot open the upper directory: {e}")),
    };
    let mut out = Vec::new();
    // Open directories from the upper root down, and the relative path of the deepest one.
    let mut stack = vec![first];
    let mut rel = PathBuf::new();
    loop {
        let depth = stack.len();
        let Some(dir) = stack.last_mut() else { break };
        let Some(entry) = dir.read() else {
            stack.pop();
            rel.pop();
            continue;
        };
        let entry = entry.map_err(|e| format!("cannot read a directory: {e}"))?;
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        walk.step()?;
        let fd = dir.fd().map_err(|e| format!("directory fd: {e}"))?;
        let path = rel.join(OsStr::from_bytes(name.to_bytes()));
        let Some(kind) = classify(fd, name, depth, walk)? else {
            continue;
        };
        match kind {
            Entry::Leaf(kind) => {
                walk.keep(&path)?;
                out.push((path, kind));
            }
            Entry::Dir { child, replaced } => {
                if replaced {
                    walk.keep(&path)?;
                    out.push((path.clone(), ChangeKind::Replaced));
                }
                stack.push(child);
                rel = path;
            }
        }
    }
    Ok(out)
}

enum Entry {
    Leaf(ChangeKind),
    /// A directory, opened for the walk to descend into.
    Dir {
        child: rustix::fs::Dir,
        replaced: bool,
    },
}

/// Stats `name` in `fd`, opening it if it is a directory. `None`: it vanished.
fn classify(
    fd: rustix::fd::BorrowedFd<'_>,
    name: &CStr,
    depth: usize,
    walk: &Walk,
) -> Result<Option<Entry>, String> {
    let st = match rustix::fs::statat(fd, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) => st,
        Err(Errno::NOENT) => return Ok(None),
        Err(e) => return Err(format!("cannot stat an entry: {e}")),
    };
    match FileType::from_raw_mode(st.st_mode) {
        FileType::Directory => {
            if depth > walk.bounds.max_depth {
                let max = walk.bounds.max_depth;
                return Err(format!("deeper than {max} directories"));
            }
            let child = match open_dir(fd, name) {
                Ok(d) => d,
                Err(Errno::NOENT) => return Ok(None),
                Err(e) => return Err(format!("cannot open a directory: {e}")),
            };
            let dfd = child.fd().map_err(|e| format!("directory fd: {e}"))?;
            let replaced = opaque(dfd)?;
            Ok(Some(Entry::Dir { child, replaced }))
        }
        FileType::CharacterDevice if st.st_rdev == 0 => Ok(Some(Entry::Leaf(ChangeKind::Deleted))),
        _ => Ok(Some(Entry::Leaf(ChangeKind::Written))),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    struct Tmp(PathBuf);

    impl Tmp {
        fn new(tag: &str) -> Self {
            // Under target/, like the stage walk's tests: `user.*` xattrs need a real filesystem
            // (a tmpfs `/tmp` only has them from kernel 6.6).
            let p = std::env::current_dir()
                .unwrap()
                .join("../../target/changes-unit")
                .join(format!("{}-{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
        fn file(&self, rel: &str) {
            let p = self.0.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, "x").unwrap();
        }
        fn list(&self, bounds: StageBounds) -> Result<Vec<(String, ChangeKind)>, String> {
            let found = list_upper(&self.0, &mut Walk::new(bounds))?;
            let mut v: Vec<_> = found
                .into_iter()
                .map(|(p, k)| (p.display().to_string(), k))
                .collect();
            v.sort();
            Ok(v)
        }
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn whiteout(p: &Path) {
        rustix::fs::mknodat(
            rustix::fs::CWD,
            p,
            FileType::CharacterDevice,
            rustix::fs::Mode::empty(),
            0,
        )
        .unwrap();
    }

    #[test]
    fn files_and_symlinks_are_written_whiteouts_deleted_and_parents_unlisted() {
        let t = Tmp::new("kinds");
        t.file("new.txt");
        t.file(".vscode/settings.json");
        t.file("sub/.git/config");
        std::os::unix::fs::symlink("/etc/passwd", t.0.join("link")).unwrap();
        whiteout(&t.0.join("gone.txt"));
        std::fs::create_dir(t.0.join("empty")).unwrap();
        let w = ChangeKind::Written;
        assert_eq!(
            t.list(StageBounds::default()).unwrap(),
            [
                (".vscode/settings.json".to_owned(), w),
                ("gone.txt".to_owned(), ChangeKind::Deleted),
                ("link".to_owned(), w),
                ("new.txt".to_owned(), w),
                ("sub/.git/config".to_owned(), w),
            ]
        );
    }

    #[test]
    fn an_opaque_directory_is_replaced_and_its_contents_listed() {
        let t = Tmp::new("opaque");
        t.file("dir/kept.txt");
        rustix::fs::setxattr(
            t.0.join("dir"),
            "user.overlay.opaque",
            b"y",
            rustix::fs::XattrFlags::empty(),
        )
        .unwrap();
        assert_eq!(
            t.list(StageBounds::default()).unwrap(),
            [
                ("dir".to_owned(), ChangeKind::Replaced),
                ("dir/kept.txt".to_owned(), ChangeKind::Written),
            ]
        );
    }

    #[test]
    fn a_missing_upper_lists_nothing_and_bounds_fail_closed() {
        let t = Tmp::new("bounds");
        let absent = list_upper(&t.0.join("absent"), &mut Walk::new(StageBounds::default()));
        assert_eq!(absent.unwrap(), []);
        t.file("a/b/c/d.txt");
        let shallow = StageBounds {
            max_depth: 1,
            ..StageBounds::default()
        };
        assert!(t.list(shallow).unwrap_err().contains("deeper than 1"));
        let few = StageBounds {
            max_entries: 2,
            ..StageBounds::default()
        };
        assert!(t.list(few).unwrap_err().contains("more than 2 entries"));
    }

    /// Names the sandbox chooses cannot grow the listing past its byte cap.
    #[test]
    fn the_listing_is_bounded_in_path_bytes() {
        let t = Tmp::new("bytes");
        for i in 0..8 {
            t.file(&format!("{}{i}", "n".repeat(200)));
        }
        let mut walk = Walk::new(StageBounds::default());
        walk.max_bytes = 1000;
        let e = list_upper(&t.0, &mut walk).unwrap_err();
        assert!(e.contains("exceeds 1000 bytes"), "{e}");
        let mut walk = Walk::new(StageBounds::default());
        assert_eq!(list_upper(&t.0, &mut walk).unwrap().len(), 8);
    }

    /// An xattr error other than "absent" fails the listing instead of hiding a replacement.
    #[test]
    fn an_unreadable_opaque_marker_fails_closed() {
        let t = Tmp::new("xattr");
        std::fs::create_dir(t.0.join("d")).unwrap();
        let fd = rustix::fs::open(
            t.0.join("d"),
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        assert_eq!(opaque(&fd), Ok(false));
        // An O_PATH fd cannot read xattrs (EBADF): a stand-in for EACCES/EIO.
        let path_fd = rustix::fs::open(
            t.0.join("d"),
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        assert!(opaque(&path_fd).is_err());
    }
}
