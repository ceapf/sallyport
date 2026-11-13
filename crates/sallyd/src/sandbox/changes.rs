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
//! The listing needs no manifest (architect Q81), so it serves a live and a stopped session alike
//! (teardown keeps the stage), across `sallyd` restarts. It trusts only directory names `sallyd`
//! wrote (`sessions/<id>/stage/<n>/upper`) and fails closed on any other: every step is opened
//! by fd beneath the `sessions/` directory, with no symlink and no magic link.
//!
//! This reads the kernel overlay's format, which rootless Podman 4.9 uses for `:O` mounts
//! (whiteout devices, opaque xattrs). fuse-overlayfs (`.wh.` files), redirect and metacopy are
//! not interpreted: Sallyport does not configure them.

use std::ffi::{CStr, OsStr};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Instant;

use rustix::fd::{AsFd, BorrowedFd, OwnedFd};
use rustix::fs::{AtFlags, FileType, Mode, OFlags, ResolveFlags};
use rustix::io::Errno;

use super::stage::{StageBounds, open_dir};
use super::types::SessionId;

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
pub enum ChangesError {
    /// No `sessions/<id>` directory: the session never existed, or its data is gone.
    #[error("unknown-session")]
    UnknownSession,
    /// The session's `stage/` directory could not be listed, or holds a name `sallyd` never
    /// writes.
    #[error("stage: {0}")]
    Stage(String),
    /// A staged mount's upper directory could not be listed.
    #[error("filesystem.mounts[{mount}]: staged changes: {reason}")]
    Mount {
        /// Manifest index of the staged mount.
        mount: usize,
        /// Why.
        reason: String,
    },
}

/// Most digits of a `stage/<n>` name: a manifest has at most 64 mounts.
const MAX_INDEX_DIGITS: usize = 2;

/// Lists the changes of session `id`, live or stopped, sorted by mount, then path (architect
/// Q81). `sessions` is the open `sessions/` data directory. Blocking.
///
/// # Errors
/// [`ChangesError`]: no such session, a name in `stage/` that is not a canonical mount index or
/// not a directory, an unreadable directory, or a walk past its bounds.
pub fn session_changes(
    sessions: BorrowedFd<'_>,
    id: &SessionId,
) -> Result<Vec<Change>, ChangesError> {
    changes_within(sessions, id, StageBounds::default())
}

fn changes_within(
    sessions: BorrowedFd<'_>,
    id: &SessionId,
    bounds: StageBounds,
) -> Result<Vec<Change>, ChangesError> {
    let session = match beneath(sessions, id.as_str()) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Err(ChangesError::UnknownSession),
        Err(e) => return Err(ChangesError::Stage(format!("cannot open the session: {e}"))),
    };
    let stage = match beneath(&session, "stage") {
        Ok(fd) => fd,
        // No staged mount.
        Err(Errno::NOENT) => return Ok(Vec::new()),
        Err(e) => return Err(ChangesError::Stage(format!("cannot open stage/: {e}"))),
    };
    let mut walk = Walk::new(bounds);
    let mut out = Vec::new();
    for (mount, dir) in mounts(&stage, &mut walk).map_err(ChangesError::Stage)? {
        let upper = match beneath(&dir, "upper") {
            Ok(fd) => fd,
            // The sandbox has written nothing yet.
            Err(Errno::NOENT) => continue,
            Err(e) => {
                let reason = format!("cannot open the upper directory: {e}");
                return Err(ChangesError::Mount { mount, reason });
            }
        };
        let found =
            list_upper(upper, &mut walk).map_err(|reason| ChangesError::Mount { mount, reason })?;
        out.extend(
            found
                .into_iter()
                .map(|(path, kind)| Change { mount, path, kind }),
        );
    }
    out.sort();
    Ok(out)
}

/// Opens directory `name` beneath `dir`: no symlink anywhere, no magic link, no escape.
fn beneath(dir: impl AsFd, name: &str) -> Result<OwnedFd, Errno> {
    sally_core::fd::openat2(
        dir,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
}

/// The `stage/<n>` directories, opened, by mount index. Every entry counts against the walk's
/// bounds; a name that is not a canonical index, or an entry that is not a directory (a symlink
/// included), fails the listing: `sallyd` wrote these names, so anything else is never
/// skipped and never followed.
fn mounts(stage: &OwnedFd, walk: &mut Walk) -> Result<Vec<(usize, OwnedFd)>, String> {
    let mut dir = rustix::fs::Dir::read_from(stage).map_err(|e| format!("cannot read: {e}"))?;
    let mut out = Vec::new();
    while let Some(entry) = dir.read() {
        let entry = entry.map_err(|e| format!("cannot read: {e}"))?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        walk.step()?;
        let shown = sally_core::text::escape(name);
        let mount = mount_index(name).ok_or_else(|| format!("{shown}: not a mount index"))?;
        // A canonical index is ASCII digits, so `shown` is the name itself.
        let fd = beneath(stage, &shown).map_err(|e| format!("{shown}: {e}"))?;
        out.push((mount, fd));
    }
    out.sort_by_key(|(m, _)| *m);
    Ok(out)
}

/// `name` as a mount index: decimal digits only, no leading zero but `0` itself, at most
/// [`MAX_INDEX_DIGITS`] digits.
fn mount_index(name: &[u8]) -> Option<usize> {
    let canonical = !name.is_empty()
        && name.len() <= MAX_INDEX_DIGITS
        && name.iter().all(u8::is_ascii_digit)
        && (name == b"0" || name.first() != Some(&b'0'));
    if !canonical {
        return None;
    }
    std::str::from_utf8(name).ok()?.parse().ok()
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
        if super::stage::past(self.until) {
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
fn list_upper(upper: OwnedFd, walk: &mut Walk) -> Result<Vec<(PathBuf, ChangeKind)>, String> {
    let first =
        rustix::fs::Dir::new(upper).map_err(|e| format!("cannot read the upper directory: {e}"))?;
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
        /// This directory, opened as the walk opens an upper directory.
        fn fd(&self) -> OwnedFd {
            sally_core::fd::open(&self.0, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty())
                .unwrap()
        }
        fn list(&self, bounds: StageBounds) -> Result<Vec<(String, ChangeKind)>, String> {
            let found = list_upper(self.fd(), &mut Walk::new(bounds))?;
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
    fn the_bounds_fail_closed() {
        let t = Tmp::new("bounds");
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

    /// Every bound is inclusive: exactly the entry count, depth and listing bytes pass; one
    /// less fails. A walk past its deadline fails closed.
    #[test]
    fn the_bounds_are_inclusive_and_the_deadline_fails_closed() {
        let t = Tmp::new("exact");
        // Entries a, a/b, a/b/c, a/b/c/d.txt; directory c is found at depth 3.
        t.file("a/b/c/d.txt");
        let bounds = |max_entries, max_depth| StageBounds {
            max_entries,
            max_depth,
            ..StageBounds::default()
        };
        assert_eq!(t.list(bounds(4, 3)).unwrap().len(), 1);
        assert!(t.list(bounds(3, 3)).unwrap_err().contains("more than 3"));
        assert!(t.list(bounds(4, 2)).unwrap_err().contains("deeper than 2"));
        // One listed path, "a/b/c/d.txt": 11 bytes plus the 64-byte per-entry cost.
        let mut walk = Walk::new(StageBounds::default());
        walk.max_bytes = 75;
        assert_eq!(list_upper(t.fd(), &mut walk).unwrap().len(), 1);
        let mut walk = Walk::new(StageBounds::default());
        walk.max_bytes = 74;
        assert!(list_upper(t.fd(), &mut walk).is_err());
        let none = StageBounds {
            deadline: std::time::Duration::ZERO,
            ..StageBounds::default()
        };
        assert!(t.list(none).unwrap_err().contains("longer than"));
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
        let e = list_upper(t.fd(), &mut walk).unwrap_err();
        assert!(e.contains("exceeds 1000 bytes"), "{e}");
        let mut walk = Walk::new(StageBounds::default());
        assert_eq!(list_upper(t.fd(), &mut walk).unwrap().len(), 8);
    }

    /// Only a 0/0 character device is a whiteout: a real device node (`/dev/null`, 1:3) is a
    /// written entry, never a deletion the apply step would carry out.
    #[test]
    fn only_a_zero_zero_device_is_a_deletion() {
        let dev = sally_core::fd::open(
            "/dev",
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        let walk = Walk::new(StageBounds::default());
        match classify(dev.as_fd(), c"null", 1, &walk).unwrap() {
            Some(Entry::Leaf(kind)) => assert_eq!(kind, ChangeKind::Written),
            _ => panic!("/dev/null is a leaf"),
        }
    }

    /// An xattr error other than "absent" fails the listing instead of hiding a replacement.
    #[test]
    fn an_unreadable_opaque_marker_fails_closed() {
        let t = Tmp::new("xattr");
        std::fs::create_dir(t.0.join("d")).unwrap();
        let fd = sally_core::fd::open(
            t.0.join("d"),
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        assert_eq!(opaque(&fd), Ok(false));
        // A one-byte marker other than `y` is not opaque.
        rustix::fs::fsetxattr(
            &fd,
            "user.overlay.opaque",
            b"n",
            rustix::fs::XattrFlags::empty(),
        )
        .unwrap();
        assert_eq!(opaque(&fd), Ok(false));
        // An O_PATH fd cannot read xattrs (EBADF): a stand-in for EACCES/EIO.
        let path_fd = sally_core::fd::open(
            t.0.join("d"),
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        assert!(opaque(&path_fd).is_err());
    }

    type Listed = Vec<(usize, String, ChangeKind)>;

    /// A `sessions/` data directory holding session `s1` (architect Q81).
    struct Sessions(Tmp);

    impl Sessions {
        fn new(tag: &str) -> Self {
            let t = Tmp::new(tag);
            std::fs::create_dir(t.0.join("s1")).unwrap();
            Self(t)
        }
        fn stage(&self) -> PathBuf {
            self.0.0.join("s1/stage")
        }
        fn write(&self, mount: &str, rel: &str) {
            self.0.file(&format!("s1/stage/{mount}/upper/{rel}"));
        }
        fn list_in(&self, id: &str, bounds: StageBounds) -> Result<Listed, ChangesError> {
            let sessions = self.0.fd();
            let id = SessionId::parse(id).unwrap();
            let found = changes_within(sessions.as_fd(), &id, bounds)?;
            Ok(found
                .into_iter()
                .map(|c| (c.mount, c.path.display().to_string(), c.kind))
                .collect())
        }
        fn list(&self) -> Result<Listed, ChangesError> {
            self.list_in("s1", StageBounds::default())
        }
    }

    fn stage_error(r: Result<Listed, ChangesError>) -> String {
        match r {
            Err(ChangesError::Stage(e)) => e,
            other => panic!("expected a stage error: {other:?}"),
        }
    }

    #[test]
    fn a_mount_index_is_canonical_decimal_of_at_most_two_digits() {
        assert_eq!(mount_index(b"0"), Some(0));
        assert_eq!(mount_index(b"7"), Some(7));
        assert_eq!(mount_index(b"12"), Some(12));
        assert_eq!(mount_index(b"99"), Some(99));
        for bad in [
            &b""[..],
            b"01",
            b"00",
            b"+1",
            b"-1",
            b"1a",
            b" 1",
            b"123",
            b"\xff",
        ] {
            assert_eq!(mount_index(bad), None, "{bad:?}");
        }
    }

    /// Every `stage/<n>` that exists is listed, `stage/0` included: the listing trusts the
    /// directory set, so "only staged mounts" holds only as far as `dirs::staged_indices`, which
    /// makes them (architect Q83). Numeric order: 2 before 10.
    #[test]
    fn every_stage_mount_is_listed_in_numeric_order() {
        let s = Sessions::new("order");
        s.write("10", "ten.txt");
        s.write("2", "two.txt");
        s.write("0", "zero.txt");
        let w = ChangeKind::Written;
        assert_eq!(
            s.list().unwrap(),
            [
                (0, "zero.txt".to_owned(), w),
                (2, "two.txt".to_owned(), w),
                (10, "ten.txt".to_owned(), w),
            ]
        );
    }

    #[test]
    fn an_unknown_session_is_named_and_missing_parts_list_nothing() {
        let s = Sessions::new("missing");
        assert!(matches!(
            s.list_in("s9", StageBounds::default()),
            Err(ChangesError::UnknownSession)
        ));
        // No stage/: no staged mount.
        assert_eq!(s.list().unwrap(), []);
        // A staged mount the sandbox has not written to yet.
        std::fs::create_dir_all(s.stage().join("0")).unwrap();
        assert_eq!(s.list().unwrap(), []);
    }

    /// `sallyd` writes only canonical index directories in `stage/`; any other name fails the
    /// whole listing, never skipped.
    #[test]
    fn a_stage_name_sallyd_never_writes_fails_the_listing() {
        for bad in ["01", "+1", "1a", "123"] {
            let s = Sessions::new(&format!("name{bad}"));
            s.write("0", "kept.txt");
            std::fs::create_dir(s.stage().join(bad)).unwrap();
            let e = stage_error(s.list());
            assert!(e.contains("not a mount index"), "{bad}: {e}");
        }
        let s = Sessions::new("nonutf8");
        std::fs::create_dir_all(s.stage()).unwrap();
        std::fs::create_dir(s.stage().join(OsStr::from_bytes(b"\xff"))).unwrap();
        assert!(stage_error(s.list()).starts_with("\\xff: not a mount index"));
    }

    /// No symlink is followed: not a session, not `stage/<n>`, not `upper`. A regular file
    /// where a directory belongs fails too.
    #[test]
    fn symlinks_and_files_in_the_stage_path_fail_the_listing() {
        let s = Sessions::new("links");
        s.write("1", "secret.txt");
        std::os::unix::fs::symlink("1", s.stage().join("0")).unwrap();
        assert!(stage_error(s.list()).starts_with("0: "));

        let s = Sessions::new("file");
        std::fs::create_dir_all(s.stage()).unwrap();
        std::fs::write(s.stage().join("0"), "x").unwrap();
        assert!(stage_error(s.list()).starts_with("0: "));

        let s = Sessions::new("upper");
        s.write("1", "secret.txt");
        std::fs::create_dir(s.stage().join("0")).unwrap();
        std::os::unix::fs::symlink("../1/upper", s.stage().join("0/upper")).unwrap();
        assert!(matches!(
            s.list(),
            Err(ChangesError::Mount { mount: 0, .. })
        ));

        let s = Sessions::new("session");
        s.write("0", "secret.txt");
        std::os::unix::fs::symlink("s1", s.0.0.join("s2")).unwrap();
        let r = s.list_in("s2", StageBounds::default());
        assert!(stage_error(r).contains("cannot open the session"));
    }

    /// The `stage/` entries count against the same entry bound as the upper walks.
    #[test]
    fn the_stage_enumeration_is_charged_to_the_entry_bound() {
        let s = Sessions::new("charged");
        std::fs::create_dir_all(s.stage().join("0")).unwrap();
        std::fs::create_dir_all(s.stage().join("1")).unwrap();
        let entries = |max_entries| StageBounds {
            max_entries,
            ..StageBounds::default()
        };
        assert_eq!(s.list_in("s1", entries(2)).unwrap(), []);
        let e = stage_error(s.list_in("s1", entries(1)));
        assert!(e.contains("more than 1 entries"), "{e}");
    }
}
