//! Removing what a previous `sallyd` left in the locked runtime directory (architect Q42 step 6;
//! security review L1): the session socket directories (`sessions/`) and `control.sock`.
//!
//! Everything is reached relative to the locked directory's fd, never by path, so a rename of
//! a path component cannot redirect the removal; symlinks are removed, never followed. A sandbox
//! could leave a tree in its own socket directory, so the walk is bounded: past [`MAX_ENTRIES`]
//! entries or [`MAX_DEPTH`] levels `sallyd` refuses to start, naming what it found, rather than
//! walk on without end.

use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::{AsFd, OwnedFd};

use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use rustix::io::Errno;

/// The session socket directories, under the locked directory.
pub const SESSIONS: &CStr = c"sessions";
/// Entries removed at most.
pub const MAX_ENTRIES: usize = 4096;
/// Directory levels below `sessions/` walked at most.
pub const MAX_DEPTH: usize = 8;

/// Removes `sessions/` and `control` (the stale socket) under `dir`; either may be missing.
///
/// # Errors
/// The first failure, or a tree past the bounds.
pub fn remove(dir: &OwnedFd, control: &str) -> io::Result<()> {
    let mut left = MAX_ENTRIES;
    remove_tree(dir, SESSIONS, 0, &mut left)?;
    match rustix::fs::unlinkat(dir, control, AtFlags::empty()) {
        Ok(()) | Err(Errno::NOENT) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

fn too_big(what: String) -> io::Error {
    io::Error::other(format!(
        "{}/ holds {what}; remove it by hand (sallyd removes at most {MAX_ENTRIES} entries, \
         {MAX_DEPTH} levels deep)",
        SESSIONS.to_string_lossy()
    ))
}

/// Removes `name` in `dir`: a whole directory tree, or one entry of any other kind (a symlink
/// is removed, not followed). Counts each entry against `left`.
fn remove_tree(dir: &impl AsFd, name: &CStr, depth: usize, left: &mut usize) -> io::Result<()> {
    *left = left
        .checked_sub(1)
        .ok_or_else(|| too_big(format!("more than {MAX_ENTRIES} entries")))?;
    let st = match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(st) => st,
        Err(Errno::NOENT) => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    if FileType::from_raw_mode(st.st_mode) != FileType::Directory {
        return Ok(rustix::fs::unlinkat(dir, name, AtFlags::empty())?);
    }
    if depth > MAX_DEPTH {
        return Err(too_big(format!("a tree deeper than {MAX_DEPTH} levels")));
    }
    let sub = sally_core::fd::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let mut names: Vec<CString> = Vec::new();
    for entry in rustix::fs::Dir::read_from(&sub)? {
        let n = entry?.file_name().to_owned();
        if n.as_c_str() == c"." || n.as_c_str() == c".." {
            continue;
        }
        if names.len() >= *left {
            return Err(too_big(format!("more than {MAX_ENTRIES} entries")));
        }
        names.push(n);
    }
    for n in &names {
        remove_tree(&sub, n, depth.saturating_add(1), left)?;
    }
    Ok(rustix::fs::unlinkat(dir, name, AtFlags::REMOVEDIR)?)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    fn scratch(name: &str) -> (PathBuf, OwnedFd) {
        let d = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/stale-tests")
            .join(format!("{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let fd = sally_core::fd::open(
            d.as_path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        (d, fd)
    }

    #[test]
    fn the_bounds_are_pinned() {
        assert_eq!((MAX_ENTRIES, MAX_DEPTH), (4096, 8));
        assert_eq!(SESSIONS, c"sessions");
    }

    #[test]
    fn sessions_and_the_socket_go_and_the_rest_stays() {
        let (d, fd) = scratch("all");
        std::fs::create_dir_all(d.join("sessions/a/harness")).unwrap();
        std::fs::write(d.join("sessions/a/harness/f"), b"x").unwrap();
        std::fs::write(d.join("control.sock"), b"stale").unwrap();
        std::fs::write(d.join("keep"), b"k").unwrap();
        remove(&fd, "control.sock").unwrap();
        assert!(!d.join("sessions").exists() && !d.join("control.sock").exists());
        assert!(d.join("keep").exists());
        // Nothing left to remove is no error.
        remove(&fd, "control.sock").unwrap();
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_symlink_in_the_tree_is_removed_not_followed() {
        let (d, fd) = scratch("link");
        let outside = d.join("outside");
        std::fs::create_dir_all(outside.join("inner")).unwrap();
        std::fs::write(outside.join("inner/precious"), b"p").unwrap();
        std::fs::create_dir_all(d.join("sessions/a")).unwrap();
        std::os::unix::fs::symlink(&outside, d.join("sessions/a/escape")).unwrap();
        // `sessions` itself a symlink: removed as one entry.
        remove(&fd, "control.sock").unwrap();
        assert!(outside.join("inner/precious").exists());
        std::fs::create_dir_all(d.join("real")).unwrap();
        std::os::unix::fs::symlink(d.join("real"), d.join("sessions")).unwrap();
        std::fs::write(d.join("real/f"), b"f").unwrap();
        remove(&fd, "control.sock").unwrap();
        assert!(d.join("real/f").exists());
        assert!(std::fs::symlink_metadata(d.join("sessions")).is_err());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_tree_past_the_entry_bound_refuses_start() {
        let (d, fd) = scratch("many");
        let s = d.join("sessions");
        std::fs::create_dir_all(&s).unwrap();
        // `sessions` itself counts: one entry less than the bound fits.
        for i in 0..MAX_ENTRIES - 1 {
            std::fs::write(s.join(i.to_string()), b"").unwrap();
        }
        remove(&fd, "control.sock").unwrap();
        std::fs::create_dir_all(&s).unwrap();
        for i in 0..MAX_ENTRIES {
            std::fs::write(s.join(i.to_string()), b"").unwrap();
        }
        let e = remove(&fd, "control.sock").unwrap_err();
        assert!(e.to_string().contains("more than 4096 entries"), "{e}");
        assert!(e.to_string().starts_with("sessions/ holds"), "{e}");
        // Refused before anything is removed: the listing is counted first.
        assert_eq!(std::fs::read_dir(&s).unwrap().count(), MAX_ENTRIES);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_tree_past_the_depth_bound_refuses_start() {
        let (d, fd) = scratch("deep");
        let fits: PathBuf = std::iter::once("sessions".to_owned())
            .chain((0..MAX_DEPTH).map(|i| i.to_string()))
            .collect();
        std::fs::create_dir_all(d.join(&fits)).unwrap();
        remove(&fd, "control.sock").unwrap();
        std::fs::create_dir_all(d.join(&fits).join("one-more")).unwrap();
        let e = remove(&fd, "control.sock").unwrap_err();
        assert!(e.to_string().contains("deeper than 8 levels"), "{e}");
        std::fs::remove_dir_all(&d).unwrap();
    }
}
