//! The free-space floor (#14, maintainer design after the 6c-1 reviews): the hard, race-free
//! guarantee that no sandbox fills a host disk.
//!
//! A session's watched filesystems are the ones its sandbox can write to: the filesystem of
//! Sallyport's state directory when the session has staged mounts or `.git` overlays, and the
//! filesystem of every `rw` mount root. Each is held open (an `O_PATH` fd) for the session's
//! lifetime and polled with `fstatfs`. When the space available to unprivileged users falls below
//! the floor, `max(min_bytes, percent % of the filesystem)`, the session is killed. A launch is
//! refused unless every watched filesystem has the floor free, plus `runtime.stage_size` on the
//! state filesystem.
//!
//! Unlike the `stage_size` walk, the floor cannot be raced: it reads the filesystem's own
//! accounting, so renames, open unlinked files and `O_TMPFILE`s all count.

use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use rustix::fs::{Mode, OFlags};

/// The free-space floor. Set from `sallyd`'s configuration; the default is 4 GiB or 5 % of the
/// filesystem, whichever is larger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskFloor {
    /// Bytes that must stay available.
    pub min_bytes: u64,
    /// Percent of the filesystem's size that must stay available (0–100).
    pub percent: u8,
}

impl Default for DiskFloor {
    fn default() -> Self {
        Self {
            min_bytes: 4 << 30,
            percent: 5,
        }
    }
}

impl DiskFloor {
    /// The floor on a filesystem of `total` bytes.
    #[must_use]
    pub fn bytes(&self, total: u64) -> u64 {
        let pct = u64::from(self.percent.min(100));
        self.min_bytes.max(total / 100 * pct)
    }
}

/// One `fstatfs` reading, in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Space {
    /// Available to unprivileged users (`f_bavail`).
    pub free: u64,
    /// The filesystem's size (`f_blocks`).
    pub total: u64,
    /// In use (`f_blocks - f_bfree`).
    pub used: u64,
}

/// A filesystem a session's sandbox can write to.
#[derive(Debug)]
pub(super) struct Watched {
    /// `state` or `filesystem.mounts[n]` (the first mount found on it).
    pub label: String,
    /// Holds Sallyport's state directory (where staged and `.git` overlay data land).
    pub state: bool,
    fd: OwnedFd,
}

impl Watched {
    /// Reads the filesystem's space. Blocking.
    pub(super) fn space(&self) -> std::io::Result<Space> {
        let s = rustix::fs::fstatvfs(&self.fd)?;
        let unit = s.f_frsize;
        Ok(Space {
            free: s.f_bavail.saturating_mul(unit),
            total: s.f_blocks.saturating_mul(unit),
            used: s.f_blocks.saturating_sub(s.f_bfree).saturating_mul(unit),
        })
    }
}

fn open_dir(path: &Path) -> Result<(OwnedFd, u64), String> {
    let fd = rustix::fs::open(
        path,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| format!("{}: {e}", path.display()))?;
    let dev = std::fs::metadata(path)
        .map_err(|e| format!("{}: {e}", path.display()))?
        .dev();
    Ok((fd, dev))
}

/// Opens the watched filesystems of a session, one per device: `state` (the nearest existing
/// ancestor of `state_dir`) when `writes_state`, and each `rw` mount root. Blocking.
///
/// # Errors
/// A path that cannot be opened.
pub(super) fn watch(
    state_dir: &Path,
    writes_state: bool,
    rw_roots: &[(usize, &Path)],
) -> Result<Vec<Watched>, String> {
    let mut out: Vec<(u64, Watched)> = Vec::new();
    if writes_state {
        let Some(dir) = state_dir.ancestors().find(|a| a.is_dir()) else {
            return Err(format!("{}: no existing ancestor", state_dir.display()));
        };
        let (fd, dev) = open_dir(dir)?;
        out.push((
            dev,
            Watched {
                label: "state".into(),
                state: true,
                fd,
            },
        ));
    }
    for (i, root) in rw_roots {
        let (fd, dev) = open_dir(root)?;
        if out.iter().all(|(d, _)| *d != dev) {
            out.push((
                dev,
                Watched {
                    label: format!("filesystem.mounts[{i}]"),
                    state: false,
                    fd,
                },
            ));
        }
    }
    Ok(out.into_iter().map(|(_, w)| w).collect())
}

/// Whether a launch may proceed on a filesystem with `space`: the floor stays free, plus `extra`
/// bytes (the session's `stage_size` on the state filesystem).
pub(super) fn admits(space: Space, floor: &DiskFloor, extra: u64) -> bool {
    space.free >= floor.bytes(space.total).saturating_add(extra)
}

/// Whether `space` is below the floor.
pub(super) fn below(space: Space, floor: &DiskFloor) -> bool {
    space.free < floor.bytes(space.total)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const GIB: u64 = 1 << 30;

    fn space(free: u64, total: u64) -> Space {
        Space {
            free,
            total,
            used: total - free,
        }
    }

    #[test]
    fn the_floor_is_the_larger_of_bytes_and_percent() {
        let f = DiskFloor::default();
        assert_eq!(f.bytes(50 * GIB), 4 * GIB);
        assert_eq!(f.bytes(1000 * GIB), 50 * GIB);
        let custom = DiskFloor {
            min_bytes: 1,
            percent: 250,
        };
        assert_eq!(custom.bytes(100), 100, "percent is capped at 100");
    }

    #[test]
    fn launch_needs_the_floor_plus_stage_size_and_kills_below_the_floor() {
        let f = DiskFloor::default();
        assert!(admits(space(14 * GIB, 50 * GIB), &f, 10 * GIB));
        assert!(!admits(space(14 * GIB - 1, 50 * GIB), &f, 10 * GIB));
        assert!(admits(space(4 * GIB, 50 * GIB), &f, 0));
        assert!(!below(space(4 * GIB, 50 * GIB), &f));
        assert!(below(space(4 * GIB - 1, 50 * GIB), &f));
    }

    #[test]
    fn one_watch_per_device_and_space_is_readable() {
        let dir = std::env::current_dir()
            .unwrap()
            .join("../../target/disk-unit")
            .join(std::process::id().to_string());
        std::fs::create_dir_all(dir.join("a")).unwrap();
        let w = watch(
            &dir.join("state/not/yet"),
            true,
            &[(0, &dir.join("a")), (2, &dir)],
        )
        .unwrap();
        assert_eq!(w.len(), 1, "same device: watched once");
        assert_eq!(w[0].label, "state");
        let s = w[0].space().unwrap();
        assert!(s.total > 0 && s.free <= s.total);
        let rw_only = watch(&dir, false, &[(3, &dir.join("a"))]).unwrap();
        assert_eq!(rw_only[0].label, "filesystem.mounts[3]");
        assert!(!rw_only[0].state);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
