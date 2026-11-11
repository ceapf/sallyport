//! Measuring what a session writes to the host disk, for the `runtime.stage_size` watchdog (#14).
//!
//! A sandbox writes to the disk that holds Sallyport's state in two places: the upper directories
//! of its `staged` mounts (kept) and of the `.git` overlays of its `rw` mounts (discarded at
//! teardown). There is no quota a rootless launcher can set, so `sallyd` measures them. Every
//! poll, the launcher sums the allocated bytes of every entry under every such upper directory.
//! It counts `st_blocks`, so a sparse file counts what it really uses, and a hard link counts once
//! per link: over-counting only hurts the session itself. A session that exceeds its limit is
//! killed.
//!
//! The tree is the sandbox's: the walk goes through directory fds, never follows a symlink, and is
//! bounded in entries and depth, holding one fd per level. An entry that disappears during the
//! walk (a build's temp file) counts as zero. Anything else it cannot measure counts as over the
//! limit, failing closed: an unreadable directory, an entry swapped for a symlink, a bound
//! reached, a missing root.
//!
//! Residual risks (THREAT_MODEL §6). The watchdog is a poll, so a session can overshoot by what it
//! writes in one interval. A file the sandbox keeps open after unlinking it (or an `O_TMPFILE`)
//! uses space the walk cannot see. A subtree moved during a walk, from a directory not yet read
//! into one already read, is missed for that pass.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags};
use rustix::io::Errno;

/// The shortest time between two measurements of a session. A measurement that took longer waits
/// [`WALK_SPACING`] times its own duration, so a huge tree is not walked back to back.
pub(crate) const STAGE_POLL: Duration = Duration::from_secs(2);
/// See [`STAGE_POLL`].
pub(crate) const WALK_SPACING: u32 = 4;

/// Bounds of one measurement.
#[derive(Debug, Clone, Copy)]
pub(crate) struct StageBounds {
    /// Entries visited across all areas.
    pub max_entries: u64,
    /// Directory depth below an upper directory; at most `max_depth + 1` fds are held.
    pub max_depth: usize,
}

impl Default for StageBounds {
    fn default() -> Self {
        Self {
            max_entries: 1_000_000,
            max_depth: 64,
        }
    }
}

/// One upper directory a sandbox writes to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Area {
    /// What it is, for the audit entry: `filesystem.mounts[1]` or
    /// `filesystem.mounts[0] .git overlay 2`.
    pub label: String,
    /// The upper directory.
    pub upper: PathBuf,
}

/// The outcome of one measurement.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// The session's data fits.
    Within {
        /// Allocated bytes across all areas.
        bytes: u64,
    },
    /// The limit is exceeded.
    Over {
        /// Allocated bytes across all areas.
        bytes: u64,
        /// The area holding the most.
        largest: String,
    },
    /// An area could not be measured; treated as over the limit.
    Unmeasurable {
        /// The area whose tree failed.
        area: String,
        /// Why.
        reason: String,
    },
    /// `cancel` was set: the session is gone.
    Cancelled,
}

/// Why a walk stopped early.
enum Stop {
    Failed(String),
    Cancelled,
}

impl From<String> for Stop {
    fn from(s: String) -> Self {
        Self::Failed(s)
    }
}

/// Measures `areas` against `limit` bytes. Blocking; checks `cancel` before every entry.
pub(crate) fn measure(
    areas: &[Area],
    limit: u64,
    bounds: StageBounds,
    cancel: &AtomicBool,
) -> Verdict {
    let mut entries = 0u64;
    let mut total = 0u64;
    let mut largest: Option<(u64, &str)> = None;
    for area in areas {
        let bytes = match usage(area, bounds, &mut entries, cancel) {
            Ok(b) => b,
            Err(Stop::Cancelled) => return Verdict::Cancelled,
            Err(Stop::Failed(reason)) => {
                return Verdict::Unmeasurable {
                    area: area.label.clone(),
                    reason,
                };
            }
        };
        total = total.saturating_add(bytes);
        if largest.is_none_or(|(b, _)| bytes > b) {
            largest = Some((bytes, &area.label));
        }
    }
    match largest {
        Some((_, label)) if total > limit => Verdict::Over {
            bytes: total,
            largest: label.to_owned(),
        },
        _ => Verdict::Within { bytes: total },
    }
}

fn open_dir(at: impl rustix::fd::AsFd, name: &std::ffi::CStr) -> Result<Dir, Errno> {
    let fd = rustix::fs::openat(
        at,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    Dir::new(fd)
}

/// Allocated bytes of `area` and everything below it, counting into `entries`. Depth-first with
/// one open directory per level, so at most `max_depth + 1` fds are held. An entry that is gone
/// by the time it is stat'ed or opened (`ENOENT`) counts as zero; every other error fails.
fn usage(
    area: &Area,
    bounds: StageBounds,
    entries: &mut u64,
    cancel: &AtomicBool,
) -> Result<u64, Stop> {
    let root_name = std::ffi::CString::new(area.upper.as_os_str().as_encoded_bytes())
        .map_err(|_| "the upper directory path contains a NUL byte".to_owned())?;
    let first = open_dir(rustix::fs::CWD, &root_name)
        .map_err(|e| format!("cannot open the upper directory: {e}"))?;
    let mut bytes = first
        .stat()
        .map(|st| allocated(&st))
        .map_err(|e| format!("cannot stat the upper directory: {e}"))?;
    // The path from the root to the directory being read; its length is the depth.
    let mut path = vec![first];
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err(Stop::Cancelled);
        }
        let depth = path.len();
        let Some(dir) = path.last_mut() else { break };
        let Some(entry) = dir.read() else {
            path.pop();
            continue;
        };
        let entry = entry.map_err(|e| format!("cannot read a directory: {e}"))?;
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        *entries = entries.saturating_add(1);
        if *entries > bounds.max_entries {
            return Err(format!("more than {} entries", bounds.max_entries).into());
        }
        let fd = dir.fd().map_err(|e| format!("directory fd: {e}"))?;
        let st = match rustix::fs::statat(fd, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(st) => st,
            Err(Errno::NOENT) => continue,
            Err(e) => return Err(format!("cannot stat an entry: {e}").into()),
        };
        bytes = bytes.saturating_add(allocated(&st));
        if FileType::from_raw_mode(st.st_mode) == FileType::Directory {
            if depth > bounds.max_depth {
                return Err(format!("deeper than {} directories", bounds.max_depth).into());
            }
            match open_dir(fd, name) {
                Ok(child) => path.push(child),
                Err(Errno::NOENT) => {}
                Err(e) => return Err(format!("cannot open a directory: {e}").into()),
            }
        }
    }
    Ok(bytes)
}

fn allocated(st: &rustix::fs::Stat) -> u64 {
    u64::try_from(st.st_blocks).unwrap_or(0).saturating_mul(512)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::os::unix::fs::PermissionsExt;

    use super::*;

    struct Tmp(PathBuf);

    impl Tmp {
        fn new(tag: &str) -> Self {
            let dir = std::env::current_dir()
                .unwrap()
                .join("../../target/stage-unit")
                .join(format!("{}-{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(std::fs::canonicalize(&dir).unwrap())
        }

        fn upper(&self, n: usize) -> PathBuf {
            let p = self.0.join(format!("stage/{n}/upper"));
            std::fs::create_dir_all(&p).unwrap();
            p
        }

        fn area(&self, n: usize) -> Area {
            area(n, self.upper(n))
        }
    }

    fn area(n: usize, upper: PathBuf) -> Area {
        Area {
            label: format!("filesystem.mounts[{n}]"),
            upper,
        }
    }

    fn run(areas: &[Area], limit: u64, bounds: StageBounds) -> Verdict {
        measure(areas, limit, bounds, &AtomicBool::new(false))
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn fill(path: &std::path::Path, kib: usize) {
        std::fs::write(path, vec![b'x'; kib * 1024]).unwrap();
    }

    const KIB: u64 = 1024;

    #[test]
    fn data_within_the_limit_passes_and_over_names_the_largest_area() {
        let t = Tmp::new("sum");
        let (a, b) = (t.area(0), t.area(3));
        fill(&a.upper.join("f"), 300);
        std::fs::create_dir_all(b.upper.join("d/e")).unwrap();
        fill(&b.upper.join("d/e/g"), 500);
        let areas = [a, b];
        match run(&areas, 2048 * KIB, StageBounds::default()) {
            Verdict::Within { bytes } => assert!(bytes >= 800 * KIB, "{bytes}"),
            v => panic!("{v:?}"),
        }
        match run(&areas, 700 * KIB, StageBounds::default()) {
            Verdict::Over { bytes, largest } => {
                assert!(bytes >= 800 * KIB, "{bytes}");
                assert_eq!(largest, "filesystem.mounts[3]");
            }
            v => panic!("{v:?}"),
        }
    }

    /// Review H1/M1 (6c-1): files created and deleted while the walk runs (a build's temp files)
    /// never make a tree unmeasurable.
    #[test]
    fn churn_during_the_walk_is_not_a_failure() {
        let t = Tmp::new("churn");
        let a = t.area(0);
        let dir = a.upper.clone();
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let churn = {
            let stop = std::sync::Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut i = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    let d = dir.join(format!("d{}", i % 50));
                    let _ = std::fs::create_dir(&d);
                    let _ = std::fs::write(d.join("f"), b"x");
                    let _ = std::fs::write(dir.join(format!("f{}", i % 50)), b"x");
                    let _ = std::fs::remove_file(d.join("f"));
                    let _ = std::fs::remove_dir(&d);
                    let _ = std::fs::remove_file(dir.join(format!("f{}", (i + 25) % 50)));
                    i += 1;
                }
            })
        };
        let verdicts: Vec<Verdict> = (0..300)
            .map(|_| run(std::slice::from_ref(&a), u64::MAX, StageBounds::default()))
            .collect();
        stop.store(true, Ordering::Relaxed);
        churn.join().unwrap();
        for v in verdicts {
            assert!(matches!(v, Verdict::Within { .. }), "{v:?}");
        }
    }

    #[test]
    fn a_cancelled_walk_stops() {
        let t = Tmp::new("cancel");
        let a = t.area(0);
        fill(&a.upper.join("f"), 1);
        let v = measure(&[a], 0, StageBounds::default(), &AtomicBool::new(true));
        assert_eq!(v, Verdict::Cancelled);
    }

    #[test]
    fn symlinks_are_not_followed_and_sparse_files_count_what_they_use() {
        let t = Tmp::new("links");
        let outside = t.0.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        fill(&outside.join("big"), 2048);
        let a = t.area(0);
        std::os::unix::fs::symlink(&outside, a.upper.join("link")).unwrap();
        std::fs::File::create(a.upper.join("sparse"))
            .unwrap()
            .set_len(1 << 40)
            .unwrap();
        assert!(matches!(
            run(&[a], 1024 * KIB, StageBounds::default()),
            Verdict::Within { .. }
        ));
    }

    #[test]
    fn an_unmeasurable_tree_fails_closed() {
        let t = Tmp::new("closed");
        let a = t.area(1);
        let label = |v: &Verdict| match v {
            Verdict::Unmeasurable { area, .. } => area.clone(),
            other => panic!("{other:?}"),
        };
        // Root bypasses permission bits, so the unreadable-directory case needs a normal user.
        if !rustix::process::geteuid().is_root() {
            let hidden = a.upper.join("hidden");
            std::fs::create_dir_all(&hidden).unwrap();
            fill(&hidden.join("f"), 4);
            std::fs::set_permissions(&hidden, std::fs::Permissions::from_mode(0o000)).unwrap();
            let v = run(std::slice::from_ref(&a), u64::MAX, StageBounds::default());
            std::fs::set_permissions(&hidden, std::fs::Permissions::from_mode(0o700)).unwrap();
            assert_eq!(label(&v), "filesystem.mounts[1]");
        }
        let missing = area(9, t.0.join("stage/9/upper"));
        let v = run(&[missing], u64::MAX, StageBounds::default());
        assert_eq!(label(&v), "filesystem.mounts[9]");
        // The root itself must not be a symlink.
        let link = t.0.join("stage/link");
        std::os::unix::fs::symlink(&a.upper, &link).unwrap();
        let v = run(&[area(2, link)], u64::MAX, StageBounds::default());
        assert_eq!(label(&v), "filesystem.mounts[2]");
    }

    #[test]
    fn the_walk_is_bounded_in_entries_and_depth() {
        let t = Tmp::new("bounds");
        let a = t.area(0);
        for i in 0..20 {
            fill(&a.upper.join(format!("f{i}")), 0);
        }
        let few = StageBounds {
            max_entries: 10,
            max_depth: 8,
        };
        let v = run(&[a], u64::MAX, few);
        assert!(
            matches!(&v, Verdict::Unmeasurable { reason, .. } if reason.contains("entries")),
            "{v:?}"
        );
        let b = t.area(1);
        std::fs::create_dir_all(b.upper.join("1/2/3/4/5/6/7/8/9")).unwrap();
        let shallow = StageBounds {
            max_entries: 1000,
            max_depth: 4,
        };
        let v = run(std::slice::from_ref(&b), u64::MAX, shallow);
        assert!(
            matches!(&v, Verdict::Unmeasurable { reason, .. } if reason.contains("deeper")),
            "{v:?}"
        );
        let deep_enough = StageBounds {
            max_entries: 1000,
            max_depth: 16,
        };
        assert!(matches!(
            run(&[b], u64::MAX, deep_enough),
            Verdict::Within { .. }
        ));
    }
}
