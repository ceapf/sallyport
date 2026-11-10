//! Measuring a session's staged upper directories for the `runtime.stage_size` watchdog (#14).
//!
//! Staged writes land on the disk that holds Sallyport's state, with no quota a rootless
//! launcher can set, so `sallyd` measures them: every [`STAGE_POLL`] the launcher sums the
//! allocated bytes (`st_blocks`, so a sparse file counts what it really uses) of every entry
//! under each staged mount's upper directory, and kills a session that exceeds its limit.
//!
//! The tree is the sandbox's: the walk goes through directory fds, never follows a symlink, and is
//! bounded in entries and depth. A tree it cannot measure (an unreadable directory, a bound
//! reached, a missing root) is treated as over the limit: fail closed.
//!
//! Residual risk (THREAT_MODEL §6): the watchdog is a poll, so a session can overshoot by what it
//! writes in one interval; and a file the sandbox keeps open after unlinking it uses space the
//! walk cannot see until it is closed.

use std::path::{Path, PathBuf};
use std::time::Duration;

use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags};

/// How often the watchdog measures.
pub(crate) const STAGE_POLL: Duration = Duration::from_secs(2);

/// Bounds of one measurement.
#[derive(Debug, Clone, Copy)]
pub(crate) struct StageBounds {
    /// Entries visited across all staged mounts.
    pub max_entries: u64,
    /// Directory depth below an upper directory.
    pub max_depth: usize,
}

impl Default for StageBounds {
    fn default() -> Self {
        Self {
            max_entries: 1_000_000,
            max_depth: 256,
        }
    }
}

/// The outcome of one measurement.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// The session's staged data fits.
    Within {
        /// Allocated bytes across all staged mounts.
        bytes: u64,
    },
    /// The limit is exceeded.
    Over {
        /// Allocated bytes across all staged mounts.
        bytes: u64,
        /// The mount (`filesystem.mounts[n]`) holding the most.
        mount: usize,
    },
    /// A staged tree could not be measured; treated as over the limit.
    Unmeasurable {
        /// The mount whose tree failed.
        mount: usize,
        /// Why.
        reason: String,
    },
}

/// Measures `stages` (`(mount index, upper directory)`) against `limit` bytes. Blocking.
pub(crate) fn measure(stages: &[(usize, PathBuf)], limit: u64, bounds: StageBounds) -> Verdict {
    let mut entries = 0u64;
    let mut total = 0u64;
    let mut largest = (0u64, 0usize);
    for (mount, upper) in stages {
        let bytes = match usage(upper, bounds, &mut entries) {
            Ok(b) => b,
            Err(reason) => {
                return Verdict::Unmeasurable {
                    mount: *mount,
                    reason,
                };
            }
        };
        total = total.saturating_add(bytes);
        if bytes >= largest.0 {
            largest = (bytes, *mount);
        }
    }
    if total > limit {
        Verdict::Over {
            bytes: total,
            mount: largest.1,
        }
    } else {
        Verdict::Within { bytes: total }
    }
}

fn open_dir(at: impl rustix::fd::AsFd, name: &std::ffi::CStr) -> Result<Dir, String> {
    let fd = rustix::fs::openat(
        at,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| format!("cannot open a directory: {e}"))?;
    Dir::new(fd).map_err(|e| format!("cannot read a directory: {e}"))
}

/// Allocated bytes of `root` and everything below it, counting into `entries`. Depth-first with
/// one open directory per level, so at most `max_depth + 1` fds are held.
fn usage(root: &Path, bounds: StageBounds, entries: &mut u64) -> Result<u64, String> {
    let root_name = std::ffi::CString::new(root.as_os_str().as_encoded_bytes())
        .map_err(|_| "the upper directory path contains a NUL byte".to_owned())?;
    let first = open_dir(rustix::fs::CWD, &root_name)?;
    let mut bytes = first
        .stat()
        .map(|st| allocated(&st))
        .map_err(|e| format!("cannot stat the upper directory: {e}"))?;
    // The path from the root to the directory being read; its length is the depth.
    let mut path = vec![first];
    loop {
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
            return Err(format!("more than {} entries", bounds.max_entries));
        }
        let fd = dir.fd().map_err(|e| format!("directory fd: {e}"))?;
        let st = rustix::fs::statat(fd, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|e| format!("cannot stat an entry: {e}"))?;
        bytes = bytes.saturating_add(allocated(&st));
        if FileType::from_raw_mode(st.st_mode) == FileType::Directory {
            if depth > bounds.max_depth {
                return Err(format!("deeper than {} directories", bounds.max_depth));
            }
            let child = open_dir(fd, name)?;
            path.push(child);
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
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn fill(path: &Path, kib: usize) {
        std::fs::write(path, vec![b'x'; kib * 1024]).unwrap();
    }

    const KIB: u64 = 1024;

    #[test]
    fn data_within_the_limit_passes_and_over_names_the_largest_mount() {
        let t = Tmp::new("sum");
        let (a, b) = (t.upper(0), t.upper(3));
        fill(&a.join("f"), 300);
        std::fs::create_dir_all(b.join("d/e")).unwrap();
        fill(&b.join("d/e/g"), 500);
        let stages = [(0, a), (3, b)];
        match measure(&stages, 2048 * KIB, StageBounds::default()) {
            Verdict::Within { bytes } => assert!(bytes >= 800 * KIB, "{bytes}"),
            v => panic!("{v:?}"),
        }
        match measure(&stages, 700 * KIB, StageBounds::default()) {
            Verdict::Over { bytes, mount } => {
                assert!(bytes >= 800 * KIB, "{bytes}");
                assert_eq!(mount, 3);
            }
            v => panic!("{v:?}"),
        }
    }

    #[test]
    fn symlinks_are_not_followed_and_sparse_files_count_what_they_use() {
        let t = Tmp::new("links");
        let outside = t.0.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        fill(&outside.join("big"), 2048);
        let a = t.upper(0);
        std::os::unix::fs::symlink(&outside, a.join("link")).unwrap();
        std::fs::File::create(a.join("sparse"))
            .unwrap()
            .set_len(1 << 40)
            .unwrap();
        assert!(matches!(
            measure(&[(0, a)], 1024 * KIB, StageBounds::default()),
            Verdict::Within { .. }
        ));
    }

    #[test]
    fn an_unmeasurable_tree_fails_closed() {
        let t = Tmp::new("closed");
        let a = t.upper(1);
        std::fs::create_dir_all(a.join("hidden")).unwrap();
        fill(&a.join("hidden/f"), 4);
        std::fs::set_permissions(a.join("hidden"), std::fs::Permissions::from_mode(0o000)).unwrap();
        let v = measure(&[(1, a.clone())], u64::MAX, StageBounds::default());
        std::fs::set_permissions(a.join("hidden"), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(v, Verdict::Unmeasurable { mount: 1, .. }), "{v:?}");
        let missing = t.0.join("stage/9/upper");
        assert!(matches!(
            measure(&[(9, missing)], u64::MAX, StageBounds::default()),
            Verdict::Unmeasurable { mount: 9, .. }
        ));
        // The root itself must not be a symlink.
        let link = t.0.join("stage/link");
        std::os::unix::fs::symlink(&a, &link).unwrap();
        assert!(matches!(
            measure(&[(2, link)], u64::MAX, StageBounds::default()),
            Verdict::Unmeasurable { mount: 2, .. }
        ));
    }

    #[test]
    fn the_walk_is_bounded_in_entries_and_depth() {
        let t = Tmp::new("bounds");
        let a = t.upper(0);
        for i in 0..20 {
            fill(&a.join(format!("f{i}")), 0);
        }
        let few = StageBounds {
            max_entries: 10,
            max_depth: 8,
        };
        let v = measure(&[(0, a.clone())], u64::MAX, few);
        assert!(
            matches!(&v, Verdict::Unmeasurable { reason, .. } if reason.contains("entries")),
            "{v:?}"
        );
        let b = t.upper(1);
        std::fs::create_dir_all(b.join("1/2/3/4/5/6/7/8/9")).unwrap();
        let shallow = StageBounds {
            max_entries: 1000,
            max_depth: 4,
        };
        let v = measure(&[(1, b.clone())], u64::MAX, shallow);
        assert!(
            matches!(&v, Verdict::Unmeasurable { reason, .. } if reason.contains("deeper")),
            "{v:?}"
        );
        let deep_enough = StageBounds {
            max_entries: 1000,
            max_depth: 16,
        };
        assert!(matches!(
            measure(&[(1, b)], u64::MAX, deep_enough),
            Verdict::Within { .. }
        ));
    }
}
