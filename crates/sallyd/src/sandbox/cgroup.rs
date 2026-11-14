//! The container cgroup's event counters (#27, architect Q48). `pids.events` `max` counts the
//! forks the pids limit refused; `memory.events` `oom_kill` counts the processes the memory limit
//! killed. Both sit in the cgroup the container's init is in (`<CgroupPath>/container` under
//! crun, `docs/dev/PROBE_NOTES.md`).
//!
//! The launcher opens both files once, between `podman init` and `podman start` (before any of
//! the container's own code runs): the init's `0::` line of `/proc/<pid>/cgroup`, read through
//! the held `/proc/<pid>` directory, names the cgroup, and each file is opened beneath the cgroup2
//! root with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`. The watchdog's
//! observer only re-reads the two descriptors (`pread` at offset 0 reads the current counts).
//! Every parser bounds its input before it looks at it. The bytes are the kernel's, not the
//! container's, so no fuzz target is added for them.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;

use rustix::fd::{AsFd, OwnedFd};
use rustix::fs::{Mode, OFlags, ResolveFlags};
use rustix::io::Errno;
use sally_core::fd;

/// Where the cgroup2 hierarchy is mounted.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
/// `CGROUP2_SUPER_MAGIC`, the `f_type` of a cgroup2 filesystem.
const CGROUP2_MAGIC: i64 = 0x6367_7270;
/// `/proc/<pid>/cgroup` and an events file are at most this long; a longer one is an error.
const READ_CAP: usize = 4096;

/// Why the event files could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ReadError {
    /// The cgroup was removed (`ENODEV`): the container has ended.
    Gone,
    /// Anything else, named.
    Failed(String),
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Gone => f.write_str("the container's cgroup is gone"),
            Self::Failed(s) => f.write_str(s),
        }
    }
}

/// A failed `pread` of an events file: `ENODEV` once its cgroup was removed (PROBE_NOTES).
fn read_error(e: Errno) -> ReadError {
    if e == Errno::NODEV {
        ReadError::Gone
    } else {
        ReadError::Failed(e.to_string())
    }
}

/// A counter the observer reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Resource {
    /// `pids.events` `max`: forks refused at `runtime.pids`.
    Pids,
    /// `memory.events` `oom_kill`: processes killed at `runtime.memory`.
    Memory,
}

impl Resource {
    /// Both, in the order they are opened and reported.
    pub(super) const ALL: [Self; 2] = [Self::Pids, Self::Memory];

    fn file(self) -> &'static str {
        match self {
            Self::Pids => "pids.events",
            Self::Memory => "memory.events",
        }
    }

    fn key(self) -> &'static str {
        match self {
            Self::Pids => "max",
            Self::Memory => "oom_kill",
        }
    }

    /// The audit entry's `resource`.
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Pids => "pids",
            Self::Memory => "memory",
        }
    }

    /// The audit entry's `reason`.
    pub(super) fn reason(self) -> &'static str {
        match self {
            Self::Pids => "pids-max",
            Self::Memory => "oom-kill",
        }
    }
}

/// The init's cgroup relative to the cgroup2 root: the one `0::` line of `/proc/<pid>/cgroup`.
/// An absolute path of plain components is required; `.`, `..`, an empty component, a NUL and the
/// root cgroup itself are refused.
///
/// # Errors
/// What is wrong with the text.
pub(super) fn cgroup_dir(text: &[u8]) -> Result<&[u8], String> {
    if text.len() > READ_CAP {
        return Err(format!("/proc/<pid>/cgroup is over {READ_CAP} bytes"));
    }
    let mut found = None;
    for line in text.split(|b| *b == b'\n') {
        if let Some(path) = line.strip_prefix(b"0::")
            && found.replace(path).is_some()
        {
            return Err("/proc/<pid>/cgroup has more than one 0:: line".into());
        }
    }
    let path = found.ok_or("/proc/<pid>/cgroup has no 0:: line (cgroup v2)")?;
    let rel = path
        .strip_prefix(b"/")
        .ok_or("the init's cgroup path is not absolute")?;
    if rel.is_empty() {
        return Err("the init is in the root cgroup".into());
    }
    let odd = |c: &[u8]| c.is_empty() || c == b"." || c == b".." || c.contains(&0);
    if rel.split(|b| *b == b'/').any(odd) {
        return Err("the init's cgroup path has an unexpected component".into());
    }
    Ok(rel)
}

/// The value of `key` in an events file: exactly one `<key> <decimal>` line.
///
/// # Errors
/// What is wrong with the text.
pub(super) fn counter(text: &[u8], key: &str) -> Result<u64, String> {
    if text.len() > READ_CAP {
        return Err(format!("an events file is over {READ_CAP} bytes"));
    }
    let mut found = None;
    for line in text.split(|b| *b == b'\n') {
        let mut parts = line.splitn(2, |b| *b == b' ');
        if parts.next() != Some(key.as_bytes()) {
            continue;
        }
        let value = parts.next().unwrap_or_default();
        if found.replace(value).is_some() {
            return Err(format!("{key} is listed twice"));
        }
    }
    let value = found.ok_or_else(|| format!("no {key} line"))?;
    decimal(value).ok_or_else(|| format!("{key} is not a count"))
}

fn decimal(v: &[u8]) -> Option<u64> {
    if v.is_empty() {
        return None;
    }
    v.iter().try_fold(0u64, |n, b| {
        let d = b.is_ascii_digit().then(|| u64::from(b - b'0'))?;
        n.checked_mul(10)?.checked_add(d)
    })
}

/// The counters that grew from `last` to `now`, with their new values. A counter never falls;
/// one that reads lower is not reported (and not taken as the new baseline by the caller).
#[must_use]
pub(super) fn risen(last: &[(Resource, u64)], now: &[(Resource, u64)]) -> Vec<(Resource, u64)> {
    now.iter()
        .filter(|(r, n)| last.iter().any(|(l, was)| l == r && n > was))
        .copied()
        .collect()
}

/// The cgroup2 root, opened `O_PATH` and checked to be a cgroup2 filesystem. Blocking.
///
/// # Errors
/// The open or the check failed.
pub(super) fn cgroup_root() -> Result<OwnedFd, String> {
    open_root(CGROUP_ROOT)
}

/// `path`, opened `O_PATH | O_DIRECTORY | O_NOFOLLOW`, if it is a cgroup2 filesystem.
fn open_root(path: &str) -> Result<OwnedFd, String> {
    let flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW;
    let root = fd::open(path, flags, Mode::empty()).map_err(|e| format!("{path}: {e}"))?;
    let st = rustix::fs::fstatfs(&root).map_err(|e| format!("{path}: {e}"))?;
    // `f_type`'s width differs between targets; the conversion is the identity on x86_64.
    #[allow(clippy::useless_conversion)]
    let kind = i64::from(st.f_type);
    if kind != CGROUP2_MAGIC {
        return Err(format!("{path} is not a cgroup2 filesystem"));
    }
    Ok(root)
}

/// The two event files of a started container, open for reading.
#[derive(Debug)]
pub(super) struct Events {
    files: Vec<(Resource, OwnedFd)>,
}

impl Events {
    /// Opens the event files of the cgroup the process of `init` (a `/proc/<pid>` directory) is
    /// in, beneath `root`. Blocking.
    ///
    /// # Errors
    /// A file could not be read, parsed or opened; the message names it.
    pub(super) fn open(init: impl AsFd, root: impl AsFd) -> Result<Self, String> {
        let list = fd::openat(&init, "cgroup", OFlags::RDONLY, Mode::empty())
            .map_err(|e| format!("/proc/<pid>/cgroup: {e}"))?;
        let text = read_capped(&list).map_err(|e| format!("/proc/<pid>/cgroup: {e}"))?;
        // `read_capped` refuses an overlong list; `cgroup_dir` checks the cap again on its own.
        let rel = cgroup_dir(&text)?;
        let mut files = Vec::with_capacity(Resource::ALL.len());
        for r in Resource::ALL {
            let mut path = rel.to_vec();
            path.push(b'/');
            path.extend_from_slice(r.file().as_bytes());
            let f = open_event_file(&root, &path).map_err(|e| format!("{}: {e}", r.file()))?;
            files.push((r, f));
        }
        Ok(Self { files })
    }

    /// Every counter now, in [`Resource::ALL`] order. Blocking.
    ///
    /// # Errors
    /// [`ReadError::Gone`] once the container's cgroup was removed; otherwise the file that
    /// could not be read or parsed, named.
    pub(super) fn read(&self) -> Result<Vec<(Resource, u64)>, ReadError> {
        self.files
            .iter()
            .map(|(r, f)| {
                let named = |e: String| ReadError::Failed(format!("{}: {e}", r.file()));
                let text = match read_capped(f) {
                    Ok(t) => t,
                    Err(ReadError::Gone) => return Err(ReadError::Gone),
                    Err(ReadError::Failed(e)) => return Err(named(e)),
                };
                counter(&text, r.key()).map(|n| (*r, n)).map_err(named)
            })
            .collect()
    }
}

/// `path` beneath `root`, read-only, refusing `..`, absolute paths, symlinks and magic links on
/// the way.
fn open_event_file(root: impl AsFd, path: &[u8]) -> rustix::io::Result<OwnedFd> {
    let resolve = ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS;
    fd::openat2(
        root,
        OsStr::from_bytes(path),
        OFlags::RDONLY,
        Mode::empty(),
        resolve,
    )
}

/// One `pread` at offset 0 of at most [`READ_CAP`] bytes; a file that fills the buffer is an
/// error, never a cut.
fn read_capped(f: &OwnedFd) -> Result<Vec<u8>, ReadError> {
    let mut buf = vec![0u8; READ_CAP.saturating_add(1)];
    let n = rustix::io::pread(f, &mut buf, 0).map_err(read_error)?;
    if n > READ_CAP {
        return Err(ReadError::Failed(format!("over {READ_CAP} bytes")));
    }
    buf.truncate(n);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress::scratch::{Scratch, scratch};

    const V2: &[u8] = b"0::/user.slice/libpod-ab.scope/container\n";

    #[test]
    fn the_zero_line_names_the_cgroup_relative_to_the_root() {
        assert_eq!(
            cgroup_dir(V2).unwrap(),
            b"user.slice/libpod-ab.scope/container"
        );
        let hybrid = b"12:pids:/x\n0::/a/b\n1:name=systemd:/y\n";
        assert_eq!(cgroup_dir(hybrid).unwrap(), b"a/b");
        assert_eq!(cgroup_dir(b"0::/a").unwrap(), b"a");
    }

    #[test]
    fn an_odd_cgroup_list_is_refused() {
        for bad in [
            &b""[..],
            b"1:pids:/a\n",
            b"0::/a\n0::/b\n",
            b"0::a/b\n",
            b"0::/\n",
            b"0::/a//b\n",
            b"0::/a/\n",
            b"0::/a/./b\n",
            b"0::/../a\n",
            b"0::/a/..\n",
            b"0::/a\0b\n",
        ] {
            assert!(
                cgroup_dir(bad).is_err(),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn a_cgroup_list_is_bounded_before_it_is_parsed() {
        let mut at_cap = b"0::/a".to_vec();
        at_cap.resize(READ_CAP, b'\n');
        assert!(cgroup_dir(&at_cap).is_ok());
        at_cap.push(b'\n');
        assert!(cgroup_dir(&at_cap).unwrap_err().contains("over 4096"));
    }

    #[test]
    fn a_counter_is_its_one_decimal_line() {
        let pids = b"max 3\n";
        assert_eq!(counter(pids, "max").unwrap(), 3);
        let mem = b"low 0\nhigh 0\nmax 7\noom 2\noom_kill 1\noom_group_kill 0\n";
        assert_eq!(counter(mem, "oom_kill").unwrap(), 1);
        assert_eq!(counter(mem, "max").unwrap(), 7);
        assert_eq!(
            counter(b"max 18446744073709551615", "max").unwrap(),
            u64::MAX
        );
    }

    #[test]
    fn an_odd_counter_is_refused() {
        for bad in [
            &b""[..],
            b"oom 1\n",
            b"max\n",
            b"max \n",
            b"max +1\n",
            b"max -1\n",
            b"max 1 \n",
            b"max 0x1\n",
            b"max 18446744073709551616\n",
            b"max 1\nmax 1\n",
        ] {
            assert!(
                counter(bad, "max").is_err(),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
        // `max` is not a prefix match of `max_x`.
        assert!(counter(b"max_x 1\n", "max").is_err());
    }

    #[test]
    fn an_events_file_is_bounded_before_it_is_parsed() {
        let mut at_cap = b"max 1".to_vec();
        at_cap.resize(READ_CAP, b'\n');
        assert_eq!(counter(&at_cap, "max").unwrap(), 1);
        at_cap.push(b'\n');
        assert!(counter(&at_cap, "max").unwrap_err().contains("over 4096"));
    }

    #[test]
    fn only_a_counter_that_grew_is_reported() {
        use Resource::{Memory, Pids};
        let last = [(Pids, 1), (Memory, 4)];
        assert_eq!(risen(&last, &[(Pids, 1), (Memory, 4)]), []);
        assert_eq!(risen(&last, &[(Pids, 2), (Memory, 4)]), [(Pids, 2)]);
        assert_eq!(risen(&last, &[(Pids, 1), (Memory, 5)]), [(Memory, 5)]);
        assert_eq!(
            risen(&last, &[(Pids, 9), (Memory, 6)]),
            [(Pids, 9), (Memory, 6)]
        );
        assert_eq!(risen(&last, &[(Pids, 0), (Memory, 3)]), []);
    }

    #[test]
    fn names_and_reasons_are_the_audited_ones() {
        let got: Vec<_> = Resource::ALL
            .iter()
            .map(|r| (r.name(), r.reason(), r.file(), r.key()))
            .collect();
        assert_eq!(
            got,
            [
                ("pids", "pids-max", "pids.events", "max"),
                ("memory", "oom-kill", "memory.events", "oom_kill"),
            ]
        );
    }

    struct Tree {
        dir: Scratch,
        proc: OwnedFd,
        root: OwnedFd,
    }

    impl Tree {
        fn path(&self, rel: &str) -> std::path::PathBuf {
            self.dir.join(rel)
        }
    }

    fn tree(name: &str, cgroup: &[u8]) -> Tree {
        let t = scratch("cgroup-tests", name);
        let proc = t.join("proc");
        let cg = t.join("cg/a/b");
        std::fs::create_dir_all(&proc).unwrap();
        std::fs::create_dir_all(&cg).unwrap();
        std::fs::write(proc.join("cgroup"), cgroup).unwrap();
        std::fs::write(cg.join("pids.events"), "max 2\n").unwrap();
        std::fs::write(cg.join("memory.events"), "oom 1\noom_kill 1\n").unwrap();
        let dir = OFlags::PATH | OFlags::DIRECTORY;
        let p = fd::open(&proc, dir, Mode::empty()).unwrap();
        let r = fd::open(t.join("cg"), dir, Mode::empty()).unwrap();
        Tree {
            dir: t,
            proc: p,
            root: r,
        }
    }

    #[test]
    fn the_event_files_open_beneath_the_root_and_read_again() {
        let t = tree("open", b"0::/a/b\n");
        let ev = Events::open(&t.proc, &t.root).unwrap();
        assert_eq!(
            ev.read().unwrap(),
            [(Resource::Pids, 2), (Resource::Memory, 1)]
        );
        std::fs::write(t.path("cg/a/b/pids.events"), "max 5\n").unwrap();
        assert_eq!(ev.read().unwrap().first(), Some(&(Resource::Pids, 5)));
    }

    #[test]
    fn a_symlink_on_the_way_is_not_followed() {
        // Relative and beneath the root: only `RESOLVE_NO_SYMLINKS` refuses it.
        let t = tree("symlink", b"0::/l/b\n");
        std::os::unix::fs::symlink("a", t.path("cg/l")).unwrap();
        let e = Events::open(&t.proc, &t.root).unwrap_err();
        assert!(e.starts_with("pids.events:"), "{e}");
    }

    #[test]
    fn an_event_file_of_exactly_the_cap_reads() {
        let t = tree("cap", b"0::/a/b\n");
        let ev = Events::open(&t.proc, &t.root).unwrap();
        let mut at_cap = b"max 4".to_vec();
        at_cap.resize(READ_CAP, b'\n');
        std::fs::write(t.path("cg/a/b/pids.events"), &at_cap).unwrap();
        assert_eq!(ev.read().unwrap().first(), Some(&(Resource::Pids, 4)));
    }

    #[test]
    fn an_overlong_cgroup_list_is_refused_by_the_read() {
        let mut long = b"0::/a/b\n".to_vec();
        long.resize(READ_CAP + 1, b'\n');
        let t = tree("longlist", &long);
        let e = Events::open(&t.proc, &t.root).unwrap_err();
        assert_eq!(e, "/proc/<pid>/cgroup: over 4096 bytes");
    }

    #[test]
    fn enodev_means_the_cgroup_is_gone() {
        assert_eq!(read_error(Errno::NODEV), ReadError::Gone);
        assert_eq!(
            read_error(Errno::IO),
            ReadError::Failed(Errno::IO.to_string())
        );
        assert_eq!(
            ReadError::Gone.to_string(),
            "the container's cgroup is gone"
        );
        assert_eq!(ReadError::Failed("x".into()).to_string(), "x");
    }

    #[test]
    fn a_missing_file_is_named() {
        let t = tree("missing", b"0::/a/b\n");
        std::fs::remove_file(t.path("cg/a/b/memory.events")).unwrap();
        let e = Events::open(&t.proc, &t.root).unwrap_err();
        assert_eq!(e, format!("memory.events: {}", Errno::NOENT));
        std::fs::remove_file(t.path("proc/cgroup")).unwrap();
        let e = Events::open(&t.proc, &t.root).unwrap_err();
        assert!(e.starts_with("/proc/<pid>/cgroup:"), "{e}");
    }

    #[test]
    fn an_overlong_file_is_an_error_not_a_cut() {
        let t = tree("long", b"0::/a/b\n");
        let ev = Events::open(&t.proc, &t.root).unwrap();
        let long = format!("max 1\n{}", "x".repeat(READ_CAP));
        std::fs::write(t.path("cg/a/b/pids.events"), long).unwrap();
        assert_eq!(
            ev.read().unwrap_err(),
            ReadError::Failed("pids.events: over 4096 bytes".into())
        );
    }

    #[test]
    fn the_host_cgroup_root_is_cgroup2_held_as_a_path() {
        // The dev host and CI both run cgroup v2 (`sally doctor` fails on v1).
        let root = cgroup_root().unwrap();
        let fl = rustix::fs::fcntl_getfl(&root).unwrap();
        assert!(fl.contains(OFlags::PATH), "{fl:?}");
    }

    #[test]
    fn a_root_that_is_not_a_cgroup2_directory_is_refused() {
        let t = scratch("cgroup-tests", "root");
        let dir = t.to_str().unwrap().to_owned();
        let e = open_root(&dir).unwrap_err();
        assert_eq!(e, format!("{dir} is not a cgroup2 filesystem"));
        // A symlink to the real root is not followed.
        let link = t.join("cg");
        std::os::unix::fs::symlink(CGROUP_ROOT, &link).unwrap();
        assert!(open_root(link.to_str().unwrap()).is_err());
        // A file on the cgroup2 filesystem is not a directory.
        let file = format!("{CGROUP_ROOT}/cgroup.controllers");
        assert!(open_root(&file).is_err(), "{file}");
    }
}
