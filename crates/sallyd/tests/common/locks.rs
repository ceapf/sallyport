//! The per-user test locks (architect Q23) and the not-run list of `scripts/test-run.sh`
//! (ruling 3, architect Q65). Moved out of `container.rs`, which re-exports them.

use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

/// `<xdg>/sallyport-test`, created 0700. Panics unless both it and `xdg` are real directories
/// owned by this user with no group or other access (architect Q23): the locks are shared by
/// every worktree of this user, so nobody else may plant or hold them.
pub fn lock_dir_in(xdg: &Path) -> PathBuf {
    let private = |d: &Path| {
        sallyd::sandbox::check_runtime_dir(d)
            .unwrap_or_else(|e| panic!("test lock directory {}: {e}", d.display()));
    };
    private(xdg);
    let dir = xdg.join("sallyport-test");
    match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => panic!("{}: {e}", dir.display()),
    }
    private(&dir);
    dir
}

/// Where the lock `name` lives: `$XDG_RUNTIME_DIR/sallyport-test/<name>.lock`. Read at run time,
/// no fallback: a per-worktree place would let two worktrees' disk tests overlap.
pub fn lock_path(name: &str) -> PathBuf {
    let xdg = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .expect("XDG_RUNTIME_DIR must be set to an absolute path");
    lock_dir_in(&xdg).join(format!("{name}.lock"))
}

/// Opens (creating) a lock file without truncating it, and never through a symlink.
pub fn open_lock(path: &Path) -> std::fs::File {
    use std::os::unix::fs::OpenOptionsExt;
    let nofollow = i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits()).unwrap();
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .custom_flags(nofollow)
        .open(path)
        .unwrap_or_else(|e| panic!("lock {}: {e}", path.display()))
}

/// How long a disk-floor test waits for the [`disk_free_lock`] (maintainer, 9a-2 part 4).
pub const DISK_FREE_WAIT: std::time::Duration = std::time::Duration::from_secs(20 * 60);

/// The `disk-free` lock, exclusive, for the disk-floor test `test` (its function name). A local
/// mutation run holds it shared for its whole length (`scripts/disk-lock.sh`): its tree copies
/// and builds move the free space that the disk-floor writer tests set their floor against.
/// Those tests take it exclusively, before the I/O lock. Back-to-back mutation runs in both
/// lanes can starve it (shared holders win over a polling exclusive one).
///
/// Past [`DISK_FREE_WAIT`] the test has not run, which is not a failure (ruling 3, architect
/// Q65): under `scripts/test-run.sh` it lists itself ([`record_not_run`]) and the caller returns
/// at once (`None`); the wrapper re-runs it once at the end and exits 6 if it still cannot run.
/// Outside the wrapper it panics naming the lock, as before. Never a hang.
pub fn disk_free_lock(test: &str) -> Option<std::fs::File> {
    let holder = "a local mutation run (scripts/disk-lock.sh) in either lane";
    let path = lock_path("disk-free");
    if let Some(f) = try_lock_exclusive_within(&path, DISK_FREE_WAIT, holder) {
        return Some(f);
    }
    let why = format!(
        "the lock {} was not free within {DISK_FREE_WAIT:?}; likely holder: {holder}",
        path.display()
    );
    record_not_run(test, &why);
    None
}

/// Lists `test` as not run, for `scripts/test-run.sh` to re-run: one line `<package> <test
/// binary> <test>` appended to `$SALLYPORT_TEST_NOT_RUN/list`. Honoured only under the wrapper
/// (`SALLYPORT_TEST_RUN` set too); otherwise it panics with `why`. It also panics when the
/// directory is not private or the line cannot be written (fail closed, Q65).
pub fn record_not_run(test: &str, why: &str) {
    let dir = std::env::var_os("SALLYPORT_TEST_RUN")
        .and(std::env::var_os("SALLYPORT_TEST_NOT_RUN"))
        .map(PathBuf::from);
    record_not_run_in(dir.as_deref(), test, why);
}

/// [`record_not_run`] with the list directory given (`None`: not under the wrapper).
pub fn record_not_run_in(dir: Option<&Path>, test: &str, why: &str) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let Some(dir) = dir else {
        panic!("{test}: {why}");
    };
    assert!(
        !test.is_empty() && test.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'),
        "not a test name: {test:?}"
    );
    sallyd::sandbox::check_runtime_dir(dir)
        .unwrap_or_else(|e| panic!("not-run directory {}: {e}", dir.display()));
    let nofollow = i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits()).unwrap();
    let line = format!(
        "{} {} {test}\n",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_CRATE_NAME")
    );
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(nofollow)
        .open(dir.join("list"))
        .and_then(|mut f| f.write_all(line.as_bytes()))
        .unwrap_or_else(|e| panic!("{test}: could not list it as not run: {e}; {why}"));
    eprintln!("NOT RUN: {test}: {why}");
}

/// An exclusive `flock` on `path`, waited for at most `wait`. While it waits it says so once on
/// stderr, naming the lock and its likely `holder`; past `wait` it panics with the same names.
pub fn lock_exclusive_within(
    path: &Path,
    wait: std::time::Duration,
    holder: &str,
) -> std::fs::File {
    try_lock_exclusive_within(path, wait, holder).unwrap_or_else(|| {
        panic!(
            "the lock {} was not free within {wait:?}; likely holder: {holder}",
            path.display()
        )
    })
}

/// [`lock_exclusive_within`], but `None` once `wait` has passed.
pub fn try_lock_exclusive_within(
    path: &Path,
    wait: std::time::Duration,
    holder: &str,
) -> Option<std::fs::File> {
    let f = open_lock(path);
    let started = std::time::Instant::now();
    let mut told = false;
    loop {
        match rustix::fs::flock(&f, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => return Some(f),
            Err(rustix::io::Errno::WOULDBLOCK) => {}
            Err(e) => panic!("lock {}: {e}", path.display()),
        }
        if started.elapsed() >= wait {
            return None;
        }
        if !told {
            eprintln!(
                "waiting up to {wait:?} for the lock {}; likely holder: {holder}",
                path.display()
            );
            told = true;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// An exclusive or shared `flock` on [`lock_path`]`(name)`, held until the file is dropped. It
/// works across worktrees, nextest's processes and `cargo test`'s threads alike. Order: the
/// disk-free lock ([`disk_free_lock`]), then the I/O lock, then the image lock; `build` never
/// takes the I/O lock.
pub fn lock(name: &str, exclusive: bool) -> std::fs::File {
    let f = open_lock(&lock_path(name));
    let op = if exclusive {
        rustix::fs::FlockOperation::LockExclusive
    } else {
        rustix::fs::FlockOperation::LockShared
    };
    rustix::fs::flock(&f, op).unwrap();
    f
}

/// The I/O lock: ordinary container tests share it; tests that write hundreds of MiB at full
/// speed take it exclusively, so their disk saturation never stalls another test's container
/// (seen on CI: `podman rm` timing out on a process blocked in I/O). The lock is per user, so
/// two worktrees share it. `flock` gives a waiting exclusive holder no priority: if two runs'
/// shared holders ever starve a disk test, add a turnstile lock rather than a longer timeout
/// (architect Q23 (6); not seen in the two-worktree proof).
pub fn io_lock(exclusive: bool) -> std::fs::File {
    lock("container-io", exclusive)
}
