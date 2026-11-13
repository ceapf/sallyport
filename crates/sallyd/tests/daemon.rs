//! Task 12 (architect Q42): the `sallyd` binary's startup, single instance and shutdown.
//!
//! Each test runs the real binary with a private `$HOME`, `$XDG_*` directories and so a private,
//! empty podman store: its `remove_orphans` never sees another test's (or the user's)
//! containers. Podman starts a pause process for the private runtime directory; it is killed
//! when the test ends.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

mod common;
use common::container::{podman, test_runtime};

static N: AtomicU32 = AtomicU32::new(0);

/// A private environment for one `sallyd`.
struct Env {
    root: PathBuf,
}

impl Env {
    fn new() -> Self {
        let n = N.fetch_add(1, Ordering::Relaxed);
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("d-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for d in ["home", "run", "data", "config/sallyport"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        let root = std::fs::canonicalize(&root).unwrap();
        std::fs::set_permissions(root.join("run"), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(
            root.join("config/sallyport/config.toml"),
            format!(
                "[sandbox]\nruntime_path = \"{}\"\n",
                test_runtime().display()
            ),
        )
        .unwrap();
        Self { root }
    }

    fn state(&self) -> PathBuf {
        self.root.join("run/sallyport")
    }

    fn sallyd(&self) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_sallyd"));
        c.env_clear()
            .env("HOME", self.root.join("home"))
            .env("XDG_RUNTIME_DIR", self.root.join("run"))
            .env("XDG_DATA_HOME", self.root.join("data"))
            .env("XDG_CONFIG_HOME", self.root.join("config"))
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        c
    }

    /// Starts `sallyd` and waits until `control.sock` exists.
    fn start(&self) -> Child {
        let mut child = self.sallyd().spawn().unwrap();
        let sock = self.state().join("control.sock");
        let end = Instant::now() + Duration::from_secs(60);
        while !sock.exists() {
            if let Some(status) = child.try_wait().unwrap() {
                panic!("sallyd exited {status}: {}", stderr(child));
            }
            assert!(Instant::now() < end, "control.sock never appeared");
            std::thread::sleep(Duration::from_millis(50));
        }
        child
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let pid = self.root.join("run/libpod/tmp/pause.pid");
        if let Some(pid) = std::fs::read_to_string(pid)
            .ok()
            .and_then(|p| p.trim().parse::<i32>().ok())
            .and_then(rustix::process::Pid::from_raw)
        {
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
        }
        let _ = podman(&["unshare", "rm", "-rf", "--", self.root.to_str().unwrap()]);
    }
}

fn stderr(child: Child) -> String {
    String::from_utf8_lossy(&child.wait_with_output().unwrap().stderr).into_owned()
}

fn terminate(child: &Child) {
    let pid = rustix::process::Pid::from_raw(i32::try_from(child.id()).unwrap()).unwrap();
    rustix::process::kill_process(pid, rustix::process::Signal::TERM).unwrap();
}

/// The value of `field:` in `/proc/<pid>/status`.
fn status_field(pid: u32, field: &str) -> String {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    status
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{field}:")))
        .unwrap()
        .trim()
        .to_owned()
}

/// Q42: one `sallyd` per user. A second one exits non-zero naming the lock; the first keeps
/// serving and stops cleanly on SIGTERM, closing `control.sock`.
#[test]
fn a_second_sallyd_exits_already_running() {
    let env = Env::new();
    let first = env.start();
    let second = env.sallyd().output().unwrap();
    assert!(!second.status.success());
    let err = String::from_utf8_lossy(&second.stderr);
    assert!(err.contains("already running"), "{err}");
    assert!(env.state().join("control.sock").exists());
    terminate(&first);
    let out = first.wait_with_output().unwrap();
    let log = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{log}");
    assert!(log.contains("\"stopped\""), "{log}");
    assert!(!env.state().join("control.sock").exists());
}

/// Q42 steps 1–5 and 8, on the running daemon: umask 077, no core dumps, not dumpable (the
/// entries under its `/proc/<pid>` belong to root; the directory itself keeps the task's owner),
/// the locked directory 0700, and `control.sock` 0600, bound through `/proc/self/fd` although
/// the process is not dumpable.
#[test]
fn the_running_daemon_is_hardened() {
    let env = Env::new();
    let child = env.start();
    let pid = child.id();
    assert_eq!(status_field(pid, "Umask"), "0077");
    let limits = std::fs::read_to_string(format!("/proc/{pid}/limits")).unwrap();
    let core = limits
        .lines()
        .find(|l| l.starts_with("Max core file size"))
        .unwrap();
    let cols: Vec<&str> = core.split_whitespace().collect();
    assert_eq!(cols.get(4..6), Some(&["0", "0"][..]), "{core}");
    let me = rustix::process::getuid().as_raw();
    assert_eq!(std::fs::metadata(format!("/proc/{pid}")).unwrap().uid(), me);
    assert_eq!(
        std::fs::symlink_metadata(format!("/proc/{pid}/fd"))
            .unwrap()
            .uid(),
        0
    );
    let mode = |p: &Path| std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mode(&env.state()), 0o700);
    assert_eq!(mode(&env.state().join("control.sock")), 0o600);
    terminate(&child);
    assert!(child.wait_with_output().unwrap().status.success());
}

/// Q42: a stale `control.sock` and stale session socket directories from a previous `sallyd`
/// are removed under the lock before the new socket is bound.
#[test]
fn stale_sockets_are_removed_at_startup() {
    let env = Env::new();
    std::fs::create_dir_all(env.state().join("sessions/old/harness")).unwrap();
    std::fs::set_permissions(env.state(), std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(env.state().join("control.sock"), b"stale").unwrap();
    // `start` returns once control.sock exists; the stale file is a regular file, so wait for a
    // socket.
    let mut child = env.sallyd().spawn().unwrap();
    let sock = env.state().join("control.sock");
    let end = Instant::now() + Duration::from_secs(60);
    loop {
        use std::os::unix::fs::FileTypeExt;
        if std::fs::symlink_metadata(&sock).is_ok_and(|m| m.file_type().is_socket()) {
            break;
        }
        if let Some(status) = child.try_wait().unwrap() {
            panic!("sallyd exited {status}: {}", stderr(child));
        }
        assert!(Instant::now() < end, "control.sock never became a socket");
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(!env.state().join("sessions").exists());
    terminate(&child);
    assert!(child.wait_with_output().unwrap().status.success());
}

/// Q42 step 4: a runtime directory others can enter is refused, and nothing is bound.
#[test]
fn a_loose_state_directory_refuses_start() {
    let env = Env::new();
    std::fs::create_dir(env.state()).unwrap();
    std::fs::set_permissions(env.state(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let out = env.sallyd().output().unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("0700"), "{err}");
    assert!(!env.state().join("control.sock").exists());
}
