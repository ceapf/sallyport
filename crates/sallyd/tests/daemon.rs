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
        self.command(Command::new(env!("CARGO_BIN_EXE_sallyd")))
    }

    /// `c` (`sallyd`, or a tracer that runs it) with the private environment.
    fn command(&self, mut c: Command) -> Command {
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
    fn start(&self) -> Guard {
        let mut child = Guard::spawn(self.sallyd());
        let sock = self.state().join("control.sock");
        let end = Instant::now() + Duration::from_secs(60);
        while !sock.exists() {
            if let Some(status) = child.try_wait() {
                panic!("sallyd exited {status}: {}", child.stderr());
            }
            assert!(Instant::now() < end, "control.sock never appeared");
            std::thread::sleep(Duration::from_millis(50));
        }
        child
    }
}

/// A child process (`sallyd`, or strace running it) that a failed assertion cannot leak: on drop
/// its own children and then it are killed and reaped, so no `sallyd` keeps its lock.
struct Guard(Option<Child>);

impl Guard {
    fn spawn(mut c: Command) -> Self {
        Self(Some(c.spawn().unwrap()))
    }

    fn child(&mut self) -> &mut Child {
        self.0.as_mut().unwrap()
    }

    fn id(&mut self) -> u32 {
        self.child().id()
    }

    fn try_wait(&mut self) -> Option<std::process::ExitStatus> {
        self.child().try_wait().unwrap()
    }

    /// Waits for the exit; its status and stderr.
    fn finish(mut self) -> std::process::Output {
        self.0.take().unwrap().wait_with_output().unwrap()
    }

    fn stderr(self) -> String {
        String::from_utf8_lossy(&self.finish().stderr).into_owned()
    }

    /// The pids of its direct children.
    fn children(&mut self) -> Vec<i32> {
        let id = self.id();
        std::fs::read_to_string(format!("/proc/{id}/task/{id}/children"))
            .unwrap_or_default()
            .split_whitespace()
            .filter_map(|p| p.parse().ok())
            .collect()
    }

    fn signal(&mut self, s: rustix::process::Signal) {
        signal(i32::try_from(self.id()).unwrap(), s);
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        if self.0.is_none() {
            return;
        }
        // A tracee outlives a killed strace: its children go first.
        for p in self.children() {
            signal(p, rustix::process::Signal::KILL);
        }
        if let Some(mut c) = self.0.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn signal(pid: i32, s: rustix::process::Signal) {
    if let Some(p) = rustix::process::Pid::from_raw(pid) {
        let _ = rustix::process::kill_process(p, s);
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

fn terminate(child: &mut Guard) {
    child.signal(rustix::process::Signal::TERM);
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
    let mut first = env.start();
    let second = env.sallyd().output().unwrap();
    assert!(!second.status.success());
    let err = String::from_utf8_lossy(&second.stderr);
    assert!(err.contains("already running"), "{err}");
    assert!(env.state().join("control.sock").exists());
    terminate(&mut first);
    let out = first.finish();
    let log = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{log}");
    assert!(log.contains("\"stopped\""), "{log}");
    assert!(!env.state().join("control.sock").exists());
}

/// RT-FS-15 through the CLI against the real daemon (architect Q79, Q81): a session's kept stage
/// (one stopped before this `sallyd` started) is listed through `control.sock` by the CLI's own
/// code, its sandbox-chosen names escaped: the exact bytes `sally session changes` prints.
/// Also the control socket's wiring in `serve`: the sessions directory, an unknown session,
/// a rejected manifest. Controls: `sallyd`'s path escaping (`control_methods::change`) for the
/// bytes; the CLI's clean-check has its own test (sally-cli `tests/cli.rs`).
#[test]
fn rt_fs_15_a_kept_stage_is_listed_escaped_through_the_cli() {
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::DirBuilderExt as _;
    let env = Env::new();
    let data = env.root.join("data/sallyport");
    let upper = data.join("sessions/s-kept/stage/0/upper");
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&upper)
        .unwrap();
    std::fs::write(
        upper.join(std::ffi::OsStr::from_bytes(b"a\n\x1b[2J\xff")),
        b"x",
    )
    .unwrap();
    std::fs::write(upper.join("ok.txt"), b"x").unwrap();
    let mut d = env.start();
    let kept = || std::fs::read_dir(&upper).unwrap().count();
    assert_eq!(kept(), 2, "startup left the kept stage alone (SI-11)");
    let mut c = sally_cli::client::Client::connect(&env.state().join("control.sock")).unwrap();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut o = sally_cli::commands::Out {
        out: &mut out,
        err: &mut err,
    };
    let code = sally_cli::commands::session_changes(&mut c, "s-kept", &mut o);
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "written mounts[0] a\\x0a\\x1b[2J\\xff\nwritten mounts[0] ok.txt\n",
        "{}",
        String::from_utf8_lossy(&err)
    );
    assert_eq!(code, sally_cli::EXIT_OK);
    assert_eq!(kept(), 2, "listing changed nothing");
    let mut o = sally_cli::commands::Out {
        out: &mut Vec::new(),
        err: &mut err,
    };
    assert_eq!(
        sally_cli::commands::session_changes(&mut c, "s-gone", &mut o),
        sally_cli::EXIT_REFUSED
    );
    assert_eq!(
        sally_cli::commands::session_list(&mut c, &mut o),
        sally_cli::EXIT_OK
    );
    let refused = c.call(
        "sessions.create",
        serde_json::json!({"manifest": "bogus: 1\n"}),
    );
    assert!(
        matches!(&refused, Err(sally_cli::client::Error::Refused(d)) if d.reason == "manifest-invalid"),
        "{refused:?}"
    );
    let err = String::from_utf8(err).unwrap();
    assert_eq!(err, "sally: refused: unknown-session\n");
    drop(c);
    terminate(&mut d);
    let out = d.finish();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let audit = std::fs::read_to_string(
        std::fs::read_dir(data.join("audit"))
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .find(|p| p.extension().is_some_and(|x| x == "jsonl"))
            .expect("the audit log"),
    )
    .unwrap();
    for event in ["rpc.request", "session.refuse", "manifest.refuse"] {
        assert!(audit.contains(&format!("\"{event}\"")), "{event}: {audit}");
    }
}

/// Security re-review S3, architect Q61/Q64: `serve` starts the periodic orphan sweep, at its
/// production period, after it serves; and the installation id whose label the sweep matches is
/// kept 0600 in this daemon's own (private) state directory. Control: the `crash.spawn` of the
/// sweep in `serve`.
#[test]
fn the_daemon_starts_its_orphan_sweep_with_its_own_installation_id() {
    let env = Env::new();
    let mut d = env.start();
    // `start` returned once control.sock exists, which serve binds after the id is created.
    let id_file = env.root.join("data/sallyport/installation");
    // The sweep's first line is written as soon as its task runs, before its first period.
    std::thread::sleep(Duration::from_millis(500));
    terminate(&mut d);
    let out = d.finish();
    let log = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{log}");
    let serving = log.find("\"serving\"").expect("serving");
    let sweep = log
        .find("\"orphan sweep started\"")
        .unwrap_or_else(|| panic!("the orphan sweep was never started: {log}"));
    assert!(serving < sweep, "{log}");
    let line = log[sweep..].lines().next().unwrap();
    assert!(line.contains("period_secs=\"60\""), "{line}");
    let meta = std::fs::metadata(&id_file).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    let id = std::fs::read_to_string(&id_file).unwrap();
    assert!(
        sallyd::sandbox::Installation::parse(id.trim_end()).is_ok(),
        "{id:?}"
    );
}

/// Security review M3: SIGHUP and SIGQUIT stop `sallyd` as SIGTERM does (cleanly, `control.sock`
/// removed), never by their default action.
#[test]
fn hangup_and_quit_stop_cleanly() {
    for (sig, name) in [
        (rustix::process::Signal::HUP, "SIGHUP"),
        (rustix::process::Signal::QUIT, "SIGQUIT"),
    ] {
        let env = Env::new();
        let mut d = env.start();
        d.signal(sig);
        let out = d.finish();
        let log = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{name}: {log}");
        assert!(log.contains(&format!("why=\"{name}\"")), "{log}");
        assert!(log.contains("\"stopped\""), "{log}");
        assert!(!env.state().join("control.sock").exists());
    }
}

/// Q42 steps 1–5 and 8, on the running daemon: umask 077, no core dumps, not dumpable (the
/// entries under its `/proc/<pid>` belong to root; the directory itself keeps the task's owner),
/// the locked directory 0700, and `control.sock` 0600, bound through `/proc/self/fd` although
/// the process is not dumpable.
#[test]
fn the_running_daemon_is_hardened() {
    let env = Env::new();
    let mut child = env.start();
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
    terminate(&mut child);
    assert!(child.finish().status.success());
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
    let mut child = Guard::spawn(env.sallyd());
    let sock = env.state().join("control.sock");
    let end = Instant::now() + Duration::from_secs(60);
    loop {
        use std::os::unix::fs::FileTypeExt;
        if std::fs::symlink_metadata(&sock).is_ok_and(|m| m.file_type().is_socket()) {
            break;
        }
        if let Some(status) = child.try_wait() {
            panic!("sallyd exited {status}: {}", child.stderr());
        }
        assert!(Instant::now() < end, "control.sock never became a socket");
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(!env.state().join("sessions").exists());
    terminate(&mut child);
    assert!(child.finish().status.success());
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

/// A trace line that could be (or prepare) an outbound connection: an IP socket, a connect to a
/// non-loopback address, or a connect whose address strace could not read. A non-dumpable
/// `sallyd` cannot have its memory read, so its addresses show as pointers: what cannot be shown
/// to be loopback counts. `socket()` arguments are plain integers and always decode. A decoded
/// Unix or netlink address (podman's helpers ask the kernel over netlink) stays on the machine.
fn outbound(line: &str) -> bool {
    if line.contains("socket(AF_INET") {
        return true;
    }
    if !line.contains("connect(") {
        return false;
    }
    if line.contains("sa_family=AF_UNIX") || line.contains("sa_family=AF_NETLINK") {
        return false;
    }
    let loopback = ["inet_addr(\"127.", "\"::1\"", "\"::ffff:127."];
    !(line.contains("AF_INET") && loopback.iter().any(|l| line.contains(l)))
}

#[test]
fn only_unix_and_loopback_lines_pass_the_trace_filter() {
    let unix = r#"7 connect(5, {sa_family=AF_UNIX, sun_path="/x"}, 110) = 0"#;
    let unix_socket = "7 socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0) = 5";
    let netlink = "7 connect(5, {sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}, 12) = 0";
    let lo4 = r#"7 connect(5, {sa_family=AF_INET, sin_port=htons(1), sin_addr=inet_addr("127.0.0.1")}, 16) = 0"#;
    let lo6 = r#"7 connect(5, {sa_family=AF_INET6, sin6_port=htons(1), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "::1", &sin6_addr), sin6_scope_id=0}, 28) = 0"#;
    let out4 = r#"7 connect(5, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("192.0.2.1")}, 16) = 0"#;
    let out6 = r#"7 connect(5, {sa_family=AF_INET6, sin6_port=htons(443), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2001:db8::1", &sin6_addr), sin6_scope_id=0}, 28) = 0"#;
    let unread = "7 connect(11, 0x7fff45e25100, 16) = 0";
    let ip4 = "7 socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, IPPROTO_IP) = 5";
    let ip6 = "7 socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP) = 5";
    for l in [unix, unix_socket, netlink, lo4, lo6] {
        assert!(!outbound(l), "{l}");
    }
    for l in [out4, out6, unread, ip4, ip6] {
        assert!(outbound(l), "{l}");
    }
}

/// RT-NET-11 (SI-12): `sallyd` with no sessions and no downloads, traced for 60 s with every
/// process it starts (`strace -f`), makes no connect() to a non-loopback address. The trace must
/// show the `control.sock` bind, or it did not follow `sallyd`.
#[test]
fn rt_net_11_an_idle_sallyd_connects_nowhere() {
    let env = Env::new();
    // Traced processes run setuid helpers without their privilege, so podman could not create
    // its user namespace (`newuidmap`); an untraced podman creates the pause process first, and
    // the traced ones join it.
    let mut pause = Command::new("podman");
    pause.args(["unshare", "true"]);
    let made = env.command(pause).output().unwrap();
    assert!(
        made.status.success(),
        "{}",
        String::from_utf8_lossy(&made.stderr)
    );
    let trace = env.root.join("trace");
    let mut strace = Command::new("strace");
    strace
        .args([
            "-f",
            "-qq",
            "-e",
            "trace=socket,connect,bind",
            "-e",
            "signal=none",
            "-o",
        ])
        .arg(&trace)
        .arg(env!("CARGO_BIN_EXE_sallyd"));
    let mut tracer = Guard::spawn(env.command(strace));
    let started = Instant::now();
    let sock = env.state().join("control.sock");
    while !sock.exists() {
        if let Some(status) = tracer.try_wait() {
            panic!("strace exited {status}: {}", tracer.stderr());
        }
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "control.sock never appeared"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    std::thread::sleep(Duration::from_secs(60).saturating_sub(started.elapsed()));
    // sallyd is strace's one child; SIGTERM goes to it, and strace exits with it.
    let sallyd = *tracer.children().first().expect("strace runs sallyd");
    signal(sallyd, rustix::process::Signal::TERM);
    let out = tracer.finish();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = std::fs::read_to_string(&trace).unwrap();
    // sallyd's own bind of control.sock (its address is unreadable: the process is not
    // dumpable), from its main thread's pid.
    let own = format!("{sallyd} bind(");
    assert!(
        text.lines()
            .any(|l| l.starts_with(&own) && l.ends_with("= 0")),
        "the trace did not follow sallyd:\n{text}"
    );
    let bad: Vec<&str> = text.lines().filter(|l| outbound(l)).collect();
    assert!(bad.is_empty(), "outbound connects: {bad:#?}");
}
