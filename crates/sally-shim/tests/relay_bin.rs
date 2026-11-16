//! The `sally-shim` binary: usage errors, stdio mode, listen mode and readiness, descriptor
//! exhaustion.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use common::{PROMPT, Scratch, T, close_at_once, connect, echo, read_exact_vec, uds_server};

// ---- the binary ---------------------------------------------------------------------------

fn shim_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sally-shim"))
}

#[test]
fn the_binary_rejects_bad_usage_with_exit_code_2() {
    let bad: [&[&str]; 9] = [
        &[],
        &["--bogus"],
        &["--listen"],
        &["--listen", "127.0.0.1:3128"],
        &["--listen", "0.0.0.0:3128=/run/x.sock"],
        &["--listen", "127.0.0.1:0=/run/x.sock"],
        &["--listen", "127.0.0.1:3128=relative.sock"],
        &["--stdio"],
        &[
            "--stdio",
            "/run/a.sock",
            "--listen",
            "127.0.0.1:3128=/run/x.sock",
        ],
    ];
    for args in bad {
        let out = shim_bin().args(args).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        let err = String::from_utf8_lossy(&out.stderr);
        // The first line names the problem; the usage text follows.
        let first = err.lines().next().unwrap_or_default();
        assert!(
            first
                .strip_prefix("sally-shim: ")
                .is_some_and(|m| !m.is_empty() && !m.starts_with("usage")),
            "{args:?}: {err}"
        );
        assert!(err.contains("usage"), "{args:?}");
    }
}

#[test]
fn the_binary_in_stdio_mode_relays_both_ways_and_exits_when_the_server_closes() {
    let s = Scratch::new("stdio");
    uds_server(&s.sock(), echo);
    let mut child = Reaper(
        shim_bin()
            .args(["--stdio"])
            .arg(s.sock())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let mut stdin = child.0.stdin.take().unwrap();
    let mut stdout = child.0.stdout.take().unwrap();
    let line: &[u8] = b"{\"jsonrpc\":\"2.0\",\"method\":\"ping\"}\n";
    stdin.write_all(line).unwrap();
    let mut got = vec![0u8; line.len()];
    stdout.read_exact(&mut got).unwrap();
    assert_eq!(got, line);
    drop(stdin);
    let status = child.0.wait().unwrap();
    assert!(status.success(), "{status:?}");
}

#[test]
fn the_binary_in_stdio_mode_fails_cleanly_without_a_socket() {
    let s = Scratch::new("stdionosock");
    let out = shim_bin()
        .args(["--stdio"])
        .arg(s.sock())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
}

/// Bound on waiting for a line from the shim binary. It only guards against a hang: the test
/// waits for the line itself, never for time to pass.
const LINE_WAIT: Duration = Duration::from_secs(30);

/// Base of the fixed ports the shim binary listens on; test `n` uses `BIN_PORT + n`.
const BIN_PORT: u16 = 23128;

/// The shim binary's listen address for test `n` of this process (issue #23). The address is
/// unique to the process: it encodes the whole pid (`pid_max` is at most 2^22, so 22 bits fit
/// below the second octet's high bit, which is set to stay clear of the `127.0.0.x` the other
/// tests bind). Nothing else binds it, so the fixed port is free without a probe.
///
/// A probe (bind port 0, read it, close) is forbidden here: it is what #23 was. A child that a
/// sibling test is forking holds a copy of every descriptor until its exec, so the closed probe
/// can still be listening when the shim binds (EADDRINUSE), and the test's connect then lands in
/// a backlog nobody accepts.
fn private_loopback(n: u16) -> SocketAddr {
    let [_, b2, b1, b0] = std::process::id().to_be_bytes();
    let ip = Ipv4Addr::new(127, 128 | (b2 & 127), b1, b0);
    SocketAddr::new(ip.into(), BIN_PORT + n)
}

/// The shim binary in listen mode, its stderr read line by line on a thread.
struct BinShim {
    child: Reaper,
    lines: mpsc::Receiver<String>,
    seen: Vec<String>,
}

impl BinShim {
    /// Starts `cmd` (the shim binary, possibly wrapped) and waits for its readiness line for
    /// `addr`. Panics with the shim's stderr if it exits first.
    fn start(mut cmd: Command, addr: SocketAddr) -> Self {
        let mut child = Reaper(
            cmd.stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let err = child.0.stderr.take().unwrap();
        let (tx, lines) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(err).lines() {
                let Ok(line) = line else { return };
                if tx.send(line).is_err() {
                    return;
                }
            }
        });
        let mut shim = Self {
            child,
            lines,
            seen: Vec::new(),
        };
        shim.expect_line(&format!("sally-shim: listening on {addr}"));
        shim
    }

    /// Waits for `want` on stderr; panics with everything seen if stderr ends or stalls first.
    fn expect_line(&mut self, want: &str) {
        self.expect_line_where(want, |line| line == want);
    }

    /// Waits for a line `pred` accepts (`what` describes it); panics with everything seen if
    /// stderr ends or stalls first.
    fn expect_line_where(&mut self, what: &str, pred: impl Fn(&str) -> bool) {
        let deadline = Instant::now() + LINE_WAIT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(line) => {
                    let found = pred(&line);
                    self.seen.push(line);
                    if found {
                        return;
                    }
                }
                Err(e) => panic!("no {what} ({e:?}); stderr so far: {:?}", self.seen),
            }
        }
    }
}

fn listen_args(cmd: &mut Command, addr: SocketAddr, sock: &Path) {
    cmd.args(["--listen", &format!("{addr}={}", sock.display())]);
}

#[test]
fn the_binary_in_listen_mode_serves_on_the_given_port() {
    let s = Scratch::new("binlisten");
    uds_server(&s.sock(), echo);
    let addr = private_loopback(1);
    let mut cmd = shim_bin();
    listen_args(&mut cmd, addr, &s.sock());
    let _shim = BinShim::start(cmd, addr);
    let mut c = connect(addr);
    c.write_all(b"ping").unwrap();
    assert_eq!(read_exact_vec(&mut c, 4), b"ping");
}

#[test]
fn the_binary_reports_no_readiness_unless_every_listener_is_bound() {
    // The second address is already taken (by this test), so the start fails as a whole: no
    // "listening" line for the first one, which did bind.
    let s = Scratch::new("binhalf");
    let (first, taken) = (private_loopback(3), private_loopback(4));
    let _holder = TcpListener::bind(taken).unwrap();
    let mut cmd = shim_bin();
    listen_args(&mut cmd, first, &s.sock());
    listen_args(&mut cmd, taken, &s.sock());
    let out = cmd.stdin(Stdio::null()).output().unwrap();
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!err.contains("listening"), "{err}");
    assert!(err.contains("(os error 98)"), "{err}"); // EADDRINUSE; strerror text varies by libc
}

/// Sets the soft descriptor limit of process `pid` (the hard limit stays, so it can be raised
/// again without privilege).
fn set_soft_nofile(pid: u32, soft: &str) {
    let status = Command::new("prlimit")
        .args(["--pid", &pid.to_string(), &format!("--nofile={soft}:")])
        .status()
        .unwrap();
    assert!(status.success(), "prlimit: {status:?}");
}

/// The soft descriptor limit of process `pid`.
fn soft_nofile(pid: u32) -> String {
    let out = Command::new("prlimit")
        .args([
            "--pid",
            &pid.to_string(),
            "--nofile",
            "--noheadings",
            "--output=SOFT",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "prlimit: {:?}", out.status);
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

/// A diagnostic the shim writes when a descriptor could not be had. The strerror text varies by
/// libc (glibc and musl differ), so only the prefix and the errno are fixed.
fn is_emfile_note(line: &str) -> bool {
    line == "sally-shim: accept failed; backing off"
        || (line.starts_with("sally-shim: relay failed: ") && line.ends_with("(os error 24)"))
}

#[test]
fn the_binary_backs_off_on_descriptor_exhaustion_and_serves_again() {
    // EMFILE from accept() is transient: the shim must back off and serve again once descriptors
    // are available, never exit.
    let s = Scratch::new("emfile");
    uds_server(&s.sock(), echo);
    let addr = private_loopback(2);
    let mut cmd = shim_bin();
    listen_args(&mut cmd, addr, &s.sock());
    let mut shim = BinShim::start(cmd, addr);
    // A soft limit equal to the lowest free descriptor number puts every new descriptor over the
    // limit (inherited descriptors can leave gaps higher up, so the listed count would not do).
    // Linux reserves accept()'s descriptor before blocking, unlisted in /proc. So if the serve
    // thread was already waiting when the limit fell, `a` gets that reserved descriptor and its
    // Unix connection fails; otherwise accept() itself fails. Either way the shim notes it, and
    // from then on every accept() fails with EMFILE until the limit rises.
    let pid = shim.child.0.id();
    let listed: Vec<usize> = std::fs::read_dir(format!("/proc/{pid}/fd"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_str().unwrap().parse().unwrap())
        .collect();
    let lowest_free = (0..).find(|n| !listed.contains(n)).unwrap();
    let original = soft_nofile(pid);
    set_soft_nofile(pid, &lowest_free.to_string());
    let _a = connect(addr);
    shim.expect_line_where("EMFILE note", is_emfile_note);
    let mut b = connect(addr); // completes in the kernel's backlog
    b.write_all(b"b").unwrap();
    // Not a timing assumption for the shim: it only gives a shim that wrongly exits on EMFILE
    // ample time to have done so before the limit rises.
    thread::sleep(Duration::from_millis(200));
    set_soft_nofile(pid, &original);
    assert_eq!(read_exact_vec(&mut b, 1), b"b");
    assert!(
        shim.child.0.try_wait().unwrap().is_none(),
        "the shim exited"
    );
}

/// Kills the child when dropped, so a failing test cannot leave a shim running.
struct Reaper(std::process::Child);

impl Drop for Reaper {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn stdio_mode_exits_when_the_server_closes_even_if_stdin_stays_open() {
    let s = Scratch::new("stdiodetach");
    uds_server(&s.sock(), close_at_once);
    let mut child = Reaper(
        shim_bin()
            .args(["--stdio"])
            .arg(s.sock())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let _keep_stdin_open = child.0.stdin.take().unwrap();
    let started = Instant::now();
    let status = child.0.wait().unwrap();
    assert!(status.success(), "{status:?}");
    assert!(started.elapsed() < PROMPT, "the shim waited for stdin");
}

#[test]
fn stdio_mode_fails_cleanly_when_stdout_is_closed() {
    let s = Scratch::new("stdioepipe");
    uds_server(&s.sock(), echo);
    let mut child = Reaper(
        shim_bin()
            .args(["--stdio"])
            .arg(s.sock())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    drop(child.0.stdout.take()); // the reader of the shim's stdout goes away
    let mut stdin = child.0.stdin.take().unwrap();
    // Keep sending until the shim exits. One write is not enough in a multithreaded test
    // binary: a sibling test's fork() can hold a copy of the pipe's read end until its exec, and
    // a write that lands in that window succeeds instead of failing with EPIPE.
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            started.elapsed() < T,
            "the shim kept running with its stdout closed"
        );
        let _ = stdin.write_all(b"hello\n");
        thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(status.code(), Some(1), "{status:?}");
    let mut err = String::new();
    child
        .0
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    assert!(err.contains("sally-shim"), "{err}");
}
