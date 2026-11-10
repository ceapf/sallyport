//! `sally-shim` relay behaviour: one UDS connection per TCP connection, opaque bytes, half-close,
//! bounded buffering, connection limit (AMENDMENTS-01 §3.3; RT-NET-10 shim half).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::ErrorKind;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use sally_shim::{Limiter, ListenSpec, bind, serve};

const T: Duration = Duration::from_secs(5);
/// A closed connection must be seen well inside this; a read timeout is a failure.
const PROMPT: Duration = Duration::from_secs(2);

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        // Short: a Unix socket path is limited to 107 bytes.
        let d = std::env::temp_dir().join(format!("sh{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Self(d)
    }
    fn sock(&self) -> PathBuf {
        self.0.join("u.sock")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A UDS server running `handler` on every accepted connection; counts accepts.
fn uds_server(path: &Path, handler: fn(UnixStream)) -> Arc<AtomicUsize> {
    let listener = UnixListener::bind(path).unwrap();
    let accepts = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepts);
    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(conn) = conn else { return };
            counter.fetch_add(1, Ordering::SeqCst);
            thread::spawn(move || handler(conn));
        }
    });
    accepts
}

fn echo(mut s: UnixStream) {
    let mut buf = [0u8; 4096];
    loop {
        match s.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if s.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
}

/// Starts a shim on an ephemeral loopback port forwarding to `sock`.
fn start_shim(sock: &Path, max: usize) -> SocketAddr {
    start_shim_with(sock, Limiter::new(max))
}

fn start_shim_with(sock: &Path, limiter: Arc<Limiter>) -> SocketAddr {
    let spec = ListenSpec {
        addr: "127.0.0.1:0".parse().unwrap(),
        socket: sock.to_owned(),
    };
    let listener = bind(&spec).unwrap();
    let addr = listener.local_addr().unwrap();
    let sock = sock.to_owned();
    thread::spawn(move || {
        let _ = serve(listener, &sock, &limiter);
    });
    addr
}

/// Asserts the peer closes the connection promptly: EOF or a reset, never data and never a
/// timeout (a read timeout would mean the shim is holding the connection open).
fn expect_closed(c: &mut TcpStream) {
    c.set_read_timeout(Some(PROMPT)).unwrap();
    let started = Instant::now();
    let mut buf = [0u8; 16];
    match c.read(&mut buf) {
        Ok(0) => {}
        Ok(n) => panic!("expected the connection to close, got {n} bytes"),
        Err(e)
            if matches!(
                e.kind(),
                ErrorKind::ConnectionReset | ErrorKind::BrokenPipe | ErrorKind::ConnectionAborted
            ) => {}
        Err(e) => panic!(
            "expected a prompt close, got {e:?} after {:?}",
            started.elapsed()
        ),
    }
}

fn connect(addr: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(T)).unwrap();
    s.set_write_timeout(Some(T)).unwrap();
    s
}

fn read_exact_vec(s: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    s.read_exact(&mut v).unwrap();
    v
}

#[test]
fn bytes_round_trip_through_the_unix_socket() {
    let s = Scratch::new("echo");
    uds_server(&s.sock(), echo);
    let mut c = connect(start_shim(&s.sock(), 8));
    c.write_all(b"GET http://example.test/ HTTP/1.1\r\n\r\n")
        .unwrap();
    assert_eq!(
        read_exact_vec(&mut c, 37),
        b"GET http://example.test/ HTTP/1.1\r\n\r\n"
    );
}

#[test]
fn each_tcp_connection_gets_its_own_unix_connection_and_no_crosstalk() {
    let s = Scratch::new("perconn");
    let accepts = uds_server(&s.sock(), echo);
    let addr = start_shim(&s.sock(), 16);
    let mut conns: Vec<TcpStream> = (0..5).map(|_| connect(addr)).collect();
    for (i, c) in conns.iter_mut().enumerate() {
        c.write_all(format!("conn-{i}").as_bytes()).unwrap();
    }
    for (i, c) in conns.iter_mut().enumerate() {
        let want = format!("conn-{i}");
        assert_eq!(read_exact_vec(c, want.len()), want.as_bytes());
    }
    assert_eq!(accepts.load(Ordering::SeqCst), 5);
}

#[test]
fn large_opaque_transfers_arrive_intact_in_both_directions() {
    let s = Scratch::new("large");
    uds_server(&s.sock(), echo);
    let mut c = connect(start_shim(&s.sock(), 8));
    let total = 8 * 1024 * 1024;
    let pattern: Vec<u8> = (0..total)
        .map(|i: usize| (i.wrapping_mul(31) ^ (i >> 7)) as u8)
        .collect();
    let mut w = c.try_clone().unwrap();
    let send = pattern.clone();
    let writer = thread::spawn(move || w.write_all(&send).unwrap());
    let got = read_exact_vec(&mut c, total);
    writer.join().unwrap();
    assert!(got == pattern, "payload corrupted in transit");
}

fn reply_after_eof(mut s: UnixStream) {
    let mut all = Vec::new();
    if s.read_to_end(&mut all).is_ok() {
        let _ = s.write_all(format!("got {} bytes", all.len()).as_bytes());
    }
}

#[test]
fn half_close_is_propagated_and_the_reply_still_arrives() {
    let s = Scratch::new("half");
    uds_server(&s.sock(), reply_after_eof);
    let mut c = connect(start_shim(&s.sock(), 8));
    c.write_all(b"0123456789").unwrap();
    c.shutdown(Shutdown::Write).unwrap();
    let mut reply = String::new();
    c.read_to_string(&mut reply).unwrap();
    assert_eq!(reply, "got 10 bytes");
}

fn close_at_once(s: UnixStream) {
    drop(s);
}

#[test]
fn the_server_closing_ends_the_tcp_connection() {
    let s = Scratch::new("srvclose");
    uds_server(&s.sock(), close_at_once);
    let mut c = connect(start_shim(&s.sock(), 8));
    expect_closed(&mut c);
}

#[test]
fn a_missing_socket_closes_the_connection_promptly() {
    let s = Scratch::new("nosock");
    let mut c = connect(start_shim(&s.sock(), 8));
    expect_closed(&mut c);
}

fn count_to_eof(mut s: UnixStream) {
    let mut buf = [0u8; 4096];
    while matches!(s.read(&mut buf), Ok(n) if n > 0) {}
    // Reaching here means the shim propagated the client's close as EOF.
    let _ = s.write_all(b"eof");
}

#[test]
fn the_client_closing_reaches_the_server_as_eof() {
    let s = Scratch::new("cliclose");
    uds_server(&s.sock(), count_to_eof);
    let mut c = connect(start_shim(&s.sock(), 8));
    c.write_all(b"data").unwrap();
    c.shutdown(Shutdown::Write).unwrap();
    let mut reply = Vec::new();
    c.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, b"eof");
}

#[test]
fn connections_over_the_limit_are_dropped_and_slots_are_released() {
    let s = Scratch::new("limit");
    uds_server(&s.sock(), echo);
    let addr = start_shim(&s.sock(), 2);
    let mut a = connect(addr);
    let mut b = connect(addr);
    for c in [&mut a, &mut b] {
        c.write_all(b"x").unwrap();
        assert_eq!(read_exact_vec(c, 1), b"x");
    }
    // The third is accepted by the kernel and then closed by the shim: it must not reach the
    // echo server (which would answer) and must not be left hanging.
    let mut third = connect(addr);
    let _ = third.write_all(b"z");
    expect_closed(&mut third);
    let mut buf = [0u8; 4];
    // Closing one frees a slot.
    drop(a);
    let mut ok = false;
    for _ in 0..50 {
        let mut c = connect(addr);
        if c.write_all(b"y").is_ok() && c.read_exact(&mut buf[..1]).is_ok() && buf[0] == b'y' {
            ok = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(ok, "the slot of a closed connection was never released");
}

#[test]
fn many_sequential_connections_do_not_leak_slots() {
    let s = Scratch::new("seq");
    uds_server(&s.sock(), echo);
    let addr = start_shim(&s.sock(), 1);
    for i in 0..60u8 {
        let mut ok = false;
        // A slot is released when both directions finish; allow a moment for that.
        for _ in 0..100 {
            let mut c = connect(addr);
            if c.write_all(&[i]).is_ok() && read_exact_one(&mut c) == Some(i) {
                ok = true;
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(ok, "connection {i} never got through: slots leak");
    }
}

fn read_exact_one(c: &mut TcpStream) -> Option<u8> {
    let mut b = [0u8; 1];
    c.read_exact(&mut b).ok().map(|()| b[0])
}

fn never_read(s: UnixStream) {
    thread::sleep(Duration::from_secs(30));
    drop(s);
}

#[test]
fn a_stalled_server_applies_backpressure_instead_of_buffering() {
    let s = Scratch::new("stall");
    uds_server(&s.sock(), never_read);
    let mut c = TcpStream::connect(start_shim(&s.sock(), 8)).unwrap();
    c.set_write_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let chunk = vec![0u8; 64 * 1024];
    let mut written = 0usize;
    let limit = 256 * 1024 * 1024;
    let blocked = loop {
        match c.write(&chunk) {
            Ok(n) => {
                written += n;
                if written >= limit {
                    break false;
                }
            }
            Err(_) => break true,
        }
    };
    assert!(
        blocked,
        "the shim accepted {written} bytes from a client whose server reads nothing"
    );
    assert!(
        written < 64 * 1024 * 1024,
        "only socket buffers may absorb data, got {written}"
    );
}

#[test]
fn bind_refuses_a_non_loopback_address() {
    let s = Scratch::new("nonloop");
    for a in ["0.0.0.0:0", "10.0.0.1:0", "[::]:0"] {
        let spec = ListenSpec {
            addr: a.parse().unwrap(),
            socket: s.sock(),
        };
        assert!(bind(&spec).is_err(), "{a}");
    }
}

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
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("usage"),
            "{args:?}"
        );
    }
}

#[test]
fn the_binary_in_stdio_mode_relays_both_ways_and_exits_when_the_server_closes() {
    let s = Scratch::new("stdio");
    uds_server(&s.sock(), echo);
    let mut child = shim_bin()
        .args(["--stdio"])
        .arg(s.sock())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let line: &[u8] = b"{\"jsonrpc\":\"2.0\",\"method\":\"ping\"}\n";
    stdin.write_all(line).unwrap();
    let mut got = vec![0u8; line.len()];
    stdout.read_exact(&mut got).unwrap();
    assert_eq!(got, line);
    drop(stdin);
    let status = child.wait().unwrap();
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

#[test]
fn the_binary_in_listen_mode_serves_on_the_given_port() {
    let s = Scratch::new("binlisten");
    uds_server(&s.sock(), echo);
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let _child = Reaper(
        shim_bin()
            .args([
                "--listen",
                &format!("127.0.0.1:{port}={}", s.sock().display()),
            ])
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let mut c = None;
    for _ in 0..100 {
        if let Ok(s) = TcpStream::connect(("127.0.0.1", port)) {
            c = Some(s);
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let mut c = c.expect("the shim never started listening");
    c.set_read_timeout(Some(T)).unwrap();
    c.write_all(b"ping").unwrap();
    assert_eq!(read_exact_vec(&mut c, 4), b"ping");
}

// ---- review round -------------------------------------------------------------------------

fn close_when_told(mut s: UnixStream) {
    // Answers once, then closes while the client socket stays open.
    let mut b = [0u8; 1];
    if s.read_exact(&mut b).is_ok() {
        let _ = s.write_all(&b);
    }
}

#[test]
fn a_client_that_never_closes_does_not_hold_its_slot_forever() {
    let s = Scratch::new("linger");
    uds_server(&s.sock(), close_when_told);
    let addr = start_shim_with(
        &s.sock(),
        Limiter::with_linger(1, Duration::from_millis(300)),
    );
    let mut a = connect(addr);
    a.write_all(b"a").unwrap();
    assert_eq!(read_exact_one(&mut a), Some(b'a'));
    expect_closed(&mut a); // server side finished; `a` itself stays open and idle
    // The slot must come back once the linger expires, even though `a` is still open.
    let mut served = false;
    for _ in 0..60 {
        let mut b = connect(addr);
        if b.write_all(b"b").is_ok() && read_exact_one(&mut b) == Some(b'b') {
            served = true;
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    assert!(served, "the slot of a lingering client was never reclaimed");
    drop(a);
}

#[test]
fn legitimate_half_close_is_not_cut_by_the_linger() {
    // The linger starts only after the server is done: a slow answer after the client's
    // half-close must still arrive.
    fn slow_reply(mut s: UnixStream) {
        let mut all = Vec::new();
        let _ = s.read_to_end(&mut all);
        thread::sleep(Duration::from_millis(700));
        let _ = s.write_all(b"late");
    }
    let s = Scratch::new("slowreply");
    uds_server(&s.sock(), slow_reply);
    let addr = start_shim_with(
        &s.sock(),
        Limiter::with_linger(2, Duration::from_millis(200)),
    );
    let mut c = connect(addr);
    c.write_all(b"req").unwrap();
    c.shutdown(Shutdown::Write).unwrap();
    let mut reply = String::new();
    c.read_to_string(&mut reply).unwrap();
    assert_eq!(reply, "late");
}

static SERVER_SAW_CLOSE: AtomicUsize = AtomicUsize::new(0);

fn flood_then_watch(mut s: UnixStream) {
    let chunk = vec![7u8; 64 * 1024];
    for _ in 0..512 {
        if s.write_all(&chunk).is_err() {
            break;
        }
    }
    // After the client vanishes the shim must close its Unix side, so this read ends.
    let mut buf = [0u8; 64];
    while matches!(s.read(&mut buf), Ok(n) if n > 0) {}
    SERVER_SAW_CLOSE.fetch_add(1, Ordering::SeqCst);
}

#[test]
fn a_vanished_client_is_propagated_to_the_server() {
    let s = Scratch::new("vanish");
    uds_server(&s.sock(), flood_then_watch);
    let mut c = connect(start_shim(&s.sock(), 8));
    let _ = read_exact_vec(&mut c, 1);
    drop(c); // closes with unread data queued: the kernel resets the connection
    let mut seen = false;
    for _ in 0..60 {
        if SERVER_SAW_CLOSE.load(Ordering::SeqCst) > 0 {
            seen = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    assert!(seen, "the server was never told the client was gone");
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

fn deaf_but_chatty(mut s: UnixStream) {
    // Stops reading, keeps talking: the shim's write toward this server fails (EPIPE) while its
    // read from it would go on for seconds.
    let _ = s.shutdown(Shutdown::Read);
    for _ in 0..40 {
        if s.write_all(b"x").is_err() {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn a_write_error_tears_the_whole_connection_down() {
    let s = Scratch::new("writeerr");
    uds_server(&s.sock(), deaf_but_chatty);
    let mut c = connect(start_shim(&s.sock(), 8));
    // Let the server thread stop reading first, then send what the shim cannot deliver.
    thread::sleep(Duration::from_millis(300));
    c.write_all(b"hello").unwrap();
    let started = Instant::now();
    let mut buf = [0u8; 64];
    loop {
        match c.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        assert!(
            started.elapsed() < PROMPT,
            "the connection outlived a failed write"
        );
    }
}
