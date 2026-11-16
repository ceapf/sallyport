//! `sally-shim` relay behaviour: one UDS connection per TCP connection, opaque bytes, half-close,
//! bounded buffering, connection limit (AMENDMENTS-01 §3.3; RT-NET-10 shim half).
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io::ErrorKind;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use common::{
    PROMPT, Scratch, T, close_at_once, connect, echo, read_exact_one, read_exact_vec, start_shim,
    start_shim_with, uds_server,
};
use sally_shim::{Limiter, ListenSpec, bind, serve};

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
fn bind_refuses_anything_outside_ipv4_loopback() {
    let s = Scratch::new("nonloop");
    for a in ["0.0.0.0:0", "10.0.0.1:0", "[::]:0", "[::1]:0"] {
        let spec = ListenSpec {
            addr: a.parse().unwrap(),
            socket: s.sock(),
        };
        assert!(bind(&spec).is_err(), "{a}");
    }
}

#[test]
fn serve_returns_a_fatal_accept_error_instead_of_backing_off() {
    // accept() on a connected stream socket fails with EINVAL: the listener can never accept, so
    // the loop must end with that error rather than back off and retry forever.
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let stream = TcpStream::connect(l.local_addr().unwrap()).unwrap();
    let not_listening = TcpListener::from(OwnedFd::from(stream));
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(serve(
            not_listening,
            Path::new("/nonexistent.sock"),
            &Limiter::new(1),
        ));
    });
    let res = rx
        .recv_timeout(T)
        .expect("serve kept going after a fatal accept error");
    assert_eq!(res.unwrap_err().kind(), ErrorKind::InvalidInput);
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
