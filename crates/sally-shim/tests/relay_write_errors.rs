//! `sally-shim` relay behaviour after a failed write: the other direction still relays, the
//! client is discarded and cut a linger after its failed send, and its slot comes back (#76).
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io::ErrorKind;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use common::{
    PROMPT, Scratch, T, connect, read_exact_one, start_shim, start_shim_with, uds_server,
};
use sally_shim::Limiter;

/// How long [`deaf_but_chatty`] talks after it stops reading: well inside [`SHORT_LINGER`], which
/// also bounds the discard from the client's failed send.
const CHATTY: Duration = Duration::from_millis(400);
/// The short linger the write-error tests run with.
const SHORT_LINGER: Duration = Duration::from_millis(1000);

/// Waits until `flag` is set; a test whose peer never sets it fails instead of hanging.
fn wait_for(flag: &AtomicBool) {
    let started = Instant::now();
    while !flag.load(Ordering::SeqCst) {
        assert!(started.elapsed() < T, "the peer never got there");
        thread::sleep(Duration::from_millis(10));
    }
}

/// Bytes [`deaf_but_chatty`] sends.
const CHATTER: usize = 10;
static CHATTY_IS_DEAF: AtomicBool = AtomicBool::new(false);

fn deaf_but_chatty(mut s: UnixStream) {
    // Stops reading, keeps talking for CHATTY: the shim's write toward this server fails (EPIPE)
    // while the server's bytes go on arriving.
    let _ = s.shutdown(Shutdown::Read);
    CHATTY_IS_DEAF.store(true, Ordering::SeqCst);
    for _ in 0..CHATTER {
        if s.write_all(b"x").is_err() {
            return;
        }
        thread::sleep(CHATTY / 10);
    }
}

/// Writes `chunk`, pausing `pause` between writes, until the shim cuts the connection; when it
/// did. Only a reset or a broken pipe is a cut: a write that ends on the client's own write
/// timeout ([`T`]) fails the test, as does a cut that takes longer than `bound`.
fn send_until_cut(c: &mut TcpStream, chunk: &[u8], pause: Duration, bound: Duration) -> Instant {
    let started = Instant::now();
    loop {
        if let Err(e) = c.write_all(chunk) {
            assert!(
                matches!(
                    e.kind(),
                    ErrorKind::BrokenPipe
                        | ErrorKind::ConnectionReset
                        | ErrorKind::ConnectionAborted
                ),
                "the send ended without a cut, after {:?}: {e:?}",
                started.elapsed()
            );
            return Instant::now();
        }
        assert!(
            started.elapsed() < bound,
            "the shim never cut a client still sending"
        );
        thread::sleep(pause);
    }
}

/// [`send_until_cut`] one byte at a time, every 20 ms.
fn send_until_refused(c: &mut TcpStream) -> Instant {
    send_until_cut(c, b"y", Duration::from_millis(20), SHORT_LINGER + PROMPT)
}

#[test]
fn a_failed_write_toward_the_server_still_relays_the_server_and_ends_a_linger_later() {
    // Successor of the test that asserted a failed write tears the whole connection down at
    // once (#76): the server's bytes still arrive after the client's send fails, and the
    // connection ends a linger after that failed send.
    let s = Scratch::new("writeerr");
    uds_server(&s.sock(), deaf_but_chatty);
    let mut c = connect(start_shim_with(
        &s.sock(),
        Limiter::with_linger(8, SHORT_LINGER),
    ));
    // Let the server thread stop reading first, then send what the shim cannot deliver.
    wait_for(&CHATTY_IS_DEAF);
    c.write_all(b"hello").unwrap();
    let sent = Instant::now();
    let mut got = Vec::new();
    c.read_to_end(&mut got).unwrap();
    // Every byte the server sent arrives: none of its writes failed after the client's did.
    assert_eq!(got, b"x".repeat(CHATTER));
    assert!(
        sent.elapsed() < CHATTY + PROMPT,
        "the server's end did not reach the client"
    );
    // The server is done; the client, still open and sending, is cut a linger after its failed
    // send, not before: until then the shim discards what it sends instead of resetting it. The
    // server ended at most CHATTY after that send, so the cut is still at least
    // SHORT_LINGER - CHATTY away (a shim that refused the client at the server's end would cut
    // it at once).
    let ended = Instant::now();
    let refused_after = send_until_refused(&mut c).duration_since(ended);
    assert!(
        refused_after >= (SHORT_LINGER - CHATTY) / 2,
        "{refused_after:?}"
    );
}

fn answer_unread(mut s: UnixStream) {
    // Answers and closes without reading a byte, as `sallyd` does when it refuses a request
    // line it stopped reading.
    let _ = s.write_all(b"reply");
}

#[test]
fn a_client_still_sending_reads_the_reply_and_its_slot_comes_back() {
    let s = Scratch::new("sendon");
    uds_server(&s.sock(), answer_unread);
    let addr = start_shim_with(&s.sock(), Limiter::with_linger(1, SHORT_LINGER));
    let mut c = connect(addr);
    let mut sender = c.try_clone().unwrap();
    let sending = thread::spawn(move || {
        let chunk = vec![b'a'; 16 * 1024];
        send_until_cut(&mut sender, &chunk, Duration::ZERO, SHORT_LINGER + PROMPT)
    });
    let mut reply = Vec::new();
    let read = c.read_to_end(&mut reply);
    let replied = Instant::now();
    assert_eq!(reply, b"reply", "{read:?}");
    assert!(read.is_ok(), "the reply ended in an error: {read:?}");
    // Until the linger runs out the shim discards what the client sends, so a client that
    // would stop at a refused send still gets to read the reply (#76).
    let refused_after = sending.join().unwrap().saturating_duration_since(replied);
    assert!(refused_after >= SHORT_LINGER / 2, "{refused_after:?}");
    // The one slot comes back after the linger, though the first client never closed.
    let mut served = false;
    for _ in 0..60 {
        let mut b = connect(addr);
        let mut got = Vec::new();
        if b.read_to_end(&mut got).is_ok() && got == b"reply" {
            served = true;
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    assert!(
        served,
        "the slot of a client still sending was never reclaimed"
    );
    drop(c);
}

fn deaf_flood(s: UnixStream) {
    flood_deaf(s, &AtomicBool::new(false));
}

/// Stops reading and sets `deaf`, then writes until a write fails: more than the buffers
/// between it and a client that never reads hold.
fn flood_deaf(mut s: UnixStream, deaf: &AtomicBool) {
    let _ = s.shutdown(Shutdown::Read);
    deaf.store(true, Ordering::SeqCst);
    let chunk = vec![b'x'; 64 * 1024];
    while s.write_all(&chunk).is_ok() {}
}

/// Connects to `addr` until a connection is served (it reads the server's first byte, `x`),
/// that is until the one slot is free again; when that was.
fn slot_comes_back(addr: SocketAddr, what: &str) -> Instant {
    for _ in 0..60 {
        let mut b = connect(addr);
        if read_exact_one(&mut b) == Some(b'x') {
            return Instant::now();
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("the slot of {what} was never reclaimed");
}

static HALFCLOSE_IS_DEAF: AtomicBool = AtomicBool::new(false);

fn deaf_flood_for_halfclose(s: UnixStream) {
    flood_deaf(s, &HALFCLOSE_IS_DEAF);
}

#[test]
fn a_client_that_half_closes_after_a_failed_send_and_never_reads_is_cut_a_linger_later() {
    // The client's EOF does not end the discard's bound while the reply is still blocked on
    // its way to the client.
    let s = Scratch::new("halfdeaf");
    uds_server(&s.sock(), deaf_flood_for_halfclose);
    let addr = start_shim_with(&s.sock(), Limiter::with_linger(1, SHORT_LINGER));
    let mut c = connect(addr);
    wait_for(&HALFCLOSE_IS_DEAF);
    c.write_all(b"hello").unwrap();
    let sent = Instant::now();
    c.shutdown(Shutdown::Write).unwrap();
    let back = slot_comes_back(addr, "a client that half-closed").duration_since(sent);
    assert!(
        back >= SHORT_LINGER / 2 && back < SHORT_LINGER + PROMPT,
        "{back:?}"
    );
    drop(c);
}

static SILENT_IS_DEAF: AtomicBool = AtomicBool::new(false);

fn deaf_flood_for_silent(s: UnixStream) {
    flood_deaf(s, &SILENT_IS_DEAF);
}

#[test]
fn a_silent_client_after_a_failed_send_is_cut_a_linger_later() {
    // Neither sends again, nor closes, nor reads: the discard's read must time out to see its
    // deadline.
    let s = Scratch::new("silentdeaf");
    uds_server(&s.sock(), deaf_flood_for_silent);
    let addr = start_shim_with(&s.sock(), Limiter::with_linger(1, SHORT_LINGER));
    let mut c = connect(addr);
    wait_for(&SILENT_IS_DEAF);
    c.write_all(b"hello").unwrap();
    let sent = Instant::now();
    let back = slot_comes_back(addr, "a silent client").duration_since(sent);
    assert!(
        back >= SHORT_LINGER / 2 && back < SHORT_LINGER + PROMPT,
        "{back:?}"
    );
    drop(c);
}

#[test]
fn a_client_that_sends_but_never_reads_is_cut_a_linger_after_its_failed_send() {
    // The server-to-client direction stays blocked writing to this client, so the linger after
    // the server's end never starts; the discard's own deadline must end it.
    let s = Scratch::new("deafdeaf");
    uds_server(&s.sock(), deaf_flood);
    let addr = start_shim_with(&s.sock(), Limiter::with_linger(1, SHORT_LINGER));
    let mut c = connect(addr);
    let started = Instant::now();
    let chunk = vec![b'a'; 16 * 1024];
    let refused_after = send_until_cut(&mut c, &chunk, Duration::ZERO, SHORT_LINGER + PROMPT)
        .duration_since(started);
    assert!(refused_after >= SHORT_LINGER / 2, "{refused_after:?}");
    slot_comes_back(addr, "a client that does not read");
}

static HALFSTOP_IS_DEAF: AtomicBool = AtomicBool::new(false);
static HALFSTOP_SENT: AtomicBool = AtomicBool::new(false);

fn deaf_then_answers(mut s: UnixStream) {
    // Stops reading at once, so the shim's write of the client's request fails (EPIPE); only
    // after that does it answer and close, as `sallyd` does after a refusal (#76).
    let _ = s.shutdown(Shutdown::Read);
    HALFSTOP_IS_DEAF.store(true, Ordering::SeqCst);
    wait_for(&HALFSTOP_SENT);
    // The client's bytes are on their way; give the shim time to fail writing them here.
    thread::sleep(Duration::from_millis(300));
    let _ = s.write_all(b"reply");
}

#[test]
fn a_write_error_stops_only_its_own_direction() {
    let s = Scratch::new("halfstop");
    uds_server(&s.sock(), deaf_then_answers);
    let mut c = connect(start_shim(&s.sock(), 8));
    wait_for(&HALFSTOP_IS_DEAF);
    c.write_all(b"hello").unwrap();
    HALFSTOP_SENT.store(true, Ordering::SeqCst);
    let mut got = Vec::new();
    let read = c.read_to_end(&mut got);
    assert_eq!(got, b"reply", "{read:?}");
    assert!(read.is_ok(), "{read:?}");
}
