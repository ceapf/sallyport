//! `sally-shim` relay behaviour after a failed write: the other direction still relays, the
//! client is discarded and cut a linger after its failed send, and its slot comes back (#76).
//! Also the write bound toward a client that stops reading, and a reader it must not cut (#155).
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io::ErrorKind;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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

/// Its control is the discard's wait for the other direction at the client's EOF. The write
/// bound (#155) now frees this slot too, so
/// [`a_client_that_half_closes_after_a_failed_send_is_cut_while_the_server_trickles`] pins that
/// control.
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

/// Its control is the discard's read timeout. The write bound (#155) now frees this slot too,
/// within a linger of the ceiling, so
/// [`a_silent_client_after_a_failed_send_is_cut_while_the_server_trickles`] pins that control.
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

/// Its control is the discard's own deadline. The write bound (#155) now frees this slot too,
/// within a linger of the ceiling, so
/// [`a_client_that_sends_on_after_a_failed_send_is_cut_while_the_server_trickles`] pins that
/// control.
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

/// How long [`trickle_deaf`] writes after it stops reading: at least four lingers, so only the
/// discard's own bounds free a slot before it ends.
const TRICKLE_FOR: Duration = Duration::from_millis(4500);
const _: () = assert!(TRICKLE_FOR.as_millis() >= 4 * SHORT_LINGER.as_millis());
/// The pause between [`trickle_deaf`]'s one-byte writes: what it writes in all stays far below
/// the buffers, so the shim's write toward the client never blocks and the write bound (#155)
/// never fires.
const TRICKLE_PAUSE: Duration = Duration::from_millis(100);

/// Stops reading and sets `deaf`, then writes one byte (`x`) per [`TRICKLE_PAUSE`] for
/// [`TRICKLE_FOR`], and closes.
fn trickle_deaf(mut s: UnixStream, deaf: &AtomicBool) {
    let _ = s.shutdown(Shutdown::Read);
    deaf.store(true, Ordering::SeqCst);
    let started = Instant::now();
    while started.elapsed() < TRICKLE_FOR {
        if s.write_all(b"x").is_err() {
            return;
        }
        thread::sleep(TRICKLE_PAUSE);
    }
}

static TRICKLE_SENDS_ON: AtomicBool = AtomicBool::new(false);

fn trickle_for_sends_on(s: UnixStream) {
    trickle_deaf(s, &TRICKLE_SENDS_ON);
}

#[test]
fn a_client_that_sends_on_after_a_failed_send_is_cut_while_the_server_trickles() {
    // Only the discard's own deadline cuts this client a linger after its failed send: the
    // server's end is four lingers away, and nothing toward the client blocks.
    let s = Scratch::new("tricksend");
    uds_server(&s.sock(), trickle_for_sends_on);
    let addr = start_shim_with(&s.sock(), Limiter::with_linger(1, SHORT_LINGER));
    let mut c = connect(addr);
    wait_for(&TRICKLE_SENDS_ON);
    let started = Instant::now();
    let cut = send_until_cut(
        &mut c,
        b"y",
        Duration::from_millis(20),
        SHORT_LINGER + PROMPT,
    );
    let after = cut.duration_since(started);
    assert!(after >= SHORT_LINGER / 2, "{after:?}");
    slot_comes_back(addr, "a client still sending to a trickling server");
}

static TRICKLE_HALF: AtomicBool = AtomicBool::new(false);

fn trickle_for_half(s: UnixStream) {
    trickle_deaf(s, &TRICKLE_HALF);
}

#[test]
fn a_client_that_half_closes_after_a_failed_send_is_cut_while_the_server_trickles() {
    // Only the discard's wait for the other direction, at the client's EOF, cuts this client
    // a linger after its failed send: the server's end is four lingers away.
    let s = Scratch::new("trickhalf");
    uds_server(&s.sock(), trickle_for_half);
    let addr = start_shim_with(&s.sock(), Limiter::with_linger(1, SHORT_LINGER));
    let mut c = connect(addr);
    wait_for(&TRICKLE_HALF);
    c.write_all(b"hello").unwrap();
    let sent = Instant::now();
    c.shutdown(Shutdown::Write).unwrap();
    let back =
        slot_comes_back(addr, "a half-closed client of a trickling server").duration_since(sent);
    assert!(
        back >= SHORT_LINGER / 2 && back < SHORT_LINGER + PROMPT,
        "{back:?}"
    );
    drop(c);
}

static TRICKLE_SILENT: AtomicBool = AtomicBool::new(false);

fn trickle_for_silent(s: UnixStream) {
    trickle_deaf(s, &TRICKLE_SILENT);
}

#[test]
fn a_silent_client_after_a_failed_send_is_cut_while_the_server_trickles() {
    // Only the discard's read timeout lets it see its deadline and cut this client a linger
    // after its failed send: the server's end is four lingers away.
    let s = Scratch::new("tricksilent");
    uds_server(&s.sock(), trickle_for_silent);
    let addr = start_shim_with(&s.sock(), Limiter::with_linger(1, SHORT_LINGER));
    let mut c = connect(addr);
    wait_for(&TRICKLE_SILENT);
    c.write_all(b"hello").unwrap();
    let sent = Instant::now();
    let back = slot_comes_back(addr, "a silent client of a trickling server").duration_since(sent);
    assert!(
        back >= SHORT_LINGER / 2 && back < SHORT_LINGER + PROMPT,
        "{back:?}"
    );
    drop(c);
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

/// The linger of the tests of a client that stops reading (#155). Duration only: no assertion
/// depends on the kernel's round count. The write bound fails a write toward such a client
/// some lingers after it blocked, as many as the kernel takes (a call that got some bytes in
/// returns them only when its linger runs out), so these tests time everything from the
/// moment it fails: the server's own write fails then, as the failed direction stops reading
/// it.
const MUTE_LINGER: Duration = Duration::from_millis(500);

/// When the first connection to a [`flood_noting`] server saw its write fail; later
/// connections are the probes of [`slot_comes_back`].
struct FirstFailure {
    seen: AtomicBool,
    at: Mutex<Option<Instant>>,
}

impl FirstFailure {
    const fn new() -> Self {
        Self {
            seen: AtomicBool::new(false),
            at: Mutex::new(None),
        }
    }

    /// When the server's write failed, waiting up to `bound` for it.
    fn wait(&self, bound: Duration) -> Instant {
        let started = Instant::now();
        loop {
            if let Some(at) = *self.at.lock().unwrap() {
                return at;
            }
            assert!(
                started.elapsed() < bound,
                "the server never learned the client is gone"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}

/// How long the tests of a client that stops reading wait for the server's write to fail: a
/// liveness bound equal to the clients' own timeout. At [`MUTE_LINGER`] it leaves room for
/// about three times the rounds measured (PROBE_NOTES), and it is the longest wait for which a
/// passing run of the mute-client test stays within nextest's slow period.
const FAILS_WITHIN: Duration = T;
/// The slow period of `.config/nextest.toml` (7.5 s): a passing run past it fails the
/// mutation baseline gate.
const _: () =
    assert!(FAILS_WITHIN.as_millis() + MUTE_LINGER.as_millis() + PROMPT.as_millis() <= 7500);

/// Writes until a write fails, without reading and without shutting its read side: more than
/// the buffers between it and a client that never reads hold. On the first connection, notes
/// when the write failed in `first`.
fn flood_noting(mut s: UnixStream, first: &FirstFailure) {
    let is_first = !first.seen.swap(true, Ordering::SeqCst);
    let chunk = vec![b'x'; 64 * 1024];
    while s.write_all(&chunk).is_ok() {}
    if is_first {
        *first.at.lock().unwrap() = Some(Instant::now());
    }
}

static MUTE: FirstFailure = FirstFailure::new();

fn flood_for_mute(s: UnixStream) {
    flood_noting(s, &MUTE);
}

#[test]
fn a_client_that_neither_sends_nor_reads_is_cut_a_linger_after_its_write_fails() {
    // #155: the server-to-client direction is blocked writing to this client. The write bound
    // fails that write, which also stops reading the server, so its write fails; the linger
    // after that direction's end then cuts the connection.
    let s = Scratch::new("mute");
    uds_server(&s.sock(), flood_for_mute);
    let addr = start_shim_with(&s.sock(), Limiter::with_linger(1, MUTE_LINGER));
    let c = connect(addr);
    let failed = MUTE.wait(FAILS_WITHIN);
    // A slot back before the failure is found at once, under the floor.
    let back = slot_comes_back(addr, "a client that neither sends nor reads");
    let after = back.duration_since(failed);
    assert!(
        after >= MUTE_LINGER / 2 && after < MUTE_LINGER + PROMPT,
        "{after:?}"
    );
    drop(c);
}

static HALFMUTE: FirstFailure = FirstFailure::new();

fn flood_for_halfmute(s: UnixStream) {
    flood_noting(s, &HALFMUTE);
}

#[test]
fn a_client_that_half_closes_after_its_request_and_never_reads_is_cut_when_its_write_fails() {
    // #155: no send failed, so there is no discard, and the client-to-server direction has
    // ended; the server-to-client direction is blocked writing to this client until the write
    // bound fails it, and the slot comes back then.
    let s = Scratch::new("halfmute");
    uds_server(&s.sock(), flood_for_halfmute);
    let addr = start_shim_with(&s.sock(), Limiter::with_linger(1, MUTE_LINGER));
    let mut c = connect(addr);
    c.write_all(b"hello").unwrap();
    let sent = Instant::now();
    c.shutdown(Shutdown::Write).unwrap();
    // The failure first: the slot comes back as it happens, so the two are not ordered.
    let failed = HALFMUTE.wait(FAILS_WITHIN);
    let back = slot_comes_back(addr, "a client that half-closed and never reads");
    let after = back.duration_since(failed);
    assert!(after < PROMPT, "{after:?}");
    let since_sent = back.duration_since(sent);
    assert!(since_sent >= MUTE_LINGER / 2, "{since_sent:?}");
    drop(c);
}

static BLOCKED: FirstFailure = FirstFailure::new();

fn flood_for_blocked(s: UnixStream) {
    flood_noting(s, &BLOCKED);
}

#[test]
fn a_client_whose_sends_block_and_that_never_reads_is_cut_a_linger_after_its_write_fails() {
    // #155: the server neither reads nor closes, so the client's sends block without failing
    // and there is no discard yet. The write bound fails the blocked write toward the client,
    // which stops reading the server; its write fails and it closes, the client's send that
    // then fails starts the discard, and the connection is cut a linger later. The client's own
    // timeout is only a backstop.
    let s = Scratch::new("blocked");
    uds_server(&s.sock(), flood_for_blocked);
    let addr = start_shim_with(&s.sock(), Limiter::with_linger(1, MUTE_LINGER));
    let mut c = connect(addr);
    let chunk = vec![b'a'; 16 * 1024];
    let cut = send_until_cut(&mut c, &chunk, Duration::ZERO, T);
    let back = slot_comes_back(addr, "a client whose sends block");
    // Noted when the shim's write toward the client failed, about a linger before the cut.
    let failed = BLOCKED.wait(PROMPT);
    assert!(failed < cut, "the client was cut before the server learned");
    for (what, at) in [("the cut", cut), ("the slot", back)] {
        let after = at.duration_since(failed);
        assert!(after < MUTE_LINGER + PROMPT, "{what}: {after:?}");
    }
}

/// How long [`steady_flow`] writes: over two lingers, so a bound that ignored the client's
/// progress would cut the reply.
const FLOW: Duration = Duration::from_millis(2500);
/// What [`a_client_reading_a_large_reply_with_pauses_gets_every_byte`] reads between pauses:
/// enough to reopen the receive window at the largest buffers seen, so each pause lets the
/// shim's blocked write make progress.
const BURST: usize = 1024 * 1024;
/// The pause between bursts: well under [`SHORT_LINGER`].
const PAUSE: Duration = Duration::from_millis(100);
static FLOW_SENT: AtomicUsize = AtomicUsize::new(0);
static FLOW_FAILED: AtomicBool = AtomicBool::new(false);
static FLOW_DONE: AtomicBool = AtomicBool::new(false);

/// Writes as fast as the client lets it for [`FLOW`], then closes; how much it wrote, and
/// whether a write failed.
fn steady_flow(mut s: UnixStream) {
    let chunk = vec![b'r'; 64 * 1024];
    let started = Instant::now();
    let mut sent = 0;
    while started.elapsed() < FLOW {
        if s.write_all(&chunk).is_err() {
            FLOW_FAILED.store(true, Ordering::SeqCst);
            break;
        }
        sent += chunk.len();
    }
    FLOW_SENT.store(sent, Ordering::SeqCst);
    FLOW_DONE.store(true, Ordering::SeqCst);
}

#[test]
fn a_client_reading_a_large_reply_with_pauses_gets_every_byte() {
    // #155's bound is on progress: a write toward the client fails only after a linger in which
    // the client accepted nothing. A client that keeps reading, with pauses under the linger,
    // gets the whole reply however long it takes; the server writes faster than it reads for
    // over two lingers, so the shim's write is blocked through every pause.
    let s = Scratch::new("slowread");
    uds_server(&s.sock(), steady_flow);
    let mut c = connect(start_shim_with(
        &s.sock(),
        Limiter::with_linger(1, SHORT_LINGER),
    ));
    let started = Instant::now();
    let mut buf = vec![0u8; BURST];
    let mut got = 0;
    'flow: while !FLOW_DONE.load(Ordering::SeqCst) {
        let mut burst = 0;
        while burst < BURST {
            let n = c.read(&mut buf[burst..]).unwrap();
            if n == 0 {
                got += burst;
                break 'flow;
            }
            burst += n;
        }
        got += burst;
        thread::sleep(PAUSE);
    }
    let mut rest = Vec::new();
    c.read_to_end(&mut rest).unwrap();
    got += rest.len();
    assert!(
        !FLOW_FAILED.load(Ordering::SeqCst),
        "the shim stopped relaying a client that reads"
    );
    assert_eq!(got, FLOW_SENT.load(Ordering::SeqCst));
    assert!(
        started.elapsed() > 2 * SHORT_LINGER,
        "{:?}",
        started.elapsed()
    );
}
