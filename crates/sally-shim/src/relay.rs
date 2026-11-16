//! The relay: fixed buffers, bounded connections, no interpretation of the bytes.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::args::{ListenSpec, is_listen_ip};

/// Copy buffer per direction, fixed at 16 KiB; changing it changes per-connection memory.
/// Together with the kernel socket buffers this is all the data a connection can hold: a stalled
/// peer stops the other side rather than growing memory.
pub const BUF_BYTES: usize = 16 * 1024;
/// Default cap on live connections across all listeners. Each costs two threads, and the sandbox
/// that runs the shim has a small `pids` limit, so the default stays well below it.
pub const MAX_CONNECTIONS: usize = 32;
/// Default time a connection may linger, with its server side finished, waiting for the client
/// to close. Pooled HTTP clients leave such sockets open; without a bound each would hold a slot
/// forever. Applies only after the server's EOF, so a long response stream is never cut.
pub const LINGER: Duration = Duration::from_secs(30);
/// Stack for a copy thread: it only holds [`BUF_BYTES`] and a few locals. Must exceed
/// [`BUF_BYTES`] plus headroom: on musl (the shipped static binary), std raises a small stack
/// only to about 2 KiB, so a copy thread would overflow. The assertion below holds it there.
const THREAD_STACK_BYTES: usize = 128 * 1024;
const _: () = assert!(THREAD_STACK_BYTES >= BUF_BYTES + 64 * 1024);
/// Pause after a failed `accept` (descriptor exhaustion), so the loop does not spin.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);
/// At most one diagnostic line per this interval, process-wide.
const LOG_INTERVAL: Duration = Duration::from_secs(5);

/// The connection budget and diagnostics shared by every listener of one process.
#[derive(Debug)]
pub struct Limiter {
    live: AtomicUsize,
    max: usize,
    linger: Duration,
    last_log: Mutex<Option<Instant>>,
}

impl Limiter {
    /// A limiter allowing `max` live connections, with the default [`LINGER`].
    #[must_use]
    pub fn new(max: usize) -> Arc<Self> {
        Self::with_linger(max, LINGER)
    }

    /// A limiter with an explicit linger time.
    #[must_use]
    pub fn with_linger(max: usize, linger: Duration) -> Arc<Self> {
        Arc::new(Self {
            live: AtomicUsize::new(0),
            max,
            linger,
            last_log: Mutex::new(None),
        })
    }

    /// Takes a slot, or `None` if the budget is spent. The slot is released on drop.
    fn admit(self: &Arc<Self>) -> Option<Slot> {
        if self.live.fetch_add(1, Ordering::SeqCst) >= self.max {
            self.live.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(Slot(Arc::clone(self)))
    }

    /// Writes a diagnostic line, at most one per [`LOG_INTERVAL`]. A closed stderr is ignored:
    /// `eprintln!` would panic, and a client must not be able to kill the shim by provoking
    /// diagnostics.
    fn note(&self, msg: &str) {
        self.note_to(&mut io::stderr(), msg);
    }

    /// [`Limiter::note`] with the destination given. The write happens after the lock is
    /// released, so a stalled stderr reader can block one diagnostic, never every accept loop.
    fn note_to(&self, out: &mut dyn Write, msg: &str) {
        let due = {
            let Ok(mut last) = self.last_log.lock() else {
                return;
            };
            let due = last.is_none_or(|t| t.elapsed() >= LOG_INTERVAL);
            if due {
                *last = Some(Instant::now());
            }
            due
        };
        if due {
            let _ = writeln!(out, "sally-shim: {msg}");
        }
    }
}

/// A connection slot; releasing it is the drop.
struct Slot(Arc<Limiter>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.live.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Binds the TCP listener for `spec`. Refuses anything outside IPv4 loopback (127/8), again (the
/// argument parser already does): inside the sandbox there is no network, but the shim must
/// never be the thing that listens beyond localhost.
///
/// # Errors
/// `InvalidInput` for an address outside 127/8; otherwise the bind error.
pub fn bind(spec: &ListenSpec) -> io::Result<TcpListener> {
    if !is_listen_ip(spec.addr.ip()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "listen address must be IPv4 loopback (127/8)",
        ));
    }
    TcpListener::bind(spec.addr)
}

/// Accepts connections on `listener` forever, relaying each to a fresh connection to `socket`.
/// Connections beyond the limiter's budget are closed at once. Returns only on a fatal listener
/// error.
///
/// # Errors
/// The (non-transient) error that ended the accept loop.
pub fn serve(listener: TcpListener, socket: &Path, limiter: &Arc<Limiter>) -> io::Result<()> {
    for incoming in listener.incoming() {
        let tcp = match incoming {
            Ok(tcp) => tcp,
            Err(e) if is_transient(&e) => {
                limiter.note("accept failed; backing off");
                thread::sleep(ACCEPT_BACKOFF);
                continue;
            }
            Err(e) => return Err(e),
        };
        let Some(slot) = limiter.admit() else {
            limiter.note("connection limit reached; dropping a connection");
            continue; // `tcp` is dropped, closing it
        };
        let path = socket.to_owned();
        let lim = Arc::clone(limiter);
        let spawned = thread::Builder::new()
            .name("conn".into())
            .stack_size(THREAD_STACK_BYTES)
            .spawn(move || {
                if let Err(e) = relay_connection(tcp, &path, &lim, &slot) {
                    lim.note(&format!("relay failed: {e}"));
                }
            });
        if spawned.is_err() {
            // The closure (the stream and the slot with it) is gone; the slot was released.
            limiter.note("cannot start a thread; dropping a connection");
        }
    }
    Ok(())
}

fn is_transient(e: &io::Error) -> bool {
    !matches!(
        e.kind(),
        io::ErrorKind::InvalidInput | io::ErrorKind::NotFound
    )
}

/// A stream the relay can read, write and shut down through a shared reference, so both
/// directions share one descriptor instead of duplicating it.
trait Half: Send + Sync + 'static {
    fn read_some(&self, buf: &mut [u8]) -> io::Result<usize>;
    fn write_all_to(&self, buf: &[u8]) -> io::Result<()>;
    fn close(&self, how: Shutdown);
    /// Bounds each later read to `wait` (not zero); a read that times out fails with
    /// `WouldBlock` or `TimedOut`.
    fn read_wait(&self, wait: Duration);
}

macro_rules! half {
    ($t:ty) => {
        impl Half for $t {
            fn read_some(&self, buf: &mut [u8]) -> io::Result<usize> {
                (&*self).read(buf)
            }
            fn write_all_to(&self, buf: &[u8]) -> io::Result<()> {
                (&*self).write_all(buf)
            }
            fn close(&self, how: Shutdown) {
                let _ = self.shutdown(how);
            }
            fn read_wait(&self, wait: Duration) {
                let _ = self.set_read_timeout(Some(wait));
            }
        }
    };
}
half!(TcpStream);
half!(UnixStream);

/// One TCP connection: connect to the Unix socket, then copy both ways until done.
///
/// When the server-to-client direction ends (the server's EOF, a read error, or a failed write
/// to the client), the client gets [`Limiter::linger`] to close its end; after that the
/// connection is torn down both ways so the slot comes back. A client still sending after the
/// server stopped reading gets the same linger from that failed write (the discard deadline in
/// [`Direction::ToServer`]); its bytes are discarded meanwhile, and the reply is relayed (#76).
/// Those two are the only places that shut both ways.
///
/// TODO(#155): a client that neither sends nor reads after a reply larger than the buffers
/// holds its slot: the server-to-client direction stays blocked writing to it.
fn relay_connection(
    tcp: TcpStream,
    socket: &Path,
    limiter: &Arc<Limiter>,
    _slot: &Slot,
) -> io::Result<()> {
    let uds = UnixStream::connect(socket)?;
    let _ = tcp.set_nodelay(true);
    let (tcp, uds) = (Arc::new(tcp), Arc::new(uds));
    let (done_tx, done_rx) = mpsc::channel::<()>();
    let cut = Arc::new(AtomicBool::new(false));
    let upstream = {
        let (from, to) = (Arc::clone(&tcp), Arc::clone(&uds));
        let (linger, cut) = (limiter.linger, Arc::clone(&cut));
        thread::Builder::new()
            .name("up".into())
            .stack_size(THREAD_STACK_BYTES)
            .spawn(move || {
                copy_half(&*from, &*to, Direction::ToServer { linger, cut: &cut });
                drop(done_tx);
            })?
    };
    copy_half(&*uds, &*tcp, Direction::ToClient);
    if matches!(
        done_rx.recv_timeout(limiter.linger),
        Err(RecvTimeoutError::Timeout)
    ) {
        // Set first, so a discard woken by the shutdowns reads no further: a close that finds
        // the client's bytes unread resets it, and a client that had filled its window learns
        // of the cut at once instead of after the kernel's FIN timeout.
        cut.store(true, Ordering::SeqCst);
        tcp.close(Shutdown::Both);
        uds.close(Shutdown::Both);
    }
    upstream
        .join()
        .map_err(|_| io::Error::other("copy thread panicked"))
}

/// Which way a [`copy_half`] copies, which decides what it does at a read error or a failed
/// write.
#[derive(Debug, Clone, Copy)]
enum Direction<'a> {
    /// Server to client. A failed write stops reading the server, so the server's next write
    /// fails and it learns the client is gone. No discard: nothing would bound it.
    ToClient,
    /// Client to server. A failed write leaves the client's bytes read and discarded, so a
    /// client still sending is not reset before it reads the reply relayed the other way (#76),
    /// for at most `linger` from that write, or until `cut` (the linger in [`relay_connection`])
    /// is set. A client's read error (it reset) also shuts the server's read side: the client can
    /// read no reply, and the other direction then ends at once.
    ToServer {
        linger: Duration,
        cut: &'a AtomicBool,
    },
}

/// Copies `from` → `to` with a fixed buffer, for one direction. It shuts down the read side of
/// `from` and the write side of `to`; only a client's read error (also the server's read side)
/// and the discard deadline (both ways, as the linger in [`relay_connection`]) shut more.
/// - At EOF it half-closes `to`, so the peer sees the end but can still answer.
/// - At a read error it shuts `from`'s read side and half-closes `to`.
/// - At a failed write it half-closes `to`, then acts as `direction` says.
fn copy_half(from: &dyn Half, to: &dyn Half, direction: Direction<'_>) {
    let mut buf = [0u8; BUF_BYTES];
    loop {
        match from.read_some(&mut buf) {
            Ok(0) => {
                to.close(Shutdown::Write);
                return;
            }
            Ok(n) => match buf.get(..n) {
                Some(chunk) if to.write_all_to(chunk).is_ok() => {}
                _ => break,
            },
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => {
                from.close(Shutdown::Read);
                to.close(Shutdown::Write);
                if let Direction::ToServer { .. } = direction {
                    to.close(Shutdown::Read);
                }
                return;
            }
        }
    }
    to.close(Shutdown::Write);
    match direction {
        Direction::ToClient => from.close(Shutdown::Read),
        Direction::ToServer { linger, cut } => {
            discard(from, to, &mut buf, Instant::now() + linger, cut);
        }
    }
}

/// Reads the client (`from`) into `buf` and drops the bytes until its EOF, `cut` is set, or
/// `deadline` passes; at the deadline it shuts both streams both ways, which also wakes the
/// other direction. A read error shuts `from`'s read side and the server's (`to`) read side.
fn discard(from: &dyn Half, to: &dyn Half, buf: &mut [u8], deadline: Instant, cut: &AtomicBool) {
    loop {
        if cut.load(Ordering::SeqCst) {
            return;
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            from.close(Shutdown::Both);
            to.close(Shutdown::Both);
            return;
        }
        from.read_wait(left);
        match from.read_some(buf) {
            Ok(0) => return,
            Ok(_) => {}
            Err(e) if is_wait(&e) => {}
            Err(_) => {
                from.close(Shutdown::Read);
                to.close(Shutdown::Read);
                return;
            }
        }
    }
}

/// A read that was interrupted or timed out, to be tried again.
fn is_wait(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

/// Relays `input` → the Unix socket and the socket → `output` (flushing every chunk), until the
/// socket closes. When `input` ends, the socket's write side is closed so the server sees EOF.
///
/// # Errors
/// Failure to connect to `socket`, or a write error on `output`.
pub fn stdio<R: Read + Send + 'static, W: Write>(
    socket: &Path,
    input: R,
    mut output: W,
) -> io::Result<()> {
    let uds = Arc::new(UnixStream::connect(socket)?);
    let uds_w = Arc::clone(&uds);
    // Detached on purpose: a blocked read on stdin must not keep the process alive once the
    // server has closed.
    thread::Builder::new()
        .name("stdin".into())
        .stack_size(THREAD_STACK_BYTES)
        .spawn(move || feed(input, &*uds_w))?;
    drain(&*uds, &mut output)
}

/// Copies `input` → `to` until EOF or a read error, then half-closes `to` so the server sees EOF.
/// A failed write returns at once: the socket is already broken.
fn feed<R: Read>(mut input: R, to: &dyn Half) {
    let mut buf = [0u8; BUF_BYTES];
    loop {
        match input.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => match buf.get(..n) {
                Some(chunk) if to.write_all_to(chunk).is_ok() => {}
                _ => return,
            },
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    to.close(Shutdown::Write);
}

/// Copies `from` → `output`, flushing every chunk, until `from` ends.
fn drain<W: Write>(from: &dyn Half, output: &mut W) -> io::Result<()> {
    let mut buf = [0u8; BUF_BYTES];
    loop {
        match from.read_some(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => {
                let Some(chunk) = buf.get(..n) else {
                    return Ok(());
                };
                output.write_all(chunk)?;
                output.flush()?;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::io::ErrorKind;

    /// One scripted read.
    enum Step {
        Data(&'static [u8]),
        Fail(ErrorKind),
        /// A read that waits this long, then times out (`WouldBlock`, as a read timeout does).
        Stall(Duration),
    }

    /// A scripted stream. Each read takes the next step; once the script is spent, reads give
    /// EOF. Writes, shutdowns and read waits are recorded.
    struct Fake {
        script: Mutex<VecDeque<Step>>,
        fail_writes: bool,
        written: Mutex<Vec<u8>>,
        closes: Mutex<Vec<Shutdown>>,
        waits: Mutex<Vec<Duration>>,
    }

    impl Fake {
        fn new(script: Vec<Step>) -> Self {
            Self {
                script: Mutex::new(script.into()),
                fail_writes: false,
                written: Mutex::default(),
                closes: Mutex::default(),
                waits: Mutex::default(),
            }
        }
        fn waits(&self) -> Vec<Duration> {
            self.waits.lock().unwrap().clone()
        }
        fn failing_writes() -> Self {
            Self {
                fail_writes: true,
                ..Self::new(Vec::new())
            }
        }
        fn written(&self) -> Vec<u8> {
            self.written.lock().unwrap().clone()
        }
        fn closes(&self) -> Vec<Shutdown> {
            self.closes.lock().unwrap().clone()
        }
        fn unread(&self) -> usize {
            self.script.lock().unwrap().len()
        }
    }

    impl Half for Fake {
        fn read_some(&self, buf: &mut [u8]) -> io::Result<usize> {
            let step = self.script.lock().unwrap().pop_front();
            match step {
                None => Ok(0),
                Some(Step::Fail(kind)) => Err(kind.into()),
                Some(Step::Stall(wait)) => {
                    thread::sleep(wait);
                    Err(ErrorKind::WouldBlock.into())
                }
                Some(Step::Data(d)) => {
                    buf.get_mut(..d.len())
                        .expect("step too long")
                        .copy_from_slice(d);
                    Ok(d.len())
                }
            }
        }
        fn write_all_to(&self, buf: &[u8]) -> io::Result<()> {
            if self.fail_writes {
                return Err(ErrorKind::BrokenPipe.into());
            }
            self.written.lock().unwrap().extend_from_slice(buf);
            Ok(())
        }
        fn close(&self, how: Shutdown) {
            self.closes.lock().unwrap().push(how);
        }
        fn read_wait(&self, wait: Duration) {
            self.waits.lock().unwrap().push(wait);
        }
    }

    impl Read for &Fake {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.read_some(buf)
        }
    }

    /// A linger no test reaches.
    const LONG: Duration = Duration::from_secs(60);
    /// A `cut` flag that stays clear.
    static NOT_CUT: AtomicBool = AtomicBool::new(false);
    /// A `cut` flag that is set.
    static CUT: AtomicBool = AtomicBool::new(true);

    fn to_server(linger: Duration, cut: &AtomicBool) -> Direction<'_> {
        Direction::ToServer { linger, cut }
    }

    #[test]
    fn copy_half_retries_an_interrupted_read_and_half_closes_at_eof() {
        for way in [Direction::ToClient, to_server(LONG, &NOT_CUT)] {
            let (from, to) = (
                Fake::new(vec![Step::Fail(ErrorKind::Interrupted), Step::Data(b"ab")]),
                Fake::new(Vec::new()),
            );
            copy_half(&from, &to, way);
            assert_eq!(to.written(), b"ab", "{way:?}");
            assert_eq!(to.closes(), [Shutdown::Write], "{way:?}");
            assert!(from.closes().is_empty(), "{way:?}");
        }
    }

    #[test]
    fn copy_half_stops_at_a_read_error_and_closes_its_own_direction() {
        // From the client (it reset) the server's read side is shut too; from the server, only
        // the copy's own halves.
        let server_read_too = [Shutdown::Write, Shutdown::Read];
        for (way, to_closes) in [
            (Direction::ToClient, &[Shutdown::Write][..]),
            (to_server(LONG, &NOT_CUT), &server_read_too[..]),
        ] {
            let (from, to) = (
                Fake::new(vec![
                    Step::Fail(ErrorKind::ConnectionReset),
                    Step::Data(b"zz"),
                ]),
                Fake::new(Vec::new()),
            );
            copy_half(&from, &to, way);
            assert_eq!(to.written(), b"", "{way:?}");
            assert_eq!(from.unread(), 1, "read on after a read error ({way:?})");
            assert_eq!(from.closes(), [Shutdown::Read], "{way:?}");
            assert_eq!(to.closes(), to_closes, "{way:?}");
        }
    }

    #[test]
    fn copy_half_toward_the_client_stops_at_a_failed_write_and_closes_only_its_own_direction() {
        let (from, to) = (
            Fake::new(vec![Step::Data(b"a"), Step::Data(b"b")]),
            Fake::failing_writes(),
        );
        copy_half(&from, &to, Direction::ToClient);
        assert_eq!(from.unread(), 1, "read on after a failed write");
        assert_eq!(from.closes(), [Shutdown::Read]);
        assert_eq!(to.closes(), [Shutdown::Write]);
    }

    #[test]
    fn copy_half_toward_the_server_discards_the_client_to_its_end_after_a_failed_write() {
        let (from, to) = (
            Fake::new(vec![
                Step::Data(b"a"),
                Step::Data(b"b"),
                Step::Fail(ErrorKind::Interrupted),
                Step::Stall(Duration::ZERO),
                Step::Fail(ErrorKind::TimedOut),
                Step::Data(b"c"),
            ]),
            Fake::failing_writes(),
        );
        copy_half(&from, &to, to_server(LONG, &NOT_CUT));
        assert_eq!(
            from.unread(),
            0,
            "stopped discarding before the client's end"
        );
        assert!(from.closes().is_empty(), "{:?}", from.closes());
        assert_eq!(to.closes(), [Shutdown::Write]);
        // Every discarding read (five steps, then the end) waits at most what is left of the
        // linger from the failed write.
        let waits = from.waits();
        assert_eq!(waits.len(), 6, "{waits:?}");
        assert!(
            waits.iter().all(|w| *w <= LONG && *w > LONG - T_SLACK),
            "{waits:?}"
        );
    }

    /// More than a unit test takes; less than [`LONG`].
    const T_SLACK: Duration = Duration::from_secs(10);

    #[test]
    fn a_read_error_ends_the_discard_and_shuts_the_server_s_read_side() {
        let (from, to) = (
            Fake::new(vec![
                Step::Data(b"a"),
                Step::Fail(ErrorKind::ConnectionReset),
                Step::Data(b"zz"),
            ]),
            Fake::failing_writes(),
        );
        copy_half(&from, &to, to_server(LONG, &NOT_CUT));
        assert_eq!(from.unread(), 1, "read on after a read error");
        assert_eq!(from.closes(), [Shutdown::Read]);
        assert_eq!(to.closes(), [Shutdown::Write, Shutdown::Read]);
    }

    #[test]
    fn the_discard_with_no_linger_left_cuts_both_ways_without_reading() {
        let (from, to) = (
            Fake::new(vec![Step::Data(b"a"), Step::Data(b"b")]),
            Fake::failing_writes(),
        );
        copy_half(&from, &to, to_server(Duration::ZERO, &NOT_CUT));
        assert_eq!(from.unread(), 1, "read on past the deadline");
        assert!(from.waits().is_empty(), "{:?}", from.waits());
        assert_eq!(from.closes(), [Shutdown::Both]);
        assert_eq!(to.closes(), [Shutdown::Write, Shutdown::Both]);
    }

    #[test]
    fn the_discard_cuts_both_ways_once_its_linger_has_passed() {
        let linger = Duration::from_millis(50);
        let (from, to) = (
            Fake::new(vec![
                Step::Data(b"a"),
                Step::Stall(linger * 2),
                Step::Data(b"b"),
            ]),
            Fake::failing_writes(),
        );
        copy_half(&from, &to, to_server(linger, &NOT_CUT));
        assert_eq!(from.unread(), 1, "read on past the deadline");
        assert_eq!(from.waits().len(), 1, "{:?}", from.waits());
        assert_eq!(from.closes(), [Shutdown::Both]);
        assert_eq!(to.closes(), [Shutdown::Write, Shutdown::Both]);
    }

    #[test]
    fn a_cut_discard_reads_no_further_and_leaves_the_closes_to_the_linger() {
        let (from, to) = (
            Fake::new(vec![Step::Data(b"a"), Step::Data(b"b")]),
            Fake::failing_writes(),
        );
        copy_half(&from, &to, to_server(LONG, &CUT));
        assert_eq!(from.unread(), 1, "read on after the cut");
        assert!(from.waits().is_empty(), "{:?}", from.waits());
        assert!(from.closes().is_empty(), "{:?}", from.closes());
        assert_eq!(to.closes(), [Shutdown::Write]);
    }

    #[test]
    fn feed_retries_an_interrupted_read_and_half_closes_at_eof() {
        let input = Fake::new(vec![Step::Fail(ErrorKind::Interrupted), Step::Data(b"hi")]);
        let to = Fake::new(Vec::new());
        feed(&input, &to);
        assert_eq!(to.written(), b"hi");
        assert_eq!(to.closes(), [Shutdown::Write]);
    }

    #[test]
    fn feed_stops_at_a_read_error_and_half_closes() {
        let input = Fake::new(vec![Step::Fail(ErrorKind::Other), Step::Data(b"zz")]);
        let to = Fake::new(Vec::new());
        feed(&input, &to);
        assert_eq!(to.written(), b"");
        assert_eq!(to.closes(), [Shutdown::Write]);
    }

    #[test]
    fn feed_returns_at_a_failed_write_without_reading_on() {
        let input = Fake::new(vec![Step::Data(b"a"), Step::Data(b"b")]);
        let to = Fake::failing_writes();
        feed(&input, &to);
        assert_eq!(input.unread(), 1, "read on after a failed write");
        assert!(to.closes().is_empty());
    }

    /// A writer that records each chunk it has been asked to flush.
    #[derive(Default)]
    struct Flushes {
        pending: Vec<u8>,
        flushed: Vec<Vec<u8>>,
    }

    impl Write for Flushes {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.pending.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            self.flushed.push(std::mem::take(&mut self.pending));
            Ok(())
        }
    }

    #[test]
    fn drain_retries_an_interrupted_read_and_flushes_every_chunk() {
        let from = Fake::new(vec![
            Step::Fail(ErrorKind::Interrupted),
            Step::Data(b"hi"),
            Step::Data(b"yo"),
        ]);
        let mut out = Flushes::default();
        drain(&from, &mut out).unwrap();
        assert_eq!(out.flushed, [b"hi".to_vec(), b"yo".to_vec()]);
        assert!(out.pending.is_empty());
    }

    #[test]
    fn drain_returns_a_read_error() {
        let from = Fake::new(vec![
            Step::Fail(ErrorKind::ConnectionReset),
            Step::Data(b"zz"),
        ]);
        let mut out = Vec::new();
        let e = drain(&from, &mut out).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::ConnectionReset);
        assert_eq!(out, b"");
    }

    #[test]
    fn only_a_listener_that_cannot_accept_ends_the_accept_loop() {
        // EINVAL (not listening) and ENOENT are fatal; descriptor exhaustion and aborted
        // connections are transient.
        for kind in [ErrorKind::InvalidInput, ErrorKind::NotFound] {
            assert!(!is_transient(&kind.into()), "{kind:?}");
        }
        const EMFILE: i32 = 24;
        for e in [
            io::Error::from_raw_os_error(EMFILE),
            ErrorKind::ConnectionAborted.into(),
        ] {
            assert!(is_transient(&e), "{e:?}");
        }
    }

    #[test]
    fn the_copy_buffer_is_the_fixed_16_kib_bound() {
        assert_eq!(BUF_BYTES, 16384);
    }

    #[test]
    fn diagnostics_are_rate_limited() {
        let lim = Limiter::new(1);
        let mut out = Vec::new();
        lim.note_to(&mut out, "first");
        lim.note_to(&mut out, "second");
        assert_eq!(
            String::from_utf8(out.clone()).unwrap(),
            "sally-shim: first\n"
        );
        // Once the interval has passed, the next line goes out.
        *lim.last_log.lock().unwrap() = Instant::now().checked_sub(LOG_INTERVAL);
        lim.note_to(&mut out, "third");
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "sally-shim: first\nsally-shim: third\n"
        );
    }
}
