//! The relay: fixed buffers, bounded connections, no interpretation of the bytes.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
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
/// forever. It runs from the server-to-client direction's end, or from a failed write toward a
/// server that stopped reading (`sallyd` only does that by closing), whatever the client does
/// after that write: a response stream still flowing is cut only in that second case, a linger
/// after the server stopped reading.
pub const LINGER: Duration = Duration::from_secs(30);
/// The longest linger [`Limiter::with_linger`] keeps: one day. Longer values are clamped, so a
/// deadline a linger from now always exists.
pub const MAX_LINGER: Duration = Duration::from_secs(24 * 60 * 60);
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

    /// A limiter with an explicit linger time, clamped to [`MAX_LINGER`].
    #[must_use]
    pub fn with_linger(max: usize, linger: Duration) -> Arc<Self> {
        Arc::new(Self {
            live: AtomicUsize::new(0),
            max,
            linger: linger.min(MAX_LINGER),
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
/// connection is torn down both ways so the slot comes back. A client whose send failed because
/// the server stopped reading gets the same linger from that failed write (the discard deadline
/// in [`Direction::ToServer`]), whether it then sends on, half-closes or goes silent; its bytes
/// are discarded meanwhile, and the reply is relayed (#76).
/// Those two tear the connection down at a deadline; a client's read error (it reset) ends both
/// directions at once.
///
/// TODO(#155): a client that does not read a reply larger than the buffers, and has had no send
/// fail (for example: it sends nothing, its sends block because the server stopped reading
/// without closing, or it half-closed after they went through), holds its slot: the
/// server-to-client direction stays blocked writing to it.
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
    let (down_done_tx, down_done_rx) = mpsc::channel::<()>();
    let cut = Arc::new(AtomicBool::new(false));
    let upstream = {
        let (from, to) = (Arc::clone(&tcp), Arc::clone(&uds));
        let (linger, cut) = (limiter.linger, Arc::clone(&cut));
        thread::Builder::new()
            .name("up".into())
            .stack_size(THREAD_STACK_BYTES)
            .spawn(move || {
                let toward = Direction::ToServer {
                    linger,
                    cut: &cut,
                    down_done: &down_done_rx,
                };
                copy_half(&*from, &*to, toward);
                drop(done_tx);
            })?
    };
    copy_half(&*uds, &*tcp, Direction::ToClient);
    // Wakes a discard waiting on a client that half-closed (see `discard`).
    drop(down_done_tx);
    if matches!(
        done_rx.recv_timeout(limiter.linger),
        Err(RecvTimeoutError::Timeout)
    ) {
        // Set first, so a discard woken by the shutdowns reads no further: a close that finds
        // the client's bytes unread resets it, and a client that had filled its window learns
        // of the cut at once instead of after the kernel's FIN timeout.
        // The socket first, so a copy toward the server cannot pass on what it reads meanwhile.
        cut.store(true, Ordering::SeqCst);
        uds.close(Shutdown::Both);
        tcp.close(Shutdown::Both);
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
    /// fails and it learns the client is gone. No discard: the linger in [`relay_connection`]
    /// starts only after this direction ends, so a discard here would have no bound.
    ToClient,
    /// Client to server. A failed write leaves the client's bytes read and discarded, so a
    /// client still sending is not reset before it reads the reply relayed the other way (#76),
    /// for at most `linger` from that write, or until `cut` (the linger in [`relay_connection`])
    /// is set. The client's EOF does not end that bound: the discard then waits for
    /// `down_done` (the server-to-client direction's end) until the same deadline. A client's
    /// read error (it reset) also shuts the server's read side: the client can read no reply,
    /// and the other direction then ends at once.
    ToServer {
        linger: Duration,
        cut: &'a AtomicBool,
        down_done: &'a Receiver<()>,
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
        Direction::ToServer {
            linger,
            cut,
            down_done,
        } => {
            // Cannot overflow: `Limiter::with_linger` clamps the linger to `MAX_LINGER`.
            let deadline = Instant::now() + linger;
            discard(from, to, &mut buf, deadline, cut, down_done);
        }
    }
}

/// Reads the client (`from`) into `buf` and drops the bytes until `cut` is set or `deadline`
/// passes; at the deadline it shuts both streams both ways, which also wakes the other
/// direction. At the client's EOF it waits, until the same deadline, for `down_done` to
/// disconnect (the reply relayed, or the client gone): a client that half-closed but does not
/// read would otherwise keep the other direction blocked writing to it. A read error shuts
/// `from`'s read side and the server's (`to`) read side.
fn discard(
    from: &dyn Half,
    to: &dyn Half,
    buf: &mut [u8],
    deadline: Instant,
    cut: &AtomicBool,
    down_done: &Receiver<()>,
) {
    loop {
        if cut.load(Ordering::SeqCst) {
            return;
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            cut_both(from, to);
            return;
        }
        from.read_wait(left);
        match from.read_some(buf) {
            Ok(0) => {
                let left = deadline.saturating_duration_since(Instant::now());
                if matches!(down_done.recv_timeout(left), Err(RecvTimeoutError::Timeout)) {
                    cut_both(from, to);
                }
                return;
            }
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

/// Shuts both streams both ways, as the linger in [`relay_connection`] does.
fn cut_both(from: &dyn Half, to: &dyn Half) {
    from.close(Shutdown::Both);
    to.close(Shutdown::Both);
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
#[path = "relay_tests.rs"]
mod tests;
