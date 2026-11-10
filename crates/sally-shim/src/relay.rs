//! The relay: fixed buffers, bounded connections, no interpretation of the bytes.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::args::ListenSpec;

/// Copy buffer per direction. Together with the kernel socket buffers this is all the data a
/// connection can hold: a stalled peer stops the other side rather than growing memory.
pub const BUF_BYTES: usize = 16 * 1024;
/// Default cap on live connections across all listeners. Each costs two threads, and the sandbox
/// that runs the shim has a small `pids` limit, so the default stays well below it.
pub const MAX_CONNECTIONS: usize = 32;
/// Default time a connection may linger, with its server side finished, waiting for the client
/// to close. Pooled HTTP clients leave such sockets open; without a bound each would hold a slot
/// forever. Applies only after the server's EOF, so a long response stream is never cut.
pub const LINGER: Duration = Duration::from_secs(30);
/// Stack for a copy thread: it only holds [`BUF_BYTES`] and a few locals.
const THREAD_STACK_BYTES: usize = 128 * 1024;
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
        let Ok(mut last) = self.last_log.lock() else {
            return;
        };
        if last.is_none_or(|t| t.elapsed() >= LOG_INTERVAL) {
            let _ = writeln!(io::stderr(), "sally-shim: {msg}");
            *last = Some(Instant::now());
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

/// Binds the TCP listener for `spec`. Refuses anything but a loopback address, again (the
/// argument parser already does): inside the sandbox there is no network, but the shim must
/// never be the thing that listens beyond localhost.
///
/// # Errors
/// `InvalidInput` for a non-loopback address; otherwise the bind error.
pub fn bind(spec: &ListenSpec) -> io::Result<TcpListener> {
    if !spec.addr.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "listen address must be loopback",
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
        }
    };
}
half!(TcpStream);
half!(UnixStream);

/// One TCP connection: connect to the Unix socket, then copy both ways until done.
///
/// When the server side finishes (EOF), the client gets [`Limiter::linger`] to close its end;
/// after that the connection is torn down so the slot comes back.
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
    let upstream = {
        let (from, to) = (Arc::clone(&tcp), Arc::clone(&uds));
        thread::Builder::new()
            .name("up".into())
            .stack_size(THREAD_STACK_BYTES)
            .spawn(move || {
                copy_half(&*from, &*to);
                drop(done_tx);
            })?
    };
    copy_half(&*uds, &*tcp);
    if matches!(
        done_rx.recv_timeout(limiter.linger),
        Err(RecvTimeoutError::Timeout)
    ) {
        tcp.close(Shutdown::Both);
        uds.close(Shutdown::Both);
    }
    upstream
        .join()
        .map_err(|_| io::Error::other("copy thread panicked"))
}

/// Copies `from` → `to` with a fixed buffer. On EOF it half-closes `to` (so the peer sees the
/// end of the request but can still answer); on an error it closes both streams, which wakes the
/// other direction.
fn copy_half(from: &dyn Half, to: &dyn Half) {
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
            Err(_) => break,
        }
    }
    from.close(Shutdown::Both);
    to.close(Shutdown::Both);
}

/// Relays `input` → the Unix socket and the socket → `output` (flushing every chunk), until the
/// socket closes. When `input` ends, the socket's write side is closed so the server sees EOF.
///
/// # Errors
/// Failure to connect to `socket`, or a write error on `output`.
pub fn stdio<R: Read + Send + 'static, W: Write>(
    socket: &Path,
    mut input: R,
    mut output: W,
) -> io::Result<()> {
    let uds = Arc::new(UnixStream::connect(socket)?);
    let uds_w = Arc::clone(&uds);
    // Detached on purpose: a blocked read on stdin must not keep the process alive once the
    // server has closed.
    thread::Builder::new()
        .name("stdin".into())
        .stack_size(THREAD_STACK_BYTES)
        .spawn(move || {
            let mut buf = [0u8; BUF_BYTES];
            loop {
                match input.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => match buf.get(..n) {
                        Some(chunk) if uds_w.write_all_to(chunk).is_ok() => {}
                        _ => return,
                    },
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
            uds_w.close(Shutdown::Write);
        })?;
    let mut buf = [0u8; BUF_BYTES];
    loop {
        match uds.read_some(&mut buf) {
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
