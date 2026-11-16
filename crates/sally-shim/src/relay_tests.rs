//! Unit tests of the relay: the copy halves, the discard, feed, drain and the accept loop.
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
/// EOF. Writes (tried and done), shutdowns and read waits are recorded.
struct Fake {
    script: Mutex<VecDeque<Step>>,
    fail_writes: Option<ErrorKind>,
    tries: Mutex<usize>,
    written: Mutex<Vec<u8>>,
    closes: Mutex<Vec<Shutdown>>,
    waits: Mutex<Vec<Duration>>,
}

impl Fake {
    fn new(script: Vec<Step>) -> Self {
        Self {
            script: Mutex::new(script.into()),
            fail_writes: None,
            tries: Mutex::default(),
            written: Mutex::default(),
            closes: Mutex::default(),
            waits: Mutex::default(),
        }
    }
    fn waits(&self) -> Vec<Duration> {
        self.waits.lock().unwrap().clone()
    }
    /// Every write fails with a broken pipe (a server that stopped reading).
    fn failing_writes() -> Self {
        Self::failing_writes_with(ErrorKind::BrokenPipe)
    }
    /// Every write fails with `kind`.
    fn failing_writes_with(kind: ErrorKind) -> Self {
        Self {
            fail_writes: Some(kind),
            ..Self::new(Vec::new())
        }
    }
    fn tries(&self) -> usize {
        *self.tries.lock().unwrap()
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
        *self.tries.lock().unwrap() += 1;
        if let Some(kind) = self.fail_writes {
            return Err(kind.into());
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
    fn write_wait(&self, _wait: Duration) -> io::Result<()> {
        Ok(())
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

/// Toward the server, with the server-to-client direction already done (its sender gone), so
/// the client's EOF ends the discard at once. The receiver is leaked, one small allocation
/// per call: a `static` one cannot exist, as `Receiver` is not `Sync`.
fn to_server(linger: Duration, cut: &AtomicBool) -> Direction<'_> {
    let down_done: &'static Receiver<()> = Box::leak(Box::new(mpsc::channel().1));
    Direction::ToServer {
        linger,
        cut,
        down_done,
    }
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
fn a_timed_out_write_toward_the_client_is_a_failed_write() {
    // #155: the client socket's write bound ends a blocked write with `WouldBlock` or
    // `TimedOut`. The copy stops as at any failed write toward the client: no retry, no further
    // read, only its own direction closed.
    for kind in [ErrorKind::WouldBlock, ErrorKind::TimedOut] {
        let (from, to) = (
            Fake::new(vec![Step::Data(b"a"), Step::Data(b"b")]),
            Fake::failing_writes_with(kind),
        );
        copy_half(&from, &to, Direction::ToClient);
        assert_eq!(to.tries(), 1, "retried a timed-out write ({kind:?})");
        assert_eq!(
            from.unread(),
            1,
            "read on after a timed-out write ({kind:?})"
        );
        assert_eq!(from.closes(), [Shutdown::Read], "{kind:?}");
        assert_eq!(to.closes(), [Shutdown::Write], "{kind:?}");
    }
}

#[test]
fn relay_connection_bounds_writes_to_the_client_by_the_limiter_s_linger() {
    // A linger other than the default, so the value is the limiter's.
    let linger = Duration::from_millis(1700);
    let dir = std::env::temp_dir().join(format!("shu{}-wired", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("u.sock");
    // The server closes at once and the client is gone, so the relay ends promptly.
    let server = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    let closing = thread::spawn(move || drop(server.accept()));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (tcp, _) = listener.accept().unwrap();
    let seen = tcp.try_clone().unwrap();
    drop(client);
    let limiter = Limiter::with_linger(1, linger);
    let slot = limiter.admit().unwrap();
    relay_connection(tcp, &sock, &limiter, &slot).unwrap();
    closing.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(seen.write_timeout().unwrap(), Some(linger));
}

#[test]
fn write_wait_bounds_each_later_write_on_a_tcp_stream() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let tcp = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let wait = Duration::from_millis(1500);
    tcp.write_wait(wait).unwrap();
    assert_eq!(tcp.write_timeout().unwrap(), Some(wait));
    // std refuses a zero timeout; a zero linger still bounds the write, by the smallest one
    // (the kernel keeps it as one clock tick).
    tcp.write_wait(Duration::ZERO).unwrap();
    let least = tcp
        .write_timeout()
        .unwrap()
        .expect("a zero linger left writes unbounded");
    assert!(
        least > Duration::ZERO && least <= Duration::from_millis(10),
        "{least:?}"
    );
}

#[test]
fn copy_half_toward_the_server_discards_the_client_to_its_end_after_a_failed_write() {
    let (from, to) = (
        Fake::new(vec![
            Step::Data(b"a"),
            Step::Data(b"b"),
            Step::Fail(ErrorKind::Interrupted),
            Step::Stall(STALL),
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
    // Each wait is what is left, not the whole linger again: the reads after the stall wait
    // at least the stall less.
    let (first, last) = (waits.first().unwrap(), waits.last().unwrap());
    assert!(*last + STALL <= *first, "{waits:?}");
}

/// The stalled read in the discard test above.
const STALL: Duration = Duration::from_millis(100);

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
    // Well above scheduling delays, so the first check still finds time left.
    let linger = Duration::from_millis(500);
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
fn a_client_eof_in_the_discard_waits_for_the_other_direction_until_the_deadline() {
    // The client half-closes after its failed send; the reply is still on its way to it
    // (the server-to-client direction's sender is held), so the bound holds.
    let linger = Duration::from_millis(300);
    let (_down_running, down_done) = mpsc::channel::<()>();
    let (from, to) = (Fake::new(vec![Step::Data(b"a")]), Fake::failing_writes());
    let started = Instant::now();
    copy_half(
        &from,
        &to,
        Direction::ToServer {
            linger,
            cut: &NOT_CUT,
            down_done: &down_done,
        },
    );
    assert!(started.elapsed() >= linger, "{:?}", started.elapsed());
    assert_eq!(from.closes(), [Shutdown::Both]);
    assert_eq!(to.closes(), [Shutdown::Write, Shutdown::Both]);
}

#[test]
fn a_client_eof_in_the_discard_ends_it_once_the_other_direction_is_done() {
    let (from, to) = (Fake::new(vec![Step::Data(b"a")]), Fake::failing_writes());
    let started = Instant::now();
    copy_half(&from, &to, to_server(LONG, &NOT_CUT));
    assert!(started.elapsed() < T_SLACK, "{:?}", started.elapsed());
    assert!(from.closes().is_empty(), "{:?}", from.closes());
    assert_eq!(to.closes(), [Shutdown::Write]);
}

#[test]
fn the_linger_is_clamped_to_a_day() {
    let tiny = Duration::from_nanos(1);
    assert_eq!(MAX_LINGER, Duration::from_secs(86_400));
    assert_eq!(Limiter::with_linger(1, MAX_LINGER).linger, MAX_LINGER);
    assert_eq!(
        Limiter::with_linger(1, MAX_LINGER + tiny).linger,
        MAX_LINGER
    );
    assert_eq!(Limiter::with_linger(1, Duration::MAX).linger, MAX_LINGER);
    assert_eq!(Limiter::with_linger(1, LINGER).linger, LINGER);
    assert_eq!(Limiter::new(1).linger, LINGER);
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
