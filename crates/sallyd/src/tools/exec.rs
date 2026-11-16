//! The `shell` tool's runner: `podman exec` in the workspace container (maintainer's Task 11
//! decision 3; #24, #62; architect ruling Q32). Container-only: its tests are the `rt_` tests.
//!
//! 1. Take the session's exec gate (the disk watchdog holds it while the container is frozen),
//!    snapshot the container's processes, start `podman exec` (null stdin, piped and drained
//!    output, killed on drop).
//! 2. Find the started process ([`procs::started`]): a candidate still in its parent's session
//!    is crun's intermediate before its `setsid` and is passed over; one that is the same process
//!    a poll later is taken, with a pidfd; release the gate. A running exec is in the container's
//!    cgroup and freezes with it, so the watchdog can measure while it runs. A command that ends
//!    before it is seen is named by the one new session it left ([`procs::new_session`], gate
//!    still held). Not found within [`START_LIMIT`] while the client still runs: kill the client
//!    and what it may have started, `killed: start-timeout`.
//! 3. Wait for the client up to the time limit; past it, kill the call ([`procs::kill_set`],
//!    repeated until a snapshot finds none) and report `killed: timeout`. After a normal exit
//!    what the command left behind in its session is killed too: one reply per call.
//!    The session's stop (architect Q59 (c)) is watched at the gate, during the search and
//!    during the wait: it takes the same awaited kill as a timeout, `killed: session-stop`,
//!    finished before the call's `tool.result`.
//! 4. Dropped at any await (session teardown): the client is killed (`kill_on_drop`), the
//!    started process is sent `SIGKILL` through its pidfd at once, and the call's session is
//!    killed off the runtime; the output readers are aborted. The container's removal ends the
//!    rest.
//!
//! The same runner serves an attached command (`sessions.attach`; architect Q101, Q145): `-i`
//! with a stdin pipe that takes each `sessions.input` in order, no time limit of its own, and
//! output escaped per stream (`StreamEscaper`) into a bounded queue, a full queue pausing the
//! reads. The connection's end is watched with the session's stop at the gate, during the
//! search and during the wait, and takes the same awaited kill (`killed: disconnect`; a stop
//! goes first when both hold). A kill stops the reading at once, so a client that does not
//! read never delays it; after an exit the pipes are read to their end or to [`DRAIN_LIMIT`] of
//! idleness.
//!
//! Killing the `podman exec` client alone leaves the command running in the container (probed,
//! `docs/dev/PROBE_NOTES.md`), hence the pidfds. A process is named by its pid and start time,
//! both read through one `/proc/<pid>` directory fd, and a signal goes only through a pidfd
//! opened for a process seen in the container's pid namespace and re-checked after the open.

use std::os::unix::process::ExitStatusExt as _;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustix::fd::OwnedFd;
use rustix::fs::{Mode, OFlags};
use rustix::process::{Pid, PidfdFlags, Signal};
use sally_core::text::StreamEscaper;
use sally_proto::Stream;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::{mpsc, watch};

use super::ops::{DISCONNECT, Ops, SESSION_STOP};
use super::procs::{self, Call, Snapshot, Stat};
use super::shell::{
    AttachIo, Captured, Chunk, Input, Output, Ran, Runner, START_LIMIT, Status, Stdin, Streamer,
    TIME_LIMIT, exec_argv, read_len,
};
use crate::sandbox::{Podman, Running};

/// Pause between snapshots while looking for the started process.
const POLL: Duration = Duration::from_millis(10);
/// Scan-and-kill rounds before a kill gives up (teardown ends whatever is left), and the pause
/// between them, so killed processes can leave `/proc`.
const KILL_ROUNDS: usize = 20;
const KILL_PAUSE: Duration = Duration::from_millis(2);
/// How long the client gets to exit once its command was killed.
const REAP_LIMIT: Duration = Duration::from_secs(10);
/// How long output is still read after the client exited (a background process can hold the
/// pipe open).
const DRAIN_LIMIT: Duration = Duration::from_millis(500);

/// `podman exec` into one session's workspace container.
#[derive(Debug, Clone)]
pub struct PodmanExec {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    podman: Podman,
    container: String,
    init_dir: Arc<OwnedFd>,
    gate: Arc<tokio::sync::Mutex<()>>,
    time_limit: Duration,
    /// The session's operations: their stop kills a running call (`killed: session-stop`).
    ops: Ops,
}

impl PodmanExec {
    /// The runner for `running`'s container, through hermetic `podman`, with [`TIME_LIMIT`]; the
    /// stop of `ops` kills what it runs (architect Q59 (c)).
    #[must_use]
    pub fn new(podman: Podman, running: &Running, ops: Ops) -> Self {
        Self::with(podman, running, TIME_LIMIT, ops)
    }

    /// The same runner with another time limit per command.
    #[must_use]
    pub fn time_limit(self, limit: Duration) -> Self {
        let i = &self.inner;
        Self {
            inner: Arc::new(Inner {
                podman: i.podman.clone(),
                container: i.container.clone(),
                init_dir: Arc::clone(&i.init_dir),
                gate: Arc::clone(&i.gate),
                time_limit: limit,
                ops: i.ops.clone(),
            }),
        }
    }

    fn with(podman: Podman, running: &Running, time_limit: Duration, ops: Ops) -> Self {
        Self {
            inner: Arc::new(Inner {
                podman,
                container: running.container().to_owned(),
                init_dir: running.init_dir(),
                gate: running.exec_gate(),
                time_limit,
                ops,
            }),
        }
    }
}

impl Inner {
    /// The container's pid namespace link (`pid:[…]`), through the init's directory fd.
    fn ns(&self) -> Option<std::ffi::CString> {
        rustix::fs::readlinkat(&*self.init_dir, "ns/pid", Vec::new()).ok()
    }

    /// The container's processes now (blocking).
    fn snapshot(&self) -> Option<Snapshot> {
        let ns = self.ns()?;
        let mut procs = Vec::new();
        for e in std::fs::read_dir("/proc").ok()?.flatten() {
            let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) else {
                continue;
            };
            if let Some(s) = stat_in(pid, Some(&ns)) {
                procs.push(s);
            }
        }
        Some(Snapshot { procs })
    }

    fn init(&self) -> Option<Stat> {
        read_stat(&self.init_dir)
    }

    /// A pidfd for `p`, if it still is `p` in the container after the open.
    fn pidfd(&self, p: Stat) -> Option<OwnedFd> {
        let fd = rustix::process::pidfd_open(Pid::from_raw(p.pid)?, PidfdFlags::empty()).ok()?;
        self.still(p).then_some(fd)
    }

    /// Whether `p` is still that process in the container.
    fn still(&self, p: Stat) -> bool {
        self.ns().and_then(|ns| stat_in(p.pid, Some(&ns))) == Some(p)
    }

    /// Whether `p` is crun's intermediate before its `setsid`: still in its parent's session.
    fn before_setsid(p: Stat) -> bool {
        stat_in(p.ppid, None).is_some_and(|parent| parent.session == p.session)
    }

    /// Kills `call` until a snapshot finds none of it (bounded rounds).
    fn kill_call(&self, call: Call) {
        let Some(init) = self.init() else {
            return;
        };
        for _ in 0..KILL_ROUNDS {
            let Some(now) = self.snapshot() else {
                return;
            };
            let set = procs::kill_set(&now, call, init);
            if set.is_empty() {
                return;
            }
            for pid in set {
                if let Some(fd) = now.get(pid).and_then(|p| self.pidfd(p)) {
                    let _ = rustix::process::pidfd_send_signal(&fd, Signal::KILL);
                }
            }
            std::thread::sleep(KILL_PAUSE);
        }
    }

    /// The session of a call never seen, from what it left since `before` (gate held).
    fn quick_session(&self, before: &Snapshot) -> Option<Call> {
        let session = procs::new_session(before, &self.snapshot()?, self.init()?)?;
        Some(Call { top: None, session })
    }
}

/// `/proc/<pid>/stat`, and its pid namespace link checked against `ns` when given, both read
/// through one `/proc/<pid>` directory fd.
fn stat_in(pid: i32, ns: Option<&std::ffi::CStr>) -> Option<Stat> {
    let dir = sally_core::fd::open(
        format!("/proc/{pid}").as_str(),
        OFlags::PATH | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .ok()?;
    if let Some(ns) = ns {
        let link = rustix::fs::readlinkat(&dir, "ns/pid", Vec::new()).ok()?;
        if link.as_c_str() != ns {
            return None;
        }
    }
    read_stat(&dir).filter(|s| s.pid == pid)
}

/// The `stat` file in a `/proc/<pid>` directory, bounded.
fn read_stat(dir: &OwnedFd) -> Option<Stat> {
    let fd = sally_core::fd::openat(dir, "stat", OFlags::RDONLY, Mode::empty()).ok()?;
    let mut text = Vec::new();
    let cap = u64::try_from(procs::MAX_STAT)
        .unwrap_or(0)
        .saturating_add(1);
    std::io::Read::read_to_end(
        &mut std::io::Read::take(std::fs::File::from(fd), cap),
        &mut text,
    )
    .ok()?;
    procs::parse_stat(&text)
}

/// What a dropped call kills: the started process at once through its pidfd, and the call's
/// session off the runtime.
struct KillOnDrop {
    pidfd: Option<OwnedFd>,
    session: Option<(Arc<Inner>, Call)>,
}

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if let Some(fd) = self.pidfd.take() {
            let _ = rustix::process::pidfd_send_signal(&fd, Signal::KILL);
        }
        if let (Some((inner, call)), Ok(rt)) =
            (self.session.take(), tokio::runtime::Handle::try_current())
        {
            drop(rt.spawn_blocking(move || inner.kill_call(call)));
        }
    }
}

/// Aborts an output reader when dropped.
struct Reader(tokio::task::JoinHandle<()>);

impl Drop for Reader {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl Runner for PodmanExec {
    async fn run(&self, argv: &[String], cwd: &str) -> Output {
        let stdout = Arc::new(Mutex::new(Captured::default()));
        let stderr = Arc::new(Mutex::new(Captured::default()));
        let io = Io::Capture {
            stdout: Arc::clone(&stdout),
            stderr: Arc::clone(&stderr),
        };
        let (status, _) = self.run_io(argv, cwd, io).await;
        Output {
            status,
            stdout: take(&stdout),
            stderr: take(&stderr),
        }
    }
}

impl Streamer for PodmanExec {
    async fn attach(&self, argv: &[String], cwd: &str, io: AttachIo) -> Ran {
        let (status, n) = self.run_io(argv, cwd, Io::Attach(io)).await;
        Ran {
            status,
            stdin: n.stdin.load(Ordering::Relaxed),
            stdout: n.stdout.load(Ordering::Relaxed),
            stderr: n.stderr.load(Ordering::Relaxed),
        }
    }
}

/// What a run reads and writes: the shell tool's capture, or an attached command's ends.
enum Io {
    Capture {
        stdout: Arc<Mutex<Captured>>,
        stderr: Arc<Mutex<Captured>>,
    },
    Attach(AttachIo),
}

/// Bytes an attached command moved, counted as they go.
#[derive(Default)]
struct Counts {
    stdin: AtomicU64,
    stdout: AtomicU64,
    stderr: AtomicU64,
}

/// The pipe tasks of one run.
struct Pipes {
    readers: [Option<Reader>; 2],
    writer: Option<Reader>,
    /// Attach only: set once the client exited (the drain's idle bound starts) and once reading
    /// must stop (a stop or a disconnect).
    exited: Option<watch::Sender<bool>>,
    halt: Option<watch::Sender<bool>>,
}

impl PodmanExec {
    /// The one runner of the shell tool and of an attached command (architect Q101, Q145).
    async fn run_io(&self, argv: &[String], cwd: &str, io: Io) -> (Status, Arc<Counts>) {
        let me = &self.inner;
        let counts = Arc::new(Counts::default());
        let (stdin, limit, disconnect) = match &io {
            Io::Capture { .. } => (Stdin::Null, Some(me.time_limit), None),
            Io::Attach(a) => (Stdin::Piped, None, Some(a.disconnect.clone())),
        };
        let out = |status| (status, Arc::clone(&counts));
        let gate = tokio::select! {
            biased;
            // Nothing started yet: nothing to kill.
            why = ended(&me.ops, disconnect.clone()) => return out(Status::Killed(why)),
            g = Arc::clone(&me.gate).lock_owned() => g,
        };
        // Closed (the stop has begun): nothing new starts, as for a write.
        if me.ops.is_closed() {
            return out(Status::Killed(SESSION_STOP));
        }
        let Some(Some(before)) = blocking(me, |i| i.snapshot()).await else {
            return out(Status::Failed(
                "cannot list the container's processes".into(),
            ));
        };
        let spawned = me
            .podman
            .command()
            .args(exec_argv(&me.container, cwd, argv, stdin))
            .stdin(match stdin {
                Stdin::Null => Stdio::null(),
                Stdin::Piped => Stdio::piped(),
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn();
        let mut child = match spawned {
            Ok(c) => c,
            Err(e) => return out(Status::Failed(format!("podman exec: {e}"))),
        };
        let pipes = pipes(&mut child, io, &counts);
        let mut guard = KillOnDrop {
            pidfd: None,
            session: None,
        };
        let found = tokio::select! {
            biased;
            why = ended(&me.ops, disconnect.clone()) => Err(Some(why)),
            f = self.find_started(&before, &mut child) => match f {
                Found::Lost => Err(None),
                f => Ok(f),
            },
        };
        let call = match found {
            Ok(Found::Started(call, fd)) => {
                guard.pidfd = Some(fd);
                Some(call)
            }
            Ok(Found::Exited(call)) => call,
            lost @ (Ok(Found::Lost) | Err(_)) => {
                let _ = child.kill().await;
                // Whatever the dead client may still have started is new since `before`.
                let call = blocking(me, move |i| i.quick_session(&before))
                    .await
                    .flatten();
                drop(gate);
                kill(me, call).await;
                let why = lost.err().flatten().unwrap_or("start-timeout");
                pipes.halt();
                return out(Status::Killed(why));
            }
        };
        drop(gate);
        guard.session = call.map(|c| (Arc::clone(me), c));
        let status = tokio::select! {
            biased;
            // The same awaited kill as a timeout, finished before `tool.result` (Q59 (c)); a
            // stop goes before a disconnect, both before the limit (architect Q145).
            why = ended(&me.ops, disconnect.clone()) => Status::Killed(why),
            r = within(limit, child.wait()) => match r {
                Ok(Ok(s)) => Status::Exited(
                    s.code()
                        .or_else(|| s.signal().map(|n| 128 + n))
                        .unwrap_or(-1),
                ),
                Ok(Err(e)) => Status::Failed(format!("podman exec: {e}")),
                Err(_) => Status::Killed("timeout"),
            },
        };
        if matches!(status, Status::Killed(_)) {
            // A blocked output queue never delays the kill; queued chunks may still go.
            pipes.halt();
        }
        // Also after a normal exit: what the command left running ends with the call. Its top
        // has exited then, so only its session is followed (its pid could be another's now).
        let left = match status {
            Status::Killed(_) => call,
            Status::Exited(_) | Status::Failed(_) => call.map(|c| Call { top: None, ..c }),
        };
        kill(me, left).await;
        guard.session = None;
        if matches!(status, Status::Killed(_))
            && tokio::time::timeout(REAP_LIMIT, child.wait())
                .await
                .is_err()
        {
            let _ = child.kill().await;
        }
        // The guard's pidfd fires here on every path (ESRCH once the process is gone is
        // harmless; a pidfd never reaches a reused pid).
        drop(guard);
        pipes.drain(&me.ops, disconnect).await;
        out(status)
    }
}

/// Resolves with why the run must end: its session stopped, or (attach only) its connection
/// is gone. A stop wins when both hold. A disconnect watch whose sender is gone is a
/// disconnect: the attach's guard fires on drop.
async fn ended(ops: &Ops, disconnect: Option<watch::Receiver<bool>>) -> &'static str {
    let gone = async move {
        match disconnect {
            Some(mut d) => {
                let _ = d.wait_for(|gone| *gone).await;
            }
            None => std::future::pending().await,
        }
    };
    tokio::select! {
        biased;
        () = ops.stopped() => SESSION_STOP,
        () = gone => DISCONNECT,
    }
}

/// `f` within `limit`; no limit: `f` to its end.
async fn within<F: Future>(
    limit: Option<Duration>,
    f: F,
) -> Result<F::Output, tokio::time::error::Elapsed> {
    match limit {
        Some(l) => tokio::time::timeout(l, f).await,
        None => Ok(f.await),
    }
}

/// Starts the tasks on the child's pipes for `io`.
fn pipes(child: &mut tokio::process::Child, io: Io, counts: &Arc<Counts>) -> Pipes {
    let (out, err) = (child.stdout.take(), child.stderr.take());
    match io {
        Io::Capture { stdout, stderr } => Pipes {
            readers: [
                out.map(|r| Reader(drain(r, stdout))),
                err.map(|r| Reader(drain(r, stderr))),
            ],
            writer: None,
            exited: None,
            halt: None,
        },
        Io::Attach(a) => {
            let (exited, halt) = (watch::Sender::new(false), watch::Sender::new(false));
            let marks = || (halt.subscribe(), exited.subscribe());
            let readers = [
                out.map(|r| {
                    let tx = a.output.clone();
                    let c = Arc::clone(counts);
                    Reader(tokio::spawn(stream(r, Stream::Stdout, tx, marks(), c)))
                }),
                err.map(|r| {
                    let tx = a.output.clone();
                    let c = Arc::clone(counts);
                    Reader(tokio::spawn(stream(r, Stream::Stderr, tx, marks(), c)))
                }),
            ];
            let writer = child
                .stdin
                .take()
                .map(|w| Reader(tokio::spawn(write_input(w, a.input, Arc::clone(counts)))));
            Pipes {
                readers,
                writer,
                exited: Some(exited),
                halt: Some(halt),
            }
        }
    }
}

impl Pipes {
    /// Stops the reading of the pipes (attach).
    fn halt(&self) {
        if let Some(h) = &self.halt {
            h.send_replace(true);
        }
    }

    /// Ends the pipe tasks once the client exited. The shell tool's readers get [`DRAIN_LIMIT`]
    /// in all; an attached command's end at the end of their pipes, at [`DRAIN_LIMIT`] of a
    /// pipe's idleness, or at a stop or disconnect; time waiting for room in the output queue
    /// does not count (architect Q145). The input writer ends with the run: an input it has
    /// not written is dropped unanswered, which its connection tells as `input-closed`.
    async fn drain(self, ops: &Ops, disconnect: Option<watch::Receiver<bool>>) {
        let Self {
            readers,
            writer,
            exited,
            halt,
        } = self;
        drop(writer);
        let Some(exited) = exited else {
            for r in readers.into_iter().flatten() {
                // A process outside the call's reach may still hold the pipe: keep what was read.
                let mut r = r;
                let _ = tokio::time::timeout(DRAIN_LIMIT, &mut r.0).await;
            }
            return;
        };
        exited.send_replace(true);
        let all = async {
            for r in readers.into_iter().flatten() {
                let mut r = r;
                let _ = (&mut r.0).await;
            }
        };
        tokio::pin!(all);
        tokio::select! {
            biased;
            () = &mut all => return,
            _ = ended(ops, disconnect) => {}
        }
        if let Some(h) = &halt {
            h.send_replace(true);
        }
        all.await;
    }
}

/// Reads one pipe of an attached command to its end: each read at most what keeps the chunk
/// with its carry within [`sally_proto::MAX_OUTPUT_CHUNK`], escaped by this stream's own
/// escaper (the RT-CLI-01 control), and queued, waiting for room. Ends at the pipe's end, at [`DRAIN_LIMIT`] of
/// idleness once the client exited, or when halted.
async fn stream(
    mut r: impl AsyncRead + Unpin + Send + 'static,
    which: Stream,
    tx: mpsc::Sender<Chunk>,
    (mut halt, mut exited): (watch::Receiver<bool>, watch::Receiver<bool>),
    counts: Arc<Counts>,
) {
    let mut esc = StreamEscaper::default();
    let mut buf = vec![0u8; sally_proto::MAX_OUTPUT_CHUNK];
    let counter = match which {
        Stream::Stdout => &counts.stdout,
        Stream::Stderr => &counts.stderr,
    };
    loop {
        let want = read_len(esc.held());
        let Some(space) = buf.get_mut(..want) else {
            return;
        };
        let idle = async {
            let _ = exited.wait_for(|e| *e).await;
            tokio::time::sleep(DRAIN_LIMIT).await;
        };
        let n = tokio::select! {
            biased;
            () = until(&mut halt) => return,
            r = r.read(space) => match r {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            },
            () = idle => break,
        };
        counter.fetch_add(u64::try_from(n).unwrap_or(u64::MAX), Ordering::Relaxed);
        let text = esc.push(buf.get(..n).unwrap_or_default());
        if !send(&tx, which, text, &mut halt).await {
            return;
        }
    }
    let rest = esc.finish();
    let _ = send(&tx, which, rest, &mut halt).await;
}

/// Queues `text` (nothing when empty), waiting for room; `false` once halted or the queue's
/// reader is gone.
async fn send(
    tx: &mpsc::Sender<Chunk>,
    stream: Stream,
    text: String,
    halt: &mut watch::Receiver<bool>,
) -> bool {
    if text.is_empty() {
        return true;
    }
    tokio::select! {
        biased;
        () = until(halt) => false,
        r = tx.send(Chunk { stream, text }) => r.is_ok(),
    }
}

/// Resolves once `w` is `true` or its sender is gone.
async fn until(w: &mut watch::Receiver<bool>) {
    let _ = w.wait_for(|v| *v).await;
}

/// Writes each input to the command's standard input in order and tells whether it was
/// written; closes the pipe after an input with `eof`. Once a write failed or the pipe was
/// closed, every later input is answered `false`.
async fn write_input(
    w: tokio::process::ChildStdin,
    mut rx: mpsc::Receiver<Input>,
    counts: Arc<Counts>,
) {
    let mut w = Some(w);
    while let Some(input) = rx.recv().await {
        let ok = match w.as_mut() {
            Some(pipe) => pipe.write_all(&input.data).await.is_ok() && pipe.flush().await.is_ok(),
            None => false,
        };
        if ok {
            let n = u64::try_from(input.data.len()).unwrap_or(u64::MAX);
            counts.stdin.fetch_add(n, Ordering::Relaxed);
        }
        if !ok || input.eof {
            w = None;
        }
        let _ = input.done.send(ok);
    }
}

/// What the search for the started process found.
enum Found {
    /// The started process, with a pidfd.
    Started(Call, OwnedFd),
    /// The client ended first; the call's session if it could be told.
    Exited(Option<Call>),
    /// Nothing found within [`START_LIMIT`].
    Lost,
}

impl PodmanExec {
    async fn find_started(&self, before: &Snapshot, child: &mut tokio::process::Child) -> Found {
        let me = &self.inner;
        let deadline = tokio::time::Instant::now() + START_LIMIT;
        loop {
            let then = before.clone();
            let hit = blocking(me, move |i| {
                let now = i.snapshot()?;
                procs::started(&then, &now)
                    .into_iter()
                    .find(|c| !Inner::before_setsid(*c))
            })
            .await
            .flatten();
            if let Some(top) = hit {
                // A process can still be on its way out: take it if it is the same process a
                // poll later, and open its pidfd then.
                tokio::time::sleep(POLL).await;
                if let Some(Some(fd)) = blocking(me, move |i| i.pidfd(top)).await {
                    let call = Call {
                        top: Some(top.pid),
                        session: top.session,
                    };
                    return Found::Started(call, fd);
                }
            }
            if matches!(child.try_wait(), Ok(Some(_))) {
                // Too quick to be seen: its session, from what it left (gate held).
                let then = before.clone();
                let call = blocking(me, move |i| i.quick_session(&then))
                    .await
                    .flatten();
                return Found::Exited(call);
            }
            if tokio::time::Instant::now() >= deadline {
                return Found::Lost;
            }
            tokio::time::sleep(POLL).await;
        }
    }
}

async fn blocking<T: Send + 'static>(
    inner: &Arc<Inner>,
    f: impl FnOnce(&Inner) -> T + Send + 'static,
) -> Option<T> {
    let i = Arc::clone(inner);
    tokio::task::spawn_blocking(move || f(&i)).await.ok()
}

/// [`Inner::kill_call`] off the runtime, for a call whose session is known.
async fn kill(inner: &Arc<Inner>, call: Option<Call>) {
    if let Some(call) = call {
        let _ = blocking(inner, move |i| i.kill_call(call)).await;
    }
}

fn take(c: &Arc<Mutex<Captured>>) -> Captured {
    std::mem::take(&mut *c.lock().unwrap_or_else(std::sync::PoisonError::into_inner))
}

/// Reads `r` to its end into `into` (capped there).
fn drain(
    mut r: impl AsyncRead + Unpin + Send + 'static,
    into: Arc<Mutex<Captured>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        loop {
            match r.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => into
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(buf.get(..n).unwrap_or_default()),
            }
        }
    })
}
