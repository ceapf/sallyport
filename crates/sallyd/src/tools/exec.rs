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
//! 4. Dropped at any await (session teardown): the client is killed (`kill_on_drop`), the
//!    started process is sent `SIGKILL` through its pidfd at once, and the call's session is
//!    killed off the runtime; the output readers are aborted. The container's removal ends the
//!    rest.
//!
//! Killing the `podman exec` client alone leaves the command running in the container (probed,
//! `docs/dev/PROBE_NOTES.md`), hence the pidfds. A process is named by its pid and start time,
//! both read through one `/proc/<pid>` directory fd, and a signal goes only through a pidfd
//! opened for a process seen in the container's pid namespace and re-checked after the open.

use std::os::unix::process::ExitStatusExt as _;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustix::fd::OwnedFd;
use rustix::fs::{Mode, OFlags};
use rustix::process::{Pid, PidfdFlags, Signal};
use tokio::io::{AsyncRead, AsyncReadExt as _};

use super::procs::{self, Call, Snapshot, Stat};
use super::shell::{Captured, Output, Runner, START_LIMIT, Status, TIME_LIMIT, exec_argv};
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
}

impl PodmanExec {
    /// The runner for `running`'s container, through hermetic `podman`, with [`TIME_LIMIT`].
    #[must_use]
    pub fn new(podman: Podman, running: &Running) -> Self {
        Self::with(podman, running, TIME_LIMIT)
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
            }),
        }
    }

    fn with(podman: Podman, running: &Running, time_limit: Duration) -> Self {
        Self {
            inner: Arc::new(Inner {
                podman,
                container: running.container().to_owned(),
                init_dir: running.init_dir(),
                gate: running.exec_gate(),
                time_limit,
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
        let me = &self.inner;
        let stdout = Arc::new(Mutex::new(Captured::default()));
        let stderr = Arc::new(Mutex::new(Captured::default()));
        let out = |status| Output {
            status,
            stdout: take(&stdout),
            stderr: take(&stderr),
        };
        let gate = Arc::clone(&me.gate).lock_owned().await;
        let Some(Some(before)) = blocking(me, |i| i.snapshot()).await else {
            return out(Status::Failed(
                "cannot list the container's processes".into(),
            ));
        };
        let spawned = me
            .podman
            .command()
            .args(exec_argv(&me.container, cwd, argv))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn();
        let mut child = match spawned {
            Ok(c) => c,
            Err(e) => return out(Status::Failed(format!("podman exec: {e}"))),
        };
        let readers = [
            child
                .stdout
                .take()
                .map(|r| Reader(drain(r, Arc::clone(&stdout)))),
            child
                .stderr
                .take()
                .map(|r| Reader(drain(r, Arc::clone(&stderr)))),
        ];
        let mut guard = KillOnDrop {
            pidfd: None,
            session: None,
        };
        let call = match self.find_started(&before, &mut child).await {
            Found::Started(call, fd) => {
                guard.pidfd = Some(fd);
                Some(call)
            }
            Found::Exited(call) => call,
            Found::Lost => {
                let _ = child.kill().await;
                // Whatever the dead client may still have started is new since `before`.
                let call = blocking(me, move |i| i.quick_session(&before))
                    .await
                    .flatten();
                drop(gate);
                kill(me, call).await;
                return out(Status::Killed("start-timeout"));
            }
        };
        drop(gate);
        guard.session = call.map(|c| (Arc::clone(me), c));
        let status = match tokio::time::timeout(me.time_limit, child.wait()).await {
            Ok(Ok(s)) => Status::Exited(
                s.code()
                    .or_else(|| s.signal().map(|n| 128 + n))
                    .unwrap_or(-1),
            ),
            Ok(Err(e)) => Status::Failed(format!("podman exec: {e}")),
            Err(_) => Status::Killed("timeout"),
        };
        // Also after a normal exit: what the command left running ends with the call. Its top
        // has exited then, so only its session is followed (its pid could be another's now).
        let left = match status {
            Status::Killed(_) => call,
            Status::Exited(_) | Status::Failed(_) => call.map(|c| Call { top: None, ..c }),
        };
        kill(me, left).await;
        guard.session = None;
        if status == Status::Killed("timeout")
            && tokio::time::timeout(REAP_LIMIT, child.wait())
                .await
                .is_err()
        {
            let _ = child.kill().await;
        }
        // The guard's pidfd fires here on every path (ESRCH once the process is gone is
        // harmless; a pidfd never reaches a reused pid).
        drop(guard);
        for r in readers.into_iter().flatten() {
            // A process outside the call's reach may still hold the pipe: keep what was read.
            let mut r = r;
            let _ = tokio::time::timeout(DRAIN_LIMIT, &mut r.0).await;
        }
        out(status)
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
