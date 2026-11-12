//! The `shell` tool's runner: `podman exec` in the workspace container (maintainer's Task 11
//! decision 3; #24, #62; architect ruling Q32). Container-only: its tests are the `rt_` tests.
//!
//! 1. Take the session's exec gate (the disk watchdog holds it while the container is frozen),
//!    snapshot the container's processes, start `podman exec` (null stdin, piped and drained
//!    output, killed on drop).
//! 2. Find the started process ([`procs::started`]), open a pidfd for it and confirm through a
//!    second snapshot that it is still that process; release the gate. A running exec is in the
//!    container's cgroup and freezes with it, so the watchdog can measure while it runs. Not found
//!    within [`START_LIMIT`] while the client still runs: kill the client, `killed:
//!    start-timeout`.
//! 3. Wait for the client up to [`TIME_LIMIT`]; past it, kill the call ([`procs::kill_set`],
//!    repeated until a snapshot finds none) and report `killed: timeout`. After a normal exit
//!    what the command left behind in its session is killed too: one reply per call.
//! 4. Dropped at any await (session teardown): the client is killed (`kill_on_drop`) and the
//!    started process is sent `SIGKILL` through its pidfd; the container's removal ends the rest.
//!
//! Killing the `podman exec` client alone leaves the command running in the container (probed,
//! `docs/dev/PROBE_NOTES.md`), hence the pidfds. Signals go only through a pidfd opened for a
//! pid seen in the container's pid namespace, re-checked after the open, so a reused pid is never
//! signalled.

use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustix::fd::OwnedFd;
use rustix::process::{Pid, PidfdFlags, Signal};
use tokio::io::{AsyncRead, AsyncReadExt as _};

use super::procs::{self, Call, Snapshot, Stat};
use super::shell::{Captured, Output, Runner, START_LIMIT, Status, TIME_LIMIT, exec_argv};
use crate::sandbox::{Podman, Running};

/// Pause between snapshots while looking for the started process.
const POLL: Duration = Duration::from_millis(10);
/// Scan-and-kill rounds before a kill gives up (teardown ends whatever is left).
const KILL_ROUNDS: usize = 20;
/// How long the client gets to exit once its command was killed.
const REAP_LIMIT: Duration = Duration::from_secs(10);
/// How long output is still read after the client exited (a background process can hold the
/// pipe open).
const DRAIN_LIMIT: Duration = Duration::from_millis(500);

/// `podman exec` into one session's workspace container.
#[derive(Debug, Clone)]
pub struct PodmanExec {
    podman: Podman,
    container: String,
    init_pid: u32,
    init_dir: Arc<OwnedFd>,
    gate: Arc<tokio::sync::Mutex<()>>,
    time_limit: Duration,
}

impl PodmanExec {
    /// The runner for `running`'s container, through hermetic `podman`, with [`TIME_LIMIT`].
    #[must_use]
    pub fn new(podman: Podman, running: &Running) -> Self {
        Self {
            podman,
            container: running.container().to_owned(),
            init_pid: running.init_pid(),
            init_dir: running.init_dir(),
            gate: running.exec_gate(),
            time_limit: TIME_LIMIT,
        }
    }

    /// The same runner with another time limit per command.
    #[must_use]
    pub fn time_limit(self, limit: Duration) -> Self {
        Self {
            time_limit: limit,
            ..self
        }
    }

    /// The container's processes now (blocking).
    fn snapshot(&self) -> Option<Snapshot> {
        let ns = rustix::fs::readlinkat(&*self.init_dir, "ns/pid", Vec::new()).ok()?;
        let mut procs = Vec::new();
        for e in std::fs::read_dir("/proc").ok()?.flatten() {
            let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) else {
                continue;
            };
            if let Some(s) = stat_in(pid, &ns) {
                procs.push(s);
            }
        }
        Some(Snapshot { procs })
    }

    fn init(&self) -> Option<Stat> {
        let text = std::fs::read(format!("/proc/{}/stat", self.init_pid)).ok()?;
        procs::parse_stat(&text)
    }

    /// A pidfd for `p`, if it still is `p` in the container after the open.
    fn pidfd(&self, p: Stat) -> Option<OwnedFd> {
        let fd = rustix::process::pidfd_open(Pid::from_raw(p.pid)?, PidfdFlags::empty()).ok()?;
        let ns = rustix::fs::readlinkat(&*self.init_dir, "ns/pid", Vec::new()).ok()?;
        (stat_in(p.pid, &ns)? == p).then_some(fd)
    }

    /// Whether `p` is still that process in the container.
    fn still(&self, p: Stat) -> bool {
        rustix::fs::readlinkat(&*self.init_dir, "ns/pid", Vec::new())
            .ok()
            .and_then(|ns| stat_in(p.pid, &ns))
            == Some(p)
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
        }
    }
}

/// `/proc/<pid>/stat` of a process in the namespace whose link text is `ns`.
fn stat_in(pid: i32, ns: &std::ffi::CStr) -> Option<Stat> {
    let link =
        rustix::fs::readlinkat(rustix::fs::CWD, format!("/proc/{pid}/ns/pid"), Vec::new()).ok()?;
    if link.as_c_str() != ns {
        return None;
    }
    let mut text = Vec::new();
    let f = std::fs::File::open(format!("/proc/{pid}/stat")).ok()?;
    std::io::Read::read_to_end(
        &mut std::io::Read::take(f, u64::try_from(procs::MAX_STAT).unwrap_or(0) + 1),
        &mut text,
    )
    .ok()?;
    procs::parse_stat(&text).filter(|s| s.pid == pid)
}

/// Sends `SIGKILL` to the started process when the call is dropped before it ended.
struct KillOnDrop(Option<OwnedFd>);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if let Some(fd) = self.0.take() {
            let _ = rustix::process::pidfd_send_signal(&fd, Signal::KILL);
        }
    }
}

async fn blocking<T: Send + 'static>(this: &PodmanExec, f: fn(&PodmanExec) -> T) -> Option<T> {
    let me = this.clone();
    tokio::task::spawn_blocking(move || f(&me)).await.ok()
}

impl Runner for PodmanExec {
    async fn run(&self, argv: &[String], cwd: &str) -> Output {
        let stdout = Arc::new(Mutex::new(Captured::default()));
        let stderr = Arc::new(Mutex::new(Captured::default()));
        let out = |status| Output {
            status,
            stdout: take(&stdout),
            stderr: take(&stderr),
        };
        let gate = Arc::clone(&self.gate).lock_owned().await;
        let Some(Some(before)) = blocking(self, PodmanExec::snapshot).await else {
            return out(Status::Failed(
                "cannot list the container's processes".into(),
            ));
        };
        let spawned = self
            .podman
            .command()
            .args(exec_argv(&self.container, cwd, argv))
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
            child.stdout.take().map(|r| drain(r, Arc::clone(&stdout))),
            child.stderr.take().map(|r| drain(r, Arc::clone(&stderr))),
        ];
        let mut guard = KillOnDrop(None);
        let found = self.find_started(&before, &mut child).await;
        let call = match found {
            Found::Started(call, fd) => {
                guard.0 = Some(fd);
                Some(call)
            }
            Found::Exited(call) => call,
            Found::Lost(call) => {
                let _ = child.kill().await;
                drop(gate);
                self.kill_in_background(call).await;
                return out(Status::Killed("start-timeout"));
            }
        };
        drop(gate);
        let status = match tokio::time::timeout(self.time_limit, child.wait()).await {
            Ok(Ok(s)) => Status::Exited(s.code().unwrap_or(-1)),
            Ok(Err(e)) => Status::Failed(format!("podman exec: {e}")),
            Err(_) => Status::Killed("timeout"),
        };
        // Also after a normal exit: what the command left running ends with the call.
        self.kill_in_background(call).await;
        if status == Status::Killed("timeout")
            && tokio::time::timeout(REAP_LIMIT, child.wait())
                .await
                .is_err()
        {
            let _ = child.kill().await;
        }
        guard.0 = None;
        for mut r in readers.into_iter().flatten() {
            if tokio::time::timeout(DRAIN_LIMIT, &mut r).await.is_err() {
                // A process outside the call's reach still holds the pipe: keep what was read.
                r.abort();
            }
        }
        out(status)
    }
}

/// What the search for the started process found; the call's session once any candidate was
/// seen (crun's intermediate shares it), also when the process itself was too quick to find.
enum Found {
    Started(Call, OwnedFd),
    Exited(Option<Call>),
    Lost(Option<Call>),
}

impl PodmanExec {
    async fn find_started(&self, before: &Snapshot, child: &mut tokio::process::Child) -> Found {
        let deadline = tokio::time::Instant::now() + START_LIMIT;
        let mut session: Option<i32> = None;
        let seen = |s: Option<i32>| s.map(|session| Call { top: None, session });
        loop {
            let me = self.clone();
            let then = before.clone();
            let hit = tokio::task::spawn_blocking(move || {
                let now = me.snapshot()?;
                let top = *procs::started(&then, &now).first()?;
                Some((top, me.pidfd(top)))
            })
            .await
            .ok()
            .flatten();
            if let Some((top, fd)) = hit {
                session = session.or(Some(top.session));
                // crun's short-lived intermediate (the one that calls setsid) matches too for a
                // moment: take a candidate only if it is still the same process a poll later.
                tokio::time::sleep(POLL).await;
                let me = self.clone();
                let alive = tokio::task::spawn_blocking(move || me.still(top))
                    .await
                    .unwrap_or(false);
                if let (true, Some(fd)) = (alive, fd) {
                    let call = Call {
                        top: Some(top.pid),
                        session: top.session,
                    };
                    return Found::Started(call, fd);
                }
            }
            if matches!(child.try_wait(), Ok(Some(_))) {
                if session.is_none() {
                    // Too quick to be seen: find its session from what it left (gate held).
                    let me = self.clone();
                    let before = before.clone();
                    session = tokio::task::spawn_blocking(move || {
                        procs::new_session(&before, &me.snapshot()?, me.init()?)
                    })
                    .await
                    .ok()
                    .flatten();
                }
                return Found::Exited(seen(session));
            }
            if tokio::time::Instant::now() >= deadline {
                return Found::Lost(seen(session));
            }
            tokio::time::sleep(POLL).await;
        }
    }

    /// [`Self::kill_call`] off the runtime, for a call whose session is known.
    async fn kill_in_background(&self, call: Option<Call>) {
        if let Some(call) = call {
            let me = self.clone();
            let _ = tokio::task::spawn_blocking(move || me.kill_call(call)).await;
        }
    }
}

fn take(c: &Arc<Mutex<Captured>>) -> Captured {
    std::mem::take(&mut *c.lock().unwrap_or_else(std::sync::PoisonError::into_inner))
}

/// Reads `r` to its end into `into` (capped there); a task, so a dropped call stops it with the
/// pipe.
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
