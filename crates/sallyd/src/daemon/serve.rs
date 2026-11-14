//! The daemon's life (architect Q42, Q47 and Q57.5): start up in a fixed order, serve
//! `control.sock`, and shut down.
//!
//! 1. umask 077, no core dumps, not dumpable; then the panic hook that writes through the
//!    oplog. 2. Refuse root and set-id. 3. Check `$XDG_RUNTIME_DIR`, then create, check and
//!    `flock` its `sallyport/` directory for the process's life (one `sallyd` per user).
//! 4. Under the lock: `config.toml` (a regular file, not followed through a symlink, never
//!    blocking on a FIFO), the audit writer, `NOFILE` raised (the launcher's fd budget is fixed
//!    when it is built, so this comes before it), the signal handlers, hermetic podman,
//!    `remove_orphans` (a failure refuses start), then the stale `sessions/` socket directories
//!    and the stale `control.sock` are removed relative to the locked directory's fd, in a
//!    bounded walk (`daemon::stale`). 5. `control.sock` is bound last, through that fd, 0600.
//!    6. The periodic orphan sweep starts (`daemon::sweep`, architect Q61).
//!
//! Shutdown (SIGTERM, SIGINT, SIGHUP, SIGQUIT, or a panic in a task that is not a session's;
//! a signal that arrives during startup is handled once it is done): `control.sock` is closed
//! first, then every session is stopped `shutdown`, all at once. A container not confirmed gone,
//! or a panic, makes `sallyd` exit non-zero; so does a second signal during the shutdown, at
//! once. TODO(#92): a container `sallyd` cannot stop because it was killed outright is bounded by
//! nothing yet; a `podman --timeout` backstop follows this PR (architect Q60).

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use sally_core::audit::{AuditError, AuditWriter, SystemClock};
use sally_core::config::{Config, MAX_CONFIG_BYTES, default_runtime_path, parse_config};
use sally_core::manifest::{AuditLevel, HostEnv, HostEnvError};
use sally_core::paths::{Paths, PathsError};
use tokio::net::UnixListener;
use tokio::signal::unix::{SignalKind, signal};

use super::crash::{CrashReporter, payload};
use super::startup::{self, STATE_DIR, StartError};
use super::{process, stale, sweep};
use crate::approvals::Approver;
use crate::approvals::hub::Hub;
use crate::oplog::Oplog;
use crate::rpc::control::{Control, ControlParts};
use crate::rpc::record::Recorder;
use crate::sandbox::budget::session_budget;
use crate::sandbox::{
    AuditSink, CheckedRuntime, DirError, DiskFloor, Installation, LaunchError, Launcher,
    LauncherParts, Podman, PodmanError, PodmanHost, ScanLimits, Sessions, SharedAudit, Sweep,
    UserIds, check_runtime_dir, open_sessions, resolve_podman,
};
use crate::session::lookup::{NoSecrets, SharedEgress};
use crate::session::{Registry, RegistryParts};

/// The trusted clients' socket in the locked runtime directory.
pub const CONTROL_SOCK: &str = "control.sock";
/// The oplog component.
const LOG: &str = "daemon";

/// Why `sallyd` stopped with an error.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DaemonError {
    /// A startup check or hardening call failed.
    #[error(transparent)]
    Start(#[from] StartError),
    /// A required environment variable is missing.
    #[error("{0} is not set")]
    Env(&'static str),
    /// `$XDG_RUNTIME_DIR` failed its check.
    #[error(transparent)]
    RuntimeDir(#[from] DirError),
    /// `config.toml` could not be read or was refused.
    #[error("{path}: {msg}")]
    Config {
        /// The file.
        path: String,
        /// What is wrong.
        msg: String,
    },
    /// The audit log could not be opened.
    #[error("audit: {0}")]
    Audit(#[from] AuditError),
    /// This installation's id could not be read or made (architect Q64).
    #[error(transparent)]
    Installation(#[from] super::install::InstallError),
    /// The host facts manifests are validated against could not be read (architect Q87).
    #[error("host facts: {0}")]
    HostEnv(#[from] HostEnvError),
    /// The sessions' data directory could not be opened (architect Q81).
    #[error("sessions directory: {0}")]
    SessionsDir(#[source] DirError),
    /// Podman or the runtime failed a check.
    #[error(transparent)]
    Podman(#[from] PodmanError),
    /// Containers a previous `sallyd` left could not be removed.
    #[error("removing orphaned containers: {0}")]
    Orphans(#[source] LaunchError),
    /// A file or socket under the runtime directory.
    #[error("{what}: {source}")]
    Io {
        /// What failed.
        what: &'static str,
        /// The error.
        #[source]
        source: std::io::Error,
    },
    /// A task that is not a session's panicked.
    #[error("task {task} panicked")]
    Crash {
        /// The task.
        task: &'static str,
    },
    /// Sessions whose containers could not be confirmed gone at shutdown.
    #[error("containers of sessions {0:?} could not be confirmed gone")]
    Unconfirmed(Vec<String>),
    /// A second signal arrived while sessions were being stopped.
    #[error("{0} during shutdown: stopped without waiting for the sessions")]
    Interrupted(&'static str),
}

/// How long the runtime's remaining blocking work may delay the exit.
const EXIT_WAIT: std::time::Duration = std::time::Duration::from_secs(1);

/// The signals that stop `sallyd`, installed before anything is started.
struct Signals {
    term: tokio::signal::unix::Signal,
    int: tokio::signal::unix::Signal,
    hup: tokio::signal::unix::Signal,
    quit: tokio::signal::unix::Signal,
}

impl Signals {
    fn install() -> Result<Self, DaemonError> {
        let on = |k: SignalKind, what: &'static str| signal(k).map_err(io(what));
        Ok(Self {
            term: on(SignalKind::terminate(), "SIGTERM handler")?,
            int: on(SignalKind::interrupt(), "SIGINT handler")?,
            hup: on(SignalKind::hangup(), "SIGHUP handler")?,
            quit: on(SignalKind::quit(), "SIGQUIT handler")?,
        })
    }

    /// The next signal's name.
    async fn next(&mut self) -> &'static str {
        tokio::select! {
            _ = self.term.recv() => "SIGTERM",
            _ = self.int.recv() => "SIGINT",
            _ = self.hup.recv() => "SIGHUP",
            _ = self.quit.recv() => "SIGQUIT",
        }
    }
}

fn io(what: &'static str) -> impl FnOnce(std::io::Error) -> DaemonError {
    move |source| DaemonError::Io { what, source }
}

/// Where `sallyd` keeps its files, from the environment.
#[derive(Debug, Clone)]
pub struct Dirs {
    /// `$HOME`.
    pub home: PathBuf,
    /// `$XDG_RUNTIME_DIR`.
    pub runtime: PathBuf,
    /// `$XDG_DATA_HOME`, when set.
    pub data_home_var: Option<PathBuf>,
    /// `$XDG_DATA_HOME`, or `~/.local/share`.
    pub data_home: PathBuf,
    /// `$XDG_CONFIG_HOME`, or `~/.config`.
    pub config_home: PathBuf,
    /// `$PATH`, for finding `podman` when `config.toml` names none.
    pub path: Option<OsString>,
    /// The derivation the CLI shares (`sally_core::paths`, architect Q107).
    pub paths: Paths,
}

impl Dirs {
    /// Reads the environment. Relative values are ignored, as the XDG spec says.
    ///
    /// # Errors
    /// [`DaemonError::Env`] when `$HOME` or `$XDG_RUNTIME_DIR` is missing or relative.
    pub fn from_env() -> Result<Self, DaemonError> {
        let env = |e| match e {
            PathsError::Home => DaemonError::Env("HOME"),
            PathsError::Runtime => DaemonError::Env("XDG_RUNTIME_DIR"),
        };
        let paths = Paths::from_env().map_err(env)?;
        let runtime = paths.runtime().map_err(env)?.to_owned();
        Ok(Self {
            home: paths.home().to_owned(),
            runtime,
            data_home_var: std::env::var_os("XDG_DATA_HOME")
                .map(PathBuf::from)
                .filter(|p| p.is_absolute()),
            data_home: paths.data_home().to_owned(),
            config_home: paths.config_home().to_owned(),
            path: std::env::var_os("PATH"),
            paths,
        })
    }

    fn state(&self) -> PathBuf {
        self.paths.state()
    }
}

/// Runs `sallyd` to its end.
///
/// # Errors
/// [`DaemonError`]: a refusal to start, or an unclean end.
pub fn run(log: &Oplog) -> Result<(), DaemonError> {
    process::harden()?;
    panic_hook(log.clone());
    process::check_own_ids()?;
    let dirs = Dirs::from_env()?;
    check_runtime_dir(&dirs.runtime)?;
    let lock = startup::open_and_lock(&dirs.runtime)?;
    let config = read_config(&dirs.paths.config_file())?;
    let audit = AuditWriter::open(&dirs.paths.audit(), Box::new(SystemClock))?;
    let audit: Arc<dyn AuditSink> = Arc::new(SharedAudit(Mutex::new(audit)));
    // Under the single-instance lock, in the state directory the audit log just made.
    let installation = super::install::load_or_create(&dirs.state())?;
    let prepared = Prepared {
        installation,
        sessions: open_sessions(&dirs.state()).map_err(DaemonError::SessionsDir)?,
        env: HostEnv::from_process()?,
    };
    let nofile = process::raise_nofile()?;
    log.info(
        LOG,
        "starting",
        &[
            ("runtime_dir", &dirs.runtime.display().to_string()),
            ("nofile", &nofile.to_string()),
        ],
    );
    let rt = super::runtime().map_err(io("tokio runtime"))?;
    // A panic in `serve` is caught here, so the runtime is still shut down within EXIT_WAIT
    // rather than dropped while unwinding, which waits for the blocking pool without bound (R9).
    let end = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        rt.block_on(serve(log, &dirs, &config, audit, &lock, nofile, prepared))
    }));
    // After a second signal, work still on the blocking pool must not hold the exit.
    rt.shutdown_timeout(EXIT_WAIT);
    match end {
        Ok(end) => end,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

/// The panic hook: one oplog line per panic, in any thread (a session task's panic is also
/// reported to its session by the crash reporter).
fn panic_hook(log: Oplog) {
    std::panic::set_hook(Box::new(move |info| {
        let at = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_default();
        log.error(
            "panic",
            "a task panicked",
            &[("at", &at), ("payload", &payload(info.payload()))],
        );
    }));
}

/// `config.toml`, or the defaults when it does not exist. Opened without following a symlink and
/// without blocking (a FIFO would hold startup), then required to be a regular file; read
/// through one bounded read (security review L2).
fn read_config(path: &Path) -> Result<Config, DaemonError> {
    use rustix::fs::{FileType, Mode, OFlags};
    let fail = |msg: String| DaemonError::Config {
        path: path.display().to_string(),
        msg,
    };
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let fd = match sally_core::fd::open(path, flags, Mode::empty()) {
        Ok(f) => f,
        Err(rustix::io::Errno::NOENT) => return Ok(Config::default()),
        Err(rustix::io::Errno::LOOP) => return Err(fail("a symlink is not followed".into())),
        Err(e) => return Err(fail(e.to_string())),
    };
    let st = rustix::fs::fstat(&fd).map_err(|e| fail(e.to_string()))?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Err(fail("not a regular file".into()));
    }
    let file = std::fs::File::from(fd);
    let mut text = String::new();
    let cap = u64::try_from(MAX_CONFIG_BYTES).unwrap_or(u64::MAX) + 1;
    std::io::Read::read_to_string(&mut std::io::Read::take(file, cap), &mut text)
        .map_err(|e| fail(e.to_string()))?;
    parse_config(&text).map_err(|e| fail(e.to_string()))
}

/// What `run` reads before the runtime starts (blocking), for `serve`.
struct Prepared {
    installation: Installation,
    /// The open `sessions/` data directory.
    sessions: OwnedFd,
    /// The host facts manifests are validated against, read once.
    env: HostEnv,
}

async fn serve(
    log: &Oplog,
    dirs: &Dirs,
    config: &Config,
    audit: Arc<dyn AuditSink>,
    lock: &OwnedFd,
    nofile: u64,
    prepared: Prepared,
) -> Result<(), DaemonError> {
    let Prepared {
        installation,
        sessions: sessions_dir,
        env,
    } = prepared;
    // First, so a signal during startup is not the default action (death, no cleanup): it
    // waits here and is handled once `control.sock` is bound (security review M3).
    let mut signals = Signals::install()?;
    let ids = UserIds {
        uid: rustix::process::geteuid().as_raw(),
        gid: rustix::process::getegid().as_raw(),
    };
    let (podman, runtime) = podman(dirs, config).await?;
    let launcher = Launcher::new(LauncherParts {
        podman: podman.clone(),
        runtime,
        ids,
        xdg_runtime_dir: dirs.runtime.clone(),
        sessions: Arc::new(Sessions::new(session_budget(nofile))),
        audit: Arc::clone(&audit),
        limits: ScanLimits::default(),
        disk_floor: DiskFloor::default(),
        // PR A has no secret set (maintainer): a source with no values refuses every grant
        // `secret-missing`. TODO(#99): `StoreFile { path: dirs.config_home.join(
        // "sallyport/secrets.toml") }`, with the #85 redactor swap and PR C's `sally secrets`.
        egress: Arc::new(SharedEgress::new(
            Arc::new(crate::egress::net::getaddrinfo),
            Arc::new(NoSecrets),
        )),
        oplog: log.clone(),
        installation,
    });
    let removed = launcher
        .remove_orphans("", Sweep::Startup)
        .await
        .map_err(DaemonError::Orphans)?;
    log.info(
        LOG,
        "orphans removed",
        &[("count", &removed.len().to_string())],
    );
    let state = dirs.runtime.join(STATE_DIR);
    let dir = lock.try_clone().map_err(io("the locked directory"))?;
    tokio::task::spawn_blocking(move || stale::remove(&dir, CONTROL_SOCK))
        .await
        .map_err(|e| DaemonError::Io {
            what: "removing stale sockets",
            source: std::io::Error::other(e.to_string()),
        })?
        .map_err(io("removing stale sockets"))?;
    let (crash, mut crashes) = CrashReporter::channel();
    // The one approver: every session's desk tells it, control watchers hear it (Q73).
    let hub = Arc::new(Hub::default());
    let registry = Registry::new(RegistryParts {
        launcher: Arc::clone(&launcher),
        audit: Arc::clone(&audit),
        podman,
        ids,
        sockets: state,
        data: dirs.state(),
        // Architect Q58: no bundled workspace image yet, so none; a manifest without
        // `runtime.image` is refused `no-default-image`. TODO(#88): the bundled image.
        default_image: None,
        oplog: log.clone(),
        approver: Arc::clone(&hub) as Arc<dyn Approver>,
        crash: crash.clone(),
        scope: String::new(),
    });
    let control = Arc::new(Control::new(ControlParts {
        record: Recorder::new(audit, String::new(), AuditLevel::default()),
        sessions: registry.clone(),
        hub,
        sessions_dir: Arc::new(sessions_dir),
        env: Arc::new(env),
        // Architect Q87: no secret store yet, so a manifest granting one is refused at
        // validation (`manifest.refuse`). TODO(#99): the store's names.
        catalog: Arc::new(BTreeSet::<String>::new()),
    }))
    .listen(bind_control(lock)?, ids.uid, crash.clone());
    log.info(LOG, "serving", &[("socket", CONTROL_SOCK)]);
    let sweeping = crash.spawn(
        "sweep",
        sweep::every(launcher, String::new(), sweep::ORPHAN_SWEEP, log.clone()),
    );

    let crashed = tokio::select! {
        s = signals.next() => {
            log.info(LOG, "shutting down", &[("why", s)]);
            None
        }
        Some(c) = crashes.recv() => {
            log.info(LOG, "shutting down", &[("why", c.task)]);
            Some(c)
        }
    };
    sweeping.abort();
    let stopping = async {
        control.shutdown().await;
        let _ = rustix::fs::unlinkat(lock, CONTROL_SOCK, rustix::fs::AtFlags::empty());
        registry.shutdown().await
    };
    let unconfirmed = tokio::select! {
        u = stopping => u,
        s = signals.next() => {
            log.error(LOG, "second signal: stopping now", &[("signal", s)]);
            return Err(DaemonError::Interrupted(s));
        }
    };
    if !unconfirmed.is_empty() {
        log.error(
            LOG,
            "containers not confirmed gone",
            &[("sessions", &unconfirmed.join(","))],
        );
        return Err(DaemonError::Unconfirmed(unconfirmed));
    }
    match crashed {
        Some(c) => Err(DaemonError::Crash { task: c.task }),
        None => {
            log.info(LOG, "stopped", &[]);
            Ok(())
        }
    }
}

/// Hermetic podman over the checked runtime (blocking checks, off the runtime).
async fn podman(dirs: &Dirs, config: &Config) -> Result<(Podman, CheckedRuntime), DaemonError> {
    let runtime_path = config
        .sandbox
        .runtime_path
        .clone()
        .unwrap_or_else(|| default_runtime_path(&dirs.data_home));
    let configured = config.sandbox.podman_path.clone();
    let host = PodmanHost {
        home: dirs.home.clone(),
        xdg_runtime_dir: dirs.runtime.clone(),
        xdg_data_home: dirs.data_home_var.clone(),
    };
    let (path, state) = (dirs.path.clone(), dirs.state().join("podman"));
    tokio::task::spawn_blocking(move || {
        let runtime = CheckedRuntime::check(&runtime_path).map_err(PodmanError::Binary)?;
        let bin = resolve_podman(configured.as_deref(), path.as_deref())?;
        let podman = Podman::setup(bin, &runtime, &state, &host)?;
        Ok((podman, runtime))
    })
    .await
    .map_err(|e| DaemonError::Io {
        what: "podman setup",
        source: std::io::Error::other(e.to_string()),
    })?
}

/// Binds `control.sock` in the locked directory, through its fd (`/proc/self/fd/N`), 0600.
fn bind_control(dir: &OwnedFd) -> Result<UnixListener, DaemonError> {
    let path = Path::new("/proc/self/fd")
        .join(dir.as_raw_fd().to_string())
        .join(CONTROL_SOCK);
    let l = std::os::unix::net::UnixListener::bind(&path).map_err(io("binding control.sock"))?;
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
        .map_err(io("chmod control.sock"))?;
    l.set_nonblocking(true)
        .map_err(io("control.sock nonblocking"))?;
    UnixListener::from_std(l).map_err(io("control.sock listener"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// The CLI finds the socket through `sally_core::paths` (architect Q107): the names agree.
    #[test]
    fn the_socket_names_are_the_ones_the_cli_derives() {
        assert_eq!(STATE_DIR, sally_core::paths::STATE_DIR);
        assert_eq!(CONTROL_SOCK, sally_core::paths::CONTROL_SOCKET);
    }

    fn scratch(name: &str) -> PathBuf {
        let d = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/serve-tests")
            .join(format!("{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn refusal(path: &Path) -> String {
        match read_config(path) {
            Err(DaemonError::Config { msg, .. }) => msg,
            other => panic!("{other:?}"),
        }
    }

    /// Security review L2: only a regular file is read; a FIFO is refused at once instead of
    /// blocking startup, and neither a symlink nor a directory is read.
    #[test]
    fn the_config_is_a_regular_file_never_a_fifo_or_a_symlink() {
        let d = scratch("config");
        let file = d.join("config.toml");
        assert_eq!(
            read_config(&file).unwrap().sandbox.podman_path,
            Config::default().sandbox.podman_path,
            "missing: the defaults"
        );
        std::fs::write(&file, "[sandbox]\nruntime_path = \"/opt/crun\"\n").unwrap();
        assert_eq!(
            read_config(&file).unwrap().sandbox.runtime_path,
            Some(PathBuf::from("/opt/crun"))
        );
        let link = d.join("link.toml");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert_eq!(refusal(&link), "a symlink is not followed");
        assert_eq!(refusal(&d), "not a regular file");
        let fifo = d.join("fifo.toml");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || tx.send(refusal(&fifo)));
        let got = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("reading a FIFO config blocked");
        assert_eq!(got, "not a regular file");
        std::fs::remove_dir_all(&d).unwrap();
    }
}
