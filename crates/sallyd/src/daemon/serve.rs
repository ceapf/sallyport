//! The daemon's life (architect Q42, Q47 and Q57.5): start up in a fixed order, serve
//! `control.sock`, and shut down.
//!
//! 1. umask 077, no core dumps, not dumpable; then the panic hook that writes through the
//!    oplog. 2. Refuse root and set-id. 3. Check `$XDG_RUNTIME_DIR`, then create, check and
//!    `flock` its `sallyport/` directory for the process's life (one `sallyd` per user).
//! 4. Under the lock: `config.toml`, the audit writer, `NOFILE` raised (the launcher's fd budget
//!    is fixed when it is built, so this comes before it), hermetic podman, `remove_orphans`
//!    (a failure refuses start), then the stale `sessions/` socket directories and the stale
//!    `control.sock` are removed. 5. `control.sock` is bound last, through the locked directory's
//!    fd, 0600.
//!
//! Shutdown (SIGTERM, SIGINT, or a panic in a task that is not a session's): `control.sock` is
//! closed first, then every session is stopped `shutdown`. A container not confirmed gone, or a
//! panic, makes `sallyd` exit non-zero.

use std::ffi::OsString;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use sally_core::audit::{AuditError, AuditWriter, SystemClock};
use sally_core::config::{Config, MAX_CONFIG_BYTES, default_runtime_path, parse_config};
use sally_core::manifest::AuditLevel;
use tokio::net::UnixListener;
use tokio::signal::unix::{SignalKind, signal};

use super::crash::{CrashReporter, payload};
use super::process;
use super::startup::{self, STATE_DIR, StartError};
use crate::oplog::Oplog;
use crate::rpc::control::Control;
use crate::rpc::record::Recorder;
use crate::sandbox::budget::session_budget;
use crate::sandbox::{
    AuditSink, CheckedRuntime, DirError, DiskFloor, LaunchError, Launcher, LauncherParts, Podman,
    PodmanError, PodmanHost, ScanLimits, Sessions, SharedAudit, UserIds, check_runtime_dir,
    resolve_podman,
};
use crate::session::lookup::SharedEgress;
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
}

impl Dirs {
    /// Reads the environment. Relative values are ignored, as the XDG spec says.
    ///
    /// # Errors
    /// [`DaemonError::Env`] when `$HOME` or `$XDG_RUNTIME_DIR` is missing or relative.
    pub fn from_env() -> Result<Self, DaemonError> {
        let abs = |v: &str| {
            std::env::var_os(v)
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
        };
        let home = abs("HOME").ok_or(DaemonError::Env("HOME"))?;
        let runtime = abs("XDG_RUNTIME_DIR").ok_or(DaemonError::Env("XDG_RUNTIME_DIR"))?;
        let data_home_var = abs("XDG_DATA_HOME");
        Ok(Self {
            data_home: data_home_var
                .clone()
                .unwrap_or_else(|| home.join(".local/share")),
            config_home: abs("XDG_CONFIG_HOME").unwrap_or_else(|| home.join(".config")),
            home,
            runtime,
            data_home_var,
            path: std::env::var_os("PATH"),
        })
    }

    fn state(&self) -> PathBuf {
        self.data_home.join(STATE_DIR)
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
    let config = read_config(&dirs.config_home.join("sallyport/config.toml"))?;
    let audit = AuditWriter::open(&dirs.state().join("audit"), Box::new(SystemClock))?;
    let audit: Arc<dyn AuditSink> = Arc::new(SharedAudit(Mutex::new(audit)));
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
    rt.block_on(serve(log, &dirs, &config, audit, &lock, nofile))
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

/// `config.toml`, or the defaults when it does not exist. Read through one bounded read.
fn read_config(path: &Path) -> Result<Config, DaemonError> {
    let fail = |msg: String| DaemonError::Config {
        path: path.display().to_string(),
        msg,
    };
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Config::default()),
        Err(e) => return Err(fail(e.to_string())),
    };
    let mut text = String::new();
    let cap = u64::try_from(MAX_CONFIG_BYTES).unwrap_or(u64::MAX) + 1;
    std::io::Read::read_to_string(&mut std::io::Read::take(file, cap), &mut text)
        .map_err(|e| fail(e.to_string()))?;
    parse_config(&text).map_err(|e| fail(e.to_string()))
}

async fn serve(
    log: &Oplog,
    dirs: &Dirs,
    config: &Config,
    audit: Arc<dyn AuditSink>,
    lock: &OwnedFd,
    nofile: u64,
) -> Result<(), DaemonError> {
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
        egress: Arc::new(SharedEgress::default()),
        oplog: log.clone(),
    });
    let removed = launcher
        .remove_orphans("")
        .await
        .map_err(DaemonError::Orphans)?;
    log.info(
        LOG,
        "orphans removed",
        &[("count", &removed.len().to_string())],
    );
    let state = dirs.runtime.join(STATE_DIR);
    let stale = state.clone();
    tokio::task::spawn_blocking(move || remove_stale(&stale))
        .await
        .map_err(|e| DaemonError::Io {
            what: "removing stale sockets",
            source: std::io::Error::other(e.to_string()),
        })??;
    let (crash, mut crashes) = CrashReporter::channel();
    let registry = Registry::new(RegistryParts {
        launcher,
        audit: Arc::clone(&audit),
        podman,
        ids,
        sockets: state,
        data: dirs.state(),
        // Architect Q58: no bundled workspace image yet, so none; a manifest without
        // `runtime.image` is refused `no-default-image`. TODO(#88): the bundled image.
        default_image: None,
        oplog: log.clone(),
        crash: crash.clone(),
        scope: String::new(),
    });
    let control = Arc::new(Control::new(Recorder::new(
        audit,
        String::new(),
        AuditLevel::default(),
    )))
    .listen(bind_control(lock)?, ids.uid, crash);
    log.info(LOG, "serving", &[("socket", CONTROL_SOCK)]);

    let mut term = signal(SignalKind::terminate()).map_err(io("SIGTERM handler"))?;
    let mut int = signal(SignalKind::interrupt()).map_err(io("SIGINT handler"))?;
    let crashed = tokio::select! {
        _ = term.recv() => None,
        _ = int.recv() => None,
        Some(c) = crashes.recv() => Some(c),
    };
    let why = crashed.as_ref().map_or("signal", |c| c.task);
    log.info(LOG, "shutting down", &[("why", why)]);
    control.shutdown().await;
    let _ = rustix::fs::unlinkat(lock, CONTROL_SOCK, rustix::fs::AtFlags::empty());
    let unconfirmed = registry.shutdown().await;
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

/// Removes what a previous `sallyd` left in the runtime directory: the session socket
/// directories (`sessions/`) and `control.sock`. The staged data under the data directory is
/// kept for review.
fn remove_stale(state: &Path) -> Result<(), DaemonError> {
    match std::fs::remove_dir_all(state.join("sessions")) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(io("removing stale session sockets")(e)),
    }
    match std::fs::remove_file(state.join(CONTROL_SOCK)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io("removing a stale control.sock")(e)),
    }
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
