//! Hermetic `podman` (#11). `check_argv` only sees the argv, but Podman also reads configuration
//! from outside it: `containers.conf` (system, user, drop-ins, `CONTAINERS_CONF_OVERRIDE`),
//! `mounts.conf`, OCI hook directories and environment variables such as `CONTAINER_HOST`. Each
//! can add a mount, a device, a capability, a hook or a remote connection. So every podman
//! process `sallyd` starts gets:
//!
//! - a cleared environment plus a short allowlist ([`Podman::env`]);
//! - `CONTAINERS_CONF` pointing at a file `sallyd` generates in its 0700 state directory, which
//!   replaces (does not merge with) every system and user file on Podman 4.9.3 (probed in
//!   Task 6b); `CONTAINERS_CONF_OVERRIDE` is never passed;
//! - `XDG_CONFIG_HOME` pointing at an empty directory of that state directory, so the user's
//!   `~/.config/containers/{storage,mounts,registries}.conf` are not read either;
//! - `--hooks-dir` naming an empty Sallyport-owned directory (in the checked argv);
//! - a podman binary resolved once to an absolute path with the runtime's ownership checks.

use std::ffi::{OsStr, OsString};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use sally_core::config::{ConfigError, check_trusted_binary};

use super::types::CheckedRuntime;

/// Directories podman and its helpers (`conmon`, `newuidmap`) may be found in. Root-owned on
/// every supported host; never the user's `PATH`.
pub const PODMAN_PATH_VAR: &str = "/usr/bin:/bin:/usr/sbin:/sbin";
/// Where `catatonit` (`--init`) lives on supported distributions, in podman's search order.
const INIT_CANDIDATES: [&str; 4] = [
    "/usr/libexec/podman/catatonit",
    "/usr/lib/podman/catatonit",
    "/usr/local/libexec/podman/catatonit",
    "/usr/bin/catatonit",
];
/// Where `conmon` lives, in podman's search order.
const CONMON_CANDIDATES: [&str; 5] = [
    "/usr/libexec/podman/conmon",
    "/usr/lib/podman/conmon",
    "/usr/local/libexec/podman/conmon",
    "/usr/bin/conmon",
    "/usr/sbin/conmon",
];

/// Why hermetic podman could not be set up.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PodmanError {
    /// A binary failed the ownership checks or was not found.
    #[error(transparent)]
    Binary(#[from] ConfigError),
    /// A binary podman needs was not found.
    #[error("{0} not found in any of {1:?}")]
    Missing(&'static str, Vec<&'static str>),
    /// A host directory is not private, or not what it should be.
    #[error("{path}: {msg}")]
    Dir {
        /// Host path.
        path: String,
        /// What is wrong.
        msg: String,
    },
    /// An I/O error.
    #[error("{path}: {source}")]
    Io {
        /// Host path.
        path: String,
        /// The underlying error.
        source: std::io::Error,
    },
}

fn io_err(path: &Path) -> impl FnOnce(std::io::Error) -> PodmanError + '_ {
    move |source| PodmanError::Io {
        path: path.display().to_string(),
        source,
    }
}

fn dir_err<T>(path: &Path, msg: &str) -> Result<T, PodmanError> {
    Err(PodmanError::Dir {
        path: path.display().to_string(),
        msg: msg.to_owned(),
    })
}

/// The host environment podman needs; everything else is dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodmanHost {
    /// `$HOME` (podman's default storage lives under it).
    pub home: PathBuf,
    /// `$XDG_RUNTIME_DIR` (podman's run root, the pause process, the event socket).
    pub xdg_runtime_dir: PathBuf,
    /// `$XDG_DATA_HOME`, passed only when set, so the user's image store is found.
    pub xdg_data_home: Option<PathBuf>,
}

/// Picks the podman binary: the configured path, else the first `podman` on `sallyd`'s own
/// `PATH`; then the ownership checks of the runtime (`sandbox.podman_path`).
///
/// # Errors
/// [`PodmanError::Missing`] or [`PodmanError::Binary`].
pub fn resolve_podman(
    configured: Option<&Path>,
    path_var: Option<&OsStr>,
) -> Result<PathBuf, PodmanError> {
    let found = match configured {
        Some(p) => p.to_owned(),
        None => path_var
            .into_iter()
            .flat_map(std::env::split_paths)
            .filter(|d| d.is_absolute())
            .map(|d| d.join("podman"))
            .find(|p| p.is_file())
            .ok_or(PodmanError::Missing("podman", vec!["$PATH"]))?,
    };
    Ok(check_trusted_binary(&found, "sandbox.podman_path")?)
}

/// The first candidate that exists, checked like the runtime.
fn first_trusted(what: &'static str, candidates: &[&'static str]) -> Result<PathBuf, PodmanError> {
    let p = candidates
        .iter()
        .map(Path::new)
        .find(|p| p.exists())
        .ok_or_else(|| PodmanError::Missing(what, candidates.to_vec()))?;
    Ok(check_trusted_binary(p, what)?)
}

/// A path as a TOML basic string: refuse what would need escaping rather than escape it.
fn toml_path(p: &Path) -> Result<String, PodmanError> {
    match p.to_str() {
        Some(s)
            if p.is_absolute() && !s.chars().any(|c| c == '"' || c == '\\' || c.is_control()) =>
        {
            Ok(format!("\"{s}\""))
        }
        _ => dir_err(
            p,
            "must be an absolute UTF-8 path without quotes, backslashes or control characters",
        ),
    }
}

/// The binaries `containers.conf` names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfBinaries {
    /// The checked OCI runtime.
    pub runtime: PathBuf,
    /// `catatonit`, the `--init` process.
    pub init: PathBuf,
    /// `conmon`.
    pub conmon: PathBuf,
}

/// The generated `containers.conf`: no default volumes, devices, capabilities, environment,
/// sysctls, ulimits, annotations or hooks; private namespaces; the pinned runtime and helpers;
/// events and logs off; never remote.
///
/// # Errors
/// [`PodmanError::Dir`] if a path cannot be written as a TOML string.
pub fn containers_conf(hooks_dir: &Path, b: &ConfBinaries) -> Result<String, PodmanError> {
    let hooks = toml_path(hooks_dir)?;
    let runtime = toml_path(&b.runtime)?;
    let init = toml_path(&b.init)?;
    let conmon = toml_path(&b.conmon)?;
    Ok(format!(
        r#"# Generated by sallyd for every podman it runs (CONTAINERS_CONF). It replaces the system
# and user containers.conf files and their drop-ins; do not edit, it is rewritten at startup.

[containers]
annotations = []
cgroupns = "private"
default_capabilities = []
default_sysctls = []
default_ulimits = []
devices = []
env = []
env_host = false
http_proxy = false
init = false
init_path = {init}
ipcns = "private"
keyring = false
label = false
log_driver = "none"
mounts = []
no_hosts = true
pidns = "private"
read_only = true
utsns = "private"
volumes = []

[engine]
active_service = ""
cdi_spec_dirs = ["/var/run/cdi"]
conmon_path = [{conmon}]
env = []
events_logger = "none"
hooks_dir = [{hooks}]
remote = false
runtime = "crun"

[engine.runtimes]
crun = [{runtime}]
"#
    ))
}

/// Hermetic podman for one `sallyd`: the checked binary, the generated configuration and the
/// environment every podman process gets.
#[derive(Debug, Clone)]
pub struct Podman {
    bin: PathBuf,
    hooks: PathBuf,
    env: Vec<(OsString, OsString)>,
}

impl Podman {
    /// Prepares `state` (`~/.local/share/sallyport/podman`, created 0700): an empty `hooks/`, an
    /// empty `config/` (the `XDG_CONFIG_HOME` podman sees) and a freshly written
    /// `containers.conf`. Performs blocking I/O.
    ///
    /// # Errors
    /// [`PodmanError`] if a binary fails its checks or a directory is not private and empty.
    pub fn setup(
        podman: PathBuf,
        runtime: &CheckedRuntime,
        state: &Path,
        host: &PodmanHost,
    ) -> Result<Self, PodmanError> {
        let bins = ConfBinaries {
            runtime: runtime.path().to_owned(),
            init: first_trusted("catatonit", &INIT_CANDIDATES)?,
            conmon: first_trusted("conmon", &CONMON_CANDIDATES)?,
        };
        private_dir(state)?;
        let hooks = state.join("hooks");
        let config_home = state.join("config");
        for d in [&hooks, &config_home] {
            private_dir(d)?;
            ensure_empty(d)?;
        }
        let conf = state.join("containers.conf");
        let text = containers_conf(&hooks, &bins)?;
        let tmp = state.join("containers.conf.tmp");
        let _ = std::fs::remove_file(&tmp);
        write_new_0600(&tmp, text.as_bytes())?;
        std::fs::rename(&tmp, &conf).map_err(io_err(&conf))?;
        Ok(Self {
            bin: podman,
            env: Self::env(host, &conf, &config_home),
            hooks,
        })
    }

    /// The complete environment of every podman process: `HOME`, `XDG_RUNTIME_DIR`, optionally
    /// `XDG_DATA_HOME`, a root-owned `PATH`, `CONTAINERS_CONF` and `XDG_CONFIG_HOME`. Nothing
    /// else, in particular no `CONTAINERS_CONF_OVERRIDE`, `CONTAINER_HOST`, `DOCKER_HOST`,
    /// `CONTAINERS_STORAGE_CONF`, `TMPDIR` or proxy variable.
    #[must_use]
    pub fn env(host: &PodmanHost, conf: &Path, config_home: &Path) -> Vec<(OsString, OsString)> {
        let mut env = vec![
            ("HOME".into(), host.home.clone().into_os_string()),
            (
                "XDG_RUNTIME_DIR".into(),
                host.xdg_runtime_dir.clone().into_os_string(),
            ),
            ("PATH".into(), PODMAN_PATH_VAR.into()),
            ("CONTAINERS_CONF".into(), conf.as_os_str().to_owned()),
            ("XDG_CONFIG_HOME".into(), config_home.as_os_str().to_owned()),
        ];
        if let Some(d) = &host.xdg_data_home {
            env.push(("XDG_DATA_HOME".into(), d.clone().into_os_string()));
        }
        env
    }

    /// The checked podman binary.
    #[must_use]
    pub fn bin(&self) -> &Path {
        &self.bin
    }

    /// The empty hooks directory, for `--hooks-dir`.
    #[must_use]
    pub fn hooks_dir(&self) -> &Path {
        &self.hooks
    }

    /// The environment passed to podman.
    #[must_use]
    pub fn environment(&self) -> &[(OsString, OsString)] {
        &self.env
    }

    /// Re-checks, before each launch, that the hooks directory is still private and empty.
    /// Performs blocking I/O.
    ///
    /// # Errors
    /// [`PodmanError::Dir`] if a file appeared in it.
    pub fn recheck(&self) -> Result<(), PodmanError> {
        private_dir(&self.hooks)?;
        ensure_empty(&self.hooks)
    }

    /// A podman command with the hermetic environment, no stdin, killed if dropped.
    #[must_use]
    pub fn command(&self) -> tokio::process::Command {
        let mut c = tokio::process::Command::new(&self.bin);
        c.env_clear()
            .envs(self.env.iter().map(|(k, v)| (k, v)))
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true);
        c
    }
}

/// Creates `dir` 0700 if missing; it must be a directory (not a symlink) owned by the current
/// user with no group or other permission bits.
pub(crate) fn private_dir(dir: &Path) -> Result<(), PodmanError> {
    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(io_err(dir)(e)),
    }
    let meta = std::fs::symlink_metadata(dir).map_err(io_err(dir))?;
    if !meta.is_dir() {
        return dir_err(dir, "is not a directory (or is a symlink)");
    }
    if meta.uid() != rustix::process::geteuid().as_raw() {
        return dir_err(dir, "is not owned by the current user");
    }
    if meta.permissions().mode() & 0o077 != 0 {
        return dir_err(dir, "must be mode 0700 (chmod 700 it)");
    }
    Ok(())
}

fn ensure_empty(dir: &Path) -> Result<(), PodmanError> {
    let mut entries = std::fs::read_dir(dir).map_err(io_err(dir))?;
    if entries.next().is_some() {
        return dir_err(dir, "must be empty; sallyd owns it and puts nothing in it");
    }
    Ok(())
}

fn write_new_0600(path: &Path, bytes: &[u8]) -> Result<(), PodmanError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(io_err(path))?;
    f.write_all(bytes).map_err(io_err(path))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn bins() -> ConfBinaries {
        ConfBinaries {
            runtime: "/opt/sp/crun".into(),
            init: "/usr/libexec/podman/catatonit".into(),
            conmon: "/usr/bin/conmon".into(),
        }
    }

    #[test]
    fn the_generated_conf_empties_every_default_that_adds_reach() {
        let c = containers_conf(Path::new("/s/hooks"), &bins()).unwrap();
        for line in [
            "volumes = []",
            "devices = []",
            "default_capabilities = []",
            "env = []",
            "mounts = []",
            "annotations = []",
            "default_sysctls = []",
            "default_ulimits = []",
            "env_host = false",
            "http_proxy = false",
            "keyring = false",
            "remote = false",
            "active_service = \"\"",
            "events_logger = \"none\"",
            "log_driver = \"none\"",
            "hooks_dir = [\"/s/hooks\"]",
            "crun = [\"/opt/sp/crun\"]",
            "init_path = \"/usr/libexec/podman/catatonit\"",
            "conmon_path = [\"/usr/bin/conmon\"]",
        ] {
            assert!(c.lines().any(|l| l == line), "{line} missing:\n{c}");
        }
        // It parses as TOML, so podman reads every key rather than stopping at a syntax error.
        let parsed: toml::Table = toml::from_str(&c).unwrap();
        assert!(parsed.contains_key("containers") && parsed.contains_key("engine"));
    }

    #[test]
    fn paths_that_would_need_toml_escaping_are_refused() {
        for bad in ["/s/ho\"oks", "/s/ho\\oks", "/s/ho\noks", "relative"] {
            assert!(containers_conf(Path::new(bad), &bins()).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_environment_is_an_allowlist() {
        let host = PodmanHost {
            home: "/home/u".into(),
            xdg_runtime_dir: "/run/user/1000".into(),
            xdg_data_home: None,
        };
        let env = Podman::env(
            &host,
            Path::new("/s/containers.conf"),
            Path::new("/s/config"),
        );
        let names: Vec<&OsStr> = env.iter().map(|(k, _)| k.as_os_str()).collect();
        assert_eq!(
            names,
            [
                "HOME",
                "XDG_RUNTIME_DIR",
                "PATH",
                "CONTAINERS_CONF",
                "XDG_CONFIG_HOME"
            ]
        );
        let with_data = Podman::env(
            &PodmanHost {
                xdg_data_home: Some("/d".into()),
                ..host
            },
            Path::new("/c"),
            Path::new("/x"),
        );
        assert_eq!(with_data.len(), 6);
    }

    #[test]
    fn podman_is_resolved_from_path_and_checked() {
        let p = resolve_podman(Some(Path::new("/bin/sh")), None).unwrap();
        assert!(p.is_absolute());
        let e = resolve_podman(None, Some(OsStr::new("relative:/nonexistent"))).unwrap_err();
        assert!(matches!(e, PodmanError::Missing("podman", _)), "{e}");
        let e = resolve_podman(Some(Path::new("/nonexistent/podman")), None).unwrap_err();
        assert!(e.to_string().starts_with("sandbox.podman_path: "), "{e}");
    }
}
