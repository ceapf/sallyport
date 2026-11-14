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
//! - `--hooks-dir` naming an empty Sallyport-owned directory and `--default-mounts-file` naming
//!   an empty Sallyport-owned file (both in the checked argv; the rootless `mounts.conf` is read
//!   through the flag, not through `containers.conf`, probed in Task 6b);
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

/// The private, empty directories of the state directory: the hooks directory (`--hooks-dir`),
/// podman's `XDG_CONFIG_HOME` and podman's `HOME`. Each is checked empty before every launch, so
/// nothing podman would read from them can appear.
const EMPTY_DIRS: [&str; 3] = ["hooks", "config", "home"];

/// Why hermetic podman could not be set up.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PodmanError {
    /// A binary failed the ownership checks or was not found.
    #[error(transparent)]
    Binary(#[from] ConfigError),
    /// A binary podman needs was not found.
    #[error("podman helper {0}: not found in any of {1:?}")]
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

/// Field names for helper binaries in errors: they come from fixed system paths, not settings.
const INIT_FIELD: &str = "podman helper catatonit";
const CONMON_FIELD: &str = "podman helper conmon";

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
    state: PathBuf,
    conf_text: String,
    env: Vec<(OsString, OsString)>,
    /// The checked `catatonit` that `containers.conf` names as `init_path`.
    init: PathBuf,
}

impl Podman {
    /// Prepares `state` (`~/.local/share/sallyport/podman`, created 0700): an empty `hooks/`, an
    /// empty `config/` (the `XDG_CONFIG_HOME` podman sees), an empty `mounts.conf` and a freshly
    /// written `containers.conf`. Performs blocking I/O.
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
            init: first_trusted(INIT_FIELD, &INIT_CANDIDATES)?,
            conmon: first_trusted(CONMON_FIELD, &CONMON_CANDIDATES)?,
        };
        private_dir(state)?;
        for d in EMPTY_DIRS {
            let d = state.join(d);
            private_dir(&d)?;
            ensure_empty(&d)?;
        }
        let text = containers_conf(&state.join("hooks"), &bins)?;
        replace_0600(state, "containers.conf", text.as_bytes())?;
        replace_0600(state, "mounts.conf", b"")?;
        let p = Self {
            bin: podman,
            env: Self::env(host, state),
            state: state.to_owned(),
            conf_text: text,
            init: bins.init,
        };
        p.recheck()?;
        Ok(p)
    }

    /// The complete environment of every podman process: `HOME` (the empty `home/` of `state`,
    /// never the host home: podman reads `~/.config/containers/mounts.conf` from `HOME` whatever
    /// `--default-mounts-file` says, found by the OCI config verifier in Task 14), the host's
    /// `XDG_RUNTIME_DIR`, `XDG_DATA_HOME` (the host's, else `<host home>/.local/share`, so the
    /// user's image store is found), a root-owned `PATH`, `CONTAINERS_CONF` and
    /// `XDG_CONFIG_HOME`. Nothing else, in particular no `CONTAINERS_CONF_OVERRIDE`,
    /// `CONTAINER_HOST`, `DOCKER_HOST`, `CONTAINERS_STORAGE_CONF`, `TMPDIR` or proxy variable.
    #[must_use]
    pub fn env(host: &PodmanHost, state: &Path) -> Vec<(OsString, OsString)> {
        let data = host
            .xdg_data_home
            .clone()
            .unwrap_or_else(|| host.home.join(".local/share"));
        vec![
            ("HOME".into(), state.join("home").into_os_string()),
            (
                "XDG_RUNTIME_DIR".into(),
                host.xdg_runtime_dir.clone().into_os_string(),
            ),
            ("PATH".into(), PODMAN_PATH_VAR.into()),
            (
                "CONTAINERS_CONF".into(),
                state.join("containers.conf").into_os_string(),
            ),
            (
                "XDG_CONFIG_HOME".into(),
                state.join("config").into_os_string(),
            ),
            ("XDG_DATA_HOME".into(), data.into_os_string()),
        ]
    }

    /// The checked podman binary.
    #[must_use]
    pub fn bin(&self) -> &Path {
        &self.bin
    }

    /// The empty hooks directory, for `--hooks-dir`.
    #[must_use]
    pub fn hooks_dir(&self) -> PathBuf {
        self.state.join("hooks")
    }

    /// The empty mounts file, for `--default-mounts-file`.
    #[must_use]
    pub fn mounts_file(&self) -> PathBuf {
        self.state.join("mounts.conf")
    }

    /// The checked `catatonit` (`init_path` in `containers.conf`): the source of every
    /// container's `/run/podman-init` (architect Q100).
    #[must_use]
    pub fn init_path(&self) -> &Path {
        &self.init
    }

    /// The environment passed to podman.
    #[must_use]
    pub fn environment(&self) -> &[(OsString, OsString)] {
        &self.env
    }

    /// Re-checks, before each launch, everything podman reads from Sallyport's state: the state
    /// directory is private, `hooks/` and `config/` are empty, `mounts.conf` is empty and
    /// `containers.conf` is exactly what was generated; and the podman binary still passes its
    /// ownership checks. Performs blocking I/O.
    ///
    /// # Errors
    /// [`PodmanError`] naming what changed.
    pub fn recheck(&self) -> Result<(), PodmanError> {
        private_dir(&self.state)?;
        for d in EMPTY_DIRS {
            let d = self.state.join(d);
            private_dir(&d)?;
            ensure_empty(&d)?;
        }
        check_private_file(&self.mounts_file(), b"")?;
        check_private_file(
            &self.state.join("containers.conf"),
            self.conf_text.as_bytes(),
        )?;
        check_trusted_binary(&self.bin, "sandbox.podman_path")?;
        Ok(())
    }

    /// A podman command with the hermetic environment, no stdin, killed if dropped, run from the
    /// private state directory: the container's conmon inherits the working directory and writes
    /// into it (an `oom` marker when the sandbox is OOM-killed), never into `sallyd`'s own.
    #[must_use]
    pub fn command(&self) -> tokio::process::Command {
        let mut c = tokio::process::Command::new(&self.bin);
        c.env_clear()
            .envs(self.env.iter().map(|(k, v)| (k, v)))
            .current_dir(&self.state)
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

/// A regular file (not a symlink) owned by the current user, mode 0600, holding exactly
/// `want`.
fn check_private_file(path: &Path, want: &[u8]) -> Result<(), PodmanError> {
    let meta = std::fs::symlink_metadata(path).map_err(io_err(path))?;
    if !meta.is_file()
        || meta.uid() != rustix::process::geteuid().as_raw()
        || meta.permissions().mode() & 0o777 != 0o600
    {
        return dir_err(
            path,
            "must be a regular file owned by the current user, mode 0600",
        );
    }
    if std::fs::read(path).map_err(io_err(path))? != want {
        return dir_err(path, "changed since sallyd wrote it");
    }
    Ok(())
}

/// Writes `name` in `dir` through a fresh temporary file and a rename (never through an
/// existing file or symlink).
fn replace_0600(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), PodmanError> {
    let tmp = dir.join(format!("{name}.tmp"));
    let target = dir.join(name);
    let _ = std::fs::remove_file(&tmp);
    write_new_0600(&tmp, bytes)?;
    std::fs::rename(&tmp, &target).map_err(io_err(&target))
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
        let env = Podman::env(&host, Path::new("/s"));
        let pairs: Vec<(&str, &str)> = env
            .iter()
            .map(|(k, v)| (k.to_str().unwrap(), v.to_str().unwrap()))
            .collect();
        // HOME is Sallyport's own empty directory, never the host home: podman reads the user's
        // `~/.config/containers/mounts.conf` from it (Task 14, architect Q118). The image store
        // stays where it is through XDG_DATA_HOME, which is always passed.
        assert_eq!(
            pairs,
            [
                ("HOME", "/s/home"),
                ("XDG_RUNTIME_DIR", "/run/user/1000"),
                ("PATH", PODMAN_PATH_VAR),
                ("CONTAINERS_CONF", "/s/containers.conf"),
                ("XDG_CONFIG_HOME", "/s/config"),
                ("XDG_DATA_HOME", "/home/u/.local/share"),
            ]
        );
        let with_data = Podman::env(
            &PodmanHost {
                xdg_data_home: Some("/d".into()),
                ..host
            },
            Path::new("/s"),
        );
        assert_eq!(
            with_data.last().map(|(k, v)| (k.to_str(), v.to_str())),
            Some((Some("XDG_DATA_HOME"), Some("/d")))
        );
        assert!(!with_data.iter().any(|(_, v)| v == "/home/u"));
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

    #[test]
    fn a_helper_is_the_first_candidate_that_exists_and_passes_the_checks() {
        let p = first_trusted("t", &["/nonexistent/a", "/bin/sh", "/usr/bin/env"]).unwrap();
        assert_eq!(p, std::fs::canonicalize("/bin/sh").unwrap());
        let e = first_trusted("t", &["/nonexistent/a"]).unwrap_err();
        assert!(matches!(e, PodmanError::Missing("t", _)), "{e}");
    }

    /// A private scratch directory, removed (after restoring write access) on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("sp-podman-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
            Self(p)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The state `Podman::setup` leaves, without the host's catatonit and conmon.
    fn podman_at(state: &Path) -> Podman {
        private_dir(state).unwrap();
        for d in EMPTY_DIRS {
            private_dir(&state.join(d)).unwrap();
        }
        let text = containers_conf(&state.join("hooks"), &bins()).unwrap();
        replace_0600(state, "containers.conf", text.as_bytes()).unwrap();
        replace_0600(state, "mounts.conf", b"").unwrap();
        let host = PodmanHost {
            home: "/home/u".into(),
            xdg_runtime_dir: "/run/user/1000".into(),
            xdg_data_home: None,
        };
        Podman {
            bin: "/bin/sh".into(),
            env: Podman::env(&host, state),
            state: state.to_owned(),
            conf_text: text,
            init: bins().init,
        }
    }

    fn dir_msg(r: Result<(), PodmanError>) -> String {
        match r {
            Err(PodmanError::Dir { msg, .. }) => msg,
            other => panic!("want a Dir error, got {other:?}"),
        }
    }

    #[test]
    fn the_accessors_name_the_state_files() {
        let s = Scratch::new("acc");
        let p = podman_at(&s.0);
        assert_eq!(p.hooks_dir(), s.0.join("hooks"));
        assert_eq!(p.mounts_file(), s.0.join("mounts.conf"));
        assert_eq!(p.environment(), p.env.as_slice());
        assert_eq!(p.environment().len(), 6);
        assert_eq!(p.bin(), Path::new("/bin/sh"));
        assert_eq!(p.init_path(), bins().init);
    }

    /// The re-check passes on the state setup wrote and refuses each kind of tampering.
    #[test]
    fn recheck_refuses_every_change_to_the_state() {
        type Tamper = fn(&Path);
        let cases: [(&str, Tamper, &str); 11] = [
            ("state mode", |s| chmod(s, 0o750), "must be mode 0700"),
            (
                "hooks entry",
                |s| touch(&s.join("hooks/x")),
                "must be empty",
            ),
            (
                "config entry",
                |s| touch(&s.join("config/x")),
                "must be empty",
            ),
            // podman's HOME: a `.config/containers/mounts.conf` there would add mounts (Q118).
            (
                "home entry",
                |s| touch(&s.join("home/.config")),
                "must be empty",
            ),
            ("home mode", |s| chmod(&s.join("home"), 0o755), "mode 0700"),
            (
                "mounts body",
                |s| put(&s.join("mounts.conf"), b"x"),
                "changed since",
            ),
            (
                "conf body",
                |s| put(&s.join("containers.conf"), b"x"),
                "changed since",
            ),
            (
                "mounts mode",
                |s| chmod(&s.join("mounts.conf"), 0o644),
                "mode 0600",
            ),
            (
                "mounts dir",
                |s| as_dir(&s.join("mounts.conf")),
                "mode 0600",
            ),
            (
                "mounts link",
                |s| as_link(&s.join("mounts.conf")),
                "mode 0600",
            ),
            (
                "hooks link",
                |s| as_link(&s.join("hooks")),
                "is not a directory",
            ),
        ];
        for (what, tamper, want) in cases {
            let s = Scratch::new("recheck");
            let p = podman_at(&s.0);
            p.recheck()
                .unwrap_or_else(|e| panic!("{what}: control: {e}"));
            tamper(&s.0);
            let msg = dir_msg(p.recheck());
            assert!(msg.contains(want), "{what}: {msg}");
        }
        let s = Scratch::new("recheck-bin");
        let mut p = podman_at(&s.0);
        p.bin = "/nonexistent/podman".into();
        assert!(matches!(p.recheck(), Err(PodmanError::Binary(_))));
    }

    fn chmod(p: &Path, mode: u32) {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn touch(p: &Path) {
        std::fs::write(p, b"").unwrap();
    }

    /// Rewrites `p` keeping its mode 0600, so only the bytes differ.
    fn put(p: &Path, bytes: &[u8]) {
        std::fs::write(p, bytes).unwrap();
        chmod(p, 0o600);
    }

    /// Replaces the file `p` with a 0600 directory of the same name.
    fn as_dir(p: &Path) {
        std::fs::remove_file(p).unwrap();
        std::fs::DirBuilder::new().mode(0o600).create(p).unwrap();
    }

    /// Replaces `p` with a symlink to a copy that would pass every other check.
    fn as_link(p: &Path) {
        let real = p.with_extension("real");
        std::fs::rename(p, &real).unwrap();
        std::os::unix::fs::symlink(&real, p).unwrap();
    }

    #[test]
    fn private_dir_creates_0700_and_keeps_an_existing_private_dir() {
        let s = Scratch::new("private");
        let d = s.0.join("new");
        private_dir(&d).unwrap();
        let mode = std::fs::metadata(&d).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        private_dir(&d).unwrap();
        // A failure other than "exists" is reported as itself, not as the later lstat's NotFound.
        chmod(&s.0, 0o500);
        let e = private_dir(&s.0.join("other"));
        chmod(&s.0, 0o700);
        if !rustix::process::geteuid().is_root() {
            match e {
                Err(PodmanError::Io { source, .. }) => {
                    assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
                }
                other => panic!("{other:?}"),
            }
        }
    }

    /// Another user's directory is refused even when its mode would pass (`/root` is root's,
    /// 0700 on supported hosts).
    #[test]
    fn a_directory_of_another_user_is_refused() {
        if rustix::process::geteuid().is_root() {
            return;
        }
        let root_home = Path::new("/root");
        let meta = std::fs::symlink_metadata(root_home).unwrap();
        assert_eq!((meta.uid(), meta.permissions().mode() & 0o077), (0, 0));
        assert!(dir_msg(private_dir(root_home)).contains("not owned by the current user"));
    }

    #[test]
    fn replace_writes_a_fresh_0600_file_and_never_follows_a_link() {
        let s = Scratch::new("replace");
        let outside = s.0.join("outside");
        std::fs::write(&outside, b"keep").unwrap();
        std::os::unix::fs::symlink(&outside, s.0.join("f")).unwrap();
        std::os::unix::fs::symlink(&outside, s.0.join("f.tmp")).unwrap();
        replace_0600(&s.0, "f", b"new").unwrap();
        assert_eq!(std::fs::read(&outside).unwrap(), b"keep");
        assert_eq!(std::fs::read(s.0.join("f")).unwrap(), b"new");
        let meta = std::fs::symlink_metadata(s.0.join("f")).unwrap();
        assert!(meta.is_file());
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert!(write_new_0600(&s.0.join("f"), b"x").is_err(), "create_new");
    }
}
