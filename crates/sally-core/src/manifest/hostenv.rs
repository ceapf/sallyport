//! Facts about the host that validation depends on: home directory, XDG dirs, Podman storage,
//! CPU count, and RAM. Gathered once by the caller and passed in, so validation is a function of
//! its inputs and tests can point it at a temporary home.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Host facts used by the validator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostEnv {
    /// The user's home directory (absolute); `~` expands to this.
    pub home: PathBuf,
    /// Other homes that get the same protection, e.g. the passwd home when `$HOME` points
    /// elsewhere (systemd units, `sudo -E`, CI wrappers).
    pub other_homes: Vec<PathBuf>,
    /// `$XDG_CONFIG_HOME`, if set to an absolute path.
    pub xdg_config_home: Option<PathBuf>,
    /// `$XDG_DATA_HOME`, if set to an absolute path.
    pub xdg_data_home: Option<PathBuf>,
    /// `$XDG_STATE_HOME`, if set to an absolute path.
    pub xdg_state_home: Option<PathBuf>,
    /// `$XDG_RUNTIME_DIR`, if set to an absolute path.
    pub xdg_runtime_dir: Option<PathBuf>,
    /// Podman storage roots (graphroot). Mounting these or any ancestor is refused.
    pub podman_storage: Vec<PathBuf>,
    /// Folders the environment moves or names for code the host runs or loads (`$CARGO_HOME`,
    /// `$GNUPGHOME`, every absolute `$PATH` entry, …). Each is denylisted like
    /// a home folder of the built-in list (MANIFEST_SPEC §2).
    pub env_dirs: Vec<EnvDir>,
    /// Logical CPUs available to the user.
    pub nproc: u32,
    /// Total host RAM in bytes.
    pub mem_bytes: u64,
}

/// A folder named by an environment variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvDir {
    /// The folder (absolute, as the variable gives it, `bin`/`pkg` appended for `$GOPATH`).
    pub path: PathBuf,
    /// The variable's name, without `$` (`PATH`, `CARGO_HOME`, …).
    pub var: &'static str,
}

/// Variables whose value is one folder the host runs or loads code from, or keeps credentials
/// in (the env-moved forms of the built-in home folders), each documented by its tool, or read
/// by its source, as one directory (pipx's two: `src/pipx/paths.py` at commit 3ce2b3c7, read
/// through `get_expanded_environ`, never split).
// TODO(#232): more tools' variables, each to be checked against the tool's own documentation
// or source.
const SINGLE_DIR_VARS: &[&str] = &[
    "CARGO_HOME",
    "RUSTUP_HOME",
    "GNUPGHOME",
    "NVM_DIR",
    "PYENV_ROOT",
    "XDG_CACHE_HOME",
    "GOBIN",
    "DOCKER_CONFIG",
    "ZDOTDIR",            // zsh startup files
    "PNPM_HOME",          // pnpm's global bin
    "VOLTA_HOME",         // .volta
    "BUN_INSTALL",        // .bun
    "PYTHONUSERBASE",     // .local: user site-packages and scripts
    "PIPX_HOME",          // .local/share/pipx
    "PIPX_BIN_DIR",       // .local/bin
    "UV_TOOL_DIR",        // .local/share/uv/tools
    "GRADLE_USER_HOME",   // .gradle
    "PASSWORD_STORE_DIR", // .password-store
];

/// The folders the environment names, from `lookup` (a variable's value, if set): each
/// [`SINGLE_DIR_VARS`] value, `bin` and `pkg` under each `$GOPATH` element, and each `$PATH`
/// entry. Only absolute values count (a relative one names no fixed folder); the first of
/// repeated paths is kept. Every distinct entry is kept: the denylist bounds `$PATH` and
/// `$GOPATH` when it builds its rules.
pub(crate) fn env_dirs(lookup: impl Fn(&str) -> Option<OsString>) -> Vec<EnvDir> {
    let mut out: Vec<EnvDir> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut add = |path: PathBuf, var: &'static str| {
        if path.is_absolute() && seen.insert(path.clone()) {
            out.push(EnvDir { path, var });
        }
    };
    for var in SINGLE_DIR_VARS {
        if let Some(v) = lookup(var) {
            add(PathBuf::from(v), var);
        }
    }
    if let Some(v) = lookup("GOPATH") {
        for p in std::env::split_paths(&v) {
            add(p.join("bin"), "GOPATH");
            add(p.join("pkg"), "GOPATH");
        }
    }
    if let Some(v) = lookup("PATH") {
        for p in std::env::split_paths(&v) {
            add(p, "PATH");
        }
    }
    out
}

/// Why host facts could not be gathered.
#[derive(Debug, thiserror::Error)]
pub enum HostEnvError {
    /// Neither `$HOME` nor the passwd entry gave an absolute home directory.
    #[error(
        "cannot determine the home directory: $HOME is unset or relative and /etc/passwd has no entry"
    )]
    NoHome,
    /// `/proc/meminfo` was unreadable or lacked `MemTotal`.
    #[error("cannot read total memory from /proc/meminfo: {0}")]
    MemInfo(String),
}

impl HostEnv {
    /// Reads the current process environment and `/proc`.
    ///
    /// Podman storage defaults to the rootless graphroot (`$XDG_DATA_HOME/containers/storage`)
    /// plus the rootful one (`/var/lib/containers/storage`); callers that know the real
    /// graphroot from `podman info` should append it.
    ///
    /// # Errors
    /// [`HostEnvError`] if the home directory or RAM size cannot be determined. Validation must
    /// not proceed with a guessed home: the denylist depends on it.
    pub fn from_process() -> Result<Self, HostEnvError> {
        let abs_var = |name: &str| {
            std::env::var_os(name)
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
        };
        let passwd_home = home_from_passwd();
        let home = abs_var("HOME")
            .or_else(|| passwd_home.clone())
            .ok_or(HostEnvError::NoHome)?;
        let other_homes = passwd_home.into_iter().filter(|p| *p != home).collect();
        let xdg_config_home = abs_var("XDG_CONFIG_HOME");
        let xdg_data_home = abs_var("XDG_DATA_HOME");
        let data_home = xdg_data_home
            .clone()
            .unwrap_or_else(|| home.join(".local/share"));
        let podman_storage = vec![
            data_home.join("containers/storage"),
            PathBuf::from("/var/lib/containers/storage"),
        ];
        let nproc = std::thread::available_parallelism()
            .map_or(1, |n| u32::try_from(n.get()).unwrap_or(u32::MAX));
        Ok(Self {
            xdg_runtime_dir: abs_var("XDG_RUNTIME_DIR"),
            home,
            other_homes,
            xdg_config_home,
            xdg_data_home,
            xdg_state_home: abs_var("XDG_STATE_HOME"),
            podman_storage,
            env_dirs: env_dirs(|name| std::env::var_os(name)),
            nproc,
            mem_bytes: mem_total()?,
        })
    }
}

/// Home directory from `/etc/passwd`, for the current effective uid (owner of `/proc/self`).
fn home_from_passwd() -> Option<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let uid = std::fs::metadata("/proc/self").ok()?.uid().to_string();
    let passwd = read_bounded(Path::new("/etc/passwd"), 4 << 20)?;
    passwd.lines().find_map(|line| {
        let f: Vec<&str> = line.split(':').collect();
        match f.as_slice() {
            [_, _, u, _, _, home, ..] if *u == uid => {
                Some(PathBuf::from(home)).filter(|p| p.is_absolute())
            }
            _ => None,
        }
    })
}

fn mem_total() -> Result<u64, HostEnvError> {
    let info = read_bounded(Path::new("/proc/meminfo"), 1 << 20)
        .ok_or_else(|| HostEnvError::MemInfo("unreadable".into()))?;
    parse_meminfo(&info).ok_or_else(|| HostEnvError::MemInfo("no MemTotal line".into()))
}

/// `MemTotal:  16384000 kB` → bytes.
fn parse_meminfo(info: &str) -> Option<u64> {
    let line = info.lines().find(|l| l.starts_with("MemTotal:"))?;
    let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    kib.checked_mul(1024)
}

fn read_bounded(path: &Path, max: u64) -> Option<String> {
    use std::io::Read;
    let mut s = String::new();
    std::fs::File::open(path)
        .ok()?
        .take(max)
        .read_to_string(&mut s)
        .ok()?;
    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meminfo_parses_kib() {
        assert_eq!(
            parse_meminfo("MemTotal:  16 kB\nMemFree: 1 kB\n"),
            Some(16 * 1024)
        );
        assert_eq!(parse_meminfo("MemFree: 1 kB\n"), None);
        assert_eq!(parse_meminfo("MemTotal: 99999999999999999999 kB\n"), None);
    }

    fn dirs(vars: &[(&str, &str)]) -> Vec<(String, &'static str)> {
        let lookup = |name: &str| {
            vars.iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| OsString::from(v))
        };
        env_dirs(lookup)
            .into_iter()
            .map(|d| (d.path.display().to_string(), d.var))
            .collect()
    }

    /// The list of single-folder variables, pinned by name (the test below builds its
    /// expectation from the list, so it could not notice a dropped name).
    #[test]
    fn the_single_folder_variables_are_pinned() {
        assert_eq!(
            SINGLE_DIR_VARS,
            [
                "CARGO_HOME",
                "RUSTUP_HOME",
                "GNUPGHOME",
                "NVM_DIR",
                "PYENV_ROOT",
                "XDG_CACHE_HOME",
                "GOBIN",
                "DOCKER_CONFIG",
                "ZDOTDIR",
                "PNPM_HOME",
                "VOLTA_HOME",
                "BUN_INSTALL",
                "PYTHONUSERBASE",
                "PIPX_HOME",
                "PIPX_BIN_DIR",
                "UV_TOOL_DIR",
                "GRADLE_USER_HOME",
                "PASSWORD_STORE_DIR",
            ]
        );
        // The most folders the environment adds, as `paths.rs`'s `LIST_BOUNDS` doc states it.
        let bounds = super::super::paths::MAX_GOPATH_DIRS + super::super::paths::MAX_PATH_DIRS;
        assert_eq!(SINGLE_DIR_VARS.len() + bounds, 306);
    }

    /// The env-moved folders, `$GOPATH`'s `bin` and `pkg`, and `$PATH`'s entries; relative
    /// values and repeats are dropped, and every listed variable is read.
    #[test]
    fn env_dirs_reads_each_variable() {
        let mut vars: Vec<(&str, String)> = SINGLE_DIR_VARS
            .iter()
            .map(|v| (*v, format!("/e/{v}")))
            .collect();
        vars.push(("GOPATH", "/g1:rel:/g2".into()));
        vars.push((
            "PATH",
            "/usr/bin:bin::/e/CARGO_HOME:/usr/bin:/h/.venv/bin".into(),
        ));
        vars.push(("UNLISTED", "/nope".into()));
        let pairs: Vec<(&str, &str)> = vars.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let mut want: Vec<(String, &'static str)> = SINGLE_DIR_VARS
            .iter()
            .map(|v| (format!("/e/{v}"), *v))
            .collect();
        for (p, v) in [
            ("/g1/bin", "GOPATH"),
            ("/g1/pkg", "GOPATH"),
            ("/g2/bin", "GOPATH"),
            ("/g2/pkg", "GOPATH"),
            ("/usr/bin", "PATH"),
            ("/h/.venv/bin", "PATH"),
        ] {
            want.push((p.into(), v));
        }
        assert_eq!(dirs(&pairs), want);
        assert_eq!(dirs(&[("CARGO_HOME", "rel/cargo")]), Vec::new());
        assert_eq!(dirs(&[]), Vec::new());
    }

    #[test]
    fn from_process_works_on_this_host() {
        let env = HostEnv::from_process();
        assert!(env.is_ok(), "{env:?}");
        let env = env.unwrap_or_else(|_| unreachable!());
        assert!(env.home.is_absolute());
        assert!(env.nproc >= 1 && env.mem_bytes > 0);
        let info = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
        assert_eq!(Some(env.mem_bytes), parse_meminfo(&info));
        assert_eq!(env.env_dirs, env_dirs(|n| std::env::var_os(n)));
        let state = std::env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute());
        assert_eq!(env.xdg_state_home, state);
        assert!(
            env.env_dirs.iter().any(|d| d.var == "PATH"),
            "this host has a PATH"
        );
    }

    /// The passwd home of the current uid, from `getent` (independent of the code under test).
    fn getent_home() -> PathBuf {
        let uid = rustix::process::geteuid().as_raw().to_string();
        let out = std::process::Command::new("getent")
            .args(["passwd", &uid])
            .output()
            .unwrap_or_else(|e| panic!("getent: {e}"));
        let line = String::from_utf8_lossy(&out.stdout).into_owned();
        PathBuf::from(line.trim_end().split(':').nth(5).unwrap_or_default())
    }

    const CHILD: &str = "SP_HOSTENV_CHILD";

    /// Runs inside the child below, where `HOME` is what the parent set.
    #[test]
    fn home_and_other_homes_child() {
        let Some(want_home) = std::env::var_os(CHILD) else {
            return;
        };
        let passwd = getent_home();
        let env = HostEnv::from_process().unwrap_or_else(|e| panic!("{e}"));
        if want_home.is_empty() {
            // No HOME: the passwd home is the home, and not also "another" home.
            assert_eq!(env.home, passwd);
            assert_eq!(env.other_homes, Vec::<PathBuf>::new());
        } else {
            assert_eq!(env.home, PathBuf::from(&want_home));
            assert_eq!(env.other_homes, [passwd]);
        }
    }

    /// `HOME` wins and the passwd home of this uid is kept as another home; without `HOME` the
    /// passwd home is used. Each case runs in a child process with its own environment.
    #[test]
    fn home_comes_from_home_else_passwd() {
        assert!(getent_home().is_absolute(), "this uid needs a passwd entry");
        let exe = std::env::current_exe().unwrap_or_else(|e| panic!("{e}"));
        for home in [Some("/sp-elsewhere/home"), None] {
            let mut cmd = std::process::Command::new(&exe);
            cmd.args([
                "--exact",
                "manifest::hostenv::tests::home_and_other_homes_child",
                "--test-threads=1",
            ])
            .env(CHILD, home.unwrap_or(""));
            match home {
                Some(h) => cmd.env("HOME", h),
                None => cmd.env_remove("HOME"),
            };
            let out = cmd.output().unwrap_or_else(|e| panic!("{e}"));
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(out.status.success(), "{home:?}: {stdout}");
            assert!(stdout.contains("1 passed"), "{home:?}: {stdout}");
        }
    }
}
