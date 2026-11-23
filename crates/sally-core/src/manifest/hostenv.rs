//! Facts about the host that validation depends on: home directory, XDG dirs, Podman storage,
//! CPU count, and RAM. Gathered once by the caller and passed in, so validation is a function of
//! its inputs and tests can point it at a temporary home.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::config::{Config, PODMAN_PATH_FIELD, RUNTIME_PATH_FIELD};

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
    /// The binaries `config.toml` names (the runtime, podman). The folder each is in, as written
    /// and as resolved, is denylisted: the host runs it on every launch (MANIFEST_SPEC §2).
    pub configured_binaries: Vec<ConfiguredBinary>,
    /// Filesystem kinds a mount root may not lie on, wherever they are mounted: on WSL, 9p and
    /// virtiofs (Windows drives and the WSL driver share; [`refused_fs_kinds`]). Empty elsewhere.
    pub refused_fs_kinds: Vec<FsKind>,
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

/// A binary a `config.toml` setting names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfiguredBinary {
    /// The path as the setting gives it (absolute: `parse_config` refuses a relative one).
    pub path: PathBuf,
    /// The setting's dotted name (`sandbox.runtime_path`, `sandbox.podman_path`).
    pub setting: &'static str,
}

/// The binaries `config` names, in a fixed order: the runtime, then podman. A setting left to
/// its default names none: the default runtime lies under the data home's `sallyport/` folder,
/// already a rule, and the default podman is a root-owned system binary.
#[must_use]
pub fn configured_binaries(config: &Config) -> Vec<ConfiguredBinary> {
    [
        (&config.sandbox.runtime_path, RUNTIME_PATH_FIELD),
        (&config.sandbox.podman_path, PODMAN_PATH_FIELD),
    ]
    .into_iter()
    .filter_map(|(path, setting)| {
        path.as_ref().map(|p| ConfiguredBinary {
            path: p.clone(),
            setting,
        })
    })
    .collect()
}

/// A filesystem kind: the type name the mount table gives it (its part before any `.`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsKind {
    /// The type, as `/proc/self/mountinfo` writes it (`9p`, `virtiofs`).
    pub name: &'static str,
}

/// 9p. On WSL, Windows drives are 9p mounts, and so is the driver share
/// (docs/dev/PROBE_NOTES.md); the type alone does not tell them apart, so every 9p is refused.
pub const V9FS: FsKind = FsKind { name: "9p" };

/// virtiofs, which newer WSL builds can serve Windows drives over. Its statfs number is FUSE's,
/// shared by every FUSE filesystem; its type name is its own, and other FUSE types are not
/// refused.
pub const VIRTIOFS: FsKind = FsKind { name: "virtiofs" };

/// Where the kernel names its release; on WSL it contains `microsoft`.
const OSRELEASE: &str = "/proc/sys/kernel/osrelease";
/// Present when WSL's Windows interop is registered.
const WSL_INTEROP: &str = "/proc/sys/fs/binfmt_misc/WSLInterop";

/// The filesystem kinds refused as mount roots, from the kernel release text and whether WSL's
/// interop entry is present: on WSL (either signal) [`V9FS`] and [`VIRTIOFS`], else none. A
/// further signal is added only once it is probed (docs/dev/PROBE_NOTES.md), and only ever adds
/// refusals (RT-FS-11: Windows drives refused by type name wherever they are mounted).
// TODO(#281): not probed on a WSL that serves Windows drives over virtiofs; a WSL that neither
// signal shows (a release without "microsoft" and interop off) keeps only the `/mnt` rule.
#[must_use]
pub fn refused_fs_kinds(osrelease: &str, interop: bool) -> Vec<FsKind> {
    if interop || osrelease.to_ascii_lowercase().contains("microsoft") {
        vec![V9FS, VIRTIOFS]
    } else {
        Vec::new()
    }
}

/// The kernel release text at `path`, at most 4 KiB; any failure is [`HostEnvError::OsRelease`]
/// with its cause.
fn read_release(path: &Path) -> Result<String, HostEnvError> {
    use std::io::Read;
    let mut s = String::new();
    std::fs::File::open(path)
        .and_then(|f| f.take(4096).read_to_string(&mut s))
        .map_err(|e| HostEnvError::OsRelease(e.to_string()))?;
    Ok(s)
}

/// Whether WSL's interop entry is present. Only a clean not-found is absence: any other answer
/// counts as present (fail closed). Where `binfmt_misc` is an automount point (systemd), the
/// lookup may mount it.
fn interop_present(path: &Path) -> bool {
    !matches!(std::fs::symlink_metadata(path), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
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
    /// `/proc/sys/kernel/osrelease` was unreadable: whether this is WSL cannot be told, and
    /// it is never assumed not to be.
    #[error("cannot read the kernel release from /proc/sys/kernel/osrelease: {0}")]
    OsRelease(String),
}

impl HostEnv {
    /// Reads the current process environment and `/proc`, and takes the binaries `config` names
    /// ([`configured_binaries`]). The caller passes the `config.toml` it read
    /// (`crate::config::read_config`), so `sallyd` and the CLI derive the same facts.
    ///
    /// Podman storage defaults to the rootless graphroot (`$XDG_DATA_HOME/containers/storage`)
    /// plus the rootful one (`/var/lib/containers/storage`); callers that know the real
    /// graphroot from `podman info` should append it.
    ///
    /// # Errors
    /// [`HostEnvError`] if the home directory, the RAM size or the kernel release (whether this
    /// is WSL) cannot be determined. Validation must
    /// not proceed with a guessed home: the denylist depends on it.
    pub fn from_process(config: &Config) -> Result<Self, HostEnvError> {
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
            configured_binaries: configured_binaries(config),
            refused_fs_kinds: refused_fs_kinds(
                &read_release(Path::new(OSRELEASE))?,
                interop_present(Path::new(WSL_INTEROP)),
            ),
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

    /// Each binary setting that is set, in order, with its name; unset settings name none.
    #[test]
    fn the_configured_binaries_come_from_their_settings() {
        let mut c = Config::default();
        assert_eq!(configured_binaries(&c), Vec::new());
        c.sandbox.podman_path = Some("/opt/p/podman".into());
        let podman = ConfiguredBinary {
            path: "/opt/p/podman".into(),
            setting: "sandbox.podman_path",
        };
        assert_eq!(configured_binaries(&c), std::slice::from_ref(&podman));
        c.sandbox.runtime_path = Some("/opt/r/crun".into());
        let runtime = ConfiguredBinary {
            path: "/opt/r/crun".into(),
            setting: "sandbox.runtime_path",
        };
        assert_eq!(configured_binaries(&c), [runtime, podman]);
        let env = HostEnv::from_process(&c).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(env.configured_binaries, configured_binaries(&c));
    }

    /// The two type names, pinned against the names the kernel registers (`9p`, `virtiofs`).
    #[test]
    fn the_refused_type_names_are_pinned() {
        assert_eq!(V9FS.name, "9p");
        assert_eq!(VIRTIOFS.name, "virtiofs");
        assert_eq!(OSRELEASE, "/proc/sys/kernel/osrelease");
        assert_eq!(WSL_INTEROP, "/proc/sys/fs/binfmt_misc/WSLInterop");
    }

    /// WSL when the kernel release says so (any case) or the interop entry is present; 9p and
    /// virtiofs are then refused. Neither: nothing.
    #[test]
    fn wsl_is_told_by_its_release_or_its_interop_entry() {
        let release = "6.18.0-microsoft-standard-WSL2\n";
        let wsl = [V9FS, VIRTIOFS];
        assert_eq!(refused_fs_kinds(release, false), wsl);
        assert_eq!(refused_fs_kinds("6.18.0-Microsoft\n", false), wsl);
        assert_eq!(refused_fs_kinds("6.8.0-45-generic\n", true), wsl);
        assert_eq!(refused_fs_kinds(release, true), wsl);
        assert_eq!(refused_fs_kinds("6.8.0-45-generic\n", false), Vec::new());
        assert_eq!(refused_fs_kinds("", false), Vec::new());
    }

    /// Only a clean not-found is absence; an entry of any type, or one that cannot be looked
    /// at, is presence.
    #[test]
    fn the_interop_entry_is_absent_only_when_not_found() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/tmp")
            .join(format!("sp-interop-{}", std::process::id()));
        struct Gone(PathBuf);
        impl Drop for Gone {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{e}"));
        let _gone = Gone(dir.clone());
        assert!(!interop_present(&dir.join("absent")));
        std::fs::write(dir.join("file"), "").unwrap_or_else(|e| panic!("{e}"));
        assert!(interop_present(&dir.join("file")));
        assert!(interop_present(&dir));
        // A lookup through a file fails with ENOTDIR, not ENOENT: present.
        assert!(interop_present(&dir.join("file/x")));
        // The release reader names its cause.
        let e = read_release(&dir.join("absent")).unwrap_err();
        assert!(
            matches!(&e, HostEnvError::OsRelease(m) if !m.is_empty()),
            "{e}"
        );
        std::fs::write(dir.join("release"), "6.8.0-generic\n").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            read_release(&dir.join("release")).ok().as_deref(),
            Some("6.8.0-generic\n")
        );
    }

    #[test]
    fn from_process_works_on_this_host() {
        let env = HostEnv::from_process(&Config::default());
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
        // The kinds, from an independent read of this host's two signals.
        let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
        let interop = Path::new("/proc/sys/fs/binfmt_misc/WSLInterop")
            .try_exists()
            .unwrap_or(true);
        assert_eq!(env.refused_fs_kinds, refused_fs_kinds(&release, interop));
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
        let env = HostEnv::from_process(&Config::default()).unwrap_or_else(|e| panic!("{e}"));
        if want_home.is_empty() {
            // No HOME: the passwd home is the home, and not also "another" home.
            assert_eq!(env.home, passwd);
            assert_eq!(env.other_homes, Vec::<PathBuf>::new());
        } else {
            assert_eq!(env.home, PathBuf::from(&want_home));
            assert_eq!(env.other_homes, [passwd]);
        }
        // The parent sets an absolute state home: the field is that variable.
        assert_eq!(
            env.xdg_state_home,
            Some(PathBuf::from("/sp-elsewhere/state"))
        );
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
            .env(CHILD, home.unwrap_or(""))
            .env("XDG_STATE_HOME", "/sp-elsewhere/state");
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
