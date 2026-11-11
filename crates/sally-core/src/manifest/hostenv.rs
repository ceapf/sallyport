//! Facts about the host that validation depends on: home directory, XDG dirs, Podman storage,
//! CPU count, and RAM. Gathered once by the caller and passed in, so validation is a function of
//! its inputs and tests can point it at a temporary home.

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
    /// `$XDG_RUNTIME_DIR`, if set to an absolute path.
    pub xdg_runtime_dir: Option<PathBuf>,
    /// Podman storage roots (graphroot). Mounting these or any ancestor is refused.
    pub podman_storage: Vec<PathBuf>,
    /// Logical CPUs available to the user.
    pub nproc: u32,
    /// Total host RAM in bytes.
    pub mem_bytes: u64,
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
            podman_storage,
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

    #[test]
    fn from_process_works_on_this_host() {
        let env = HostEnv::from_process();
        assert!(env.is_ok(), "{env:?}");
        let env = env.unwrap_or_else(|_| unreachable!());
        assert!(env.home.is_absolute());
        assert!(env.nproc >= 1 && env.mem_bytes > 0);
        let info = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
        assert_eq!(Some(env.mem_bytes), parse_meminfo(&info));
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
