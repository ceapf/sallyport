//! `sally doctor` for M1 (architect Q106): host facts only. It starts nothing, pulls nothing and
//! touches no network. Each check is a pure function over a fact the thin [`facts`] reads.
//! `scripts/doctor.sh` stays the developer preflight. TODO(#DOCTOR_ISSUE): the container-backed
//! checks (a test container, the limits bind, runtime provenance) come with M6 task 4.

use std::io::Read as _;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use sally_core::paths::Paths;

use crate::commands::Out;
use crate::{EXIT_FAILED, EXIT_OK, EXIT_REFUSED, clean};

/// `CGROUP2_SUPER_MAGIC`.
const CGROUP2_MAGIC: i64 = 0x6367_7270;
/// The oldest kernel the launch scan works on (`STATX_MNT_ID`).
const MIN_KERNEL: (u32, u32) = (5, 8);

/// One check's verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Ready.
    Pass(String),
    /// Sallyport refuses to run, or runs unsafely, until this is fixed.
    Fail(String),
    /// Worth knowing; not a failure.
    Note(String),
    /// The fact could not be read.
    Unknown(String),
}

/// What `doctor` looks at, read once.
#[derive(Debug, Clone)]
pub struct Facts {
    /// `statfs("/sys/fs/cgroup").f_type`.
    pub cgroup_fs: Result<i64, String>,
    /// `/proc/sys/kernel/osrelease`.
    pub kernel: Result<String, String>,
    /// `$XDG_RUNTIME_DIR`: `None` when unset or relative; else its owner, mode and whether it is
    /// a directory (not following a symlink).
    pub runtime_dir: Option<Result<(u32, u32, bool), String>>,
    /// The effective uid.
    pub euid: u32,
    /// Whether `~/.config/containers/storage.conf` exists.
    pub storage_conf: bool,
}

/// The cgroup version: v2 or FAIL (Podman drops limits silently on v1).
#[must_use]
pub fn cgroup(fs: &Result<i64, String>) -> Verdict {
    match fs {
        Ok(t) if *t == CGROUP2_MAGIC => Verdict::Pass("cgroup v2".into()),
        Ok(_) => Verdict::Fail(
            "/sys/fs/cgroup is not cgroup v2: resource limits would be dropped".into(),
        ),
        Err(e) => Verdict::Unknown(format!("/sys/fs/cgroup: {e}")),
    }
}

/// The kernel release: at least 5.8.
#[must_use]
pub fn kernel(release: &Result<String, String>) -> Verdict {
    let r = match release {
        Ok(r) => r.trim(),
        Err(e) => return Verdict::Unknown(format!("kernel release: {e}")),
    };
    let mut parts = r.split(|c: char| !c.is_ascii_digit());
    let num = |p: Option<&str>| p.and_then(|s| s.parse::<u32>().ok());
    match (num(parts.next()), num(parts.next())) {
        (Some(major), Some(minor)) if (major, minor) >= MIN_KERNEL => {
            Verdict::Pass(format!("kernel {r}"))
        }
        (Some(_), Some(_)) => Verdict::Fail(format!(
            "kernel {r} is older than {}.{}",
            MIN_KERNEL.0, MIN_KERNEL.1
        )),
        _ => Verdict::Unknown(format!("kernel release {r:?} is not a version")),
    }
}

/// `$XDG_RUNTIME_DIR`: set, absolute, a directory owned by `euid`, mode 0700.
#[must_use]
pub fn runtime_dir(dir: &Option<Result<(u32, u32, bool), String>>, euid: u32) -> Verdict {
    match dir {
        None => Verdict::Fail("$XDG_RUNTIME_DIR is not set to an absolute path".into()),
        Some(Err(e)) => Verdict::Unknown(format!("$XDG_RUNTIME_DIR: {e}")),
        Some(Ok((_, _, false))) => Verdict::Fail("$XDG_RUNTIME_DIR is not a directory".into()),
        Some(Ok((owner, _, true))) if *owner != euid => {
            Verdict::Fail("$XDG_RUNTIME_DIR is owned by another user".into())
        }
        Some(Ok((_, mode, true))) if mode & 0o7777 != 0o700 => Verdict::Fail(format!(
            "$XDG_RUNTIME_DIR has mode {:04o}; it must be 0700",
            mode & 0o7777
        )),
        Some(Ok(_)) => Verdict::Pass("$XDG_RUNTIME_DIR is private".into()),
    }
}

/// Not root: `sallyd` refuses to run as root.
#[must_use]
pub fn not_root(euid: u32) -> Verdict {
    if euid == 0 {
        Verdict::Fail("running as root; sallyd refuses root".into())
    } else {
        Verdict::Pass("not root".into())
    }
}

/// A storage.conf may move Podman's graphroot (ARCHITECTURE §4): reported, not failed.
#[must_use]
pub fn storage_conf(exists: bool) -> Verdict {
    if exists {
        Verdict::Note(
            "~/.config/containers/storage.conf exists: a non-default graphroot must move to the \
             default location"
                .into(),
        )
    } else {
        Verdict::Pass("default container storage".into())
    }
}

/// Every verdict, in order, and the exit code: 2 if a fact could not be read, else 1 if a
/// check failed, else 0.
#[must_use]
pub fn verdicts(f: &Facts) -> (Vec<Verdict>, u8) {
    let all = vec![
        cgroup(&f.cgroup_fs),
        kernel(&f.kernel),
        runtime_dir(&f.runtime_dir, f.euid),
        not_root(f.euid),
        storage_conf(f.storage_conf),
    ];
    let code = if all.iter().any(|v| matches!(v, Verdict::Unknown(_))) {
        EXIT_FAILED
    } else if all.iter().any(|v| matches!(v, Verdict::Fail(_))) {
        EXIT_REFUSED
    } else {
        EXIT_OK
    };
    (all, code)
}

/// `sally doctor`: one line per check.
pub fn doctor(f: &Facts, o: &mut Out<'_>) -> u8 {
    let (all, code) = verdicts(f);
    for v in all {
        let (tag, msg) = match &v {
            Verdict::Pass(m) => ("PASS", m),
            Verdict::Fail(m) => ("FAIL", m),
            Verdict::Note(m) => ("NOTE", m),
            Verdict::Unknown(m) => ("????", m),
        };
        let _ = writeln!(o.out, "{tag} {}", clean::line(msg).text);
    }
    code
}

/// Reads the facts. Blocking; spawns nothing.
#[must_use]
pub fn facts(paths: &Paths) -> Facts {
    let cgroup_fs = rustix::fs::statfs("/sys/fs/cgroup")
        .map(|s| {
            #[allow(clippy::useless_conversion)] // `f_type`'s width differs between targets.
            i64::from(s.f_type)
        })
        .map_err(|e| e.to_string());
    let runtime_dir = paths.runtime().ok().map(|d| {
        std::fs::symlink_metadata(d)
            .map(|m| (m.uid(), m.permissions().mode(), m.is_dir()))
            .map_err(|e| e.to_string())
    });
    Facts {
        cgroup_fs,
        kernel: read_small(Path::new("/proc/sys/kernel/osrelease")),
        runtime_dir,
        euid: rustix::process::geteuid().as_raw(),
        storage_conf: paths.config_home().join("containers/storage.conf").exists(),
    }
}

fn read_small(p: &Path) -> Result<String, String> {
    let mut s = String::new();
    std::fs::File::open(p)
        .and_then(|f| f.take(256).read_to_string(&mut s))
        .map_err(|e| e.to_string())?;
    Ok(s)
}

#[cfg(test)]
#[path = "doctor_tests.rs"]
mod tests;
