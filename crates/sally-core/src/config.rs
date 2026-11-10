//! `config.toml`: host-side settings that are not part of any manifest (ARCHITECTURE §3.1).
//!
//! Strict like manifests (`deny_unknown_fields`), small, and parsed from trusted user files. The
//! one security-relevant setting today is the OCI runtime: Sallyport passes
//! `--runtime <sandbox.runtime_path>` on every `podman` call so it never depends on the distro
//! `crun`, which is the release build and never gets security updates (AMENDMENTS-02 B5).
//!
//! Blocking I/O: [`check_runtime_binary`] calls `stat`/`realpath`; async callers use
//! `spawn_blocking`.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Largest accepted `config.toml`.
pub const MAX_CONFIG_BYTES: usize = 64 * 1024;

/// Mode bits that let someone other than the owner change a file or directory.
const GROUP_OTHER_WRITE: u32 = 0o022;
/// Any execute bit.
const ANY_EXEC: u32 = 0o111;

/// The whole `config.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Sandbox driver settings.
    pub sandbox: SandboxConfig,
}

/// `[sandbox]`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SandboxConfig {
    /// Which OCI runtime family the argv builder targets (AMENDMENTS-01 §6.5). v1 ships `crun`.
    pub runtime: RuntimeKind,
    /// Absolute path of the runtime binary. `None` = [`default_runtime_path`], the pinned
    /// upstream build installed by `install.sh`.
    pub runtime_path: Option<PathBuf>,
    /// Absolute path of the `podman` binary. `None` = the first `podman` on `sallyd`'s `PATH`
    /// at startup. Either way it is resolved once and checked like the runtime (#11).
    pub podman_path: Option<PathBuf>,
}

/// OCI runtime family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeKind {
    /// `crun` (v1 default).
    #[default]
    Crun,
    /// gVisor `runsc` (M6 spike). Parsed so the error is specific; refused in v1.
    Runsc,
}

/// Why `config.toml` or the runtime binary was refused. Messages name the field.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// Input exceeds [`MAX_CONFIG_BYTES`].
    #[error("config.toml is larger than {MAX_CONFIG_BYTES} bytes")]
    TooLarge,
    /// Not valid TOML, or an unknown key or value.
    #[error("config.toml: {0}")]
    Parse(String),
    /// A value parsed but is not acceptable.
    #[error("{field}: {msg}")]
    Invalid {
        /// Dotted field path, e.g. `sandbox.runtime_path`.
        field: &'static str,
        /// What is wrong.
        msg: &'static str,
    },
    /// A trusted binary (the runtime, podman) failed a host check.
    #[error("{field}: {path}: {msg}")]
    Binary {
        /// The setting the binary came from, e.g. `sandbox.runtime_path`.
        field: &'static str,
        /// Host path as configured.
        path: String,
        /// What is wrong.
        msg: String,
    },
}

/// Parses `config.toml` text.
///
/// # Errors
/// [`ConfigError`] for oversize input, TOML errors, unknown keys, `runtime = "runsc"` (not
/// supported in v1), or a relative runtime path.
pub fn parse_config(text: &str) -> Result<Config, ConfigError> {
    if text.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::TooLarge);
    }
    let config: Config = toml::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))?;
    if config.sandbox.runtime == RuntimeKind::Runsc {
        return Err(ConfigError::Invalid {
            field: "sandbox.runtime",
            msg: "runsc is not supported in v1 (gVisor is the M6 spike); use crun",
        });
    }
    for (field, path) in [
        ("sandbox.runtime_path", &config.sandbox.runtime_path),
        ("sandbox.podman_path", &config.sandbox.podman_path),
    ] {
        if path.as_ref().is_some_and(|p| !p.is_absolute()) {
            return Err(ConfigError::Invalid {
                field,
                msg: "must be an absolute path",
            });
        }
    }
    Ok(config)
}

/// Where `install.sh` puts the pinned upstream runtime: `<data_home>/sallyport/bin/crun`.
#[must_use]
pub fn default_runtime_path(data_home: &Path) -> PathBuf {
    data_home.join("sallyport/bin/crun")
}

/// Checks that the runtime binary cannot be swapped by anyone but its owner or root: it
/// resolves to a regular executable file, and that file and **every directory above it** are
/// owned by the current user or root and not writable by group or others (whoever can rename
/// any ancestor can swap the whole subtree). Returns the realpath, which is what
/// `podman --runtime` gets; a symlink is followed (the install layout is `crun -> crun-<ver>`).
///
/// This narrows but cannot close the window between the check and podman's exec of the path;
/// the sandbox driver re-checks before every launch.
///
/// # Errors
/// [`ConfigError::Binary`] naming `sandbox.runtime_path`, the path and the failed check.
pub fn check_runtime_binary(path: &Path) -> Result<PathBuf, ConfigError> {
    check_trusted_binary(path, "sandbox.runtime_path")
}

/// The checks of [`check_runtime_binary`] for any binary `sallyd` executes with the user's
/// authority (the runtime, podman); errors name `field`.
///
/// # Errors
/// [`ConfigError::Binary`] naming `field`, the path and the failed check.
pub fn check_trusted_binary(path: &Path, field: &'static str) -> Result<PathBuf, ConfigError> {
    let fail = |msg: &str| ConfigError::Binary {
        field,
        path: path.display().to_string(),
        msg: msg.to_owned(),
    };
    let real = std::fs::canonicalize(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => fail("does not exist"),
        _ => fail(&format!("cannot be resolved: {e}")),
    })?;
    let euid = rustix::process::geteuid().as_raw();
    let meta = std::fs::metadata(&real).map_err(|e| fail(&format!("cannot be inspected: {e}")))?;
    if !meta.is_file() {
        return Err(fail("is not a regular file"));
    }
    let mode = meta.permissions().mode();
    if mode & ANY_EXEC == 0 {
        return Err(fail("is not executable"));
    }
    if mode & GROUP_OTHER_WRITE != 0 {
        return Err(fail("is writable by group or others"));
    }
    if !owner_ok(meta.uid(), euid) {
        return Err(fail("is owned by another user"));
    }
    for dir in real.ancestors().skip(1) {
        let d = dir.display();
        let dmeta = std::fs::metadata(dir).map_err(|e| fail(&format!("{d}: {e}")))?;
        if dmeta.permissions().mode() & GROUP_OTHER_WRITE != 0 {
            return Err(fail(&format!(
                "{d}: directory is writable by group or others"
            )));
        }
        if !owner_ok(dmeta.uid(), euid) {
            return Err(fail(&format!("{d}: directory is owned by another user")));
        }
    }
    Ok(real)
}

/// Only root or the current user may own the runtime binary and the directories above it.
fn owner_ok(file_uid: u32, euid: u32) -> bool {
    file_uid == 0 || file_uid == euid
}

#[cfg(test)]
mod tests {
    use super::owner_ok;

    #[test]
    fn runtime_owner_must_be_root_or_us() {
        assert!(owner_ok(0, 1000));
        assert!(owner_ok(1000, 1000));
        assert!(!owner_ok(1001, 1000));
        assert!(!owner_ok(1000, 1001));
    }
}
