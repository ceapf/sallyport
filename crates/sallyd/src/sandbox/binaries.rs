//! How `sallyd` finds the binaries hermetic podman runs, and what it records about them at start
//! (R1, architect Q123–Q128).
//!
//! - **podman.** `sandbox.podman_path` when set: checked with [`Owner::RootOrUser`], like the
//!   runtime. Otherwise only `<dir>/podman` for each directory of [`PODMAN_PATH_VAR`], in order,
//!   with [`Owner::Root`]. `sallyd`'s own `PATH` is never consulted.
//! - **`conmon`, `catatonit`.** Their fixed candidate lists, with [`Owner::Root`]: they are found
//!   the same way and are never configured.
//! - **A search never falls through.** The first candidate that exists (by `lstat`: a dangling
//!   link or a directory counts) is checked, and a failed check is an error. Only a candidate
//!   that does not exist moves the search on, so a refused binary is never silently replaced by
//!   a later one.
//! - **Recorded at start.** The resolved podman and runtime, each with its `--version` (bounded,
//!   timed, fail-closed: [`probe_version`]). A configured podman that the system search would
//!   not have accepted runs, and the daemon says so ([`outside_system_rule`]).

use std::path::{Path, PathBuf};
use std::time::Duration;

use sally_core::config::{ConfigError, Owner, check_binary};

use super::commands::read_capped;
use super::podman::{PODMAN_PATH_VAR, PodmanError};

/// How long a `--version` probe may take before the binary is refused.
pub const VERSION_TIMEOUT: Duration = Duration::from_secs(5);
/// How much of a `--version` probe's stdout and stderr is kept.
pub const VERSION_CAP: usize = 4096;
/// Longest version token accepted.
const VERSION_TOKEN_MAX: usize = 64;
/// The field named when podman comes from the system search.
const SYSTEM_FIELD: &str = "podman";
/// The field named when podman comes from the setting.
const CONFIGURED_FIELD: &str = "sandbox.podman_path";

/// Where the podman binary came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PodmanSource {
    /// The system search over [`PODMAN_PATH_VAR`]'s directories: root-owned only.
    System,
    /// `sandbox.podman_path`: root- or user-owned.
    Configured,
}

impl PodmanSource {
    /// The source as the start line names it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Configured => CONFIGURED_FIELD,
        }
    }

    /// Who may own a binary from this source.
    #[must_use]
    pub fn owner(self) -> Owner {
        match self {
            Self::System => Owner::Root,
            Self::Configured => Owner::RootOrUser,
        }
    }

    /// The field an error about a binary from this source names.
    #[must_use]
    pub fn field(self) -> &'static str {
        match self {
            Self::System => SYSTEM_FIELD,
            Self::Configured => CONFIGURED_FIELD,
        }
    }
}

/// A podman binary and where it came from. [`Podman::setup`](super::Podman::setup) and every
/// launch re-check it under its source's policy, so a wrong `source` fails closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPodman {
    /// The realpath of the binary.
    pub path: PathBuf,
    /// Where it came from.
    pub source: PodmanSource,
}

/// `<dir>/<name>` for each directory of [`PODMAN_PATH_VAR`], in its order.
#[must_use]
pub fn system_candidates(name: &str) -> Vec<PathBuf> {
    PODMAN_PATH_VAR
        .split(':')
        .map(|d| Path::new(d).join(name))
        .collect()
}

/// Picks the podman binary: `configured` checked as root- or user-owned, else the system search
/// (root-owned only, no fall-through). Performs blocking I/O.
///
/// # Errors
/// [`PodmanError::Missing`], [`PodmanError::Binary`] (a configured binary, naming
/// `sandbox.podman_path`) or [`PodmanError::System`] (a system one, saying that
/// `sandbox.podman_path` can name another).
pub fn resolve_podman(configured: Option<&Path>) -> Result<ResolvedPodman, PodmanError> {
    let (path, source) = match configured {
        Some(p) => (p.to_owned(), PodmanSource::Configured),
        None => (
            first_existing(SYSTEM_FIELD, &system_candidates("podman"))?,
            PodmanSource::System,
        ),
    };
    Ok(ResolvedPodman {
        path: check_podman(&path, source)?,
        source,
    })
}

/// The checks of a podman binary from `source`; the realpath.
///
/// # Errors
/// As [`resolve_podman`].
pub(super) fn check_podman(path: &Path, source: PodmanSource) -> Result<PathBuf, PodmanError> {
    check_binary(path, source.field(), source.owner()).map_err(|e| match source {
        PodmanSource::System => PodmanError::System(e),
        PodmanSource::Configured => PodmanError::Binary(e),
    })
}

/// The first of `candidates` that exists, checked as root-owned (a helper search).
///
/// # Errors
/// [`PodmanError::Missing`], [`PodmanError::Io`] or [`PodmanError::Binary`] naming `what`.
pub(super) fn first_root_owned(
    what: &'static str,
    candidates: &[PathBuf],
) -> Result<PathBuf, PodmanError> {
    let found = first_existing(what, candidates)?;
    Ok(check_binary(&found, what, Owner::Root)?)
}

/// The first of `candidates` that `lstat` finds; only "does not exist" moves on.
fn first_existing(what: &'static str, candidates: &[PathBuf]) -> Result<PathBuf, PodmanError> {
    for c in candidates {
        match std::fs::symlink_metadata(c) {
            Ok(_) => return Ok(c.clone()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(PodmanError::Io {
                    path: c.display().to_string(),
                    source,
                });
            }
        }
    }
    Err(PodmanError::Missing(what, candidates.to_vec()))
}

/// Why a configured podman would not have been accepted by the system search, so it runs only
/// because `sandbox.podman_path` names it; `None` for a system binary, or a configured one that
/// is the root-owned binary of a system candidate. Performs blocking I/O.
#[must_use]
pub fn outside_system_rule(r: &ResolvedPodman) -> Option<&'static str> {
    if r.source == PodmanSource::System {
        return None;
    }
    let root_owned = check_binary(&r.path, CONFIGURED_FIELD, Owner::Root).is_ok();
    let listed = system_candidates("podman")
        .iter()
        .filter_map(|c| std::fs::canonicalize(c).ok())
        .any(|c| c == r.path);
    outside_reason(root_owned, listed)
}

/// [`outside_system_rule`]'s decision over its two facts.
fn outside_reason(root_owned: bool, listed: bool) -> Option<&'static str> {
    if !root_owned {
        Some("not owned by root")
    } else if !listed {
        Some("not in a system directory")
    } else {
        None
    }
}

/// Runs `cmd --version` and parses its first line as `<name> version <token>`. `cmd` must
/// already carry its environment; its stdin is null. stdout and stderr are kept up to
/// [`VERSION_CAP`] each, and the process is killed after `timeout`.
///
/// # Errors
/// What went wrong, for the caller's error: spawn, timeout, a failed exit or a bad line.
pub async fn probe_version(
    mut cmd: tokio::process::Command,
    name: &str,
    timeout: Duration,
) -> Result<String, String> {
    let mut child = cmd
        .arg("--version")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| e.to_string())?;
    let (Some(out), Some(err)) = (child.stdout.take(), child.stderr.take()) else {
        return Err("no pipes".into());
    };
    let work = async {
        let (out, _) = tokio::join!(read_capped(out, VERSION_CAP), read_capped(err, VERSION_CAP));
        (out, child.wait().await)
    };
    let (out, status) = tokio::time::timeout(timeout, work)
        .await
        .map_err(|_| format!("--version timed out after {} ms", timeout.as_millis()))?;
    let status = status.map_err(|e| e.to_string())?;
    if !status.success() {
        return Err(format!("--version failed: {status}"));
    }
    parse_version(name, &out)
}

/// The version token of `<name> version <token>`, the first line of `out`. The token is 1 to
/// 64 bytes of `[0-9A-Za-z.+~-]`.
///
/// # Errors
/// The line, cut and escaped, when it is not of that form.
pub fn parse_version(name: &str, out: &[u8]) -> Result<String, String> {
    let line = out.split(|&b| b == b'\n').next().unwrap_or_default();
    let shown = || {
        let s: String = String::from_utf8_lossy(line).chars().take(80).collect();
        format!("--version printed {s:?}, not \"{name} version <version>\"")
    };
    let token = std::str::from_utf8(line)
        .ok()
        .and_then(|l| l.strip_prefix(name))
        .and_then(|l| l.strip_prefix(" version "))
        .ok_or_else(shown)?;
    let ok = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'~' | b'-');
    if token.is_empty() || token.len() > VERSION_TOKEN_MAX || !token.bytes().all(ok) {
        return Err(shown());
    }
    Ok(token.to_owned())
}

/// The field an error about the runtime's version names.
pub const RUNTIME_FIELD: &str = "sandbox.runtime_path";

/// A [`ConfigError`] for a version probe that failed, naming `field` and `path`.
#[must_use]
pub fn version_error(field: &'static str, path: &Path, msg: String) -> ConfigError {
    ConfigError::Binary {
        field,
        path: path.display().to_string(),
        msg,
    }
}

#[cfg(test)]
#[path = "binaries_tests.rs"]
mod tests;
