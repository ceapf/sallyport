//! Inputs of the argv builder. Every value that ends up in an argv is validated when it is
//! constructed, so the builder never has to trust a raw string.

use std::path::{Path, PathBuf};

use sally_core::config::{ConfigError, check_runtime_binary};
use sally_core::manifest::{ByteSize, Cpus};

/// Why an argv could not be built.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ArgvError {
    /// An input is malformed (a path that would break the `-v` syntax, a bad id, a git scan
    /// entry outside its mount).
    #[error("sandbox argv input: {0}")]
    Input(String),
    /// The argv contains a flag or value the sandbox must never run with (CLAUDE.md hard rules).
    /// From the builder this means a bug: it checks its own output and refuses to return it.
    #[error("sandbox argv refused: {0}")]
    Forbidden(String),
}

pub(crate) fn input<T>(msg: impl Into<String>) -> Result<T, ArgvError> {
    Err(ArgvError::Input(msg.into()))
}

/// The OCI runtime binary after `sally_core::config::check_runtime_binary`: a realpath that only
/// its owner or root can swap (AMENDMENTS-02 B5). Passed as `--runtime` on every `podman` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedRuntime(PathBuf);

impl CheckedRuntime {
    /// Runs the runtime binary checks and keeps the realpath. Performs blocking I/O.
    ///
    /// # Errors
    /// [`ConfigError::Runtime`] naming the failed check.
    pub fn check(path: &Path) -> Result<Self, ConfigError> {
        check_runtime_binary(path).map(Self)
    }

    /// The checked realpath.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.0
    }
}

/// A session or inference-instance id: `[a-z0-9][a-z0-9-]{0,63}`. It becomes part of container
/// names and host paths, so it is restricted to characters that are safe in both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionId(String);

impl SessionId {
    /// Validates an id.
    ///
    /// # Errors
    /// [`ArgvError::Input`] if it does not match the grammar.
    pub fn parse(s: &str) -> Result<Self, ArgvError> {
        let mut b = s.bytes();
        let ok = s.len() <= 64
            && b.next()
                .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
            && b.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-');
        if ok {
            Ok(Self(s.to_owned()))
        } else {
            input("id must be 1-64 characters of a-z, 0-9 and -, starting with a letter or digit")
        }
    }

    /// The id.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An image pinned by digest: `<name>@sha256:<64 lowercase hex>` (SI-11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageRef(String);

impl ImageRef {
    /// Validates an image reference.
    ///
    /// # Errors
    /// [`ArgvError::Input`] unless it is a digest-pinned reference with a plain name.
    pub fn parse(s: &str) -> Result<Self, ArgvError> {
        let Some((name, digest)) = s.split_once("@sha256:") else {
            return input("image must be pinned by digest (<name>@sha256:<hex>)");
        };
        let name_ok = !name.is_empty()
            && !name.starts_with('-')
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"./_-:".contains(&b));
        let digest_ok = digest.len() == 64
            && digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if name_ok && digest_ok {
            Ok(Self(s.to_owned()))
        } else {
            input("image must be <name>@sha256:<64 lowercase hex>")
        }
    }

    /// The reference.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The host user the container maps to (`--userns=keep-id --user <uid>:<gid>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserIds {
    /// Host uid.
    pub uid: u32,
    /// Host gid.
    pub gid: u32,
}

/// Settings shared by every role.
#[derive(Debug, Clone)]
pub struct CommonArgs {
    /// Checked OCI runtime.
    pub runtime: CheckedRuntime,
    /// Host user.
    pub ids: UserIds,
    /// Directory holding `seccomp-{workspace,harness,inference}.json`.
    pub profiles: PathBuf,
}

/// Host directories of one session (ARCHITECTURE §3.1, AMENDMENTS-01 §2, AMENDMENTS-02 B2).
#[derive(Debug, Clone)]
pub struct SessionPaths {
    id: SessionId,
    sockets: PathBuf,
    data: PathBuf,
}

impl SessionPaths {
    /// `sockets` is `$XDG_RUNTIME_DIR/sallyport`, `data` is `~/.local/share/sallyport`; the
    /// session's directories are `sessions/<id>` under each.
    ///
    /// # Errors
    /// [`ArgvError::Input`] if a root is not absolute.
    pub fn new(id: SessionId, sockets: &Path, data: &Path) -> Result<Self, ArgvError> {
        if !sockets.is_absolute() || !data.is_absolute() {
            return input("session roots must be absolute paths");
        }
        let sockets = sockets.join("sessions").join(id.as_str());
        let data = data.join("sessions").join(id.as_str());
        Ok(Self { id, sockets, data })
    }

    /// The session id.
    #[must_use]
    pub fn id(&self) -> &SessionId {
        &self.id
    }

    /// The session's socket root: one subdirectory per role, never shared.
    #[must_use]
    pub fn socket_root(&self) -> &Path {
        &self.sockets
    }

    /// Socket directory of the workspace role (`net.sock`, CA bundle).
    #[must_use]
    pub fn workspace_sockets(&self) -> PathBuf {
        self.sockets.join("workspace")
    }

    /// Socket directory of the harness role (`llm.sock`, `agent.sock`).
    #[must_use]
    pub fn harness_sockets(&self) -> PathBuf {
        self.sockets.join("harness")
    }

    /// The session's scratch root (stage and `.git` overlay directories).
    #[must_use]
    pub fn data_root(&self) -> &Path {
        &self.data
    }

    /// Upper and work directories of the staged mount at manifest index `mount`; kept after the
    /// session so `sally session changes` can read them.
    #[must_use]
    pub fn stage(&self, mount: usize) -> (PathBuf, PathBuf) {
        let d = self.data.join("stage").join(mount.to_string());
        (d.join("upper"), d.join("work"))
    }

    /// Upper and work directories of the `k`-th `.git` overlay; discarded at teardown.
    #[must_use]
    pub fn git_overlay(&self, k: usize) -> (PathBuf, PathBuf) {
        let d = self.data.join("git").join(k.to_string());
        (d.join("upper"), d.join("work"))
    }
}

/// What the launch scan found inside one `rw` mount (AMENDMENTS-02 B2(a)): `.git` directories,
/// mounted as overlays over session scratch, and `.git` files (worktree or submodule pointers),
/// bound read-only. Paths are relative to the mount root and end in a `.git` component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitScan {
    /// Index of the mount in the manifest.
    pub mount: usize,
    /// `.git` directories.
    pub dirs: Vec<PathBuf>,
    /// `.git` files.
    pub files: Vec<PathBuf>,
}

/// One inference instance (ARCHITECTURE §3.2, AMENDMENTS-01 §6.2).
#[derive(Debug, Clone)]
pub struct InferenceSpec {
    /// Instance id.
    pub instance: SessionId,
    /// Host socket directory, `$XDG_RUNTIME_DIR/sallyport/infer/<id>`.
    pub socket_dir: PathBuf,
    /// The verified model blob (SI-6), mounted read-only.
    pub model: PathBuf,
    /// Inference image.
    pub image: ImageRef,
    /// Pass the GPU through (`--device nvidia.com/gpu=all`).
    pub gpu: bool,
    /// `-ngl`.
    pub gpu_layers: u32,
    /// `-c`.
    pub context: u32,
    /// `--cpus`.
    pub cpus: Cpus,
    /// `--memory`; optional because mmap'd weights count as page cache.
    pub memory: Option<ByteSize>,
}
