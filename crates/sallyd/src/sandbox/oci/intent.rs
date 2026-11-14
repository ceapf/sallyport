//! What an argv builder meant (architect Q100): recorded by the same `Argv` methods that push the
//! flags, so the argv and the verifier's expectation come from one place. What every container
//! of a role gets regardless of the manifest (no capabilities, `no_new_privs`, a read-only root,
//! the namespace list, `--init`) is not recorded: the verifier knows it per role.

use std::path::PathBuf;

use crate::sandbox::types::{Role, UserIds};

/// One mount the argv asked for, as the guest will see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Wanted {
    /// `-v host:guest:{ro|rw},nosuid,nodev,bind`.
    Bind {
        /// Host path, as passed.
        host: String,
        /// Guest path.
        guest: String,
        /// `rw` rather than `ro`.
        rw: bool,
    },
    /// `-v host:guest:O,upperdir=…,workdir=…`.
    Overlay {
        /// The lower layer (host path).
        host: String,
        /// Guest path.
        guest: String,
        /// Upper directory.
        upper: String,
        /// Work directory.
        work: String,
    },
}

/// The argv's intent for one container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intent {
    /// The role.
    pub role: Role,
    /// `--user`.
    pub ids: UserIds,
    /// The directory of the session's seccomp profiles (the annotation names the role's file).
    pub profiles: PathBuf,
    /// `--tmpfs /tmp`: size in bytes and whether it is `exec`.
    pub tmp: Option<(u64, bool)>,
    /// `--pids-limit`.
    pub pids: Option<u32>,
    /// `--cpus`, in thousandths of a CPU.
    pub cpu_millis: Option<u32>,
    /// `--memory` (and `--memory-swap`, equal).
    pub memory: Option<u64>,
    /// `--hostname`; `None` lets podman use the container id.
    pub hostname: Option<String>,
    /// `--env` pairs, in order.
    pub env: Vec<(String, String)>,
    /// `-v` mounts, in order.
    pub mounts: Vec<Wanted>,
    /// The image reference.
    pub image: String,
    /// The command after the image.
    pub command: Vec<String>,
    /// `--device nvidia.com/gpu=all`.
    pub gpu: bool,
}

impl Intent {
    /// An intent with nothing recorded yet.
    #[must_use]
    pub fn begin(role: Role, ids: UserIds, profiles: PathBuf) -> Self {
        Self {
            role,
            ids,
            profiles,
            tmp: None,
            pids: None,
            cpu_millis: None,
            memory: None,
            hostname: None,
            env: Vec::new(),
            mounts: Vec::new(),
            image: String::new(),
            command: Vec::new(),
            gpu: false,
        }
    }
}

/// An argv and the intent it was built from.
#[derive(Debug, Clone)]
pub struct Built {
    /// The arguments after the `podman` program name.
    pub argv: Vec<String>,
    /// What the argv asked for.
    pub intent: Intent,
}
