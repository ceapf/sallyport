//! The sandbox driver (ARCHITECTURE §3, AMENDMENTS-01 §2 and §6, AMENDMENTS-02 B2 and B5).
//!
//! This part is pure: it turns a validated manifest and the session's paths into `podman run`
//! argv for each role, and checks every argv against the hardening rules before returning it.
//! Launching, the launch scan and the mount re-checks come in later tasks.

mod argv;
mod check;
mod types;

pub use argv::{harness_argv, inference_argv, workspace_argv};
pub use check::check_argv;
pub use types::{
    ArgvError, CheckedRuntime, CommonArgs, GitScan, ImageRef, InferenceSpec, SessionId,
    SessionPaths, UserIds,
};
