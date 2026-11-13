//! The sandbox driver (ARCHITECTURE §3, AMENDMENTS-01 §2 and §6, AMENDMENTS-02 B2 and B5).
//!
//! The argv builders are pure: they turn a validated manifest and the session's paths into
//! `podman create` argv for each role and check every argv against the hardening rules before
//! returning it. The launcher (Task 6b) adds what the argv cannot see: the launch scan, the
//! session overlap rule, private session directories, hermetic podman and the post-init mount
//! check.

mod argv;
pub mod budget;
mod changes;
mod check;
mod commands;
mod dirs;
mod disk;
mod images;
mod inside;
mod launch;
mod overlap;
mod podman;
mod profiles;
mod scan;
mod stage;
mod types;
mod watchdog;

pub use argv::{harness_argv, inference_argv, workspace_argv};
pub use changes::{Change, ChangeKind, ChangesError, staged_changes};
pub use check::{Allowed, Grant, Source, check_argv};
pub use dirs::{DirError, SessionDirs, check_runtime_dir};
pub use disk::DiskFloor;
pub use inside::Mismatch;
/// Public only for `tests/launch.rs`, which compares identities inside a real container; the
/// launcher is the one production caller (#17).
#[doc(hidden)]
pub use inside::{Expect, check_in_container};
pub use launch::{
    AuditSink, LaunchError, Launcher, LauncherParts, Running, SharedAudit, StopError,
    WorkspaceRequest,
};
pub use overlap::{Claim, Conflict, ReserveError, Sessions, claims};
pub use podman::{PODMAN_PATH_VAR, Podman, PodmanError, PodmanHost, resolve_podman};
pub use profiles::profile;
pub use scan::{GitScan, LaunchScan, Pin, PinKind, ScanError, ScanLimits, scan_mounts};
pub use types::{
    ArgvError, CheckedRuntime, CommonArgs, ImageRef, InferenceSpec, OverlayDirs, Role, SessionId,
    SessionPaths, UserIds, VerifiedModel,
};
