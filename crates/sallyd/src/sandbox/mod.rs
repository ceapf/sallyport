//! The sandbox driver (ARCHITECTURE §3, AMENDMENTS-01 §2 and §6, AMENDMENTS-02 B2 and B5).
//!
//! The argv builders are pure: they turn a validated manifest and the session's paths into
//! `podman create` argv for each role and check every argv against the hardening rules before
//! returning it. The launcher (Task 6b) adds what the argv cannot see: the launch scan, the
//! session overlap rule, private session directories, hermetic podman and the post-init mount
//! check.

mod argv;
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
pub use check::{Allowed, Grant, Source, check_argv};
pub use dirs::{DirError, SessionDirs, check_runtime_dir};
pub use disk::DiskFloor;
// TODO(#17): narrow the test-only items in Task 12, when the launcher gets its real callers.
pub use inside::{Expect, Mismatch, check_in_container};
pub use launch::{
    AuditSink, LaunchError, Launcher, LauncherParts, Running, SharedAudit, StopError,
    WorkspaceRequest,
};
pub use overlap::{Claim, Conflict, ReserveError, Sessions, claims, conflict};
pub use podman::{
    ConfBinaries, PODMAN_PATH_VAR, Podman, PodmanError, PodmanHost, containers_conf, resolve_podman,
};
pub use profiles::{profile, write_profiles};
pub use scan::{GitScan, LaunchScan, Pin, PinKind, ScanError, ScanLimits, scan_mounts};
pub use types::{
    ArgvError, CheckedRuntime, CommonArgs, ImageRef, InferenceSpec, OverlayDirs, Role, SessionId,
    SessionPaths, UserIds, VerifiedModel,
};
