//! Permission manifests: parse, validate, summarize (MANIFEST_SPEC.md).
//!
//! The pipeline is `bytes → parse → Manifest → validate → ValidatedManifest`. Only a
//! [`ValidatedManifest`] can be launched. It is a self-contained canonical struct: launch never
//! re-reads the manifest file (RT-MAN-03). It does re-check mount roots on the host to catch a
//! swap after validation (RT-FS-06).
//!
//! Blocking I/O: [`validate`], [`load`], and [`ValidatedManifest::recheck_mounts`] call
//! `lstat`/`realpath` on the host. Async callers must run them under `spawn_blocking`.

mod diag;
mod host;
mod hostenv;
mod image;
mod parse;
mod paths;
mod summary;
mod types;
mod units;
mod validate;

pub use diag::{Code, Diagnostic, Rejected, Severity};
pub use host::{HostError, HostPattern, parse_host_pattern, parse_hostname};
pub use hostenv::{HostEnv, HostEnvError};
pub use image::is_pinned_image_ref;
pub use parse::{MAX_MANIFEST_BYTES, parse, parse_bytes, to_yaml};
pub use summary::summary;
pub use types::{
    ApiVersion, Approvals, ApproveGlobs, Audit, AuditLevel, BuiltinTool, FetchWrites, Filesystem,
    Harness, HostRule, Inject, Kind, Manifest, McpApproval, McpServer, Model, Mount, MountMode,
    Network, NetworkMode, Policy, Runtime, SecretGrant, ShellPolicy, Tools,
};
pub use units::{ByteSize, Cpus, Duration, GpuLayers};
pub use validate::{
    EgressRule, GlobError, ResolvedMount, SecretCatalog, Validated, ValidatedManifest, check_glob,
    load, validate,
};

/// JSON Schema for [`Manifest`], for the UI editor. Generated from the same types the parser
/// uses, so `additionalProperties: false` mirrors `deny_unknown_fields`.
#[must_use]
pub fn json_schema() -> schemars::Schema {
    schemars::schema_for!(Manifest)
}
