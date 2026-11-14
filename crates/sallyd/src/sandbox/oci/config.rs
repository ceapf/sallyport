//! The OCI config Podman 4.9.3 writes for a Sallyport container, parsed strictly: every object
//! refuses a key it does not list, so a field the verifier does not know is a mismatch, never
//! ignored (Task 14). Hooks, devices, sysctls, a terminal, an AppArmor or SELinux label and
//! every other OCI field Podman does not write for these roles are absent from these types.
//!
//! Bounds first: [`parse`] refuses input over [`MAX_CONFIG`] before parsing, and refuses
//! duplicate keys (`rpc::json`), so no key can be read two ways.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value;

use super::Mismatch;
use super::seccomp::OciSeccomp;

/// The largest config accepted. A workspace with the most `.git` shields the launch scan
/// allows stays far below it.
pub const MAX_CONFIG: usize = 1024 * 1024;

/// The whole config, as [`parse`] assembles it from its sections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Spec version.
    pub oci_version: String,
    /// The container's process.
    pub process: Process,
    /// The root filesystem.
    pub root: Root,
    /// The UTS hostname.
    pub hostname: String,
    /// Mounts, in the order the runtime makes them.
    pub mounts: Vec<Mount>,
    /// Annotations.
    pub annotations: BTreeMap<String, String>,
    /// Linux settings.
    pub linux: Linux,
}

/// `process`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Process {
    /// Identity.
    pub user: User,
    /// Command line.
    pub args: Vec<String>,
    /// `NAME=value` pairs.
    #[serde(default)]
    pub env: Vec<String>,
    /// Working directory.
    pub cwd: String,
    /// Capability sets; every one must be empty.
    #[serde(default)]
    pub capabilities: Capabilities,
    /// Resource limits.
    #[serde(default)]
    pub rlimits: Vec<Rlimit>,
    /// `no_new_privs`.
    #[serde(default)]
    pub no_new_privileges: bool,
}

/// `process.user`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct User {
    /// User id.
    pub uid: u32,
    /// Group id.
    pub gid: u32,
    /// File mode creation mask.
    pub umask: Option<u32>,
    /// Supplementary groups.
    #[serde(default)]
    pub additional_gids: Vec<u32>,
}

/// `process.capabilities`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    /// Bounding set.
    #[serde(default)]
    pub bounding: Vec<String>,
    /// Effective set.
    #[serde(default)]
    pub effective: Vec<String>,
    /// Inheritable set.
    #[serde(default)]
    pub inheritable: Vec<String>,
    /// Permitted set.
    #[serde(default)]
    pub permitted: Vec<String>,
    /// Ambient set.
    #[serde(default)]
    pub ambient: Vec<String>,
}

/// One `process.rlimits` entry.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rlimit {
    /// `RLIMIT_*`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Hard limit.
    pub hard: u64,
    /// Soft limit.
    pub soft: u64,
}

/// `root`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Root {
    /// The rootfs directory.
    pub path: String,
    /// Mounted read-only.
    #[serde(default)]
    pub readonly: bool,
}

/// One `mounts` entry.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mount {
    /// Guest path.
    pub destination: String,
    /// Filesystem type (`bind`, `overlay`, `tmpfs`, …).
    #[serde(rename = "type")]
    pub kind: String,
    /// Host path or pseudo source.
    pub source: String,
    /// Mount options.
    #[serde(default)]
    pub options: Vec<String>,
}

/// `linux`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Linux {
    /// User namespace uid map.
    #[serde(default)]
    pub uid_mappings: Vec<IdMap>,
    /// User namespace gid map.
    #[serde(default)]
    pub gid_mappings: Vec<IdMap>,
    /// cgroup limits.
    #[serde(default)]
    pub resources: Resources,
    /// cgroup path.
    pub cgroups_path: String,
    /// Namespaces.
    pub namespaces: Vec<Namespace>,
    /// The seccomp filter.
    pub seccomp: OciSeccomp,
    /// Paths hidden from the container.
    #[serde(default)]
    pub masked_paths: Vec<String>,
    /// Paths read-only in the container.
    #[serde(default)]
    pub readonly_paths: Vec<String>,
}

/// One id mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdMap {
    /// First id inside.
    #[serde(rename = "containerID")]
    pub container_id: u32,
    /// First id outside.
    #[serde(rename = "hostID")]
    pub host_id: u32,
    /// Count.
    pub size: u32,
}

/// `linux.resources`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resources {
    /// Memory and swap.
    pub memory: Option<Memory>,
    /// CPU quota.
    pub cpu: Option<Cpu>,
    /// Process count.
    pub pids: Option<Pids>,
}

/// `linux.resources.memory`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Memory {
    /// Bytes.
    pub limit: Option<i64>,
    /// Memory plus swap, bytes.
    pub swap: Option<i64>,
}

/// `linux.resources.cpu`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cpu {
    /// Microseconds per period.
    pub quota: Option<i64>,
    /// Period, microseconds.
    pub period: Option<u64>,
}

/// `linux.resources.pids`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pids {
    /// Maximum.
    pub limit: i64,
}

/// One `linux.namespaces` entry.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Namespace {
    /// Namespace type.
    #[serde(rename = "type")]
    pub kind: String,
    /// An existing namespace to join; must be absent.
    pub path: Option<String>,
}

/// The top level, each section kept as a value so a shape error can name its section.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Sections {
    oci_version: Value,
    process: Value,
    root: Value,
    hostname: Value,
    mounts: Value,
    #[serde(default)]
    annotations: Option<Value>,
    linux: Value,
}

/// A serde error as a field path and a kind of fault (architect Q110): serde's own text can echo
/// a value, so only the key name it reports is kept, escaped and capped by [`Mismatch::new`].
fn shape(section: &str, e: &serde_json::Error) -> Mismatch {
    let msg = e.to_string();
    let key = |prefix: &str| {
        msg.strip_prefix(prefix)
            .and_then(|rest| rest.split('`').next())
            .map(str::to_owned)
    };
    if let Some(k) = key("unknown field `") {
        Mismatch::new(section, format!("unknown key {k}"))
    } else if let Some(k) = key("missing field `") {
        Mismatch::new(section, format!("missing key {k}"))
    } else if let Some(k) = key("duplicate field `") {
        Mismatch::new(section, format!("duplicate key {k}"))
    } else {
        Mismatch::new(section, "a value has the wrong type or is out of range")
    }
}

fn section<T: serde::de::DeserializeOwned>(name: &str, v: Value) -> Result<T, Mismatch> {
    serde_json::from_value(v).map_err(|e| shape(name, &e))
}

/// serde also fills a struct from an array, by position; podman writes objects, so a section
/// that should be one and is not is refused before it is read. (Inside a section the same holds
/// for nested objects: every value read there is still compared, so a positional form cannot
/// carry anything the comparison does not see.)
fn object(name: &str, v: Value) -> Result<Value, Mismatch> {
    if v.is_object() {
        Ok(v)
    } else {
        Err(Mismatch::new(name, "not an object"))
    }
}

/// Parses `bytes` strictly: bounded first, then no duplicate key at any depth (`rpc::json`), no
/// unknown or missing key, every value of its type.
///
/// # Errors
/// A [`Mismatch`] naming the section and the key.
pub fn parse(bytes: &[u8]) -> Result<Config, Mismatch> {
    if bytes.len() > MAX_CONFIG {
        return Err(Mismatch::new("config", "over the size bound"));
    }
    let value = crate::rpc::json::parse(bytes).map_err(|_| {
        Mismatch::new(
            "config",
            "not strict JSON (malformed, not UTF-8, trailing data or a repeated key)",
        )
    })?;
    let s: Sections = section("config", object("config", value)?)?;
    Ok(Config {
        oci_version: section("ociVersion", s.oci_version)?,
        process: section("process", object("process", s.process)?)?,
        root: section("root", object("root", s.root)?)?,
        hostname: section("hostname", s.hostname)?,
        mounts: section("mounts", s.mounts)?,
        annotations: match s.annotations {
            Some(a) => section("annotations", object("annotations", a)?)?,
            None => BTreeMap::new(),
        },
        linux: section("linux", object("linux", s.linux)?)?,
    })
}
