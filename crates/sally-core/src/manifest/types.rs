//! Manifest schema types (MANIFEST_SPEC §1).
//!
//! Every struct uses `deny_unknown_fields` (SI-7). These types are the *unvalidated* parse
//! result: they only guarantee the YAML had the right shape. Semantic checks (ranges, paths,
//! hostnames, secret references) live in [`super::validate`], which produces a
//! [`super::ValidatedManifest`].

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::units::{ByteSize, Cpus, Duration, GpuLayers};

/// A parsed (not yet validated) permission manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Must be exactly `sallyport/v1`.
    #[serde(rename = "apiVersion")]
    pub api_version: ApiVersion,
    /// Must be exactly `Manifest`.
    pub kind: Kind,
    /// Slug, `[a-z0-9-]{1,64}`.
    pub name: String,
    /// Free text, at most 512 characters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The harness container (model-steered code; no mounts, no network). `None` = the bundled
    /// reference harness.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness: Option<Harness>,
    /// Workspace container resources.
    #[serde(default)]
    pub runtime: Runtime,
    /// Which model the session uses.
    pub model: Model,
    /// Host directories visible to the sandbox.
    #[serde(default)]
    pub filesystem: Filesystem,
    /// Brokered egress.
    #[serde(default)]
    pub network: Network,
    /// Secrets injected by the broker (names only; values never appear in manifests).
    #[serde(default)]
    pub secrets: Vec<SecretGrant>,
    /// Tools the agent may call.
    #[serde(default)]
    pub tools: Tools,
    /// Human-approval settings.
    #[serde(default)]
    pub approvals: Approvals,
    /// Audit verbosity.
    #[serde(default)]
    pub audit: Audit,
    /// Reserved for v2 signed org policies; parsed and ignored in v1.
    #[serde(default)]
    pub policy: Policy,
}

/// The manifest format version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum ApiVersion {
    /// `sallyport/v1`
    #[serde(rename = "sallyport/v1")]
    V1,
}

/// The document kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum Kind {
    /// `Manifest`
    Manifest,
}

/// The harness container (AMENDMENTS-01 §2). Its resources are fixed in v1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Harness {
    /// Harness image, `<ref>@sha256:<64 hex>`.
    pub image: String,
}

/// Workspace container resources (`podman run --cpus/--memory/--pids-limit/--tmpfs`). The
/// workspace holds the mounts and the egress socket; only the broker acts in it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct Runtime {
    /// Workspace (toolchain) image, `<ref>@sha256:<64 hex>`. `None` = bundled workspace image.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// CPU quota, 0.5 to the host's CPU count.
    pub cpus: Cpus,
    /// Memory limit, at least 64MiB and at most 75% of host RAM.
    pub memory: ByteSize,
    /// Process limit, 16–4096.
    pub pids: u32,
    /// Session wall clock, 1m–24h.
    pub timeout: Duration,
    /// Size of the `/tmp` tmpfs, 1MiB up to `memory`.
    pub tmp_size: ByteSize,
    /// Mount `/tmp` without `noexec`.
    pub tmp_exec: bool,
    /// Limit on what the sandbox writes to the host disk, 1MiB–1TiB: the upper directories of its
    /// `staged` mounts and of the `.git` overlays of its `rw` mounts, together. A watchdog in
    /// `sallyd` kills a session that exceeds it and audits `session.resource_limit`.
    pub stage_size: ByteSize,
}

impl Default for Runtime {
    fn default() -> Self {
        Self {
            image: None,
            cpus: Cpus::from_millis(4000),
            memory: ByteSize::from_bytes(8 * ByteSize::GIB),
            pids: 512,
            timeout: Duration::from_secs(2 * 3600),
            tmp_size: ByteSize::from_bytes(ByteSize::GIB),
            tmp_exec: false,
            stage_size: ByteSize::from_bytes(10 * ByteSize::GIB),
        }
    }
}

/// Model selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Model {
    /// `library://<name-or-sha256>` or `any` (user picks at launch).
    #[serde(rename = "ref")]
    pub reference: String,
    /// Context length in tokens; clamped later by model metadata and VRAM.
    #[serde(default = "default_context")]
    pub context: u32,
    /// GPU offload.
    #[serde(default)]
    pub gpu_layers: GpuLayers,
}

fn default_context() -> u32 {
    8192
}

/// Host directories visible to the sandbox.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct Filesystem {
    /// Bind mounts.
    pub mounts: Vec<Mount>,
    /// Extra host paths to refuse, on top of the built-in denylist.
    pub deny: Vec<String>,
}

/// One bind mount.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Mount {
    /// Absolute or `~/`-prefixed host directory.
    pub host: String,
    /// Absolute guest path under `/workspace/`.
    pub guest: String,
    /// Access mode.
    pub mode: MountMode,
    /// Approval globs; only meaningful for `brokered`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approve: Option<ApproveGlobs>,
}

/// Mount access mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum MountMode {
    /// Read-only bind mount.
    Ro,
    /// Read-write bind mount (`nosuid,nodev`). The blast radius.
    Rw,
    /// Read-only bind mount; writes/deletes go through the broker's `fs_*` tools.
    Brokered,
    /// Overlay with the host directory as the read-only lower layer: the sandbox writes freely,
    /// every change lands in a kept upper directory in session scratch, and the host directory
    /// is untouched (AMENDMENTS-02 B2(b)). v1 can list the changes but not apply them.
    Staged,
}

/// Globs (relative to the mount) whose brokered writes/deletes need approval. An omitted list
/// means `["**"]` (everything needs approval): omission never disables a gate (SI-5).
/// Unapproved operations need an explicit empty list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApproveGlobs {
    /// Write globs.
    #[serde(default = "approve_everything")]
    pub writes: Vec<String>,
    /// Delete globs.
    #[serde(default = "approve_everything")]
    pub deletes: Vec<String>,
}

impl ApproveGlobs {
    /// Every write and delete needs approval (the default for `brokered`).
    #[must_use]
    pub fn everything() -> Self {
        Self {
            writes: approve_everything(),
            deletes: approve_everything(),
        }
    }

    /// No globs (used for `ro`/`rw` mounts, where approve globs do not apply).
    #[must_use]
    pub const fn not_applicable() -> Self {
        Self {
            writes: Vec::new(),
            deletes: Vec::new(),
        }
    }
}

fn approve_everything() -> Vec<String> {
    vec!["**".to_owned()]
}

/// Brokered egress settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct Network {
    /// `none` = no shim, no socket; `proxy` = brokered egress.
    pub mode: NetworkMode,
    /// Hostname rules; only meaningful with `mode: proxy`.
    pub allow: Vec<HostRule>,
    /// Must be `true` if any rule has `host: "*"`.
    pub acknowledge_unrestricted_egress: bool,
    /// Per-request body cap.
    pub max_request_bytes: ByteSize,
    /// Per-response body cap.
    pub max_response_bytes: ByteSize,
    /// Concurrent connection cap.
    pub max_connections: u32,
}

impl Default for Network {
    fn default() -> Self {
        Self {
            mode: NetworkMode::None,
            allow: Vec::new(),
            acknowledge_unrestricted_egress: false,
            max_request_bytes: ByteSize::from_bytes(8 * ByteSize::MIB),
            max_response_bytes: ByteSize::from_bytes(64 * ByteSize::MIB),
            max_connections: 32,
        }
    }
}

/// Network mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum NetworkMode {
    /// No network path at all.
    #[default]
    None,
    /// Egress through the broker's proxy.
    Proxy,
}

/// One egress allow rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostRule {
    /// Exact hostname, `*.example.com` (subdomains only), or `*`.
    pub host: String,
    /// Allowed upstream ports.
    #[serde(default = "default_ports")]
    pub ports: Vec<u16>,
}

fn default_ports() -> Vec<u16> {
    vec![443]
}

/// A secret the broker injects into requests toward one host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretGrant {
    /// Name in the secrets store, `[A-Z][A-Z0-9_]{0,63}`. The same name may appear in several
    /// grants with different hosts.
    pub name: String,
    /// Where and how to inject it.
    pub inject: Inject,
    /// Set this env var to a public placeholder in the workspace container, for tools that
    /// refuse to run without a token. The proxy overwrites the header; the value never enters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expose_env: Option<String>,
}

/// Injection target for a secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Inject {
    /// Exact hostname; wildcards refused.
    pub host: String,
    /// Header name.
    pub header: String,
    /// Header value template containing exactly one of `{value}` or `{basic}`.
    pub format: String,
    /// User name for `{basic}` = base64(`basic_user:secret`). Required with `{basic}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub basic_user: Option<String>,
}

/// Tool permissions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct Tools {
    /// Broker-implemented tools available to this session.
    pub builtin: Vec<BuiltinTool>,
    /// Shell policy.
    pub shell: ShellPolicy,
    /// In `shell: allow`, commands tagged destructive still need approval.
    pub destructive_requires_approval: bool,
    /// Whether `fetch` calls other than GET/HEAD need approval.
    pub fetch_writes: FetchWrites,
    /// Accepted unapproved channels (AMENDMENTS-02 B3): `shell`, `fetch`, `mcp:<server>`. Each
    /// entry is required exactly when its risk is live, and an entry that is not needed is an
    /// error, so a stale acknowledgement cannot linger.
    pub acknowledge_unapproved: Vec<String>,
    /// MCP servers the broker starts inside the workspace container.
    pub mcp: Vec<McpServer>,
}

impl Default for Tools {
    fn default() -> Self {
        Self {
            builtin: Vec::new(),
            shell: ShellPolicy::Deny,
            destructive_requires_approval: true,
            fetch_writes: FetchWrites::Approve,
            acknowledge_unapproved: Vec::new(),
            mcp: Vec::new(),
        }
    }
}

/// Approval policy for `fetch` methods other than GET/HEAD.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum FetchWrites {
    /// Non-GET/HEAD requests wait for human approval.
    #[default]
    Approve,
    /// Non-GET/HEAD requests run without approval.
    Allow,
}

/// A broker-implemented tool. Names are function-name safe (they are MCP tool names on the wire).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum BuiltinTool {
    /// `fs_read`
    FsRead,
    /// `fs_list`
    FsList,
    /// `fs_write`
    FsWrite,
    /// `fs_delete`
    FsDelete,
    /// `shell`
    Shell,
    /// `fetch`
    Fetch,
}

impl BuiltinTool {
    /// The manifest and wire spelling, e.g. `fs_read`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FsRead => "fs_read",
            Self::FsList => "fs_list",
            Self::FsWrite => "fs_write",
            Self::FsDelete => "fs_delete",
            Self::Shell => "shell",
            Self::Fetch => "fetch",
        }
    }
}

/// Shell policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ShellPolicy {
    /// Every shell call is denied.
    #[default]
    Deny,
    /// Every shell call waits for human approval.
    Approve,
    /// Shell calls run; destructive-tagged ones may still need approval.
    Allow,
}

/// An MCP server the broker starts inside the workspace container and relays tool calls to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct McpServer {
    /// Slug, `[a-z0-9-]{1,64}`.
    pub name: String,
    /// argv; first element is the program.
    pub command: Vec<String>,
    /// Literal environment; secret-like names are refused.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Whether each relayed tool call needs human approval.
    #[serde(default)]
    pub approve: McpApproval,
}

/// Approval policy for a declared MCP server's tools.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum McpApproval {
    /// Every call waits for human approval.
    #[default]
    Always,
    /// Calls run without approval (still audited).
    Never,
}

/// Human-approval settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct Approvals {
    /// How long a pending request waits; expiry = deny. 30s–1h.
    pub timeout: Duration,
    /// Pending requests beyond this are auto-denied. 1–64.
    pub max_pending: u32,
}

impl Default for Approvals {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(300),
            max_pending: 5,
        }
    }
}

/// Audit settings.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct Audit {
    /// Verbosity.
    pub level: AuditLevel,
}

/// Audit verbosity. Levels control detail, never coverage (SI-4): every decision is recorded
/// at every level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum AuditLevel {
    /// Decision records plus per-request lines for intercepted HTTP (method + path, never
    /// bodies), `fs_read` events, and inference metadata.
    #[default]
    Full,
    /// Decision records only: one per tool call, egress connection (allow and deny, with
    /// host:port and byte counts), approval, launch, and model import.
    Actions,
}

/// Reserved for v2 signed org policies.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    /// Signer identity (ignored in v1).
    pub signed_by: Option<String>,
    /// Signature (ignored in v1).
    pub signature: Option<String>,
}
