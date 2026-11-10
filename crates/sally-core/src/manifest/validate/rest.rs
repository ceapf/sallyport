//! Identity, runtime, model, tools, approvals, and policy checks.

use std::collections::HashSet;

use super::super::diag::{Code, Diags};
use super::super::hostenv::HostEnv;
use super::super::types::{
    BuiltinTool, Harness, Manifest, Model, MountMode, NetworkMode, Runtime, ShellPolicy,
};
use super::super::units::{ByteSize, Cpus, Duration, GpuLayers};
use super::EgressRule;

const MAX_DESCRIPTION: usize = 512;
const MIN_CPUS: Cpus = Cpus::from_millis(500);
const MIN_MEMORY: u64 = 64 * ByteSize::MIB;
const PIDS: (u32, u32) = (16, 4096);
const SESSION_TIMEOUT: (u64, u64) = (60, 24 * 3600);
const APPROVAL_TIMEOUT: (u64, u64) = (30, 3600);
const MAX_PENDING: (u32, u32) = (1, 64);
const MAX_CONTEXT: u32 = 1 << 20;
const MAX_GPU_LAYERS: u32 = 1024;
const MAX_NAME: usize = 64;
const MAX_MODEL_NAME: usize = 128;

/// Records `out-of-range` unless `min <= v <= max`.
pub(super) fn in_range<T: PartialOrd + Copy>(
    d: &mut Diags,
    path: &str,
    v: T,
    min: T,
    max: T,
    show: impl Fn(T) -> String,
) {
    if v < min || v > max {
        d.error(
            path,
            Code::OutOfRange,
            format!("{} is outside {}–{}", show(v), show(min), show(max)),
        );
    }
}

/// `[a-z0-9-]{1,64}`
pub(super) fn is_slug(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_NAME
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

pub(super) fn check_identity(m: &Manifest, d: &mut Diags) {
    if !is_slug(&m.name) {
        d.error(
            "name",
            Code::InvalidValue,
            format!("{:?} must match [a-z0-9-]{{1,64}}", m.name),
        );
    }
    if let Some(desc) = &m.description {
        if desc.chars().count() > MAX_DESCRIPTION {
            d.error(
                "description",
                Code::OutOfRange,
                format!("longer than {MAX_DESCRIPTION} characters"),
            );
        }
        if desc
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t')
        {
            d.error(
                "description",
                Code::InvalidValue,
                "contains a control character",
            );
        }
    }
}

pub(super) fn check_harness(h: Option<&Harness>, d: &mut Diags) {
    if let Some(h) = h
        && let Err(msg) = check_image(&h.image)
    {
        d.error("harness.image", Code::NotPinned, msg);
    }
}

pub(super) fn check_runtime(r: &Runtime, env: &HostEnv, d: &mut Diags) {
    if let Some(image) = &r.image
        && let Err(msg) = check_image(image)
    {
        d.error("runtime.image", Code::NotPinned, msg);
    }
    let max_cpus = Cpus::from_millis(env.nproc.saturating_mul(1000));
    if r.cpus < MIN_CPUS || r.cpus > max_cpus {
        d.error(
            "runtime.cpus",
            Code::OutOfRange,
            format!("{} is outside 0.5–{max_cpus} (host CPUs)", r.cpus),
        );
    }
    let max_mem = env.mem_bytes / 4 * 3;
    let bytes = |x| ByteSize::from_bytes(x).to_string();
    in_range(
        d,
        "runtime.memory",
        r.memory.bytes(),
        MIN_MEMORY,
        max_mem,
        bytes,
    );
    in_range(d, "runtime.pids", r.pids, PIDS.0, PIDS.1, |x| x.to_string());
    let secs = |x| Duration::from_secs(x).to_string();
    in_range(
        d,
        "runtime.timeout",
        r.timeout.as_secs(),
        SESSION_TIMEOUT.0,
        SESSION_TIMEOUT.1,
        secs,
    );
    in_range(
        d,
        "runtime.tmp_size",
        r.tmp_size.bytes(),
        ByteSize::MIB,
        r.memory.bytes(),
        bytes,
    );
}

/// `<name>@sha256:<64 lowercase hex>` (SI-11). Tags before the digest are allowed but ignored
/// by the runtime; the digest is what gets checked against the local image.
fn check_image(s: &str) -> Result<(), String> {
    let hint = "must be pinned by digest: <image>@sha256:<64 hex chars>";
    let Some((name, digest)) = s.split_once("@sha256:") else {
        return Err(format!("{s:?} {hint}"));
    };
    let name_ok = !name.is_empty()
        && name.len() <= 255
        && name
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && name.bytes().all(|b| {
            b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || matches!(b, b'.' | b'_' | b'-' | b'/' | b':')
        });
    let digest_ok = digest.len() == 64
        && digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if name_ok && digest_ok {
        Ok(())
    } else {
        Err(format!("{s:?} {hint}"))
    }
}

pub(super) fn check_model(m: &Model, d: &mut Diags) {
    let ok = m.reference == "any"
        || m.reference.strip_prefix("library://").is_some_and(|n| {
            !n.is_empty()
                && n.len() <= MAX_MODEL_NAME
                && n.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
                })
        });
    if !ok {
        d.error(
            "model.ref",
            Code::InvalidValue,
            format!(
                "{:?} must be \"any\" or library://<name-or-sha256>",
                m.reference
            ),
        );
    }
    in_range(d, "model.context", m.context, 1, MAX_CONTEXT, |x| {
        x.to_string()
    });
    if let GpuLayers::Layers(n) = m.gpu_layers {
        in_range(d, "model.gpu_layers", n, 0, MAX_GPU_LAYERS, |x| {
            x.to_string()
        });
    }
}

pub(super) fn check_tools(m: &Manifest, d: &mut Diags) {
    let mut seen = HashSet::new();
    for (i, tool) in m.tools.builtin.iter().enumerate() {
        if !seen.insert(*tool) {
            d.error(
                format!("tools.builtin[{i}]"),
                Code::Duplicate,
                format!("{} is listed twice", tool.as_str()),
            );
        }
    }
    check_shell(m, d);
    check_fetch(m, d);
    check_fs_tools(m, d);
}

// The `*_needs_ack` predicates are the single definition of "this widening is live": the
// validator requires the flag exactly when one returns true, and
// `ValidatedManifest::acknowledged_risks` reports the flag exactly then.

/// Some allow rule reaches attacker-registrable hosts. `egress` is the parsed rule list (also
/// parsed under `mode: none`, where the validator still requires the flag so a later mode
/// switch cannot silently widen; the risk is only *in effect* with `mode: proxy`).
pub(super) fn wildcard_needs_ack(egress: &[EgressRule]) -> bool {
    egress.iter().any(|r| r.host.is_effectively_unrestricted())
}

fn check_shell(m: &Manifest, d: &mut Diags) {
    let t = &m.tools;
    let has_shell = t.builtin.contains(&BuiltinTool::Shell);
    match (t.shell, has_shell) {
        (ShellPolicy::Allow, _) => {
            let tail = if t.destructive_requires_approval {
                "unless tagged destructive"
            } else {
                "at all (destructive_requires_approval is false)"
            };
            d.warn(
                "tools.shell",
                Code::Risky,
                format!("\"allow\" — shell commands run without approval {tail}"),
            );
        }
        (ShellPolicy::Deny, true) => d.warn(
            "tools.shell",
            Code::Inconsistent,
            "shell is in tools.builtin but every call is denied",
        ),
        (ShellPolicy::Approve, _) | (ShellPolicy::Deny, false) => {}
    }
    if t.shell != ShellPolicy::Deny && !has_shell {
        d.warn(
            "tools.shell",
            Code::Inconsistent,
            "has no effect: shell is not in tools.builtin",
        );
    }
}

fn check_fetch(m: &Manifest, d: &mut Diags) {
    if m.tools.builtin.contains(&BuiltinTool::Fetch) && m.network.mode == NetworkMode::None {
        d.warn(
            "tools.builtin",
            Code::Inconsistent,
            "fetch is enabled but network.mode is none",
        );
    }
}

/// `fs_read`/`fs_list` act on any mount; `fs_write`/`fs_delete` on `rw` and `brokered` mounts
/// (`ro` → denied; `staged` → denied: only the sandbox's own commands write there). Enabling them with nothing to act on is a mistake worth a warning.
fn check_fs_tools(m: &Manifest, d: &mut Diags) {
    let has = |tool| m.tools.builtin.contains(&tool);
    let mounts = &m.filesystem.mounts;
    if (has(BuiltinTool::FsRead) || has(BuiltinTool::FsList)) && mounts.is_empty() {
        d.warn(
            "tools.builtin",
            Code::Inconsistent,
            "fs_read/fs_list act on mounts, and there are none",
        );
    }
    let writable = mounts
        .iter()
        .any(|mt| matches!(mt.mode, MountMode::Rw | MountMode::Brokered));
    if (has(BuiltinTool::FsWrite) || has(BuiltinTool::FsDelete)) && !writable {
        d.warn(
            "tools.builtin",
            Code::Inconsistent,
            "fs_write/fs_delete act on rw or brokered mounts, and there are none",
        );
    }
}

pub(super) fn check_approvals_and_policy(m: &Manifest, d: &mut Diags) {
    let a = &m.approvals;
    let secs = |x| Duration::from_secs(x).to_string();
    in_range(
        d,
        "approvals.timeout",
        a.timeout.as_secs(),
        APPROVAL_TIMEOUT.0,
        APPROVAL_TIMEOUT.1,
        secs,
    );
    in_range(
        d,
        "approvals.max_pending",
        a.max_pending,
        MAX_PENDING.0,
        MAX_PENDING.1,
        |x| x.to_string(),
    );
    if m.policy.signed_by.is_some() || m.policy.signature.is_some() {
        d.warn(
            "policy",
            Code::Inconsistent,
            "signed policies are not supported in v1; ignored",
        );
    }
}
