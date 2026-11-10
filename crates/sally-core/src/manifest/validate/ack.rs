//! `tools.acknowledge_unapproved` (AMENDMENTS-02 B3): one list for every unapproved channel.
//!
//! [`needed`] is the single definition of "this widening is live": the validator requires an
//! entry exactly when it returns that entry, refuses entries it does not return (so a stale
//! acknowledgement cannot linger), and `ValidatedManifest::acknowledged_risks` reports exactly
//! the listed, needed entries.

use std::collections::HashSet;

use super::super::diag::{Code, Diags};
use super::super::types::{
    BuiltinTool, FetchWrites, Manifest, McpApproval, NetworkMode, ShellPolicy,
};

const FIELD: &str = "tools.acknowledge_unapproved";
const SHELL: &str = "shell";
const FETCH: &str = "fetch";
const MCP_PREFIX: &str = "mcp:";

/// Any mount or secret: something the model could read or act on that is not public. Reads the
/// raw manifest; equivalent to the resolved mounts once validation has passed.
fn has_private_data(m: &Manifest) -> bool {
    !m.filesystem.mounts.is_empty() || !m.secrets.is_empty()
}

/// `shell: allow` (with the tool granted) when destructive approval is off, or when the
/// `[data-can-leave]` finding fires: unapproved commands could then carry private data out.
fn shell_needs(m: &Manifest, data_can_leave: bool) -> bool {
    m.tools.builtin.contains(&BuiltinTool::Shell)
        && m.tools.shell == ShellPolicy::Allow
        && (!m.tools.destructive_requires_approval || data_can_leave)
}

/// `fetch` enabled with unapproved writes, a network path, and private data to carry out.
fn fetch_needs(m: &Manifest) -> bool {
    m.tools.builtin.contains(&BuiltinTool::Fetch)
        && m.tools.fetch_writes == FetchWrites::Allow
        && m.network.mode == NetworkMode::Proxy
        && has_private_data(m)
}

/// The entries this manifest needs, in a fixed order: `shell`, `fetch`, then `mcp:<name>` in
/// server order.
pub(super) fn needed(m: &Manifest, data_can_leave: bool) -> Vec<String> {
    let mut out = Vec::new();
    if shell_needs(m, data_can_leave) {
        out.push(SHELL.to_owned());
    }
    if fetch_needs(m) {
        out.push(FETCH.to_owned());
    }
    if has_private_data(m) {
        out.extend(
            m.tools
                .mcp
                .iter()
                .filter(|s| s.approve == McpApproval::Never)
                .map(|s| format!("{MCP_PREFIX}{}", s.name)),
        );
    }
    out
}

/// Why an entry is needed, for the error that asks for it.
fn reason(m: &Manifest, entry: &str) -> String {
    match entry {
        SHELL if !m.tools.destructive_requires_approval => {
            "shell: allow with destructive_requires_approval: false runs every command without approval"
                .to_owned()
        }
        SHELL => "shell: allow runs commands without approval while mounted files or secrets can \
                  reach an allowed host ([data-can-leave])"
            .to_owned(),
        FETCH => "fetch_writes: allow lets fetch send mounted files or data your secrets unlock \
                  without approval"
            .to_owned(),
        _ => format!(
            "MCP server {} has approve: never, so its tool calls run without approval while it \
             can reach mounted files or secrets",
            entry.trim_start_matches(MCP_PREFIX)
        ),
    }
}

/// Whether `entry` names something that exists in this manifest at all.
fn is_known(m: &Manifest, entry: &str) -> bool {
    match entry.strip_prefix(MCP_PREFIX) {
        Some(name) => m.tools.mcp.iter().any(|s| s.name == name),
        None => entry == SHELL || entry == FETCH,
    }
}

/// Requires every needed entry; refuses unknown, duplicate and unneeded ones.
pub(super) fn check(m: &Manifest, data_can_leave: bool, d: &mut Diags) {
    let needed = needed(m, data_can_leave);
    let listed = &m.tools.acknowledge_unapproved;
    let mut seen = HashSet::new();
    for (i, entry) in listed.iter().enumerate() {
        let at = format!("{FIELD}[{i}]");
        if !is_known(m, entry) {
            d.error(
                at,
                Code::InvalidValue,
                "unknown entry; use shell, fetch or mcp:<server name> exactly",
            );
        } else if !seen.insert(entry.as_str()) {
            d.error(at, Code::Duplicate, "listed twice");
        } else if !needed.contains(entry) {
            d.error(
                at,
                Code::Inconsistent,
                "not needed: nothing in this manifest runs unapproved through it; remove it",
            );
        }
    }
    for entry in &needed {
        if !listed.contains(entry) {
            d.error(
                FIELD,
                Code::UnacknowledgedRisk,
                format!(
                    "{}; add {entry:?} to {FIELD} to accept this",
                    reason(m, entry)
                ),
            );
        }
    }
}

/// Listed entries that are needed, as `tools.acknowledge_unapproved: <entry>`, in [`needed`]
/// order.
pub(super) fn acknowledged(m: &Manifest, data_can_leave: bool) -> Vec<String> {
    needed(m, data_can_leave)
        .into_iter()
        .filter(|e| m.tools.acknowledge_unapproved.contains(e))
        .map(|e| format!("{FIELD}: {e}"))
        .collect()
}
