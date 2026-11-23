//! Plain-English summary of a validated manifest (MANIFEST_SPEC intro).
//!
//! Generated from the parsed struct, never from YAML text, so it cannot drift from what is
//! enforced. It must never claim *less* than the manifest grants, and every setting that widens
//! the blast radius is named in plain words (SI-5). Host paths are realpaths (CLAUDE.md
//! conventions).
//!
//! RT-MAN-05 (launch summary disguise): every string that comes from the manifest or the host is
//! escaped to printable ASCII by the shared [`crate::text`] alphabet before it is placed in a line
//! (architect Q710), so no text can add a line, drive a terminal or hide behind a direction mark.
//! A list a reader could misjoin is quoted item by item (globs, MCP arguments, the injection header
//! and format), and a cut is marked outside the quoted text. Each setting that differs from its
//! default, where that can widen what the session may do, gets a line naming the default (Q712).
//! The manifest's `description` is not shown; if it ever is, it is one line through the same
//! escape, its newlines and tabs included.

use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

use super::host::HostPattern;
use super::types::{
    Approvals, AuditLevel, BuiltinTool, FetchWrites, Manifest, McpApproval, McpServer, MountMode,
    Network, NetworkMode, Runtime, ShellPolicy,
};
use super::validate::{ResolvedMount, ValidatedManifest, data_can_leave};
use crate::text;

/// Files a host may execute that an `rw` mount cannot protect: `.git` folders found at launch are
/// overlays and `.git` pointer files are read-only (AMENDMENTS-02 B2(a)), but nothing else is,
/// including hooks or config a repository takes from its working tree (6a re-review L7).
const UNPROTECTED_HOST_FILES: &str = "Makefile, package.json scripts, .vscode/tasks.json, .envrc, \
     git hooks or config taken from the folder itself (core.hooksPath, include.path, .husky/), \
     a .git folder created during the session, or a git repository not named .git, such as a \
     bare project.git";
/// Longest rendering of an MCP server's command in the summary: bytes of the escaped, quoted
/// arguments between the backticks (architect Q713).
const MAX_COMMAND_SHOWN: usize = 200;

/// An optional `[data-can-leave]` line, an optional `[direct-write]` line (any `rw` mount; the
/// second line when both are present), then `This agent:` and one line per capability, each
/// starting with `- `. Lines are stable for UI snapshot tests.
#[must_use]
pub fn summary(v: &ValidatedManifest) -> String {
    let m = v.manifest();
    let mut lines = vec![model_line(m)];
    lines.extend(file_lines(m, v.mounts()));
    lines.push(network_line(m, v));
    lines.extend(network_limit_lines(m, v));
    lines.extend(secret_lines(m));
    lines.push(shell_line(m));
    lines.extend(fetch_line(m));
    lines.extend(tool_lines(m));
    lines.extend(approval_lines(m));
    lines.extend(runtime_lines(m));
    let mut out = String::new();
    // TODO(#196): the summary does not mask token-shaped names the way diagnostics do.
    if let Some(finding) = data_can_leave(m, v.mounts(), v.egress()) {
        out.push_str("[data-can-leave] ");
        out.push_str(&bare(&finding));
        out.push('\n');
    }
    if let Some(line) = direct_write_line(v.mounts()) {
        out.push_str(&line);
        out.push('\n');
    }
    out.push_str("This agent:\n");
    for l in lines {
        out.push_str("- ");
        out.push_str(&l);
        out.push('\n');
    }
    out
}

/// Manifest or host text shown as it is, escaped to printable ASCII (RT-MAN-05).
fn bare(s: &str) -> String {
    text::escape(s.as_bytes())
}

/// Manifest text shown between double quotes, escaped, a `"` in it written `\"` (RT-MAN-05).
fn quoted(s: &str) -> String {
    format!("\"{}\"", text::escape_backslash_quoted(s.as_bytes()))
}

/// A host realpath, escaped from its bytes (RT-MAN-05).
fn path(p: &Path) -> String {
    text::escape(p.as_os_str().as_bytes())
}

/// AMENDMENTS-02 B2(b): `rw` stays, with a warning that names the folders and the alternative.
fn direct_write_line(mounts: &[ResolvedMount]) -> Option<String> {
    let hosts: Vec<String> = mounts
        .iter()
        .filter(|mt| mt.mode == MountMode::Rw)
        .map(|mt| path(&mt.host))
        .collect();
    (!hosts.is_empty()).then(|| {
        format!(
            "[direct-write] Changes the agent makes in {} land on your machine at once, with no \
             review. Use mode: staged to review changes before they reach your files.",
            hosts.join(", ")
        )
    })
}

/// Whether the manifest lists `entry` in `tools.acknowledge_unapproved` (a validated manifest
/// lists exactly the needed entries).
fn acknowledged(m: &Manifest, entry: &str) -> bool {
    m.tools.acknowledge_unapproved.iter().any(|e| e == entry)
}

fn model_line(m: &Manifest) -> String {
    match m.model.reference.as_str() {
        "any" => "uses a model you pick at launch.".into(),
        r => format!(
            "uses the model {}.",
            bare(r.trim_start_matches("library://"))
        ),
    }
}

// TODO(#322): realpaths are shown escaped but not quoted, so a folder name holding ", " or
// " (at " can read as two folders or as a guest path.
fn file_lines(m: &Manifest, mounts: &[ResolvedMount]) -> Vec<String> {
    if mounts.is_empty() {
        return vec!["sees no host files.".into()];
    }
    let can = |t| m.tools.builtin.contains(&t);
    mounts
        .iter()
        .map(|mt| {
            let (host, guest) = (path(&mt.host), bare(&mt.guest));
            match mt.mode {
                MountMode::Ro => format!("can read {host} (at {guest})."),
                MountMode::Rw => format!(
                    "can read, write, and delete anything in {host} (at {guest}), directly on \
                     your machine. Its .git folders are shielded: commits made in the session \
                     are discarded, and file changes arrive as uncommitted modifications. Other \
                     files your machine may run are not protected ({UNPROTECTED_HOST_FILES})."
                ),
                MountMode::Staged => format!(
                    "can change files in {host} (at {guest}) only inside the sandbox; your folder \
                     is not changed. The changes are kept apart (`sally session changes` lists \
                     them; this version cannot apply them), and commits made in the session are \
                     never applied.{}",
                    staged_tools(can(BuiltinTool::FsWrite), can(BuiltinTool::FsDelete))
                ),
                MountMode::Brokered => {
                    let writes =
                        brokered_op(can(BuiltinTool::FsWrite), &mt.approve.writes, "write");
                    let deletes =
                        brokered_op(can(BuiltinTool::FsDelete), &mt.approve.deletes, "delete");
                    format!("can read {host} (at {guest}); {writes}; {deletes}.")
                }
            }
        })
        .collect()
}

/// The broker runs `fs_write` and `fs_delete` on a staged mount without asking: they change the
/// session's own copy (architect Q711). Names only the enabled tools.
fn staged_tools(write: bool, delete: bool) -> &'static str {
    match (write, delete) {
        (true, true) => " The fs_write and fs_delete tools change that copy without asking you.",
        (true, false) => " The fs_write tool changes that copy without asking you.",
        (false, true) => " The fs_delete tool changes that copy without asking you.",
        (false, false) => "",
    }
}

fn brokered_op(enabled: bool, globs: &[String], verb: &str) -> String {
    match (enabled, globs.is_empty()) {
        (false, _) => format!("cannot {verb} there"),
        (true, true) => format!("{verb}s without asking you"),
        (true, false) if globs.iter().any(|g| g == "**") => {
            format!("can {verb} there with your approval")
        }
        (true, false) => {
            let shown: Vec<String> = globs.iter().map(|g| quoted(g)).collect();
            format!(
                "can {verb} there; your approval is needed only for {}",
                shown.join(", ")
            )
        }
    }
}

fn network_line(m: &Manifest, v: &ValidatedManifest) -> String {
    let egress = v.egress();
    match m.network.mode {
        NetworkMode::None => "has no network access.".into(),
        NetworkMode::Proxy if egress.is_empty() => {
            "has no network access (proxy on, but no hosts allowed).".into()
        }
        NetworkMode::Proxy => {
            let hosts: Vec<String> = egress
                .iter()
                .map(|r| {
                    let ports: Vec<String> = r.ports.iter().map(u16::to_string).collect();
                    let who = match &r.host {
                        HostPattern::Any => "any public hostname".to_owned(),
                        h if h.is_effectively_unrestricted() => {
                            format!("{} (anyone can register these)", bare(&h.to_string()))
                        }
                        h => bare(&h.to_string()),
                    };
                    format!("{who} on port {}", ports.join("/"))
                })
                .collect();
            format!(
                "can reach {} (through the Sallyport proxy only).",
                hosts.join(", ")
            )
        }
    }
}

/// The proxy's limits that differ from their defaults, when a host is reachable (Q712).
fn network_limit_lines(m: &Manifest, v: &ValidatedManifest) -> Vec<String> {
    if m.network.mode == NetworkMode::None || v.egress().is_empty() {
        return Vec::new();
    }
    let (n, d) = (&m.network, Network::default());
    let mut lines = Vec::new();
    if n.max_request_bytes != d.max_request_bytes {
        lines.push(format!(
            "can send up to {} in one request body the proxy reads, for fetch and at hosts with \
             a credential grant (default {}).",
            n.max_request_bytes, d.max_request_bytes
        ));
    }
    if n.max_response_bytes != d.max_response_bytes {
        lines.push(format!(
            "can receive up to {} in one response body the proxy reads, for fetch and at hosts \
             with a credential grant (default {}).",
            n.max_response_bytes, d.max_response_bytes
        ));
    }
    if n.max_connections != d.max_connections {
        lines.push(format!(
            "can hold up to {} proxy connections open at once (default {}).",
            n.max_connections, d.max_connections
        ));
    }
    lines
}

fn secret_lines(m: &Manifest) -> Vec<String> {
    let mut lines = Vec::new();
    let mut exposed = std::collections::BTreeSet::new();
    for s in &m.secrets {
        lines.push(format!(
            "uses your {} secret only toward {}, sent as the header {} in the form {} (the agent \
             never sees the value).",
            bare(&s.name),
            bare(&s.inject.host),
            quoted(&s.inject.header),
            quoted(&s.inject.format)
        ));
        if let Some(env) = &s.expose_env
            && exposed.insert(env.as_str())
        {
            lines.push(format!(
                "sees {} set to a placeholder, never the real value.",
                bare(env)
            ));
        }
    }
    lines
}

fn shell_line(m: &Manifest) -> String {
    let has_shell_tool = m.tools.builtin.contains(&BuiltinTool::Shell);
    match (m.tools.shell, has_shell_tool) {
        (ShellPolicy::Deny, _) | (_, false) => "cannot run shell commands.".into(),
        (ShellPolicy::Approve, true) => "can run shell commands with your approval.".into(),
        (ShellPolicy::Allow, true) if m.tools.destructive_requires_approval => {
            let ack = if acknowledged(m, "shell") {
                " (acknowledged)"
            } else {
                ""
            };
            format!(
                "can run shell commands without approval (destructive ones need approval){ack}."
            )
        }
        (ShellPolicy::Allow, true) => {
            "can run any shell command without approval (acknowledged).".into()
        }
    }
}

/// Issue 263, the maintainer's words: GET and HEAD never ask, and with a credential grant a
/// request to its host carries the credential.
fn fetch_line(m: &Manifest) -> Option<String> {
    if !m.tools.builtin.contains(&BuiltinTool::Fetch) {
        return None;
    }
    let credential = if m.secrets.is_empty() {
        ""
    } else {
        " At a host with a credential grant it carries that credential."
    };
    Some(match m.tools.fetch_writes {
        FetchWrites::Approve => format!(
            "fetch sends GET and HEAD requests without asking you. A GET can still change things \
             at a host.{credential}"
        ),
        FetchWrites::Allow => {
            let ack = if acknowledged(m, "fetch") {
                " (acknowledged)"
            } else {
                ""
            };
            format!(
                "fetch can send data (POST, PUT, DELETE, ...) without your approval{ack}.\
                 {credential}"
            )
        }
    })
}

fn tool_lines(m: &Manifest) -> Vec<String> {
    let mut lines = Vec::new();
    let tools: Vec<&str> = m
        .tools
        .builtin
        .iter()
        .filter(|t| **t != BuiltinTool::Shell)
        .map(|t| t.as_str())
        .collect();
    if !tools.is_empty() {
        lines.push(format!("may call: {}.", tools.join(", ")));
    }
    lines.extend(m.tools.mcp.iter().map(|s| mcp_line(m, s)));
    lines
}

/// The server's command runs at launch, unapproved, in the workspace (mounts + egress), so the
/// summary shows it; only its tool calls are gated by `approve`. Each argument is quoted; a cut is
/// marked after the closing backtick, naming the input bytes not shown (Q713).
fn mcp_line(m: &Manifest, s: &McpServer) -> String {
    let (cmd, cut) = text::quoted_args_capped(&s.command, MAX_COMMAND_SHOWN);
    let marker = cut.map_or_else(String::new, |n| {
        format!(" (cut here: {n} more bytes not shown)")
    });
    let env = if s.env.is_empty() {
        String::new()
    } else {
        let keys: Vec<String> = s.env.keys().map(|k| bare(k)).collect();
        format!(" with env {}", keys.join(", "))
    };
    let calls = match s.approve {
        McpApproval::Always => "each of its tool calls needs your approval",
        McpApproval::Never if acknowledged(m, &format!("mcp:{}", s.name)) => {
            "its tool calls run without approval (acknowledged)"
        }
        McpApproval::Never => "its tool calls run without approval",
    };
    format!(
        "starts MCP server {} at launch, in its workspace and without approval: \
         `{cmd}`{marker}{env}; {calls}.",
        bare(&s.name)
    )
}

/// `approvals` settings that differ from their defaults, in either direction (Q713).
fn approval_lines(m: &Manifest) -> Vec<String> {
    let (a, d) = (&m.approvals, Approvals::default());
    let mut lines = Vec::new();
    if a.timeout != d.timeout {
        lines.push(format!(
            "an approval request waits up to {} for your answer, then is denied (default {}).",
            a.timeout, d.timeout
        ));
    }
    if a.max_pending != d.max_pending {
        lines.push(format!(
            "up to {} approval requests can wait at once; more are denied (default {}).",
            a.max_pending, d.max_pending
        ));
    }
    lines
}

fn runtime_lines(m: &Manifest) -> Vec<String> {
    let (r, d) = (&m.runtime, Runtime::default());
    let mut lines = Vec::new();
    if let Some(h) = &m.harness {
        lines.push(format!("runs a custom harness image: {}.", bare(&h.image)));
    }
    if let Some(image) = &r.image {
        lines.push(format!(
            "runs tools in a custom workspace image: {}.",
            bare(image)
        ));
    }
    if r.tmp_exec {
        lines.push("can execute files it writes to /tmp.".into());
    }
    if m.audit.level == AuditLevel::Actions {
        lines.push(
            "is audited at reduced detail (every action, connection, intercepted HTTP request \
             line and file read is still recorded; inference response metadata is not)."
                .into(),
        );
    }
    lines.push(format!(
        "is limited to {} CPUs, {} memory, {} processes, and {} of wall time.",
        r.cpus, r.memory, r.pids, r.timeout
    ));
    if r.tmp_size != d.tmp_size {
        lines.push(format!(
            "can write up to {} to /tmp, counted against its memory (default {}).",
            r.tmp_size, d.tmp_size
        ));
    }
    if r.stage_size != d.stage_size {
        lines.push(format!(
            "can write up to {} of staged and .git overlay changes to your disk before it is \
             stopped (default {}).",
            r.stage_size, d.stage_size
        ));
    }
    lines
}
