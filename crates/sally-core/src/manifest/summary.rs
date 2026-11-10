//! Plain-English summary of a validated manifest (MANIFEST_SPEC intro).
//!
//! Generated from the parsed struct, never from YAML text, so it cannot drift from what is
//! enforced. It must never claim *less* than the manifest grants, and every setting that widens
//! the blast radius is named in plain words (SI-5). Host paths are realpaths (CLAUDE.md
//! conventions).

use super::host::HostPattern;
use super::types::{
    AuditLevel, BuiltinTool, FetchWrites, Manifest, McpApproval, McpServer, MountMode, NetworkMode,
    ShellPolicy,
};
use super::validate::{ResolvedMount, ValidatedManifest, data_can_leave};

/// Files a host may execute that an `rw` mount cannot protect: `.git` folders found at launch are
/// overlays and `.git` pointer files are read-only (AMENDMENTS-02 B2(a)), but nothing else is,
/// including hooks or config a repository takes from its working tree (6a re-review L7).
const UNPROTECTED_HOST_FILES: &str = "Makefile, package.json scripts, .vscode/tasks.json, .envrc, \
     git hooks or config taken from the folder itself (core.hooksPath, include.path, .husky/), \
     a .git folder created during the session, or a git repository not named .git, such as a \
     bare project.git";
/// Longest rendering of an MCP server's command in the summary.
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
    lines.extend(secret_lines(m));
    lines.push(shell_line(m));
    lines.extend(fetch_line(m));
    lines.extend(tool_lines(m));
    lines.extend(runtime_lines(m));
    let mut out = String::new();
    if let Some(finding) = data_can_leave(m, v.mounts(), v.egress()) {
        out.push_str("[data-can-leave] ");
        out.push_str(&finding);
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

/// AMENDMENTS-02 B2(b): `rw` stays, with a warning that names the folders and the alternative.
fn direct_write_line(mounts: &[ResolvedMount]) -> Option<String> {
    let hosts: Vec<String> = mounts
        .iter()
        .filter(|mt| mt.mode == MountMode::Rw)
        .map(|mt| mt.host.display().to_string())
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
        r => format!("uses the model {}.", r.trim_start_matches("library://")),
    }
}

fn file_lines(m: &Manifest, mounts: &[ResolvedMount]) -> Vec<String> {
    if mounts.is_empty() {
        return vec!["sees no host files.".into()];
    }
    let can = |t| m.tools.builtin.contains(&t);
    mounts
        .iter()
        .map(|mt| {
            let (host, guest) = (mt.host.display(), &mt.guest);
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
                     never applied."
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

fn brokered_op(enabled: bool, globs: &[String], verb: &str) -> String {
    match (enabled, globs.is_empty()) {
        (false, _) => format!("cannot {verb} there"),
        (true, true) => format!("{verb}s without asking you"),
        (true, false) if globs.iter().any(|g| g == "**") => {
            format!("can {verb} there with your approval")
        }
        (true, false) => format!(
            "can {verb} there; your approval is needed only for {}",
            globs.join(", ")
        ),
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
                            format!("{h} (anyone can register these)")
                        }
                        h => h.to_string(),
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

fn secret_lines(m: &Manifest) -> Vec<String> {
    let mut lines = Vec::new();
    let mut exposed = std::collections::BTreeSet::new();
    for s in &m.secrets {
        lines.push(format!(
            "uses your {} secret only toward {} (the agent never sees the value).",
            s.name, s.inject.host
        ));
        if let Some(env) = &s.expose_env
            && exposed.insert(env.as_str())
        {
            lines.push(format!(
                "sees {env} set to a placeholder, never the real value."
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

fn fetch_line(m: &Manifest) -> Option<String> {
    if !m.tools.builtin.contains(&BuiltinTool::Fetch) {
        return None;
    }
    Some(match m.tools.fetch_writes {
        FetchWrites::Approve => "fetch can only read (GET/HEAD) without your approval.".into(),
        FetchWrites::Allow => {
            let ack = if acknowledged(m, "fetch") {
                " (acknowledged)"
            } else {
                ""
            };
            format!("fetch can send data (POST, PUT, DELETE, …) without your approval{ack}.")
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
/// summary shows it; only its tool calls are gated by `approve`.
fn mcp_line(m: &Manifest, s: &McpServer) -> String {
    let mut cmd = s
        .command
        .iter()
        .map(|a| {
            if a.is_empty() || a.chars().any(|c| c.is_whitespace() || c == '`' || c == '"') {
                format!("{a:?}")
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    if let Some((cut, _)) = cmd.char_indices().nth(MAX_COMMAND_SHOWN) {
        cmd.truncate(cut);
        cmd.push('…');
    }
    let env = if s.env.is_empty() {
        String::new()
    } else {
        let keys: Vec<&str> = s.env.keys().map(String::as_str).collect();
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
        "starts MCP server {} at launch, in its workspace and without approval: `{cmd}`{env}; {calls}.",
        s.name
    )
}

fn runtime_lines(m: &Manifest) -> Vec<String> {
    let r = &m.runtime;
    let mut lines = Vec::new();
    if let Some(h) = &m.harness {
        lines.push(format!("runs a custom harness image: {}.", h.image));
    }
    if let Some(image) = &r.image {
        lines.push(format!("runs tools in a custom workspace image: {image}."));
    }
    if r.tmp_exec {
        lines.push("can execute files it writes to /tmp.".into());
    }
    if m.audit.level == AuditLevel::Actions {
        lines.push(
            "is audited at reduced detail (every action and connection is still recorded; \
             per-request HTTP lines, file reads, and inference metadata are not)."
                .into(),
        );
    }
    lines.push(format!(
        "is limited to {} CPUs, {} memory, {} processes, and {} of wall time.",
        r.cpus, r.memory, r.pids, r.timeout
    ));
    lines
}
