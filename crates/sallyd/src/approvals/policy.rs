//! Which actions wait for a human (SI-5; MANIFEST_SPEC §1.1 and §3). Pure: a [`Policy`] built
//! once from the validated manifest, and an [`Action`] in, a [`Need`] out.
//!
//! Omission never disables a gate: a mount, server or method the policy does not know is denied
//! or asked, never run. Every denial comes before any ask, so nobody is asked about an action
//! that could not run (architect ruling Q27). Under `shell: approve` every command asks; commands
//! are not sorted into safe and dangerous (maintainer's Task 10 decision 5). Under `shell: allow`
//! with `destructive_requires_approval`, the destructive tag is an input: `tools::shell`'s tagger
//! (Task 11) supplies it, and without a tag the command asks. Protected paths are refused by
//! `tools::fs` (Task 11, #19) before it builds the action.

use sally_core::manifest::{
    ApproveGlobs, BuiltinTool, FetchWrites, McpApproval, MountMode, ShellPolicy, ValidatedManifest,
};

use super::action::{Action, Target};
use super::glob;

/// What an action needs before it runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Need {
    /// Runs without approval.
    Run,
    /// Waits for a human decision.
    Ask,
    /// Never runs; the code is the `denied: <code>` text.
    Deny(&'static str),
}

/// One mount, as the gate sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountRule {
    /// Guest root.
    pub guest: String,
    /// Access mode.
    pub mode: MountMode,
    /// Approval globs (meaningful for `brokered`).
    pub approve: ApproveGlobs,
}

/// The approval-relevant part of a session's manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// `tools.builtin`.
    pub builtin: Vec<BuiltinTool>,
    /// `tools.shell`.
    pub shell: ShellPolicy,
    /// `tools.destructive_requires_approval`.
    pub destructive_requires_approval: bool,
    /// `tools.fetch_writes`.
    pub fetch_writes: FetchWrites,
    /// `filesystem.mounts`, resolved.
    pub mounts: Vec<MountRule>,
    /// `tools.mcp[]`: name and `approve`.
    pub mcp: Vec<(String, McpApproval)>,
}

impl Policy {
    /// The policy of a validated manifest.
    #[must_use]
    pub fn from_manifest(v: &ValidatedManifest) -> Self {
        let m = v.manifest();
        Self {
            builtin: m.tools.builtin.clone(),
            shell: m.tools.shell,
            destructive_requires_approval: m.tools.destructive_requires_approval,
            fetch_writes: m.tools.fetch_writes,
            mounts: v
                .mounts()
                .iter()
                .map(|r| MountRule {
                    guest: r.guest.clone(),
                    mode: r.mode,
                    approve: r.approve.clone(),
                })
                .collect(),
            mcp: m
                .tools
                .mcp
                .iter()
                .map(|s| (s.name.clone(), s.approve))
                .collect(),
        }
    }

    /// What `action` needs. `destructive` is the shell tagger's verdict for a shell command
    /// (`None`: no tagger ran); other actions ignore it.
    #[must_use]
    pub fn need(&self, action: &Action, destructive: Option<bool>) -> Need {
        let builtin = match action {
            Action::Shell { .. } => Some(BuiltinTool::Shell),
            Action::FsWrite { .. } => Some(BuiltinTool::FsWrite),
            Action::FsDelete { .. } => Some(BuiltinTool::FsDelete),
            Action::Fetch { .. } => Some(BuiltinTool::Fetch),
            Action::Mcp { .. } => None,
        };
        if builtin.is_some_and(|t| !self.builtin.contains(&t)) {
            return Need::Deny("tool_not_granted");
        }
        match action {
            Action::Shell { .. } => match self.shell {
                ShellPolicy::Deny => Need::Deny("shell-denied"),
                ShellPolicy::Approve => Need::Ask,
                ShellPolicy::Allow if !self.destructive_requires_approval => Need::Run,
                ShellPolicy::Allow => match destructive {
                    Some(false) => Need::Run,
                    Some(true) | None => Need::Ask,
                },
            },
            Action::FsWrite { target, .. } => self.file(target, |g| &g.writes),
            Action::FsDelete { target } => self.file(target, |g| &g.deletes),
            Action::Fetch {
                method,
                body,
                headers,
                ..
            } => {
                // HTTP methods are case-sensitive: only these exact spellings are reads, and only
                // with no body and no header that turns them into something else.
                let read = (method == "GET" || method == "HEAD")
                    && body.is_empty()
                    && !headers
                        .iter()
                        .any(|(n, _)| WRITE_HEADERS.iter().any(|w| n.eq_ignore_ascii_case(w)));
                if read {
                    Need::Run
                } else {
                    match self.fetch_writes {
                        FetchWrites::Approve => Need::Ask,
                        FetchWrites::Allow => Need::Run,
                    }
                }
            }
            Action::Mcp { server, .. } => match self.mcp.iter().find(|(n, _)| n == server) {
                None => Need::Deny("unknown-server"),
                Some((_, McpApproval::Always)) => Need::Ask,
                Some((_, McpApproval::Never)) => Need::Run,
            },
        }
    }

    fn file(&self, t: &Target, globs: impl Fn(&ApproveGlobs) -> &Vec<String>) -> Need {
        // The globs match canonical paths only; anything else could match less than it should.
        if !canonical(&t.rel) {
            return Need::Deny("bad-path");
        }
        let Some(m) = self.mounts.iter().find(|m| m.guest == t.mount) else {
            return Need::Deny("unknown-mount");
        };
        match m.mode {
            MountMode::Ro | MountMode::Staged => Need::Deny("read-only"),
            MountMode::Rw => Need::Run,
            MountMode::Brokered => {
                if glob::any_matches(globs(&m.approve), &t.rel) {
                    Need::Ask
                } else {
                    Need::Run
                }
            }
        }
    }
}

/// Request headers that make a GET or HEAD a write: method overrides many servers honour, and
/// body framing on a request that has no body.
const WRITE_HEADERS: [&str; 5] = [
    "x-http-method-override",
    "x-http-method",
    "x-method-override",
    "content-length",
    "transfer-encoding",
];

/// A canonical path relative to a mount: not empty, not absolute, no empty, `.` or `..`
/// segment, at most [`glob::MAX_PATH`] bytes.
fn canonical(rel: &str) -> bool {
    !rel.is_empty()
        && rel.len() <= glob::MAX_PATH
        && rel.split('/').all(|s| !matches!(s, "" | "." | ".."))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::super::action::Payload;
    use super::*;

    fn policy() -> Policy {
        Policy {
            builtin: vec![
                BuiltinTool::Shell,
                BuiltinTool::FsWrite,
                BuiltinTool::FsDelete,
                BuiltinTool::Fetch,
            ],
            shell: ShellPolicy::Approve,
            destructive_requires_approval: true,
            fetch_writes: FetchWrites::Approve,
            mounts: vec![
                rule(
                    "/workspace/ro",
                    MountMode::Ro,
                    ApproveGlobs::not_applicable(),
                ),
                rule(
                    "/workspace/rw",
                    MountMode::Rw,
                    ApproveGlobs::not_applicable(),
                ),
                rule(
                    "/workspace/st",
                    MountMode::Staged,
                    ApproveGlobs::not_applicable(),
                ),
                rule(
                    "/workspace/all",
                    MountMode::Brokered,
                    ApproveGlobs::everything(),
                ),
                rule(
                    "/workspace/notes",
                    MountMode::Brokered,
                    ApproveGlobs {
                        writes: vec!["*.md".to_owned()],
                        deletes: vec![],
                    },
                ),
            ],
            mcp: vec![
                ("gh".to_owned(), McpApproval::Always),
                ("calc".to_owned(), McpApproval::Never),
            ],
        }
    }

    fn rule(guest: &str, mode: MountMode, approve: ApproveGlobs) -> MountRule {
        MountRule {
            guest: guest.to_owned(),
            mode,
            approve,
        }
    }

    fn target(mount: &str, rel: &str) -> Target {
        Target {
            mount: mount.to_owned(),
            rel: rel.to_owned(),
            host: format!("/h{mount}/{rel}"),
        }
    }

    fn write(mount: &str, rel: &str) -> Action {
        Action::FsWrite {
            target: target(mount, rel),
            content: Payload::new(b"x".to_vec()),
        }
    }

    fn delete(mount: &str, rel: &str) -> Action {
        Action::FsDelete {
            target: target(mount, rel),
        }
    }

    fn shell() -> Action {
        Action::Shell {
            argv: vec!["ls".to_owned()],
            cwd: "/workspace/rw".to_owned(),
        }
    }

    fn fetch(method: &str) -> Action {
        Action::Fetch {
            method: method.to_owned(),
            url: "https://h/".to_owned(),
            headers: vec![],
            body: Payload::new(vec![]),
        }
    }

    fn mcp(server: &str) -> Action {
        Action::Mcp {
            server: server.to_owned(),
            tool: "t".to_owned(),
            args: Payload::new(b"{}".to_vec()),
        }
    }

    #[test]
    fn shell_follows_tools_shell_and_every_command_asks_under_approve() {
        let mut p = policy();
        assert_eq!(need(&p, &shell()), Need::Ask);
        let harmless = Action::Shell {
            argv: vec!["true".to_owned()],
            cwd: "/".to_owned(),
        };
        assert_eq!(need(&p, &harmless), Need::Ask);
        // Under approve a tag changes nothing: commands are not sorted (decision 5).
        assert_eq!(p.need(&harmless, Some(false)), Need::Ask);
        p.shell = ShellPolicy::Deny;
        assert_eq!(need(&p, &shell()), Need::Deny("shell-denied"));
        assert_eq!(p.need(&shell(), Some(true)), Need::Deny("shell-denied"));
    }

    #[test]
    fn allow_asks_for_tagged_and_untagged_commands_while_destructive_needs_approval() {
        let mut p = policy();
        p.shell = ShellPolicy::Allow;
        assert_eq!(p.need(&shell(), Some(false)), Need::Run);
        assert_eq!(p.need(&shell(), Some(true)), Need::Ask);
        // No tagger ran (Task 11 not wired): never Run.
        assert_eq!(p.need(&shell(), None), Need::Ask);
        p.destructive_requires_approval = false;
        for tag in [None, Some(true), Some(false)] {
            assert_eq!(p.need(&shell(), tag), Need::Run);
        }
    }

    #[test]
    fn an_ungranted_tool_is_denied_before_anything_asks() {
        let mut p = policy();
        p.builtin.clear();
        assert_eq!(need(&p, &shell()), Need::Deny("tool_not_granted"));
        assert_eq!(
            need(&p, &write("/workspace/all", "x")),
            Need::Deny("tool_not_granted")
        );
        assert_eq!(
            need(&p, &delete("/workspace/all", "x")),
            Need::Deny("tool_not_granted")
        );
        assert_eq!(need(&p, &fetch("POST")), Need::Deny("tool_not_granted"));
        // MCP tools are granted by declaring the server, not by tools.builtin.
        assert_eq!(need(&p, &mcp("gh")), Need::Ask);
        // Granting one tool grants only it.
        p.builtin.push(BuiltinTool::FsWrite);
        assert_eq!(need(&p, &write("/workspace/all", "x")), Need::Ask);
        assert_eq!(
            need(&p, &delete("/workspace/all", "x")),
            Need::Deny("tool_not_granted")
        );
    }

    #[test]
    fn a_validated_manifest_gives_its_policy() {
        use sally_core::manifest::{HostEnv, load};
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/approvals-policy-fixture/notes");
        std::fs::create_dir_all(&dir).unwrap();
        let host = std::fs::canonicalize(&dir).unwrap();
        let env = HostEnv {
            home: "/nonexistent/home".into(),
            other_homes: Vec::new(),
            xdg_config_home: None,
            xdg_data_home: None,
            xdg_runtime_dir: None,
            podman_storage: Vec::new(),
            nproc: 8,
            mem_bytes: 16 << 30,
        };
        let body = format!(
            "apiVersion: sallyport/v1\nkind: Manifest\nname: t\nmodel:\n  ref: any\n\
             filesystem:\n  mounts:\n    - host: {}\n      guest: /workspace/notes\n      \
             mode: brokered\n      approve:\n        writes: [\"*.md\"]\n        deletes: []\n\
             tools:\n  builtin: [fs_write, fs_delete, shell]\n  shell: allow\n  \
             destructive_requires_approval: true\n  fetch_writes: allow\n  \
             acknowledge_unapproved: [\"mcp:gh\"]\n  mcp:\n    - name: gh\n      command: [gh]\n      \
             approve: never\n",
            host.display()
        );
        let v = load(&body, &env, &std::collections::BTreeSet::new())
            .unwrap()
            .manifest;
        let p = Policy::from_manifest(&v);
        let want = Policy {
            builtin: vec![
                BuiltinTool::FsWrite,
                BuiltinTool::FsDelete,
                BuiltinTool::Shell,
            ],
            shell: ShellPolicy::Allow,
            destructive_requires_approval: true,
            fetch_writes: FetchWrites::Allow,
            mounts: vec![rule(
                "/workspace/notes",
                MountMode::Brokered,
                ApproveGlobs {
                    writes: vec!["*.md".to_owned()],
                    deletes: vec![],
                },
            )],
            mcp: vec![("gh".to_owned(), McpApproval::Never)],
        };
        assert_eq!(p, want);
    }

    fn need(p: &Policy, a: &Action) -> Need {
        p.need(a, None)
    }

    #[test]
    fn brokered_writes_ask_where_a_glob_matches_and_run_elsewhere() {
        let p = policy();
        assert_eq!(need(&p, &write("/workspace/notes", "a.md")), Need::Ask);
        assert_eq!(need(&p, &write("/workspace/notes", "a.txt")), Need::Run);
        assert_eq!(need(&p, &write("/workspace/notes", "d/a.md")), Need::Run);
        assert_eq!(need(&p, &write("/workspace/all", "any/thing")), Need::Ask);
    }

    #[test]
    fn brokered_deletes_use_their_own_globs() {
        let p = policy();
        assert_eq!(need(&p, &delete("/workspace/all", "x")), Need::Ask);
        // `deletes: []` on notes: an explicit empty list runs unapproved (MANIFEST_SPEC §1.1).
        assert_eq!(need(&p, &delete("/workspace/notes", "a.md")), Need::Run);
    }

    #[test]
    fn rw_runs_and_ro_staged_and_unknown_mounts_are_denied() {
        let p = policy();
        for a in [write("/workspace/rw", "x"), delete("/workspace/rw", "x")] {
            assert_eq!(need(&p, &a), Need::Run);
        }
        for m in ["/workspace/ro", "/workspace/st"] {
            assert_eq!(need(&p, &write(m, "x")), Need::Deny("read-only"));
            assert_eq!(need(&p, &delete(m, "x")), Need::Deny("read-only"));
        }
        assert_eq!(
            need(&p, &write("/workspace/nope", "x")),
            Need::Deny("unknown-mount")
        );
        assert_eq!(
            need(&p, &write("/workspace/notes/sub", "a.md")),
            Need::Deny("unknown-mount")
        );
    }

    #[test]
    fn fetch_reads_run_and_every_other_method_follows_fetch_writes() {
        let mut p = policy();
        assert_eq!(need(&p, &fetch("GET")), Need::Run);
        assert_eq!(need(&p, &fetch("HEAD")), Need::Run);
        for m in [
            "POST", "PUT", "PATCH", "DELETE", "get", "head", "OPTIONS", "",
        ] {
            assert_eq!(need(&p, &fetch(m)), Need::Ask, "{m}");
        }
        // A read with a body is a write.
        for m in ["GET", "HEAD"] {
            let Action::Fetch {
                method,
                url,
                headers,
                ..
            } = fetch(m)
            else {
                unreachable!()
            };
            let with_body = Action::Fetch {
                method,
                url,
                headers,
                body: Payload::new(b"x".to_vec()),
            };
            assert_eq!(need(&p, &with_body), Need::Ask, "{m}");
        }
        // A read with a header that makes it a write.
        for h in WRITE_HEADERS
            .iter()
            .map(|h| h.to_ascii_uppercase())
            .chain(["X-Http-Method-Override".to_owned()])
        {
            let a = Action::Fetch {
                method: "GET".to_owned(),
                url: "https://h/".to_owned(),
                headers: vec![
                    ("Accept".to_owned(), "*/*".to_owned()),
                    (h.clone(), "DELETE".to_owned()),
                ],
                body: Payload::new(vec![]),
            };
            assert_eq!(need(&p, &a), Need::Ask, "{h}");
        }
        let plain = Action::Fetch {
            method: "HEAD".to_owned(),
            url: "https://h/".to_owned(),
            headers: vec![("Accept".to_owned(), "*/*".to_owned())],
            body: Payload::new(vec![]),
        };
        assert_eq!(need(&p, &plain), Need::Run);
        p.fetch_writes = FetchWrites::Allow;
        assert_eq!(need(&p, &fetch("POST")), Need::Run);
        assert_eq!(need(&p, &fetch("GET")), Need::Run);
    }

    #[test]
    fn a_path_that_is_not_canonical_is_denied_before_any_glob() {
        let p = policy();
        let too_long = "a".repeat(glob::MAX_PATH + 1);
        let at_bound = "a".repeat(glob::MAX_PATH);
        for rel in [
            "", "/a.md", "./a.md", "a.md/", "d//a.md", "d/./a.md", "../a.md", "d/..", &too_long,
        ] {
            for m in ["/workspace/notes", "/workspace/rw", "/workspace/all"] {
                assert_eq!(
                    need(&p, &write(m, rel)),
                    Need::Deny("bad-path"),
                    "{m} {rel}"
                );
                assert_eq!(
                    need(&p, &delete(m, rel)),
                    Need::Deny("bad-path"),
                    "{m} {rel}"
                );
            }
        }
        for rel in ["a.md", ".hidden", "d/a..b", &at_bound] {
            assert_ne!(
                need(&p, &write("/workspace/rw", rel)),
                Need::Deny("bad-path")
            );
        }
    }

    #[test]
    fn mcp_follows_each_servers_approve_and_unknown_servers_are_denied() {
        let p = policy();
        assert_eq!(need(&p, &mcp("gh")), Need::Ask);
        assert_eq!(need(&p, &mcp("calc")), Need::Run);
        assert_eq!(need(&p, &mcp("other")), Need::Deny("unknown-server"));
    }
}
