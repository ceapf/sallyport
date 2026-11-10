//! Task 6a: AMENDMENTS-02 B3 (one `tools.acknowledge_unapproved` list) and B2(b) (the `staged`
//! mount mode), plus the B2 summary lines for `rw`. Allow + deny for every enforcement point.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{Fixture, assert_ok, assert_rejects, errors, warnings};
use sally_core::manifest::{Code, MountMode, parse, summary};

const PROXY: &str = "network:\n  mode: proxy\n  allow:\n    - host: api.github.com\n";

fn mount(mode: &str) -> String {
    format!(
        "filesystem:\n  mounts:\n    - host: \"~/code/myproject\"\n      guest: /workspace/p\n      mode: {mode}\n"
    )
}

fn mcp_never() -> &'static str {
    "  mcp:\n    - name: docs\n      command: [docs-server]\n      approve: never\n"
}

// ---- B3: the list replaces the two flags ------------------------------------------------------

#[test]
fn the_old_boolean_flags_are_unknown_fields() {
    for flag in [
        "acknowledge_unapproved_shell",
        "acknowledge_unapproved_fetch",
    ] {
        let e = parse(&format!("{}tools:\n  {flag}: true\n", common::HEADER)).unwrap_err();
        assert_eq!(e.errors[0].code, Code::Schema, "{flag}");
        assert_eq!(e.errors[0].path, format!("tools.{flag}"));
    }
}

#[test]
fn allowed_shell_needs_acknowledgement_when_data_can_leave() {
    let f = Fixture::new();
    // Destructive approval kept, but private data plus an outward channel: B3 requires `shell`.
    let base = format!(
        "{}{PROXY}tools:\n  builtin: [shell]\n  shell: allow\n",
        mount("ro")
    );
    assert_rejects(
        &f.load(&base),
        "tools.acknowledge_unapproved",
        Code::UnacknowledgedRisk,
    );
    let r = f.load(&format!("{base}  acknowledge_unapproved: [shell]\n"));
    assert_ok(&r);
    let v = r.unwrap().manifest;
    assert_eq!(
        v.acknowledged_risks(),
        vec!["tools.acknowledge_unapproved: shell"]
    );
    assert!(summary(&v).contains("(acknowledged)"), "{}", summary(&v));
    // Same shell policy without an outward channel: nothing to acknowledge, and listing it is
    // an error.
    let no_leave = format!(
        "{}tools:\n  builtin: [shell]\n  shell: allow\n",
        mount("ro")
    );
    assert_ok(&f.load(&no_leave));
    assert_rejects(
        &f.load(&format!("{no_leave}  acknowledge_unapproved: [shell]\n")),
        "tools.acknowledge_unapproved[0]",
        Code::Inconsistent,
    );
}

#[test]
fn mcp_without_approval_needs_acknowledgement_only_with_private_data() {
    let f = Fixture::new();
    let with_data = format!("{}tools:\n{}", mount("ro"), mcp_never());
    assert_rejects(
        &f.load(&with_data),
        "tools.acknowledge_unapproved",
        Code::UnacknowledgedRisk,
    );
    let r = f.load(&format!(
        "{with_data}  acknowledge_unapproved: [\"mcp:docs\"]\n"
    ));
    assert_ok(&r);
    let v = r.unwrap().manifest;
    assert_eq!(
        v.acknowledged_risks(),
        vec!["tools.acknowledge_unapproved: mcp:docs"]
    );
    let s = summary(&v);
    assert!(
        s.contains("its tool calls run without approval (acknowledged)"),
        "{s}"
    );
    // No mount and no secret: nothing private, no acknowledgement, and listing it is an error.
    let bare = format!("tools:\n{}", mcp_never());
    assert_ok(&f.load(&bare));
    assert_rejects(
        &f.load(&format!("{bare}  acknowledge_unapproved: [\"mcp:docs\"]\n")),
        "tools.acknowledge_unapproved[0]",
        Code::Inconsistent,
    );
    // approve: always never needs one.
    let always = format!(
        "{}tools:\n  mcp:\n    - name: docs\n      command: [docs-server]\n",
        mount("ro")
    );
    assert_ok(&f.load(&always));
}

#[test]
fn unknown_and_duplicate_entries_are_errors() {
    let f = Fixture::new();
    let base = format!("{}tools:\n{}", mount("ro"), mcp_never());
    for bad in [
        "bogus",
        "mcp:",
        "mcp:nosuch",
        "MCP:docs",
        "Shell",
        "mcp:docs ",
    ] {
        let r = f.load(&format!(
            "{base}  acknowledge_unapproved: [\"mcp:docs\", \"{bad}\"]\n"
        ));
        assert_eq!(
            errors(&r),
            vec![(
                "tools.acknowledge_unapproved[1]".to_owned(),
                Code::InvalidValue
            )],
            "{bad:?}"
        );
    }
    let r = f.load(&format!(
        "{base}  acknowledge_unapproved: [\"mcp:docs\", \"mcp:docs\"]\n"
    ));
    assert_eq!(
        errors(&r),
        vec![(
            "tools.acknowledge_unapproved[1]".to_owned(),
            Code::Duplicate
        )]
    );
}

#[test]
fn several_needed_entries_each_appear_once() {
    let f = Fixture::new();
    let body = format!(
        "{}{PROXY}tools:\n  builtin: [shell, fetch]\n  shell: allow\n  fetch_writes: allow\n{}  acknowledge_unapproved: [fetch, \"mcp:docs\", shell]\n",
        mount("ro"),
        mcp_never()
    );
    let r = f.load(&body);
    assert_ok(&r);
    assert_eq!(
        r.unwrap().manifest.acknowledged_risks(),
        vec![
            "tools.acknowledge_unapproved: shell",
            "tools.acknowledge_unapproved: fetch",
            "tools.acknowledge_unapproved: mcp:docs",
        ]
    );
}

// ---- B2(b): staged -----------------------------------------------------------------------------

#[test]
fn staged_mounts_validate_and_leave_the_host_folder_untouched_in_the_summary() {
    let f = Fixture::new();
    let r = f.load(&mount("staged"));
    assert_ok(&r);
    let v = r.unwrap().manifest;
    assert_eq!(v.mounts()[0].mode, MountMode::Staged);
    let s = summary(&v);
    assert!(
        s.contains("only inside the sandbox; your folder is not changed"),
        "{s}"
    );
    assert!(s.contains("sally session changes"), "{s}");
    assert!(!s.contains("[direct-write]"), "{s}");
}

#[test]
fn rw_summary_warns_direct_write_and_states_that_commits_are_discarded() {
    let f = Fixture::new();
    let s = summary(&f.load(&mount("rw")).unwrap().manifest);
    let first = s.lines().next().unwrap();
    assert!(first.starts_with("[direct-write] "), "{s}");
    assert!(first.contains("mode: staged"), "{s}");
    assert!(
        s.contains("commits made in the session are discarded"),
        "{s}"
    );
    assert!(s.contains("uncommitted modifications"), "{s}");
    // With [data-can-leave], [direct-write] is the second line.
    let s = summary(&f.load(&format!("{}{PROXY}", mount("rw"))).unwrap().manifest);
    let lines: Vec<&str> = s.lines().collect();
    assert!(lines[0].starts_with("[data-can-leave] "), "{s}");
    assert!(lines[1].starts_with("[direct-write] "), "{s}");
}

#[test]
fn staged_mounts_reject_approve_globs_like_rw() {
    let f = Fixture::new();
    let r = f.load(&format!(
        "{}      approve: {{writes: [\"**\"]}}\n",
        mount("staged")
    ));
    assert!(
        warnings(&r).contains(&(
            "filesystem.mounts[0].approve".to_owned(),
            Code::Inconsistent
        )),
        "{r:#?}"
    );
}

#[test]
fn broker_write_tools_do_not_act_on_staged_mounts() {
    let f = Fixture::new();
    let r = f.load(&format!(
        "{}tools:\n  builtin: [fs_write]\n",
        mount("staged")
    ));
    assert!(
        warnings(&r).contains(&("tools.builtin".to_owned(), Code::Inconsistent)),
        "{r:#?}"
    );
}

#[test]
fn staged_mounts_inside_git_metadata_are_refused() {
    let f = Fixture::new();
    std::fs::create_dir_all(f.env.home.join("code/myproject/.git/hooks")).unwrap();
    assert_rejects(
        &f.load(
            "filesystem:\n  mounts:\n    - host: \"~/code/myproject/.git/hooks\"\n      guest: /workspace/h\n      mode: staged\n",
        ),
        "filesystem.mounts[0].host",
        Code::ProtectedPath,
    );
}

#[test]
fn the_coding_agent_example_uses_staged() {
    let text = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../manifests/examples/coding-agent.yaml"),
    )
    .unwrap();
    assert!(text.contains("mode: staged"), "{text}");
    assert!(!text.contains("mode: rw"), "{text}");
}
