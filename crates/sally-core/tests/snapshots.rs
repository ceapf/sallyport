//! Snapshot tests (insta, AMENDMENTS-01 §15): what the user reads — summaries of the shipped
//! examples and the rendered diagnostics for a deliberately broken manifest. A change here is a
//! user-visible wording change and must be reviewed as one (`cargo insta review`).
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{Fixture, fake_token};
use sally_core::manifest::{load, summary};

fn example(name: &str) -> String {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../manifests/examples/");
    std::fs::read_to_string(format!("{p}{name}")).unwrap()
}

/// Replaces the fixture root (lexical and canonical) with `$ROOT`.
fn stable(f: &Fixture, s: &str) -> String {
    // Canonical first: the lexical root may be a substring of the realpath (symlinked target).
    let real = std::fs::canonicalize(&f.root).unwrap();
    f.redact(&s.replace(&real.display().to_string(), "$ROOT"))
}

#[test]
fn example_summaries() {
    let f = Fixture::new();
    // The secrets the shipped examples grant.
    let catalog: std::collections::BTreeSet<String> = ["GITHUB_TOKEN", "BRAVE_SEARCH_KEY"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    for name in ["chat-only", "coding-agent", "web-research"] {
        let v = load(&example(&format!("{name}.yaml")), &f.env, &catalog).unwrap();
        insta::assert_snapshot!(format!("summary-{name}"), stable(&f, &summary(&v.manifest)));
    }
}

#[test]
fn diagnostics_for_a_hostile_manifest() {
    let f = Fixture::new();
    let canary = fake_token(&["s", "k-"], "canary");
    let body = "filesystem:\n  mounts:\n    - {host: \"~/.ssh\", guest: /workspace/s, mode: rw}\n    - {host: \"~/code/myproject\", guest: /etc, mode: rw}\nnetwork:\n  mode: proxy\n  allow:\n    - host: \"*\"\n    - host: 10.0.0.1\nsecrets:\n  - {name: GITHUB_TOKEN, inject: {host: \"*.github.com\", header: Host, format: \"{value}{value}\"}}\ntools:\n  builtin: [shell]\n  shell: allow\n  destructive_requires_approval: false\n  mcp:\n    - {name: x, command: [x], env: {OPENAI_API_KEY: \"@CANARY@\", LD_PRELOAD: /x.so}}\n"
        .replace("@CANARY@", &canary);
    let r = f.load(&body);
    let e = r.unwrap_err();
    let text: Vec<String> = e
        .errors
        .iter()
        .chain(&e.warnings)
        .map(|d| stable(&f, &d.to_string()))
        .collect();
    assert!(text.iter().all(|l| !l.contains(&canary)));
    insta::assert_snapshot!("diagnostics-hostile", text.join("\n"));
}
