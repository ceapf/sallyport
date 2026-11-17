//! Architect Q351, Q374 (#158): every diagnostic producer quotes the manifest values its message
//! includes, so a token-shaped value that a user pasted into the wrong field is masked. The
//! masking in `manifest/diag.rs` covers quoted spans; these are the producers that put a name
//! in a message bare. Each name here passes its field's own check (a secret name, an MCP server
//! name), which admits no quote, backslash, space or slash, so a quoted name is masked whole.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::Fixture;
use sally_core::manifest::{Rejected, Validated};

/// Every rendered diagnostic, errors and warnings, from success or rejection.
fn texts(r: &Result<Validated, Rejected>) -> Vec<String> {
    let (errors, warnings) = match r {
        Ok(v) => (&[][..], &v.warnings[..]),
        Err(e) => (&e.errors[..], &e.warnings[..]),
    };
    errors.iter().chain(warnings).map(ToString::to_string).collect()
}

/// No diagnostic holds more than the masked head of `token`, and at least one names it.
#[track_caller]
fn assert_masked(r: &Result<Validated, Rejected>, token: &str) {
    let texts = texts(r);
    let head = token.get(..4).unwrap();
    assert!(texts.iter().any(|t| t.contains(head)), "{texts:#?}");
    let longer = token.get(..8).unwrap();
    for t in &texts {
        assert!(!t.contains(longer), "{t}");
    }
}

fn grant(name: &str) -> String {
    format!(
        "network:\n  mode: proxy\n  allow:\n    - host: api.github.com\nsecrets:\n  - {{name: \
         {name}, inject: {{host: api.github.com, header: Authorization, format: \"{{value}}\"}}}}\n"
    )
}

/// secrets.rs: a granted name that is not in the store is named in the hint's command.
#[test]
fn a_missing_secret_name_is_masked_in_the_store_hint() {
    let name = "K9".repeat(12);
    let f = Fixture::new();
    assert_masked(&f.load(&grant(&name)), &name);
}

/// exposure.rs: the [data-can-leave] warning names each granted secret.
#[test]
fn a_granted_secret_name_is_masked_in_the_data_can_leave_warning() {
    let name = "K9".repeat(12);
    let f = Fixture::new();
    assert_masked(&f.load_with(&grant(&name), &[name.as_str()]), &name);
}

/// ack.rs: an unacknowledged `approve: never` server is named in the reason.
#[test]
fn an_mcp_server_name_is_masked_in_the_acknowledgement_reason() {
    let name = "k9".repeat(12);
    let f = Fixture::new();
    let body = format!(
        "filesystem:\n  mounts:\n    - host: \"~/code/myproject\"\n      guest: /workspace/p\n      \
         mode: ro\ntools:\n  mcp:\n    - name: {name}\n      command: [docs-server]\n      \
         approve: never\n"
    );
    assert_masked(&f.load(&body), &name);
}
