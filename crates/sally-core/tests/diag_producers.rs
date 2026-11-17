//! Architect Q351, Q374, Q376 (#158): the diagnostic producers that name a secret or MCP server
//! name outside that name's own check. `manifest/diag.rs` masks a token-shaped quoted span whole,
//! so these producers quote the name (Q374). Quoting masks a name only when it admits no quote,
//! backslash, space or slash, which holds only for a name that passed its field's check; so a
//! diagnostic that is not the value's own check error names a value only if it passed that check
//! (Q376). The first tests pin the quoting of valid names; the rest pin that a malformed name
//! (or a grant whose host is malformed) is never named by another field's diagnostic.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{Fixture, errors, fake_token, rendered_all};
use sally_core::manifest::{Code, Rejected, Validated};

/// No diagnostic holds more than the masked head of `token`, and at least one names it.
#[track_caller]
fn assert_masked(r: &Result<Validated, Rejected>, token: &str) {
    let texts = rendered_all(r);
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

/// The body of the pasted token in the malformed-value tests below; no diagnostic may hold it.
const BODY: &str = "0123456789abcdefghij";

fn pasted() -> String {
    fake_token(&["gh", "p_"], BODY)
}

/// A proxy manifest allowing api.github.com, with these `secrets[]` entries.
fn proxy_with(secrets: &[String]) -> String {
    format!(
        "network:\n  mode: proxy\n  allow:\n    - host: api.github.com\nsecrets:\n{}",
        secrets.concat()
    )
}

/// One `secrets[]` entry; YAML single quotes keep `"`, `\` and spaces literal.
fn entry(name: &str, host: &str, header: &str) -> String {
    format!(
        "  - name: '{name}'\n    inject: {{host: '{host}', header: {header}, format: \"{{value}}\"}}\n"
    )
}

/// The one `[data-can-leave]` warning, rendered.
#[track_caller]
fn leave_warning(r: &Result<Validated, Rejected>) -> String {
    let w = match r {
        Ok(v) => &v.warnings,
        Err(e) => &e.warnings,
    };
    let found: Vec<String> = w
        .iter()
        .filter(|d| d.code == Code::DataCanLeave)
        .map(ToString::to_string)
        .collect();
    assert_eq!(found.len(), 1, "{r:#?}");
    found.into_iter().next().unwrap()
}

#[track_caller]
fn assert_not_echoed(texts: &[String]) {
    for t in texts {
        assert!(!t.contains(BODY), "token echoed: {t}");
    }
}

/// exposure.rs (Q376): a secret name that fails its check is not named in the warning, whatever
/// it holds: a slash, a space (a pasted `Bearer` header) or a quote and backslash.
#[test]
fn a_malformed_secret_name_is_not_named_in_the_data_can_leave_warning() {
    let tok = pasted();
    let f = Fixture::new();
    for name in [
        format!("A/{tok}"),
        format!("Bearer {tok}"),
        format!("X\"\\{tok}"),
    ] {
        let r = f.load(&proxy_with(&[entry(
            &name,
            "api.github.com",
            "Authorization",
        )]));
        assert_not_echoed(&rendered_all(&r));
        assert!(
            leave_warning(&r).contains(
                "Anything this agent reads (whatever the secret at secrets[0] unlocks) can be \
                 sent to api.github.com (acting as you)."
            ),
            "{r:#?}"
        );
    }
}

/// exposure.rs (Q376): a valid grant beside a malformed one is still named, before the
/// placeholder.
#[test]
fn a_valid_sibling_grant_is_still_named() {
    let f = Fixture::new();
    let body = proxy_with(&[
        entry(&format!("A/{}", pasted()), "api.github.com", "A"),
        entry("GITHUB_TOKEN", "api.github.com", "B"),
    ]);
    let r = f.load_with(&body, &["GITHUB_TOKEN"]);
    assert_not_echoed(&rendered_all(&r));
    assert!(
        leave_warning(&r).contains(
            "Anything this agent reads (whatever your \"GITHUB_TOKEN\" unlocks on api.github.com \
             and whatever the secret at secrets[0] unlocks) can be sent to api.github.com \
             (acting as you)."
        ),
        "{r:#?}"
    );
}

/// exposure.rs (Q376): a valid name whose host fails its check is not named either, and the
/// host is not echoed in the warning. (The host's own check error still echoes it: #195.)
#[test]
fn a_grant_with_a_malformed_host_is_not_named_in_the_warning() {
    let f = Fixture::new();
    let body = proxy_with(&[entry(
        "GITHUB_TOKEN",
        &format!("api.github.com/{}", pasted()),
        "Authorization",
    )]);
    let r = f.load_with(&body, &["GITHUB_TOKEN"]);
    let w = leave_warning(&r);
    assert_not_echoed(std::slice::from_ref(&w));
    assert!(
        w.contains(
            "Anything this agent reads (whatever the secret at secrets[0] unlocks) can be sent \
             to api.github.com."
        ),
        "{w}"
    );
}

/// ack.rs (Q376): an `approve: never` server whose name fails its check gets only the name
/// error, whether or not `mcp:<name>` is listed.
#[test]
fn a_malformed_mcp_name_gets_only_its_own_error() {
    let tok = pasted();
    let f = Fixture::new();
    for ack in [
        String::new(),
        format!("  acknowledge_unapproved: ['mcp:docs/{tok}']\n"),
    ] {
        let body = format!(
            "filesystem:\n  mounts:\n    - host: \"~/code/myproject\"\n      guest: /workspace/p\n      \
             mode: ro\ntools:\n  mcp:\n    - name: 'docs/{tok}'\n      command: [docs-server]\n      \
             approve: never\n{ack}"
        );
        let r = f.load(&body);
        assert_eq!(
            errors(&r),
            vec![("tools.mcp[0].name".to_owned(), Code::InvalidValue)],
            "{ack}"
        );
        assert_not_echoed(&rendered_all(&r));
    }
}

/// secrets.rs (Q376): two grants sharing a malformed `expose_env` get its own error each, and
/// no duplicate error echoes it.
#[test]
fn a_shared_malformed_expose_env_gets_only_its_own_errors() {
    let env = format!("X/{}", pasted());
    let f = Fixture::new();
    let with_env = |name: &str, header: &str| {
        format!(
            "{}    expose_env: '{env}'\n",
            entry(name, "api.github.com", header)
        )
    };
    let body = proxy_with(&[with_env("A_TOKEN", "A"), with_env("B_TOKEN", "B")]);
    let r = f.load_with(&body, &["A_TOKEN", "B_TOKEN"]);
    assert_eq!(
        errors(&r),
        vec![
            ("secrets[0].expose_env".to_owned(), Code::InvalidValue),
            ("secrets[1].expose_env".to_owned(), Code::InvalidValue),
        ]
    );
    assert_not_echoed(&rendered_all(&r));
}
