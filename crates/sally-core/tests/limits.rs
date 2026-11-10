//! Exact boundaries of every size and count limit (accept at the maximum, refuse one above), and
//! the remaining deny paths cargo-mutants found untested (AMENDMENTS-01 §15 zero-survivor gate).
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{Fixture, assert_ok, assert_rejects, errors, rendered, warnings};
use sally_core::manifest::{Code, HostEnv, Rejected, Validated, load};

fn mount(host: &str, guest: &str, mode: &str) -> String {
    format!("    - {{host: \"{host}\", guest: \"{guest}\", mode: {mode}}}\n")
}

fn mounts(list: &str) -> String {
    format!("filesystem:\n  mounts:\n{list}")
}

fn proxy(hosts: &[String]) -> String {
    let rules: String = hosts
        .iter()
        .map(|h| format!("    - host: \"{h}\"\n"))
        .collect();
    format!("network:\n  mode: proxy\n  allow:\n{rules}")
}

/// Path and code of the first error, if any.
fn first(r: &Result<Validated, Rejected>) -> Option<(String, Code)> {
    errors(r).into_iter().next()
}

// ---- paths -------------------------------------------------------------------------------------

#[test]
fn host_path_length_limit() {
    let f = Fixture::new();
    // Components under NAME_MAX so the at-max path fails only because it does not exist.
    let seg = format!("{}/", "a".repeat(199));
    let mut at_max = format!("~/{}", seg.repeat(20));
    at_max.push_str(&"b".repeat(4096 - at_max.len()));
    assert_eq!(at_max.len(), 4096);
    let r = f.load(&mounts(&mount(&at_max, "/workspace/p", "ro")));
    assert_eq!(first(&r).map(|e| e.1), Some(Code::NotFound));
    let over = format!("{at_max}b");
    let r = f.load(&mounts(&mount(&over, "/workspace/p", "ro")));
    assert_rejects(&r, "filesystem.mounts[0].host", Code::InvalidValue);
}

#[test]
fn guest_path_length_limit() {
    let f = Fixture::new();
    let prefix = "/workspace/";
    let at_max = format!("{prefix}{}", "a".repeat(4096 - prefix.len()));
    assert_ok(&f.load(&mounts(&mount("~/code/myproject", &at_max, "ro"))));
    let over = format!("{at_max}a");
    let r = f.load(&mounts(&mount("~/code/myproject", &over, "ro")));
    assert_rejects(&r, "filesystem.mounts[0].guest", Code::GuestPath);
}

#[test]
fn comma_in_a_host_realpath_is_refused() {
    let f = Fixture::new();
    std::fs::create_dir_all(f.home().join("code/a,b")).unwrap();
    let r = f.load(&mounts(&mount("~/code/a,b", "/workspace/p", "ro")));
    assert_rejects(&r, "filesystem.mounts[0].host", Code::PathChars);
}

#[test]
fn missing_mount_says_it_does_not_exist() {
    let f = Fixture::new();
    let r = f.load(&mounts(&mount("~/nope", "/workspace/p", "ro")));
    assert!(rendered(&r)[0].contains("does not exist"), "{r:#?}");
}

#[test]
fn denylist_rule_reached_through_a_symlink_matches_its_real_target() {
    let f = Fixture::new();
    // ~/.kube is a symlink to ~/vault/kube: the real directory is protected too.
    std::fs::create_dir_all(f.home().join("vault/kube")).unwrap();
    std::os::unix::fs::symlink(f.home().join("vault/kube"), f.home().join(".kube")).unwrap();
    let r = f.load(&mounts(&mount("~/vault/kube", "/workspace/k", "ro")));
    assert_rejects(&r, "filesystem.mounts[0].host", Code::Denylisted);
}

#[test]
fn mount_count_limit() {
    let f = Fixture::new();
    let list = |n: usize| -> String {
        (0..n)
            .map(|i| {
                std::fs::create_dir_all(f.home().join(format!("code/m{i}"))).unwrap();
                mount(&format!("~/code/m{i}"), &format!("/workspace/m{i}"), "ro")
            })
            .collect()
    };
    assert_ok(&f.load(&mounts(&list(64))));
    assert_rejects(
        &f.load(&mounts(&list(65))),
        "filesystem.mounts",
        Code::OutOfRange,
    );
}

#[test]
fn approve_glob_limits() {
    let f = Fixture::new();
    let with = |globs: &[String]| {
        let list: Vec<String> = globs.iter().map(|g| format!("\"{g}\"")).collect();
        format!(
            "filesystem:\n  mounts:\n    - {{host: \"~/Documents/research\", guest: /workspace/r, mode: brokered, approve: {{writes: [{}]}}}}\n",
            list.join(", ")
        )
    };
    let many = |n: usize| (0..n).map(|i| format!("d{i}/*")).collect::<Vec<_>>();
    assert_ok(&f.load(&with(&many(256))));
    assert_rejects(
        &f.load(&with(&many(257))),
        "filesystem.mounts[0].approve.writes",
        Code::OutOfRange,
    );
    assert_ok(&f.load(&with(&["a".repeat(256)])));
    assert_rejects(
        &f.load(&with(&["a".repeat(257)])),
        "filesystem.mounts[0].approve.writes[0]",
        Code::InvalidValue,
    );
}

#[test]
fn empty_approve_list_without_the_tool_does_not_warn() {
    let f = Fixture::new();
    let body = "filesystem:\n  mounts:\n    - {host: \"~/Documents/research\", guest: /workspace/r, mode: brokered, approve: {writes: [], deletes: [\"**\"]}}\ntools:\n  builtin: [fs_delete]\n";
    assert_eq!(warnings(&f.load(body)), vec![]);
}

// ---- hostnames and rules -----------------------------------------------------------------------

#[test]
fn hostname_and_label_length_limits() {
    let f = Fixture::new();
    let (a, b, c) = ("a".repeat(63), "b".repeat(63), "c".repeat(63));
    let host_253 = format!("{a}.{b}.{c}.{}", "d".repeat(61));
    assert_eq!(host_253.len(), 253);
    assert_ok(&f.load(&proxy(std::slice::from_ref(&host_253))));
    let host_254 = format!("{a}.{b}.{c}.{}", "d".repeat(62));
    assert_rejects(
        &f.load(&proxy(&[host_254])),
        "network.allow[0].host",
        Code::BadHost,
    );
    assert_ok(&f.load(&proxy(&[format!("{a}.example")])));
    assert_rejects(
        &f.load(&proxy(&[format!("{a}a.example")])),
        "network.allow[0].host",
        Code::BadHost,
    );
}

#[test]
fn numeric_last_label_is_an_ip_spelling_but_a_bare_0x_label_is_not() {
    let f = Fixture::new();
    for h in ["foo.123", "foo.0x7f"] {
        assert_rejects(
            &f.load(&proxy(&[h.to_owned()])),
            "network.allow[0].host",
            Code::IpLiteral,
        );
    }
    assert_ok(&f.load(&proxy(&["foo.0x".to_owned()])));
}

#[test]
fn allow_rule_count_limit() {
    let f = Fixture::new();
    let hosts = |n: usize| (0..n).map(|i| format!("h{i}.example")).collect::<Vec<_>>();
    assert_ok(&f.load(&proxy(&hosts(256))));
    assert_rejects(
        &f.load(&proxy(&hosts(257))),
        "network.allow",
        Code::OutOfRange,
    );
}

#[test]
fn shared_hosting_destination_is_named_in_the_finding() {
    let f = Fixture::new();
    let body = format!(
        "{}{}  acknowledge_unrestricted_egress: true\n",
        mounts(&mount("~/code/myproject", "/workspace/p", "ro")),
        proxy(&["*.github.io".to_owned()])
    );
    let r = f.load(&body);
    let finding = r
        .unwrap()
        .warnings
        .into_iter()
        .find(|w| w.code == Code::DataCanLeave)
        .unwrap();
    assert!(
        finding
            .message
            .contains("*.github.io (anyone can register these)"),
        "{}",
        finding.message
    );
}

#[test]
fn needless_egress_acknowledgement_is_not_reported_as_a_risk() {
    let f = Fixture::new();
    let body = format!(
        "{}  acknowledge_unrestricted_egress: true\n",
        proxy(&["pypi.org".to_owned()])
    );
    let v = f.load(&body).unwrap();
    assert!(v.manifest.acknowledged_risks().is_empty());
}

// ---- secrets -----------------------------------------------------------------------------------

fn grant(inject: &str, extra: &str) -> String {
    format!(
        "{}secrets:\n  - {{name: GITHUB_TOKEN, inject: {inject}{extra}}}\n",
        proxy(&["github.com".to_owned()])
    )
}

#[test]
fn basic_user_header_and_format_length_limits() {
    let f = Fixture::new();
    let basic = |u: &str| {
        grant(
            &format!(
                "{{host: github.com, header: Authorization, format: \"Basic {{basic}}\", basic_user: \"{u}\"}}"
            ),
            "",
        )
    };
    assert_ok(&f.load(&basic(&"u".repeat(256))));
    assert_rejects(
        &f.load(&basic(&"u".repeat(257))),
        "secrets[0].inject.basic_user",
        Code::InvalidValue,
    );

    let header = |h: &str| {
        grant(
            &format!("{{host: github.com, header: \"{h}\", format: \"{{value}}\"}}"),
            "",
        )
    };
    assert_ok(&f.load(&header(&format!("X{}", "a".repeat(63)))));
    assert_rejects(
        &f.load(&header(&format!("X{}", "a".repeat(64)))),
        "secrets[0].inject.header",
        Code::BadHeader,
    );

    let format = |n: usize| {
        grant(
            &format!(
                "{{host: github.com, header: A, format: \"{{value}}{}\"}}",
                "a".repeat(n)
            ),
            "",
        )
    };
    assert_ok(&f.load(&format(1024 - "{value}".len())));
    assert_rejects(
        &f.load(&format(1025 - "{value}".len())),
        "secrets[0].inject.format",
        Code::BadFormat,
    );
}

#[test]
fn secret_name_must_be_uppercase_throughout() {
    let f = Fixture::new();
    for bad in ["Ab", "GITHUB-TOKEN"] {
        let body = grant("{host: github.com, header: A, format: \"{value}\"}", "")
            .replace("GITHUB_TOKEN", bad);
        assert_rejects(&f.load(&body), "secrets[0].name", Code::InvalidValue);
    }
}

#[test]
fn one_secret_may_expose_the_same_placeholder_from_several_grants() {
    let f = Fixture::new();
    let body = format!(
        "{}secrets:\n  - {{name: GITHUB_TOKEN, inject: {{host: api.github.com, header: A, format: \"{{value}}\"}}, expose_env: GH_TOKEN}}\n  - {{name: GITHUB_TOKEN, inject: {{host: github.com, header: A, format: \"{{value}}\"}}, expose_env: GH_TOKEN}}\n",
        proxy(&["api.github.com".to_owned(), "github.com".to_owned()])
    );
    assert_ok(&f.load(&body));
}

#[test]
fn run_together_secret_env_names_are_caught_by_suffix() {
    let f = Fixture::new();
    for k in ["ACCESSTOKEN", "CLIENTSECRET", "DBPASSWORD", "MYKEY"] {
        let r = f.load(&format!(
            "tools:\n  mcp:\n    - {{name: a, command: [x], env: {{{k}: v}}}}\n"
        ));
        assert_rejects(&r, &format!("tools.mcp[0].env.{k}"), Code::SecretLikeEnv);
    }
}

#[test]
fn hash_set_catalog_works_like_a_btree_set() {
    let f = Fixture::new();
    let body = format!(
        "apiVersion: sallyport/v1\nkind: Manifest\nname: t\nmodel: {{ref: any}}\n{}",
        grant("{host: github.com, header: A, format: \"{value}\"}", "")
    );
    let has: std::collections::HashSet<String> =
        std::iter::once("GITHUB_TOKEN".to_owned()).collect();
    assert_ok(&load(&body, &f.env, &has));
    let empty: std::collections::HashSet<String> = std::collections::HashSet::new();
    assert_rejects(
        &load(&body, &f.env, &empty),
        "secrets[0].name",
        Code::SecretMissing,
    );
}

// ---- MCP -----------------------------------------------------------------------------------------

#[test]
fn mcp_count_argv_and_value_limits() {
    let f = Fixture::new();
    let servers = |n: usize| {
        let list: String = (0..n)
            .map(|i| format!("    - {{name: s{i}, command: [x]}}\n"))
            .collect();
        format!("tools:\n  mcp:\n{list}")
    };
    assert_ok(&f.load(&servers(32)));
    assert_rejects(&f.load(&servers(33)), "tools.mcp", Code::OutOfRange);

    let argv = |args: &[String]| {
        let list: Vec<String> = args.iter().map(|a| format!("\"{a}\"")).collect();
        format!(
            "tools:\n  mcp:\n    - {{name: a, command: [{}]}}\n",
            list.join(", ")
        )
    };
    let n_args = |n: usize| vec!["x".to_owned(); n];
    assert_ok(&f.load(&argv(&n_args(256))));
    assert_rejects(
        &f.load(&argv(&n_args(257))),
        "tools.mcp[0].command",
        Code::InvalidValue,
    );
    assert_ok(&f.load(&argv(&["a".repeat(4096)])));
    assert_rejects(
        &f.load(&argv(&["a".repeat(4097)])),
        "tools.mcp[0].command[0]",
        Code::InvalidValue,
    );
    assert_rejects(
        &f.load(&argv(&["a\\0b".to_owned()])),
        "tools.mcp[0].command[0]",
        Code::InvalidValue,
    );

    let env = |v: &str| {
        format!("tools:\n  mcp:\n    - {{name: a, command: [x], env: {{LOG_LEVEL: \"{v}\"}}}}\n")
    };
    assert_ok(&f.load(&env(&"a".repeat(4096))));
    assert_rejects(
        &f.load(&env(&"a".repeat(4097))),
        "tools.mcp[0].env.LOG_LEVEL",
        Code::InvalidValue,
    );
    assert_rejects(
        &f.load(&env("a\\0b")),
        "tools.mcp[0].env.LOG_LEVEL",
        Code::InvalidValue,
    );
}

// ---- launch-time recheck messages --------------------------------------------------------------

#[test]
fn recheck_distinguishes_a_replaced_directory_from_a_moved_path() {
    let f = Fixture::new();
    let home = f.home().to_path_buf();
    std::fs::create_dir_all(home.join("code/x")).unwrap();
    std::fs::create_dir_all(home.join("code/y")).unwrap();
    std::os::unix::fs::symlink(home.join("code/x"), home.join("code/cur")).unwrap();
    let body = mounts(&mount("~/code/cur/", "/workspace/c", "ro"));
    let v = f.load(&body).unwrap().manifest;
    let env: &HostEnv = &f.env;

    // Same path, different directory.
    std::fs::rename(home.join("code/x"), home.join("code/x-old")).unwrap();
    std::fs::create_dir_all(home.join("code/x")).unwrap();
    let e = v.recheck_mounts(env).unwrap_err();
    assert!(
        e.errors[0]
            .message
            .contains("was replaced by a different directory"),
        "{e:#?}"
    );
    assert_eq!(e.errors[0].code, Code::MountChanged);

    // The path now resolves elsewhere.
    std::fs::remove_file(home.join("code/cur")).unwrap();
    std::os::unix::fs::symlink(home.join("code/y"), home.join("code/cur")).unwrap();
    let e = v.recheck_mounts(env).unwrap_err();
    assert!(e.errors[0].message.contains("now resolves to"), "{e:#?}");
    assert_eq!(e.errors[0].code, Code::MountChanged);
}
