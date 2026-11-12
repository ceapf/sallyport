//! Allow + deny tests for every validate/load-time enforcement point in MANIFEST_SPEC §3.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{Fixture, assert_ok, assert_rejects, errors, fake_token, warnings};
use sally_core::manifest::{Code, HostPattern, MountMode, json_schema, parse, summary, to_yaml};

// ---- apiVersion / kind / unknown fields / name (parse) ------------------------------------

#[test]
fn header_allow() {
    assert_ok(&Fixture::new().load(""));
}

#[test]
fn api_version_and_kind_must_be_exact() {
    for (text, path) in [
        (
            "apiVersion: sallyport/v2\nkind: Manifest\nname: t\nmodel: {ref: any}\n",
            "apiVersion",
        ),
        (
            "apiVersion: sallyport/v1\nkind: Policy\nname: t\nmodel: {ref: any}\n",
            "kind",
        ),
    ] {
        let e = parse(text).unwrap_err();
        assert_eq!(
            (e.errors[0].path.as_str(), e.errors[0].code),
            (path, Code::Schema)
        );
    }
}

#[test]
fn unknown_fields_rejected_at_every_level() {
    for (body, path) in [
        ("extra: 1\n", "extra"),
        ("runtime:\n  privileged: true\n", "runtime.privileged"),
        ("network:\n  dns: 1.1.1.1\n", "network.dns"),
        (
            "filesystem:\n  mounts:\n    - {host: /a, guest: /workspace/a, mode: ro, opts: z}\n",
            "filesystem.mounts[0].opts",
        ),
        (
            "tools:\n  mcp:\n    - {name: a, command: [x], cwd: /}\n",
            "tools.mcp[0].cwd",
        ),
        ("policy:\n  override: true\n", "policy.override"),
    ] {
        let e = parse(&format!("{}{body}", common::HEADER)).unwrap_err();
        assert_eq!(
            (e.errors[0].path.as_str(), e.errors[0].code),
            (path, Code::Schema),
            "{body}"
        );
        assert!(
            e.errors[0].message.contains("unknown field"),
            "{}",
            e.errors[0].message
        );
    }
}

#[test]
fn name_allow_and_deny() {
    let f = Fixture::new();
    for good in ["a", "coding-agent-2", &"a".repeat(64)] {
        let r = sally_core::manifest::load(
            &common::HEADER.replace("name: t", &format!("name: {good}")),
            &f.env,
            &std::collections::BTreeSet::new(),
        );
        assert_ok(&r);
    }
    for bad in ["A", "a_b", "\"\"", &"a".repeat(65), "a.b", "\"a b\""] {
        let r = sally_core::manifest::load(
            &common::HEADER.replace("name: t", &format!("name: {bad}")),
            &f.env,
            &std::collections::BTreeSet::new(),
        );
        assert_rejects(&r, "name", Code::InvalidValue);
    }
}

#[test]
fn description_limits() {
    let f = Fixture::new();
    assert_ok(&f.load(&format!("description: \"{}\"\n", "é".repeat(512))));
    assert_rejects(
        &f.load(&format!("description: \"{}\"\n", "a".repeat(513))),
        "description",
        Code::OutOfRange,
    );
    assert_rejects(
        &f.load("description: \"a\\u001bb\"\n"),
        "description",
        Code::InvalidValue,
    );
}

// ---- runtime ------------------------------------------------------------------------------

const DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[test]
fn runtime_image_must_be_digest_pinned() {
    let f = Fixture::new();
    assert_ok(&f.load(&format!("runtime:\n  image: ghcr.io/a/b@sha256:{DIGEST}\n")));
    assert_ok(&f.load(&format!(
        "runtime:\n  image: localhost/sandbox-base:1@sha256:{DIGEST}\n"
    )));
    for bad in [
        "ghcr.io/a/b".to_owned(),
        "ghcr.io/a/b:latest".to_owned(),
        format!("ghcr.io/a/b@sha256:{}", &DIGEST[1..]),
        format!("ghcr.io/a/b@sha256:{}", DIGEST.replace('0', "A")),
        format!("ghcr.io/a/b@sha512:{DIGEST}{DIGEST}"),
        format!("@sha256:{DIGEST}"),
        format!("Ghcr.io/a@sha256:{DIGEST}"),
    ] {
        assert_rejects(
            &f.load(&format!("runtime:\n  image: \"{bad}\"\n")),
            "runtime.image",
            Code::NotPinned,
        );
    }
}

#[test]
fn runtime_ranges() {
    let f = Fixture::new();
    assert_ok(&f.load(
        "runtime:\n  cpus: 0.5\n  memory: 64MiB\n  pids: 16\n  timeout: 1m\n  tmp_size: 1MiB\n  \
         stage_size: 1MiB\n",
    ));
    assert_ok(&f.load(
        "runtime:\n  cpus: 8\n  memory: 12GiB\n  pids: 4096\n  timeout: 24h\n  tmp_size: 12GiB\n  \
         stage_size: 1TiB\n",
    ));
    for (body, path) in [
        ("cpus: 0.4", "runtime.cpus"),
        ("cpus: 9", "runtime.cpus"),
        ("memory: 63MiB\n  tmp_size: 1MiB", "runtime.memory"),
        ("memory: 13GiB", "runtime.memory"), // > 75% of 16 GiB
        ("pids: 15", "runtime.pids"),
        ("pids: 4097", "runtime.pids"),
        ("timeout: 59s", "runtime.timeout"),
        ("timeout: 25h", "runtime.timeout"),
        ("tmp_size: 9GiB", "runtime.tmp_size"), // > memory (default 8GiB)
        ("tmp_size: 0B", "runtime.tmp_size"),
        ("stage_size: 1023KiB", "runtime.stage_size"),
        ("stage_size: 1025GiB", "runtime.stage_size"), // > 1 TiB
    ] {
        assert_rejects(
            &f.load(&format!("runtime:\n  {body}\n")),
            path,
            Code::OutOfRange,
        );
    }
}

/// #14: staged upper directories are limited to 10 GiB per session unless the manifest says
/// otherwise.
#[test]
fn stage_size_defaults_to_ten_gib() {
    let m = parse(common::HEADER).unwrap();
    assert_eq!(m.runtime.stage_size.bytes(), 10 << 30);
}

#[test]
fn cpus_must_be_a_finite_number_with_at_most_three_decimals() {
    for bad in [".nan", ".inf", "-.inf", "-1", "0.0005", "\"2\""] {
        let e = parse(&format!("{}runtime:\n  cpus: {bad}\n", common::HEADER)).unwrap_err();
        assert_eq!(
            (e.errors[0].path.as_str(), e.errors[0].code),
            ("runtime.cpus", Code::Schema),
            "{bad}"
        );
    }
    let m = parse(&format!("{}runtime:\n  cpus: 1.25\n", common::HEADER)).unwrap();
    assert_eq!(m.runtime.cpus.millis(), 1250);
    assert_eq!(parse(&to_yaml(&m).unwrap()).unwrap(), m);
}

// ---- model --------------------------------------------------------------------------------

#[test]
fn model_ref_and_ranges() {
    let f = Fixture::new();
    let with = |model: &str| {
        sally_core::manifest::load(
            &format!("apiVersion: sallyport/v1\nkind: Manifest\nname: t\nmodel:\n{model}"),
            &f.env,
            &std::collections::BTreeSet::new(),
        )
    };
    assert_ok(&with(
        "  ref: library://qwen2.5-coder-7b-instruct-q4_k_m\n  context: 32768\n  gpu_layers: 33\n",
    ));
    assert_ok(&with(&format!(
        "  ref: library://{DIGEST}\n  gpu_layers: auto\n"
    )));
    assert_rejects(
        &with("  ref: https://hf.co/x\n"),
        "model.ref",
        Code::InvalidValue,
    );
    assert_rejects(
        &with("  ref: library://\n"),
        "model.ref",
        Code::InvalidValue,
    );
    assert_rejects(
        &with("  ref: library://../x\n"),
        "model.ref",
        Code::InvalidValue,
    );
    assert_rejects(
        &with("  ref: any\n  context: 0\n"),
        "model.context",
        Code::OutOfRange,
    );
    assert_rejects(
        &with("  ref: any\n  gpu_layers: 5000\n"),
        "model.gpu_layers",
        Code::OutOfRange,
    );
    let e = parse(
        "apiVersion: sallyport/v1\nkind: Manifest\nname: t\nmodel:\n  ref: any\n  gpu_layers: most\n",
    )
    .unwrap_err();
    assert_eq!(e.errors[0].path, "model.gpu_layers");
}

// ---- filesystem.mounts[].host ---------------------------------------------------------------

fn mount(host: &str, guest: &str, mode: &str) -> String {
    format!(
        "filesystem:\n  mounts:\n    - host: \"{host}\"\n      guest: {guest}\n      mode: {mode}\n"
    )
}

#[test]
fn mount_host_allow_resolves_realpath() {
    let f = Fixture::new();
    let r = f.load(&mount("~/code/myproject", "/workspace/p", "rw"));
    assert_ok(&r);
    let v = r.unwrap().manifest;
    assert_eq!(
        v.mounts()[0].host,
        std::fs::canonicalize(f.home().join("code/myproject")).unwrap()
    );
    assert_eq!(v.mounts()[0].mode, MountMode::Rw);
    // Absolute and dotted forms resolve the same way.
    let abs = format!("{}/code/other/../myproject", f.home().display());
    assert_ok(&f.load(&mount(&abs, "/workspace/p", "ro")));
}

#[test]
fn mount_host_deny_cases() {
    let f = Fixture::new();
    std::os::unix::fs::symlink(f.home().join("code/myproject"), f.home().join("link")).unwrap();
    std::fs::create_dir_all(f.home().join("code/a:b")).unwrap();
    let cases = [
        ("~/missing", Code::NotFound),
        ("~/code/file.txt", Code::NotDirectory),
        ("~/link", Code::IsSymlink),
        ("~/code/a:b", Code::PathChars),
        ("code/myproject", Code::InvalidValue),
        ("~root/x", Code::InvalidValue),
        ("~/code/../.ssh", Code::Denylisted),
        ("~/.local", Code::Denylisted), // contains ~/.local/share/sallyport
        ("~/.local/share/containers", Code::Denylisted),
    ];
    for (host, code) in cases {
        assert_rejects(
            &f.load(&mount(host, "/workspace/p", "ro")),
            "filesystem.mounts[0].host",
            code,
        );
    }
}

#[test]
fn mount_through_symlinked_parent_into_denylist_is_refused() {
    let f = Fixture::new();
    std::os::unix::fs::symlink(f.home().join(".ssh"), f.home().join("code/keys")).unwrap();
    std::fs::create_dir_all(f.home().join(".ssh/sub")).unwrap();
    // The root ("sub") is a real directory, but its realpath is inside ~/.ssh.
    assert_rejects(
        &f.load(&mount("~/code/keys/sub", "/workspace/p", "ro")),
        "filesystem.mounts[0].host",
        Code::Denylisted,
    );
}

#[test]
fn mount_containing_a_symlink_to_denylisted_path_is_allowed() {
    // MANIFEST_SPEC §2: symlinks inside a mount resolve inside the container rootfs (RT-FS-03).
    let f = Fixture::new();
    std::os::unix::fs::symlink(f.home().join(".ssh"), f.home().join("code/myproject/.ssh"))
        .unwrap();
    assert_ok(&f.load(&mount("~/code/myproject", "/workspace/p", "rw")));
}

#[test]
fn filesystem_deny_extends_denylist() {
    let f = Fixture::new();
    let body = format!(
        "{}  deny: [\"~/code/myproject\"]\n",
        mount("~/code/myproject", "/workspace/p", "ro")
    );
    assert_rejects(
        &f.load(&body),
        "filesystem.mounts[0].host",
        Code::Denylisted,
    );
    let body = format!(
        "{}  deny: [\"~/code/other\"]\n",
        mount("~/code/myproject", "/workspace/p", "ro")
    );
    assert_ok(&f.load(&body));
    let body = "filesystem:\n  deny: [\"relative/path\"]\n";
    assert_rejects(&f.load(body), "filesystem.deny[0]", Code::InvalidValue);
}

#[test]
fn mounts_must_not_overlap() {
    let f = Fixture::new();
    let two = |h1: &str, g1: &str, h2: &str, g2: &str| {
        format!(
            "filesystem:\n  mounts:\n    - {{host: \"{h1}\", guest: {g1}, mode: rw}}\n    - {{host: \"{h2}\", guest: {g2}, mode: brokered}}\n"
        )
    };
    assert_ok(&f.load(&two(
        "~/code/myproject",
        "/workspace/a",
        "~/code/other",
        "/workspace/b",
    )));
    // rw parent + brokered child would bypass the child's approvals.
    assert_rejects(
        &f.load(&two(
            "~/code",
            "/workspace/a",
            "~/code/myproject",
            "/workspace/b",
        )),
        "filesystem.mounts[1].host",
        Code::Overlap,
    );
    assert_rejects(
        &f.load(&two(
            "~/code/myproject",
            "/workspace/a",
            "~/code/other",
            "/workspace/a",
        )),
        "filesystem.mounts[1].guest",
        Code::Duplicate,
    );
    assert_rejects(
        &f.load(&two(
            "~/code/myproject",
            "/workspace/a",
            "~/code/other",
            "/workspace/a/b",
        )),
        "filesystem.mounts[1].guest",
        Code::Overlap,
    );
}

// ---- filesystem.mounts[].guest / mode / approve ----------------------------------------------

#[test]
fn guest_allow_and_deny() {
    let f = Fixture::new();
    assert_ok(&f.load(&mount(
        "~/code/myproject",
        "/workspace/my-project_1.0",
        "ro",
    )));
    for g in [
        "/etc",
        "/workspace",
        "/workspace/../root",
        "/workspace/a/../../etc",
        "/workspace/a,ro",
        "/workspace/a:/etc",
        "\"/workspace/a b\"",
    ] {
        assert_rejects(
            &f.load(&mount("~/code/myproject", g, "ro")),
            "filesystem.mounts[0].guest",
            Code::GuestPath,
        );
    }
}

#[test]
fn approve_globs() {
    let f = Fixture::new();
    let brokered = |globs: &str| {
        format!(
            "{}      approve:\n        writes: {globs}\n",
            mount("~/Documents/research", "/workspace/r", "brokered")
        )
    };
    let r = f.load(&brokered("[\"**\", \"drafts/*.md\"]"));
    assert_ok(&r);
    assert_eq!(
        r.unwrap().manifest.mounts()[0].approve.writes,
        vec!["**", "drafts/*.md"]
    );
    assert_rejects(
        &f.load(&brokered("[\"/etc/*\"]")),
        "filesystem.mounts[0].approve.writes[0]",
        Code::InvalidValue,
    );
    assert_rejects(
        &f.load(&brokered("[\"../*\"]")),
        "filesystem.mounts[0].approve.writes[0]",
        Code::InvalidValue,
    );
    assert_rejects(
        &f.load(&brokered("[\"\"]")),
        "filesystem.mounts[0].approve.writes[0]",
        Code::InvalidValue,
    );
    // Glob syntax (architect ruling Q20): no classes, braces, escapes or negation, no empty or
    // `.` segments, no trailing `/`; each would silently match less than the user meant.
    for bad in [
        "[ab].md", "a]", "{a,b}", "a}", "a\\\\*", "!a", "a//b", "./a", "a/./b", "a/.", "notes/",
        "**.md", "notes**", "a/b**c/d", "***",
    ] {
        assert_rejects(
            &f.load(&brokered(&format!("[\"{bad}\"]"))),
            "filesystem.mounts[0].approve.writes[0]",
            Code::InvalidValue,
        );
    }
    for good in [
        "notes/**", "a!", ".hidden", "a/.b/c", "x?y", "**/*.md", "a..b", "**", "a/**/b", "*.*",
    ] {
        assert_ok(&f.load(&brokered(&format!("[\"{good}\"]"))));
    }
    // The diagnostic says what to write instead.
    let msg = sally_core::manifest::check_glob("**.md")
        .unwrap_err()
        .to_string();
    assert!(msg.contains("\"**/*.md\""), "{msg}");
    let msg = sally_core::manifest::check_glob("notes/")
        .unwrap_err()
        .to_string();
    assert!(msg.contains("\"dir/**\""), "{msg}");
    // Brokered without globs: everything needs approval (SI-5), so nothing to warn about.
    let r = f.load(&mount("~/Documents/research", "/workspace/r", "brokered"));
    assert_eq!(warnings(&r), vec![]);
    assert_eq!(r.unwrap().manifest.mounts()[0].approve.deletes, vec!["**"]);
    // approve on rw: ignored with a warning, not carried into the validated mount.
    let body = format!(
        "{}      approve: {{writes: [\"**\"]}}\n",
        mount("~/code/myproject", "/workspace/p", "rw")
    );
    let r = f.load(&body);
    assert_eq!(
        warnings(&r),
        vec![(
            "filesystem.mounts[0].approve".to_owned(),
            Code::Inconsistent
        )]
    );
    assert!(r.unwrap().manifest.mounts()[0].approve.writes.is_empty());
}

#[test]
fn mount_mode_must_be_known() {
    let e = parse(&format!(
        "{}{}",
        common::HEADER,
        mount("/x", "/workspace/x", "rwx")
    ))
    .unwrap_err();
    assert_eq!(e.errors[0].path, "filesystem.mounts[0].mode");
}

// ---- network ----------------------------------------------------------------------------------

fn proxy(rules: &str, extra: &str) -> String {
    format!("network:\n  mode: proxy\n  allow:\n{rules}{extra}")
}

#[test]
fn network_allow_rules() {
    let f = Fixture::new();
    let r = f.load(&proxy(
        "    - host: api.github.com\n    - host: \"*.pypi.org\"\n      ports: [443, 80]\n",
        "",
    ));
    assert_ok(&r);
    let v = r.unwrap().manifest;
    assert_eq!(
        v.egress()[0].host,
        HostPattern::Exact("api.github.com".into())
    );
    assert_eq!(v.egress()[0].ports, vec![443]);
    assert_eq!(v.egress()[1].host, HostPattern::Suffix("pypi.org".into()));
    for (host, code) in [
        ("127.0.0.1", Code::IpLiteral),
        ("\"[::1]\"", Code::IpLiteral),
        ("\"0x7f000001\"", Code::IpLiteral),
        ("API.github.com", Code::BadHost),
        ("\"*.com\"", Code::BadHost),
        ("\"a.*.com\"", Code::BadHost),
        ("github.com.", Code::BadHost),
    ] {
        let r = f.load(&proxy(&format!("    - host: {host}\n"), ""));
        assert_rejects(&r, "network.allow[0].host", code);
    }
}

#[test]
fn network_ports() {
    let f = Fixture::new();
    let with = |ports: &str| {
        f.load(&proxy(
            &format!("    - host: a.example.com\n      ports: {ports}\n"),
            "",
        ))
    };
    assert_ok(&with("[80, 443, 8443]"));
    assert_rejects(&with("[]"), "network.allow[0].ports", Code::InvalidValue);
    assert_rejects(&with("[0]"), "network.allow[0].ports[0]", Code::OutOfRange);
    assert_rejects(
        &with("[443, 443]"),
        "network.allow[0].ports[1]",
        Code::Duplicate,
    );
    assert_eq!(
        parse(&format!(
            "{}{}",
            common::HEADER,
            proxy("    - host: a.b\n      ports: [70000]\n", "")
        ))
        .unwrap_err()
        .errors[0]
            .path,
        "network.allow[0].ports[0]"
    );
}

#[test]
fn duplicate_rules_rejected() {
    let f = Fixture::new();
    let r = f.load(&proxy(
        "    - host: a.example.com\n    - host: a.example.com\n",
        "",
    ));
    assert_rejects(&r, "network.allow[1].host", Code::Duplicate);
}

#[test]
fn shared_suffix_wildcards_require_ack() {
    let f = Fixture::new();
    for host in [
        "*.github.io",
        "*.s3.amazonaws.com",
        "*.workers.dev",
        "*.ngrok.app",
    ] {
        let r = f.load(&proxy(&format!("    - host: \"{host}\"\n"), ""));
        assert_rejects(&r, "network.allow[0].host", Code::UnacknowledgedWildcard);
        let acked = proxy(
            &format!("    - host: \"{host}\"\n"),
            "  acknowledge_unrestricted_egress: true\n",
        );
        assert_ok(&f.load(&acked));
    }
    assert_ok(&f.load(&proxy("    - host: \"*.myorg.github.io\"\n", "")));
}

#[test]
fn wildcard_requires_ack() {
    let f = Fixture::new();
    let r = f.load(&proxy("    - host: \"*\"\n", ""));
    assert_rejects(&r, "network.allow[0].host", Code::UnacknowledgedWildcard);
    let r = f.load(&proxy(
        "    - host: \"*\"\n",
        "  acknowledge_unrestricted_egress: true\n",
    ));
    assert_ok(&r);
    assert_eq!(
        warnings(&r),
        vec![("network.allow".to_owned(), Code::Risky)]
    );
    let r = f.load(&proxy(
        "    - host: a.b.c\n",
        "  acknowledge_unrestricted_egress: true\n",
    ));
    assert_eq!(
        warnings(&r),
        vec![(
            "network.acknowledge_unrestricted_egress".to_owned(),
            Code::Inconsistent
        )]
    );
}

#[test]
fn network_limits() {
    let f = Fixture::new();
    assert_ok(&f.load("network:\n  max_request_bytes: 1KiB\n  max_response_bytes: 16GiB\n  max_connections: 1024\n"));
    for (body, path) in [
        ("max_request_bytes: 1023B", "network.max_request_bytes"),
        ("max_request_bytes: 2GiB", "network.max_request_bytes"),
        ("max_response_bytes: 17GiB", "network.max_response_bytes"),
        ("max_connections: 0", "network.max_connections"),
        ("max_connections: 1025", "network.max_connections"),
    ] {
        assert_rejects(
            &f.load(&format!("network:\n  {body}\n")),
            path,
            Code::OutOfRange,
        );
    }
}

#[test]
fn allow_rules_without_proxy_warn_and_grant_nothing() {
    let f = Fixture::new();
    let r = f.load("network:\n  mode: none\n  allow:\n    - host: a.example.com\n");
    assert_eq!(
        warnings(&r),
        vec![("network.allow".to_owned(), Code::Inconsistent)]
    );
    assert!(r.unwrap().manifest.egress().is_empty());
}

// ---- secrets ----------------------------------------------------------------------------------

fn secret(name: &str, host: &str, header: &str, format: &str) -> String {
    format!(
        "{}secrets:\n  - name: {name}\n    inject:\n      host: \"{host}\"\n      header: \"{header}\"\n      format: \"{format}\"\n",
        proxy(
            "    - host: api.github.com\n    - host: \"*.github.com\"\n",
            ""
        )
    )
}

#[test]
fn secret_allow() {
    let f = Fixture::new();
    assert_ok(&f.load(&secret(
        "GITHUB_TOKEN",
        "api.github.com",
        "Authorization",
        "Bearer {value}",
    )));
}

#[test]
fn secret_name_must_exist_and_be_well_formed() {
    let f = Fixture::new();
    let r = f.load_with(
        &secret("GITHUB_TOKEN", "api.github.com", "Authorization", "{value}"),
        &[],
    );
    assert_rejects(&r, "secrets[0].name", Code::SecretMissing);
    let r = f.load(&secret(
        "github_token",
        "api.github.com",
        "Authorization",
        "{value}",
    ));
    assert_rejects(&r, "secrets[0].name", Code::InvalidValue);
}

#[test]
fn secret_host_must_be_exact_and_allowed() {
    let f = Fixture::new();
    for (host, code) in [
        ("*", Code::NotExactHost),
        ("*.github.com", Code::NotExactHost),
        ("140.82.112.6", Code::IpLiteral),
        // Matched by the *.github.com rule, but injection needs its own exact rule.
        ("uploads.github.com", Code::SecretHostNotAllowed),
        ("evil.example", Code::SecretHostNotAllowed),
    ] {
        assert_rejects(
            &f.load(&secret("GITHUB_TOKEN", host, "Authorization", "{value}")),
            "secrets[0].inject.host",
            code,
        );
    }
}

#[test]
fn secret_requires_proxy_mode() {
    let f = Fixture::new();
    let body = "secrets:\n  - {name: X, inject: {host: a.example.com, header: X-Key, format: \"{value}\"}}\n";
    assert_rejects(&f.load(body), "secrets", Code::NetworkDisabled);
}

#[test]
fn secret_header_and_format() {
    let f = Fixture::new();
    for h in [
        "Host",
        "content-length",
        "Transfer-Encoding",
        "Proxy-Authorization",
        "X Bad",
        "X:Y",
        "",
    ] {
        let r = f.load(&secret("X", "api.github.com", h, "{value}"));
        assert_rejects(&r, "secrets[0].inject.header", Code::BadHeader);
    }
    for fmt in [
        "Bearer",
        "{value}{value}",
        "Bearer {value}\\r\\nX-Evil: 1",
        "{VALUE}",
    ] {
        let r = f.load(&secret("X", "api.github.com", "Authorization", fmt));
        assert_rejects(&r, "secrets[0].inject.format", Code::BadFormat);
    }
}

#[test]
fn secret_duplicates() {
    let f = Fixture::new();
    let base = proxy("    - host: api.github.com\n", "");
    let body = format!(
        "{base}secrets:\n  - {{name: X, inject: {{host: api.github.com, header: A, format: \"{{value}}\"}}}}\n  - {{name: X, inject: {{host: api.github.com, header: B, format: \"{{value}}\"}}}}\n  - {{name: GITHUB_TOKEN, inject: {{host: api.github.com, header: a, format: \"{{value}}\"}}}}\n"
    );
    // The same secret may serve several hosts, but only once per host.
    assert_eq!(
        errors(&f.load(&body)),
        vec![
            ("secrets[1].inject.host".to_owned(), Code::Duplicate),
            ("secrets[2].inject".to_owned(), Code::Duplicate)
        ]
    );
}

// ---- tools ------------------------------------------------------------------------------------

#[test]
fn builtin_tools() {
    let f = Fixture::new();
    assert_ok(
        &f.load("tools:\n  builtin: [shell, fetch]\n  shell: approve\nnetwork:\n  mode: proxy\n"),
    );
    assert_rejects(
        &f.load("tools:\n  builtin: [fs_read, fs_read]\n"),
        "tools.builtin[1]",
        Code::Duplicate,
    );
}

#[test]
fn shell_policy_warnings() {
    let f = Fixture::new();
    let w = |body: &str| warnings(&f.load(body));
    assert_eq!(w("tools:\n  builtin: [shell]\n  shell: approve\n"), vec![]);
    assert_eq!(
        w("tools:\n  builtin: [shell]\n  shell: allow\n"),
        vec![("tools.shell".to_owned(), Code::Risky)]
    );
    assert_eq!(
        w("tools:\n  builtin: [shell]\n  shell: deny\n"),
        vec![("tools.shell".to_owned(), Code::Inconsistent)]
    );
    assert_eq!(
        w("tools:\n  shell: approve\n"),
        vec![("tools.shell".to_owned(), Code::Inconsistent)]
    );
    assert_eq!(
        w("tools:\n  builtin: [fetch]\n"),
        vec![("tools.builtin".to_owned(), Code::Inconsistent)]
    );
    assert_eq!(
        w("tools:\n  builtin: [fs_write]\n"),
        vec![("tools.builtin".to_owned(), Code::Inconsistent)]
    );
}

#[test]
fn mcp_servers() {
    let f = Fixture::new();
    assert_ok(&f.load("tools:\n  mcp:\n    - name: fs\n      command: [npx, -y, server]\n      env: {LOG_LEVEL: debug, NODE_ENV: \"\"}\n"));
    for name in [
        "OPENAI_API_KEY",
        "github_token",
        "MY_SECRET",
        "DB_PASSWORD",
        "AWS_CREDENTIALS",
        "SSH_KEYFILE",
        "GH_PAT",
        "HTTP_AUTH",
        "SESSION_COOKIE",
        "DB_PASS",
    ] {
        let r = f.load(&format!(
            "tools:\n  mcp:\n    - name: fs\n      command: [x]\n      env: {{{name}: v}}\n"
        ));
        assert_rejects(&r, &format!("tools.mcp[0].env.{name}"), Code::SecretLikeEnv);
    }
    assert_rejects(
        &f.load("tools:\n  mcp:\n    - {name: fs, command: []}\n"),
        "tools.mcp[0].command",
        Code::InvalidValue,
    );
    assert_rejects(
        &f.load("tools:\n  mcp:\n    - {name: Fs, command: [x]}\n"),
        "tools.mcp[0].name",
        Code::InvalidValue,
    );
    assert_rejects(
        &f.load("tools:\n  mcp:\n    - {name: a, command: [x]}\n    - {name: a, command: [y]}\n"),
        "tools.mcp[1].name",
        Code::Duplicate,
    );
    assert_rejects(
        &f.load("tools:\n  mcp:\n    - {name: a, command: [x], env: {\"1BAD\": v}}\n"),
        "tools.mcp[0].env[\"1BAD\"]",
        Code::InvalidValue,
    );
    // A hostile key cannot put a newline into the diagnostic path.
    let r = f.load("tools:\n  mcp:\n    - {name: a, command: [x], env: {\"A\\nB\": v}}\n");
    assert_rejects(&r, "tools.mcp[0].env[\"A\\nB\"]", Code::InvalidValue);
}

#[test]
fn mcp_env_values_that_look_like_credentials_are_refused_without_echo() {
    let f = Fixture::new();
    // PATH and similar names are fine (no `_PAT` false positive).
    assert_ok(&f.load(
        "tools:\n  mcp:\n    - {name: a, command: [x], env: {PATH: /usr/bin, XPATH_MODE: on}}\n",
    ));
    for v in [
        fake_token(&["gh", "p_"], "abc123"),
        fake_token(&["s", "k-"], "proj-xyz"),
        fake_token(&["AK", "IA"], "0000FAKE0000FAKE"),
        fake_token(&["xo", "xb-"], "1-2"),
        fake_token(&["github", "_pat_"], "11A"),
    ] {
        let r = f.load(&format!(
            "tools:\n  mcp:\n    - {{name: a, command: [x], env: {{CONFIG: \"{v}\"}}}}\n"
        ));
        assert_rejects(&r, "tools.mcp[0].env.CONFIG", Code::SecretLikeEnv);
        assert!(!common::rendered(&r)[0].contains(&v), "value echoed: {v}");
    }
}

// ---- approvals / audit / policy -------------------------------------------------------------

#[test]
fn approvals_ranges() {
    let f = Fixture::new();
    assert_ok(&f.load("approvals:\n  timeout: 30s\n  max_pending: 1\n"));
    assert_ok(&f.load("approvals:\n  timeout: 1h\n  max_pending: 64\n"));
    assert_rejects(
        &f.load("approvals:\n  timeout: 29s\n"),
        "approvals.timeout",
        Code::OutOfRange,
    );
    assert_rejects(
        &f.load("approvals:\n  timeout: 61m\n"),
        "approvals.timeout",
        Code::OutOfRange,
    );
    assert_rejects(
        &f.load("approvals:\n  max_pending: 0\n"),
        "approvals.max_pending",
        Code::OutOfRange,
    );
    assert_rejects(
        &f.load("approvals:\n  max_pending: 65\n"),
        "approvals.max_pending",
        Code::OutOfRange,
    );
}

#[test]
fn audit_level_and_policy() {
    let f = Fixture::new();
    assert_ok(&f.load("audit:\n  level: actions\n"));
    assert!(parse(&format!("{}audit:\n  level: none\n", common::HEADER)).is_err());
    let r = f.load("policy:\n  signed_by: org\n  signature: abc\n");
    assert_eq!(
        warnings(&r),
        vec![("policy".to_owned(), Code::Inconsistent)]
    );
    assert_ok(&f.load("policy:\n  signed_by: null\n  signature: null\n"));
}

// ---- all errors reported at once ------------------------------------------------------------

#[test]
fn all_errors_are_reported_together() {
    let f = Fixture::new();
    let r = f.load("runtime:\n  pids: 1\n  cpus: 100\napprovals:\n  max_pending: 0\n");
    assert_eq!(errors(&r).len(), 3);
}

// ---- examples, summary, schema, round-trip ---------------------------------------------------

fn example(name: &str) -> String {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../manifests/examples/");
    std::fs::read_to_string(format!("{p}{name}")).unwrap()
}

#[test]
fn shipped_examples_validate() {
    let f = Fixture::new();
    let secrets: std::collections::BTreeSet<String> = ["GITHUB_TOKEN", "BRAVE_SEARCH_KEY"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    for name in ["chat-only.yaml", "coding-agent.yaml", "web-research.yaml"] {
        let r = sally_core::manifest::load(&example(name), &f.env, &secrets);
        assert!(r.is_ok(), "{name}: {:#?}", r.err());
    }
}

#[test]
fn summary_of_coding_agent() {
    let f = Fixture::new();
    let secrets: std::collections::BTreeSet<String> =
        std::iter::once("GITHUB_TOKEN".to_owned()).collect();
    let v = sally_core::manifest::load(&example("coding-agent.yaml"), &f.env, &secrets).unwrap();
    let s = f.redact(&summary(&v.manifest));
    let real_root = std::fs::canonicalize(&f.root)
        .unwrap()
        .display()
        .to_string();
    let s = s.replace(&real_root, "$ROOT");
    assert_eq!(
        s,
        "[data-can-leave] Anything this agent reads — $ROOT/home/code/myproject and whatever your GITHUB_TOKEN unlocks on api.github.com or github.com — can be sent to pypi.org, files.pythonhosted.org, api.github.com (acting as you) and github.com (acting as you).\n\
         This agent:\n\
         - uses the model qwen2.5-coder-7b-instruct-q4_k_m.\n\
         - can change files in $ROOT/home/code/myproject (at /workspace/myproject) only inside the sandbox; your folder is not changed. The changes are kept apart (`sally session changes` lists them; this version cannot apply them), and commits made in the session are never applied.\n\
         - can reach pypi.org on port 443, files.pythonhosted.org on port 443, api.github.com on port 443, github.com on port 443 (through the Sallyport proxy only).\n\
         - uses your GITHUB_TOKEN secret only toward api.github.com (the agent never sees the value).\n\
         - sees GH_TOKEN set to a placeholder, never the real value.\n\
         - uses your GITHUB_TOKEN secret only toward github.com (the agent never sees the value).\n\
         - can run shell commands with your approval.\n\
         - fetch can only read (GET/HEAD) without your approval.\n\
         - may call: fs_read, fs_list, fetch.\n\
         - runs tools in a custom workspace image: ghcr.io/ceapf/sallyport-workspace-python@sha256:0000000000000000000000000000000000000000000000000000000000000000.\n\
         - can execute files it writes to /tmp.\n\
         - is limited to 6 CPUs, 12GiB memory, 1024 processes, and 4h of wall time.\n"
    );
}

#[test]
fn summary_of_chat_only() {
    let f = Fixture::new();
    let v = sally_core::manifest::load(
        &example("chat-only.yaml"),
        &f.env,
        &std::collections::BTreeSet::new(),
    )
    .unwrap();
    assert_eq!(
        summary(&v.manifest),
        "This agent:\n\
         - uses a model you pick at launch.\n\
         - sees no host files.\n\
         - has no network access.\n\
         - cannot run shell commands.\n\
         - is audited at reduced detail (every action and connection is still recorded; per-request HTTP lines, file reads, and inference metadata are not).\n\
         - is limited to 2 CPUs, 2GiB memory, 64 processes, and 8h of wall time.\n"
    );
}

#[test]
fn summary_of_web_research_states_writes_and_deletes_separately() {
    let f = Fixture::new();
    let secrets: std::collections::BTreeSet<String> =
        std::iter::once("BRAVE_SEARCH_KEY".to_owned()).collect();
    let v = sally_core::manifest::load(&example("web-research.yaml"), &f.env, &secrets).unwrap();
    let s = summary(&v.manifest);
    assert!(s.contains("home/Documents/research (at /workspace/research); can write there with your approval; cannot delete there."), "{s}");
    assert!(s.contains("any public hostname on port 443"), "{s}");
}

#[test]
fn summary_discloses_unapproved_deletes_and_git_hooks() {
    let f = Fixture::new();
    std::fs::create_dir_all(f.home().join("code/myproject/.git")).unwrap();
    let body = "filesystem:\n  mounts:\n    - {host: \"~/code/myproject\", guest: /workspace/p, mode: rw}\n    - {host: \"~/Documents/research\", guest: /workspace/r, mode: brokered, approve: {deletes: []}}\ntools:\n  builtin: [fs_write, fs_delete]\n";
    let s = summary(&f.load(body).unwrap().manifest);
    assert!(s.contains("Its .git folders are shielded"), "{s}");
    assert!(s.starts_with("[direct-write] "), "{s}");
    assert!(
        s.contains("can write there with your approval; deletes without asking you."),
        "{s}"
    );
}

#[test]
fn examples_round_trip() {
    for name in ["chat-only.yaml", "coding-agent.yaml", "web-research.yaml"] {
        let m = parse(&example(name)).unwrap();
        let again = parse(&to_yaml(&m).unwrap()).unwrap();
        assert_eq!(m, again, "{name}");
    }
}

#[test]
fn json_schema_forbids_additional_properties() {
    let schema = json_schema();
    let v = schema.as_value();
    assert_eq!(v["additionalProperties"], false);
    assert_eq!(v["$defs"]["Mount"]["additionalProperties"], false);
    assert_eq!(v["$defs"]["Runtime"]["additionalProperties"], false);
    assert!(
        v["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == "model")
    );
}
