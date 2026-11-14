//! Red-team tests for the manifest layer (tests/redteam/REDTEAM_SUITE.md).
//!
//! Covered here: RT-MAN-01, RT-MAN-02, RT-MAN-03 (validate half), RT-FS-05 (validate half),
//! RT-FS-06 (validate + re-check half), RT-SEC-08, RT-MAN-04. The launch halves ("no container launched",
//! "launch uses the stored struct") are asserted again by the sandbox/session tests (tasks 6, 12).
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::{Duration, Instant};

use common::{Fixture, HEADER, assert_rejects, fake_token, rendered};
use sally_core::manifest::{Code, MAX_MANIFEST_BYTES, parse, parse_bytes, to_yaml, validate};

// ---- RT-MAN-01: schema fuzz --------------------------------------------------------------------

/// Deterministic xorshift64*, so failures reproduce from the printed case index.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % (n.max(1) as u64)).unwrap()
    }
}

const SNIPPETS: &[&str] = &[
    ": ",
    "\n",
    "- ",
    "{",
    "}",
    "[",
    "]",
    "&a ",
    "*a",
    "!!binary ",
    "!!str ",
    "!custom ",
    "<<: ",
    "---\n",
    "...\n",
    "\t",
    "\"",
    "'",
    "~",
    "null",
    "1e999",
    "-1",
    "0x",
    "\0",
    "é",
    "  ",
    "#",
    "? ",
    "|\n",
    ">-\n",
    "%YAML 1.2\n",
    "\u{feff}",
    "host: \"*\"\n",
    "value: secret\n",
    "mode: rw\n",
    "18446744073709551616",
    ".nan",
    "yes",
    "\\u0000",
    "\r\n",
];

fn mutate(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut v = seed.to_vec();
    for _ in 0..=rng.below(4) {
        let at = rng.below(v.len() + 1);
        match rng.below(6) {
            0 if !v.is_empty() => {
                let i = rng.below(v.len());
                v[i] ^= 1 << rng.below(8);
            }
            1 if !v.is_empty() => {
                let end = (at + rng.below(32)).min(v.len());
                v.drain(at.min(end)..end);
            }
            2 | 3 => {
                let s = SNIPPETS[rng.below(SNIPPETS.len())].as_bytes();
                v.splice(at..at, s.iter().copied());
            }
            4 => {
                // Duplicate a line: produces duplicate keys and odd indentation.
                let text = String::from_utf8_lossy(&v).into_owned();
                let lines: Vec<&str> = text.lines().collect();
                if !lines.is_empty() {
                    let line = lines[rng.below(lines.len())].to_owned();
                    v.splice(at..at, format!("{line}\n").into_bytes());
                }
            }
            _ => v.insert(at, u8::try_from(rng.below(256)).unwrap()),
        }
    }
    v
}

fn seeds() -> Vec<String> {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../manifests/examples/");
    let mut s: Vec<String> = ["chat-only.yaml", "coding-agent.yaml", "web-research.yaml"]
        .iter()
        .map(|n| std::fs::read_to_string(format!("{p}{n}")).unwrap())
        .collect();
    s.push(HEADER.to_owned());
    s
}

/// One case: must not panic, must finish under the time budget, and anything accepted must
/// round-trip to an identical struct and survive validation without panicking.
fn check_case(input: &[u8], f: &Fixture, budget: Duration) -> Result<(), String> {
    // Best of two runs, so one scheduler hiccup on a shared CI runner is not a failure; an
    // algorithmic blow-up is slow both times.
    let timed = || {
        let start = Instant::now();
        (parse_bytes(input), start.elapsed())
    };
    let (parsed, first) = timed();
    if first > budget {
        let (_, second) = timed();
        if second > budget {
            return Err(format!("parse took {first:?} then {second:?}"));
        }
    }
    if let Ok(m) = parsed {
        let yaml = to_yaml(&m).map_err(|e| format!("serialize failed: {e}"))?;
        let again = parse(&yaml).map_err(|e| format!("re-parse failed: {e:?}\n{yaml}"))?;
        if again != m {
            return Err(format!("round-trip changed the manifest:\n{yaml}"));
        }
        let _ = validate(m, &f.env, &std::collections::BTreeSet::<String>::new());
    }
    Ok(())
}

/// Per-case time budget. RT-MAN-01 says 50 ms; unoptimized test builds get 4x headroom so the
/// test measures algorithmic blow-ups, not the debug profile.
fn budget() -> Duration {
    if cfg!(debug_assertions) {
        Duration::from_millis(200)
    } else {
        Duration::from_millis(50)
    }
}

// RT-MAN-01's 10 000 cases, split into four tests so no one of them runs long under the per-test
// limit of mutation runs (#82, architect rulings Q2 and R3). Generation is separate from the part
// filter: `mutated_cases` yields every case in order from one stream and knows nothing about
// parts, so every part sees the identical inputs and a part can only choose which of them to
// check. A block of one case per seed goes to part `(case / seeds) % PARTS`, so each part sees
// every seed equally. The four parts together are the row's 10 000 cases; the macro list and
// `rt_man_01_the_parts_cover_every_case_once` keep a part from going missing or doubling.
const CASES: usize = 10_000;
const PARTS: usize = 4;

/// Every RT-MAN-01 case in order, as (case index, input), from the row's one stream.
fn mutated_cases() -> impl Iterator<Item = (usize, Vec<u8>)> {
    let seeds = seeds();
    let mut rng = Rng(0x5A11_7090_2026_1109);
    (0..CASES).map(move |case| (case, mutate(&mut rng, seeds[case % seeds.len()].as_bytes())))
}

fn mutated_manifests_part(part: usize) {
    assert!(part < PARTS, "part {part} of {PARTS}");
    let f = Fixture::new();
    let block = seeds().len();
    let (mut seen, mut checked) = (0, 0);
    for (case, input) in mutated_cases() {
        seen += 1;
        if (case / block) % PARTS != part {
            continue;
        }
        checked += 1;
        if let Err(why) = check_case(&input, &f, budget()) {
            panic!(
                "case {case}: {why}\ninput: {:?}",
                String::from_utf8_lossy(&input)
            );
        }
    }
    assert_eq!((seen, checked), (CASES, CASES / PARTS), "part {part}");
}

macro_rules! rt_man_01_parts {
    ($($name:ident = $part:literal),+ $(,)?) => {
        /// The part indices the generated tests cover, in order.
        const PART_INDICES: &[usize] = &[$($part),+];
        $(
            #[test]
            fn $name() {
                mutated_manifests_part($part);
            }
        )+
    };
}

rt_man_01_parts! {
    rt_man_01_mutated_manifests_never_panic_and_round_trip_part_0 = 0,
    rt_man_01_mutated_manifests_never_panic_and_round_trip_part_1 = 1,
    rt_man_01_mutated_manifests_never_panic_and_round_trip_part_2 = 2,
    rt_man_01_mutated_manifests_never_panic_and_round_trip_part_3 = 3,
}

#[test]
fn rt_man_01_the_parts_cover_every_case_once() {
    assert_eq!(PART_INDICES, (0..PARTS).collect::<Vec<_>>());
}

#[test]
fn rt_man_01_alias_bombs_are_refused() {
    let laughs = "a: &a [x, x, x, x, x, x, x, x, x, x]\n\
                  b: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a, *a]\n\
                  c: &c [*b, *b, *b, *b, *b, *b, *b, *b, *b, *b]\n\
                  d: &d [*c, *c, *c, *c, *c, *c, *c, *c, *c, *c]\n\
                  e: [*d, *d, *d, *d, *d, *d, *d, *d, *d, *d]\n";
    let in_field = format!("{HEADER}description: &x hi\nfilesystem:\n  deny: [*x, *x]\n");
    for text in [laughs.to_owned(), in_field] {
        let start = Instant::now();
        let e = parse(&text).unwrap_err();
        assert!(start.elapsed() < budget());
        assert_eq!(e.errors.len(), 1);
        assert!(
            matches!(e.errors[0].code, Code::Syntax | Code::Schema),
            "{e:?}"
        );
    }
    // Anchors alone are refused too: manifests have no use for them.
    let e = parse(&format!("{HEADER}description: &x hi\n")).unwrap_err();
    assert_eq!(e.errors[0].code, Code::Syntax);
}

#[test]
fn rt_man_01_oversized_input_is_refused_before_parsing() {
    let big = format!("{HEADER}description: \"{}\"\n", "a".repeat(10 << 20));
    let start = Instant::now();
    let e = parse(&big).unwrap_err();
    // Refused on length alone: far faster than parsing 10 MiB would be.
    assert!(start.elapsed() < Duration::from_millis(50));
    assert_eq!(e.errors[0].code, Code::TooLarge);
    assert!(parse_bytes(&vec![b' '; MAX_MANIFEST_BYTES + 1]).is_err());
}

/// The size limit is inclusive, for text and bytes alike: a valid manifest of exactly
/// `MAX_MANIFEST_BYTES` parses, one byte more is `too-large`.
#[test]
fn rt_man_01_the_size_limit_is_inclusive() {
    let pad = MAX_MANIFEST_BYTES - HEADER.len() - 2;
    let exact = format!("{HEADER}#{}\n", "x".repeat(pad));
    assert_eq!(exact.len(), MAX_MANIFEST_BYTES);
    parse(&exact).unwrap();
    parse_bytes(exact.as_bytes()).unwrap();
    // A small manifest too: `parse` re-checks the size, so only an input well under the limit
    // shows that `parse_bytes`'s own check does not refuse it.
    parse_bytes(format!("{HEADER}#\n").as_bytes()).unwrap();
    let over = format!("{exact} ");
    assert_eq!(parse(&over).unwrap_err().errors[0].code, Code::TooLarge);
    let e = parse_bytes(over.as_bytes()).unwrap_err();
    assert_eq!(e.errors[0].code, Code::TooLarge);
}

#[test]
fn rt_man_01_deep_nesting_is_refused() {
    for text in [
        format!(
            "{HEADER}description: {}{}\n",
            "[".repeat(100_000),
            "]".repeat(100_000)
        ),
        format!("{HEADER}x:{}\n", "\n -".repeat(10_000)),
        "a:\n".to_owned()
            + &(1..200)
                .map(|i| format!("{}a:\n", " ".repeat(i)))
                .collect::<String>(),
    ] {
        let text = &text[..text.len().min(MAX_MANIFEST_BYTES)];
        let start = Instant::now();
        assert!(parse(text).is_err());
        assert!(start.elapsed() < budget());
    }
}

#[test]
fn rt_man_01_duplicate_keys_tags_and_documents() {
    let cases = [
        (format!("{HEADER}name: other\n"), Code::Syntax, ""), // duplicate top-level key
        (
            format!("{HEADER}runtime:\n  pids: 64\n  pids: 4096\n"),
            Code::Syntax,
            "runtime",
        ),
        (
            format!(
                "{HEADER}tools:\n  mcp:\n    - {{name: a, command: [x], env: {{A: \"1\", A: \"2\"}}}}\n"
            ),
            Code::Syntax,
            "tools.mcp[0].env",
        ),
        (
            format!("{HEADER}description: !custom x\n"),
            Code::Syntax,
            "",
        ), // unknown tag
        (format!("{HEADER}---\n{HEADER}"), Code::Syntax, ""), // second document
        (
            format!("{HEADER}runtime:\n  tmp_exec: yes\n"),
            Code::Schema,
            "runtime.tmp_exec",
        ),
        (format!("{HEADER}<<: {{name: x}}\n"), Code::Syntax, ""), // merge key
        (
            format!("{HEADER}description: 123\n"),
            Code::Schema,
            "description",
        ), // unquoted number
        (
            format!("{HEADER}runtime:\n  memory: 1024\n"),
            Code::Schema,
            "runtime.memory",
        ),
    ];
    for (text, code, path) in &cases {
        let e = parse(text).expect_err(text);
        assert_eq!(
            (e.errors[0].code, e.errors[0].path.as_str()),
            (*code, *path),
            "{text}"
        );
    }
    // `!!binary` never silently decodes into a string: the literal text is what is validated.
    let m = parse(&format!("{HEADER}description: !!binary aGVsbG8=\n")).unwrap();
    assert_eq!(m.description.as_deref(), Some("aGVsbG8="));
}

// ---- RT-MAN-02: privilege via manifest --------------------------------------------------------

#[test]
fn rt_man_02_privilege_escalation_attempts_rejected_with_documented_codes() {
    let f = Fixture::new();
    let m = |host: &str, guest: &str| {
        format!(
            "filesystem:\n  mounts:\n    - {{host: \"{host}\", guest: \"{guest}\", mode: rw}}\n"
        )
    };
    let proxy = "network:\n  mode: proxy\n  allow:\n    - host: api.github.com\n";
    let cases: Vec<(String, &str, Code, &str)> = vec![
        (
            m("~", "/workspace/h"),
            "filesystem.mounts[0].host",
            Code::Denylisted,
            r#"error: filesystem.mounts[0].host: "~" is the home directory root (denylisted) [denylisted]"#,
        ),
        (
            m("~/", "/workspace/h"),
            "filesystem.mounts[0].host",
            Code::Denylisted,
            r#"error: filesystem.mounts[0].host: "~/" is the home directory root (denylisted) [denylisted]"#,
        ),
        (
            m("/", "/workspace/r"),
            "filesystem.mounts[0].host",
            Code::Denylisted,
            r#"error: filesystem.mounts[0].host: "/" is the filesystem root (denylisted) [denylisted]"#,
        ),
        (
            m("~/.config/sallyport", "/workspace/c"),
            "filesystem.mounts[0].host",
            Code::Denylisted,
            r#"error: filesystem.mounts[0].host: "~/.config/sallyport" is inside $ROOT/home/.config — configuration folders are never mountable (denylisted) [denylisted]"#,
        ),
        (
            m("~/code/myproject", "/etc"),
            "filesystem.mounts[0].guest",
            Code::GuestPath,
            r#"error: filesystem.mounts[0].guest: "/etc" must be under /workspace/ [guest-path]"#,
        ),
        (
            m("~/code/myproject", "/workspace/../root"),
            "filesystem.mounts[0].guest",
            Code::GuestPath,
            r#"error: filesystem.mounts[0].guest: "/workspace/../root" contains ".." [guest-path]"#,
        ),
        (
            "runtime:\n  image: ghcr.io/x/harness:latest\n".into(),
            "runtime.image",
            Code::NotPinned,
            r#"error: runtime.image: "ghcr.io/x/harness:latest" must be pinned by digest: <image>@sha256:<64 hex chars> [not-pinned]"#,
        ),
        (
            "network:\n  mode: proxy\n  allow:\n    - host: \"*\"\n".into(),
            "network.allow[0].host",
            Code::UnacknowledgedWildcard,
            r#"error: network.allow[0].host: "*" requires network.acknowledge_unrestricted_egress: true [unacknowledged-wildcard]"#,
        ),
        (
            format!(
                "{proxy}secrets:\n  - {{name: GITHUB_TOKEN, inject: {{host: \"*\", header: Authorization, format: \"{{value}}\"}}}}\n"
            ),
            "secrets[0].inject.host",
            Code::NotExactHost,
            r#"error: secrets[0].inject.host: "*": host must be exact (no wildcards) [not-exact-host]"#,
        ),
        (
            "runtime:\n  cpus: 1000000\n".into(),
            "runtime.cpus",
            Code::OutOfRange,
            r#"error: runtime.cpus: 1000000 is outside 0.5–8 (host CPUs) [out-of-range]"#,
        ),
    ];
    for (body, path, code, message) in cases {
        let r = f.load(&body);
        assert_rejects(&r, path, code);
        assert_eq!(
            rendered(&r).iter().map(|s| f.redact(s)).collect::<Vec<_>>(),
            vec![message],
            "{body}"
        );
    }
}

/// SI-11: Podman reads `<transport>:<rest>` as "load from this host path or daemon" even with
/// `--pull=never`, so a digest suffix on a transport reference pins nothing.
#[test]
fn rt_man_02_image_transport_prefixes_are_refused() {
    let f = Fixture::new();
    let d = "0".repeat(64);
    for image in [
        "dir:/home/u/project/img",
        "dir:5000/rel",
        "oci:foo",
        "oci-archive:/x.tar",
        "docker-archive:/x.tar",
        "docker-daemon:x",
        "containers-storage:x",
        "docker://ghcr.io/a/b",
    ] {
        for field in ["runtime", "harness"] {
            let r = f.load(&format!("{field}:\n  image: \"{image}@sha256:{d}\"\n"));
            assert_rejects(&r, &format!("{field}.image"), Code::NotPinned);
        }
    }
}

// ---- RT-MAN-03: TOCTOU on the manifest file -----------------------------------------------------

#[test]
fn rt_man_03_validated_manifest_is_independent_of_the_file() {
    let f = Fixture::new();
    let path = f.root.join("m.yaml");
    let safe = format!(
        "{HEADER}filesystem:\n  mounts:\n    - {{host: \"~/code/myproject\", guest: /workspace/p, mode: ro}}\n"
    );
    std::fs::write(&path, &safe).unwrap();
    let v = f
        .load_with(
            &std::fs::read_to_string(&path).unwrap()[HEADER.len()..],
            &[],
        )
        .unwrap()
        .manifest;
    let snapshot = v.clone();

    // Attacker rewrites the file after validation.
    std::fs::write(
        &path,
        safe.replace("~/code/myproject", "~/.ssh")
            .replace("mode: ro", "mode: rw"),
    )
    .unwrap();

    // The validated struct (what launch consumes) is unchanged ...
    assert_eq!(v, snapshot);
    assert_eq!(v.mounts()[0].mode, sally_core::manifest::MountMode::Ro);
    assert!(v.mounts()[0].host.ends_with("code/myproject"));
    // ... the mount re-check still passes (the *host directory* did not change) ...
    assert!(v.recheck_mounts(&f.env).is_ok());
    // ... and re-loading the mutated file is rejected.
    let reread = std::fs::read_to_string(&path).unwrap();
    assert_rejects(
        &f.load(&reread[HEADER.len()..]),
        "filesystem.mounts[0].host",
        Code::Denylisted,
    );
}

// ---- RT-FS-05: denylisted mounts ---------------------------------------------------------------

#[test]
fn rt_fs_05_denylisted_mounts_rejected() {
    let f = Fixture::new();
    let runtime_dir = f.env.xdg_runtime_dir.clone().unwrap();
    for host in [
        "~".to_owned(),
        "~/.ssh".to_owned(),
        "/".to_owned(),
        "/mnt/c".to_owned(),
        "~/.config/sallyport".to_owned(),
        "/etc".to_owned(),
        runtime_dir.display().to_string(),
        "~/.gnupg".to_owned(),
        "~/.aws".to_owned(),
        "~/.local/share/sallyport".to_owned(),
        "/proc".to_owned(),
        "/sys".to_owned(),
        "/dev".to_owned(),
        "/run".to_owned(),
        "/var/run".to_owned(),
        "/boot".to_owned(),
        "/root".to_owned(),
        "/usr/lib/wsl".to_owned(),
        "/var/lib/containers/storage".to_owned(),
        "~/.local/share/containers/storage".to_owned(),
        // Executed or auto-loaded by the host (persistence → host code execution, G4).
        "~/.local/bin".to_owned(),
        "~/bin".to_owned(),
        "~/.cargo".to_owned(),
        "~/.local/share/applications".to_owned(),
        // Credentials.
        "~/.claude".to_owned(),
        "~/.kube".to_owned(),
        "~/.docker".to_owned(),
        // Other programs' Unix sockets (ssh-agent, X11): a network path around SI-1.
        "/tmp".to_owned(),
        "/tmp/.X11-unix".to_owned(),
        "/var/tmp".to_owned(),
    ] {
        let body = format!(
            "filesystem:\n  mounts:\n    - {{host: \"{host}\", guest: /workspace/x, mode: ro}}\n"
        );
        let r = f.load(&body);
        assert_rejects(&r, "filesystem.mounts[0].host", Code::Denylisted);
        assert!(rendered(&r)[0].contains("denylisted"), "{host}");
    }
}

#[test]
fn rt_fs_05_xdg_dirs_are_denylisted_when_set() {
    let mut f = Fixture::new();
    let cfg = f.root.join("xdg-config");
    let data = f.root.join("xdg-data");
    std::fs::create_dir_all(cfg.join("tool")).unwrap();
    std::fs::create_dir_all(data.join("app")).unwrap();
    f.env.xdg_config_home = Some(cfg.clone());
    f.env.xdg_data_home = Some(data.clone());
    for host in [cfg.join("tool"), data.join("app"), cfg, data] {
        let body = format!(
            "filesystem:\n  mounts:\n    - {{host: \"{}\", guest: /workspace/x, mode: ro}}\n",
            host.display()
        );
        assert_rejects(
            &f.load(&body),
            "filesystem.mounts[0].host",
            Code::Denylisted,
        );
    }
}

// ---- RT-FS-06: mount root is a symlink -----------------------------------------------------------

#[test]
fn rt_fs_06_symlinked_mount_root_rejected_at_validate() {
    let f = Fixture::new();
    std::os::unix::fs::symlink(f.home().join(".ssh"), f.home().join("proj")).unwrap();
    let r =
        f.load("filesystem:\n  mounts:\n    - {host: \"~/proj\", guest: /workspace/p, mode: rw}\n");
    assert_rejects(&r, "filesystem.mounts[0].host", Code::IsSymlink);
}

#[test]
fn rt_fs_06_swap_after_validation_is_caught_by_recheck() {
    let f = Fixture::new();
    std::fs::create_dir(f.home().join("proj")).unwrap();
    let v = f
        .load("filesystem:\n  mounts:\n    - {host: \"~/proj\", guest: /workspace/p, mode: rw}\n")
        .unwrap()
        .manifest;
    assert!(v.recheck_mounts(&f.env).is_ok());

    // Swap: the validated directory becomes a symlink to ~/.ssh.
    std::fs::rename(f.home().join("proj"), f.home().join("proj.orig")).unwrap();
    std::os::unix::fs::symlink(f.home().join(".ssh"), f.home().join("proj")).unwrap();
    let e = v.recheck_mounts(&f.env).unwrap_err();
    assert_eq!(e.errors[0].code, Code::IsSymlink);

    // Swap: a different real directory at the same path (same realpath, different inode).
    std::fs::remove_file(f.home().join("proj")).unwrap();
    std::fs::create_dir(f.home().join("proj")).unwrap();
    let e = v.recheck_mounts(&f.env).unwrap_err();
    assert_eq!(e.errors[0].code, Code::MountChanged);
}

// ---- RT-SEC-08: secret via manifest --------------------------------------------------------------

#[test]
fn rt_sec_08_secret_values_cannot_enter_through_the_manifest() {
    let f = Fixture::new();
    // A token pasted into the wrong field is not echoed back into UI/audit text.
    let tok = fake_token(&["gh", "p_"], "0123456789abcdefghijABCDEFGHIJ");
    for body in [
        format!("runtime:\n  timeout: {tok}\n"),
        format!("audit:\n  level: {tok}\n"),
        format!("{tok}: 1\n"),
        format!(
            "secrets:\n  - {{name: {tok}, inject: {{host: a.b, header: H, format: \"{{value}}\"}}}}\n"
        ),
    ] {
        let shown = rendered(&f.load(&body)).join("\n");
        assert!(!shown.is_empty(), "{body}");
        assert!(
            !shown.contains("0123456789abcdefghij"),
            "token echoed: {shown}"
        );
    }
    rt_sec_08_original_rows(&f);
}

fn rt_sec_08_original_rows(f: &Fixture) {
    let proxy = "network:\n  mode: proxy\n  allow:\n    - host: api.openai.com\n";
    let canary = fake_token(&["s", "k-"], "canary");

    let inline_value = format!(
        "{proxy}secrets:\n  - name: X\n    value: \"{canary}\"\n    inject: {{host: api.openai.com, header: Authorization, format: \"Bearer {{value}}\"}}\n"
    );
    let r = f.load(&inline_value);
    assert_rejects(&r, "secrets[0].value", Code::Schema);
    assert!(rendered(&r)[0].contains("unknown field `value`"));
    assert!(
        !rendered(&r)[0].contains(&canary),
        "error must not echo the value"
    );

    let wildcard = format!(
        "{proxy}secrets:\n  - {{name: X, inject: {{host: \"*\", header: Authorization, format: \"{{value}}\"}}}}\n"
    );
    let r = f.load(&wildcard);
    assert_rejects(&r, "secrets[0].inject.host", Code::NotExactHost);
    assert!(rendered(&r)[0].contains("host must be exact"));

    let env = format!(
        "tools:\n  mcp:\n    - name: llm\n      command: [server]\n      env: {{OPENAI_API_KEY: \"{canary}\"}}\n"
    );
    let r = f.load(&env);
    assert_rejects(&r, "tools.mcp[0].env.OPENAI_API_KEY", Code::SecretLikeEnv);
    assert!(rendered(&r)[0].contains("secret-like env name"));
    assert!(
        !rendered(&r)[0].contains(&canary),
        "error must not echo the value"
    );
}

// ---- RT-MAN-04: [data-can-leave] on the shipped fixtures -----------------------------------

#[test]
fn rt_man_04_data_can_leave_flags_coding_agent_and_web_research_but_not_chat_only() {
    let f = Fixture::new();
    // The secrets the shipped manifests/examples/*.yaml grant.
    let catalog: std::collections::BTreeSet<String> = ["GITHUB_TOKEN", "BRAVE_SEARCH_KEY"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../manifests/examples/");
    for (name, expected) in [
        ("coding-agent.yaml", true),
        ("web-research.yaml", true),
        ("chat-only.yaml", false),
    ] {
        let text = std::fs::read_to_string(format!("{p}{name}")).unwrap();
        let v = sally_core::manifest::load(&text, &f.env, &catalog)
            .unwrap_or_else(|e| panic!("{name}: {e:#?}"));
        let flagged = v.warnings.iter().any(|w| w.code == Code::DataCanLeave);
        let s = sally_core::manifest::summary(&v.manifest);
        assert_eq!(flagged, expected, "{name}: {:#?}", v.warnings);
        assert_eq!(s.starts_with("[data-can-leave] "), expected, "{name}:\n{s}");
        if expected {
            assert!(
                s.lines().next().unwrap().contains("acting as you"),
                "{name}:\n{s}"
            );
        }
    }
}
