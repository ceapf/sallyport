//! Red-team tests for the manifest layer (tests/redteam/REDTEAM_SUITE.md).
//!
//! Covered here: RT-MAN-01, RT-MAN-02, RT-MAN-03 (the place check the launchers call; its red-team
//! tests run the `sally` binary and a real launch), RT-FS-05 (validate half),
//! RT-FS-06 (validate + re-check half), RT-SEC-08, RT-MAN-04, RT-FS-19. The launch halves ("no container launched",
//! "launch uses the stored struct") are asserted again by the sandbox/session tests (tasks 6, 12).
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::{Duration, Instant};

use common::rendered_all;
use common::{Fixture, HEADER, assert_rejects, fake_token, rendered};
use sally_core::manifest::{
    Code, EnvDir, FsKind, LocationError, MAX_MANIFEST_BYTES, ManifestPlace, parse, parse_bytes,
    to_yaml, validate,
};

/// The control of a return-value refusal (#122): `body`, which differs from the refused case
/// only in the attribute under test, is accepted by the same load.
#[track_caller]
fn twin_ok(f: &Fixture, body: &str) {
    let r = f.load(body);
    assert!(
        r.is_ok(),
        "control: the accepted twin is refused: {body}: {:#?}",
        r.as_ref().err()
    );
}

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
    let digest = "0".repeat(64);
    let wildcard = |host: &str, ack: bool| {
        let ack = if ack {
            "  acknowledge_unrestricted_egress: true\n"
        } else {
            ""
        };
        format!("network:\n  mode: proxy\n  allow:\n    - host: \"{host}\"\n{ack}")
    };
    let secret = |host: &str| {
        format!(
            "{proxy}secrets:\n  - {{name: GITHUB_TOKEN, inject: {{host: \"{host}\", header: Authorization, format: \"{{value}}\"}}}}\n"
        )
    };
    // Each rejected case and its control (#122): an accepted twin through the same `f.load`,
    // differing only in the attribute under test.
    let cases: Vec<(String, String, &str, Code, &str)> = vec![
        (
            m("~", "/workspace/h"),
            m("~/code/myproject", "/workspace/h"),
            "filesystem.mounts[0].host",
            Code::Denylisted,
            r#"error: filesystem.mounts[0].host: "~" is the home directory root (denylisted) [denylisted]"#,
        ),
        (
            m("~/", "/workspace/h"),
            m("~/code/myproject", "/workspace/h"),
            "filesystem.mounts[0].host",
            Code::Denylisted,
            r#"error: filesystem.mounts[0].host: "~/" is the home directory root (denylisted) [denylisted]"#,
        ),
        (
            m("/", "/workspace/r"),
            m("~/code/myproject", "/workspace/r"),
            "filesystem.mounts[0].host",
            Code::Denylisted,
            r#"error: filesystem.mounts[0].host: "/" is the filesystem root (denylisted) [denylisted]"#,
        ),
        (
            m("~/.config/sallyport", "/workspace/c"),
            m("~/code/myproject", "/workspace/c"),
            "filesystem.mounts[0].host",
            Code::Denylisted,
            r#"error: filesystem.mounts[0].host: "~/.config/sallyport" is inside $ROOT/home/.config: configuration folders are never mountable (denylisted) [denylisted]"#,
        ),
        (
            m("~/code/myproject", "/etc"),
            m("~/code/myproject", "/workspace/etc"),
            "filesystem.mounts[0].guest",
            Code::GuestPath,
            r#"error: filesystem.mounts[0].guest: "/etc" must be under /workspace/ [guest-path]"#,
        ),
        (
            m("~/code/myproject", "/workspace/../root"),
            m("~/code/myproject", "/workspace/root"),
            "filesystem.mounts[0].guest",
            Code::GuestPath,
            r#"error: filesystem.mounts[0].guest: "/workspace/../root" contains ".." [guest-path]"#,
        ),
        (
            "runtime:\n  image: ghcr.io/x/harness:latest\n".into(),
            format!("runtime:\n  image: ghcr.io/x/harness@sha256:{digest}\n"),
            "runtime.image",
            Code::NotPinned,
            r#"error: runtime.image: "ghcr.io/x/harness:latest" must be pinned by digest: <image>@sha256:<64 hex chars> [not-pinned]"#,
        ),
        (
            "network:\n  mode: proxy\n  allow:\n    - host: \"*\"\n".into(),
            // The acknowledgement is the defence's own switch (architect Q184).
            "network:\n  mode: proxy\n  allow:\n    - host: \"*\"\n  acknowledge_unrestricted_egress: true\n"
                .into(),
            "network.allow[0].host",
            Code::UnacknowledgedWildcard,
            r#"error: network.allow[0].host: "*" requires network.acknowledge_unrestricted_egress: true [unacknowledged-wildcard]"#,
        ),
        // A wildcard under a shared tree (a regional endpoint), one over a shared tree itself and
        // one over a parent of a listed entry each reach hosts anyone can register, as `*` does.
        (
            wildcard("*.s3.us-east-1.amazonaws.com", false),
            wildcard("*.s3.us-east-1.amazonaws.com", true),
            "network.allow[0].host",
            Code::UnacknowledgedWildcard,
            // Long and holding a digit, the host is masked like any token-shaped value
            // (TODO(#236): whether a parsed host pattern is exempt is the maintainer's choice).
            r#"error: network.allow[0].host: "*.s3...[28 chars hidden]" covers hosts anyone can register, so it requires network.acknowledge_unrestricted_egress: true [unacknowledged-wildcard]"#,
        ),
        (
            wildcard("*.windows.net", false),
            wildcard("*.windows.net", true),
            "network.allow[0].host",
            Code::UnacknowledgedWildcard,
            r#"error: network.allow[0].host: "*.windows.net" covers hosts anyone can register, so it requires network.acknowledge_unrestricted_egress: true [unacknowledged-wildcard]"#,
        ),
        (
            wildcard("*.googleapis.com", false),
            wildcard("*.googleapis.com", true),
            "network.allow[0].host",
            Code::UnacknowledgedWildcard,
            r#"error: network.allow[0].host: "*.googleapis.com" covers hosts anyone can register, so it requires network.acknowledge_unrestricted_egress: true [unacknowledged-wildcard]"#,
        ),
        (
            secret("*"),
            secret("api.github.com"),
            "secrets[0].inject.host",
            Code::NotExactHost,
            r#"error: secrets[0].inject.host: "*": host must be exact (no wildcards) [not-exact-host]"#,
        ),
        (
            "runtime:\n  cpus: 1000000\n".into(),
            "runtime:\n  cpus: 8\n".into(),
            "runtime.cpus",
            Code::OutOfRange,
            r#"error: runtime.cpus: 1000000 is outside 0.5 to 8 (host CPUs) [out-of-range]"#,
        ),
    ];
    for (body, twin, path, code, message) in cases {
        twin_ok(&f, &twin);
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
            // Control (#122): the registry form with the same digest is accepted.
            twin_ok(
                &f,
                &format!("{field}:\n  image: \"ghcr.io/a/b@sha256:{d}\"\n"),
            );
            let r = f.load(&format!("{field}:\n  image: \"{image}@sha256:{d}\"\n"));
            assert_rejects(&r, &format!("{field}.image"), Code::NotPinned);
        }
    }
}

/// Each channel that runs unapproved is refused without its `tools.acknowledge_unapproved`
/// entry: `shell: allow`, `fetch_writes: allow`, and an MCP server with `approve: never`. Control
/// for each (#122): its twin with the entry, through the same `f.load`, is accepted and reports
/// exactly that acknowledgement.
#[test]
fn rt_man_02_unapproved_channels_are_refused_without_their_acknowledgement() {
    let f = Fixture::new();
    let mount = "filesystem:\n  mounts:\n    - {host: \"~/code/myproject\", guest: /workspace/p, \
                 mode: ro}\n";
    let proxy = "network:\n  mode: proxy\n  allow:\n    - host: api.github.com\n";
    let cases = [
        (
            "tools:\n  builtin: [shell]\n  shell: allow\n  destructive_requires_approval: false\n"
                .to_owned(),
            "shell",
        ),
        (
            format!("{mount}{proxy}tools:\n  builtin: [fetch]\n  fetch_writes: allow\n"),
            "fetch",
        ),
        (
            format!(
                "{mount}tools:\n  mcp:\n    - name: docs\n      command: [docs-server]\n      \
                 approve: never\n"
            ),
            "mcp:docs",
        ),
    ];
    for (body, entry) in cases {
        let twin = format!("{body}  acknowledge_unapproved: [\"{entry}\"]\n");
        twin_ok(&f, &twin);
        assert_eq!(
            f.load(&twin).unwrap().manifest.acknowledged_risks(),
            [format!("tools.acknowledge_unapproved: {entry}")],
            "{entry}"
        );
        assert_rejects(
            &f.load(&body),
            "tools.acknowledge_unapproved",
            Code::UnacknowledgedRisk,
        );
        let said = rendered(&f.load(&body)).join("\n");
        assert!(
            said.contains(&format!("add \"{entry}\" to tools.acknowledge_unapproved")),
            "{entry}: {said}"
        );
    }
}

// ---- RT-MAN-03: the manifest file's place ---------------------------------------------------
// The red-team tests of RT-MAN-03 run the `sally` binary (sally-cli tests/consent.rs) and a real
// launch (sallyd tests/session.rs). Here: the place check the launchers call on a validated
// manifest.

/// A manifest kept inside one of its own `rw` or `brokered` mounts is refused, naming the mount;
/// kept inside a `staged` or `ro` one, or outside every mount, it is not.
#[test]
fn the_place_check_refuses_a_manifest_inside_its_own_writable_mount() {
    let f = Fixture::new();
    let inside = f.home().join("code/myproject/m.yaml");
    let outside = f.root.join("m.yaml");
    for (mode, refused) in [
        ("rw", true),
        ("brokered", true),
        ("staged", false),
        ("ro", false),
    ] {
        let body = format!(
            "filesystem:\n  mounts:\n    - {{host: \"~/code/other\", guest: /workspace/o, mode: ro}}\n    - {{host: \"~/code/myproject\", guest: /workspace/p, mode: {mode}}}\n"
        );
        let v = f.load(&body).unwrap().manifest;
        for (file, want) in [(&inside, refused), (&outside, false)] {
            std::fs::write(file, format!("{HEADER}{body}")).unwrap();
            let r = v.check_place(&ManifestPlace::inspect(file).unwrap());
            match r {
                Err(LocationError::Inside { mount, root, .. }) => {
                    assert!(want, "{mode} {}: refused", file.display());
                    assert_eq!(mount, 1);
                    assert_eq!(root, v.mounts()[1].host);
                }
                Err(e) => panic!("{mode}: {e}"),
                Ok(()) => assert!(!want, "{mode} {}: not refused", file.display()),
            }
        }
    }
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

/// The default data home (`~/.local/share`) and state home (`~/.local/state`) are rules whether
/// or not `$XDG_DATA_HOME` or `$XDG_STATE_HOME` is exported: user units, session services and
/// completion scripts the host runs live there. Controls: the data home refused the same way
/// when its variable is exported with its default value, and a folder of the same name outside
/// a home is accepted.
#[test]
fn rt_fs_05_the_default_data_and_state_homes_are_rules_unexported() {
    let mut f = Fixture::new();
    let home = f.home().to_owned();
    for d in [
        ".local/share/systemd/user",
        ".local/share/dbus-1/services",
        ".local/share/bash-completion",
        ".local/state/app",
        "code/myproject/.local/share/systemd",
    ] {
        std::fs::create_dir_all(home.join(d)).unwrap();
    }
    assert_eq!(f.env.xdg_data_home, None);
    assert_eq!(f.env.xdg_state_home, None);
    let refused = [
        "~/.local/share/systemd",
        "~/.local/share/dbus-1",
        "~/.local/share/bash-completion",
        "~/.local/share",
        "~/.local/state",
        "~/.local/state/app",
    ];
    for host in refused {
        let r = f.load(&mount(host, "rw"));
        assert_rejects(&r, "filesystem.mounts[0].host", Code::Denylisted);
    }
    twin_ok(&f, &mount("~/code/myproject/.local/share/systemd", "rw"));
    f.env.xdg_data_home = Some(home.join(".local/share"));
    assert_rejects(
        &f.load(&mount("~/.local/share/systemd", "rw")),
        "filesystem.mounts[0].host",
        Code::Denylisted,
    );
}

#[test]
fn rt_fs_05_xdg_dirs_are_denylisted_when_set() {
    let mut f = Fixture::new();
    let cfg = f.root.join("xdg-config");
    let data = f.root.join("xdg-data");
    let state = f.root.join("xdg-state");
    std::fs::create_dir_all(cfg.join("tool")).unwrap();
    std::fs::create_dir_all(data.join("app")).unwrap();
    std::fs::create_dir_all(state.join("app")).unwrap();
    f.env.xdg_config_home = Some(cfg.clone());
    f.env.xdg_data_home = Some(data.clone());
    f.env.xdg_state_home = Some(state.clone());
    for host in [
        cfg.join("tool"),
        data.join("app"),
        state.join("app"),
        cfg,
        data,
        state,
    ] {
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

// ---- RT-FS-11: a root on a refused filesystem kind (Windows drives on WSL) -----------------------

/// The production reader (`statfs` of the identified root) through a seam that runs on every
/// host: listing the kind the fixture's own folder is on refuses its mount `denylisted`, naming
/// the kind, at validation and at the re-check. Controls: no kind listed accepts it, and so does
/// a list holding only another kind. On WSL, `rt_fs_11_wsl_…` shows a real drive is on a kind
/// this host lists.
#[test]
fn rt_fs_11_a_root_on_a_refused_filesystem_kind_is_refused() {
    let mut f = Fixture::new();
    let here = rustix::fs::statfs(f.home().join("code/myproject")).unwrap();
    let magic = u64::try_from(here.f_type).unwrap();
    let body = mount("~/code/myproject", "rw");
    twin_ok(&f, &body);
    let other = magic.wrapping_add(1);
    f.env.refused_fs_kinds = vec![FsKind {
        magic: other,
        label: "other",
    }];
    twin_ok(&f, &body);
    let v = f.load(&body).unwrap().manifest;
    let listed = FsKind {
        magic,
        label: "test-kind",
    };
    f.env.refused_fs_kinds = vec![
        FsKind {
            magic: other,
            label: "other",
        },
        listed,
    ];
    let r = f.load(&body);
    assert_rejects(&r, "filesystem.mounts[0].host", Code::Denylisted);
    let msg = &r.unwrap_err().errors[0].message;
    let want = "which is on a test-kind filesystem (on WSL a Windows drive or share): never \
                mountable (denylisted)";
    assert!(msg.contains(want), "{msg}");
    let e = v.recheck_mounts(&f.env).unwrap_err();
    assert_eq!(e.errors[0].code, Code::Denylisted);
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

/// A trailing `/` or `/.` makes the kernel follow a final symlink, `lstat` included, so the root
/// is judged as the same path without them. Controls: the bare spelling is refused the same way,
/// and an ordinary folder written with a trailing `/` or `/.` is accepted.
#[test]
fn rt_fs_06_a_symlinked_root_with_a_trailing_slash_or_dot_is_refused() {
    let f = Fixture::new();
    std::fs::create_dir(f.home().join("real")).unwrap();
    std::os::unix::fs::symlink(f.home().join("real"), f.home().join("proj")).unwrap();
    for host in ["~/proj", "~/proj/", "~/proj/.", "~/proj//", "~/proj/./"] {
        let r = f.load(&mount(host, "rw"));
        assert_rejects(&r, "filesystem.mounts[0].host", Code::IsSymlink);
        assert_eq!(r.as_ref().unwrap_err().errors.len(), 1, "{host}");
    }
    for host in ["~/real", "~/real/", "~/real/."] {
        twin_ok(&f, &mount(host, "rw"));
    }
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

    // The same swap under the spellings a trailing `/` or `/.` gives (the kernel follows the
    // link there): the re-check judges them as the bare path. Control: before the swap each
    // re-check passes.
    for host in ["~/proj2/", "~/proj2/."] {
        let dir = f.home().join("proj2");
        std::fs::create_dir(&dir).unwrap();
        let v = f.load(&mount(host, "rw")).unwrap().manifest;
        assert!(v.recheck_mounts(&f.env).is_ok(), "{host}");
        std::fs::rename(&dir, f.home().join("proj2.orig")).unwrap();
        std::os::unix::fs::symlink(f.home().join("proj2.orig"), &dir).unwrap();
        let e = v.recheck_mounts(&f.env).unwrap_err();
        assert_eq!(e.errors[0].code, Code::IsSymlink, "{host}");
        std::fs::remove_file(&dir).unwrap();
        std::fs::remove_dir(f.home().join("proj2.orig")).unwrap();
    }
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
    rt_sec_08_malformed_names_in_warnings(&f);
}

/// A token pasted as a secret name that its check refuses, with a slash, a space or a quote in
/// it, is not echoed by the warnings either: with an allow rule, the `[data-can-leave]` warning
/// names grants, and only a checked name is masked whole when quoted (architect Q376). Control:
/// the name guard in `validate/exposure.rs` (without it the warning echoes the token).
fn rt_sec_08_malformed_names_in_warnings(f: &Fixture) {
    let tok = fake_token(&["gh", "p_"], "0123456789abcdefghijABCDEFGHIJ");
    for name in [
        format!("A/{tok}"),
        format!("Bearer {tok}"),
        format!("X\"{tok}"),
    ] {
        let body = format!(
            "network:\n  mode: proxy\n  allow:\n    - host: api.github.com\nsecrets:\n  - name: \
             '{name}'\n    inject: {{host: api.github.com, header: H, format: \"{{value}}\"}}\n"
        );
        let shown = rendered_all(&f.load(&body)).join("\n");
        assert!(shown.contains("[data-can-leave]"), "{shown}");
        assert!(
            !shown.contains("0123456789abcdefghij"),
            "token echoed: {shown}"
        );
    }
}

fn rt_sec_08_original_rows(f: &Fixture) {
    let proxy = "network:\n  mode: proxy\n  allow:\n    - host: api.openai.com\n";
    let canary = fake_token(&["s", "k-"], "canary");

    // Each rejected case's control (#122): an accepted twin through the same `f.load`, differing
    // only in the attribute under test.
    let inject =
        "    inject: {host: api.openai.com, header: Authorization, format: \"Bearer {value}\"}\n";
    twin_ok(f, &format!("{proxy}secrets:\n  - name: X\n{inject}"));
    let inline_value = format!("{proxy}secrets:\n  - name: X\n    value: \"{canary}\"\n{inject}");
    let r = f.load(&inline_value);
    assert_rejects(&r, "secrets[0].value", Code::Schema);
    assert!(rendered(&r)[0].contains("unknown field `value`"));
    assert!(
        !rendered(&r)[0].contains(&canary),
        "error must not echo the value"
    );

    let wildcard = |host: &str| {
        format!(
            "{proxy}secrets:\n  - {{name: X, inject: {{host: \"{host}\", header: Authorization, format: \"{{value}}\"}}}}\n"
        )
    };
    twin_ok(f, &wildcard("api.openai.com"));
    let r = f.load(&wildcard("*"));
    assert_rejects(&r, "secrets[0].inject.host", Code::NotExactHost);
    assert!(rendered(&r)[0].contains("host must be exact"));

    let env = |name: &str, value: &str| {
        format!(
            "tools:\n  mcp:\n    - name: llm\n      command: [server]\n      env: {{{name}: \"{value}\"}}\n"
        )
    };
    // The canary value is refused on its own too (shown here: an ordinary name with the canary,
    // refused by the value, not echoed), so the pair that differs only in the name carries a
    // plain value; the canary case below is the original row (architect Q189).
    let by_value = f.load(&env("LLM_MODE", &canary));
    assert_rejects(&by_value, "tools.mcp[0].env.LLM_MODE", Code::SecretLikeEnv);
    assert!(
        rendered(&by_value)[0].contains("value looks like a credential"),
        "{:?}",
        rendered(&by_value)
    );
    assert!(
        !rendered(&by_value)[0].contains(&canary),
        "error must not echo the value"
    );
    twin_ok(f, &env("LLM_MODE", "1"));
    assert_rejects(
        &f.load(&env("OPENAI_API_KEY", "1")),
        "tools.mcp[0].env.OPENAI_API_KEY",
        Code::SecretLikeEnv,
    );
    let r = f.load(&env("OPENAI_API_KEY", &canary));
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

// ---- RT-FS-19: a link out of a protected folder ------------------------------------------------

fn mount(host: &str, mode: &str) -> String {
    format!(
        "filesystem:\n  mounts:\n    - {{host: \"{host}\", guest: /workspace/x, mode: {mode}}}\n"
    )
}

/// Makes `~/<link> -> ~/<target>` in the fixture home, creating the link's folder. Returns
/// how a refusal names it: "<target>, which <link>".
fn link(f: &Fixture, link: &str, target: &str) -> String {
    let l = f.home().join(link);
    let t = f.home().join(target);
    std::fs::create_dir_all(l.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&t, &l).unwrap();
    format!("{}, which {}", t.display(), l.display())
}

/// A mount of `host` is refused `denylisted`, and the message says it contains the link's
/// target, naming the link: "<host> contains <target>, which <link> points to: …". A message
/// past the diagnostic cap (300 characters, MANIFEST_SPEC §4; a long fixture root) is checked
/// up to its cut.
#[track_caller]
fn refused_naming(f: &Fixture, host: &str, mode: &str, named: &str) {
    let r = f.load(&mount(host, mode));
    assert_rejects(&r, "filesystem.mounts[0].host", Code::Denylisted);
    let msg = &r.as_ref().unwrap_err().errors[0].message;
    let want = format!("{host:?} contains {named} points to: ");
    let shown = msg
        .strip_suffix("...")
        .filter(|_| msg.chars().count() == 300);
    match shown {
        Some(head) => assert!(want.starts_with(head) || head.starts_with(&want), "{msg}"),
        None => assert!(msg.starts_with(&want), "{msg}"),
    }
}

/// A symlink inside a protected folder makes its target part of what the host runs or loads:
/// mounting the target's folder is refused, naming the link (MANIFEST_SPEC §2). Control: the
/// same mount is accepted before the link exists, by the same validator.
#[test]
fn rt_fs_19_a_link_out_of_a_protected_folder_protects_its_target() {
    let mut f = Fixture::new();
    let home = f.home().to_owned();
    std::fs::create_dir_all(home.join("tools/t/bin")).unwrap();
    std::fs::write(home.join("tools/t/bin/t"), "").unwrap();
    for dir in [
        "dotfiles/gh",
        "rc",
        "later",
        "tools/u",
        "plugs",
        "crates",
        "cargohome/bin",
        "stow/cargo",
        "stow/ktools",
    ] {
        std::fs::create_dir_all(home.join(dir)).unwrap();
    }
    let body = mount("~/tools/t", "rw");
    twin_ok(&f, &body);
    // Control: every mount refused below is accepted here, before its link or variable exists.
    for (host, mode) in [
        ("~/tools", "ro"),
        ("~/dotfiles", "ro"),
        ("~/rc", "rw"),
        ("~/later", "rw"),
        ("~/plugs", "rw"),
        ("~/crates", "rw"),
        ("~/cargohome", "rw"),
        ("~/stow/ktools", "rw"),
    ] {
        twin_ok(&f, &mount(host, mode));
    }
    let before = f.load(&body).unwrap().manifest;

    // `~/.local/bin/t -> ~/tools/t/bin/t` (pipx / uv tool layout).
    let t = link(&f, ".local/bin/t", "tools/t/bin/t");
    refused_naming(&f, "~/tools/t", "rw", &t);
    refused_naming(&f, "~/tools", "ro", &t);
    // A manifest validated before the link is refused by the library's re-check after it.
    let e = before.recheck_mounts(&f.env).unwrap_err();
    assert_eq!(e.errors[0].code, Code::Denylisted, "{e:#?}");
    // A config folder linked out (stow), even read-only.
    let gh = link(&f, ".config/gh", "dotfiles/gh");
    refused_naming(&f, "~/dotfiles", "ro", &gh);
    // A home dotfile.
    let rc = link(&f, ".bashrc", "rc/bashrc");
    refused_naming(&f, "~/rc", "rw", &rc);
    // A dangling link protects its lexical target before it exists.
    let gone = link(&f, ".local/bin/gone", "later/gone");
    refused_naming(&f, "~/later", "rw", &gone);
    // A link at depth 2 (a subfolder of a protected folder).
    let plug = link(&f, ".config/app/plug", "plugs/p");
    refused_naming(&f, "~/plugs", "rw", &plug);
    // A stow-folded protected folder (`~/.cargo -> ~/stow/cargo`) holding a relative link:
    // `../ktools/k` resolves against the real folder, to `~/stow/ktools/k`.
    std::os::unix::fs::symlink(home.join("stow/cargo"), home.join(".cargo")).unwrap();
    std::os::unix::fs::symlink("../ktools/k", home.join("stow/cargo/k")).unwrap();
    let real_home = std::fs::canonicalize(&home).unwrap();
    let k = format!(
        "{}, which {}",
        real_home.join("stow/ktools/k").display(),
        home.join(".cargo/k").display()
    );
    refused_naming(&f, "~/stow/ktools", "rw", &k);
    // A folder the environment names is a rule naming its variable, and its links are read.
    f.env.env_dirs = vec![EnvDir {
        path: home.join("cargohome"),
        var: "CARGO_HOME",
    }];
    let r = f.load(&mount("~/cargohome", "rw"));
    assert_rejects(&r, "filesystem.mounts[0].host", Code::Denylisted);
    assert!(
        rendered(&r).join("\n").contains("(from $CARGO_HOME)"),
        "{r:#?}"
    );
    let c = link(&f, "cargohome/bin/c", "crates/c");
    refused_naming(&f, "~/crates", "rw", &c);

    // Allow twin, with every link above in place: an ordinary folder and a sibling of a link's
    // target are accepted. A link whose target is inside a rule is in place too (that it adds
    // no rule is pinned in `paths.rs`).
    link(&f, ".local/bin/k", ".ssh/key");
    for host in ["~/code/myproject", "~/tools/u"] {
        twin_ok(&f, &mount(host, "rw"));
    }
}
