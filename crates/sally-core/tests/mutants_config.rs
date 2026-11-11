//! Checks `.cargo/mutants.toml` (issue #36): every exclusion matches by file, function and
//! operator (never by line), sits under a reason comment, names a file that exists, and every
//! `|` -> `^` exclusion is proven equivalent: the flag constants its function combines (with the
//! flags each call site passes, for a flags parameter) are distinct and pairwise disjoint, so
//! `a ^ b == a | b` for every combination.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use rustix::fs::{Mode, OFlags, ResolveFlags};

const XOR_MID: &str = r":\d+:\d+: replace \| with \^ in ";
const WILDCARD: &str = r":\d+:\d+: ";
/// Bitflags types whose constants the proof knows; any `|` line in an excluded function must
/// name one of them.
const TYPES: [&str; 3] = ["OFlags", "ResolveFlags", "Mode"];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn config_text() -> String {
    std::fs::read_to_string(root().join(".cargo/mutants.toml")).unwrap()
}

fn exclusions() -> Vec<String> {
    let v: toml::Value = toml::from_str(&config_text()).unwrap();
    v.get("exclude_re")
        .and_then(toml::Value::as_array)
        .expect("exclude_re array")
        .iter()
        .map(|e| e.as_str().expect("string entry").to_owned())
        .collect()
}

/// The raw value of a known constant; an unknown name fails the proof.
fn value(ty: &str, name: &str) -> u64 {
    let o = |f: OFlags| u64::from(f.bits());
    let r = |f: ResolveFlags| f.bits();
    let m = |f: Mode| u64::from(f.bits());
    match (ty, name) {
        ("OFlags", "RDONLY") => o(OFlags::RDONLY),
        ("OFlags", "WRONLY") => o(OFlags::WRONLY),
        ("OFlags", "RDWR") => o(OFlags::RDWR),
        ("OFlags", "APPEND") => o(OFlags::APPEND),
        ("OFlags", "CREATE") => o(OFlags::CREATE),
        ("OFlags", "EXCL") => o(OFlags::EXCL),
        ("OFlags", "TRUNC") => o(OFlags::TRUNC),
        ("OFlags", "NOFOLLOW") => o(OFlags::NOFOLLOW),
        ("OFlags", "NONBLOCK") => o(OFlags::NONBLOCK),
        ("OFlags", "DIRECTORY") => o(OFlags::DIRECTORY),
        ("OFlags", "PATH") => o(OFlags::PATH),
        ("OFlags", "CLOEXEC") => o(OFlags::CLOEXEC),
        ("OFlags", "TMPFILE") => o(OFlags::TMPFILE),
        ("OFlags", "SYNC") => o(OFlags::SYNC),
        ("OFlags", "DSYNC") => o(OFlags::DSYNC),
        ("ResolveFlags", "BENEATH") => r(ResolveFlags::BENEATH),
        ("ResolveFlags", "IN_ROOT") => r(ResolveFlags::IN_ROOT),
        ("ResolveFlags", "NO_SYMLINKS") => r(ResolveFlags::NO_SYMLINKS),
        ("ResolveFlags", "NO_MAGICLINKS") => r(ResolveFlags::NO_MAGICLINKS),
        ("ResolveFlags", "NO_XDEV") => r(ResolveFlags::NO_XDEV),
        ("Mode", "RUSR") => m(Mode::RUSR),
        ("Mode", "WUSR") => m(Mode::WUSR),
        ("Mode", "XUSR") => m(Mode::XUSR),
        ("Mode", "RWXU") => m(Mode::RWXU),
        _ => panic!("{ty}::{name} is not a constant the disjointness proof knows"),
    }
}

/// `(type, name)` of every known-type constant in `text`, in order.
fn constants(text: &str) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    for ty in TYPES {
        let pat = format!("{ty}::");
        for (at, _) in text.match_indices(&pat) {
            let before = text[..at].chars().next_back();
            if before.is_some_and(|c| c.is_alphanumeric() || c == '_') {
                continue; // e.g. `StatxFlags::` when looking for `Flags::`
            }
            let name: String = text[at + pat.len()..]
                .chars()
                .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_')
                .collect();
            if !name.is_empty() {
                out.push((ty, name));
            }
        }
    }
    out
}

/// The source of `fn name` in `src`: signature through its matching closing brace. The name
/// must be defined exactly once in the file.
fn function<'a>(src: &'a str, name: &str, file: &str) -> &'a str {
    let starts: Vec<usize> = src
        .match_indices(&format!("fn {name}"))
        .map(|(i, _)| i)
        .filter(|&i| {
            let next = src[i + 3 + name.len()..].chars().next();
            matches!(next, Some('(' | '<'))
        })
        .collect();
    assert_eq!(
        starts.len(),
        1,
        "{file}: `fn {name}` must be defined exactly once"
    );
    let start = starts[0];
    let open = start + src[start..].find('{').expect("function body");
    let mut depth = 0usize;
    for (i, c) in src[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &src[start..=open + i];
                }
            }
            _ => {}
        }
    }
    panic!("{file}: unbalanced braces in `fn {name}`");
}

/// Distinct names, pairwise disjoint values, per type.
fn assert_disjoint(names: &[(&'static str, String)], what: &str) {
    for (i, (ta, a)) in names.iter().enumerate() {
        for (tb, b) in &names[i + 1..] {
            if ta != tb {
                continue;
            }
            assert_ne!(a, b, "{what}: {ta}::{a} is combined twice");
            let (va, vb) = (value(ta, a), value(tb, b));
            assert_eq!(
                va & vb,
                0,
                "{what}: {ta}::{a} ({va:#o}) overlaps {tb}::{b} ({vb:#o})"
            );
        }
    }
}

/// Every `|` -> `^` exclusion is equivalent: its function combines only distinct, pairwise
/// disjoint constants, every binary `|` line there names one, and a flags parameter is checked
/// together with the constants at each of its call sites.
#[test]
fn xor_exclusions_combine_disjoint_flags() {
    let mut proven = 0;
    for e in exclusions() {
        let Some((file, func)) = e.strip_suffix('$').and_then(|s| s.split_once(XOR_MID)) else {
            continue;
        };
        let file = file.replace(r"\.", ".");
        let name = func.rsplit("::").next().unwrap();
        let src = std::fs::read_to_string(root().join(&file)).unwrap();
        let body = function(&src, name, &file);
        let what = format!("{file} {func}");
        for line in body.lines().filter(|l| l.contains(" | ")) {
            assert!(
                !constants(line).is_empty(),
                "{what}: `|` on a line without a known flag constant: {line}"
            );
        }
        let own = constants(body);
        assert!(!own.is_empty(), "{what}: no flag constants found");
        assert_disjoint(&own, &what);
        let sig = &body[..body.find('{').unwrap()];
        if TYPES.iter().any(|t| sig.contains(&format!(": {t}"))) {
            assert!(
                !sig.trim_start().starts_with("pub"),
                "{what}: a flags parameter must be private"
            );
            let calls: Vec<&str> = src
                .lines()
                .filter(|l| l.contains(&format!("{name}(")) && !l.contains(&format!("fn {name}")))
                .collect();
            assert!(!calls.is_empty(), "{what}: no call sites found");
            for call in calls {
                let mut all = constants(call);
                assert!(
                    !all.is_empty(),
                    "{what}: call site without its flags on one line: {call}"
                );
                all.extend(own.iter().cloned());
                assert_disjoint(&all, &format!("{what} called as `{}`", call.trim()));
            }
        }
        proven += 1;
    }
    assert!(
        proven > 0,
        "no `| -> ^` exclusions found; did the config format change?"
    );
}

/// Never by line: every exclusion keeps `\d+:\d+` as a wildcard, is anchored at the end, and
/// names a source file that exists.
#[test]
fn exclusions_match_by_file_function_and_operator() {
    let all = exclusions();
    assert!(!all.is_empty());
    for e in &all {
        let (file, rest) = e
            .split_once(WILDCARD)
            .unwrap_or_else(|| panic!("no wildcard: {e}"));
        assert!(e.ends_with('$'), "not anchored: {e}");
        assert!(
            rest.contains(" in ") || rest.starts_with("replace "),
            "no function: {e}"
        );
        assert!(
            file.ends_with(r"\.rs"),
            "file part must end at the file name: {e}"
        );
        let path = root().join(file.replace(r"\.", "."));
        assert!(path.is_file(), "{e}: {} does not exist", path.display());
    }
}

/// The proof itself refuses an overlap (RWXU contains RUSR) and a constant combined twice.
#[test]
#[should_panic(expected = "overlaps")]
fn the_proof_refuses_overlapping_constants() {
    assert_disjoint(&constants("Mode::RWXU | Mode::RUSR"), "self-test");
}

#[test]
#[should_panic(expected = "combined twice")]
fn the_proof_refuses_a_repeated_constant() {
    assert_disjoint(
        &constants("OFlags::PATH | OFlags::NOFOLLOW | OFlags::PATH"),
        "self-test",
    );
}

#[test]
#[should_panic(expected = "not a constant the disjointness proof knows")]
fn the_proof_refuses_an_unknown_constant() {
    assert_disjoint(&constants("OFlags::NOATIME | OFlags::PATH"), "self-test");
}

/// Each group of entries sits under a reason comment.
#[test]
fn every_exclusion_group_has_a_reason() {
    let text = config_text();
    let mut prev = "";
    for line in text.lines().map(str::trim) {
        if line.starts_with('\'') {
            assert!(
                prev.starts_with('#') || prev.starts_with('\''),
                "entry without a reason comment above it: {line}"
            );
        }
        prev = line;
    }
}
