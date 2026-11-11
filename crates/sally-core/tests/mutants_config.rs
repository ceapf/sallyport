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

/// `src` with the contents of string and char literals blanked (same length), so a brace or a
/// `|` inside one is not read as code. Lifetimes (`'a`) are left alone.
fn strip_literals(src: &str) -> String {
    let chars: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let starts_word = i == 0 || !is_ident(chars[i - 1]);
        let raw_hashes = (c == 'r' && starts_word)
            .then(|| chars[i + 1..].iter().take_while(|&&h| h == '#').count())
            .filter(|&n| chars.get(i + 1 + n) == Some(&'"'));
        if let Some(n) = raw_hashes {
            let close: String = std::iter::once('"').chain("#".repeat(n).chars()).collect();
            let body_start = i + 2 + n;
            let rest: String = chars[body_start..].iter().collect();
            let at = rest.find(&close).expect("unterminated raw string");
            let end = body_start + rest[..at].chars().count();
            out.push_str(&" ".repeat(end + close.len() - i));
            i = end + close.len();
        } else if c == '"' {
            let mut j = i + 1;
            while chars[j] != '"' {
                j += if chars[j] == '\\' { 2 } else { 1 };
            }
            out.push_str(&" ".repeat(j + 1 - i));
            i = j + 1;
        } else if c == '\'' && chars.get(i + 1) == Some(&'\\') {
            let j = i
                + 2
                + chars[i + 2..]
                    .iter()
                    .position(|&q| q == '\'')
                    .expect("char literal");
            out.push_str(&" ".repeat(j + 1 - i));
            i = j + 1;
        } else if c == '\'' && chars.get(i + 2) == Some(&'\'') {
            out.push_str("   ");
            i += 3;
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

/// Names of the parameters whose type mentions a flags type (however it is spelled).
fn flag_params(sig: &str) -> Vec<String> {
    let params = sig.split_once('(').map_or("", |(_, p)| p);
    params
        .split(',')
        .filter(|p| TYPES.iter().any(|t| p.contains(t)))
        .filter_map(|p| p.split_once(':'))
        .map(|(n, _)| n.trim().trim_start_matches("mut ").to_owned())
        .collect()
}

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || c == ':'
}

/// `op` is a local whose `let` initializer is built from known constants only (an `if`/`else`
/// between them is fine): no call, field, method, path or bare constant other than those.
fn local_of_constants(flat: &str, op: &str) -> bool {
    let Some((_, rest)) = flat.split_once(&format!("let {op} = ")) else {
        return false;
    };
    let init = rest.split(';').next().unwrap_or_default();
    let words: Vec<&str> = init
        .split(|c: char| !is_ident(c))
        .filter(|w| !w.is_empty())
        .collect();
    let paths = words.iter().filter(|w| w.contains("::")).count();
    let bare_caps = words
        .iter()
        .any(|w| !w.contains("::") && w.chars().any(|c| c.is_ascii_uppercase()));
    !init.contains(['(', '.']) && !bare_caps && paths == constants(init).len() && paths > 0
}

/// Every operand of every binary `|` in `body` is a known `Type::CONST` (an unknown one fails
/// in [`value`]), one of `params`, or a local built from known constants: no raw value, call,
/// field or other constant slips in.
fn assert_operands(body: &str, params: &[String], what: &str) {
    let flat = body.split_whitespace().collect::<Vec<_>>().join(" ");
    for (at, _) in flat.match_indices(" | ") {
        let before = &flat[..at];
        let left_start = before
            .char_indices()
            .rev()
            .take_while(|&(_, c)| is_ident(c))
            .last()
            .map_or(at, |(i, _)| i);
        let left = &before[left_start..];
        let ahead = before[..left_start].chars().next_back();
        let after = &flat[at + 3..];
        let right: String = after.chars().take_while(|&c| is_ident(c)).collect();
        let call = after[right.len()..].starts_with('(');
        for (op, bad) in [(left, ahead == Some('.')), (right.as_str(), call)] {
            let known = match op.split_once("::") {
                Some((ty, name)) if TYPES.contains(&ty) => {
                    value(ty, name);
                    true
                }
                _ => params.iter().any(|p| p == op) || local_of_constants(&flat, op),
            };
            assert!(
                known && !bad,
                "{what}: `|` operand `{op}` is not a known flag constant or flags parameter"
            );
        }
    }
}

/// The source of `fn name` in `src`: signature through its matching closing brace. The name
/// must be defined exactly once in the file. `src` must already be [`strip_literals`]ed.
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
        let src = strip_literals(&std::fs::read_to_string(root().join(&file)).unwrap());
        let body = function(&src, name, &file);
        let what = format!("{file} {func}");
        let sig = &body[..body.find('{').unwrap()];
        let params = flag_params(sig);
        assert_operands(body, &params, &what);
        let own = constants(body);
        assert!(!own.is_empty(), "{what}: no flag constants found");
        assert_disjoint(&own, &what);
        if !params.is_empty() {
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

/// The operand check refuses a raw value, a call, a field and an unlisted constant.
#[test]
#[should_panic(expected = "is not a known flag constant")]
fn the_proof_refuses_a_call_operand() {
    assert_operands("Mode::from_raw_mode(0o600) | Mode::RUSR", &[], "self-test");
}

#[test]
#[should_panic(expected = "is not a known flag constant")]
fn the_proof_refuses_an_unlisted_constant_operand() {
    let kind = vec!["kind".to_owned()];
    assert_operands("kind | OFlags::NOFOLLOW | EXTRA", &kind, "self-test");
}

#[test]
#[should_panic(expected = "is not a known flag constant")]
fn the_proof_refuses_a_field_operand() {
    assert_operands(
        "self.flags | OFlags::PATH",
        &["flags".to_owned()],
        "self-test",
    );
}

#[test]
#[should_panic(expected = "is not a known flag constant")]
fn the_proof_refuses_a_local_built_from_a_call() {
    let body = "let access = Mode::from_raw_mode(0o600); access | Mode::RUSR";
    assert_operands(body, &[], "self-test");
}

#[test]
#[should_panic(expected = "is not a known flag constant")]
fn the_proof_refuses_a_local_holding_an_unlisted_constant() {
    let body = "let access = if w { EXTRA } else { OFlags::RDONLY }; access | OFlags::PATH";
    assert_operands(body, &[], "self-test");
}

#[test]
fn the_proof_accepts_a_local_built_from_constants() {
    let body = "let access = if writable { OFlags::RDWR | OFlags::APPEND } else { OFlags::RDONLY }; \
                access | OFlags::NOFOLLOW";
    assert_operands(body, &[], "self-test");
}

#[test]
fn the_proof_accepts_constants_and_flags_parameters() {
    let sig = "fn f(root: &OwnedFd, kind: rustix::fs::OFlags, n: usize)";
    let params = flag_params(sig);
    assert_eq!(params, ["kind"]);
    assert_operands(
        "OFlags::RDONLY\n        | OFlags::DIRECTORY | kind",
        &params,
        "self-test",
    );
}

/// A brace or `|` inside a literal is not code: the body is not cut short, and the literal's
/// text is not an operand.
#[test]
fn literals_do_not_end_a_function_or_add_operands() {
    let src = "fn f() { let c = '}'; let s = \"} | x\"; let r = r#\"}\"#; let e = '\\''; \
               OFlags::PATH | OFlags::DIRECTORY }\nfn g() {}";
    let stripped = strip_literals(src);
    let body = function(&stripped, "f", "self-test");
    assert!(body.ends_with("OFlags::DIRECTORY }"), "{body}");
    assert_operands(body, &[], "self-test");
}

/// `src` defines `fn name` as a test that runs: the line is code (not a comment), and the
/// attributes and doc lines right above it include `#[test]` and no `ignore`.
fn is_live_test(src: &str, name: &str) -> bool {
    let lines: Vec<&str> = src.lines().map(str::trim).collect();
    let Some(at) = lines
        .iter()
        .position(|l| l.starts_with(&format!("fn {name}(")))
    else {
        return false;
    };
    let above: Vec<&str> = lines[..at]
        .iter()
        .rev()
        .take_while(|l| l.starts_with("#[") || l.starts_with("//"))
        .copied()
        .collect();
    above.contains(&"#[test]")
        && !above
            .iter()
            .any(|l| l.starts_with("#[") && l.contains("ignore"))
}

#[test]
fn a_cited_proof_must_be_a_live_test() {
    assert!(is_live_test("/// doc\n#[test]\nfn p() {}", "p"));
    assert!(!is_live_test("fn p() {}", "p"), "not a test");
    assert!(
        !is_live_test("#[test]\n#[ignore]\nfn p() {}", "p"),
        "ignored"
    );
    assert!(!is_live_test("#[test]\n// fn p() {}", "p"), "commented out");
}

/// Every `Proof:` comment names a live test (`file.rs` `test_name`) in that file.
#[test]
fn every_cited_proof_test_exists() {
    let mut cited = 0;
    for line in config_text().lines().filter(|l| l.contains("Proof:")) {
        let mut ticks = line.split('`').skip(1).step_by(2);
        let name = ticks
            .next()
            .unwrap_or_else(|| panic!("no test named: {line}"));
        let file = line
            .split_whitespace()
            .find(|w| w.ends_with(".rs"))
            .unwrap_or_else(|| panic!("no file named: {line}"));
        // Where the excluded files and their proofs live.
        let dirs = [
            "crates/sally-core/tests",
            "crates/sally-core/src/audit",
            "crates/sally-core/src/secrets",
            "crates/sallyd/src/sandbox",
        ];
        let found = dirs
            .iter()
            .map(|d| root().join(d).join(file))
            .filter_map(|p| std::fs::read_to_string(p).ok())
            .any(|src| is_live_test(&src, name));
        assert!(found, "{line}: no live `#[test] fn {name}` in {file}");
        cited += 1;
    }
    assert!(cited >= 2, "the proofs are no longer cited");
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
