//! Checks `.cargo/mutants.toml` (issue #36): every exclusion matches by file, function and
//! operator (never by line), sits under a reason comment, names a file that exists, and every
//! `|` -> `^` exclusion is proven equivalent: the flag constants its function combines (with the
//! flags each call site passes, for a flags parameter) are distinct and pairwise disjoint, so
//! `a ^ b == a | b` for every combination.
//!
//! It also holds the skip-rule guards: what cargo-mutants never mutates (a method named `new`,
//! an `impl Default`, `mutants::skip`) holds no logic in mutation scope. TODO(#192): split those
//! into their own test binary (move-only).
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
        ("OFlags", "NOCTTY") => o(OFlags::NOCTTY),
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
        ("Mode", "RGRP") => m(Mode::RGRP),
        ("Mode", "ROTH") => m(Mode::ROTH),
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

/// The index just past the block comment opening at `chars[start]` (`/*`). Block comments nest
/// in Rust: `/* /* */ */` is one comment. An unterminated one panics, as an unterminated string
/// does: the scanners would be out of step with the compiler.
fn block_comment_end(chars: &[char], start: usize) -> usize {
    let mut depth = 0usize;
    let mut j = start;
    while let Some(&c) = chars.get(j) {
        match (c, chars.get(j + 1)) {
            ('/', Some('*')) => {
                depth += 1;
                j += 2;
            }
            ('*', Some('/')) => {
                depth -= 1;
                j += 2;
                if depth == 0 {
                    return j;
                }
            }
            _ => j += 1,
        }
    }
    panic!("unterminated block comment at char {start}");
}

/// `src` with the contents of string and char literals and of comments blanked (same length,
/// newlines kept), so a brace, a quote or a `|` inside one is not read as code. Lifetimes (`'a`)
/// are left alone.
fn strip_literals(src: &str) -> String {
    let chars: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        if c == '/' && matches!(next, Some('/' | '*')) {
            let end = if next == Some('/') {
                chars[i..]
                    .iter()
                    .position(|&q| q == '\n')
                    .map_or(chars.len(), |n| i + n)
            } else {
                block_comment_end(&chars, i)
            };
            out.extend(
                chars[i..end]
                    .iter()
                    .map(|&q| if q == '\n' { q } else { ' ' }),
            );
            i = end;
            continue;
        }
        let starts_word = i == 0 || !is_ident(chars[i - 1]);
        // `br"…"` too: the `r` follows a `b` that starts the word.
        let byte_raw = i > 0 && chars[i - 1] == 'b' && (i == 1 || !is_ident(chars[i - 2]));
        let raw_hashes = (c == 'r' && (starts_word || byte_raw))
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
            while chars.get(j).expect("unterminated string") != &'"' {
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
        literal_entry(e).unwrap_or_else(|why| panic!("{e}: {why}"));
    }
}

/// Q367: exclusion `e`, with its one `:\d+:\d+: ` and its final `$` cut out, is literal, so it
/// names one mutant and never a family (`.* in .*$` would drop a whole file's).
fn literal_entry(e: &str) -> Result<(), String> {
    let (file, rest) = e.split_once(WILDCARD).ok_or("no wildcard")?;
    let body = rest.strip_suffix('$').ok_or("not anchored")?;
    literal_part(file)?;
    literal_part(body)
}

/// Every regex metacharacter in `part` is escaped, and a backslash escapes only one of them:
/// `\d`, `\w`, `\S`, `\b` are patterns, and a trailing `\` escaped the anchor.
fn literal_part(part: &str) -> Result<(), String> {
    const META: &str = r"\.+*?()[]{}|^$";
    let mut chars = part.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some(m) if META.contains(m) => {}
                Some(m) => return Err(format!("`\\{m}` is a pattern, not a literal")),
                None => return Err("a trailing `\\` escapes the anchor".to_owned()),
            }
        } else if META.contains(c) {
            return Err(format!("unescaped `{c}`"));
        }
    }
    Ok(())
}

#[test]
fn an_exclusion_is_literal_but_for_its_wildcard() {
    let head = r"crates/sallyd/src/sandbox/scan\.rs:\d+:\d+: ";
    for tail in [
        r"replace \| with \^ in .*$",
        r"replace .+ in f$",
        r"replace \+ with - in f$|.*$",
        r"replace \+ with - in \w+$",
        r"replace \+ with - in [a-z_]+$",
        r"replace \+ with - in (a|b)$",
        r"replace \+ with - in f?$",
        r"replace \+ with - in f\$",
        r"replace \+ with - in f:\d+:\d+: g$",
    ] {
        assert!(literal_entry(&format!("{head}{tail}")).is_err(), "{tail}");
    }
    assert!(literal_entry(r"crates/.*\.rs:\d+:\d+: replace \+ with - in f$").is_err());
    for tail in [
        r"replace \| with \^ in Walk<'a>::list$",
        r"replace \+ with \* in Head::read_owned_by$",
        r"replace sync_dir -> Result<\(\), AuditError> with Ok\(\(\)\)$",
        r"replace match guard e\.kind\(\) == std::io::ErrorKind::NotFound with true in f$",
    ] {
        assert_eq!(literal_entry(&format!("{head}{tail}")), Ok(()), "{tail}");
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

/// The files in mutation scope: the `--file` lists of the Makefile's mutation targets
/// (`MUTANTS_FILES` and the four `MUTANTS_WIDE_*`), with `$(addprefix …)` and `dir/*.rs`
/// expanded, so a file added to a list is covered at once. Read as text: nothing here proves
/// cargo-mutants reaches each one (right `--package`, a parsed `mod` chain, every shard row).
/// TODO(#193).
fn mutation_scope() -> Vec<String> {
    let make = std::fs::read_to_string(root().join("Makefile")).unwrap();
    let vars = [
        "MUTANTS_FILES",
        "MUTANTS_WIDE_CORE",
        "MUTANTS_WIDE_SALLYD",
        "MUTANTS_WIDE_SHIM",
        "MUTANTS_WIDE_CLI",
    ];
    let files: Vec<String> = vars.iter().flat_map(|v| make_list(&make, v)).collect();
    assert!(files.len() >= 60, "the Makefile lists moved: {files:?}");
    files
}

/// The paths `var := …` and every later `var += …` name in `make` (continuation lines joined,
/// `dir/*.rs` expanded). Any other assignment of `var` (a second `:=`, `=`, `?=`) fails: it
/// would replace the list.
fn make_list(make: &str, var: &str) -> Vec<String> {
    let mut defs = 0;
    let mut out = Vec::new();
    let mut offset = 0;
    for line in make.split_inclusive('\n') {
        let start = offset;
        offset += line.len();
        let Some(rest) = line.strip_prefix(var) else {
            continue;
        };
        let rest = rest.trim_start();
        let (op, value) = match ["+=", "::=", ":=", "?=", "="]
            .iter()
            .find_map(|op| rest.strip_prefix(op).map(|v| (*op, v)))
        {
            Some(found) => found,
            None => continue, // another variable that starts with `var`
        };
        if op != "+=" {
            defs += 1;
            assert!(
                op == ":=" && defs == 1,
                "Makefile: `{var}` is defined more than once or not with `:=`"
            );
        }
        let at = start + line.len() - value.len();
        out.extend(make_words(&make[at..]));
    }
    assert_eq!(defs, 1, "Makefile: no `{var} := `");
    out.into_iter().flat_map(expand_rs_glob).collect()
}

/// The words of the make value starting `text` (its continuation lines joined), with
/// `$(addprefix p,a b)` expanded.
fn make_words(text: &str) -> Vec<String> {
    let mut def = String::new();
    for line in text.lines() {
        if let Some(more) = line.strip_suffix('\\') {
            def.push_str(more);
            def.push(' ');
        } else {
            def.push_str(line);
            break;
        }
    }
    let mut out = Vec::new();
    let mut rest = def.trim_start();
    while !rest.is_empty() {
        if let Some(inner) = rest.strip_prefix("$(addprefix ") {
            let close = inner.find(')').expect("addprefix: no `)`");
            let (prefix, list) = inner[..close].split_once(',').expect("addprefix: no `,`");
            out.extend(list.split_whitespace().map(|f| format!("{prefix}{f}")));
            rest = inner[close + 1..].trim_start();
        } else {
            let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
            out.push(rest[..end].to_owned());
            rest = rest[end..].trim_start();
        }
    }
    out
}

/// `dir/*.rs` as the sorted `.rs` files of `dir`; any other path as itself.
fn expand_rs_glob(path: String) -> Vec<String> {
    let Some(dir) = path.strip_suffix("/*.rs") else {
        return vec![path];
    };
    let mut files: Vec<String> = std::fs::read_dir(root().join(dir))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.ends_with(".rs"))
        .map(|n| format!("{dir}/{n}"))
        .collect();
    files.sort();
    files
}

/// `src` (stripped) with every inline `#[cfg(test)]` module's body blanked: test helpers may
/// hold logic in a `fn new`, product code may not.
fn without_test_modules(src: &str) -> String {
    let mut out = src.to_owned();
    let mut from = 0;
    while let Some(at) = out[from..].find("#[cfg(test)]").map(|i| from + i) {
        let after = at + "#[cfg(test)]".len();
        let item = out[after..].trim_start();
        let is_mod = ["mod ", "pub mod ", "pub(crate) mod "]
            .iter()
            .any(|p| item.starts_with(p));
        let open = out[after..].find(['{', ';']).map(|i| after + i);
        if let (true, Some(open)) = (is_mod, open)
            && out[open..].starts_with('{')
        {
            let close = matching_brace(&out, open);
            out.replace_range(open..=close, &" ".repeat(close + 1 - open));
        }
        from = after;
    }
    out
}

/// The index of the `}` closing the `{` at `open`.
fn matching_brace(src: &str, open: usize) -> usize {
    let mut depth = 0usize;
    for (i, c) in src[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return open + i;
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced braces after byte {open}");
}

/// Each `fn new` in `src` (stripped): where `fn` starts, and the index of its body's `{`, or
/// `None` for a declaration without a body (a trait's).
fn new_sites(src: &str) -> impl Iterator<Item = (usize, Option<usize>)> + '_ {
    src.match_indices("fn new").filter_map(|(at, _)| {
        let after = &src[at + "fn new".len()..];
        let word_start = at == 0 || !src[..at].ends_with(is_ident);
        (word_start && matches!(after.chars().next(), Some('(' | '<')))
            .then(|| (at, body_open(after).map(|i| at + "fn new".len() + i)))
    })
}

/// Each `fn new` with a body in `src` (stripped): the type of the innermost `impl` block holding
/// it (`(free fn)` outside every block), and the body between its braces.
fn news(src: &str) -> Vec<(String, String)> {
    let blocks = impl_blocks(src);
    let mut out = Vec::new();
    for (at, open) in new_sites(src) {
        let Some(open) = open else {
            continue; // a trait's declaration: no body, so Q358's count disagrees (Q370)
        };
        let close = matching_brace(src, open);
        let ty = blocks
            .iter()
            .rfind(|(_, o, c)| *o < at && at < *c)
            .map_or_else(|| "(free fn)".to_owned(), |(h, _, _)| impl_type(h));
        out.push((ty, src[open + 1..close].to_owned()));
    }
    out
}

/// Each `impl` block in `src` (stripped), in order: its header from `impl` to the block's `{`
/// with whitespace collapsed to one line (rustfmt wraps long ones), and the indices of its `{`
/// and `}`. An `impl Trait` in a parameter type has no block and is skipped; one in return
/// position (`-> impl Iterator<Item = u8> {`) is read as a block, which can only mislabel a
/// `fn new` nested in that function, never hide a `Default` impl (its header has no `for`).
fn impl_blocks(src: &str) -> Vec<(String, usize, usize)> {
    let mut out = Vec::new();
    for (at, _) in src.match_indices("impl") {
        let word = (at == 0 || !src[..at].ends_with(is_ident))
            && !src[at + "impl".len()..].starts_with(is_ident);
        if !word {
            continue;
        }
        let Some(open) = block_open(&src[at..]).map(|i| at + i) else {
            continue;
        };
        let header = src[at..open].split_whitespace().collect::<Vec<_>>();
        out.push((header.join(" "), open, matching_brace(src, open)));
    }
    out
}

/// In `rest` (the text from an `impl` keyword): the index of its block's `{`, the first outside
/// `<…>`, `(…)`, `[…]` and `{…}` (an `->` arrow is not a `>`; inside braces, as in `Buf<{ N }>`,
/// only braces count). `None` when a `;` or an unmatched closer comes first: an `impl Trait` in
/// a type, not a block.
fn block_open(rest: &str) -> Option<usize> {
    let (mut depth, mut braces) = (0usize, 0usize);
    let mut prev = ' ';
    for (i, c) in rest.char_indices() {
        match c {
            '{' if depth == 0 && braces == 0 => return Some(i),
            ';' if depth == 0 && braces == 0 => return None,
            '{' => braces += 1,
            '}' => braces = braces.checked_sub(1)?,
            _ if braces > 0 => {}
            '<' | '(' | '[' => depth += 1,
            '>' if prev == '-' => {}
            '>' | ')' | ']' => depth = depth.checked_sub(1)?,
            _ => {}
        }
        prev = c;
    }
    None
}

/// Each function with a body inside an `impl … Default for T` block in `src` (stripped): `T`, the
/// function's name, and its body. cargo-mutants skips every such block (Q356), whatever its
/// functions are named. A trait path counts when its last segment is exactly `Default`.
fn defaults(src: &str) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for (header, open, close) in impl_blocks(src) {
        if !default_trait(&header) {
            continue;
        }
        let ty = impl_type(&header);
        let mut from = open + 1;
        while let Some(f) = src[from..close].find("fn ").map(|i| from + i) {
            let name: String = src[f + "fn ".len()..]
                .chars()
                .take_while(|&c| is_ident(c))
                .collect();
            let sig = f + "fn ".len() + name.len();
            let body = body_open(&src[sig..close]).map(|i| sig + i);
            let Some(body) = body.filter(|_| !src[..f].ends_with(is_ident)) else {
                from = sig;
                continue;
            };
            let end = matching_brace(src, body);
            out.push((ty.clone(), name, src[body + 1..end].to_owned()));
            from = end;
        }
    }
    out
}

/// `header` (from `impl` to the block's `{`) implements a trait whose path ends in `Default`.
fn default_trait(header: &str) -> bool {
    let rest = past_generics(header.trim_start_matches("impl").trim_start());
    let Some((tr, _)) = rest.split_once(" for ") else {
        return false;
    };
    let path = tr.split('<').next().unwrap_or_default().trim();
    path.rsplit("::").next() == Some("Default")
}

/// In `sig` (the text right after a `fn` name): the index of the body's `{`, the first at depth
/// 0 after the parameter list's matching `)`, or `None` when a `;` comes first (a declaration).
/// `<…>`, `(…)` and `[…]` nest (an `->` arrow is not a `>`), and inside a `{…}` that is not the
/// body (`Bar<{ N < 3 }>`) only braces count, so G5's const generic return is skipped.
fn body_open(sig: &str) -> Option<usize> {
    let (mut depth, mut braces) = (0usize, 0usize);
    let mut params_done = false;
    let mut prev = ' ';
    for (i, c) in sig.char_indices() {
        match c {
            '{' if depth == 0 && braces == 0 && params_done => return Some(i),
            ';' if depth == 0 && braces == 0 && params_done => return None,
            '{' => braces += 1,
            '}' => braces -= 1,
            _ if braces > 0 => {}
            '<' | '(' | '[' => depth += 1,
            '>' if prev == '-' => {}
            '>' | ']' => depth -= 1,
            ')' => {
                depth -= 1;
                params_done |= depth == 0;
            }
            _ => {}
        }
        prev = c;
    }
    None
}

/// The type an `impl` block is for, from its one-line `header` (as [`impl_blocks`] gives it):
/// the path after `for` when there is one, its last segment, without generics.
fn impl_type(header: &str) -> String {
    let mut rest = past_generics(header.trim_start_matches("impl").trim_start());
    if let Some((_, ty)) = rest.split_once(" for ") {
        rest = ty;
    }
    // `is_ident` takes `:`, so the whole path is read.
    let path: String = rest.chars().take_while(|&c| is_ident(c)).collect();
    path.rsplit("::").next().unwrap_or_default().to_owned()
}

/// `rest` (the text after `impl`) without a leading generic parameter list `<…>` (the `>` of an
/// `->` arrow, as in `<F: Fn() -> u8>`, does not close it).
fn past_generics(rest: &str) -> &str {
    if !rest.starts_with('<') {
        return rest;
    }
    let mut depth = 0usize;
    let mut prev = ' ';
    let end = rest
        .char_indices()
        .find(|&(_, c)| {
            depth = match c {
                '<' => depth + 1,
                '>' if prev == '-' => depth,
                '>' => depth - 1,
                _ => depth,
            };
            prev = c;
            depth == 0
        })
        .map_or(rest.len(), |(i, _)| i + 1);
    rest[end..].trim_start()
}

/// Why `body` (a stripped body of a `fn new` or of a function in a `Default` impl) holds decision
/// logic, or `None` for a delegating call or a plain struct literal. Mechanical and conservative:
/// a statement, `?`, `..`, a control-flow keyword or a nested `fn`, a closure, a `!` that is not
/// a macro's, a binary operator (rustfmt spaces every one), or a method call other than a
/// conversion. A false positive is fixed by delegating to a named function, never by
/// allowlisting (architect Q12).
fn logic_in(body: &str) -> Option<String> {
    const OPERATORS: [&str; 18] = [
        " + ", " - ", " * ", " / ", " % ", " == ", " != ", " < ", " > ", " <= ", " >= ", " && ",
        " || ", " & ", " | ", " ^ ", " << ", " >> ",
    ];
    // `fn`: an item nested in a body cargo-mutants skips is never visited either.
    const KEYWORDS: [&str; 9] = [
        "if", "else", "match", "for", "while", "loop", "let", "return", "fn",
    ];
    const CONVERSIONS: [&str; 6] = [
        "into",
        "clone",
        "to_owned",
        "to_string",
        "as_ref",
        "into_iter",
    ];
    let flat = body.split_whitespace().collect::<Vec<_>>().join(" ");
    let spaced = format!(" {flat} ");
    if flat.contains(';') {
        return Some("a statement".into());
    }
    if flat.contains('?') {
        return Some("`?`".into());
    }
    // cargo-mutants deletes a field from a struct literal that has a `..base` (Q356).
    if flat.contains("..") {
        return Some("`..` (a struct base or a range)".into());
    }
    if let Some(op) = OPERATORS.iter().find(|op| spaced.contains(*op)) {
        return Some(format!("the operator `{}`", op.trim()));
    }
    if flat.contains('|') {
        return Some("a closure".into());
    }
    let words: Vec<&str> = flat
        .split(|c: char| !is_ident(c))
        .filter(|w| !w.is_empty())
        .collect();
    if let Some(k) = KEYWORDS.iter().find(|k| words.contains(k)) {
        return Some(format!("`{k}`"));
    }
    let chars: Vec<char> = flat.chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        let prev = i.checked_sub(1).map(|p| chars[p]);
        if c == '!' && !prev.is_some_and(is_ident) {
            return Some("`!`".into());
        }
        // A unary minus: not `->`, not after an operand (rustfmt spaces a binary one).
        if c == '-'
            && chars.get(i + 1) != Some(&'>')
            && !prev.is_some_and(|p| is_ident(p) || p == ')')
        {
            return Some("a unary `-`".into());
        }
        if c == '.' {
            let (name, call) = called(&chars, i + 1);
            if call && !CONVERSIONS.contains(&name.as_str()) {
                return Some(format!("the method call `.{name}(…)`"));
            }
        }
        if is_ident(c) && !prev.is_some_and(|p| is_ident(p) || p == '.') {
            let (path, call) = called(&chars, i);
            if call && std_path_call(&path) {
                return Some(format!("the call `{path}(…)`"));
            }
        }
    }
    None
}

/// The path or name starting at `chars[start]` (an optional turbofish `::<…>` skipped, `::`
/// trimmed), and whether a `(` follows it: `.sum::<u64>()` is the call `sum`.
fn called(chars: &[char], start: usize) -> (String, bool) {
    let name: String = chars[start..]
        .iter()
        .take_while(|&&q| is_ident(q))
        .collect();
    let mut j = start + name.chars().count();
    if name.ends_with("::") && chars.get(j) == Some(&'<') {
        let mut depth = 0usize;
        while let Some(&q) = chars.get(j) {
            let arrow = j > 0 && chars[j - 1] == '-';
            j += 1;
            match q {
                '<' => depth += 1,
                '>' if !arrow => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
        }
    }
    let call = chars.get(j) == Some(&'(');
    (name.trim_end_matches(':').to_owned(), call)
}

/// G1: a call of `path` computes rather than delegates: its qualifier is a primitive or a std
/// type, module or trait (`usize::max`, `std::cmp::min`) or a generic one (`<T as Ord>::max`,
/// read as `::max`), and it is not a constructor. `Self::f`, `Type::f` and bare `f` delegate.
fn std_path_call(path: &str) -> bool {
    const STD: [&str; 27] = [
        "u8",
        "u16",
        "u32",
        "u64",
        "u128",
        "usize",
        "i8",
        "i16",
        "i32",
        "i64",
        "i128",
        "isize",
        "f32",
        "f64",
        "bool",
        "char",
        "str",
        "std",
        "core",
        "alloc",
        "cmp",
        "mem",
        "Ord",
        "PartialOrd",
        "Iterator",
        "Option",
        "Result",
    ];
    const CONSTRUCTORS: [&str; 4] = ["new", "default", "from", "with_capacity"];
    let segments: Vec<&str> = path.split("::").collect();
    let Some((method, qualifiers)) = segments.split_last() else {
        return false;
    };
    !CONSTRUCTORS.contains(method) && qualifiers.iter().any(|q| q.is_empty() || STD.contains(q))
}

/// A `fn new` in mutation scope, by file and `impl` type, that delegates in one call: the guard
/// must find it and judge it clean, so a scan that finds no `fn new` at all cannot pass.
const CLEAN_NEW: (&str, &str) = ("crates/sallyd/src/rpc/rate.rs", "Rate");

/// Architect Q12 (R3): decision logic never lives in a function named `new` in mutation scope.
/// cargo-mutants skips a method or trait function named `new`, so logic there would go untested
/// by the nightly; this rule also covers a free `fn new`, which cargo-mutants does mutate. There
/// is no allowlist (Q354). Per file, a simple token count is the coverage proof (Q358).
#[test]
fn no_fn_new_in_mutation_scope_holds_logic() {
    let mut found = Vec::new();
    let mut clean = Vec::new();
    for file in mutation_scope() {
        let src =
            std::fs::read_to_string(root().join(&file)).unwrap_or_else(|e| panic!("{file}: {e}"));
        let code = without_test_modules(&strip_literals(&src));
        let found_here = news(&code);
        let simple = word_pairs(&code, "fn", "new");
        let what = "fn new (a body-less `fn new(..);` is a disagreement too, Q370)";
        assert_scanned(&file, what, simple, found_here.len());
        for (ty, body) in found_here {
            match logic_in(&body) {
                Some(why) => found.push(format!("{file}: {ty}::new holds {why}")),
                None => clean.push((file.clone(), ty)),
            }
        }
    }
    assert!(
        found.is_empty(),
        "move this logic into a named function (CLAUDE.md):\n{}",
        found.join("\n")
    );
    let (file, ty) = CLEAN_NEW;
    assert!(
        clean.iter().any(|(f, t)| f == file && t == ty),
        "the guard did not judge {file}: {ty}::new clean; it read {clean:?}"
    );
}

/// An `impl Default` in mutation scope, by file and type, whose body is a plain struct literal:
/// the guard must find it and judge it clean, so a scan that finds no block cannot pass.
const CLEAN_DEFAULT: (&str, &str) = ("crates/sallyd/src/sandbox/scan.rs", "ScanLimits");

/// Q356: cargo-mutants skips every `impl … Default for` block, so in mutation scope each of its
/// functions is a delegating call or a plain struct literal, as for `fn new`. No allowlist. Per
/// file, a simple token count is the coverage proof (Q358).
#[test]
fn no_default_impl_in_mutation_scope_holds_logic() {
    let mut found = Vec::new();
    let mut clean = Vec::new();
    for file in mutation_scope() {
        let src =
            std::fs::read_to_string(root().join(&file)).unwrap_or_else(|e| panic!("{file}: {e}"));
        let code = without_test_modules(&strip_literals(&src));
        let found_here = defaults(&code);
        let simple = word_pairs(&code, "Default", "for");
        assert_scanned(&file, "Default impl", simple, found_here.len());
        for (ty, name, body) in found_here {
            match logic_in(&body) {
                Some(why) => found.push(format!("{file}: <{ty} as Default>::{name} holds {why}")),
                None => clean.push((file.clone(), ty)),
            }
        }
    }
    assert!(
        found.is_empty(),
        "move this logic into a named function or a literal (CLAUDE.md):\n{}",
        found.join("\n")
    );
    let (file, ty) = CLEAN_DEFAULT;
    assert!(
        clean.iter().any(|(f, t)| f == file && t == ty),
        "the guard did not judge {file}: <{ty} as Default> clean; it read {clean:?}"
    );
}

#[test]
fn the_guard_finds_each_default_impl_with_its_type() {
    let src = strip_literals(
        "impl Default for A {\n    fn default() -> Self {\n        Self::new()\n    }\n}\n\
         impl<T: Clone> Default for B<T> {\n    \
         fn default() -> Self { Self { v: Vec::new() } }\n}\n\
         impl std::default::Default for C {\n    fn default() -> Self { Self { n: 4 << 30 } }\n}\n\
         impl Debug for D {\n    fn fmt(&self) -> u8 { if x { 1 } else { 2 } }\n}\n\
         impl DefaultThing for E {\n    fn default() -> Self { Self { n: 1 + 2 } }\n}\n\
         impl F {\n    fn implement() -> Self { Self { n: 3 * 4 } }\n}\n\
         #[cfg(test)]\nmod tests {\n    impl Default for G { \
         fn default() -> Self { if x { a } else { b } } }\n}\n",
    );
    let found = defaults(&without_test_modules(&src));
    let types: Vec<(&str, &str)> = found
        .iter()
        .map(|(t, n, _)| (t.as_str(), n.as_str()))
        .collect();
    assert_eq!(
        types,
        [("A", "default"), ("B", "default"), ("C", "default")]
    );
    let judged: Vec<bool> = found
        .iter()
        .map(|(_, _, b)| logic_in(b).is_some())
        .collect();
    assert_eq!(judged, [false, false, true], "{found:?}");
}

/// A `->` in the generics, a brace in the type or the where clause, and a wrapped header all
/// still yield the block's functions, with the type named.
#[test]
fn the_guard_finds_a_default_impl_behind_arrows_braces_and_wrapping() {
    let body = "fn default() -> Self { if x { a } else { b } }";
    let src = strip_literals(&format!(
        "impl<F: Fn() -> u8> Default for H<F> {{\n    {body}\n}}\n\
         impl Default for Buf<{{ N }}> {{\n    {body}\n}}\n\
         impl<T> Default for W<T>\nwhere\n    [(); {{ N }}]: Sized,\n{{\n    {body}\n}}\n\
         impl<T: Clone> std::default::Default\n    for Wrapped<T>\n{{\n    {body}\n}}\n\
         fn f(d: impl Default) -> u8 {{ 1 }}\n"
    ));
    let found = defaults(&src);
    let types: Vec<&str> = found.iter().map(|(t, _, _)| t.as_str()).collect();
    assert_eq!(types, ["H", "Buf", "W", "Wrapped"], "{found:?}");
    assert_eq!(word_pairs(&src, "Default", "for"), found.len());
    assert!(
        found.iter().all(|(_, _, b)| logic_in(b).is_some()),
        "{found:?}"
    );
}

#[test]
fn a_free_fn_new_is_labelled_free_and_a_method_by_its_innermost_impl() {
    let src = strip_literals(
        "impl A {\n    fn a() {}\n}\n\
         pub fn new() -> u8 { 1 }\n\
         impl B {\n    fn f() { struct C; impl C { fn new() -> u8 { 2 } } }\n    \
         fn new() -> Self { Self }\n}\n",
    );
    let types: Vec<String> = news(&src).into_iter().map(|(t, _)| t).collect();
    assert_eq!(types, ["(free fn)", "C", "B"]);
    assert_eq!(word_pairs(&src, "fn", "new"), types.len());
}

/// cargo-mutants never visits an item nested in a function it skips.
#[test]
#[should_panic(expected = "holds")]
fn the_guard_refuses_a_nested_fn() {
    refuse(" fn h() -> u8 { 1 } Self { n: h() } ");
}

#[test]
fn the_guard_reads_the_makefile_lists_and_their_globs() {
    let make = "A := x/y.rs \\\n     $(addprefix p/,a.rs b.rs) \\\n     z.rs\nB := q.rs\n";
    assert_eq!(make_list(make, "A"), ["x/y.rs", "p/a.rs", "p/b.rs", "z.rs"]);
    assert_eq!(make_list(make, "B"), ["q.rs"]);
    let scope = mutation_scope();
    assert!(
        scope
            .iter()
            .any(|f| f.ends_with("manifest/validate/mod.rs")),
        "glob"
    );
    assert!(scope.contains(&"crates/sallyd/src/egress/redact.rs".to_owned()));
}

#[test]
fn the_guard_finds_each_fn_new_with_its_impl_type() {
    let src = strip_literals(
        "impl<T: X> Foo<T> {\n    pub fn new(a: T) -> Self { Self::build(a) }\n}\n\
         impl Bar for Baz { fn new_ish() {} }\n\
         trait Q { fn new() -> Self; }\n\
         impl Default for Baz {\n    fn new() -> Self {\n        // if a comment\n        \
         Self { a: \"if\" }\n    }\n}\n\
         #[cfg(test)]\nmod tests {\n    impl T { fn new() -> u8 { if x { 1 } else { 2 } } }\n}\n",
    );
    let code = without_test_modules(&src);
    let found = news(&code);
    let types: Vec<&str> = found.iter().map(|(t, _)| t.as_str()).collect();
    assert_eq!(types, ["Foo", "Baz"]);
    // Q370: trait Q's body-less `fn new` is a token the scanner does not return, so the
    // coverage check would refuse it.
    assert_eq!(word_pairs(&code, "fn", "new"), found.len() + 1);
    assert!(
        found.iter().all(|(_, b)| logic_in(b).is_none()),
        "{found:?}"
    );
}

#[test]
fn a_delegating_call_or_a_plain_struct_literal_is_no_logic() {
    for body in [
        " Self::from_forms(secrets) ",
        " Self { a, b: Vec::new(), c: Arc::new(Mutex::new(State::default())), d: x.into() } ",
        " Self { inner, stream: redaction.stream_of(&r) } ",
        " Self { n: vec![], m: format!(\"x\") } ",
    ] {
        let body = body.replace("stream_of", "clone");
        assert_eq!(logic_in(&strip_literals(&body)), None, "{body}");
    }
}

/// cargo-mutants deletes a field of a struct literal with a base (Q356): not a plain literal.
#[test]
#[should_panic(expected = "holds")]
fn the_guard_refuses_a_struct_base() {
    // A plain base: only the `..` rule refuses it (`..Self::default()` also trips the method
    // call rule on its second dot).
    refuse(" Self { inner, ..base } ");
}

#[test]
#[should_panic(expected = "holds")]
fn the_guard_refuses_a_branch() {
    refuse(" if a { Self { a } } else { Self { a: 0 } } ");
}

#[test]
#[should_panic(expected = "holds")]
fn the_guard_refuses_a_statement() {
    refuse(" let a = 1; Self { a } ");
}

#[test]
#[should_panic(expected = "holds")]
fn the_guard_refuses_an_operator() {
    refuse(" Self { burst: rate * 2 } ");
}

#[test]
#[should_panic(expected = "holds")]
fn the_guard_refuses_a_method_call() {
    refuse(" Self { burst: rate.max(1) } ");
}

#[test]
#[should_panic(expected = "holds")]
fn the_guard_refuses_a_closure_and_a_not() {
    refuse(" Self { v: x.into_iter().filter(|f| !f.is_empty()).collect() } ");
}

#[test]
#[should_panic(expected = "holds")]
fn the_guard_refuses_a_question_mark() {
    refuse(" Ok(Self { v: parse(x)? }) ");
}

/// G1: a path call whose qualifier is a primitive or std type, module or trait is logic.
#[test]
#[should_panic(expected = "holds")]
fn the_guard_refuses_a_primitive_ufcs_call() {
    refuse(" Self { burst: usize::max(rate, 1) } ");
}

#[test]
#[should_panic(expected = "holds")]
fn the_guard_refuses_a_ufcs_saturating_add() {
    refuse(" Self { end: u64::saturating_add(start, len) } ");
}

#[test]
#[should_panic(expected = "holds")]
fn the_guard_refuses_a_ufcs_then_some() {
    refuse(" Self { v: bool::then_some(on, x) } ");
}

#[test]
#[should_panic(expected = "holds")]
fn the_guard_refuses_a_std_path_call() {
    refuse(" Self { a: std::cmp::min(a, b) } ");
}

#[test]
fn constructors_and_delegations_on_paths_are_no_logic() {
    for body in [
        " Self::build(a) ",
        " Self { v: Vec::with_capacity(n), s: String::from(x), a: Arc::new(x), d: Foo::default() } ",
        " Self { v: std::sync::Arc::new(x), w: u64::from(n), z: build(a) } ",
        " Self { v: Vec::<u8>::new() } ",
    ] {
        assert_eq!(logic_in(&strip_literals(body)), None, "{body}");
    }
}

/// G2: a turbofish method call is still a method call.
#[test]
#[should_panic(expected = "holds")]
fn the_guard_refuses_a_turbofish_method_call() {
    refuse(" Self { total: sizes.into_iter().sum::<u64>() } ");
}

/// G3: a unary minus is logic (cargo-mutants deletes it).
#[test]
#[should_panic(expected = "holds")]
fn the_guard_refuses_a_unary_minus() {
    refuse(" Self { offset: -delta } ");
}

#[test]
#[should_panic(expected = "holds")]
fn the_guard_refuses_a_negative_literal() {
    refuse(" Self { offset: -1 } ");
}

/// G4: `VAR += …` lines extend the list.
#[test]
fn the_guard_reads_appended_makefile_lists() {
    let make = "A := x.rs \\\n     y.rs\nB := q.rs\nA += $(addprefix p/,a.rs) \\\n     z.rs\n";
    assert_eq!(make_list(make, "A"), ["x.rs", "y.rs", "p/a.rs", "z.rs"]);
}

#[test]
#[should_panic(expected = "defined more than once")]
fn the_guard_refuses_a_redefined_makefile_list() {
    make_list("A := x.rs\nA := y.rs\n", "A");
}

/// G5: the body is the first `{` after the parameter list at depth 0, not one inside the
/// generics or the return type; a `;` inside the return type is not a declaration's end.
#[test]
fn the_guard_finds_the_body_after_a_braced_return_type() {
    let src = strip_literals(
        "impl Foo {\n    fn new<T: Fn(u8)>(a: T) -> Bar<{ N }> { if a { x } else { y } }\n}\n\
         impl Baz {\n    fn new() -> [u8; 4] { [0, 1, 2, 3] }\n}\n\
         trait Q { fn new() -> [u8; 4]; }\n",
    );
    let found = news(&src);
    assert_eq!(found.len(), 2, "{found:?}");
    assert_eq!(
        word_pairs(&src, "fn", "new"),
        3,
        "trait Q's declaration disagrees (Q370)"
    );
    assert_eq!(found[0].0, "Foo");
    assert!(logic_in(&found[0].1).is_some(), "{found:?}");
    assert_eq!(found[1], ("Baz".to_owned(), " [0, 1, 2, 3] ".to_owned()));
}

/// The cargo-mutants version whose src/visit.rs and src/config.rs the skip-rule guards in this
/// file were read against (Q359).
const CARGO_MUTANTS_READ_AT: &str = "27.1.0";

/// Q359: the nightly runs the version the guards were read at, and the public sentence in
/// `.cargo/mutants.toml` names it. A bump fails here until the re-read is done.
#[test]
fn the_nightly_pins_the_cargo_mutants_version_the_guards_were_read_at() {
    let reread = "before changing CARGO_MUTANTS_READ_AT, re-read cargo-mutants src/visit.rs \
                  (visit_impl_item_fn, visit_trait_item_fn, visit_item_impl, attrs_excluded, \
                  fn_sig_excluded) and the config keys in src/config.rs";
    let nightly = std::fs::read_to_string(root().join(".github/workflows/nightly.yml")).unwrap();
    let pins: Vec<&str> = nightly
        .lines()
        .filter_map(|l| l.trim_start().strip_prefix("CARGO_MUTANTS_VERSION:"))
        .map(|v| v.trim().trim_matches('"'))
        .collect();
    assert_eq!(pins, [CARGO_MUTANTS_READ_AT], "nightly.yml: {reread}");
    let named = format!("cargo-mutants ({CARGO_MUTANTS_READ_AT},");
    assert!(
        config_text().contains(&named),
        ".cargo/mutants.toml must say `{named}`: {reread}"
    );
}

/// Q360: cargo-mutants 27.1.0 config.rs also takes `exclude_globs`, `examine_globs`,
/// `examine_re`, `skip_calls` and `skip_calls_defaults`, which no check here reads; each would
/// narrow the nightly unseen.
#[test]
fn the_mutants_config_holds_only_the_known_keys() {
    let v: toml::Value = toml::from_str(&config_text()).unwrap();
    let mut keys: Vec<&str> = v
        .as_table()
        .expect("a table")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["exclude_re", "profile", "test_tool"]);
}

/// `text` names the attribute `mutants::skip`, with any whitespace between its tokens (checked on
/// the raw text and with comments blanked, so a comment between the tokens does not hide it).
fn names_mutants_skip(text: &str) -> bool {
    let squeezed = |t: &str| t.split_whitespace().collect::<String>();
    squeezed(text).contains("mutants::skip")
        || squeezed(&strip_literals(text)).contains("mutants::skip")
}

/// Every `.rs` file under `dir`, recursively. A symlink fails the walk by name: it could loop or
/// lead out of the tree, and the crates hold none.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
        let path = entry
            .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
            .path();
        let kind = std::fs::symlink_metadata(&path)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
            .file_type();
        assert!(
            !kind.is_symlink(),
            "{}: a symlink in a crate's src/",
            path.display()
        );
        if kind.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|x| x == "rs") {
            out.push(path);
        }
    }
}

/// Q360: cargo-mutants skips an item, a `mod foo;` and with it a whole file, or a file through
/// its inner attributes, when it carries `mutants::skip`, even inside a `cfg_attr` whose
/// predicate is false (`#[cfg_attr(miri, mutants::skip)]` needs no dependency and never
/// expands). So no source file of a crate with a file in mutation scope names it, listed or not.
#[test]
fn no_source_of_a_mutated_crate_names_mutants_skip() {
    let scope = mutation_scope();
    let mut crates: Vec<&str> = scope
        .iter()
        .filter_map(|f| f.find("/src/").map(|i| &f[..i + "/src".len()]))
        .collect();
    crates.sort_unstable();
    crates.dedup();
    let mut files = Vec::new();
    for dir in &crates {
        rust_files(&root().join(dir), &mut files);
    }
    let read: Vec<String> = files
        .iter()
        .map(|p| {
            p.strip_prefix(root())
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    let unread: Vec<&String> = scope.iter().filter(|f| !read.contains(f)).collect();
    assert!(unread.is_empty(), "the walk missed scope files: {unread:?}");
    let named: Vec<&String> = read
        .iter()
        .zip(&files)
        .filter(|(_, p)| {
            let text =
                std::fs::read_to_string(p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
            names_mutants_skip(&text)
        })
        .map(|(f, _)| f)
        .collect();
    assert!(
        named.is_empty(),
        "mutants::skip hides code from the nightly: {named:?}"
    );
}

#[test]
fn the_skip_scan_sees_every_spelling_and_nothing_else() {
    for text in [
        "#[mutants::skip]\nfn f() {}",
        "#[cfg_attr(miri, mutants::skip)]\nfn f() {}",
        "#![cfg_attr(miri, mutants :: skip)]",
        "#[cfg_attr(miri, mutants\n    ::\n    skip)]",
        "#[cfg_attr(miri, mutants /* hidden */ :: skip)]",
        "#[cfg_attr(miri, mutants /* /* nested */ */ :: skip)]",
    ] {
        assert!(names_mutants_skip(text), "{text}");
    }
    for text in [
        "fn mutants() { skip(); }",
        "use crate::mutants;\nlet skip = 1;",
    ] {
        assert!(!names_mutants_skip(text), "{text}");
    }
}

/// Occurrences in `code` of the word `first`, whitespace, then the word `second` (no identifier
/// character before `first` or after `second`): a count simple enough to trust, which each
/// guard's structural scanner must match (Q358).
fn word_pairs(code: &str, first: &str, second: &str) -> usize {
    // Not `is_ident`, which takes `:` for paths: `std::default::Default for` is a pair.
    let word = |c: char| c.is_alphanumeric() || c == '_';
    code.match_indices(first)
        .filter(|&(at, _)| {
            let after = &code[at + first.len()..];
            let rest = after.trim_start();
            !code[..at].ends_with(word)
                && rest.len() < after.len()
                && rest.starts_with(second)
                && !rest[second.len()..].starts_with(word)
        })
        .count()
}

/// Q358, the coverage proof: in `file` the scanner found as many `what` as the simple count
/// says are there. A false alarm is fixed by teaching the scanner the shape, never by an
/// allowlist.
fn assert_scanned(file: &str, what: &str, simple: usize, scanned: usize) {
    assert_eq!(
        simple, scanned,
        "{file}: {simple} {what} by token count, {scanned} by the scanner; teach the scanner"
    );
}

#[test]
#[should_panic(expected = "by token count")]
fn the_count_check_refuses_a_disagreement() {
    assert_scanned("x.rs", "Default impl", 1, 0);
}

#[test]
fn the_simple_counts_skip_identifiers_and_cross_lines() {
    let code = "impl Default\n    for A {}\nimpl MyDefault for B {}\nimpl Default fork\n\
                impl Defaultfor C {}\nfn new() {} fn newer() {} dfn new() {} fn  new() {} \
                fnnew() {}";
    assert_eq!(word_pairs(code, "Default", "for"), 1);
    assert_eq!(word_pairs(code, "fn", "new"), 2);
}

/// Q369: block comments nest, so the tail of an outer one stays blank (its `|` adds no operand,
/// its `{` opens no body) and `/*/` does not close one.
#[test]
fn a_nested_block_comment_is_one_comment() {
    let src = "a /* x /* y */ | { */ b\n/*/ c */ d";
    let out = strip_literals(src);
    assert_eq!(out.chars().count(), src.chars().count());
    assert_eq!(out.lines().count(), 2);
    assert_eq!(out.split_whitespace().collect::<Vec<_>>(), ["a", "b", "d"]);
}

#[test]
#[should_panic(expected = "unterminated block comment")]
fn an_unterminated_block_comment_panics() {
    strip_literals("a /* b /* c */ d");
}

#[test]
fn an_impl_block_opens_outside_brackets_and_an_impl_in_a_type_has_none() {
    fn at(s: &str) -> Option<&str> {
        block_open(s).map(|i| &s[..i])
    }
    let arrow = "impl<F: Fn() -> u8> Default for H<F> { x }";
    assert_eq!(at(arrow), Some("impl<F: Fn() -> u8> Default for H<F> "));
    let header = "impl<T> Default for W<{ N }>\nwhere\n    [(); { N }]: Sized,\n";
    assert_eq!(at(&format!("{header}{{ x }}")), Some(header));
    for none in [
        "impl Default) -> u8 { 1 }",
        "impl Default> { 1 }",
        "impl Iterator<Item = u8>;",
        "impl X } {",
    ] {
        assert_eq!(block_open(none), None, "{none}");
    }
}

/// Panics with "holds …" when `body` holds logic.
fn refuse(body: &str) {
    if let Some(why) = logic_in(&strip_literals(body)) {
        panic!("holds {why}");
    }
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
            "crates/sallyd/src/rpc",
            "crates/sallyd/src/session",
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
