//! Architect Q226: the manifest's own diagnostic and summary text is ASCII. The CLI prints it
//! through its clean-check (`sally-cli` `Printer`), where any escaped character makes the run
//! exit 1; a valid manifest must not fail on sally-core's own punctuation. Text quoted from the
//! manifest is not covered: a non-ASCII value still escapes (#130).
//!
//! Architect Q237: a scan of every product line of the manifest module (with its control) plus
//! the shipped examples meets Q226, with two rules that close the scanner's silent holes: a
//! non-ASCII escape (`\u{..}` above 7f, `\x80` to `\xff`) on a product line is found like the
//! character itself, and a `#[cfg(test)]` followed by anything but an inline `mod <name> {`
//! fails the scan, since the cut at it could hide product code; so does a test module that is
//! not the file's unindented tail. Not found: a non-ASCII character built at run time
//! (`char::from_u32` and the like); none is in the module today.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};

use sally_core::manifest::summary;

/// Every `.rs` file under `dir`.
fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            sources(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// Whether `l` writes a non-ASCII character as an escape: `\u{..}` above 7f, or `\x80`..`\xff`.
fn non_ascii_escape(l: &str) -> bool {
    let unicode = l.match_indices("\\u{").any(|(i, _)| {
        l.get(i + 3..)
            .and_then(|rest| rest.split_once('}'))
            .and_then(|(hex, _)| u32::from_str_radix(&hex.replace('_', ""), 16).ok())
            .is_some_and(|v| v > 0x7f)
    });
    let byte = l.match_indices("\\x").any(|(i, _)| {
        l.get(i + 2..i + 4)
            .and_then(|hex| u8::from_str_radix(hex, 16).ok())
            .is_some_and(|v| v >= 0x80)
    });
    unicode || byte
}

/// Whether `l` (trimmed) opens an inline module: `mod <name> {`.
fn inline_mod(l: &str) -> bool {
    l.strip_prefix("mod ")
        .and_then(|r| r.strip_suffix(" {"))
        .is_some_and(|name| {
            !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        })
}

/// The lines of `text` before its first `#[cfg(test)]` that are not comment lines and hold a
/// non-ASCII character or escape, with their 1-based numbers. `Err(n)`: line `n` holds a
/// `#[cfg(test)]` that is not alone on its line followed by an inline `mod <name> {`, or (the
/// first one) whose module is not the file's tail, so the cut could hide product code.
fn non_ascii_product_lines(text: &str) -> Result<Vec<(usize, &str)>, usize> {
    let lines: Vec<&str> = text.lines().collect();
    for (i, l) in lines.iter().enumerate() {
        if l.contains("#[cfg(test)]") {
            let next = lines.get(i + 1).map_or("", |n| n.trim());
            if l.trim() != "#[cfg(test)]" || !inline_mod(next) {
                return Err(i + 1);
            }
        }
    }
    if let Some(at) = lines.iter().position(|l| l.contains("#[cfg(test)]")) {
        // The cut's module is the file's tail: rustfmt indents its body, so after its opening
        // line the only line at column 0 is its closing brace, the last non-blank line.
        let top: Vec<&str> = lines
            .iter()
            .skip(at + 2)
            .filter(|l| !l.trim().is_empty() && !l.starts_with([' ', '\t']))
            .copied()
            .collect();
        let last = lines.iter().rev().find(|l| !l.trim().is_empty()).copied();
        if lines.get(at) != Some(&"#[cfg(test)]") || top != ["}"] || last != Some("}") {
            return Err(at + 1);
        }
    }
    Ok(text
        .split("#[cfg(test)]")
        .next()
        .unwrap_or_default()
        .lines()
        .enumerate()
        .filter(|(_, l)| {
            !l.trim_start().starts_with("//") && (!l.is_ascii() || non_ascii_escape(l))
        })
        .map(|(i, l)| (i + 1, l))
        .collect())
}

/// Every product line of the manifest module (every literal the validator and the summary can
/// print, whether or not a test reaches it) is ASCII.
#[test]
fn no_manifest_product_line_holds_a_non_ascii_character() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/manifest");
    let mut files = Vec::new();
    sources(&root, &mut files);
    assert!(files.len() > 10, "the manifest module's sources: {files:?}");
    let mut found = Vec::new();
    for f in &files {
        let text = std::fs::read_to_string(f).unwrap();
        match non_ascii_product_lines(&text) {
            Ok(lines) => {
                for (n, line) in lines {
                    found.push(format!("{}:{n}: {line}", f.display()));
                }
            }
            Err(n) => found.push(format!(
                "{}:{n}: a cfg(test) cut not at an inline mod",
                f.display()
            )),
        }
    }
    assert_eq!(found, Vec::<String>::new());
}

/// The scan's control: it finds a non-ASCII product line and a non-ASCII escape (not an ASCII
/// one), and skips a comment and the inline test module.
#[test]
fn the_scan_finds_a_non_ascii_product_line_only() {
    let text = "/// a \u{2014} b\nlet x = \"\u{2026}\";\nlet e = \"\\u{2014}\";\n\
                let b = b\"\\xe2\";\nlet ok = \"\\u{41}\\x41\\u{7f}\\x7f\";\nlet e8 = \"\\u{80}\";\n\
                #[cfg(test)]\nmod tests {\n    let y = \"\u{2013}\";\n}\n";
    assert_eq!(
        non_ascii_product_lines(text),
        Ok(vec![
            (2, "let x = \"\u{2026}\";"),
            (3, "let e = \"\\u{2014}\";"),
            (4, "let b = b\"\\xe2\";"),
            (6, "let e8 = \"\\u{80}\";"),
        ])
    );
}

/// The cut's control (architect Q237): a `#[cfg(test)]` on an item, on an out-of-line module,
/// sharing its line, indented (a test module nested in product code), or whose module is
/// followed by product code fails the scan at its line, so no product code can be hidden.
#[test]
fn a_cfg_test_cut_not_at_an_inline_mod_fails_the_scan() {
    for (text, line) in [
        (
            "let a = 1;\n#[cfg(test)]\nfn helper() {}\nlet b = \"\u{2026}\";\n",
            2,
        ),
        ("#[cfg(test)]\n#[path = \"x_tests.rs\"]\nmod x_tests;\n", 1),
        ("let a = 1;\n#[cfg(test)]\nmod x;\nlet b = 2;\n", 2),
        ("#[cfg(test)] fn h() {}\nmod tests {\n}\n", 1),
        (
            "#[cfg(test)]\nmod tests {\n    fn t() {}\n}\nconst X: &str = \"\u{2014}\";\n",
            1,
        ),
        (
            "mod inner {\n    #[cfg(test)]\n    mod tests {\n    }\n}\n",
            2,
        ),
    ] {
        assert_eq!(non_ascii_product_lines(text), Err(line), "{text}");
    }
    assert_eq!(
        non_ascii_product_lines("#[cfg(test)]\nmod tests {\n}\n"),
        Ok(vec![])
    );
}

/// What the user reads of the shipped examples, warnings included, is ASCII (their manifests
/// quote nothing non-ASCII).
#[test]
fn the_examples_validate_and_summarize_in_ascii() {
    let f = common::Fixture::new();
    let catalog: std::collections::BTreeSet<String> = ["GITHUB_TOKEN", "BRAVE_SEARCH_KEY"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../manifests/examples");
    for name in ["chat-only", "coding-agent", "web-research"] {
        let text = std::fs::read_to_string(dir.join(format!("{name}.yaml"))).unwrap();
        let v = sally_core::manifest::load(&text, &f.env, &catalog).unwrap();
        for w in &v.warnings {
            assert!(w.to_string().is_ascii(), "{name}: {w}");
        }
        let s = summary(&v.manifest);
        assert!(s.is_ascii(), "{name}: {s}");
    }
}
