//! Architect Q226: the manifest's own diagnostic and summary text is ASCII. The CLI prints it
//! through its clean-check (`sally-cli` `Printer`), where any escaped character makes the run
//! exit 1; a valid manifest must not fail on sally-core's own punctuation. Text quoted from the
//! manifest is not covered: a non-ASCII value still escapes (#130).
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

/// The lines of `text` before its first `#[cfg(test)]` that are not comment lines and hold a
/// non-ASCII character, with their 1-based numbers.
fn non_ascii_product_lines(text: &str) -> Vec<(usize, &str)> {
    text.split("#[cfg(test)]")
        .next()
        .unwrap_or_default()
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.trim_start().starts_with("//") && !l.is_ascii())
        .map(|(i, l)| (i + 1, l))
        .collect()
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
        for (n, line) in non_ascii_product_lines(&text) {
            found.push(format!("{}:{n}: {line}", f.display()));
        }
    }
    assert_eq!(found, Vec::<String>::new());
}

/// The scan's control: it finds a non-ASCII product line, and skips one in a comment and one
/// after `#[cfg(test)]`.
#[test]
fn the_scan_finds_a_non_ascii_product_line_only() {
    let text = "/// a \u{2014} b\nlet x = \"\u{2026}\";\n#[cfg(test)]\nlet y = \"\u{2013}\";\n";
    assert_eq!(
        non_ascii_product_lines(text),
        [(2, "let x = \"\u{2026}\";")]
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
