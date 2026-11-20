#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::cell::Cell;
use std::io::Cursor;

use sally_core::manifest::{HostEnv, load};

use super::*;

const HEAD: &str = "apiVersion: sallyport/v1\nkind: Manifest\nname: t\nmodel:\n  ref: any\n";

const RISKY: &str = "tools:\n  builtin: [shell]\n  shell: allow\n  \
                     destructive_requires_approval: false\n  acknowledge_unapproved: [shell]\n";

fn validated(body: &str) -> Validated {
    let env = HostEnv {
        home: std::env::temp_dir(),
        other_homes: Vec::new(),
        xdg_config_home: None,
        xdg_data_home: None,
        xdg_runtime_dir: None,
        podman_storage: Vec::new(),
        env_dirs: Vec::new(),
        nproc: 8,
        mem_bytes: 16 << 30,
    };
    let names = std::collections::BTreeSet::<String>::new();
    load(&format!("{HEAD}{body}"), &env, &names).unwrap()
}

/// Asks on a terminal whose input is `typed`: (the answer, what was shown, how many times
/// typed-ahead input was discarded).
fn ask(typed: &[u8]) -> (bool, String, usize) {
    let mut input = Cursor::new(typed.to_vec());
    let mut output = Vec::new();
    let flushes = Cell::new(0);
    let mut flush = || flushes.set(flushes.get() + 1);
    let answer = {
        let mut t = Tty {
            input: &mut input,
            output: &mut output,
            flush: &mut flush,
        };
        asked_yes(&mut t)
    };
    (answer, String::from_utf8(output).unwrap(), flushes.get())
}

#[test]
fn only_yes_typed_after_the_question_starts() {
    for (typed, want) in [
        (&b"yes\n"[..], true),
        (b"  yes \n", true),
        (b"Yes\n", false),
        (b"y\n", false),
        (b"yes please\n", false),
        (b"no\n", false),
        (b"\n", false),
        (b"", false),
        // The end of input before a newline is not an answer.
        (b"yes", false),
        (b"\xffyes\n", false),
    ] {
        let (answer, shown, flushes) = ask(typed);
        assert_eq!(answer, want, "{typed:?}");
        assert_eq!(shown, QUESTION);
        assert_eq!(
            flushes, 1,
            "typed-ahead input is discarded once, before the read"
        );
    }
}

#[test]
fn an_answer_longer_than_the_bound_refuses() {
    let at = usize::try_from(MAX_ANSWER).unwrap();
    // `yes` padded with spaces to exactly the bound, then its newline: read whole.
    let fits = format!("yes{}\n", " ".repeat(at - 3));
    assert!(ask(fits.as_bytes()).0);
    let over = format!("yes{}\n", " ".repeat(at - 2));
    assert!(!ask(over.as_bytes()).0);
}

#[test]
fn consent_is_needed_for_a_warning_or_an_acknowledged_risk_only() {
    assert!(needs_consent(&validated(RISKY)));
    assert!(!needs_consent(&validated("")));
    let mut warned = validated("");
    warned.warnings = validated(RISKY).warnings;
    assert!(needs_consent(&warned));
}

#[test]
fn the_block_is_the_summary_then_the_warnings_then_the_acknowledged_risks() {
    let v = validated(RISKY);
    let lines = block(&v).unwrap();
    let summary_lines: Vec<String> = summary(&v.manifest)
        .lines()
        .map(ToOwned::to_owned)
        .collect();
    let rest = besides_summary(&v);
    assert_eq!(lines, [summary_lines, rest.clone()].concat());
    assert_eq!(rest.len(), 2, "{rest:?}");
    assert_eq!(rest[0], v.warnings[0].to_string());
    assert_eq!(rest[1], "acknowledged: tools.acknowledge_unapproved: shell");
    assert!(besides_summary(&validated("")).is_empty());
}

#[test]
fn the_digest_is_the_sha256_of_the_text() {
    assert_eq!(
        digest("").as_hex(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_ne!(digest("a"), digest("a\n"));
}
