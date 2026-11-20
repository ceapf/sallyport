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
    let (answer, shown, flushes, _) = ask_flushing(typed, true);
    (answer, shown, flushes)
}

/// [`ask`] on a terminal whose typed-ahead input can be discarded (`flush_ok`) or not; also how
/// many bytes of `typed` were read.
fn ask_flushing(typed: &[u8], flush_ok: bool) -> (bool, String, usize, u64) {
    let mut input = Cursor::new(typed.to_vec());
    let mut output = Vec::new();
    let flushes = Cell::new(0);
    let mut flush = || {
        flushes.set(flushes.get() + 1);
        if flush_ok {
            Ok(())
        } else {
            Err(std::io::Error::other("tcflush failed"))
        }
    };
    let answer = {
        let mut t = Tty {
            input: &mut input,
            output: &mut output,
            flush: &mut flush,
        };
        asked_yes(&mut t)
    };
    let read = input.position();
    (
        answer,
        String::from_utf8(output).unwrap(),
        flushes.get(),
        read,
    )
}

#[test]
fn a_terminal_that_cannot_discard_typed_ahead_input_is_not_read() {
    let (answer, shown, _, read) = ask_flushing(b"yes\n", false);
    assert!(!answer);
    assert_eq!(shown, QUESTION);
    assert_eq!(read, 0, "nothing typed ahead is read");
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
        // Typed-ahead input is discarded before the read, and what is left after any answer
        // but `yes`.
        assert_eq!(flushes, if want { 1 } else { 2 }, "{typed:?}");
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

/// A line that fails the clean-check withholds the block and is named, escaped: the first one.
#[test]
fn a_line_that_cannot_be_shown_withholds_the_block_and_is_named() {
    let mut v = validated(RISKY);
    assert!(block(&v).is_ok());
    v.warnings[0].message.push_str("caf\u{e9}\u{1b}[2J");
    let dirty = block(&v).unwrap_err();
    assert!(
        dirty.contains("caf") && dirty.contains(&v.warnings[0].path),
        "{dirty}"
    );
    assert!(
        dirty.chars().all(|c| c.is_ascii_graphic() || c == ' '),
        "{dirty:?}"
    );
}

#[test]
fn the_consent_rule() {
    use Verdict::{Ask, ByHash, Mismatch, NeedsFlag, Send};
    for (needs, on_terminal, matches, want) in [
        (false, false, None, Send),
        (false, true, None, Send),
        (false, false, Some(true), Send),
        (false, true, Some(true), Send),
        (false, false, Some(false), Mismatch),
        (false, true, Some(false), Mismatch),
        (true, true, None, Ask),
        (true, true, Some(true), Ask),
        (true, true, Some(false), Mismatch),
        (true, false, Some(true), ByHash),
        (true, false, Some(false), Mismatch),
        (true, false, None, NeedsFlag),
    ] {
        assert_eq!(
            decide(needs, on_terminal, matches),
            want,
            "{needs} {on_terminal} {matches:?}"
        );
    }
}

/// A manifest file of its own for `test`, holding `body` after the header: (its path, its text).
/// The folder is removed when the guard drops, a failing test included.
fn manifest_file(test: &str, body: &str) -> (std::path::PathBuf, String, Gone) {
    let dir = std::env::temp_dir().join(format!("sally-consent-{}-{test}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("m.yaml");
    let text = format!("{HEAD}{body}");
    std::fs::write(&path, &text).unwrap();
    (path, text, Gone(dir))
}

/// A folder removed on drop.
struct Gone(std::path::PathBuf);

impl Drop for Gone {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// [`launch_text`] off a terminal: the result and what `err` holds.
fn launch_off(path: &Path, accept: Option<&str>) -> (Result<String, u8>, String) {
    let store = path.with_file_name("no-store");
    let mut err = Vec::new();
    let g = Gate {
        store: &store,
        accept,
        terminal: None,
    };
    let r = launch_text(path, g, &mut err);
    (r, String::from_utf8(err).unwrap())
}

#[test]
fn off_a_terminal_a_given_hash_must_name_the_text_read() {
    let (risky, risky_text, _risky) = manifest_file("off-risky", RISKY);
    let (quiet, quiet_text, _quiet) = manifest_file("off-quiet", "");
    let right = digest(&risky_text).as_hex().to_owned();
    let wrong = digest(&quiet_text).as_hex().to_owned();

    assert_eq!(launch_off(&risky, Some(&right)).0, Ok(risky_text.clone()));
    let (r, err) = launch_off(&risky, Some(&wrong));
    assert_eq!(r, Err(EXIT_REFUSED));
    assert!(
        err.contains("not the text --accept-manifest names"),
        "{err}"
    );
    let (r, err) = launch_off(&risky, None);
    assert_eq!(r, Err(EXIT_REFUSED));
    assert!(err.contains("pass --accept-manifest"), "{err}");
    // The block is on stderr whatever the outcome; the hash of the text read never is.
    assert!(err.contains("acknowledged: "), "{err}");
    assert!(!err.contains(&right), "{err}");

    // A manifest that needs no consent is sent without the flag, and refused with a wrong one.
    assert_eq!(launch_off(&quiet, None).0, Ok(quiet_text.clone()));
    assert_eq!(launch_off(&quiet, Some(&right)).0, Err(EXIT_REFUSED));

    // A malformed value fails before anything is read, and is never echoed.
    let upper = right.to_ascii_uppercase();
    let (r, err) = launch_off(&risky, Some(&upper));
    assert_eq!(r, Err(EXIT_FAILED));
    assert!(
        !err.contains(&upper) && !err.contains("acknowledged"),
        "{err}"
    );
    // A manifest that cannot be read fails.
    let gone = risky.with_file_name("gone.yaml");
    assert_eq!(launch_off(&gone, None).0, Err(EXIT_FAILED));
}

/// [`launch_text`] on a terminal whose input is `typed`: the result, what the terminal shows,
/// and how many times typed-ahead input was discarded.
fn launch_on(
    path: &Path,
    accept: Option<&str>,
    typed: &[u8],
) -> (Result<String, u8>, String, usize) {
    let store = path.with_file_name("no-store");
    let mut input = Cursor::new(typed.to_vec());
    let mut output = Vec::new();
    let flushes = Cell::new(0);
    let mut flush = || {
        flushes.set(flushes.get() + 1);
        Ok(())
    };
    let mut err = Vec::new();
    let r = {
        let mut t = Tty {
            input: &mut input,
            output: &mut output,
            flush: &mut flush,
        };
        let g = Gate {
            store: &store,
            accept,
            terminal: Some(&mut t),
        };
        launch_text(path, g, &mut err)
    };
    (r, String::from_utf8(output).unwrap(), flushes.get())
}

#[test]
fn on_a_terminal_only_a_manifest_that_needs_consent_is_asked() {
    let (risky, risky_text, _risky) = manifest_file("on-risky", RISKY);
    let (quiet, quiet_text, _quiet) = manifest_file("on-quiet", "");
    let right = digest(&risky_text).as_hex().to_owned();

    let (r, shown, flushes) = launch_on(&quiet, None, b"no\n");
    assert_eq!(r, Ok(quiet_text));
    assert_eq!((shown.as_str(), flushes), ("", 0), "nothing asked");

    let (r, shown, _) = launch_on(&risky, None, b"yes\n");
    assert_eq!(r, Ok(risky_text.clone()));
    assert!(
        shown.contains("acknowledged: ") && shown.ends_with(QUESTION),
        "{shown}"
    );
    // The right hash does not replace the question.
    assert_eq!(
        launch_on(&risky, Some(&right), b"no\n").0,
        Err(EXIT_REFUSED)
    );
    assert_eq!(launch_on(&risky, Some(&right), b"yes\n").0, Ok(risky_text));
}

#[test]
fn the_digest_is_the_sha256_of_the_text() {
    assert_eq!(
        digest("").as_hex(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_ne!(digest("a"), digest("a\n"));
}
