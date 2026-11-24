//! Fuzz target: arbitrary bytes → the reader of a line a launch shows
//! (`sally_core::text::refused_escape`, RT-MAN-05). The lines it reads hold manifest and host
//! text, escaped; CLAUDE.md: every reader of untrusted text has a fuzz target.
//!
//! Input: the bytes, read two ways: as a line (when it is UTF-8), and as raw text the escapers
//! write out.
//!
//! Invariants: never panics; what it names is a part of the line that starts with `\`; for any
//! bytes, the reader refuses the escaped forms (`escape`, `escape_backslash_quoted`,
//! `quoted_path`) exactly when the bytes held a refused character or a byte that is not UTF-8.
//! The rows an approval prompt breaks escaped text into (`escaped_rows`, RT-AG-04), with and
//! without run marks (`escape_runs_backslash_quoted`): put together they are the text, none is
//! empty, none parts a unit from its mark, and at a width of at least `LONGEST_UNIT` none is
//! wider. The capped form (`escape_runs_capped`) is a prefix of the whole within its bound.
#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use sally_core::text::{
    LONGEST_UNIT, escape, escape_backslash_quoted, escape_runs_backslash_quoted,
    escape_runs_capped, escaped_rows, is_refused, quoted_path, refused_escape,
};

fuzz_target!(|data: &[u8]| {
    if let Ok(line) = std::str::from_utf8(data) {
        if let Some(named) = refused_escape(line) {
            assert!(named.starts_with('\\'), "named {named:?}");
            assert!(line.contains(named), "named {named:?} is not in the line");
        }
    }
    let refused = data
        .utf8_chunks()
        .any(|c| !c.invalid().is_empty() || c.valid().chars().any(is_refused));
    for shown in [
        escape(data),
        escape_backslash_quoted(data),
        quoted_path(data),
    ] {
        assert_eq!(refused_escape(&shown).is_some(), refused, "{shown:?}");
    }
    let first = usize::from(data.first().copied().unwrap_or(0));
    for shown in [
        escape_backslash_quoted(data),
        escape_runs_backslash_quoted(data),
    ] {
        for width in [1 + first % 8, LONGEST_UNIT + first] {
            let rows = escaped_rows(&shown, width);
            assert_eq!(rows.concat(), shown, "width {width}");
            assert!(rows.iter().all(|r| !r.is_empty()), "an empty row: {rows:?}");
            if width >= LONGEST_UNIT {
                assert!(rows.iter().all(|r| r.len() <= width), "{width}: {rows:?}");
            }
            // No row parts a unit from its mark: the escaper writes a `\` as `\\`, so a row
            // starting with `\{` would be a mark cut off from its unit.
            assert!(!rows.iter().any(|r| r.starts_with("\\{")), "{rows:?}");
        }
    }
    // The capped form is a prefix of the whole, ends on a unit, and shows at most the input.
    let whole = escape_runs_backslash_quoted(data);
    let (capped, shown) = escape_runs_capped(data, first);
    assert!(capped.len() <= first && whole.starts_with(&capped), "{capped:?}");
    assert!(shown <= data.len());
    assert_eq!(escaped_rows(&whole, LONGEST_UNIT).concat(), whole);
});
