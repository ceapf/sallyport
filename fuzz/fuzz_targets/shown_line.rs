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
#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use sally_core::text::{escape, escape_backslash_quoted, is_refused, quoted_path, refused_escape};

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
});
