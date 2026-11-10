//! Fuzz target: arbitrary bytes → audit log line parser (SI-4; CLAUDE.md: every parser of
//! untrusted bytes has one).
//!
//! Invariants: never panics; an accepted line is byte-for-byte the canonical serialization of
//! its entry, carries a hash that matches its contents, and respects the field rules.
#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use sally_core::audit::{MAX_LINE_BYTES, parse_line};

fuzz_target!(|data: &[u8]| {
    if let Ok(entry) = parse_line(data) {
        assert!(data.len() <= MAX_LINE_BYTES, "accepted an over-long line");
        assert_eq!(
            entry.to_line().as_bytes(),
            data,
            "accepted a non-canonical line"
        );
        assert_eq!(
            entry.compute_hash(),
            entry.hash,
            "accepted a line with a wrong hash"
        );
        assert!(entry.seq >= 1);
    }
});
