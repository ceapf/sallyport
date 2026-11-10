//! RT-MAN-01 fuzz target: arbitrary bytes → manifest parser.
//!
//! Invariants: never panics; anything accepted serializes and re-parses to an identical struct.
#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use sally_core::manifest::{parse, parse_bytes, to_yaml};

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = parse_bytes(data) {
        let yaml = to_yaml(&m).expect("serializing an accepted manifest must not fail");
        let again = parse(&yaml).expect("canonical YAML must re-parse");
        assert_eq!(m, again, "round-trip changed the manifest");
    }
});
