//! Fuzz target: arbitrary bytes → the egress proxy's request-head parser, then the CONNECT
//! authority parser and the audit escaping (SI-9; CLAUDE.md: every parser of untrusted bytes has
//! one).
//!
//! Invariants: never panics; a complete head lies within the first 8 KiB and its target is a
//! slice of the input; an accepted authority is canonical (it round-trips through `host:port`)
//! and never an IP literal; the audit text of a target is bounded and printable ASCII.
#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use sallyd::egress::authority::{self, LOGGED_TARGET_BYTES, escape_target};
use sallyd::egress::head::{self, MAX_HEAD, Parsed};

fuzz_target!(|data: &[u8]| {
    if let Parsed::Complete(h) = head::parse(data) {
        assert!(h.len <= MAX_HEAD && h.len <= data.len(), "head length out of range");
        let (text, len, cut) = escape_target(h.target.as_bytes());
        assert!(text.len() <= 4 * LOGGED_TARGET_BYTES, "audit text unbounded");
        assert!(text.bytes().all(|b| (0x20..0x7f).contains(&b)), "audit text not printable");
        assert_eq!((len, cut), (h.target.len(), h.target.len() > LOGGED_TARGET_BYTES));
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(a) = authority::parse(text) {
        assert_ne!(a.port, 0, "port 0 accepted");
        assert!(a.host.parse::<std::net::IpAddr>().is_err(), "IP literal accepted");
        let again = authority::parse(&format!("{}:{}", a.host, a.port));
        assert_eq!(again.as_ref(), Ok(&a), "authority is not canonical");
    }
});
