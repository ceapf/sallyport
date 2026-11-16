//! Fuzz target: arbitrary bytes → the egress proxy's request-head parser, then the CONNECT
//! authority parser and the audit text (SI-9; CLAUDE.md: every parser of untrusted bytes has
//! one).
//!
//! Invariants: never panics; a complete head lies within the first 8 KiB and its target is a
//! slice of the input; an accepted authority is canonical (it round-trips through `host:port`)
//! and never an IP literal; the audit text of a target is bounded and printable ASCII, both for
//! a session without secret grants (`None`: cut as the raw text is) and for one with a fixed
//! secret (`Some`: the secret's value never appears, and a cut text holds the full 256 bytes;
//! architect Q264).
#![no_main]
#![forbid(unsafe_code)]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use sally_core::audit::Redactor;
use sallyd::egress::authority::{self, LOGGED_TARGET_BYTES, audit_text};
use sallyd::egress::head::{self, MAX_HEAD, Parsed};

/// The fixed secret and its redactor. The value is 14 lower-case letters assembled at run time,
/// none of them a letter of the placeholder `[REDACTED:C]`, so masking can never rebuild it; a
/// seed in the corpus carries it as a CONNECT host label.
fn secret() -> &'static (String, Redactor) {
    static SECRET: OnceLock<(String, Redactor)> = OnceLock::new();
    SECRET.get_or_init(|| {
        let value: String = (b'j'..=b'q').chain(b'u'..=b'z').map(char::from).collect();
        let redactor = Redactor::new([("C", value.as_str())]);
        (value, redactor)
    })
}

/// Bounded and printable ASCII, whatever the target held.
fn check_printable(text: &str) {
    assert!(text.len() <= 4 * LOGGED_TARGET_BYTES, "audit text unbounded");
    assert!(text.bytes().all(|b| (0x20..0x7f).contains(&b)), "audit text not printable");
}

fuzz_target!(|data: &[u8]| {
    if let Parsed::Complete(h) = head::parse(data) {
        assert!(h.len <= MAX_HEAD && h.len <= data.len(), "head length out of range");
        let (text, len, cut) = audit_text(h.target, None);
        check_printable(&text);
        assert_eq!((len, cut), (h.target.len(), h.target.len() > LOGGED_TARGET_BYTES));
        let (value, redactor) = secret();
        let (text, len, cut) = audit_text(h.target, Some(redactor));
        check_printable(&text);
        assert_eq!(len, h.target.len(), "raw length not reported");
        assert!(!text.contains(value.as_str()), "secret value in the audit text");
        assert!(!cut || text.len() >= LOGGED_TARGET_BYTES, "cut text shorter than the cut");
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(a) = authority::parse(text) {
        assert_ne!(a.port, 0, "port 0 accepted");
        assert!(a.host.parse::<std::net::IpAddr>().is_err(), "IP literal accepted");
        // inet_aton spellings (decimal, octal, hex, 1-4 parts) end in a numeric label. A bare
        // `0x` is not one: glibc and musl both need a digit after it.
        let last = a.host.rsplit('.').next().unwrap_or_default();
        let hex = last
            .strip_prefix("0x")
            .is_some_and(|h| !h.is_empty() && h.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(!last.bytes().all(|b| b.is_ascii_digit()) && !hex, "numeric last label accepted");
        let again = authority::parse(&format!("{}:{}", a.host, a.port));
        assert_eq!(again.as_ref(), Ok(&a), "authority is not canonical");
    }
});
