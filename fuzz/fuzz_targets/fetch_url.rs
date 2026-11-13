//! Fuzz target: arbitrary text → the `fetch` tool's URL parser (#75; architect ruling Q4;
//! CLAUDE.md: every parser of untrusted bytes has one).
//!
//! Invariants: never panics; an accepted URL is within the length bound, its host is a
//! lower-case hostname without a trailing dot, its port is not 0, its target starts with `/`
//! and holds only RFC 3986 path and query bytes; and its canonical form is a fixed point: it
//! parses to the same URL, and so to the same canonical form.
#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use sallyd::tools::fetch_url::{MAX_URL, parse};

fuzz_target!(|data: &[u8]| {
    let Ok(url) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(u) = parse(url) else {
        return;
    };
    assert!(url.len() <= MAX_URL, "over the bound");
    assert!(!u.host.is_empty() && !u.host.ends_with('.'), "host not normal");
    assert_eq!(u.host, u.host.to_ascii_lowercase(), "host not lower-case");
    assert_ne!(u.port, 0, "port 0");
    assert!(u.target.starts_with('/'), "target not origin-form");
    assert!(
        u.target
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@/?%".contains(&b)),
        "target byte outside RFC 3986: {:?}",
        u.target
    );
    let c = u.canonical();
    let again = parse(&c).expect("the canonical form parses");
    assert_eq!(again, u, "canonical form names another URL");
    assert_eq!(again.canonical(), c, "canonical form not a fixed point");
});
