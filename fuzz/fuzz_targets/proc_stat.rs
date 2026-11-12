//! Fuzz target: arbitrary bytes → the `/proc/<pid>/stat` parser the shell runner uses to find
//! and kill a call's processes (architect ruling Q32: the command name is chosen by the
//! container; CLAUDE.md: every parser of untrusted bytes has one).
//!
//! Invariants: never panics; input over the bound is refused; a parsed pid is the leading
//! decimal field, and a command name holding `)` or spaces cannot move the fields read after
//! the last `)`.
#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use sallyd::tools::procs::{MAX_STAT, parse_stat};

fuzz_target!(|data: &[u8]| {
    let Some(s) = parse_stat(data) else {
        return;
    };
    assert!(data.len() <= MAX_STAT, "over the bound");
    assert!(s.pid >= 0 && s.ppid >= 0 && s.session >= 0, "negative pid");
    let lead = data.split(|&b| b == b'(').next().unwrap_or_default();
    assert_eq!(
        std::str::from_utf8(lead.trim_ascii()).ok().and_then(|t| t.parse::<i32>().ok()),
        Some(s.pid),
        "pid not the leading field"
    );
    // The same fields behind any other command name parse the same.
    let close = data.iter().rposition(|&b| b == b')').expect("a parsed line has ')'");
    let mut other = format!("{} (a) b (c)", s.pid).into_bytes();
    other.extend_from_slice(data.get(close + 1..).unwrap_or_default());
    if other.len() <= MAX_STAT {
        assert_eq!(parse_stat(&other), Some(s), "the name moved the fields");
    }
});
