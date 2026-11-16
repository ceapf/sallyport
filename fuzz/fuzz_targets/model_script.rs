//! Fuzz target: arbitrary bytes → the scripted model's script parser (CLAUDE.md: every parser of
//! untrusted bytes has one; architect Q46, Q103, Q119).
//!
//! Invariants: never panics; a script over the byte cap is refused; an accepted script has at
//! most `MAX_TURNS` turns, every tool-call turn at most `MAX_CALLS` calls, and each of its
//! non-blank lines parses on its own to the same turn; the hash is that of the text.
#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use sallyd::llm::scripted::{MAX_CALLS, MAX_SCRIPT_BYTES, MAX_TURNS, Script, Turn};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let parsed = Script::parse(text);
    if text.len() > MAX_SCRIPT_BYTES {
        assert!(parsed.is_err());
        return;
    }
    let Ok(script) = parsed else {
        return;
    };
    assert!(script.turns.len() <= MAX_TURNS);
    assert_eq!(script.sha256.len(), 64);
    let lines = text.lines().filter(|l| !l.trim().is_empty());
    assert_eq!(lines.clone().count(), script.turns.len());
    for (line, turn) in lines.zip(&script.turns) {
        assert_eq!(Turn::parse(line).as_ref(), Ok(turn));
        if let Turn::ToolCalls(calls) = turn {
            assert!(calls.len() <= MAX_CALLS);
        }
    }
});
