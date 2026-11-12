//! Fuzz target: arbitrary bytes → `llm.sock`'s request-head parser and chat-body checker
//! (Task 7 decision 6; CLAUDE.md: every parser of untrusted bytes has one).
//!
//! Invariants: never panics; a complete head lies within the first 8 KiB; an accepted body is
//! within 4 MiB, has 1 to 1024 messages, a token limit within the context, and no `model`
//! member; every top-level member forwarded is on the allowlist.
#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use sallyd::llm::body::{self, MAX_BODY, MAX_MESSAGES};
use sallyd::llm::head::{self, MAX_HEAD, Parsed};

const CONTEXT: u64 = 8192;
const TOP: [&str; 16] = [
    "messages",
    "tools",
    "tool_choice",
    "parallel_tool_calls",
    "temperature",
    "top_p",
    "max_tokens",
    "max_completion_tokens",
    "stop",
    "seed",
    "stream",
    "stream_options",
    "response_format",
    "presence_penalty",
    "frequency_penalty",
    "n",
];

fuzz_target!(|data: &[u8]| {
    if let Parsed::Complete(h) = head::parse(data) {
        assert!(h.len <= MAX_HEAD && h.len <= data.len(), "head length out of range");
    }
    if let Ok(c) = body::check(data, CONTEXT) {
        assert!(data.len() <= MAX_BODY, "oversize body accepted");
        assert!((1..=MAX_MESSAGES).contains(&c.messages), "message count out of range");
        assert!((1..=CONTEXT).contains(&c.max_tokens), "token limit out of range");
        assert!(!c.body.contains_key("model"), "model forwarded");
        assert!(c.body.keys().all(|k| TOP.contains(&k.as_str())), "member off the allowlist");
    }
});
