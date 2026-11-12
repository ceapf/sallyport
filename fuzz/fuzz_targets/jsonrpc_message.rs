//! Fuzz target: arbitrary bytes → the session socket's JSON-RPC message parser, then the MCP
//! lifecycle classifier for both connection states (Task 7 decision 6; CLAUDE.md: every parser of
//! untrusted bytes has one).
//!
//! Invariants: never panics; an accepted message has a method of at most 64 bytes and an id of at
//! most 128; nothing nested deeper than 64 is accepted; a classified request's method is on the
//! session allowlist; an unsupported version kept for the reply is at most 64 bytes.
#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use sallyd::rpc::mcp::{self, MAX_VERSION_BYTES, Refusal, SESSION_METHODS};
use sallyd::rpc::message::{self, Id, MAX_DEPTH, MAX_ID_BYTES, MAX_METHOD_BYTES, Message};

fuzz_target!(|data: &[u8]| {
    let Ok(m) = message::parse(data) else {
        return;
    };
    assert!(!message::too_deep(data, MAX_DEPTH), "too-deep input accepted");
    let (method, params) = match m {
        Message::Request { id, method, params } => {
            if let Id::Str(s) = &id {
                assert!(s.len() <= MAX_ID_BYTES, "long id accepted");
            }
            (method, params)
        }
        Message::Notification { method, params } => {
            for legacy in [false, true] {
                let _ = mcp::classify_note(&method, &params, legacy);
            }
            (method, params)
        }
        Message::Response => return,
    };
    assert!(method.len() <= MAX_METHOD_BYTES, "long method accepted");
    for legacy in [false, true] {
        match mcp::classify(&method, &params, legacy) {
            Ok(_) => assert!(SESSION_METHODS.contains(&method.as_str()), "method off the allowlist"),
            Err(Refusal::UnsupportedVersion(v)) => assert!(v.len() <= MAX_VERSION_BYTES),
            Err(r) => {
                let _ = r.error();
            }
        }
    }
});
