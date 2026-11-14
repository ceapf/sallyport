//! Fuzz target: arbitrary bytes → the session socket's JSON-RPC message parser, then the MCP
//! lifecycle classifier for both connection states (Task 7 decision 6; CLAUDE.md: every parser of
//! untrusted bytes has one).
//!
//! Invariants: never panics; an accepted message has a method of at most 64 bytes and an id of at
//! most 128; nothing nested deeper than 64 is accepted; a classified request's method is on the
//! session allowlist; an unsupported version kept for the reply is at most 64 bytes.
//!
//! Every accepted request's params also go to the control socket's strict parser (architect
//! Q96), once under each control method and once under the fuzzed method: an accepted call
//! names the method it was parsed under; a method off the control table is not found; an
//! accepted stop or listing keeps the id it was given (only a canonical id is accepted).
#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use sallyd::rpc::control_methods::{Call, NotAdmitted};
use sallyd::rpc::mcp::{self, CONTROL_METHODS, MAX_VERSION_BYTES, Refusal, SESSION_METHODS};
use sallyd::rpc::message::{self, Id, MAX_DEPTH, MAX_ID_BYTES, MAX_METHOD_BYTES, Message};
use serde_json::{Map, Value};

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
            for m in CONTROL_METHODS.iter().copied().chain([method.as_str()]) {
                control_call(m, &params);
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

/// `params` under control method `m`, checked against the invariants above.
fn control_call(m: &str, params: &Map<String, Value>) {
    match Call::parse(m, params.clone()) {
        Ok(call) => {
            assert_eq!(call.method(), m, "a call names another method");
            if let Call::Stop(id) | Call::Changes(id) = &call {
                let given = params.get("id").and_then(Value::as_str);
                assert_eq!(given, Some(id.as_str()), "a session id changed in parsing");
            }
        }
        Err(NotAdmitted::MethodNotFound) => {
            assert!(!CONTROL_METHODS.contains(&m), "a control method not found");
        }
        Err(NotAdmitted::InvalidParams) => {
            assert!(CONTROL_METHODS.contains(&m), "params checked for an unknown method");
        }
    }
}
