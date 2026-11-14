//! Fuzz target: arbitrary bytes from "sallyd" → the CLI's frame reader under a small cap, then
//! its one split of a frame into a reply or a notification, then the wire types it reads from
//! them (architect Q96; Q79 treats the daemon's replies as hostile input to the CLI; CLAUDE.md:
//! every parser of untrusted bytes has one).
//!
//! Invariants: never panics; a frame longer than the cap is `TooLarge`, and a frame within it is
//! returned whole, at most the cap, with no newline (checked against a plain split of the
//! input); a stream that ends inside a frame is `Closed`; a frame with an `id` decodes as a
//! reply, one without an `id` but with a `method` as a notification, anything else is refused.
#![no_main]
#![forbid(unsafe_code)]

use std::io::BufReader;

use libfuzzer_sys::fuzz_target;
use sally_cli::client::{Decoded, Error, decode, read_frame};
use sally_proto::{Closed, ErrorData, Flood, Prompt, Prompts};
use serde_json::Value;

/// Small, so the fuzzer reaches the cap often.
const CAP: usize = 256;

fuzz_target!(|data: &[u8]| {
    // A small buffer, so frames span several reads.
    let mut r = BufReader::with_capacity(7, data);
    let mut rest = data;
    loop {
        let got = read_frame(&mut r, CAP);
        let (frame, after, ended) = match rest.iter().position(|&b| b == b'\n') {
            Some(n) => (rest.get(..n).unwrap_or_default(), rest.get(n + 1..), false),
            None => (rest, None, true),
        };
        if frame.len() > CAP {
            assert!(matches!(got, Err(Error::TooLarge)), "an over-cap frame: {got:?}");
            return;
        }
        if ended {
            match got {
                Ok(None) => assert!(frame.is_empty(), "the end inside a frame"),
                Err(Error::Closed) => assert!(!frame.is_empty(), "a cut frame at the end"),
                other => panic!("at the end of the input: {other:?}"),
            }
            return;
        }
        let bytes = got.expect("a frame within the cap").expect("not the end");
        assert_eq!(bytes, frame, "the frame differs from the input's line");
        assert!(bytes.len() <= CAP && !bytes.contains(&b'\n'));
        check(&bytes);
        rest = after.unwrap_or_default();
    }
});

fn check(bytes: &[u8]) {
    let Ok(v) = serde_json::from_slice::<Value>(bytes) else {
        return;
    };
    let had_id = v.get("id").is_some();
    let had_method = v.get("method").is_some();
    match decode(v) {
        Ok(Decoded::Reply { result, .. }) => {
            assert!(had_id, "a reply without an id");
            match result {
                Ok(r) => {
                    let _ = serde_json::from_value::<Prompts>(r.clone());
                    let _ = serde_json::from_value::<Prompt>(r);
                }
                Err(Error::Refused(ErrorData { reason, .. })) => {
                    let _ = reason.len();
                }
                Err(_) => {}
            }
        }
        Ok(Decoded::Note(n)) => {
            assert!(!had_id && had_method, "a note with an id or without a method");
            let params = n.get("params").cloned().unwrap_or(Value::Null);
            let _ = serde_json::from_value::<Prompt>(params.clone());
            let _ = serde_json::from_value::<Closed>(params.clone());
            let _ = serde_json::from_value::<Flood>(params);
        }
        Err(e) => {
            assert!(!had_id && !had_method, "a valid frame refused: {e}");
        }
    }
}
