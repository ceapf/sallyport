//! Fuzz target: arbitrary bytes → model detect and the strict GGUF header parser (SI-6;
//! CLAUDE.md: every parser of untrusted bytes has one).
//!
//! Invariants:
//! - never panics, on any input, for detect's name step, its magic step, or the parser;
//! - an accepted header is within every limit: at most MAX_TENSORS tensors and MAX_KV entries,
//!   every tensor's data and the data end inside the file, at most MAX_RETAINED_TEXT_BYTES of
//!   kept file text;
//! - a refusal's message is printable ASCII and at most MAX_MESSAGE bytes;
//! - a reader that yields one byte per read gives the same result as the whole slice.
#![no_main]
#![forbid(unsafe_code)]

use std::ffi::OsStr;
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;

use libfuzzer_sys::fuzz_target;
use sally_core::model::detect;
use sally_core::model::gguf::{self, MAX_KV, MAX_RETAINED_TEXT_BYTES, MAX_TENSORS};

/// Longest refusal message: the fixed text plus one quoted key or name, escaped and capped.
const MAX_MESSAGE: usize = 256;

struct OneByte<'a>(&'a [u8]);

impl Read for OneByte<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match (self.0.split_first(), buf.first_mut()) {
            (Some((byte, rest)), Some(slot)) => {
                *slot = *byte;
                self.0 = rest;
                Ok(1)
            }
            _ => Ok(0),
        }
    }
}

/// The result as text: Debug (floats print the same even when NaN) plus every kept key, string
/// and name, which Debug shows only as lengths.
fn summary(result: &Result<gguf::GgufHeader, gguf::GgufError>) -> String {
    let mut out = format!("{result:?}");
    if let Ok(header) = result {
        for m in header.metadata() {
            out.push_str(m.key().as_str());
            if let gguf::Value::String(s) = m.value() {
                out.push_str(s.as_str());
            }
        }
        for t in header.tensors() {
            out.push_str(t.name().as_str());
        }
    }
    out
}

fuzz_target!(|data: &[u8]| {
    // The name step reads no bytes and must take any name.
    let _ = detect::by_name(OsStr::from_bytes(data));
    if let Ok(candidate) = detect::by_name(OsStr::new("model.gguf")) {
        let _ = candidate.check_magic(data);
    }

    let file_len = data.len() as u64;
    let result = gguf::parse(data, file_len);
    let chunked = gguf::parse(OneByte(data), file_len);
    assert_eq!(summary(&result), summary(&chunked), "chunking changed the result");
    match result {
        Ok(header) => {
            assert!(header.tensors().len() as u64 <= MAX_TENSORS);
            assert!(header.metadata().len() as u64 <= MAX_KV);
            assert!(header.retained_text_bytes() <= MAX_RETAINED_TEXT_BYTES);
            assert!(header.data_end() <= header.file_len());
            for t in header.tensors() {
                let end = header
                    .data_start()
                    .checked_add(t.offset())
                    .and_then(|start| start.checked_add(t.bytes()))
                    .expect("an accepted tensor's end fits in u64");
                assert!(end <= file_len, "tensor data past the end of the file");
            }
        }
        Err(e) => {
            let shown = e.to_string();
            assert!(shown.len() <= MAX_MESSAGE, "message too long: {}", shown.len());
            assert!(shown.bytes().all(|b| (0x20..0x7f).contains(&b)), "{shown:?}");
        }
    }
});
