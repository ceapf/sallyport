//! Fuzz target: arbitrary bytes → model detect and the strict GGUF header parser (SI-6;
//! CLAUDE.md: every parser of untrusted bytes has one).
//!
//! The parser runs three times: with `file_len` equal to the input's length, shorter by the
//! input's last byte, and longer by a thousand times it (a file that shrank or grew after its
//! length was taken).
//!
//! Invariants:
//! - never panics, on any input, for detect's name step, its magic step, or the parser;
//! - an accepted header is within every limit: at most MAX_TENSORS tensors and MAX_KV entries,
//!   at most MAX_RETAINED_TEXT_BYTES of kept file text, every tensor's data and the data end
//!   within `file_len`;
//! - an accepted header's layout is llama.cpp's: the data section starts aligned (where the
//!   header ends is not exposed, so that half is the unit tests'), the first tensor at offset 0,
//!   each next at the previous end rounded up to the alignment;
//! - no kept key, string or tensor name holds a NUL, and `split.count`, when present, is a u16
//!   of 0 or 1;
//! - a name detect accepts holds no `/` and no NUL;
//! - a refusal's message is printable ASCII and at most MAX_MESSAGE bytes;
//! - a reader that yields one byte per read gives the same result as the whole slice.
#![no_main]
#![forbid(unsafe_code)]

use std::ffi::OsStr;
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;

use libfuzzer_sys::fuzz_target;
use sally_core::model::detect;
use sally_core::model::gguf::{self, GgufHeader, MAX_KV, MAX_RETAINED_TEXT_BYTES, MAX_TENSORS};

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

/// The result as text: Debug plus every kept key, string and name, which Debug shows only as
/// lengths.
fn summary(result: &Result<GgufHeader, gguf::GgufError>) -> String {
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

fn check_accepted(header: &GgufHeader, file_len: u64) {
    assert!(header.tensors().len() as u64 <= MAX_TENSORS);
    assert!(header.metadata().len() as u64 <= MAX_KV);
    assert!(header.retained_text_bytes() <= MAX_RETAINED_TEXT_BYTES);
    assert_eq!(header.file_len(), file_len);
    assert!(header.data_end() <= file_len);
    for m in header.metadata() {
        assert!(!m.key().as_str().contains('\0'));
        if let gguf::Value::String(s) = m.value() {
            assert!(!s.as_str().contains('\0'), "kept string holds a NUL");
        }
        if m.key().as_str() == "split.count" {
            assert!(
                matches!(m.value(), gguf::Value::U16(0 | 1)),
                "split.count says multi-file"
            );
        }
    }
    for t in header.tensors() {
        assert!(!t.name().as_str().contains('\0'));
    }
    let align = u64::from(header.alignment());
    assert!(align.is_power_of_two() && align >= 8);
    assert_eq!(header.data_start() % align, 0, "data section not aligned");
    let mut expected = 0u64;
    for t in header.tensors() {
        assert_eq!(t.offset(), expected, "tensors not back to back");
        let end = header
            .data_start()
            .checked_add(t.offset())
            .and_then(|start| start.checked_add(t.bytes()))
            .expect("an accepted tensor's end fits in u64");
        assert!(end <= file_len, "tensor data past the end of the file");
        expected = (t.offset() + t.bytes()).next_multiple_of(align);
    }
}

fn check(data: &[u8], file_len: u64) {
    let result = gguf::parse(data, file_len);
    let chunked = gguf::parse(OneByte(data), file_len);
    assert_eq!(summary(&result), summary(&chunked), "chunking changed the result");
    match result {
        Ok(header) => check_accepted(&header, file_len),
        Err(e) => {
            let shown = e.to_string();
            assert!(shown.len() <= MAX_MESSAGE, "message too long: {}", shown.len());
            assert!(shown.bytes().all(|b| (0x20..0x7f).contains(&b)), "{shown:?}");
        }
    }
}

fuzz_target!(|data: &[u8]| {
    // The name step reads no bytes and must take any name.
    if detect::by_name(OsStr::from_bytes(data)).is_ok() {
        assert!(!data.contains(&b'/') && !data.contains(&0), "a path or NUL passed by_name");
    }
    if let Ok(candidate) = detect::by_name(OsStr::new("model.gguf")) {
        let _ = candidate.check_magic(data);
    }

    let len = data.len() as u64;
    let delta = data.last().map_or(0, |b| u64::from(*b));
    check(data, len);
    check(data, len.saturating_sub(delta));
    check(data, len + delta * 1000);
});
