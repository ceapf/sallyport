//! Fuzz target: a tool selector byte plus arbitrary JSON → the built-in tools' argument parser,
//! then the shell's destructive tagger on what it accepts (maintainer's Task 11 decision 8;
//! rust review LOW9; CLAUDE.md: every parser of untrusted bytes has one).
//!
//! Invariants: never panics; an accepted read asks for at most `READ_CAP` bytes and its end does
//! not overflow; an accepted write body is canonical base64 (it re-encodes to the input); an
//! accepted command has 1 to `MAX_ARGV` words, the first not empty, none holding NUL; an accepted
//! `cwd` is absolute and canonical (no empty, `.` or `..` segment, no trailing `/`); the tagger
//! returns on every accepted command and on every word list the input splits into.
#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use sallyd::tools::args::{Args, MAX_ARGV, READ_CAP, parse};
use sallyd::tools::tag::destructive;
use serde_json::{Map, Value};

const TOOLS: [&str; 6] = ["fs_read", "fs_list", "fs_write", "fs_delete", "shell", "fetch"];

fuzz_target!(|data: &[u8]| {
    let Some((sel, body)) = data.split_first() else {
        return;
    };
    let tool = TOOLS
        .get(usize::from(*sel) % TOOLS.len())
        .expect("index in range");
    // The tagger also sees raw word lists, not only parsed ones: one word per NUL-separated piece.
    if let Ok(text) = std::str::from_utf8(body) {
        let words: Vec<String> = text.split('\0').map(str::to_owned).collect();
        let _ = destructive(&words);
    }
    let Ok(map) = serde_json::from_slice::<Map<String, Value>>(body) else {
        return;
    };
    let Ok(args) = parse(tool, &map) else {
        return;
    };
    match args {
        Args::Read { offset, len, .. } => {
            assert!(len <= READ_CAP, "read above the cap");
            assert!(offset.checked_add(len).is_some(), "read end overflows");
        }
        Args::Write { content, .. } => {
            let Some(Value::String(b64)) = map.get("content_b64") else {
                panic!("write accepted without a string body");
            };
            assert_eq!(&encode(&content), b64, "non-canonical base64 accepted");
        }
        Args::Shell { cmd, cwd } => {
            assert!(!cmd.is_empty() && cmd.len() <= MAX_ARGV, "argv length");
            assert!(cmd.first().is_some_and(|c| !c.is_empty()), "empty program");
            assert!(cmd.iter().all(|w| !w.contains('\0')), "NUL in argv");
            if let Some(c) = cwd {
                assert!(c.starts_with('/'), "relative cwd");
                assert!(
                    c == "/"
                        || c.split('/')
                            .skip(1)
                            .all(|s| !matches!(s, "" | "." | "..")),
                    "cwd not canonical: {c:?}"
                );
            }
            let _ = destructive(&cmd);
        }
        Args::List { .. } | Args::Delete { .. } => {}
    }
});

/// Standard base64 with padding, written out here so the target checks the parser against an
/// encoder that is not the one it decodes with.
fn encode(bytes: &[u8]) -> String {
    const ABC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let sym = |n: u32| char::from(*ABC.get((n & 63) as usize).expect("6 bits"));
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = |i: usize| u32::from(chunk.get(i).copied().unwrap_or(0));
        let n = (b(0) << 16) | (b(1) << 8) | b(2);
        out.push(sym(n >> 18));
        out.push(sym(n >> 12));
        out.push(if chunk.len() > 1 { sym(n >> 6) } else { '=' });
        out.push(if chunk.len() > 2 { sym(n) } else { '=' });
    }
    out
}
