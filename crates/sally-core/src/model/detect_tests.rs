#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;

use super::*;

/// A pickle protocol-2 stream's first bytes (`\x80\x02` then a GLOBAL opcode), assembled here so
/// no pickle file sits in the tree.
fn pickle_head() -> Vec<u8> {
    let mut head = vec![0x80, 0x02, b'c'];
    head.extend_from_slice(b"posix\nsystem\n");
    head
}

#[test]
fn a_gguf_name_with_the_magic_is_gguf() {
    for name in [
        "model.gguf",
        "Qwen2.5-7B-Q4_K_M.gguf",
        "a.b.gguf",
        "model .gguf",
    ] {
        let candidate = by_name(OsStr::new(name)).unwrap();
        assert_eq!(
            candidate.check_magic(b"GGUF\x03\x00\x00\x00"),
            Ok(Format::Gguf)
        );
    }
    assert_eq!(
        by_name(OsStr::new("m.gguf")).unwrap().check_magic(b"GGUF"),
        Ok(Format::Gguf)
    );
}

#[test]
fn every_other_name_is_refused_before_any_bytes() {
    let refused = [
        "model.GGUF",
        "model.Gguf",
        "model.safetensors",
        "model",
        "gguf",
        ".gguf",
        "model.gguf.bin",
        "model.gguf.",
        "model.gguf ",
        "model.gguf\n",
        "model.bin",
        "model.pt",
        "model.pth",
        "model.pkl",
        "model.pickle",
        "model.ckpt",
        "model.h5",
        "model.zip",
        "",
        // One path component only: never a path, never a NUL.
        "dir/model.gguf",
        "/model.gguf",
        "model.gguf/",
        "./model.gguf",
        "x.gguf/.",
        "a.pkl/b.gguf",
        "a\0.gguf",
        "model.pkl\0.gguf",
    ];
    for name in refused {
        assert_eq!(
            by_name(OsStr::new(name)),
            Err(DetectError::FormatNotAllowed),
            "{name:?}"
        );
    }
}

#[test]
fn a_name_that_is_not_utf8_is_refused() {
    let name = OsStr::from_bytes(b"mod\xffel.gguf");
    assert_eq!(by_name(name), Err(DetectError::FormatNotAllowed));
}

#[test]
fn a_gguf_name_without_the_magic_is_a_mismatch() {
    let heads: [&[u8]; 6] = [b"", b"GGU", b"gguf", b"FUGG", b"PK\x03\x04", b"\x00GGUF"];
    for head in heads {
        let candidate = by_name(OsStr::new("model.gguf")).unwrap();
        assert_eq!(
            candidate.check_magic(head),
            Err(DetectError::MagicMismatch),
            "{head:?}"
        );
    }
}

#[test]
fn a_pickle_renamed_to_gguf_is_a_mismatch() {
    let candidate = by_name(OsStr::new("model.gguf")).unwrap();
    assert_eq!(
        candidate.check_magic(&pickle_head()),
        Err(DetectError::MagicMismatch)
    );
}

#[test]
fn codes_are_pinned() {
    assert_eq!(DetectError::FormatNotAllowed.code(), "format_not_allowed");
    assert_eq!(DetectError::MagicMismatch.code(), "magic_mismatch");
}

#[test]
fn messages_never_echo_the_name() {
    let name = "secret-name-xyz.pt";
    let e = by_name(OsStr::new(name)).unwrap_err();
    assert!(!format!("{e} {e:?}").contains("secret"));
}
