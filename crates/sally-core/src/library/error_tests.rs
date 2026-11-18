#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::collections::BTreeSet;
use std::io;

use super::*;
use crate::library::testkit::every_library_error;
use crate::model::hash::Digest;

fn digest() -> Digest {
    Digest::parse(&"a".repeat(64)).unwrap()
}

/// Every variant has its own stable code; wrapped errors keep theirs.
#[test]
fn every_variant_has_its_code() {
    for (err, code) in every_library_error() {
        assert_eq!(err.code(), code, "{err}");
    }
}

/// The `=> "..."` literals of the `const fn code(` in `source`, up to its closing brace.
fn code_literals(source: &str) -> BTreeSet<&str> {
    source
        .lines()
        .skip_while(|line| !line.contains("const fn code("))
        .take_while(|line| *line != "    }")
        .filter_map(|line| line.split_once("=> \""))
        .filter_map(|(_, rest)| rest.split_once('"'))
        .map(|(code, _)| code)
        .collect()
}

/// Every code the library, detect and GGUF code tables can return has a row in
/// `every_library_error`, and every row's code is in a table: the two sets are equal, so a
/// scan that read nothing fails too.
#[test]
fn every_code_has_a_row() {
    let tables: BTreeSet<&str> = [
        include_str!("error.rs"),
        include_str!("../model/detect.rs"),
        include_str!("../model/gguf/error.rs"),
    ]
    .into_iter()
    .flat_map(code_literals)
    .collect();
    let rows: BTreeSet<&str> = every_library_error()
        .iter()
        .map(|(_, code)| *code)
        .collect();
    assert_eq!(tables, rows);
}

/// Messages name the operation or the library path, never file-chosen text.
#[test]
fn messages_say_what_failed() {
    let not_private = LibraryError::NotPrivate {
        path: "/x/library".to_owned(),
        msg: "mode is 0750".to_owned(),
    };
    assert_eq!(not_private.to_string(), "/x/library: mode is 0750");
    let io = LibraryError::Io {
        op: "read the source",
        source: io::Error::from(io::ErrorKind::NotFound),
    };
    assert!(io.to_string().starts_with("read the source: "), "{io}");
    let mismatch = LibraryError::HashMismatch {
        expected: digest(),
        actual: Digest::parse(&"b".repeat(64)).unwrap(),
    };
    let text = mismatch.to_string();
    assert!(
        text.contains(&"a".repeat(64)) && text.contains(&"b".repeat(64)),
        "{text}"
    );
}
