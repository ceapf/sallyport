#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::os::unix::fs::symlink;

use super::*;
use crate::library::testkit::{TmpRoot, chmod, gguf, names, sha};

fn with(root: &TmpRoot, tags: &[&str]) -> (Library, Vec<Entry>) {
    let mut lib = Library::open(root.path(), 0).unwrap();
    let entries = tags
        .iter()
        .map(|t| {
            let source = root.source(&format!("{t}.gguf"), &gguf(t));
            lib.import_file(&source, None).unwrap()
        })
        .collect();
    (lib, entries)
}

/// list returns every row in digest order.
#[test]
fn list_is_in_digest_order() {
    let root = TmpRoot::new("lib-list");
    let (lib, mut entries) = with(&root, &["a", "b", "c", "d"]);
    entries.sort_by(|x, y| x.digest().cmp(y.digest()));
    assert_eq!(lib.list().unwrap(), entries);
}

/// inspect re-parses the blob and returns its row with the header.
#[test]
fn inspect_returns_the_row_and_header() {
    let root = TmpRoot::new("lib-inspect");
    let (lib, entries) = with(&root, &["a", "b"]);
    for e in &entries {
        let got = lib.inspect(e.digest()).unwrap();
        assert_eq!(got.entry(), e);
        assert_eq!(got.header().tensors().len(), 1);
        assert_eq!(got.header().file_len(), e.size());
    }
}

/// An unknown digest is not_found for inspect and for remove.
#[test]
fn an_unknown_digest_is_not_found() {
    let root = TmpRoot::new("lib-unknown");
    let (lib, _) = with(&root, &["a"]);
    let other = sha(b"none");
    let err = lib.inspect(&other).unwrap_err();
    assert_eq!(err.code(), "not_found");
    assert!(err.to_string().contains(other.as_hex()));
    assert_eq!(lib.remove(&other).unwrap_err().code(), "not_found");
    assert_eq!(lib.list().unwrap().len(), 1);
}

/// A blob that no longer matches its row is blob_mismatch: gone, writable, another size,
/// a symlink.
#[test]
fn a_changed_blob_is_blob_mismatch() {
    let root = TmpRoot::new("lib-blob");
    let (lib, entries) = with(&root, &["a"]);
    let digest = entries[0].digest();
    let blob = root.blobs().join(digest.as_hex());
    let bytes = std::fs::read(&blob).unwrap();
    let blobs = root.blobs();
    let cases: [(&str, &dyn Fn()); 6] = [
        ("owner write", &|| chmod(&blob, 0o644)),
        ("group write", &|| chmod(&blob, 0o464)),
        ("other write", &|| chmod(&blob, 0o446)),
        ("longer", &|| {
            chmod(&blob, 0o644);
            let mut longer = bytes.clone();
            longer.push(0);
            std::fs::write(&blob, longer).unwrap();
            chmod(&blob, 0o444);
        }),
        ("gone", &|| std::fs::remove_file(&blob).unwrap()),
        ("symlink", &|| {
            std::fs::remove_file(&blob).unwrap();
            let real = blobs.join("real");
            std::fs::write(&real, &bytes).unwrap();
            chmod(&real, 0o444);
            symlink(&real, &blob).unwrap();
        }),
    ];
    for (what, change) in cases {
        change();
        let err = lib.inspect(digest).unwrap_err();
        assert_eq!(err.code(), "blob_mismatch", "{what}");
        assert!(err.to_string().contains(digest.as_hex()), "{what}: {err}");
        let _ = std::fs::remove_file(blobs.join("real"));
        let _ = std::fs::remove_file(&blob);
        std::fs::write(&blob, &bytes).unwrap();
        chmod(&blob, 0o444);
        lib.inspect(digest).unwrap();
    }
}

/// stored answers from the row and its checked blob: nothing for an unknown digest, the row
/// when the blob passes, blob_mismatch when it is writable or gone.
#[test]
fn stored_answers_only_from_a_checked_blob() {
    let root = TmpRoot::new("lib-stored");
    let (lib, entries) = with(&root, &["a"]);
    let digest = entries[0].digest();
    assert_eq!(lib.stored(&sha(b"none")).unwrap(), None);
    assert_eq!(lib.stored(digest).unwrap().as_ref(), Some(&entries[0]));
    let blob = root.blobs().join(digest.as_hex());
    let bytes = std::fs::read(&blob).unwrap();
    chmod(&blob, 0o644);
    assert_eq!(lib.stored(digest).unwrap_err().code(), "blob_mismatch");
    chmod(&blob, 0o444);
    assert!(lib.stored(digest).unwrap().is_some());
    std::fs::remove_file(&blob).unwrap();
    assert_eq!(lib.stored(digest).unwrap_err().code(), "blob_mismatch");
    std::fs::write(&blob, &bytes).unwrap();
    chmod(&blob, 0o444);
    assert!(lib.stored(digest).unwrap().is_some());
}

/// inspect parses again: a blob whose bytes were changed in place (same size, read-only) is
/// refused by the parser, not trusted because of its row.
#[test]
fn inspect_reparses_the_blob() {
    let root = TmpRoot::new("lib-reparse");
    let (lib, entries) = with(&root, &["a"]);
    let blob = root.blobs().join(entries[0].digest().as_hex());
    let mut bytes = std::fs::read(&blob).unwrap();
    bytes[4] = 9; // version 9
    chmod(&blob, 0o644);
    std::fs::write(&blob, &bytes).unwrap();
    chmod(&blob, 0o444);
    assert_eq!(
        lib.inspect(entries[0].digest()).unwrap_err().code(),
        "bad_version"
    );
}

/// remove deletes the row and then the blob; a blob already gone is still a removal.
#[test]
fn remove_deletes_row_then_blob() {
    let root = TmpRoot::new("lib-remove");
    let (lib, entries) = with(&root, &["a", "b"]);
    lib.remove(entries[0].digest()).unwrap();
    assert_eq!(lib.list().unwrap(), [entries[1].clone()]);
    assert_eq!(names(&root.blobs()), [entries[1].digest().as_hex()]);
    assert_eq!(
        lib.inspect(entries[0].digest()).unwrap_err().code(),
        "not_found"
    );
    std::fs::remove_file(root.blobs().join(entries[1].digest().as_hex())).unwrap();
    lib.remove(entries[1].digest()).unwrap();
    assert!(lib.list().unwrap().is_empty());
}

/// A blob that cannot be unlinked (a directory in its place) is an I/O error after the row is
/// gone: the row never outlives the decision to remove.
#[test]
fn remove_reports_an_unlink_failure_after_the_row() {
    let root = TmpRoot::new("lib-remove-dir");
    let (lib, entries) = with(&root, &["a"]);
    let blob = root.blobs().join(entries[0].digest().as_hex());
    std::fs::remove_file(&blob).unwrap();
    std::fs::create_dir(&blob).unwrap();
    assert_eq!(
        lib.remove(entries[0].digest()).unwrap_err().code(),
        "io_error"
    );
    assert!(lib.list().unwrap().is_empty());
}

/// The library persists: a second open lists what the first imported.
#[test]
fn a_reopened_library_lists_the_same_rows() {
    let root = TmpRoot::new("lib-reopen");
    let (lib, entries) = with(&root, &["a"]);
    drop(lib);
    let lib = Library::open(root.path(), 0).unwrap();
    assert_eq!(lib.list().unwrap(), entries);
    lib.inspect(entries[0].digest()).unwrap();
}

/// An entry's Debug shows the source name escaped to printable ASCII.
#[test]
fn entry_debug_escapes_the_source_name() {
    let root = TmpRoot::new("lib-debug");
    let mut lib = Library::open(root.path(), 0).unwrap();
    let source = root.source("a\u{202e}b.gguf", &gguf("debug"));
    let entry = lib.import_file(&source, None).unwrap();
    let text = format!("{entry:?}");
    assert!(text.is_ascii(), "{text}");
    assert!(text.contains("a\\u{202e}b.gguf"), "{text}");
    assert!(text.contains(entry.digest().as_hex()), "{text}");
}
