#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use super::*;

const FILE: u32 = 0o100_000;
const DIR: u32 = 0o040_000;
const ME: u32 = 1000;

/// A blob is a regular file of the current user, with no write bit, of the row's size.
#[test]
fn blob_ok_checks_kind_owner_write_bits_and_size() {
    assert!(blob_ok(FILE | 0o444, ME, ME, 10, 10));
    assert!(blob_ok(FILE | 0o400, ME, ME, 10, 10));
    assert!(!blob_ok(DIR | 0o444, ME, ME, 10, 10), "not a file");
    assert!(!blob_ok(FILE | 0o444, ME + 1, ME, 10, 10), "other owner");
    assert!(!blob_ok(FILE | 0o444, 0, ME, 10, 10), "root-owned");
    for w in [0o200, 0o020, 0o002] {
        assert!(!blob_ok(FILE | 0o444 | w, ME, ME, 10, 10), "{w:o}");
    }
    assert!(!blob_ok(FILE | 0o444, ME, ME, 11, 10), "longer");
    assert!(!blob_ok(FILE | 0o444, ME, ME, 9, 10), "shorter");
}

/// is_file: a blob that is the file itself is; another file under the name is not; a blob gone
/// is not.
#[test]
fn is_file_compares_the_linked_inode() {
    use crate::library::testkit::{TmpRoot, sha};
    let root = TmpRoot::new("blob-isfile");
    let src = root.source("a.gguf", b"aaaa");
    let other = root.source("b.gguf", b"bbbb");
    let blobs = crate::fd::open(
        root.path().join("src"),
        OFlags::RDONLY.union(OFlags::DIRECTORY),
        Mode::empty(),
    )
    .unwrap();
    let file = File::open(&src).unwrap();
    let digest = sha(b"aaaa");
    let blob = root.path().join("src").join(digest.as_hex());
    assert!(!is_file(&blobs, &digest, &file).unwrap(), "absent");
    std::fs::hard_link(&src, &blob).unwrap();
    assert!(is_file(&blobs, &digest, &file).unwrap(), "the file itself");
    std::fs::remove_file(&blob).unwrap();
    std::fs::hard_link(&other, &blob).unwrap();
    assert!(!is_file(&blobs, &digest, &file).unwrap(), "another file");
}
