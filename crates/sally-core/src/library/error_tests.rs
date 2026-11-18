#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::io;

use super::*;
use crate::model::detect::DetectError;
use crate::model::gguf::GgufError;
use crate::model::hash::Digest;

fn digest() -> Digest {
    Digest::parse(&"a".repeat(64)).unwrap()
}

/// Every variant has its own stable code; wrapped errors keep theirs.
#[test]
fn every_variant_has_its_code() {
    let cases = [
        (
            LibraryError::Detect(DetectError::FormatNotAllowed),
            "format_not_allowed",
        ),
        (
            LibraryError::Detect(DetectError::MagicMismatch),
            "magic_mismatch",
        ),
        (LibraryError::Gguf(GgufError::Truncated), "truncated"),
        (LibraryError::Gguf(GgufError::BadVersion(9)), "bad_version"),
        (LibraryError::SymlinkInImport, "symlink_in_import"),
        (LibraryError::NotRegularFile, "not_regular_file"),
        (
            LibraryError::SourceNameNotAllowed,
            "source_name_not_allowed",
        ),
        (
            LibraryError::InsufficientDisk { size: 7 },
            "insufficient_disk",
        ),
        (LibraryError::SourceChanged, "source_changed"),
        (
            LibraryError::HashMismatch {
                expected: digest(),
                actual: digest(),
            },
            "hash_mismatch",
        ),
        (LibraryError::NotFound(digest()), "not_found"),
        (LibraryError::BlobMismatch(digest()), "blob_mismatch"),
        (LibraryError::BlobChanged, "blob_changed"),
        (LibraryError::QuarantineChanged, "quarantine_changed"),
        (LibraryError::QuarantineBusy, "quarantine_busy"),
        (LibraryError::DownloadBusy, "download_busy"),
        (
            LibraryError::DownloadIncomplete { have: 1, size: 2 },
            "download_incomplete",
        ),
        (LibraryError::DownloadTooLong, "download_too_long"),
        (LibraryError::DownloadNotPrivate, "download_not_private"),
        (
            LibraryError::NotPrivate {
                path: "p".to_owned(),
                msg: "m".to_owned(),
            },
            "not_private",
        ),
        (
            LibraryError::IndexNotPrivate {
                path: "p".to_owned(),
            },
            "index_not_private",
        ),
        (
            LibraryError::UnknownIndexVersion(2),
            "unknown_index_version",
        ),
        (LibraryError::IndexCorrupt, "index_corrupt"),
        (
            LibraryError::Index(rusqlite::Error::InvalidQuery),
            "index_error",
        ),
        (
            LibraryError::Io {
                op: "read",
                source: io::Error::other("x"),
            },
            "io_error",
        ),
    ];
    for (err, code) in cases {
        assert_eq!(err.code(), code, "{err}");
    }
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
