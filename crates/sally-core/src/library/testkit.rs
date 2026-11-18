//! Test helpers for the library: a private temporary data directory and GGUF sources.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use super::LibraryError;
use crate::model::detect::DetectError;
use crate::model::gguf::build::Gguf;
use crate::model::gguf::error::tests::every_variant;
use crate::model::hash::{Digest, Hasher};

/// A private (0700) data directory under the temp dir, removed on drop. Every file under it is
/// made writable first, so the 0444 blobs go too.
pub(crate) struct TmpRoot(PathBuf);

impl TmpRoot {
    pub(crate) fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!("sp-lib-{}-{tag}", std::process::id()));
        remove_tree(&root);
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(root)
    }

    /// The data directory a [`super::Library`] opens.
    pub(crate) fn path(&self) -> &Path {
        &self.0
    }

    /// `<root>/library`.
    pub(crate) fn lib(&self) -> PathBuf {
        self.0.join("library")
    }

    /// `<root>/library/blobs/sha256`.
    pub(crate) fn blobs(&self) -> PathBuf {
        self.lib().join("blobs").join("sha256")
    }

    /// `<root>/library/quarantine`.
    pub(crate) fn quarantine(&self) -> PathBuf {
        self.lib().join("quarantine")
    }

    /// `<root>/library/downloads`.
    pub(crate) fn downloads(&self) -> PathBuf {
        self.lib().join("downloads")
    }

    /// `<root>/library/library.db`.
    pub(crate) fn index(&self) -> PathBuf {
        self.lib().join("library.db")
    }

    /// Writes `bytes` to `<root>/src/<name>` and returns the path.
    pub(crate) fn source(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let dir = self.0.join("src");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }
}

impl Drop for TmpRoot {
    fn drop(&mut self) {
        remove_tree(&self.0);
    }
}

/// Removes `path` and everything below it, adding the owner write bit to every directory first.
fn remove_tree(path: &Path) {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return;
    };
    if meta.is_dir() {
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
        if let Ok(entries) = std::fs::read_dir(path) {
            for e in entries.flatten() {
                remove_tree(&e.path());
            }
        }
        let _ = std::fs::remove_dir(path);
    } else {
        let _ = std::fs::remove_file(path);
    }
}

/// A small valid GGUF file; `tag` changes its bytes (and so its digest).
pub(crate) fn gguf(tag: &str) -> Vec<u8> {
    Gguf::valid().kv_str("general.name", tag.as_bytes()).bytes()
}

/// The SHA-256 of `bytes`.
pub(crate) fn sha(bytes: &[u8]) -> Digest {
    let mut h = Hasher::default();
    h.update(bytes);
    h.finish()
}

/// The names in a directory, sorted.
pub(crate) fn names(dir: &Path) -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    out.sort();
    out
}

/// Permission bits of `path` (not following a symlink).
pub(crate) fn mode(path: &Path) -> u32 {
    std::fs::symlink_metadata(path).unwrap().mode() & 0o7777
}

/// Sets the permission bits of `path`.
pub(crate) fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// One of each [`LibraryError`] variant with the code it must keep: the library's own, both
/// detect errors and every GGUF error, wrapped. Together these are every code
/// [`LibraryError::code`] can return. The list is written by hand;
/// `error_tests::every_code_has_a_row` fails when a code table gains a code with no row here.
pub(crate) fn every_library_error() -> Vec<(LibraryError, &'static str)> {
    let digest = || sha(b"row");
    let mut rows = vec![
        (
            LibraryError::Detect(DetectError::FormatNotAllowed),
            "format_not_allowed",
        ),
        (
            LibraryError::Detect(DetectError::MagicMismatch),
            "magic_mismatch",
        ),
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
                source: std::io::Error::other("x"),
            },
            "io_error",
        ),
    ];
    rows.extend(
        every_variant()
            .into_iter()
            .map(|(e, code)| (LibraryError::Gguf(e), code)),
    );
    rows
}

/// Nothing in `blobs/sha256`, nothing in `quarantine`, nothing in `downloads`, and no row.
pub(crate) fn assert_nothing_stored(root: &TmpRoot, lib: &super::Library) {
    assert!(names(&root.blobs()).is_empty(), "a blob was left");
    assert!(names(&root.quarantine()).is_empty(), "quarantine not empty");
    assert!(names(&root.downloads()).is_empty(), "downloads not empty");
    assert!(lib.list().unwrap().is_empty(), "a row was left");
}
