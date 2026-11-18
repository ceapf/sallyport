//! Why a library operation failed. Each variant has a stable [`LibraryError::code`] for the
//! `model.refuse` reason; the message text may change, the codes may not.
//!
//! No variant holds raw text the imported file or its name chose: digests are code-made hex,
//! paths are the library's own directories, and the source path an import was given is never
//! echoed. The one exception is [`GgufError`], whose duplicate-key and duplicate-tensor-name
//! refusals quote the file's key or name, escaped to printable ASCII and capped at 64 bytes by
//! [`crate::text::escape_quoted_capped`].

use std::io;

use crate::model::detect::DetectError;
use crate::model::gguf::GgufError;
use crate::model::hash::Digest;

/// Why a library operation failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LibraryError {
    /// The file name is not on the allowlist, or the first bytes are not the format's magic.
    #[error(transparent)]
    Detect(#[from] DetectError),
    /// The strict header parse refused the file.
    #[error(transparent)]
    Gguf(#[from] GgufError),
    /// The source path names a symlink; the library imports only the file itself.
    #[error("the file to import is a symlink; import the file it points to")]
    SymlinkInImport,
    /// The source is not a regular file (a directory, a FIFO, a device).
    #[error("the file to import is not a regular file")]
    NotRegularFile,
    /// The file name has an allowed extension but holds a control character or is longer than
    /// 255 bytes, so the library will not keep it.
    #[error("the file name holds a control character or is over 255 bytes; rename the file")]
    SourceNameNotAllowed,
    /// The file is larger than the space the library may use on its filesystem.
    #[error("not enough free disk space for this model ({size} bytes)")]
    InsufficientDisk {
        /// The file's size.
        size: u64,
    },
    /// The file grew while it was copied.
    #[error("the file to import grew while it was copied")]
    SourceChanged,
    /// The file's SHA-256 is not the one expected.
    #[error("the file's SHA-256 is {actual}, not the expected {expected}")]
    HashMismatch {
        /// The digest the caller expected.
        expected: Digest,
        /// The digest of the bytes read.
        actual: Digest,
    },
    /// No model with this digest is in the library.
    #[error("no model {0} in the library")]
    NotFound(Digest),
    /// The model's blob is missing or no longer matches its row (type, owner, write bits, size).
    #[error("the blob of model {0} is missing or does not match the library index")]
    BlobMismatch(Digest),
    /// The quarantine copy's length on disk is not the number of bytes copied into it.
    #[error("the quarantine copy changed while it was written")]
    QuarantineChanged,
    /// Every quarantine name this import tried was taken.
    #[error("no free quarantine directory name; remove stale ones under library/quarantine")]
    QuarantineBusy,
    /// Another download of the same file holds its partial.
    #[error("this model is already being downloaded")]
    DownloadBusy,
    /// The partial holds fewer bytes than the file's size; it is kept for a resume.
    #[error("the download is incomplete ({have} of {size} bytes)")]
    DownloadIncomplete {
        /// Bytes on disk.
        have: u64,
        /// The file's listed size.
        size: u64,
    },
    /// More bytes arrived than the file's listed size.
    #[error("the download is longer than the file's listed size")]
    DownloadTooLong,
    /// The partial under `library/downloads` is not a regular 0600 file of the current user; it
    /// is left as it was.
    #[error(
        "a partial download under library/downloads is not a regular file owned by the current \
         user with mode 0600; remove it"
    )]
    DownloadNotPrivate,
    /// A library directory (or the data directory) is not private.
    #[error("{path}: {msg}")]
    NotPrivate {
        /// Host path of the directory.
        path: String,
        /// What is wrong and how to fix it.
        msg: String,
    },
    /// The index file is not a regular 0600 file of the current user.
    #[error(
        "{path}: the library index must be a regular file owned by the current user with mode \
         0600 (chmod 600)"
    )]
    IndexNotPrivate {
        /// Host path of the index.
        path: String,
    },
    /// The index's schema version is not this library's.
    #[error("the library index has schema version {0}, which this version does not read")]
    UnknownIndexVersion(i64),
    /// A row holds a value the library would not have written.
    #[error("the library index holds a row this library did not write")]
    IndexCorrupt,
    /// SQLite failed.
    #[error("the library index failed: {0}")]
    Index(#[from] rusqlite::Error),
    /// A filesystem operation failed.
    #[error("{op}: {source}")]
    Io {
        /// What was being done.
        op: &'static str,
        /// The underlying error.
        source: io::Error,
    },
}

impl LibraryError {
    /// The stable reason code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Detect(e) => e.code(),
            Self::Gguf(e) => e.code(),
            Self::SymlinkInImport => "symlink_in_import",
            Self::NotRegularFile => "not_regular_file",
            Self::SourceNameNotAllowed => "source_name_not_allowed",
            Self::InsufficientDisk { .. } => "insufficient_disk",
            Self::SourceChanged => "source_changed",
            Self::HashMismatch { .. } => "hash_mismatch",
            Self::NotFound(_) => "not_found",
            Self::BlobMismatch(_) => "blob_mismatch",
            Self::QuarantineChanged => "quarantine_changed",
            Self::QuarantineBusy => "quarantine_busy",
            Self::DownloadBusy => "download_busy",
            Self::DownloadIncomplete { .. } => "download_incomplete",
            Self::DownloadTooLong => "download_too_long",
            Self::DownloadNotPrivate => "download_not_private",
            Self::NotPrivate { .. } => "not_private",
            Self::IndexNotPrivate { .. } => "index_not_private",
            Self::UnknownIndexVersion(_) => "unknown_index_version",
            Self::IndexCorrupt => "index_corrupt",
            Self::Index(_) => "index_error",
            Self::Io { .. } => "io_error",
        }
    }

    /// An I/O failure of `op`.
    pub(crate) fn io(op: &'static str, e: impl Into<io::Error>) -> Self {
        Self::Io {
            op,
            source: e.into(),
        }
    }
}

#[cfg(test)]
#[path = "error_tests.rs"]
mod tests;
