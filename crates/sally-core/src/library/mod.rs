//! The model library (SI-6, SI-11): content-addressed, read-only model files and their index.
//!
//! ```text
//! <data>/library/                 0700
//!   library.db                    0600  the index: one row per model, never proof of content
//!   blobs/sha256/<hex>            0444  the model files, named by their SHA-256
//!   quarantine/<pid>-<n>/blob     0600  an import in progress
//!   downloads/<hex>.part          0600  a download in progress, named by its publisher's hash
//! ```
//!
//! Bytes enter `blobs/` two ways, and both end in the same tail: the file made read-only and
//! linked under its digest, the row written last. Only a file the library created itself is
//! ever linked; no entry point takes an arbitrary path and links it.
//!
//! - [`Library::import_file`] runs the whole SI-6 chain itself on a private copy: the name's
//!   allowlist before any open, the magic on the first bytes copied, the strict header parse of
//!   the copy, and the SHA-256 of the very bytes copied. A refusal leaves no blob, no row and no
//!   quarantine directory. The source is only ever read, never linked or renamed.
//! - [`Library::begin_download`] creates the partial beneath the library's own directory and
//!   hands out a [`Download`], which has no constructor from a path; the caller only appends
//!   bytes to it. [`Download::verify`] then checks the publisher's SHA-256 over every byte on
//!   disk before anything else reads them, and only on a match the magic and the strict parse;
//!   it needs no library, so it runs without the library's lock. Only it makes a [`Verified`],
//!   which [`Library::promote`] takes for the tail. A refusal from the hash on deletes the
//!   partial and leaves no blob and no row.
//!
//! The tail links by name while the checks ran on the descriptor: a blob it created that is
//! not the checked file itself is removed again and refused ([`LibraryError::BlobChanged`]).
//!
//! The blob directory decides what a model's bytes are; the index only lists them. Add writes
//! the blob first, then the row; remove deletes the row first, then the blob. A crash leaves at
//! most a blob without a row, which nothing lists or resolves.
//!
//! Neither inspect nor an import that finds its blob already stored hashes the blob again: a
//! blob rewritten in place at the same size by the owner's own uid is not detected here. The
//! content control is the SHA-256 checked again by whatever hands a blob to an engine (SI-6;
//! that caller does not exist yet, see `blob_ok`).
//!
//! Every open beneath the library goes through [`crate::fd::openat2`] from a pinned directory
//! descriptor with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`; the index is
//! the one path-based open, inside the checked 0700 directory.
//!
//! The API is synchronous: async callers use `spawn_blocking`.

// TODO(#209): the models.* RPC methods and the model.import / model.remove / model.refuse audit
// entries land with the first sallyd caller, with the audit-before-effect ordering tested there.
// TODO(#210): library:// name resolution, and refusing to remove a model in use.

mod blob;
mod dirs;
mod download;
mod error;
mod import;
mod index;
mod name;
mod quarantine;

use std::path::Path;

use rustix::fs::{AtFlags, ResolveFlags};

pub use download::{Download, Verified};
pub use error::LibraryError;
pub use name::SourceName;

use crate::model::detect::Format;
use crate::model::gguf::{self, GgufHeader};
use crate::model::hash::Digest;

/// How every open beneath the library resolves its path.
const RESOLVE: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS);

/// One model in the library: one row of the index. Its `Debug` shows the source name escaped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    digest: Digest,
    size: u64,
    format: Format,
    source_name: SourceName,
    imported_at: jiff::Timestamp,
}

impl Entry {
    /// The SHA-256 of the model's bytes, and its blob's name.
    #[must_use]
    pub const fn digest(&self) -> &Digest {
        &self.digest
    }

    /// Bytes in the blob.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// The model format.
    #[must_use]
    pub const fn format(&self) -> Format {
        self.format
    }

    /// The name of the file it was imported from, chosen by whoever named the file; its
    /// `Display` escapes it.
    #[must_use]
    pub const fn source_name(&self) -> &SourceName {
        &self.source_name
    }

    /// When it was imported, to the second.
    #[must_use]
    pub const fn imported_at(&self) -> jiff::Timestamp {
        self.imported_at
    }
}

/// A model's row and the header parsed again from its blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inspected {
    entry: Entry,
    header: GgufHeader,
}

impl Inspected {
    /// The row.
    #[must_use]
    pub const fn entry(&self) -> &Entry {
        &self.entry
    }

    /// The header, parsed from the blob by this call.
    #[must_use]
    pub const fn header(&self) -> &GgufHeader {
        &self.header
    }
}

/// The model library under one data directory.
///
/// One process opens a library at a time: `sallyd` is one per user and holds its runtime lock
/// for life. Two processes importing and removing the same bytes at once could leave a row
/// whose blob the other removed; every later inspect of it answers
/// [`LibraryError::BlobMismatch`], so it fails closed.
pub struct Library {
    dirs: dirs::Dirs,
    index: index::Index,
    /// The next quarantine counter to try (`<pid>-<n>`).
    next_quarantine: u32,
    /// Bytes an import must leave free on the library's filesystem.
    reserve: u64,
}

impl Library {
    /// Opens the library under `data_dir` (an absolute path to a directory that must exist and
    /// be private), creating `library/`, `blobs/sha256/`, `quarantine/` at 0700 and the index at
    /// 0600 when missing. An import is refused when the file would leave less than `reserve`
    /// bytes free on the library's filesystem.
    ///
    /// A umask that clears owner bits makes a fresh directory or index fail its own mode check;
    /// `sallyd` runs with umask 077.
    ///
    /// # Errors
    /// [`LibraryError::NotPrivate`] for a relative `data_dir` or a directory that is not the
    /// current user's at exactly 0700 (never repaired), [`LibraryError::IndexNotPrivate`] for
    /// an index that is not a regular 0600 file of the current user,
    /// [`LibraryError::UnknownIndexVersion`] for an index of another schema,
    /// [`LibraryError::IndexCorrupt`] for an index holding anything but this library's table,
    /// [`LibraryError::Io`] and [`LibraryError::Index`] otherwise.
    // TODO(#209): sallyd passes the state filesystem's free-space floor as `reserve`.
    pub fn open(data_dir: &Path, reserve: u64) -> Result<Self, LibraryError> {
        let (dirs, lib_path) = dirs::open(data_dir)?;
        let index = index::Index::open(&dirs.lib, &lib_path)?;
        Ok(Self {
            dirs,
            index,
            next_quarantine: 0,
            reserve,
        })
    }

    /// Imports the model file at `source`: the whole SI-6 chain on a private copy, then the copy
    /// is stored read-only under its SHA-256 and listed. Importing bytes already in the library
    /// returns their existing row.
    ///
    /// # Errors
    /// The first check that failed: [`LibraryError::Detect`] (name or magic),
    /// [`LibraryError::SourceNameNotAllowed`], [`LibraryError::SymlinkInImport`],
    /// [`LibraryError::NotRegularFile`], [`LibraryError::InsufficientDisk`],
    /// [`LibraryError::SourceChanged`], [`LibraryError::Gguf`], [`LibraryError::HashMismatch`]
    /// when `expected` is given and differs, [`LibraryError::BlobMismatch`] when a blob already
    /// stored under the digest fails its checks, [`LibraryError::QuarantineBusy`], or an I/O or
    /// index error. A refusal leaves no blob, no row and no quarantine directory.
    pub fn import_file(
        &mut self,
        source: &Path,
        expected: Option<&Digest>,
    ) -> Result<Entry, LibraryError> {
        import::run(self, source, expected)
    }

    /// Begins (or resumes) the download of a file the publisher lists as `file_name`, `size`
    /// bytes with SHA-256 `expected`. The name goes through the same allowlist and name check
    /// as an import before anything is created; the partial `downloads/<hex>.part` is created
    /// at 0600 or, if one is there, checked and resumed from its length (emptied when longer
    /// than `size`), and locked for the life of the returned [`Download`].
    ///
    /// # Errors
    /// [`LibraryError::Detect`] or [`LibraryError::SourceNameNotAllowed`] for the name,
    /// [`LibraryError::InsufficientDisk`] when the rest of the file plus a twentieth of its size
    /// would leave less than the reserve free, [`LibraryError::DownloadNotPrivate`] for a
    /// partial that is not a regular 0600 file of the current user (left as found),
    /// [`LibraryError::DownloadBusy`] when another download holds it, or an I/O error.
    pub fn begin_download(
        &mut self,
        file_name: &str,
        expected: &Digest,
        size: u64,
    ) -> Result<Download, LibraryError> {
        download::begin(self, file_name, expected, size)
    }

    /// Promotes a verified download (see [`Download::verify`]) through the tail shared with
    /// import: read-only, synced, linked under its digest, the row; then the partial's name is
    /// removed. Bytes already in the library return their existing row.
    ///
    /// # Errors
    /// [`LibraryError::BlobChanged`] when the partial's name no longer names the verified file
    /// (the name is left as found); otherwise the partial is deleted and the error is
    /// [`LibraryError::BlobMismatch`] for a blob already stored under the digest that fails its
    /// checks, or an I/O or index error. No refusal leaves a blob or a row.
    pub fn promote(&mut self, verified: Verified) -> Result<Entry, LibraryError> {
        download::promote(self, verified)
    }

    /// The row stored under `digest`, if any, with its blob checked as inspect checks it (a
    /// regular file of the current user, no write bit, the row's size). It neither parses nor
    /// hashes the blob. A pull asks this before it downloads anything.
    ///
    /// # Errors
    /// [`LibraryError::BlobMismatch`] for a row whose blob is missing or fails the checks
    /// (refused, never repaired), or an I/O or index error.
    pub fn stored(&self, digest: &Digest) -> Result<Option<Entry>, LibraryError> {
        let Some(entry) = self.index.get(digest)? else {
            return Ok(None);
        };
        drop(blob::open_checked(&self.dirs.blobs, &entry)?);
        Ok(Some(entry))
    }

    /// Every model, in digest order.
    ///
    /// # Errors
    /// [`LibraryError::IndexCorrupt`] for a row this library would not have written,
    /// [`LibraryError::Index`] otherwise.
    pub fn list(&self) -> Result<Vec<Entry>, LibraryError> {
        self.index.list()
    }

    /// A model's row, with its blob checked (a regular file of the current user, no write bit,
    /// the row's size) and its header parsed again. It does not hash the blob again.
    ///
    /// # Errors
    /// [`LibraryError::NotFound`] for a digest with no row, [`LibraryError::BlobMismatch`] for a
    /// blob that is missing or fails the checks, [`LibraryError::Gguf`] for a header the parser
    /// refuses, or an I/O or index error.
    pub fn inspect(&self, digest: &Digest) -> Result<Inspected, LibraryError> {
        let entry = self
            .index
            .get(digest)?
            .ok_or_else(|| LibraryError::NotFound(digest.clone()))?;
        let file = blob::open_checked(&self.dirs.blobs, &entry)?;
        let header = match entry.format {
            Format::Gguf => gguf::parse(&file, entry.size)?,
        };
        Ok(Inspected { entry, header })
    }

    /// Removes a model: its row first, then its blob. A blob already gone is not an error.
    ///
    /// # Errors
    /// [`LibraryError::NotFound`] for a digest with no row; an I/O error if the blob could not
    /// be unlinked (the row is already gone, so the blob is an orphan nothing lists).
    pub fn remove(&self, digest: &Digest) -> Result<(), LibraryError> {
        if !self.index.delete(digest)? {
            return Err(LibraryError::NotFound(digest.clone()));
        }
        match rustix::fs::unlinkat(&self.dirs.blobs, digest.as_hex(), AtFlags::empty()) {
            Ok(()) | Err(rustix::io::Errno::NOENT) => {}
            Err(e) => return Err(LibraryError::io("remove the blob", e)),
        }
        // The removal is already visible; a failed directory fsync only weakens durability.
        let _ = rustix::fs::fsync(&self.dirs.blobs);
        Ok(())
    }
}

#[cfg(test)]
#[path = "testkit.rs"]
pub(crate) mod testkit;

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
