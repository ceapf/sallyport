//! The model library (SI-6, SI-11): content-addressed, read-only model files and their index.
//!
//! ```text
//! <data>/library/                 0700
//!   library.db                    0600  the index: one row per model, never proof of content
//!   blobs/sha256/<hex>            0444  the model files, named by their SHA-256
//!   quarantine/<pid>-<n>/blob     0600  an import in progress
//! ```
//!
//! [`Library::import_file`] is the one way bytes enter `blobs/`. It runs the whole SI-6 chain
//! itself on a private copy: the name's allowlist before any open, the magic on the first bytes
//! copied, the strict header parse of the copy, and the SHA-256 of the very bytes copied. Only
//! then is the copy made read-only and linked under its digest; the row is written last. A
//! refusal leaves no blob, no row and no quarantine directory. The source is only ever read,
//! never linked or renamed.
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
mod error;
mod import;
mod index;
mod name;
mod quarantine;

use std::path::Path;

use rustix::fs::{AtFlags, ResolveFlags};

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
