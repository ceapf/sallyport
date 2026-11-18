//! The import: the whole SI-6 chain on a private copy, in this order.
//!
//! 1. The file name through [`detect::by_name`], before anything is opened.
//! 2. The source opened `O_RDONLY | O_NOFOLLOW | O_NONBLOCK` and checked on the descriptor: a
//!    regular file. A symlink is refused, never followed.
//! 3. One pass copies the source into a fresh quarantine directory while hashing it; the first
//!    four bytes go through the magic check before the copy goes on. The bytes checked, hashed
//!    and stored are the same bytes.
//! 4. The strict header parse of the copy from byte 0, against the copy's own length, which
//!    must equal the bytes copied.
//! 5. The digest compared with the expected one, when given.
//! 6. The copy made 0444 and synced, then linked into `blobs/sha256/<hex>` without replacing
//!    a blob already there.
//! 7. The row, then the quarantine directory removed.
//!
//! Any refusal removes the quarantine directory and leaves no blob and no row. The source is
//! only ever read.
#![deny(clippy::indexing_slicing)]

use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;

use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use rustix::io::Errno;

use super::index::source_name_ok;
use super::quarantine::Quarantine;
use super::{Entry, Library, LibraryError, blob};
use crate::model::detect::{self, Candidate, DetectError, Format};
use crate::model::gguf;
use crate::model::hash::{Digest, Hasher};

/// The copy's read buffer.
const COPY_BUFFER: usize = 65_536;
/// Bytes the magic check reads before the copy goes on.
const MAGIC_LEN: u64 = 4;
/// A blob's mode.
const BLOB_MODE: u32 = 0o444;

/// [`Library::import_file`].
pub(super) fn run(
    lib: &mut Library,
    source: &Path,
    expected: Option<&Digest>,
) -> Result<Entry, LibraryError> {
    let file_name = source.file_name().ok_or(DetectError::FormatNotAllowed)?;
    let candidate = detect::by_name(file_name)?;
    let source_name = file_name
        .to_str()
        .filter(|n| source_name_ok(n))
        .ok_or(DetectError::FormatNotAllowed)?
        .to_owned();
    let src = open_source(source)?;
    let quarantine = Quarantine::create(&lib.dirs.quarantine, &mut lib.next_quarantine)?;
    let mut copy = quarantine.create_file()?;
    let (format, hasher) = copy_checked(src, &mut copy, candidate)?;
    let size = check_copy(&mut copy, format, hasher.bytes())?;
    let digest = hasher.finish();
    if let Some(want) = expected
        && *want != digest
    {
        return Err(LibraryError::HashMismatch {
            expected: want.clone(),
            actual: digest,
        });
    }
    rustix::fs::fchmod(&copy, Mode::from_raw_mode(BLOB_MODE))
        .map_err(|e| LibraryError::io("make the copy read-only", e))?;
    copy.sync_all()
        .map_err(|e| LibraryError::io("sync the quarantine copy", e))?;
    let created = blob::link(quarantine.dir(), &lib.dirs.blobs, &digest)?;
    let entry = Entry {
        digest,
        size,
        format,
        source_name,
        imported_at: jiff::Timestamp::now(),
    };
    if let Err(e) = lib.index.insert(&entry) {
        if created {
            let _ = rustix::fs::unlinkat(&lib.dirs.blobs, entry.digest.as_hex(), AtFlags::empty());
        }
        return Err(e);
    }
    let stored = lib
        .index
        .get(&entry.digest)?
        .ok_or(LibraryError::IndexCorrupt)?;
    drop(quarantine);
    Ok(stored)
}

/// Opens the file to import without following a symlink, and checks it is a regular file.
fn open_source(path: &Path) -> Result<File, LibraryError> {
    let flags = OFlags::RDONLY
        .union(OFlags::NOFOLLOW)
        .union(OFlags::NONBLOCK);
    let fd = match crate::fd::open(path, flags, Mode::empty()) {
        Ok(fd) => fd,
        Err(Errno::LOOP) => return Err(LibraryError::SymlinkInImport),
        Err(e) => return Err(LibraryError::io("open the file to import", e)),
    };
    let st = rustix::fs::fstat(&fd).map_err(|e| LibraryError::io("stat the file to import", e))?;
    if FileType::from_raw_mode(st.st_mode) == FileType::RegularFile {
        Ok(File::from(fd))
    } else {
        Err(LibraryError::NotRegularFile)
    }
}

/// Copies `src` into `dst` in one pass, hashing every byte written; the magic check runs on the
/// first bytes before anything else is read.
fn copy_checked(
    src: File,
    dst: &mut File,
    candidate: Candidate,
) -> Result<(Format, Hasher), LibraryError> {
    let read_err = |e| LibraryError::io("read the file to import", e);
    let mut reader = BufReader::with_capacity(COPY_BUFFER, src);
    let mut head = Vec::new();
    (&mut reader)
        .take(MAGIC_LEN)
        .read_to_end(&mut head)
        .map_err(read_err)?;
    let format = candidate.check_magic(&head)?;
    let mut hasher = Hasher::default();
    write_hashed(dst, &mut hasher, &head)?;
    // A read interrupted by a signal fails the import (fail closed); the caller may retry.
    loop {
        let chunk = reader.fill_buf().map_err(read_err)?;
        if chunk.is_empty() {
            break;
        }
        write_hashed(dst, &mut hasher, chunk)?;
        let used = chunk.len();
        reader.consume(used);
    }
    Ok((format, hasher))
}

/// Writes `chunk` to the copy and feeds it to the hash.
fn write_hashed(dst: &mut File, hasher: &mut Hasher, chunk: &[u8]) -> Result<(), LibraryError> {
    dst.write_all(chunk)
        .map_err(|e| LibraryError::io("write the quarantine copy", e))?;
    hasher.update(chunk);
    Ok(())
}

/// Checks the copy's length against the bytes copied, then parses it from byte 0 against that
/// length. Returns the length.
fn check_copy(copy: &mut File, format: Format, copied: u64) -> Result<u64, LibraryError> {
    let on_disk = copy
        .metadata()
        .map_err(|e| LibraryError::io("stat the quarantine copy", e))?
        .len();
    let size = same_length(copied, on_disk)?;
    copy.seek(SeekFrom::Start(0))
        .map_err(|e| LibraryError::io("rewind the quarantine copy", e))?;
    match format {
        Format::Gguf => gguf::parse(&*copy, size)?,
    };
    Ok(size)
}

/// The copy's length, when the bytes copied and the length on disk agree.
pub(super) fn same_length(copied: u64, on_disk: u64) -> Result<u64, LibraryError> {
    if copied == on_disk {
        Ok(copied)
    } else {
        Err(LibraryError::QuarantineChanged)
    }
}

#[cfg(test)]
#[path = "import_tests.rs"]
mod tests;
