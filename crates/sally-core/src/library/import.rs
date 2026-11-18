//! The import: the whole SI-6 chain on a private copy, in this order.
//!
//! 1. The file name through [`detect::by_name`] and the library's own name check (no control
//!    character, at most 255 bytes), before anything is opened.
//! 2. The source opened `O_RDONLY | O_NOFOLLOW | O_NONBLOCK` and checked on the descriptor: a
//!    regular file. A symlink is refused, never followed. Its size must fit in the library
//!    filesystem's free space less the reserve.
//! 3. One pass copies the source into a fresh quarantine directory while hashing it; the first
//!    four bytes go through the magic check before the copy goes on. The bytes checked, hashed
//!    and stored are the same bytes. The copy stops one byte past the source's size, and that
//!    byte refuses the import (the source grew).
//! 4. The strict header parse of the copy from byte 0, against the copy's own length, which
//!    must equal the bytes copied.
//! 5. The digest compared with the expected one, when given. A model downloaded against its
//!    publisher's hash does not come this way: the pull's promote (`download.rs`) checks that
//!    hash before anything else reads the file.
//! 6. The copy made 0444 and synced, then linked into `blobs/sha256/<hex>` without replacing
//!    a blob already there. A blob found there is used only if it passes inspect's checks
//!    against this import's size; otherwise the import is refused and the blob left as found.
//! 7. The row, then the quarantine directory removed.
//!
//! Any refusal removes the quarantine directory and leaves no blob and no row. The source is
//! only ever read.
#![deny(clippy::indexing_slicing)]

use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;

use rustix::fd::OwnedFd;
use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use rustix::io::Errno;

use super::quarantine::{BLOB, Quarantine};
use super::{Entry, Library, LibraryError, SourceName, blob};
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
        .and_then(SourceName::checked)
        .ok_or(LibraryError::SourceNameNotAllowed)?;
    let (src, source_size) = open_source(source)?;
    let vfs = rustix::fs::fstatvfs(&lib.dirs.blobs)
        .map_err(|e| LibraryError::io("check the library's free space", e))?;
    let available = vfs.f_bavail.saturating_mul(vfs.f_frsize);
    if !admits(source_size, available, lib.reserve) {
        return Err(LibraryError::InsufficientDisk { size: source_size });
    }
    let quarantine = Quarantine::create(&lib.dirs.quarantine, &mut lib.next_quarantine)?;
    let mut copy = quarantine.create_file()?;
    let (format, hasher) = copy_checked(src, source_size, &mut copy, candidate)?;
    not_grown(hasher.bytes(), source_size)?;
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
    let entry = Entry {
        digest,
        size,
        format,
        source_name,
        imported_at: jiff::Timestamp::now(),
    };
    let stored = store(lib, &copy, quarantine.dir(), BLOB, entry)?;
    drop(quarantine);
    Ok(stored)
}

/// The tail shared by import and promote, once every check of the chain has passed on `file`
/// (the library's own file `name` in `dir`): read-only, synced, linked under its digest (a blob
/// found already there is used only if it passes inspect's checks against this size, and is
/// never changed), then the row. Returns the row as stored.
pub(super) fn store(
    lib: &Library,
    file: &File,
    dir: &OwnedFd,
    name: &str,
    entry: Entry,
) -> Result<Entry, LibraryError> {
    rustix::fs::fchmod(file, Mode::from_raw_mode(BLOB_MODE))
        .map_err(|e| LibraryError::io("make the file read-only", e))?;
    file.sync_all()
        .map_err(|e| LibraryError::io("sync the verified file", e))?;
    let created = blob::link(dir, name, &lib.dirs.blobs, &entry.digest)?;
    if !created {
        drop(blob::open_checked(&lib.dirs.blobs, &entry)?);
    }
    if let Err(e) = lib.index.insert(&entry) {
        if created {
            let _ = rustix::fs::unlinkat(&lib.dirs.blobs, entry.digest.as_hex(), AtFlags::empty());
        }
        return Err(e);
    }
    lib.index
        .get(&entry.digest)?
        .ok_or(LibraryError::IndexCorrupt)
}

/// Whether a file of `size` bytes fits in `available` bytes while leaving `reserve` free. An
/// admission check only: other writers can use the space while the copy runs.
pub(super) fn admits(size: u64, available: u64, reserve: u64) -> bool {
    available
        .checked_sub(reserve)
        .is_some_and(|room| size <= room)
}

/// The copy stops one byte past the source's size; that byte means the source grew.
pub(super) fn not_grown(copied: u64, source_size: u64) -> Result<(), LibraryError> {
    if copied > source_size {
        Err(LibraryError::SourceChanged)
    } else {
        Ok(())
    }
}

/// Opens the file to import without following a symlink, and checks it is a regular file.
/// Returns it with its size.
fn open_source(path: &Path) -> Result<(File, u64), LibraryError> {
    let flags = OFlags::RDONLY
        .union(OFlags::NOFOLLOW)
        .union(OFlags::NONBLOCK);
    let fd = match crate::fd::open(path, flags, Mode::empty()) {
        Ok(fd) => fd,
        Err(Errno::LOOP) => return Err(LibraryError::SymlinkInImport),
        Err(e) => return Err(LibraryError::io("open the file to import", e)),
    };
    let st = rustix::fs::fstat(&fd).map_err(|e| LibraryError::io("stat the file to import", e))?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Err(LibraryError::NotRegularFile);
    }
    let size = u64::try_from(st.st_size).map_err(|_| LibraryError::NotRegularFile)?;
    Ok((File::from(fd), size))
}

/// Copies at most `source_size + 1` bytes of `src` into `dst` in one pass, hashing every byte
/// written; the magic check runs on the first bytes before anything else is read.
fn copy_checked(
    src: File,
    source_size: u64,
    dst: &mut File,
    candidate: Candidate,
) -> Result<(Format, Hasher), LibraryError> {
    let read_err = |e| LibraryError::io("read the file to import", e);
    let bounded = src.take(source_size.saturating_add(1));
    let mut reader = BufReader::with_capacity(COPY_BUFFER, bounded);
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
