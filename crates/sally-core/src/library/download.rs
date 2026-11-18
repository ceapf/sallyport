//! A model download in progress, and its promote: the second way bytes enter `blobs/`.
//!
//! The partial is `downloads/<hex>.part`, named by the digest its publisher lists, the only
//! name a caller can choose being the validated [`Digest`]. It is opened beneath the pinned
//! `downloads/` descriptor without `O_EXCL` (a resume opens the same file) and checked on the
//! descriptor: a regular file of the current user with mode exactly 0600. Anything else is
//! refused and left as it was found, never repaired. An exclusive, non-blocking `flock` is held
//! for the life of the [`Download`]; a second download of the same digest is refused busy. The
//! lock dies with its process, so a stopped download leaves a resumable file and no stale lock.
//!
//! A partial is never executed, never mounted, never listed, and is opened only here: by the
//! writer and by promote. It lies outside `blobs/`, and nothing reads it as a model until
//! promote has checked its SHA-256.
//!
//! Admission is checked before the file is created and again on the length found: what is
//! left to fetch plus a twentieth of the size (rounded up) must fit above the reserve.
//!
//! Promote, in this order, on the library's own descriptor:
//! 1. The length on disk equals the listed size. Shorter is incomplete and kept for a resume;
//!    longer is refused and deleted.
//! 2. One pass from byte 0 computes the SHA-256 of every byte on disk, whichever run wrote it,
//!    and compares it with the publisher's. Nothing else has read the bytes before this.
//! 3. Only on a match: the magic check, then the strict header parse against the length on
//!    disk.
//! 4. The tail shared with import: read-only, synced, linked under the digest, the row; then
//!    the partial's name is removed (the blob keeps the file).
//!
//! A refusal from step 2 on deletes the partial: a file that failed its hash is never resumed.
//! The file name the publisher lists passes the same allowlist and name check as an import
//! before anything is created.

// TODO(#211): a later sweep of downloads/ takes the same lock, non-blocking, and never touches a
// partial another download holds; how long a stale partial is kept is decided there.

use std::ffi::OsStr;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;

use rustix::fd::OwnedFd;
use rustix::fs::{AtFlags, FileType, FlockOperation, Mode, OFlags};
use rustix::io::Errno;

use super::import::store;
use super::{Entry, Library, LibraryError, RESOLVE, SourceName};
use crate::model::detect::{self, Format};
use crate::model::gguf;
use crate::model::hash::{Digest, Hasher};

/// The only mode a partial may have.
const PART_MODE: u32 = 0o600;
/// The hash pass's read buffer.
const HASH_BUFFER: usize = 65_536;
/// Bytes the magic check reads.
const MAGIC_LEN: usize = 4;
/// Admission adds `ceil(size / SLACK_DIVISOR)` to the bytes left to fetch.
const SLACK_DIVISOR: u64 = 20;

/// One download in progress: the locked partial and what it must become. Made only by
/// [`Library::begin_download`]; consumed by [`Library::promote`] or [`Download::discard`], or
/// dropped (the partial is kept and the lock released).
#[derive(Debug)]
pub struct Download {
    file: File,
    dir: OwnedFd,
    name: String,
    expected: Digest,
    size: u64,
    written: u64,
    source_name: SourceName,
}

impl Download {
    /// Bytes in the partial: where the download goes on from.
    #[must_use]
    pub const fn written(&self) -> u64 {
        self.written
    }

    /// The file's listed size.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// The SHA-256 the publisher lists.
    #[must_use]
    pub const fn expected(&self) -> &Digest {
        &self.expected
    }

    /// Appends `chunk` to the partial.
    ///
    /// # Errors
    /// [`LibraryError::DownloadTooLong`] when the chunk would take the partial past its size
    /// (nothing of it is written), or an I/O error.
    pub fn append(&mut self, chunk: &[u8]) -> Result<(), LibraryError> {
        let len = u64::try_from(chunk.len()).map_err(|_| LibraryError::DownloadTooLong)?;
        let after = self
            .written
            .checked_add(len)
            .filter(|after| *after <= self.size)
            .ok_or(LibraryError::DownloadTooLong)?;
        self.file
            .write_all(chunk)
            .map_err(|e| LibraryError::io("write the download", e))?;
        self.written = after;
        Ok(())
    }

    /// Empties the partial; the download goes on from byte 0.
    ///
    /// # Errors
    /// An I/O error.
    pub fn restart(&mut self) -> Result<(), LibraryError> {
        empty(&mut self.file)?;
        self.written = 0;
        Ok(())
    }

    /// Deletes the partial.
    ///
    /// # Errors
    /// An I/O error if its name could not be removed.
    pub fn discard(self) -> Result<(), LibraryError> {
        rustix::fs::unlinkat(&self.dir, self.name.as_str(), AtFlags::empty())
            .map_err(|e| LibraryError::io("remove the download", e))
    }
}

/// [`Library::begin_download`].
pub(super) fn begin(
    lib: &mut Library,
    file_name: &str,
    expected: &Digest,
    size: u64,
) -> Result<Download, LibraryError> {
    detect::by_name(OsStr::new(file_name))?;
    let source_name = SourceName::checked(file_name).ok_or(LibraryError::SourceNameNotAllowed)?;
    let name = format!("{}.part", expected.as_hex());
    let fd = match open_part(&lib.dirs.downloads, &name, OFlags::empty()) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => {
            admit(lib, size, 0)?;
            open_part(&lib.dirs.downloads, &name, OFlags::CREATE).map_err(open_err)?
        }
        Err(e) => return Err(open_err(e)),
    };
    let st = rustix::fs::fstat(&fd).map_err(|e| LibraryError::io("stat the download", e))?;
    if !part_ok(st.st_mode, st.st_uid, rustix::process::geteuid().as_raw()) {
        return Err(LibraryError::DownloadNotPrivate);
    }
    match rustix::fs::flock(&fd, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => {}
        Err(Errno::WOULDBLOCK) => return Err(LibraryError::DownloadBusy),
        Err(e) => return Err(LibraryError::io("lock the download", e)),
    }
    let mut file = File::from(fd);
    let on_disk = length(&file)?;
    let written = start_offset(on_disk, size);
    if written != on_disk {
        empty(&mut file)?;
    }
    admit(lib, size, written)?;
    file.seek(SeekFrom::Start(written))
        .map_err(|e| LibraryError::io("seek the download", e))?;
    let dir = lib
        .dirs
        .downloads
        .try_clone()
        .map_err(|e| LibraryError::io("hold the downloads directory", e))?;
    Ok(Download {
        file,
        dir,
        name,
        expected: expected.clone(),
        size,
        written,
        source_name,
    })
}

/// [`Library::promote`].
pub(super) fn promote(lib: &mut Library, mut d: Download) -> Result<Entry, LibraryError> {
    let on_disk = length(&d.file)?;
    if on_disk < d.size {
        return Err(LibraryError::DownloadIncomplete {
            have: on_disk,
            size: d.size,
        });
    }
    if on_disk > d.size {
        return refuse(d, LibraryError::DownloadTooLong);
    }
    let digest = hash_from_start(&mut d.file, d.size)?;
    if digest != d.expected {
        let actual = digest;
        let expected = d.expected.clone();
        return refuse(d, LibraryError::HashMismatch { expected, actual });
    }
    match verified_tail(lib, &d) {
        Ok(entry) => {
            // The blob holds the file now; the partial's name only goes.
            let _ = rustix::fs::unlinkat(&d.dir, d.name.as_str(), AtFlags::empty());
            Ok(entry)
        }
        Err(e) => refuse(d, e),
    }
}

/// Steps 3 and 4 of promote, after the digest matched.
fn verified_tail(lib: &mut Library, d: &Download) -> Result<Entry, LibraryError> {
    let mut head = [0_u8; MAGIC_LEN];
    d.file
        .read_exact_at(&mut head, 0)
        .map_err(|e| LibraryError::io("read the download", e))?;
    // The name passed the same check when the download began; the candidate is single-use.
    let format = detect::by_name(OsStr::new(d.source_name.as_raw_str()))?.check_magic(&head)?;
    (&d.file)
        .seek(SeekFrom::Start(0))
        .map_err(|e| LibraryError::io("rewind the download", e))?;
    match format {
        Format::Gguf => gguf::parse(&d.file, d.size)?,
    };
    let entry = Entry {
        digest: d.expected.clone(),
        size: d.size,
        format,
        source_name: d.source_name.clone(),
        imported_at: jiff::Timestamp::now(),
    };
    store(lib, &d.file, &d.dir, &d.name, entry)
}

/// Deletes the partial and returns `err`.
fn refuse(d: Download, err: LibraryError) -> Result<Entry, LibraryError> {
    // The refusal is the answer; a partial that could not be removed is refused at the next
    // begin's checks or by its hash, never promoted.
    let _ = d.discard();
    Err(err)
}

/// The SHA-256 of the file's first `size` bytes, read from byte 0. The caller has checked the
/// length; a file that shrank meanwhile is incomplete.
fn hash_from_start(file: &mut File, size: u64) -> Result<Digest, LibraryError> {
    let read_err = |e| LibraryError::io("read the download", e);
    file.seek(SeekFrom::Start(0)).map_err(read_err)?;
    let mut reader = BufReader::with_capacity(HASH_BUFFER, (&*file).take(size));
    let mut hasher = Hasher::default();
    loop {
        let chunk = reader.fill_buf().map_err(read_err)?;
        if chunk.is_empty() {
            break;
        }
        hasher.update(chunk);
        let used = chunk.len();
        reader.consume(used);
    }
    if hasher.bytes() != size {
        return Err(LibraryError::DownloadIncomplete {
            have: hasher.bytes(),
            size,
        });
    }
    Ok(hasher.finish())
}

/// Opens the partial `name` beneath `dir`, read-write, with `extra` (`O_CREAT` at 0600, never
/// `O_EXCL`: a download that lost a race to create it opens the winner's and checks it).
fn open_part(dir: &OwnedFd, name: &str, extra: OFlags) -> rustix::io::Result<OwnedFd> {
    let flags = OFlags::RDWR.union(OFlags::NONBLOCK).union(extra);
    // openat2 takes a mode only with O_CREAT.
    let mode = if extra.contains(OFlags::CREATE) {
        Mode::from_raw_mode(PART_MODE)
    } else {
        Mode::empty()
    };
    crate::fd::openat2(dir, name, flags, mode, RESOLVE)
}

/// A failed open of the partial: a symlink in its place, or a file the owner may not open for
/// writing, is not private; the rest is I/O.
fn open_err(e: Errno) -> LibraryError {
    match e {
        Errno::LOOP | Errno::ACCESS => LibraryError::DownloadNotPrivate,
        e => LibraryError::io("open the download", e),
    }
}

/// The partial's length, from its descriptor.
fn length(file: &File) -> Result<u64, LibraryError> {
    file.metadata()
        .map(|m| m.len())
        .map_err(|e| LibraryError::io("stat the download", e))
}

/// Truncates the partial to 0 and rewinds it. The name is kept: the lock is on this file.
fn empty(file: &mut File) -> Result<(), LibraryError> {
    file.set_len(0)
        .map_err(|e| LibraryError::io("empty the download", e))?;
    file.seek(SeekFrom::Start(0))
        .map_err(|e| LibraryError::io("seek the download", e))?;
    Ok(())
}

/// Refuses a download of `size` bytes with `on_disk` already fetched that does not fit.
fn admit(lib: &Library, size: u64, on_disk: u64) -> Result<(), LibraryError> {
    let vfs = rustix::fs::fstatvfs(&lib.dirs.downloads)
        .map_err(|e| LibraryError::io("check the library's free space", e))?;
    let available = vfs.f_bavail.saturating_mul(vfs.f_frsize);
    if admits_download(size, on_disk, available, lib.reserve) {
        Ok(())
    } else {
        Err(LibraryError::InsufficientDisk { size })
    }
}

/// Whether the rest of a download (`size - on_disk` bytes) plus `ceil(size / 20)` fits in
/// `available` bytes while leaving `reserve` free. An admission check only.
pub(super) fn admits_download(size: u64, on_disk: u64, available: u64, reserve: u64) -> bool {
    let rest = size.saturating_sub(on_disk);
    let slack = size.div_ceil(SLACK_DIVISOR);
    let Some(need) = rest.checked_add(slack) else {
        return false;
    };
    available
        .checked_sub(reserve)
        .is_some_and(|room| need <= room)
}

/// Where a download goes on from: the bytes on disk, or 0 when there are more than `size` (the
/// partial is emptied).
pub(super) const fn start_offset(on_disk: u64, size: u64) -> u64 {
    if on_disk > size { 0 } else { on_disk }
}

/// A regular file of `euid` with mode exactly 0600.
pub(super) fn part_ok(st_mode: u32, uid: u32, euid: u32) -> bool {
    FileType::from_raw_mode(st_mode) == FileType::RegularFile
        && uid == euid
        && st_mode & 0o7777 == PART_MODE
}

#[cfg(test)]
#[path = "download_tests.rs"]
mod tests;
