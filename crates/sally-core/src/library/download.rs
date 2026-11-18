//! A model download in progress, its verify, and its promote: the second way bytes enter
//! `blobs/`.
//!
//! The partial is `downloads/<hex>.part`, named by the digest its publisher lists, the only
//! name a caller can choose being the validated [`Digest`]. It is opened beneath the pinned
//! `downloads/` descriptor without `O_EXCL` (a resume opens the same file) and checked on the
//! descriptor: a regular file of the current user with mode exactly 0600 and one link. Anything
//! else is refused and left as it was found, never repaired. Then an exclusive, non-blocking
//! `flock` is taken and bound to the name: after the lock the name must still be the locked
//! file (same device and inode, not followed), or the begin is refused busy; the file is checked
//! again on the locked descriptor. The lock is held for the life of the [`Download`] and the
//! [`Verified`] made from it; a second download of the same digest is refused busy. The lock
//! dies with its process, so a stopped download leaves a resumable file and no stale lock.
//!
//! The link-count check stops a second name (a hard link to a file elsewhere) being taken as a
//! partial and appended to, emptied or made read-only. A process of the same user can still
//! change `downloads/` itself; what such a change can do is bounded by the checks above and by
//! the hash, which runs on the very descriptor that is stored.
//!
//! A partial is never executed, never mounted, never listed, and is opened only here. It lies
//! outside `blobs/`, and nothing reads it as a model until verify has checked its SHA-256.
//!
//! Admission is checked before the file is created, again on the length found, and before
//! every append: what is left to fetch plus a twentieth of the size (rounded up) must fit above
//! the reserve the download began with. A partial already complete needs no room. It is a
//! check, not a reservation: concurrent writers can overshoot it by what they write between
//! two checks.
//!
//! [`Download::verify`], in this order, on the library's own descriptor, without the library:
//! 1. The length on disk equals the listed size. Shorter is incomplete and kept for a resume;
//!    longer is refused and deleted.
//! 2. One pass from byte 0 computes the SHA-256 of every byte on disk, whichever run wrote it,
//!    and compares it with the publisher's. Nothing else has read the bytes before this.
//! 3. Only on a match: the magic check, then the strict header parse against the length on
//!    disk; then the file is synced.
//!
//! A refusal from step 2 on deletes the partial: a file that failed its hash is never resumed.
//! A [`Verified`] dropped before its promote leaves a 0600 partial, which the next begin
//! resumes at its full length and verifies again from byte 0.
//!
//! [`Library::promote`] is then only the tail shared with import: read-only, synced, linked
//! under the digest, the row; then the partial's name is removed (the blob keeps the file). A
//! tail refusal deletes the partial, except [`LibraryError::BlobChanged`] (the name no longer
//! names the verified file), which leaves the name as found.
//!
//! The file name the publisher lists passes the same allowlist and name check as an import
//! before anything is created.

// TODO(#211): a later sweep of downloads/ takes the same lock, non-blocking, and never touches a
// partial another download holds; how long a stale partial is kept is decided there.

use std::ffi::OsStr;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::os::unix::fs::FileExt;

use rustix::fd::OwnedFd;
use rustix::fs::{AtFlags, FileType, FlockOperation, Mode, OFlags, Stat};
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
/// [`Library::begin_download`]; consumed by [`Download::verify`] or [`Download::discard`], or
/// dropped (the partial is kept and the lock released).
#[derive(Debug)]
pub struct Download {
    file: File,
    dir: OwnedFd,
    name: String,
    expected: Digest,
    size: u64,
    written: u64,
    reserve: u64,
    source_name: SourceName,
}

/// A download whose length, publisher's SHA-256, magic and header all passed, still locked.
/// Made only by [`Download::verify`], never cloned; consumed by [`Library::promote`], or
/// dropped (the 0600 partial is kept and verified again by the next download).
#[derive(Debug)]
pub struct Verified {
    download: Download,
    format: Format,
}

impl Verified {
    /// The digest the bytes were verified against.
    #[must_use]
    pub const fn digest(&self) -> &Digest {
        &self.download.expected
    }
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

    /// Appends `chunk` to the partial at its own offset, after checking the room again.
    ///
    /// # Errors
    /// [`LibraryError::DownloadTooLong`] when the chunk would take the partial past its size,
    /// [`LibraryError::InsufficientDisk`] when the rest of the file plus its slack no longer
    /// fits above the reserve (nothing of the chunk is written either way; the partial is
    /// kept), or an I/O error.
    pub fn append(&mut self, chunk: &[u8]) -> Result<(), LibraryError> {
        let available = free_space(&self.dir)?;
        self.append_with(chunk, available)
    }

    /// [`Download::append`] with `available` bytes free.
    fn append_with(&mut self, chunk: &[u8], available: u64) -> Result<(), LibraryError> {
        let len = u64::try_from(chunk.len()).map_err(|_| LibraryError::DownloadTooLong)?;
        let after = self
            .written
            .checked_add(len)
            .filter(|after| *after <= self.size)
            .ok_or(LibraryError::DownloadTooLong)?;
        if !admits_download(self.size, self.written, available, self.reserve) {
            return Err(LibraryError::InsufficientDisk { size: self.size });
        }
        self.file
            .write_all_at(chunk, self.written)
            .map_err(|e| LibraryError::io("write the download", e))?;
        self.written = after;
        Ok(())
    }

    /// Empties the partial; the download goes on from byte 0.
    ///
    /// # Errors
    /// An I/O error.
    pub fn restart(&mut self) -> Result<(), LibraryError> {
        empty(&self.file)?;
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

    /// Verifies the finished partial on its own descriptor: its length, then the SHA-256 of
    /// every byte on disk from byte 0 against the publisher's, then the magic and the strict
    /// header parse; then syncs it. Needs no library, so a caller runs it without the
    /// library's lock.
    ///
    /// # Errors
    /// [`LibraryError::DownloadIncomplete`] for a short partial (kept for a resume); otherwise
    /// the partial is deleted and the error is [`LibraryError::DownloadTooLong`],
    /// [`LibraryError::HashMismatch`], [`LibraryError::Detect`], [`LibraryError::Gguf`], or an
    /// I/O error. An I/O error while hashing keeps the partial; whoever resumes it hashes it
    /// again from byte 0.
    pub fn verify(mut self) -> Result<Verified, LibraryError> {
        let on_disk = length(&self.file)?;
        if on_disk < self.size {
            return Err(LibraryError::DownloadIncomplete {
                have: on_disk,
                size: self.size,
            });
        }
        if on_disk > self.size {
            return Err(self.refuse(LibraryError::DownloadTooLong));
        }
        let actual = hash_from_start(&mut self.file, self.size)?;
        if actual != self.expected {
            let expected = self.expected.clone();
            return Err(self.refuse(LibraryError::HashMismatch { expected, actual }));
        }
        match self.check_matched() {
            Ok(format) => Ok(Verified {
                download: self,
                format,
            }),
            Err(e) => Err(self.refuse(e)),
        }
    }

    /// Step 3 of verify, after the digest matched: magic, parse, sync. Returns the format.
    fn check_matched(&self) -> Result<Format, LibraryError> {
        let mut head = [0_u8; MAGIC_LEN];
        self.file
            .read_exact_at(&mut head, 0)
            .map_err(|e| LibraryError::io("read the download", e))?;
        // The name passed the same check when the download began; the candidate is single-use.
        let format =
            detect::by_name(OsStr::new(self.source_name.as_raw_str()))?.check_magic(&head)?;
        (&self.file)
            .seek(SeekFrom::Start(0))
            .map_err(|e| LibraryError::io("rewind the download", e))?;
        match format {
            Format::Gguf => gguf::parse(&self.file, self.size)?,
        };
        self.file
            .sync_all()
            .map_err(|e| LibraryError::io("sync the download", e))?;
        Ok(format)
    }

    /// Deletes the partial and returns `err`. A partial that could not be removed survives
    /// only as bytes: the next begin checks it, and its verify hashes it again from byte 0;
    /// it is never trusted.
    fn refuse(self, err: LibraryError) -> LibraryError {
        let _ = self.discard();
        err
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
    let fd = open_unlocked(lib, &name, size)?;
    let file = File::from(lock_and_bind(fd, &lib.dirs.downloads, &name)?);
    let on_disk = length(&file)?;
    let written = start_offset(on_disk, size);
    if written != on_disk {
        empty(&file)?;
    }
    admit(lib, size, written)?;
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
        reserve: lib.reserve,
        source_name,
    })
}

/// Opens the partial `name`, creating it at 0600 (after the admission check) when there is
/// none, and checks it on the descriptor. Not locked yet.
fn open_unlocked(lib: &Library, name: &str, size: u64) -> Result<OwnedFd, LibraryError> {
    let fd = match open_part(&lib.dirs.downloads, name, OFlags::empty()) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => {
            admit(lib, size, 0)?;
            open_part(&lib.dirs.downloads, name, OFlags::CREATE).map_err(open_err)?
        }
        Err(e) => return Err(open_err(e)),
    };
    check_private(&fd)?;
    Ok(fd)
}

/// Locks the opened partial and binds the lock to `name`: once locked, `name` beneath `dir`
/// (not followed) must still be this file, or another download replaced or removed it in
/// between and this one is refused busy. The file is then checked again on the locked
/// descriptor.
fn lock_and_bind(fd: OwnedFd, dir: &OwnedFd, name: &str) -> Result<OwnedFd, LibraryError> {
    match rustix::fs::flock(&fd, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => {}
        Err(Errno::WOULDBLOCK) => return Err(LibraryError::DownloadBusy),
        Err(e) => return Err(LibraryError::io("lock the download", e)),
    }
    let own = rustix::fs::fstat(&fd).map_err(|e| LibraryError::io("stat the download", e))?;
    match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(at) if (at.st_dev, at.st_ino) == (own.st_dev, own.st_ino) => {}
        Ok(_) | Err(Errno::NOENT) => return Err(LibraryError::DownloadBusy),
        Err(e) => return Err(LibraryError::io("stat the download", e)),
    }
    check_private(&fd)?;
    Ok(fd)
}

/// Stats the partial on its descriptor and refuses it unless [`part_ok`].
fn check_private(fd: &OwnedFd) -> Result<Stat, LibraryError> {
    let st = rustix::fs::fstat(fd).map_err(|e| LibraryError::io("stat the download", e))?;
    let euid = rustix::process::geteuid().as_raw();
    if part_ok(st.st_mode, st.st_nlink, st.st_uid, euid) {
        Ok(st)
    } else {
        Err(LibraryError::DownloadNotPrivate)
    }
}

/// [`Library::promote`]: the tail shared with import, on the verified descriptor.
pub(super) fn promote(lib: &mut Library, v: Verified) -> Result<Entry, LibraryError> {
    let d = &v.download;
    let entry = Entry {
        digest: d.expected.clone(),
        size: d.size,
        format: v.format,
        source_name: d.source_name.clone(),
        imported_at: jiff::Timestamp::now(),
    };
    match store(lib, &d.file, &d.dir, &d.name, entry) {
        Ok(entry) => {
            // The row is written and the blob holds the file. If this unlink fails, a 0444
            // second link is left under downloads/: the next begin refuses it as not private,
            // and nothing reads it as a model.
            // TODO(#211): the sweep removes a 0444 leftover whose digest is stored.
            let _ = rustix::fs::unlinkat(&d.dir, d.name.as_str(), AtFlags::empty());
            Ok(entry)
        }
        // The name is another file now: it is left as found.
        Err(LibraryError::BlobChanged) => Err(LibraryError::BlobChanged),
        Err(e) => Err(v.download.refuse(e)),
    }
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

/// Truncates the partial to 0 in place. The name is kept: the lock is on this file, and a new
/// file under the name would reopen the race the lock's binding closes. Writes are positional,
/// so no cursor needs moving.
fn empty(file: &File) -> Result<(), LibraryError> {
    file.set_len(0)
        .map_err(|e| LibraryError::io("empty the download", e))
}

/// Free bytes for an unprivileged writer on the filesystem of `dir`.
fn free_space(dir: &OwnedFd) -> Result<u64, LibraryError> {
    let vfs = rustix::fs::fstatvfs(dir)
        .map_err(|e| LibraryError::io("check the library's free space", e))?;
    Ok(vfs.f_bavail.saturating_mul(vfs.f_frsize))
}

/// Refuses a download of `size` bytes with `on_disk` already fetched that does not fit.
fn admit(lib: &Library, size: u64, on_disk: u64) -> Result<(), LibraryError> {
    let available = free_space(&lib.dirs.downloads)?;
    if admits_download(size, on_disk, available, lib.reserve) {
        Ok(())
    } else {
        Err(LibraryError::InsufficientDisk { size })
    }
}

/// Whether the rest of a download (`size - on_disk` bytes) plus `ceil(size / 20)` fits in
/// `available` bytes while leaving `reserve` free. A partial already complete (`on_disk >=
/// size`) writes nothing more and is admitted. An admission check only.
pub(super) fn admits_download(size: u64, on_disk: u64, available: u64, reserve: u64) -> bool {
    if on_disk >= size {
        return true;
    }
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

/// A regular file of `euid` with mode exactly 0600 and exactly one link. Unlike a blob (whose
/// link count is not checked), a partial is appended to, emptied and made read-only, and no
/// partial the library made has a second name.
pub(super) fn part_ok(st_mode: u32, nlink: u64, uid: u32, euid: u32) -> bool {
    FileType::from_raw_mode(st_mode) == FileType::RegularFile
        && nlink == 1
        && uid == euid
        && st_mode & 0o7777 == PART_MODE
}

#[cfg(test)]
#[path = "download_tests.rs"]
mod tests;
