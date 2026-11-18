//! Blobs: `blobs/sha256/<hex>`, read-only files named by their SHA-256. A blob is linked in from
//! a verified quarantine copy and never replaced; it is checked again whenever it is opened.

use std::fs::File;

use rustix::fd::OwnedFd;
use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use rustix::io::Errno;

use super::{Entry, LibraryError, RESOLVE};
use crate::model::hash::Digest;

/// Any write bit.
const WRITE_BITS: u32 = 0o222;

/// Links the verified file `name` in `dir` (a quarantine copy or a promoted download, both
/// files the library created) into `blobs` as `<hex>`, never replacing a blob already there, and
/// syncs the directory. Whether this call created the blob. A blob found already there is not
/// checked here: the caller checks it with [`open_checked`] before it writes a row. If the sync
/// fails, a blob this call created is unlinked again.
pub(super) fn link(
    dir: &OwnedFd,
    name: &str,
    blobs: &OwnedFd,
    digest: &Digest,
) -> Result<bool, LibraryError> {
    let created = match rustix::fs::linkat(dir, name, blobs, digest.as_hex(), AtFlags::empty()) {
        Ok(()) => true,
        Err(Errno::EXIST) => false,
        Err(e) => return Err(LibraryError::io("store the blob", e)),
    };
    if let Err(e) = rustix::fs::fsync(blobs) {
        if created {
            let _ = rustix::fs::unlinkat(blobs, digest.as_hex(), AtFlags::empty());
        }
        return Err(LibraryError::io("sync the blobs directory", e));
    }
    Ok(created)
}

/// Opens `entry`'s blob beneath `blobs` and checks it on the descriptor: a regular file of the
/// current user, no write bit, the row's size.
pub(super) fn open_checked(blobs: &OwnedFd, entry: &Entry) -> Result<File, LibraryError> {
    let mismatch = || LibraryError::BlobMismatch(entry.digest.clone());
    let flags = OFlags::RDONLY.union(OFlags::NONBLOCK);
    let fd = match crate::fd::openat2(blobs, entry.digest.as_hex(), flags, Mode::empty(), RESOLVE) {
        Ok(fd) => fd,
        Err(Errno::NOENT | Errno::LOOP) => return Err(mismatch()),
        Err(e) => return Err(LibraryError::io("open the blob", e)),
    };
    let st = rustix::fs::fstat(&fd).map_err(|e| LibraryError::io("stat the blob", e))?;
    let size = u64::try_from(st.st_size).map_err(|_| mismatch())?;
    let euid = rustix::process::geteuid().as_raw();
    if blob_ok(st.st_mode, st.st_uid, euid, size, entry.size) {
        Ok(File::from(fd))
    } else {
        Err(mismatch())
    }
}

/// A regular file of `euid` with no write bit, `size` bytes long where `want` were stored.
///
/// The link count is not checked: a second hard link lets the owner do nothing it cannot do
/// through `blobs/` itself, and another import of the same bytes holds a second link until its
/// quarantine is removed. Nothing here rehashes the blob.
// TODO(#210): the caller that hands a blob to an engine checks its SHA-256 then (SI-6).
pub(super) fn blob_ok(st_mode: u32, uid: u32, euid: u32, size: u64, want: u64) -> bool {
    FileType::from_raw_mode(st_mode) == FileType::RegularFile
        && uid == euid
        && st_mode & WRITE_BITS == 0
        && size == want
}

#[cfg(test)]
#[path = "blob_tests.rs"]
mod tests;
