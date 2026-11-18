//! Blobs: `blobs/sha256/<hex>`, read-only files named by their SHA-256. A blob is linked in from
//! a verified quarantine copy and never replaced; it is checked again whenever it is opened.

use std::fs::File;

use rustix::fd::OwnedFd;
use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use rustix::io::Errno;

use super::quarantine::BLOB;
use super::{Entry, LibraryError, RESOLVE};
use crate::model::hash::Digest;

/// Any write bit.
const WRITE_BITS: u32 = 0o222;

/// Links the copy in `qdir` into `blobs` as `<hex>`, never replacing a blob already there, and
/// syncs the directory. Whether this call created the blob (an existing one is success).
pub(super) fn link(qdir: &OwnedFd, blobs: &OwnedFd, digest: &Digest) -> Result<bool, LibraryError> {
    let created = match rustix::fs::linkat(qdir, BLOB, blobs, digest.as_hex(), AtFlags::empty()) {
        Ok(()) => true,
        Err(Errno::EXIST) => false,
        Err(e) => return Err(LibraryError::io("store the blob", e)),
    };
    rustix::fs::fsync(blobs).map_err(|e| LibraryError::io("sync the blobs directory", e))?;
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
pub(super) fn blob_ok(st_mode: u32, uid: u32, euid: u32, size: u64, want: u64) -> bool {
    FileType::from_raw_mode(st_mode) == FileType::RegularFile
        && uid == euid
        && st_mode & WRITE_BITS == 0
        && size == want
}

#[cfg(test)]
#[path = "blob_tests.rs"]
mod tests;
