//! A private directory for one import's copy, removed when the import ends, whatever its outcome.
//!
//! Names are `<pid>-<n>`, `n` from the library's counter. Uniqueness comes from `mkdirat` alone:
//! a name that already exists is skipped, never opened, reused or removed, and after
//! [`MAX_TRIES`] taken names the import is refused. The new directory is opened beneath the
//! quarantine descriptor and only that descriptor is used; cleanup removes only the name this
//! import created. The name is not secret, and it never appears in an error or in the index.

// TODO(#211): a daemon killed mid-import leaves its `<pid>-<n>` directory; sweep those at start.

use std::fs::File;
use std::path::Path;

use rustix::fd::OwnedFd;
use rustix::fs::{AtFlags, Mode, OFlags};
use rustix::io::Errno;

use super::{LibraryError, RESOLVE};

/// Most names one import tries.
pub(super) const MAX_TRIES: u32 = 64;
/// The copy's name inside a quarantine directory.
pub(super) const BLOB: &str = "blob";

/// One import's quarantine directory; dropping it removes the copy and the directory.
pub(super) struct Quarantine<'a> {
    parent: &'a OwnedFd,
    name: String,
    dir: OwnedFd,
}

impl<'a> Quarantine<'a> {
    /// Creates the next free `<pid>-<n>` directory under `parent` (the quarantine directory),
    /// moving `counter` on by one per name tried.
    pub(super) fn create(parent: &'a OwnedFd, counter: &mut u32) -> Result<Self, LibraryError> {
        let pid = std::process::id();
        for _ in 0..MAX_TRIES {
            let n = *counter;
            *counter = n.wrapping_add(1);
            let name = name(pid, n);
            match rustix::fs::mkdirat(parent, name.as_str(), Mode::from_raw_mode(0o700)) {
                Ok(()) => {}
                Err(Errno::EXIST) => continue,
                Err(e) => return Err(LibraryError::io("create a quarantine directory", e)),
            }
            let shown = Path::new("library/quarantine/<new>");
            return match super::dirs::open_private_dir(parent, &name, shown) {
                Ok(dir) => Ok(Self { parent, name, dir }),
                Err(e) => {
                    let _ = rustix::fs::unlinkat(parent, name.as_str(), AtFlags::REMOVEDIR);
                    Err(e)
                }
            };
        }
        Err(LibraryError::QuarantineBusy)
    }

    /// Creates the copy, `blob`, at 0600; it must not exist yet.
    pub(super) fn create_file(&self) -> Result<File, LibraryError> {
        let flags = OFlags::RDWR.union(OFlags::CREATE).union(OFlags::EXCL);
        let fd = crate::fd::openat2(&self.dir, BLOB, flags, Mode::from_raw_mode(0o600), RESOLVE)
            .map_err(|e| LibraryError::io("create the quarantine copy", e))?;
        Ok(File::from(fd))
    }

    /// The directory's descriptor.
    pub(super) const fn dir(&self) -> &OwnedFd {
        &self.dir
    }
}

impl Drop for Quarantine<'_> {
    fn drop(&mut self) {
        let _ = rustix::fs::unlinkat(&self.dir, BLOB, AtFlags::empty());
        let _ = rustix::fs::unlinkat(self.parent, self.name.as_str(), AtFlags::REMOVEDIR);
    }
}

/// The quarantine directory name for process `pid` and counter `n`.
pub(super) fn name(pid: u32, n: u32) -> String {
    format!("{pid}-{n}")
}

#[cfg(test)]
#[path = "quarantine_tests.rs"]
mod tests;
