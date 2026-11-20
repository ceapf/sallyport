//! Where a manifest file may be kept: never inside a folder the same manifest lets its session
//! write (`rw` or `brokered`). A session that could rewrite its own manifest would choose the next
//! session's grants. A launcher that reads a manifest from a file inspects the file's place first
//! ([`ManifestPlace::inspect`]), reads the file it resolved to, validates that text, and asks the
//! result ([`ValidatedManifest::check_place`]) before it sends anything.
//!
//! Two folders are checked: the one holding the name as given (a link inside a writable folder is
//! a name the session can point elsewhere), and the one holding the file the name resolves to.
//! Each is refused when its realpath is, or lies under, a writable mount's root, or when its
//! chain of directory identities holds that root's identity (a bind alias of the folder, or the
//! root renamed after validation). `staged` and `ro` mounts never refuse: the session cannot change
//! the host folder through them.
//!
//! TODO(#254): residuals: a link chain that passes through a writable folder at an intermediate
//! hop, a hard link of the manifest file into a writable folder, and a bind of a subdirectory
//! (whose real parents the identity chain does not see; #17).

use std::path::{Path, PathBuf};

use super::paths::{DirId, identity_chain};
use super::types::MountMode;
use super::validate::ValidatedManifest;

/// A folder that holds the manifest: its realpath and the identities of it and its ancestors.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Holder {
    realpath: PathBuf,
    chain: Vec<DirId>,
}

/// Where a manifest file is: the folders that hold it, and the file its name resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestPlace {
    file: PathBuf,
    holders: Vec<Holder>,
}

/// Why a manifest's place refuses its launch.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LocationError {
    /// The manifest lies inside a folder the manifest lets the session write.
    #[error(
        "the manifest {} lies inside filesystem.mounts[{mount}] ({}), which the session can \
         write: keep the manifest outside every rw and brokered mount",
        manifest.display(),
        root.display()
    )]
    Inside {
        /// The folder holding the manifest (or its name), as a host realpath.
        manifest: PathBuf,
        /// The mount's index in `filesystem.mounts`.
        mount: usize,
        /// The mount's host root, as a realpath.
        root: PathBuf,
    },
    /// The manifest's place could not be inspected.
    #[error("the manifest {} cannot be inspected: {reason}", path.display())]
    Uninspectable {
        /// The name as given.
        path: PathBuf,
        /// The failure.
        reason: String,
    },
}

impl ManifestPlace {
    /// Inspects the place of the manifest named `given`: the folder holding the name (the name
    /// made absolute, its last component not resolved) and the folder holding the file it
    /// resolves to, each with its realpath and identity chain. Reads no file content.
    ///
    /// # Errors
    /// [`LocationError::Uninspectable`] when a path cannot be resolved or a folder walked.
    pub fn inspect(given: &Path) -> Result<Self, LocationError> {
        let failed = |e: std::io::Error| LocationError::Uninspectable {
            path: given.to_path_buf(),
            reason: e.to_string(),
        };
        let absolute = std::path::absolute(given).map_err(failed)?;
        let named_in = absolute
            .parent()
            .ok_or_else(|| failed(std::io::Error::other("the name has no folder")))?;
        let file = std::fs::canonicalize(given).map_err(failed)?;
        let resolved_in = file
            .parent()
            .ok_or_else(|| failed(std::io::Error::other("the file has no folder")))?;
        let holder = |dir: &Path| -> Result<Holder, LocationError> {
            let realpath = std::fs::canonicalize(dir).map_err(failed)?;
            let chain = identity_chain(&realpath).map_err(failed)?;
            Ok(Holder { realpath, chain })
        };
        let holders = vec![holder(named_in)?, holder(resolved_in)?];
        Ok(Self { file, holders })
    }

    /// The file the name resolved to: the one path a launcher reads the manifest's text from.
    #[must_use]
    pub fn file(&self) -> &Path {
        &self.file
    }
}

/// One mount as the place check sees it.
struct Root<'a> {
    index: usize,
    host: &'a Path,
    id: DirId,
    mode: MountMode,
}

/// The first `(holder, root)` pair where a writable root holds the holder, by path (the
/// holder's realpath is the root's or lies under it, compared by component) or by identity (the
/// holder's chain holds the root's identity). Pure: the decision of
/// [`ValidatedManifest::check_place`].
fn first_inside<'a>(
    holders: &'a [Holder],
    roots: &'a [Root<'a>],
) -> Option<(&'a Holder, &'a Root<'a>)> {
    let writable = roots
        .iter()
        .filter(|r| matches!(r.mode, MountMode::Rw | MountMode::Brokered));
    for root in writable {
        for h in holders {
            if h.realpath.starts_with(root.host) || h.chain.contains(&root.id) {
                return Some((h, root));
            }
        }
    }
    None
}

impl ValidatedManifest {
    /// Refuses a launch of this manifest from `place` when a folder holding it lies inside one of
    /// the manifest's `rw` or `brokered` mounts (module docs).
    ///
    /// # Errors
    /// [`LocationError::Inside`] naming the folder and the mount.
    pub fn check_place(&self, place: &ManifestPlace) -> Result<(), LocationError> {
        let roots: Vec<Root<'_>> = self
            .mounts()
            .iter()
            .enumerate()
            .map(|(index, m)| {
                let (dev, ino) = m.identity();
                Root {
                    index,
                    host: &m.host,
                    id: DirId { dev, ino },
                    mode: m.mode,
                }
            })
            .collect();
        match first_inside(&place.holders, &roots) {
            Some((h, r)) => Err(LocationError::Inside {
                manifest: h.realpath.clone(),
                mount: r.index,
                root: r.host.to_path_buf(),
            }),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
#[path = "location_tests.rs"]
mod tests;
