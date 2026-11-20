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
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

    use super::*;

    fn id(ino: u64) -> DirId {
        DirId { dev: 7, ino }
    }

    fn holder(path: &str, chain: &[u64]) -> Holder {
        Holder {
            realpath: PathBuf::from(path),
            chain: chain.iter().map(|i| id(*i)).collect(),
        }
    }

    fn root(index: usize, host: &str, ino: u64, mode: MountMode) -> Root<'_> {
        Root {
            index,
            host: Path::new(host),
            id: id(ino),
            mode,
        }
    }

    /// The `(holder realpath, root index)` of the first hit.
    fn hit(holders: &[Holder], roots: &[Root<'_>]) -> Option<(String, usize)> {
        first_inside(holders, roots).map(|(h, r)| (h.realpath.display().to_string(), r.index))
    }

    #[test]
    fn a_holder_at_or_under_a_writable_root_is_inside_by_path() {
        for mode in [MountMode::Rw, MountMode::Brokered] {
            let roots = [root(0, "/h/p", 10, mode)];
            let under = [holder("/h/p/sub", &[11, 1])];
            assert_eq!(
                hit(&under, &roots),
                Some(("/h/p/sub".into(), 0)),
                "{mode:?}"
            );
            let at = [holder("/h/p", &[12, 1])];
            assert_eq!(hit(&at, &roots), Some(("/h/p".into(), 0)), "{mode:?}");
        }
    }

    #[test]
    fn a_holder_whose_chain_holds_a_writable_root_is_inside_by_identity() {
        // The path is elsewhere (an alias, or the root renamed): only the identity hits.
        let roots = [root(3, "/h/p", 10, MountMode::Rw)];
        let alias = [holder("/elsewhere/q", &[20, 10, 1])];
        assert_eq!(hit(&alias, &roots), Some(("/elsewhere/q".into(), 3)));
    }

    #[test]
    fn paths_compare_by_component_not_by_prefix() {
        let roots = [root(0, "/h/p", 10, MountMode::Rw)];
        let sibling = [holder("/h/pp", &[11, 1])];
        assert_eq!(hit(&sibling, &roots), None);
        let parent = [holder("/h", &[2, 1])];
        assert_eq!(hit(&parent, &roots), None);
    }

    #[test]
    fn staged_and_read_only_roots_never_refuse() {
        for mode in [MountMode::Staged, MountMode::Ro] {
            let roots = [root(0, "/h/p", 10, mode)];
            let inside = [holder("/h/p", &[10, 1])];
            assert_eq!(hit(&inside, &roots), None, "{mode:?}");
        }
    }

    #[test]
    fn every_holder_and_every_writable_root_is_looked_at() {
        let roots = [
            root(0, "/h/r", 30, MountMode::Ro),
            root(1, "/h/a", 31, MountMode::Rw),
            root(2, "/h/b", 32, MountMode::Brokered),
        ];
        // The second holder (the resolved file's folder) is the one inside the third mount.
        let holders = [
            holder("/h/named", &[40, 1]),
            holder("/h/b/real", &[41, 32, 1]),
        ];
        assert_eq!(hit(&holders, &roots), Some(("/h/b/real".into(), 2)));
        let none = [holder("/h/named", &[40, 1]), holder("/h/r/x", &[42, 30, 1])];
        assert_eq!(hit(&none, &roots), None);
    }

    /// A scratch directory removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let d = std::env::temp_dir().join(format!("sc-place-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            Self(std::fs::canonicalize(&d).unwrap())
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The real walk: a mount root renamed after validation still holds the manifest by
    /// identity, where its old path no longer does.
    #[test]
    fn a_renamed_root_still_holds_the_manifest_by_identity() {
        let s = Scratch::new("rename");
        let p = s.0.join("p");
        std::fs::create_dir(&p).unwrap();
        let pinned = identity_chain(&p).unwrap()[0];
        std::fs::rename(&p, s.0.join("q")).unwrap();
        std::fs::write(s.0.join("q/m.yaml"), "x").unwrap();
        let place = ManifestPlace::inspect(&s.0.join("q/m.yaml")).unwrap();
        assert_eq!(place.file(), s.0.join("q/m.yaml"));
        let old = p.display().to_string();
        let roots = [Root {
            index: 0,
            host: Path::new(&old),
            id: pinned,
            mode: MountMode::Rw,
        }];
        let (h, _) = first_inside(&place.holders, &roots).unwrap();
        assert!(
            !h.realpath.starts_with(&p),
            "the path no longer hits: {h:?}"
        );
    }

    /// Both folders are inspected: the name's (a link inside the folder) and the file's.
    #[test]
    fn the_named_and_the_resolved_folders_are_both_inspected() {
        let s = Scratch::new("link");
        std::fs::create_dir(s.0.join("p")).unwrap();
        std::fs::write(s.0.join("m.yaml"), "x").unwrap();
        std::os::unix::fs::symlink(s.0.join("m.yaml"), s.0.join("p/l.yaml")).unwrap();
        let place = ManifestPlace::inspect(&s.0.join("p/l.yaml")).unwrap();
        assert_eq!(place.file(), s.0.join("m.yaml"));
        let paths: Vec<&Path> = place.holders.iter().map(|h| h.realpath.as_path()).collect();
        assert_eq!(paths, [s.0.join("p").as_path(), s.0.as_path()]);
        for h in &place.holders {
            assert_eq!(h.chain[0], identity_chain(&h.realpath).unwrap()[0]);
        }
    }

    #[test]
    fn a_place_that_cannot_be_resolved_is_uninspectable() {
        let s = Scratch::new("gone");
        let e = ManifestPlace::inspect(&s.0.join("missing.yaml")).unwrap_err();
        assert!(matches!(e, LocationError::Uninspectable { .. }), "{e:?}");
        assert!(e.to_string().contains("cannot be inspected"), "{e}");
    }
}
