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
//! A launch whose only consent is a hash of the text (`--accept-manifest`) also needs each mount
//! host written as the folder it resolves to ([`ValidatedManifest::check_hosts_as_written`]):
//! the hash names the text, and a link on a host's way can point elsewhere later. `~` expands
//! against HOME as given, so where HOME's own path goes through a link, every `~` host is
//! refused under the flag (TODO(#255)).
//!
//! TODO(#254): residuals: a link chain that passes through a writable folder at an intermediate
//! hop, a hard link of the manifest file into a writable folder, and a bind of a subdirectory
//! (whose real parents the identity chain does not see; #17).

use std::path::{Path, PathBuf};

use super::paths::{DirId, expand, identity_chain};
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
        "the manifest's folder {} lies inside filesystem.mounts[{mount}] ({}), which the session can \
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

/// Whether a mount of `mode` lets the session change the host folder: `rw` directly, `brokered`
/// through the broker. Exhaustive, so a new mode must say.
fn session_writes(mode: MountMode) -> bool {
    match mode {
        MountMode::Rw | MountMode::Brokered => true,
        MountMode::Ro | MountMode::Staged => false,
    }
}

/// The first `(holder, root)` pair where a writable root holds the holder, by path (the
/// holder's realpath is the root's or lies under it, compared by component) or by identity (the
/// holder's chain holds the root's identity). Pure: the decision of
/// [`ValidatedManifest::check_place`].
fn first_inside<'a>(
    holders: &'a [Holder],
    roots: &'a [Root<'a>],
) -> Option<(&'a Holder, &'a Root<'a>)> {
    let writable = roots.iter().filter(|r| session_writes(r.mode));
    for root in writable {
        for h in holders {
            if h.realpath.starts_with(root.host) || h.chain.contains(&root.id) {
                return Some((h, root));
            }
        }
    }
    None
}

/// A mount host written as another path than the folder it resolved to: through a link, or
/// with `..`. Such a host can resolve to another folder later with the same text, so a hash of
/// the text does not name the folders mounted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "filesystem.mounts[{mount}].host is written {written:?} but resolves to {}: a launch \
     accepted by --accept-manifest needs each mount host written as the folder it is, so \
     write the host as that folder",
    resolved.display()
)]
pub struct HostAsWritten {
    /// The mount's index in `filesystem.mounts`.
    pub mount: usize,
    /// The host as the manifest writes it.
    pub written: String,
    /// The host realpath the summary shows.
    pub resolved: PathBuf,
}

/// The first mount whose host as written (`~` expanded against `home`) is not its resolved
/// realpath (compared by component), with both; a mount missing either is never as written.
/// Pure: the decision of [`ValidatedManifest::check_hosts_as_written`].
fn first_not_as_written<'a>(
    hosts: &[(Option<&'a str>, Option<&'a Path>)],
    home: &Path,
) -> Option<(usize, &'a str, &'a Path)> {
    hosts.iter().enumerate().find_map(|(i, pair)| match *pair {
        (Some(written), Some(resolved))
            if expand(written, home).is_ok_and(|p| p.as_path() == resolved) =>
        {
            None
        }
        (written, resolved) => Some((
            i,
            written.unwrap_or_default(),
            resolved.unwrap_or(Path::new("")),
        )),
    })
}

impl ValidatedManifest {
    /// Refuses a launch accepted by a hash of the text alone when a mount host is not written
    /// as the folder it resolved to: the same text could then mount another folder than the
    /// summary showed. `~` expands against `home` as given, so a home whose own path goes
    /// through a link refuses every `~` host here; write such hosts as their realpaths.
    ///
    /// # Errors
    /// [`HostAsWritten`] naming the first such mount.
    pub fn check_hosts_as_written(&self, home: &Path) -> Result<(), HostAsWritten> {
        let raw = &self.manifest().filesystem.mounts;
        let resolved = self.mounts();
        let hosts: Vec<(Option<&str>, Option<&Path>)> = (0..raw.len().max(resolved.len()))
            .map(|i| {
                (
                    raw.get(i).map(|r| r.host.as_str()),
                    resolved.get(i).map(|m| m.host.as_path()),
                )
            })
            .collect();
        match first_not_as_written(&hosts, home) {
            Some((mount, written, resolved)) => Err(HostAsWritten {
                mount,
                written: written.to_owned(),
                resolved: resolved.to_path_buf(),
            }),
            None => Ok(()),
        }
    }

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

    /// Allow: hosts written as their realpaths, absolute or under `~`. Deny: a host written
    /// through a link, with `..`, or not expandable, and a mount missing either path; the
    /// first such mount is named with both paths.
    #[test]
    fn a_host_must_be_written_as_the_folder_it_resolved_to() {
        let first = |hosts: &[(&str, &Path)], home: &Path| {
            let pairs: Vec<(Option<&str>, Option<&Path>)> =
                hosts.iter().map(|(w, r)| (Some(*w), Some(*r))).collect();
            first_not_as_written(&pairs, home).map(|(i, w, r)| (i, w.to_owned(), r.to_owned()))
        };
        let home = Path::new("/home/u");
        let p = Path::new("/home/u/code/p");
        let q = Path::new("/srv/q");
        assert_eq!(first(&[], home), None);
        assert_eq!(
            first(&[("~/code/p", p), ("/srv/q", q), ("/srv/q/", q)], home),
            None
        );
        // A trailing `/` or `/.` is the same path, as the mount-root check judges it
        // (`paths::check_mount_host`): a root that is a link is refused there in every spelling.
        assert_eq!(
            first(
                &[("~/code/p/.", p), ("/srv/q/.", q), ("~/code/p/./", p)],
                home
            ),
            None
        );
        assert_eq!(first(&[("~", home)], home), None);
        for written in [
            "~/code/link",
            "~/code/x/../p",
            "/home/u/code/P",
            "code/p",
            "~other/p",
        ] {
            assert_eq!(
                first(&[("/srv/q", q), (written, p)], home),
                Some((1, written.to_owned(), p.to_owned())),
                "{written}"
            );
        }
        assert_eq!(
            first(&[("~/code/link", p), ("/srv/x", q)], home).map(|h| h.0),
            Some(0)
        );
        // A home whose own path goes through a link (/home -> var/home): `~` expands against
        // HOME as given, so a `~` host is refused and its realpath, written out, is not.
        let real = Path::new("/var/home/u/code/p");
        assert_eq!(first(&[("~/code/p", real)], home).map(|h| h.0), Some(0));
        assert_eq!(first(&[("/var/home/u/code/p", real)], home), None);
        // A mount missing either path is never as written.
        for pairs in [[(Some("/srv/q"), None)], [(None, Some(q))]] {
            assert_eq!(first_not_as_written(&pairs, home).map(|h| h.0), Some(0));
        }
    }

    /// The check on a real manifest: a host written through a link on its way (validation
    /// refuses a host that is a link itself) is named with both paths; the same folder written
    /// as its realpath passes.
    #[test]
    fn a_validated_mount_written_through_a_link_is_named() {
        use crate::manifest::{HostEnv, load};
        // Under the workspace's target dir: /tmp is never mountable.
        let home = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/tmp")
            .join(format!("sc-aswritten-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(home.join("real/sub")).unwrap();
        let home = std::fs::canonicalize(home).unwrap();
        let real = home.join("real/sub");
        std::os::unix::fs::symlink(home.join("real"), home.join("link")).unwrap();
        let env = HostEnv {
            home: home.clone(),
            other_homes: Vec::new(),
            xdg_config_home: None,
            xdg_data_home: None,
            xdg_state_home: None,
            configured_binaries: Vec::new(),
            xdg_runtime_dir: None,
            podman_storage: Vec::new(),
            env_dirs: Vec::new(),
            nproc: 8,
            mem_bytes: 16 << 30,
        };
        let names = std::collections::BTreeSet::<String>::new();
        let body = |host: &str| {
            format!(
                "apiVersion: sallyport/v1\nkind: Manifest\nname: t\nmodel:\n  ref: any\n\
                 filesystem:\n  mounts:\n    - {{host: \"{host}\", guest: /workspace/p, mode: ro}}\n"
            )
        };
        let v = load(&body("~/link/sub"), &env, &names).unwrap().manifest;
        let e = v.check_hosts_as_written(&env.home).unwrap_err();
        assert_eq!(e.mount, 0);
        assert_eq!(e.written, "~/link/sub");
        assert_eq!(e.resolved, real);
        assert!(e.to_string().contains("filesystem.mounts[0].host"), "{e}");
        assert!(
            e.to_string().ends_with("write the host as that folder"),
            "{e}"
        );
        let v = load(&body("~/real/sub"), &env, &names).unwrap().manifest;
        assert_eq!(v.check_hosts_as_written(&env.home), Ok(()));
        std::fs::remove_dir_all(&home).unwrap();
    }

    #[test]
    fn a_place_that_cannot_be_resolved_is_uninspectable() {
        let s = Scratch::new("gone");
        let e = ManifestPlace::inspect(&s.0.join("missing.yaml")).unwrap_err();
        assert!(matches!(e, LocationError::Uninspectable { .. }), "{e:?}");
        assert!(e.to_string().contains("cannot be inspected"), "{e}");
    }
}
