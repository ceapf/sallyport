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

/// The real walk: a mount root renamed after validation still holds the manifest by identity,
/// where its old path no longer does.
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
