#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::os::unix::fs::symlink;
use std::path::Path;

use super::*;
use crate::library::Library;
use crate::library::testkit::{TmpRoot, chmod, mode, names};

const DIR: u32 = 0o040_000;
const FILE: u32 = 0o100_000;
const ME: u32 = 1000;

/// Open lays out library/, blobs/sha256/ and quarantine/ at exactly 0700, and opens again.
#[test]
fn open_creates_the_tree_private_and_reopens() {
    let root = TmpRoot::new("dirs-fresh");
    drop(Library::open(root.path(), 0).unwrap());
    for d in [
        root.lib(),
        root.lib().join("blobs"),
        root.blobs(),
        root.quarantine(),
    ] {
        assert_eq!(mode(&d), 0o700, "{}", d.display());
    }
    assert_eq!(names(&root.lib()), ["blobs", "library.db", "quarantine"]);
    drop(Library::open(root.path(), 0).unwrap());
}

/// Each directory of the tree, found with a wider mode, is refused and left as it was.
#[test]
fn a_dir_with_another_mode_is_refused_unchanged() {
    for (rel, bad) in [
        ("library", 0o750),
        ("library/blobs", 0o711),
        ("library/blobs/sha256", 0o701),
        ("library/quarantine", 0o755),
        ("library/quarantine", 0o500),
    ] {
        let root = TmpRoot::new("dirs-mode");
        drop(Library::open(root.path(), 0).unwrap());
        let dir = root.path().join(rel);
        chmod(&dir, bad);
        let err = Library::open(root.path(), 0).err().unwrap();
        assert_eq!(err.code(), "not_private", "{rel} {bad:o}");
        assert!(err.to_string().contains(rel), "{rel}: {err}");
        assert!(
            err.to_string().contains(&format!("mode is {bad:04o}")),
            "{err}"
        );
        assert_eq!(mode(&dir), bad, "{rel} was changed");
        chmod(&dir, 0o700);
    }
}

/// A symlink in place of a directory of the tree is refused; its target is not touched.
#[test]
fn a_symlinked_dir_is_refused() {
    let root = TmpRoot::new("dirs-link");
    let elsewhere = root.path().join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    chmod(&elsewhere, 0o700);
    symlink(&elsewhere, root.lib()).unwrap();
    let err = Library::open(root.path(), 0).err().unwrap();
    assert_eq!(err.code(), "not_private", "{err}");
    assert!(err.to_string().contains("not a symlink"), "{err}");
    assert!(names(&elsewhere).is_empty());
}

/// A regular file in place of a directory of the tree is refused and left as it was.
#[test]
fn a_file_in_place_of_a_dir_is_refused() {
    let root = TmpRoot::new("dirs-file");
    std::fs::write(root.lib(), b"x").unwrap();
    let err = Library::open(root.path(), 0).err().unwrap();
    assert_eq!(err.code(), "not_private", "{err}");
    assert_eq!(std::fs::read(root.lib()).unwrap(), b"x");
}

/// The data directory must be absolute, exist and be private: relative is refused, missing
/// is an I/O error, group-writable is refused, and nothing is created in any case.
#[test]
fn the_data_dir_must_exist_and_be_private() {
    let root = TmpRoot::new("dirs-root");
    let err = Library::open(Path::new("relative-data"), 0).err().unwrap();
    assert_eq!(err.code(), "not_private");
    assert!(err.to_string().contains("absolute"), "{err}");
    assert!(!Path::new("relative-data").exists());
    let missing = root.path().join("missing");
    let err = Library::open(&missing, 0).err().unwrap();
    assert_eq!(err.code(), "io_error");
    assert!(!missing.exists());
    chmod(root.path(), 0o770);
    let err = Library::open(root.path(), 0).err().unwrap();
    assert_eq!(err.code(), "not_private");
    assert!(!root.lib().exists());
    chmod(root.path(), 0o700);
}

/// The data directory's descriptor rule: a directory of the current user or root, not
/// writable by group or others.
#[test]
fn data_dir_ok_follows_the_path_rule() {
    assert!(data_dir_ok(DIR | 0o700, ME, ME));
    assert!(data_dir_ok(DIR | 0o755, 0, ME), "root-owned");
    assert!(data_dir_ok(DIR | 0o1755, ME, ME), "sticky");
    assert!(!data_dir_ok(DIR | 0o700, ME + 1, ME), "other owner");
    assert!(!data_dir_ok(FILE | 0o700, ME, ME), "not a directory");
    for bad in [0o720, 0o702, 0o777] {
        assert!(!data_dir_ok(DIR | bad, ME, ME), "{bad:o}");
    }
}

/// Two stat results name the same object only when device and inode both match.
#[test]
fn same_object_needs_device_and_inode() {
    assert!(same_object((1, 2), (1, 2)));
    assert!(!same_object((1, 2), (1, 3)));
    assert!(!same_object((1, 2), (4, 2)));
}

/// A library path checked against its own descriptor passes; against another one it is
/// refused.
#[test]
fn path_is_fd_compares_the_objects() {
    let root = TmpRoot::new("dirs-same");
    drop(Library::open(root.path(), 0).unwrap());
    let open = |p: &Path| {
        crate::fd::open(p, OFlags::RDONLY.union(OFlags::DIRECTORY), Mode::empty()).unwrap()
    };
    path_is_fd(&root.lib(), &open(&root.lib())).unwrap();
    let err = path_is_fd(&root.lib(), &open(&root.blobs())).unwrap_err();
    assert_eq!(err.code(), "not_private");
}

/// The fd check: a directory, the current user's, mode exactly 0700.
#[test]
fn private_dir_is_exactly_an_own_0700_directory() {
    assert!(private_dir(DIR | 0o700, ME, ME));
    assert!(!private_dir(DIR | 0o700, 0, ME), "root-owned");
    assert!(!private_dir(DIR | 0o700, ME + 1, ME), "other owner");
    assert!(!private_dir(FILE | 0o700, ME, ME), "not a directory");
    for bad in [0o500, 0o600, 0o710, 0o701, 0o770, 0o1700, 0o2700, 0o4700] {
        assert!(!private_dir(DIR | bad, ME, ME), "{bad:o}");
    }
}
