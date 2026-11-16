//! Unit tests of [`Walk::of_mount`] (architect Q216 (iii): every named constructor of the
//! `fn new` sweep has direct tests).
#![allow(clippy::unwrap_used)]

use std::os::unix::fs::MetadataExt as _;

use super::*;
use crate::egress::scratch::Scratch;

/// A fresh directory under `target/scan-unit`, canonical, and its guard, which removes it on drop
/// so a failing assertion leaves nothing behind.
fn scratch(tag: &str) -> (PathBuf, Scratch) {
    let guard = crate::egress::scratch::scratch("scan-unit", tag);
    (std::fs::canonicalize(&*guard).unwrap(), guard)
}

/// A manifest whose home is `dir/home`, with `~/a` (`rw`, mount 0) and `~/b` (`staged`, mount 1).
fn manifest(dir: &Path) -> ValidatedManifest {
    use sally_core::manifest::{HostEnv, load};
    let home = dir.join("home");
    for d in ["a", "b"] {
        std::fs::create_dir_all(home.join(d)).unwrap();
    }
    let env = HostEnv {
        home: home.clone(),
        other_homes: Vec::new(),
        xdg_config_home: None,
        xdg_data_home: None,
        xdg_runtime_dir: None,
        podman_storage: Vec::new(),
        nproc: 8,
        mem_bytes: 16 << 30,
    };
    let body = "apiVersion: sallyport/v1\nkind: Manifest\nname: t\nmodel:\n  ref: any\n\
                filesystem:\n  mounts:\n    - {host: \"~/a\", guest: /workspace/a, mode: rw}\n\
                \x20   - {host: \"~/b\", guest: /workspace/b, mode: staged}\n";
    load(body, &env, &std::collections::BTreeSet::new())
        .unwrap()
        .manifest
}

/// A walk starts at the validated root, holding it open, with the root's own mount id and empty
/// counts and records for its own mount index.
#[test]
fn of_mount_opens_the_validated_root_and_records_its_mount_id() {
    let (dir, _gone) = scratch("start");
    let v = manifest(&dir);
    let limits = ScanLimits::default();
    for (i, m) in v.mounts().iter().enumerate() {
        let w = Walk::of_mount(i, m, &limits).unwrap();
        let want = std::fs::metadata(&m.host).unwrap();
        let got = rustix::fs::fstat(&w.root).unwrap();
        assert_eq!((got.st_dev, got.st_ino), (want.dev(), want.ino()), "{i}");
        let mnt = rustix::fs::statx(
            rustix::fs::CWD,
            &m.host,
            AtFlags::empty(),
            StatxFlags::MNT_ID,
        )
        .unwrap()
        .stx_mnt_id;
        assert_eq!(w.root_mnt, mnt, "{i}");
        assert_eq!((w.mount, w.git.mount), (i, i));
        assert_eq!((w.entries, w.pending_bytes), (0, 0));
        assert!(w.git.dirs.is_empty() && w.git.files.is_empty() && w.pins.is_empty());
    }
}

/// A root replaced since validation (by another directory, or by a symlink to the original) is
/// refused as changed, under its own mount index.
#[test]
fn of_mount_refuses_a_root_replaced_since_validation() {
    let (dir, _gone) = scratch("replaced");
    let v = manifest(&dir);
    let limits = ScanLimits::default();
    let m = v.mounts().get(1).unwrap();
    let moved = dir.join("moved");
    std::fs::rename(&m.host, &moved).unwrap();
    std::fs::create_dir(&m.host).unwrap();
    let e = Walk::of_mount(1, m, &limits).err().unwrap();
    assert!(matches!(e, ScanError::Changed { mount: 1, .. }), "{e:?}");
    std::fs::remove_dir(&m.host).unwrap();
    std::os::unix::fs::symlink(&moved, &m.host).unwrap();
    let e = Walk::of_mount(1, m, &limits).err().unwrap();
    assert!(matches!(e, ScanError::Changed { mount: 1, .. }), "{e:?}");
}
