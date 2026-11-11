//! `ResolvedMount::identity` is the real `(st_dev, st_ino)` of the host directory at validation:
//! the value the sandbox driver pins the mount root to (AMENDMENTS-02 B4, RT-FS-06).
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::os::unix::fs::MetadataExt;

use common::Fixture;

/// #33: two different folders report their own real identities, not a constant.
#[test]
fn each_mount_reports_the_real_identity_of_its_folder() {
    let f = Fixture::new();
    let body = "filesystem:\n  mounts:\n    - host: \"~/code/myproject\"\n      guest: /workspace/a\n      mode: ro\n    - host: \"~/code/other\"\n      guest: /workspace/b\n      mode: ro\n";
    let v = f.load(body).unwrap().manifest;
    let real = |rel: &str| {
        let m = std::fs::metadata(f.home().join(rel)).unwrap();
        (m.dev(), m.ino())
    };
    let (a, b) = (real("code/myproject"), real("code/other"));
    assert_ne!(a, b);
    assert_eq!(v.mounts()[0].identity(), a);
    assert_eq!(v.mounts()[1].identity(), b);
}
