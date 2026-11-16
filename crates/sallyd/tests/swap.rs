//! RT-FS-06 through the launcher: a mount root swapped after validation and before launch is
//! refused by `Launcher::launch_workspace` itself (audited `sandbox.refuse`, reason
//! `mount-changed`), and nothing is created. There is no production hook: the swap happens
//! between `load` (validation) and `launch`. `scan.rs` covers the same check at scan level.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use sallyd::sandbox::LaunchError;

mod common;
use common::container::*;
use common::*;

/// The overlap claim (which opens the root first, without following a symlink) or the launch
/// scan refuses it; both are `mount-changed`. `base`: the audit entries written before the
/// refused launch.
fn refused_as_changed(x: &Lx, e: &LaunchError, tag: &str, base: usize) {
    assert!(
        matches!(e, LaunchError::Scan(_) | LaunchError::Claims(_)),
        "{tag}: {e}"
    );
    assert_eq!(x.events.list()[base..], ["sandbox.refuse"], "{tag}");
    let args = x.events.args("sandbox.refuse").unwrap();
    assert_eq!(args["reason"], "mount-changed", "{tag}: {args}");
    assert!(!x.listed(), "{tag}: nothing was created");
}

/// Swaps `~/code/myproject` after validation with `swap`, then launches. Control, first: the
/// same validated manifest, unswapped, launches on the same fixture and its container is
/// listed by the same probe (`Lx::listed_control`).
async fn swapped(swap: impl Fn(&Path, &Path), tag: &str) {
    let x = Lx::new();
    let v =
        x.f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", "rw")]));
    let base = x.listed_control(&v, &format!("{tag}c")).await;
    let home = x.f.root.join("home");
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    swap(&home.join("code/myproject"), &home);
    let e = x.launch(&v, tag).await.unwrap_err();
    refused_as_changed(&x, &e, tag, base);
}

/// The validated root is moved away and a new directory takes its path.
#[test]
fn rt_fs_06_launch_refuses_a_root_replaced_by_another_directory() {
    rt().block_on(swapped(
        |p, home| {
            std::fs::rename(p, home.join("code/moved")).unwrap();
            std::fs::create_dir(p).unwrap();
        },
        "fs06d",
    ));
}

/// The row's attack: the validated root becomes `~/proj -> ~/.ssh`.
#[test]
fn rt_fs_06_launch_refuses_a_root_replaced_by_a_symlink_to_ssh() {
    rt().block_on(swapped(
        |p, home| {
            std::fs::rename(p, home.join("code/moved")).unwrap();
            std::os::unix::fs::symlink(home.join(".ssh"), p).unwrap();
        },
        "fs06s",
    ));
}
