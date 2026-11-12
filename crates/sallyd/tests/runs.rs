//! Two runs at once (Task 8 PR C, architect Q23–Q25): two worktrees can run the container
//! tests side by side. Each run's container and image names carry its own run id, and the locks
//! that serialize disk-heavy work are per user, not per target directory.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

mod common;
use common::container::*;

fn scratch(tag: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("runs-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}

#[test]
fn the_run_id_is_eight_lowercase_alphanumerics_and_follows_the_wrapper() {
    let id = run_id();
    assert_eq!(id.len(), 8, "{id}");
    assert!(
        id.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()),
        "{id}"
    );
    if let Ok(set) = std::env::var("SALLYPORT_TEST_RUN") {
        assert_eq!(id, set, "the wrapper's id is the run id");
    }
    assert_eq!(id, run_id(), "one id per process");
}

#[test]
fn a_malformed_run_id_is_refused() {
    for bad in ["", "abc", "abcdefgh1", "ABCDEFGH", "abcd-efg", "abcdefg/"] {
        assert!(parse_run_id(bad).is_none(), "{bad:?}");
    }
    assert_eq!(parse_run_id("a1b2c3d4"), Some("a1b2c3d4"));
}

#[test]
fn every_container_name_carries_the_run_id() {
    let x = Lx::new();
    let want = format!("t{}-{}-", run_id(), std::process::id());
    assert!(x.scope.starts_with(&want), "{} vs {want}", x.scope);
    let id = x
        .paths("a-long-tag-of-thirty-two-chars-x")
        .id()
        .as_str()
        .to_owned();
    assert!(id.starts_with(&want), "{id}");
}

#[test]
fn locks_live_in_the_user_runtime_directory_not_the_worktree() {
    let xdg = PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR").unwrap());
    let p = lock_path("runs-probe");
    assert_eq!(p, xdg.join("sallyport-test/runs-probe.lock"));
    assert!(!p.starts_with(env!("CARGO_TARGET_TMPDIR")));
    let held = lock("runs-probe", false);
    let mode = std::fs::metadata(p.parent().unwrap())
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o700);
    drop(held);
}

#[test]
fn a_lock_file_is_never_truncated() {
    let d = scratch("trunc");
    let dir = lock_dir_in(&d);
    std::fs::write(dir.join("t.lock"), "keep").unwrap();
    drop(open_lock(&dir.join("t.lock")));
    assert_eq!(std::fs::read_to_string(dir.join("t.lock")).unwrap(), "keep");
}

#[test]
fn a_lock_directory_open_to_others_or_a_symlink_is_refused() {
    let d = scratch("loose");
    std::fs::create_dir(d.join("sallyport-test")).unwrap();
    std::fs::set_permissions(
        d.join("sallyport-test"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    assert!(
        std::panic::catch_unwind(|| lock_dir_in(&d)).is_err(),
        "0755 accepted"
    );

    let e = scratch("link");
    std::os::unix::fs::symlink(&d, e.join("sallyport-test")).unwrap();
    std::fs::set_permissions(
        d.join("sallyport-test"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    assert!(
        std::panic::catch_unwind(|| lock_dir_in(&e)).is_err(),
        "symlink accepted"
    );

    let f = scratch("open-parent");
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        std::panic::catch_unwind(|| lock_dir_in(&f)).is_err(),
        "loose parent accepted"
    );
    for p in [&d, &e, &f] {
        std::fs::remove_dir_all(p).unwrap();
    }
}

/// The test image's tag carries this run's id (ad hoc: `local`), and the digest the tests use is
/// that tag's image.
#[test]
fn the_test_image_is_tagged_for_this_run() {
    let image = test_image();
    let tags = podman(&["images", "--format", "{{.Repository}}:{{.Tag}}"]);
    let tags = String::from_utf8_lossy(&tags.stdout);
    let prefix = format!("localhost/sallyport-test:{}-", image_run());
    assert!(
        tags.lines().any(|t| t.starts_with(&prefix)),
        "{prefix} in {tags}"
    );
    let digest = image.as_str().split_once('@').unwrap().1;
    let ids = podman(&[
        "image",
        "inspect",
        "--format",
        "{{.Digest}}",
        &tag_of(&tags, &prefix),
    ]);
    assert_eq!(String::from_utf8_lossy(&ids.stdout).trim(), digest);
}

fn tag_of(tags: &str, prefix: &str) -> String {
    tags.lines()
        .find(|t| t.starts_with(prefix))
        .unwrap()
        .to_owned()
}
