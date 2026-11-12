//! Two runs at once (Task 8 PR C, architect Q23–Q25): two worktrees can run the container
//! tests side by side. Each run's container and image names carry its own run id, and the locks
//! that serialize disk-heavy work are per user, not per target directory.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
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

fn is_run_id(id: &str) -> bool {
    id.len() == 8
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

#[test]
fn the_run_id_is_eight_lowercase_alphanumerics_and_follows_the_wrapper() {
    let id = run_id();
    assert!(is_run_id(id), "{id}");
    if let Ok(set) = std::env::var("SALLYPORT_TEST_RUN") {
        assert_eq!(id, set, "the wrapper's id is the run id");
    }
    assert_eq!(id, run_id(), "one id per process");
    assert!(is_run_id(&random_run_id()));
}

/// Set: the wrapper's value wins, verbatim. Unset: a random id. Malformed, or not UTF-8: an
/// error (a panic in `run_id`), never a fallback the wrapper could not sweep.
#[test]
fn the_wrapper_value_wins_and_a_malformed_one_is_an_error() {
    use std::env::VarError;
    let never = || -> String { panic!("random id used for a set variable") };
    assert_eq!(
        resolve_run_id(Ok("a1b2c3d4".into()), never).unwrap(),
        "a1b2c3d4"
    );
    assert_eq!(
        resolve_run_id(Err(VarError::NotPresent), || "zz".into()).unwrap(),
        "zz"
    );
    assert!(resolve_run_id(Ok("ABC".into()), never).is_err());
    let raw = OsString::from_vec(vec![b'a', 0xff, b'b', b'c', b'd', b'e', b'f', b'g']);
    assert!(resolve_run_id(Err(VarError::NotUnicode(raw)), never).is_err());
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
    let name = format!("runs-probe-{}", std::process::id());
    let p = lock_path(&name);
    assert_eq!(p, xdg.join(format!("sallyport-test/{name}.lock")));
    assert!(!p.starts_with(env!("CARGO_TARGET_TMPDIR")));
    let held = lock(&name, false);
    let mode = std::fs::metadata(p.parent().unwrap())
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o700);
    drop(held);
    std::fs::remove_file(&p).unwrap();
}

/// Created 0700 when missing; an existing lock file keeps its bytes; a symlink at the lock path
/// is not followed.
#[test]
fn a_lock_file_is_never_truncated_or_reached_through_a_symlink() {
    let d = scratch("trunc");
    let dir = lock_dir_in(&d);
    std::fs::write(dir.join("t.lock"), "keep").unwrap();
    drop(open_lock(&dir.join("t.lock")));
    assert_eq!(std::fs::read_to_string(dir.join("t.lock")).unwrap(), "keep");
    std::os::unix::fs::symlink(dir.join("t.lock"), dir.join("l.lock")).unwrap();
    assert!(std::panic::catch_unwind(|| open_lock(&dir.join("l.lock"))).is_err());
    std::fs::remove_dir_all(&d).unwrap();
}

/// The disk-free lock's bound (maintainer, 9a-2 part 4): a test waits for a held lock at most
/// its bound, then fails naming the lock; once the holder lets go, it gets the lock.
#[test]
fn a_bounded_lock_fails_naming_the_lock_once_its_wait_runs_out() {
    let d = scratch("bounded");
    let path = lock_dir_in(&d).join("disk-free.lock");
    let holder = open_lock(&path);
    rustix::fs::flock(&holder, rustix::fs::FlockOperation::LockShared).unwrap();
    let wait = std::time::Duration::from_millis(300);
    let started = std::time::Instant::now();
    let err =
        std::panic::catch_unwind(|| lock_exclusive_within(&path, wait, "a test")).unwrap_err();
    assert!(started.elapsed() >= wait);
    let msg = err.downcast_ref::<String>().cloned().unwrap_or_default();
    assert!(
        msg.contains("disk-free.lock") && msg.contains("a test"),
        "{msg}"
    );
    drop(holder);
    drop(lock_exclusive_within(&path, wait, "a test"));
    std::fs::remove_dir_all(&d).unwrap();
}

#[test]
fn a_lock_directory_open_to_others_or_a_symlink_is_refused() {
    let d = scratch("loose");
    let planted = d.join("sallyport-test");
    std::fs::create_dir(&planted).unwrap();
    std::fs::set_permissions(&planted, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        std::panic::catch_unwind(|| lock_dir_in(&d)).is_err(),
        "0755 accepted"
    );

    // A private directory, but reached through a symlink.
    std::fs::set_permissions(&planted, std::fs::Permissions::from_mode(0o700)).unwrap();
    let e = scratch("link");
    std::os::unix::fs::symlink(&planted, e.join("sallyport-test")).unwrap();
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

/// The test image is built under this run's tag (ad hoc: `local`), and the digest the tests use
/// is that tag's image.
#[test]
fn the_test_image_is_tagged_for_this_run() {
    let digest = test_image().as_str().split_once('@').unwrap().1.to_owned();
    let tag = test_image_tag();
    let key = tag
        .strip_prefix(&format!("localhost/sallyport-test:{}-", image_run()))
        .unwrap_or_else(|| panic!("{tag}"));
    assert!(
        key.len() == 16 && key.bytes().all(|b| b.is_ascii_hexdigit()),
        "{tag}"
    );
    let out = podman(&["image", "inspect", "--format", "{{.Digest}}", tag]);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), digest);
}
