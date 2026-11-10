//! Task 6b without containers: the launch scan (RT-FS-13, AMENDMENTS-02 B2(a) and B4, maintainer
//! decision D), the 0700 session directories and the pinned model blob (#10).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

use sallyd::sandbox::{
    PinKind, ScanError, ScanLimits, SessionDirs, VerifiedModel, check_runtime_dir, scan_mounts,
};

mod common;
use common::*;

fn one(f: &Fx, mode: &str) -> sally_core::manifest::ValidatedManifest {
    f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", mode)]))
}

fn project(f: &Fx) -> PathBuf {
    f.root.join("home/code/myproject")
}

const MODES: [&str; 4] = ["ro", "rw", "brokered", "staged"];

/// Binds a Unix socket at `p`, through a short symlink to its directory: fixture paths are
/// longer than `sun_path`.
fn bind_socket(p: &Path) -> UnixListener {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let short = std::env::temp_dir().join(format!("sp-{}-{n}", std::process::id()));
    let _ = std::fs::remove_file(&short);
    std::os::unix::fs::symlink(p.parent().unwrap(), &short).unwrap();
    let l = UnixListener::bind(short.join(p.file_name().unwrap())).unwrap();
    std::fs::remove_file(&short).unwrap();
    l
}

/// RT-FS-13: a Unix socket anywhere in a mount refuses the launch, in every mode (`connect`
/// works on a read-only mount), including inside a `.git` directory (git's fsmonitor socket).
#[test]
fn a_socket_in_any_mount_refuses_the_launch() {
    for at in ["s.sock", "deep/er/s.sock", ".git/fsmonitor--daemon.ipc"] {
        for mode in MODES {
            let f = Fx::new();
            let p = project(&f).join(at);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            let _l = bind_socket(&p);
            let v = one(&f, mode);
            match scan_mounts(&v, &ScanLimits::default()) {
                Err(ScanError::SocketInMount { mount: 0, rel }) => {
                    assert_eq!(rel, Path::new(at), "{mode}");
                }
                other => panic!("{at} {mode}: {other:?}"),
            }
        }
    }
}

#[test]
fn rw_mounts_record_git_dirs_and_files_sorted_and_nothing_inside_a_git_dir() {
    let f = Fx::new();
    f.tree(
        "code/myproject",
        &["z/.git", ".git/modules/m/.git", "a/b/.git"],
        &["sub/.git"],
    );
    std::os::unix::fs::symlink("a", project(&f).join("link")).unwrap();
    // A `.git` symlink is neither shielded nor followed (git in the sandbox resolves it there).
    std::fs::create_dir_all(project(&f).join("x")).unwrap();
    std::os::unix::fs::symlink("../a/b/.git", project(&f).join("x/.git")).unwrap();
    let scan = f.scan(&one(&f, "rw"));
    let g = &scan.git()[0];
    assert_eq!(g.mount(), 0);
    let dirs: Vec<&str> = g.dirs().iter().map(|p| p.to_str().unwrap()).collect();
    // `.git` itself (from .git/modules/...), sorted; nothing below a .git; symlinks ignored.
    assert_eq!(dirs, [".git", "a/b/.git", "z/.git"]);
    assert_eq!(g.files(), [PathBuf::from("sub/.git")]);
    for mode in ["ro", "brokered", "staged"] {
        assert!(f.scan(&one(&f, mode)).git().is_empty(), "{mode}");
    }
}

/// Maintainer decision D: more than 32 shielded entries in one `rw` mount refuse the launch and
/// recommend `staged`; 32 are fine.
#[test]
fn more_than_32_shields_refuse_with_a_staged_recommendation() {
    let f = Fx::new();
    let dirs: Vec<String> = (0..32).map(|i| format!("r{i:02}/.git")).collect();
    let refs: Vec<&str> = dirs.iter().map(String::as_str).collect();
    f.tree("code/myproject", &refs, &[]);
    assert_eq!(f.scan(&one(&f, "rw")).git()[0].dirs().len(), 32);
    f.tree("code/myproject", &[], &["one-more/.git"]);
    let e = scan_mounts(&one(&f, "rw"), &ScanLimits::default()).unwrap_err();
    assert!(
        matches!(
            e,
            ScanError::TooManyShields {
                count: 33,
                max: 32,
                ..
            }
        ),
        "{e}"
    );
    assert!(e.to_string().contains("mode: staged"), "{e}");
    // Not an rw mount: nothing to shield, nothing refused.
    f.scan(&one(&f, "staged"));
}

#[test]
fn walk_bounds_refuse_rather_than_truncate() {
    let f = Fx::new();
    for i in 0..10 {
        std::fs::write(project(&f).join(format!("f{i}")), "").unwrap();
    }
    std::fs::create_dir_all(project(&f).join("a/b/c/d")).unwrap();
    let entries = ScanLimits {
        max_entries: 9,
        ..ScanLimits::default()
    };
    let depth = ScanLimits {
        max_depth: 3,
        ..ScanLimits::default()
    };
    for (limits, what) in [(entries, "9 entries"), (depth, "depth 3")] {
        let e = scan_mounts(&one(&f, "rw"), &limits).unwrap_err();
        assert!(e.to_string().contains(what), "{e}");
        assert!(e.to_string().contains("mode: staged"), "rw advice: {e}");
        let e = scan_mounts(&one(&f, "ro"), &limits).unwrap_err();
        assert!(matches!(e, ScanError::Limit { .. }), "{e}");
        assert!(!e.to_string().contains("staged"), "ro advice: {e}");
    }
}

/// RT-FS-06 at launch: the root is re-opened without following symlinks and must be the
/// directory validation saw.
#[test]
fn a_root_replaced_since_validation_is_refused() {
    let f = Fx::new();
    let v = one(&f, "rw");
    let p = project(&f);
    std::fs::rename(&p, f.root.join("home/code/moved")).unwrap();
    std::fs::create_dir(&p).unwrap();
    let e = scan_mounts(&v, &ScanLimits::default()).unwrap_err();
    assert!(e.to_string().contains("replaced since validation"), "{e}");
    std::fs::remove_dir(&p).unwrap();
    std::os::unix::fs::symlink(f.root.join("home/code/moved"), &p).unwrap();
    let e = scan_mounts(&v, &ScanLimits::default()).unwrap_err();
    assert!(e.to_string().contains("without following a symlink"), "{e}");
    // A symlinked ancestor is refused even when it leads to the validated directory itself:
    // podman resolves the same path later, and a symlink can be swapped in between.
    std::fs::remove_file(&p).unwrap();
    std::fs::rename(f.root.join("home/code/moved"), &p).unwrap();
    scan_mounts(&v, &ScanLimits::default()).unwrap();
    let code = f.root.join("home/code");
    std::fs::rename(&code, f.root.join("home/code2")).unwrap();
    std::os::unix::fs::symlink("code2", &code).unwrap();
    let e = scan_mounts(&v, &ScanLimits::default()).unwrap_err();
    assert!(e.to_string().contains("without following a symlink"), "{e}");
}

#[test]
fn symlinked_directories_are_not_followed() {
    let f = Fx::new();
    let outside = f.root.join("outside");
    std::fs::create_dir_all(outside.join("repo/.git")).unwrap();
    let _l = bind_socket(&outside.join("daemon.sock"));
    std::os::unix::fs::symlink(&outside, project(&f).join("out")).unwrap();
    let scan = f.scan(&one(&f, "rw"));
    assert!(scan.git()[0].dirs().is_empty());
}

/// #10 and B4: every shielded entry, every parent between it and the root, and the root are
/// pinned by identity; the kinds say how each is compared later.
#[test]
fn pins_carry_identity_guest_path_and_kind() {
    let f = Fx::new();
    f.tree("code/myproject", &["v/lib/.git"], &["m/.git"]);
    let scan = f.scan(&one(&f, "rw"));
    let by_rel = |rel: &str| {
        scan.pins()
            .iter()
            .find(|p| p.rel == Path::new(rel))
            .unwrap_or_else(|| panic!("{rel}: {:?}", scan.pins()))
            .clone()
    };
    for (rel, guest, kind) in [
        ("", "/workspace/p", PinKind::Bind),
        ("v", "/workspace/p/v", PinKind::Bind),
        ("v/lib", "/workspace/p/v/lib", PinKind::Bind),
        ("m", "/workspace/p/m", PinKind::Bind),
        ("m/.git", "/workspace/p/m/.git", PinKind::Bind),
        (
            "v/lib/.git",
            "/workspace/p/v/lib/.git",
            PinKind::OverlayLower,
        ),
    ] {
        let pin = by_rel(rel);
        let meta = std::fs::symlink_metadata(project(&f).join(rel)).unwrap();
        assert_eq!((pin.dev, pin.ino), (meta.dev(), meta.ino()), "{rel}");
        assert_eq!((pin.guest.as_str(), pin.kind), (guest, kind), "{rel}");
    }
    assert_eq!(scan.pins().len(), 6);
    let staged = f.scan(&one(&f, "staged"));
    assert_eq!(staged.pins().len(), 1);
    assert_eq!(staged.pins()[0].kind, PinKind::OverlayLower);
}

/// The 6a re-review's H1 setup on the host side: a pinned parent renamed and recreated between
/// the scan and `podman create` is caught by the last host re-check.
#[test]
fn recheck_host_catches_a_swapped_parent_or_entry() {
    let f = Fx::new();
    f.tree("code/myproject", &["v/lib/.git"], &["m/.git"]);
    let v = one(&f, "rw");
    let scan = f.scan(&v);
    scan.recheck_host(&v).unwrap();
    let p = project(&f);
    std::fs::rename(p.join("v"), p.join("v2")).unwrap();
    std::fs::create_dir_all(p.join("v/lib/.git")).unwrap();
    let e = scan.recheck_host(&v).unwrap_err();
    assert!(
        e.to_string().contains("changed since the launch scan"),
        "{e}"
    );
    std::fs::remove_dir_all(p.join("v")).unwrap();
    std::os::unix::fs::symlink("v2", p.join("v")).unwrap();
    assert!(
        scan.recheck_host(&v).is_err(),
        "a symlink is never followed"
    );
}

// ---- session directories (#10) --------------------------------------------------------------

fn mode(p: &Path) -> u32 {
    std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
}

#[test]
fn session_directories_are_fresh_0700_and_hold_the_profiles() {
    let f = Fx::new();
    let xdg = f.root.join("run");
    std::fs::set_permissions(&xdg, std::fs::Permissions::from_mode(0o700)).unwrap();
    let dirs = SessionDirs::create(&f.paths, &xdg, &[1], 2).unwrap();
    let data = f.paths.data_root();
    for d in [
        f.paths.socket_root().to_owned(),
        f.paths.workspace_sockets(),
        f.paths.harness_sockets(),
        data.to_owned(),
        data.parent().unwrap().to_owned(),
        dirs.profiles().to_owned(),
        f.paths.stage(1).upper,
        f.paths.stage(1).work,
        f.paths.git_overlay(0).upper,
        f.paths.git_overlay(1).work,
    ] {
        assert_eq!(mode(&d), 0o700, "{}", d.display());
    }
    for role in ["workspace", "harness", "inference"] {
        let p = dirs.profiles().join(format!("seccomp-{role}.json"));
        assert_eq!(mode(&p), 0o600, "{}", p.display());
    }
    let e = SessionDirs::create(&f.paths, &xdg, &[], 0).unwrap_err();
    assert!(e.to_string().contains("never reused"), "{e}");
    assert!(
        e.reused,
        "nothing was created, so nothing may be cleaned up"
    );
}

/// A launch scan belongs to the manifest it was made for (6b Rust review): the builder and the
/// host re-check refuse a scan of other mounts.
#[test]
fn a_scan_is_bound_to_its_manifest() {
    let f = Fx::new();
    f.tree("code/myproject", &[".git"], &[]);
    let a = one(&f, "rw");
    let b = f.load(&mounts(&[mount("~/code/other", "/workspace/p", "rw")]));
    let scan = f.scan(&a);
    assert!(scan.is_for(&a) && !scan.is_for(&b));
    let e =
        sallyd::sandbox::workspace_argv(&f.common, &f.paths, &b, &scan, &ws_image()).unwrap_err();
    assert!(e.to_string().contains("another manifest"), "{e}");
    assert!(scan.recheck_host(&b).is_err());
}

#[test]
fn the_runtime_dir_must_be_ours_and_private() {
    let f = Fx::new();
    let xdg = f.root.join("run");
    std::fs::set_permissions(&xdg, std::fs::Permissions::from_mode(0o755)).unwrap();
    let e = check_runtime_dir(&xdg).unwrap_err();
    assert!(e.to_string().contains("0700"), "{e}");
    let e = SessionDirs::create(&f.paths, &xdg, &[], 0).unwrap_err();
    assert!(!e.reused && e.created.is_empty(), "nothing created: {e:?}");
    // 6b re-review M-1: a stopped session's directory is reported as reused even when another
    // check would fail too, so cleanup never removes its kept data.
    std::fs::create_dir_all(f.paths.data_root().join("stage/0/upper")).unwrap();
    let e = SessionDirs::create(&f.paths, &xdg, &[], 0).unwrap_err();
    assert!(e.reused && e.created.is_empty(), "{e:?}");
    std::fs::remove_dir_all(f.paths.data_root()).unwrap();
    std::fs::set_permissions(&xdg, std::fs::Permissions::from_mode(0o700)).unwrap();
    check_runtime_dir(&xdg).unwrap();
    let link = f.root.join("run-link");
    std::os::unix::fs::symlink(&xdg, &link).unwrap();
    assert!(check_runtime_dir(&link).is_err());
}

#[test]
fn a_pre_existing_session_directory_with_loose_permissions_is_refused() {
    let f = Fx::new();
    let xdg = f.root.join("run");
    std::fs::set_permissions(&xdg, std::fs::Permissions::from_mode(0o700)).unwrap();
    let sessions = f.paths.data_root().parent().unwrap().to_owned();
    std::fs::create_dir_all(&sessions).unwrap();
    std::fs::set_permissions(&sessions, std::fs::Permissions::from_mode(0o755)).unwrap();
    let e = SessionDirs::create(&f.paths, &xdg, &[], 0).unwrap_err();
    assert!(e.to_string().contains("mode 0700"), "{e}");
}

// ---- the model blob (#10) -------------------------------------------------------------------

#[test]
fn a_model_blob_is_pinned_only_when_named_by_hash_read_only_and_not_a_symlink() {
    let f = Fx::new();
    let blobs = f.root.join("blobs");
    std::fs::create_dir_all(blobs.join("sha256")).unwrap();
    let blob = |hex: &str, perm: u32| {
        let p = blobs.join("sha256").join(hex);
        std::fs::write(&p, b"GGUF").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(perm)).unwrap();
        p
    };
    let ok = blob(D0, 0o444);
    let m = VerifiedModel::pin(&blobs, D0).unwrap();
    let meta = std::fs::metadata(&ok).unwrap();
    assert_eq!(m.identity(), (meta.dev(), meta.ino()));
    assert_eq!(m.path(), ok);
    blob(D1, 0o644);
    assert!(VerifiedModel::pin(&blobs, D1).is_err(), "writable");
    std::os::unix::fs::symlink(&ok, blobs.join("sha256").join(D2)).unwrap();
    assert!(VerifiedModel::pin(&blobs, D2).is_err(), "symlink");
    for bad in ["", "../x", &D0.to_uppercase().replace('0', "A"), &D0[1..]] {
        assert!(VerifiedModel::pin(&blobs, bad).is_err(), "{bad:?}");
    }
}
