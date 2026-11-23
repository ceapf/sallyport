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
        xdg_state_home: None,
        xdg_runtime_dir: None,
        podman_storage: Vec::new(),
        env_dirs: Vec::new(),
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
    let replaced = format!("{} was replaced since validation", m.host.display());
    assert!(
        matches!(&e, ScanError::Changed { msg, .. } if *msg == replaced),
        "{e:?}"
    );
    std::fs::remove_dir(&m.host).unwrap();
    std::os::unix::fs::symlink(&moved, &m.host).unwrap();
    let e = Walk::of_mount(1, m, &limits).err().unwrap();
    assert!(matches!(e, ScanError::Changed { mount: 1, .. }), "{e:?}");
    let symlink = format!(
        "{} can no longer be opened as a directory without following a symlink: ",
        m.host.display()
    );
    assert!(
        matches!(&e, ScanError::Changed { msg, .. } if msg.starts_with(&symlink)),
        "{e:?}"
    );
}

/// A live session's value, with a quote, a backslash and a non-printable byte, as a sandbox
/// could name a file in an `rw` mount.
const NAMED: &str = "q\"u\\o\x01te-secret-0123456789";

fn run_of(text: &str) -> bool {
    NAMED
        .as_bytes()
        .windows(8)
        .filter_map(|w| std::str::from_utf8(w).ok())
        .any(|w| text.contains(w))
}

/// Architect Q303: a path in a scan message is shown raw (lossy UTF-8, `.` for the root),
/// never Debug-escaped, so the audit writer can mask a form in it.
#[test]
fn a_path_is_shown_raw() {
    use std::os::unix::ffi::OsStrExt as _;
    assert_eq!(shown(Path::new("")), ".");
    assert_eq!(shown(Path::new("a/b")), "a/b");
    assert_eq!(shown(Path::new(NAMED)), NAMED);
    assert_eq!(shown(Path::new("x\ny")), "x\ny");
    let odd = Path::new(std::ffi::OsStr::from_bytes(b"a\xffb"));
    assert_eq!(shown(odd), "a\u{fffd}b");
    assert_eq!(
        changed_text(Path::new(NAMED), "during the launch scan"),
        format!("\"{NAMED}\" changed during the launch scan")
    );
    let io = ScanError::Io {
        mount: 0,
        rel: PathBuf::from(NAMED),
        source: std::io::Error::other("gone"),
    };
    assert_eq!(
        io.to_string(),
        format!("filesystem.mounts[0]: \"{NAMED}\": gone")
    );
}

/// Architect Q303: a Unix socket a sandbox named with a live form refuses the launch, and the
/// `sandbox.refuse` detail built from it holds the placeholder and no run of the value.
/// Control: the old `{rel:?}` escaped the quote and backslash, so the mask missed it.
#[test]
fn a_socket_named_with_a_form_is_masked_in_the_refusal_detail() {
    use sally_core::audit::{Actor, NewEntry, Redactor};
    let (dir, _guard) = scratch("named-socket");
    let m = manifest(&dir);
    let short = std::env::temp_dir().join(format!("sp-scan-{}", std::process::id()));
    let _ = std::fs::remove_file(&short);
    std::os::unix::fs::symlink(dir.join("home/a"), &short).unwrap();
    // Removes the short link if anything below panics before it is removed.
    struct Unlink(PathBuf);
    impl Drop for Unlink {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let _unlink = Unlink(short.clone());
    let _l = std::os::unix::net::UnixListener::bind(short.join(NAMED)).unwrap();
    std::fs::remove_file(&short).unwrap();
    let e = scan_mounts(&m, &ScanLimits::default()).err().unwrap();
    assert!(matches!(e, ScanError::SocketInMount { .. }), "{e:?}");
    let e = crate::sandbox::launch::LaunchError::from(e);
    let v = NewEntry::new(Actor::Sallyd, "sandbox.refuse")
        .text(
            "detail",
            e.to_string(),
            crate::sandbox::launch::DETAIL_STYLE,
        )
        .resolved(&Redactor::new([("Y", NAMED)]));
    let detail = v["detail"].as_str().expect("the detail is logged");
    assert!(detail.contains("[REDACTED:Y]"), "{detail}");
    assert!(!run_of(detail), "{detail}");
}
