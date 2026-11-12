//! Confinement tests on real directories under `target/`: no container. `/proc/self` stands in
//! for a container's init (its root is the host root), and a reaped child for a dead one.

#![allow(clippy::unwrap_used)]

use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

/// A fresh directory under `target/` (removed first if a previous run left it).
fn scratch(name: &str) -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::SeqCst);
    let d = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/tools-fs-tests")
        .join(format!("{name}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::canonicalize(&d).unwrap()
}

/// `(mount root, a sibling outside it)`.
fn mount(name: &str) -> (PathBuf, PathBuf) {
    let d = scratch(name);
    let (m, out) = (d.join("mount"), d.join("outside"));
    std::fs::create_dir(&m).unwrap();
    std::fs::create_dir(&out).unwrap();
    std::fs::write(out.join("secret"), b"outside").unwrap();
    (m, out)
}

fn pin(p: &Path) -> (u64, u64) {
    let md = std::fs::metadata(p).unwrap();
    (md.dev(), md.ino())
}

fn host(m: &Path) -> RootSource {
    let (dev, ino) = pin(m);
    RootSource::Host {
        path: m.to_owned(),
        dev,
        ino,
    }
}

fn proc_dir(pid: u32) -> Arc<OwnedFd> {
    let p = format!("/proc/{pid}");
    Arc::new(fd::open(p.as_str(), OFlags::PATH | OFlags::DIRECTORY, Mode::empty()).unwrap())
}

/// The mount seen "in the container" of this process (whose root is the host root).
fn bind(m: &Path) -> RootSource {
    let (dev, ino) = pin(m);
    RootSource::Bind {
        proc_dir: proc_dir(std::process::id()),
        guest: m.display().to_string(),
        dev,
        ino,
    }
}

fn mkfifo(p: &Path) {
    rustix::fs::mknodat(
        rustix::fs::CWD,
        p,
        FileType::Fifo,
        Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
}

#[test]
fn a_host_root_must_be_the_pinned_directory_reached_without_symlinks() {
    let (m, out) = mount("host-root");
    assert!(host(&m).open().is_ok());
    let (dev, ino) = pin(&out);
    let other = RootSource::Host {
        path: m.clone(),
        dev,
        ino,
    };
    assert_eq!(other.open().err(), Some(FsError::MountChanged));
    let (dev, ino) = pin(&m);
    let wrong_dev = RootSource::Host {
        path: m.clone(),
        dev: dev ^ 1,
        ino,
    };
    assert_eq!(wrong_dev.open().err(), Some(FsError::MountChanged));
    // The folder replaced by a symlink to itself elsewhere: refused, not followed.
    let link = m.parent().unwrap().join("link");
    std::os::unix::fs::symlink(&m, &link).unwrap();
    let via_link = RootSource::Host {
        path: link,
        dev,
        ino,
    };
    assert_eq!(via_link.open().err(), Some(FsError::MountChanged));
    let gone = RootSource::Host {
        path: m.join("missing"),
        dev,
        ino,
    };
    assert_eq!(gone.open().err(), Some(FsError::MountChanged));
}

#[test]
fn rt_fs_04_reads_never_leave_the_mount() {
    let (m, out) = mount("rt-fs-04");
    std::fs::create_dir(m.join("d")).unwrap();
    std::fs::write(m.join("d/a.md"), b"inside").unwrap();
    std::os::unix::fs::symlink(out.join("secret"), m.join("to-outside")).unwrap();
    std::os::unix::fs::symlink("d/a.md", m.join("to-inside")).unwrap();
    std::os::unix::fs::symlink(&out, m.join("dir-out")).unwrap();
    for src in [host(&m), bind(&m)] {
        let root = src.open().unwrap();
        for rel in [
            "../outside/secret",
            "d/../../outside/secret",
            "to-outside",
            "to-inside",
            "dir-out/secret",
            "/etc/passwd",
        ] {
            assert_eq!(read(&root, rel, 0, 100), Err(FsError::Escapes), "{rel}");
        }
        assert_eq!(read(&root, "d/a.md", 0, 100).unwrap().bytes, b"inside");
    }
}

#[test]
fn a_read_returns_its_range_and_the_size() {
    let (m, _) = mount("read-range");
    std::fs::write(m.join("f"), b"0123456789").unwrap();
    let root = host(&m).open().unwrap();
    let r = |o, l| read(&root, "f", o, l).unwrap();
    assert_eq!(
        r(0, 100),
        ReadOut {
            size: 10,
            bytes: b"0123456789".to_vec()
        }
    );
    assert_eq!(r(3, 4).bytes, b"3456");
    assert_eq!(r(8, 4).bytes, b"89");
    assert_eq!(r(10, 4).bytes, b"");
    assert_eq!(r(11, 4).bytes, b"");
    assert_eq!(r(0, 0).bytes, b"");
    assert_eq!(r(u64::MAX, 1).size, 10);
}

#[test]
fn the_read_and_list_checks_resolve_as_the_effects_do() {
    let (m, out) = mount("checks");
    std::fs::create_dir(m.join("d")).unwrap();
    std::fs::write(m.join("f"), b"x").unwrap();
    std::os::unix::fs::symlink(out.join("secret"), m.join("link")).unwrap();
    std::os::unix::fs::symlink(&out, m.join("dlink")).unwrap();
    mkfifo(&m.join("fifo"));
    let root = host(&m).open().unwrap();
    assert_eq!(check_read(&root, "f"), Ok(()));
    assert_eq!(check_read(&root, "d"), Err(FsError::NotAFile));
    assert_eq!(check_read(&root, "fifo"), Err(FsError::NotAFile));
    assert_eq!(check_read(&root, "link"), Err(FsError::Escapes));
    assert_eq!(check_read(&root, "missing"), Err(FsError::NotFound));
    assert_eq!(check_list(&root, ""), Ok(()));
    assert_eq!(check_list(&root, "d"), Ok(()));
    assert_eq!(check_list(&root, "f"), Err(FsError::NotADir));
    assert_eq!(check_list(&root, "dlink"), Err(FsError::Escapes));
}

#[test]
fn only_regular_files_are_read() {
    let (m, _) = mount("read-kind");
    std::fs::create_dir(m.join("d")).unwrap();
    mkfifo(&m.join("fifo"));
    let root = host(&m).open().unwrap();
    assert_eq!(read(&root, "d", 0, 1), Err(FsError::NotAFile));
    // Opened non-blocking: a FIFO with no writer never hangs the broker.
    assert_eq!(read(&root, "fifo", 0, 1), Err(FsError::NotAFile));
    assert_eq!(read(&root, "missing", 0, 1), Err(FsError::NotFound));
    std::fs::write(m.join("file"), b"x").unwrap();
    assert_eq!(read(&root, "file/x", 0, 1), Err(FsError::NotADir));
}

#[test]
fn the_host_side_never_crosses_into_another_file_system() {
    // `/proc` is its own mount under `/`: the host side refuses the crossing, while the
    // container side (where the sandbox's own mounts are what it sees) follows it.
    let (dev, ino) = pin(Path::new("/"));
    let on_host = RootSource::Host {
        path: "/".into(),
        dev,
        ino,
    }
    .open()
    .unwrap();
    assert_eq!(read(&on_host, "proc/version", 0, 16), Err(FsError::Escapes));
    let in_container = RootSource::Bind {
        proc_dir: proc_dir(std::process::id()),
        guest: "/".into(),
        dev,
        ino,
    }
    .open()
    .unwrap();
    // procfs reports size 0, so the read is empty, but it is allowed.
    assert!(read(&in_container, "proc/version", 0, 16).is_ok());
}

#[test]
fn a_container_root_needs_the_live_init_and_the_pinned_guest_root() {
    let (m, out) = mount("bind");
    assert!(bind(&m).open().is_ok());
    let (dev, ino) = pin(&out);
    let other = RootSource::Bind {
        proc_dir: proc_dir(std::process::id()),
        guest: m.display().to_string(),
        dev,
        ino,
    };
    assert_eq!(other.open().err(), Some(FsError::MountChanged));
    let missing = RootSource::Bind {
        proc_dir: proc_dir(std::process::id()),
        guest: m.join("nope").display().to_string(),
        dev,
        ino,
    };
    assert_eq!(missing.open().err(), Some(FsError::MountChanged));
    // A guest root reached through a symlink is refused.
    let link = m.parent().unwrap().join("bind-link");
    std::os::unix::fs::symlink(&m, &link).unwrap();
    let (dev, ino) = pin(&m);
    let via_link = RootSource::Bind {
        proc_dir: proc_dir(std::process::id()),
        guest: link.display().to_string(),
        dev,
        ino,
    };
    assert_eq!(via_link.open().err(), Some(FsError::MountChanged));
    // The init is gone (its pid directory fd outlives it): nothing resolves, not even on the
    // host root.
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let dead = proc_dir(child.id());
    child.kill().unwrap();
    child.wait().unwrap();
    for src in [
        RootSource::Bind {
            proc_dir: Arc::clone(&dead),
            guest: m.display().to_string(),
            dev,
            ino,
        },
        RootSource::Overlay {
            proc_dir: dead,
            guest: m.display().to_string(),
        },
    ] {
        assert_eq!(src.open().err(), Some(FsError::ContainerGone));
    }
}

#[test]
fn a_staged_root_must_be_an_overlay_mount_root() {
    let (m, _) = mount("overlay");
    for guest in [m.display().to_string(), "/".to_owned()] {
        let src = RootSource::Overlay {
            proc_dir: proc_dir(std::process::id()),
            guest: guest.clone(),
        };
        assert_eq!(src.open().err(), Some(FsError::MountChanged), "{guest}");
    }
}

#[test]
fn a_listing_is_sorted_bounded_and_never_lossy() {
    let (m, out) = mount("list");
    std::fs::write(m.join("b"), b"12345").unwrap();
    std::fs::create_dir(m.join("a")).unwrap();
    std::os::unix::fs::symlink(&out, m.join("c")).unwrap();
    mkfifo(&m.join("d"));
    let raw = std::ffi::OsStr::from_bytes(b"bad\xff");
    std::fs::write(m.join(raw), b"").unwrap();
    let root = host(&m).open().unwrap();
    let l = list(&root, "").unwrap();
    let names: Vec<(&str, &str)> = l
        .entries
        .iter()
        .map(|e| (e.name.as_str(), e.kind))
        .collect();
    assert_eq!(
        names,
        [
            ("a", "dir"),
            ("b", "file"),
            ("c", "symlink"),
            ("d", "other")
        ]
    );
    assert_eq!(l.entries[1].size, 5);
    assert_eq!((l.truncated, l.unlisted), (false, 1));
    assert_eq!(list(&root, "a").unwrap(), Listing::default());
    assert_eq!(list(&root, "b"), Err(FsError::NotADir));
    assert_eq!(list(&root, "c"), Err(FsError::Escapes));
    assert_eq!(list(&root, "missing"), Err(FsError::NotFound));
}

#[test]
fn a_listing_stops_at_max_entries() {
    let (m, _) = mount("list-cap");
    for i in 0..MAX_ENTRIES {
        std::fs::write(m.join(format!("f{i:04}")), b"").unwrap();
    }
    let root = host(&m).open().unwrap();
    let l = list(&root, "").unwrap();
    assert_eq!((l.entries.len(), l.truncated), (MAX_ENTRIES, false));
    std::fs::write(m.join("one-more"), b"").unwrap();
    let l = list(&root, "").unwrap();
    assert_eq!((l.entries.len(), l.truncated), (MAX_ENTRIES, true));
}

#[test]
fn a_write_creates_or_replaces_a_regular_file_only() {
    let (m, _) = mount("write");
    let root = host(&m).open().unwrap();
    check_write(&root, "new", true).unwrap();
    write(&root, "new", b"hello world", true).unwrap();
    assert_eq!(std::fs::read(m.join("new")).unwrap(), b"hello world");
    let mode = std::fs::metadata(m.join("new"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode & !0o644, 0, "{mode:o}");
    write(&root, "new", b"hi", true).unwrap();
    assert_eq!(std::fs::read(m.join("new")).unwrap(), b"hi");
    write(&root, "new", b"", true).unwrap();
    assert_eq!(std::fs::read(m.join("new")).unwrap(), b"");
    std::fs::create_dir(m.join("d")).unwrap();
    assert_eq!(check_write(&root, "d", true), Err(FsError::NotAFile));
    assert_eq!(write(&root, "d", b"x", true), Err(FsError::NotAFile));
    mkfifo(&m.join("fifo"));
    assert_eq!(check_write(&root, "fifo", true), Err(FsError::NotAFile));
    assert_eq!(write(&root, "fifo", b"x", true), Err(FsError::NotAFile));
    assert_eq!(check_write(&root, "nodir/f", true), Err(FsError::NotFound));
    assert_eq!(write(&root, "nodir/f", b"x", true), Err(FsError::NotFound));
    write(&root, "d/f", b"x", false).unwrap();
    assert_eq!(std::fs::read(m.join("d/f")).unwrap(), b"x");
}

#[test]
fn a_write_never_follows_a_symlink_out() {
    let (m, out) = mount("write-link");
    std::os::unix::fs::symlink(out.join("secret"), m.join("link")).unwrap();
    std::os::unix::fs::symlink(&out, m.join("dir")).unwrap();
    for src in [host(&m), bind(&m)] {
        let root = src.open().unwrap();
        for rel in ["link", "dir/secret", "dir/new", "../outside/secret"] {
            assert_eq!(
                check_write(&root, rel, true),
                Err(FsError::Escapes),
                "{rel}"
            );
            assert_eq!(
                write(&root, rel, b"pwned", true),
                Err(FsError::Escapes),
                "{rel}"
            );
        }
    }
    assert_eq!(std::fs::read(out.join("secret")).unwrap(), b"outside");
    assert!(!out.join("new").exists());
}

#[test]
fn a_brokered_write_refuses_a_hard_link_and_leaves_its_other_name_untouched() {
    let (m, out) = mount("hardlink");
    std::fs::hard_link(out.join("secret"), m.join("h")).unwrap();
    let root = host(&m).open().unwrap();
    assert_eq!(check_write(&root, "h", true), Err(FsError::HardLink));
    assert_eq!(write(&root, "h", b"pwned", true), Err(FsError::HardLink));
    assert_eq!(std::fs::read(out.join("secret")).unwrap(), b"outside");
    // In the workspace's own view (rw, staged) the sandbox could write it anyway.
    check_write(&root, "h", false).unwrap();
    write(&root, "h", b"same as in the sandbox", false).unwrap();
    assert_eq!(
        std::fs::read(out.join("secret")).unwrap(),
        b"same as in the sandbox"
    );
}

/// Architect ruling Q37: the target is re-resolved from the pinned root at run time.
#[test]
fn a_directory_swapped_for_a_symlink_after_prepare_is_refused_at_run() {
    let (m, out) = mount("swap");
    std::fs::create_dir(m.join("d")).unwrap();
    std::fs::write(m.join("d/f"), b"old").unwrap();
    let src = host(&m);
    check_write(&src.open().unwrap(), "d/f", true).unwrap();
    check_delete(&src.open().unwrap(), "d/f").unwrap();
    std::fs::rename(m.join("d"), m.join("d-moved")).unwrap();
    std::fs::write(out.join("f"), b"outside f").unwrap();
    std::os::unix::fs::symlink(&out, m.join("d")).unwrap();
    let root = src.open().unwrap();
    assert_eq!(write(&root, "d/f", b"pwned", true), Err(FsError::Escapes));
    assert_eq!(delete(&root, "d/f"), Err(FsError::Escapes));
    assert_eq!(std::fs::read(out.join("f")).unwrap(), b"outside f");
}

#[test]
fn a_delete_takes_a_file_or_an_empty_directory_only() {
    let (m, out) = mount("delete");
    std::fs::write(m.join("f"), b"x").unwrap();
    std::fs::create_dir(m.join("empty")).unwrap();
    std::fs::create_dir(m.join("full")).unwrap();
    std::fs::write(m.join("full/x"), b"x").unwrap();
    std::os::unix::fs::symlink(out.join("secret"), m.join("link")).unwrap();
    mkfifo(&m.join("fifo"));
    let root = host(&m).open().unwrap();
    for rel in ["f", "empty", "full"] {
        check_delete(&root, rel).unwrap();
    }
    delete(&root, "f").unwrap();
    delete(&root, "empty").unwrap();
    assert!(!m.join("f").exists() && !m.join("empty").exists());
    assert_eq!(delete(&root, "full"), Err(FsError::NotEmpty));
    assert_eq!(check_delete(&root, "link"), Err(FsError::Escapes));
    assert_eq!(delete(&root, "link"), Err(FsError::Escapes));
    assert!(m.join("link").symlink_metadata().is_ok());
    assert_eq!(std::fs::read(out.join("secret")).unwrap(), b"outside");
    assert_eq!(check_delete(&root, "fifo"), Err(FsError::NotAFile));
    assert_eq!(delete(&root, "fifo"), Err(FsError::NotAFile));
    assert_eq!(delete(&root, "missing"), Err(FsError::NotFound));
    assert_eq!(check_delete(&root, "missing/x"), Err(FsError::NotFound));
}

#[test]
fn errnos_map_to_their_codes() {
    let cases = [
        (Errno::LOOP, "path_escapes_mount"),
        (Errno::XDEV, "path_escapes_mount"),
        (Errno::NOENT, "not-found"),
        (Errno::ISDIR, "not-a-file"),
        (Errno::NXIO, "not-a-file"),
        (Errno::NOTDIR, "not-a-directory"),
        (Errno::NOTEMPTY, "not-empty"),
        (Errno::ROFS, "read-only"),
        (Errno::NOSPC, "no-space"),
        (Errno::DQUOT, "no-space"),
        (Errno::ACCESS, "permission"),
        (Errno::PERM, "permission"),
        (Errno::IO, "io-error"),
    ];
    for (e, code) in cases {
        assert_eq!(FsError::from_errno(e).code(), code, "{e:?}");
    }
    for (e, code) in [
        (FsError::HardLink, "hard-link"),
        (FsError::MountChanged, "mount-changed"),
        (FsError::ContainerGone, "container-gone"),
    ] {
        assert_eq!(e.code(), code);
    }
}

#[test]
fn host_paths_join_the_root_and_rel() {
    let r = Path::new("/home/u/notes");
    assert_eq!(host_path(r, ""), "/home/u/notes");
    assert_eq!(host_path(r, "a/b.md"), "/home/u/notes/a/b.md");
}
