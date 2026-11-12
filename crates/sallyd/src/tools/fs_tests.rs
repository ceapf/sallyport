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

/// This process's own uid and gid: the sandbox identity of the tests that are not about it.
fn me() -> UserIds {
    UserIds {
        uid: rustix::process::getuid().as_raw(),
        gid: rustix::process::getgid().as_raw(),
    }
}

/// A mount root under a scratch directory, which is removed with it (and the sibling outside).
struct Dir(PathBuf);

impl std::ops::Deref for Dir {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for Dir {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        if let Some(base) = self.0.parent() {
            let _ = std::fs::remove_dir_all(base);
        }
    }
}

/// `(mount root, a sibling outside it)`.
fn mount(name: &str) -> (Dir, PathBuf) {
    let d = scratch(name);
    let (m, out) = (d.join("mount"), d.join("outside"));
    std::fs::create_dir(&m).unwrap();
    std::fs::create_dir(&out).unwrap();
    std::fs::write(out.join("secret"), b"outside").unwrap();
    (Dir(m), out)
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
    assert!(host(&m).open(me()).is_ok());
    let (dev, ino) = pin(&out);
    let other = RootSource::Host {
        path: m.to_path_buf(),
        dev,
        ino,
    };
    assert_eq!(other.open(me()).err(), Some(FsError::MountChanged));
    let (dev, ino) = pin(&m);
    let wrong_dev = RootSource::Host {
        path: m.to_path_buf(),
        dev: dev ^ 1,
        ino,
    };
    assert_eq!(wrong_dev.open(me()).err(), Some(FsError::MountChanged));
    // The folder replaced by a symlink to itself elsewhere: refused, not followed.
    let link = m.parent().unwrap().join("link");
    std::os::unix::fs::symlink(&m, &link).unwrap();
    let via_link = RootSource::Host {
        path: link,
        dev,
        ino,
    };
    assert_eq!(via_link.open(me()).err(), Some(FsError::MountChanged));
    let gone = RootSource::Host {
        path: m.join("missing"),
        dev,
        ino,
    };
    assert_eq!(gone.open(me()).err(), Some(FsError::MountChanged));
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
        let root = src.open(me()).unwrap();
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

/// Rust review M6: a symlink in the middle of a path that stays inside the mount. Only
/// `RESOLVE_NO_SYMLINKS` refuses it (`BENEATH` allows it, `O_NOFOLLOW` sees only the end).
#[test]
fn an_in_mount_directory_symlink_is_refused_on_the_way() {
    let (m, _) = mount("mid-link");
    std::fs::create_dir(m.join("d")).unwrap();
    std::fs::write(m.join("d/a.md"), b"x").unwrap();
    std::os::unix::fs::symlink("d", m.join("dlink")).unwrap();
    for src in [host(&m), bind(&m)] {
        let root = src.open(me()).unwrap();
        assert_eq!(read(&root, "dlink/a.md", 0, 1), Err(FsError::Escapes));
        assert_eq!(check_read(&root, "dlink/a.md"), Err(FsError::Escapes));
        assert_eq!(list(&root, "dlink").err(), Some(FsError::Escapes));
        assert_eq!(check_write(&root, "dlink/new", true), Err(FsError::Escapes));
        assert_eq!(
            write(&root, "dlink/new", b"x", false),
            Err(FsError::Escapes)
        );
        assert_eq!(check_delete(&root, "dlink/a.md"), Err(FsError::Escapes));
        assert_eq!(delete(&root, "dlink/a.md"), Err(FsError::Escapes));
    }
    assert!(!m.join("d/new").exists());
    assert!(m.join("d/a.md").exists());
}

#[test]
fn a_read_returns_its_range_and_the_size() {
    let (m, _) = mount("read-range");
    std::fs::write(m.join("f"), b"0123456789").unwrap();
    let root = host(&m).open(me()).unwrap();
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
    let root = host(&m).open(me()).unwrap();
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
    let root = host(&m).open(me()).unwrap();
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
    .open(me())
    .unwrap();
    assert_eq!(read(&on_host, "proc/version", 0, 16), Err(FsError::Escapes));
    let in_container = RootSource::Bind {
        proc_dir: proc_dir(std::process::id()),
        guest: "/".into(),
        dev,
        ino,
    }
    .open(me())
    .unwrap();
    // procfs reports size 0, so the read is empty, but it is allowed.
    assert!(read(&in_container, "proc/version", 0, 16).is_ok());
}

#[test]
fn a_container_root_needs_the_live_init_and_the_pinned_guest_root() {
    let (m, out) = mount("bind");
    assert!(bind(&m).open(me()).is_ok());
    let (dev, ino) = pin(&out);
    let other = RootSource::Bind {
        proc_dir: proc_dir(std::process::id()),
        guest: m.display().to_string(),
        dev,
        ino,
    };
    assert_eq!(other.open(me()).err(), Some(FsError::MountChanged));
    let missing = RootSource::Bind {
        proc_dir: proc_dir(std::process::id()),
        guest: m.join("nope").display().to_string(),
        dev,
        ino,
    };
    assert_eq!(missing.open(me()).err(), Some(FsError::MountChanged));
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
    assert_eq!(via_link.open(me()).err(), Some(FsError::MountChanged));
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
        assert_eq!(src.open(me()).err(), Some(FsError::ContainerGone));
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
        assert_eq!(src.open(me()).err(), Some(FsError::MountChanged), "{guest}");
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
    let root = host(&m).open(me()).unwrap();
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
    let root = host(&m).open(me()).unwrap();
    let l = list(&root, "").unwrap();
    assert_eq!((l.entries.len(), l.truncated), (MAX_ENTRIES, false));
    std::fs::write(m.join("one-more"), b"").unwrap();
    let l = list(&root, "").unwrap();
    assert_eq!((l.entries.len(), l.truncated), (MAX_ENTRIES, true));
}

/// Security review LOW-4: names that are never listed still count towards the scan bound.
#[test]
fn a_listing_reads_at_most_max_scanned_entries() {
    assert_eq!(MAX_SCANNED, 10 * MAX_ENTRIES);
    let (m, _) = mount("scan-cap");
    let mut name = b"bad\xff".to_vec();
    for i in 0..MAX_SCANNED {
        name.truncate(4);
        name.extend_from_slice(i.to_string().as_bytes());
        std::fs::write(m.join(std::ffi::OsStr::from_bytes(&name)), b"").unwrap();
    }
    let root = host(&m).open(me()).unwrap();
    let l = list(&root, "").unwrap();
    assert!(l.truncated);
    assert!(l.entries.is_empty());
    // `.` and `..` are read too, so a little less than the bound is counted.
    let unlisted = usize::try_from(l.unlisted).unwrap();
    assert!(
        (MAX_SCANNED - 2..MAX_SCANNED).contains(&unlisted),
        "{unlisted}"
    );
}

#[test]
fn a_write_creates_or_replaces_a_regular_file_only() {
    let (m, _) = mount("write");
    let root = host(&m).open(me()).unwrap();
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
        let root = src.open(me()).unwrap();
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

/// The two guards no resolution can reach today, tested where they decide: a symlink met as the
/// target escapes, and a name created by someone else between the probe and the create is
/// refused rather than judged as the wrong case.
#[test]
fn a_symlink_target_escapes_and_a_lost_create_race_is_refused() {
    let (m, _) = mount("guards");
    std::os::unix::fs::symlink("x", m.join("l")).unwrap();
    std::fs::write(m.join("f"), b"").unwrap();
    let st = |p: &str| rustix::fs::lstat(m.join(p).as_path()).unwrap();
    assert_eq!(kind_ok(&st("l"), false), Err(FsError::Escapes));
    assert_eq!(kind_ok(&st("."), false), Err(FsError::NotAFile));
    assert_eq!(kind_ok(&st("f"), true), Ok(()));
    assert_eq!(create_error(FsError::Io(Errno::EXIST)), FsError::Permission);
    for other in [
        FsError::NoSpace,
        FsError::ReadOnly,
        FsError::Io(Errno::IO),
        FsError::NotFound,
    ] {
        assert_eq!(create_error(other), other);
    }
}

#[test]
fn a_brokered_write_refuses_a_hard_link_and_leaves_its_other_name_untouched() {
    let (m, out) = mount("hardlink");
    std::fs::hard_link(out.join("secret"), m.join("h")).unwrap();
    let root = host(&m).open(me()).unwrap();
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
    check_write(&src.open(me()).unwrap(), "d/f", true).unwrap();
    check_delete(&src.open(me()).unwrap(), "d/f").unwrap();
    std::fs::rename(m.join("d"), m.join("d-moved")).unwrap();
    std::fs::write(out.join("f"), b"outside f").unwrap();
    std::os::unix::fs::symlink(&out, m.join("d")).unwrap();
    let root = src.open(me()).unwrap();
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
    let root = host(&m).open(me()).unwrap();
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
        assert_eq!(e.to_string(), code);
    }
}

#[test]
fn host_paths_join_the_root_and_rel() {
    let r = Path::new("/home/u/notes");
    assert_eq!(host_path(r, ""), "/home/u/notes");
    assert_eq!(host_path(r, "a/b.md"), "/home/u/notes/a/b.md");
}

// Architect ruling Q39: objects are judged by the sandbox's identity, never by sallyd's. The ids
// passed are the seam: another uid with this process's gid is judged by the group bits, another
// uid and gid by the other bits, while the kernel still lets this process do everything.

/// Same gid, another uid: the group class.
fn group() -> UserIds {
    UserIds {
        uid: me().uid.wrapping_add(1),
        gid: me().gid,
    }
}

/// Another uid and gid: the other class (like a group the user holds only as a supplementary
/// group).
fn other() -> UserIds {
    UserIds {
        uid: me().uid.wrapping_add(1),
        gid: me().gid.wrapping_add(1),
    }
}

fn chmod(p: &Path, mode: u32) {
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[test]
fn rt_fs_18_reads_follow_the_sandbox_identity_not_sallyds() {
    let (m, _) = mount("dac-read");
    for (name, mode) in [("g", 0o640), ("u", 0o600), ("o", 0o644)] {
        std::fs::write(m.join(name), b"x").unwrap();
        chmod(&m.join(name), mode);
    }
    for src in [host(&m), bind(&m)] {
        let as_group = src.open(group()).unwrap();
        let as_other = src.open(other()).unwrap();
        assert!(read(&as_group, "g", 0, 1).is_ok());
        assert_eq!(read(&as_other, "g", 0, 1), Err(FsError::Permission));
        assert_eq!(check_read(&as_other, "g"), Err(FsError::Permission));
        assert_eq!(read(&as_group, "u", 0, 1), Err(FsError::Permission));
        assert!(read(&as_other, "o", 0, 1).is_ok());
        assert!(read(&src.open(me()).unwrap(), "u", 0, 1).is_ok());
    }
}

#[test]
fn rt_fs_18_a_directory_must_be_searchable_before_anything_deeper_is_looked_at() {
    let (m, _) = mount("dac-search");
    std::fs::create_dir(m.join("x")).unwrap();
    std::fs::write(m.join("x/f"), b"x").unwrap();
    chmod(&m.join("x/f"), 0o644);
    chmod(&m.join("x"), 0o710);
    let as_group = host(&m).open(group()).unwrap();
    let as_other = host(&m).open(other()).unwrap();
    assert!(read(&as_group, "x/f", 0, 1).is_ok());
    // Search refused: `permission`, whether or not the name exists (no existence oracle).
    for rel in ["x/f", "x/missing"] {
        assert_eq!(
            read(&as_other, rel, 0, 1),
            Err(FsError::Permission),
            "{rel}"
        );
        assert_eq!(
            check_write(&as_other, rel, false),
            Err(FsError::Permission),
            "{rel}"
        );
        assert_eq!(
            check_delete(&as_other, rel),
            Err(FsError::Permission),
            "{rel}"
        );
    }
    // A listing needs read and search: 0710 gives the group search only.
    assert_eq!(list(&as_group, "x").err(), Some(FsError::Permission));
    assert_eq!(check_list(&as_group, "x"), Err(FsError::Permission));
    chmod(&m.join("x"), 0o750);
    assert!(list(&as_group, "x").is_ok());
    // The mount root is judged like every directory.
    chmod(&m, 0o700);
    let as_group = host(&m).open(group()).unwrap();
    assert_eq!(check_list(&as_group, ""), Err(FsError::Permission));
    assert_eq!(read(&as_group, "x/f", 0, 1), Err(FsError::Permission));
    chmod(&m, 0o755);
}

#[test]
fn rt_fs_18_writes_creates_and_deletes_need_the_sandboxs_write_bits() {
    let (m, _) = mount("dac-write");
    std::fs::create_dir(m.join("ro")).unwrap();
    std::fs::create_dir(m.join("rw")).unwrap();
    for d in ["ro", "rw"] {
        std::fs::write(m.join(d).join("f"), b"old").unwrap();
        chmod(&m.join(d).join("f"), 0o644);
    }
    chmod(&m.join("ro"), 0o755);
    chmod(&m.join("rw"), 0o775);
    let as_group = host(&m).open(group()).unwrap();
    // An existing file: its own write bit (0644 gives the group none).
    assert_eq!(
        check_write(&as_group, "rw/f", true),
        Err(FsError::Permission)
    );
    assert_eq!(
        write(&as_group, "rw/f", b"new", true),
        Err(FsError::Permission)
    );
    assert_eq!(
        std::fs::read(m.join("rw/f")).unwrap(),
        b"old",
        "truncated anyway"
    );
    chmod(&m.join("rw/f"), 0o664);
    check_write(&as_group, "rw/f", true).unwrap();
    write(&as_group, "rw/f", b"new", true).unwrap();
    assert_eq!(std::fs::read(m.join("rw/f")).unwrap(), b"new");
    // A new file and a delete: the parent's write and search bits.
    assert_eq!(
        check_write(&as_group, "ro/n", true),
        Err(FsError::Permission)
    );
    assert_eq!(
        write(&as_group, "ro/n", b"x", true),
        Err(FsError::Permission)
    );
    assert!(!m.join("ro/n").exists());
    assert_eq!(check_delete(&as_group, "ro/f"), Err(FsError::Permission));
    assert_eq!(delete(&as_group, "ro/f"), Err(FsError::Permission));
    assert!(m.join("ro/f").exists());
    check_write(&as_group, "rw/n", true).unwrap();
    write(&as_group, "rw/n", b"x", true).unwrap();
    assert_eq!(std::fs::read(m.join("rw/n")).unwrap(), b"x");
    check_delete(&as_group, "rw/n").unwrap();
    delete(&as_group, "rw/n").unwrap();
    assert!(!m.join("rw/n").exists());
    // The other class: a group-shared folder (0770) the sandbox's gid does not own.
    chmod(&m.join("rw"), 0o770);
    let as_other = host(&m).open(other()).unwrap();
    assert_eq!(
        write(&as_other, "rw/n", b"x", true),
        Err(FsError::Permission)
    );
    assert!(!m.join("rw/n").exists());
}

/// Security re-review MEDIUM-1: a refused file is never opened for I/O (opening a device with the
/// broker's groups can already act). The kernel sends no open event for an `O_PATH` fd, so an
/// `IN_OPEN` watch sees only a real open.
#[test]
fn rt_fs_18_a_refused_file_is_never_opened() {
    use rustix::fs::inotify::{CreateFlags, WatchFlags, add_watch, init};
    let (m, _) = mount("dac-open");
    std::fs::write(m.join("f"), b"x").unwrap();
    chmod(&m.join("f"), 0o600);
    #[allow(clippy::disallowed_methods)] // CLOEXEC is passed: the lint's reason does not apply
    let watch = init(CreateFlags::NONBLOCK | CreateFlags::CLOEXEC).unwrap();
    add_watch(&watch, m.join("f").as_path(), WatchFlags::OPEN).unwrap();
    let opened = || {
        let mut buf = [0u8; 4096];
        match rustix::io::read(&watch, &mut buf) {
            Ok(n) => n > 0,
            Err(Errno::AGAIN) => false,
            Err(e) => panic!("{e}"),
        }
    };
    for src in [host(&m), bind(&m)] {
        let as_other = src.open(other()).unwrap();
        assert_eq!(read(&as_other, "f", 0, 1), Err(FsError::Permission));
        assert_eq!(write(&as_other, "f", b"y", false), Err(FsError::Permission));
        assert!(!opened(), "a refused file was opened");
        // The control: an allowed read opens it, and the watch sees that.
        read(&src.open(me()).unwrap(), "f", 0, 1).unwrap();
        assert!(opened(), "the watch saw no open");
    }
    assert_eq!(std::fs::read(m.join("f")).unwrap(), b"x");
}

/// Holds a write lease on a file: the open that breaks it ends the holder (`SIGIO`, default
/// action), releasing the lease. Rust has no lease call without `unsafe` or a new crate, so a
/// `python3` process takes it (architect ruling Q40). Killed and reaped on drop.
struct Lease(std::process::Child);

impl Lease {
    /// The lease is taken only once the holder prints `ready`; anything else fails the test.
    fn take(path: &Path) -> Self {
        use std::io::BufRead as _;
        const SCRIPT: &str = "import fcntl, os, sys, time\n\
            fd = os.open(sys.argv[1], os.O_RDONLY)\n\
            fcntl.fcntl(fd, fcntl.F_SETLEASE, fcntl.F_WRLCK)\n\
            print('ready', flush=True)\n\
            time.sleep(60)\n";
        let child = std::process::Command::new("python3")
            .args(["-I", "-c", SCRIPT])
            .arg(path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("this test needs python3 on PATH: {e}"));
        let mut lease = Self(child);
        let out = lease.0.stdout.take().expect("piped stdout");
        let mut line = String::new();
        std::io::BufReader::new(out)
            .read_line(&mut line)
            .expect("the lease holder's ready line");
        assert_eq!(
            line.trim(),
            "ready",
            "the lease holder could not take its lease (see its stderr above)"
        );
        lease
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Q40: a file another process holds a lease on fails at once (`O_NONBLOCK`) instead of parking
/// a broker thread, and with it the exec gate on a write, until the lease breaks.
#[test]
fn a_leased_file_fails_at_once_instead_of_stalling_the_broker() {
    let (m, _) = mount("lease");
    std::fs::write(m.join("f"), b"x").unwrap();
    let root = host(&m).open(me()).unwrap();
    {
        let _held = Lease::take(&m.join("f"));
        assert_eq!(read(&root, "f", 0, 1), Err(FsError::Io(Errno::AGAIN)));
    }
    {
        let _held = Lease::take(&m.join("f"));
        assert_eq!(
            write(&root, "f", b"y", false),
            Err(FsError::Io(Errno::AGAIN))
        );
    }
    assert_eq!(
        std::fs::read(m.join("f")).unwrap(),
        b"x",
        "truncated anyway"
    );
    // The control: with no lease the same read runs.
    assert_eq!(read(&root, "f", 0, 1).unwrap().bytes, b"x");
}

/// An object carrying an access ACL is judged by its owner bits only: its group bits are the
/// ACL mask, and named entries cannot be judged by mode bits.
#[test]
fn rt_fs_18_an_acl_leaves_a_non_owner_nothing() {
    let (m, _) = mount("dac-acl");
    std::fs::write(m.join("f"), b"x").unwrap();
    chmod(&m.join("f"), 0o644);
    let as_other = host(&m).open(other()).unwrap();
    assert!(read(&as_other, "f", 0, 1).is_ok());
    // ACL_USER_OBJ rw, ACL_USER nobody r, ACL_GROUP_OBJ r, ACL_MASK r, ACL_OTHER r.
    let mut blob = 2u32.to_le_bytes().to_vec();
    for (tag, perm, id) in [
        (1u16, 6u16, u32::MAX),
        (2, 4, 65_534),
        (4, 4, u32::MAX),
        (0x10, 4, u32::MAX),
        (0x20, 4, u32::MAX),
    ] {
        blob.extend_from_slice(&tag.to_le_bytes());
        blob.extend_from_slice(&perm.to_le_bytes());
        blob.extend_from_slice(&id.to_le_bytes());
    }
    rustix::fs::setxattr(
        m.join("f").as_path(),
        "system.posix_acl_access",
        &blob,
        rustix::fs::XattrFlags::empty(),
    )
    .unwrap();
    assert_eq!(read(&as_other, "f", 0, 1), Err(FsError::Permission));
    assert!(read(&host(&m).open(me()).unwrap(), "f", 0, 1).is_ok());
}
