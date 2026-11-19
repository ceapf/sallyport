//! Unit tests of the mount-link probe's pure parts: the walk (allow and deny), the probe's name
//! and argv, and the inspect parses.
#![allow(clippy::unwrap_used)]

use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use rustix::io::Errno;

use super::*;
use crate::egress::scratch::{Scratch, scratch};

/// A fresh root directory under `target/mount-probe-unit` holding the image-like tree every walk
/// test reads, and its guard:
///
/// ```text
/// workspace/a/        directory
/// workspace/b -> a    a link above any destination below /workspace/b
/// workspace/q -> p/x  a link at a destination
/// workspace/up -> /etc  an absolute link
/// workspace/f         regular file
/// workspace/fifo      FIFO
/// tmp -> workspace/a  a one-component link
/// etc/                directory
/// ```
fn tree(tag: &str) -> (PathBuf, Scratch) {
    let guard = scratch("mount-probe-unit", tag);
    let root = guard.join("root");
    std::fs::create_dir_all(root.join("workspace/a")).unwrap();
    std::fs::create_dir_all(root.join("etc")).unwrap();
    symlink("a", root.join("workspace/b")).unwrap();
    symlink("p/x", root.join("workspace/q")).unwrap();
    symlink("/etc", root.join("workspace/up")).unwrap();
    std::fs::write(root.join("workspace/f"), b"x").unwrap();
    rustix::fs::mknodat(
        rustix::fs::CWD,
        root.join("workspace/fifo"),
        FileType::Fifo,
        Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    symlink("workspace/a", root.join("tmp")).unwrap();
    (guard.to_path_buf(), guard)
}

fn dir(p: &Path) -> rustix::fd::OwnedFd {
    sally_core::fd::open(p, OFlags::PATH | OFlags::DIRECTORY, Mode::empty()).unwrap()
}

fn refused(dest: &str, why: &str) -> Result<Found, Refused> {
    Err(Refused {
        dest: dest.into(),
        why: why.into(),
    })
}

fn link(e: Errno) -> String {
    format!("not reached without a link: {e}")
}

#[test]
fn a_directory_or_a_regular_file_reached_without_a_link_is_present() {
    let (base, _g) = tree("present");
    let root = dir(&base.join("root"));
    assert_eq!(walk(&root, "/workspace/a"), Ok(Found::Present));
    assert_eq!(walk(&root, "/workspace/f"), Ok(Found::Present));
    assert_eq!(walk(&root, "/etc"), Ok(Found::Present));
}

#[test]
fn a_missing_destination_below_real_directories_is_absent() {
    let (base, _g) = tree("absent");
    let root = dir(&base.join("root"));
    assert_eq!(walk(&root, "/workspace/a/c"), Ok(Found::Absent));
    assert_eq!(walk(&root, "/workspace/p"), Ok(Found::Absent));
    assert_eq!(walk(&root, "/run/sallyport"), Ok(Found::Absent));
}

#[test]
fn a_link_above_a_destination_refuses() {
    let (base, _g) = tree("above");
    let root = dir(&base.join("root"));
    let loop_ = link(Errno::LOOP);
    assert_eq!(
        walk(&root, "/workspace/b/c"),
        refused("/workspace/b/c", &loop_)
    );
    // Even when what lies beyond the link exists.
    std::fs::create_dir(base.join("root/workspace/a/c")).unwrap();
    assert_eq!(
        walk(&root, "/workspace/b/c"),
        refused("/workspace/b/c", &loop_)
    );
    assert_eq!(
        walk(&root, "/workspace/up/passwd"),
        refused("/workspace/up/passwd", &loop_)
    );
}

#[test]
fn a_link_at_a_destination_refuses_whether_its_target_exists_or_not() {
    let (base, _g) = tree("at");
    let root = dir(&base.join("root"));
    let loop_ = link(Errno::LOOP);
    assert_eq!(walk(&root, "/workspace/q"), refused("/workspace/q", &loop_));
    // A link to a directory that exists: still refused (no O_NOFOLLOW success on the link).
    assert_eq!(walk(&root, "/workspace/b"), refused("/workspace/b", &loop_));
    assert_eq!(
        walk(&root, "/workspace/up"),
        refused("/workspace/up", &loop_)
    );
}

#[test]
fn a_link_at_a_one_component_destination_refuses() {
    let (base, _g) = tree("tmp");
    let root = dir(&base.join("root"));
    assert_eq!(walk(&root, "/tmp"), refused("/tmp", &link(Errno::LOOP)));
}

#[test]
fn a_destination_below_a_file_refuses() {
    let (base, _g) = tree("notdir");
    let root = dir(&base.join("root"));
    assert_eq!(
        walk(&root, "/workspace/f/x"),
        refused("/workspace/f/x", &link(Errno::NOTDIR))
    );
}

#[test]
fn a_destination_that_is_neither_a_directory_nor_a_regular_file_refuses() {
    let (base, _g) = tree("fifo");
    let root = dir(&base.join("root"));
    assert_eq!(
        walk(&root, "/workspace/fifo"),
        refused(
            "/workspace/fifo",
            "a Fifo, not a directory or a regular file"
        )
    );
}

#[test]
fn an_unclean_destination_refuses_before_any_open() {
    let (base, _g) = tree("unclean");
    let root = dir(&base.join("root"));
    for d in [
        "",
        "/",
        "workspace/a",
        "/workspace/../etc",
        "/workspace/./a",
        "/workspace//a",
        "/workspace/a/",
        "/workspace/\na",
    ] {
        assert_eq!(
            walk(&root, d),
            refused(d, "not a clean absolute path"),
            "{d:?}"
        );
    }
}

#[test]
fn walk_in_opens_the_root_beneath_the_proc_dir_and_stops_at_the_first_refusal() {
    let (base, _g) = tree("walk-in");
    let proc_dir = dir(&base);
    let fine = ["/workspace/a".to_owned(), "/workspace/p".to_owned()];
    assert_eq!(walk_in(&proc_dir, &fine), Ok(()));
    let some = [
        "/workspace/a".to_owned(),
        "/tmp".to_owned(),
        "/workspace/b/c".to_owned(),
    ];
    assert_eq!(
        walk_in(&proc_dir, &some),
        Err(WalkError::Link(Refused {
            dest: "/tmp".into(),
            why: link(Errno::LOOP),
        }))
    );
    assert_eq!(walk_in(&proc_dir, &[]), Ok(()));
    // No `root` beneath the directory: the probe's root cannot be opened.
    let elsewhere = dir(&base.join("root/workspace"));
    assert_eq!(
        walk_in(&elsewhere, &fine),
        Err(WalkError::Root(Errno::NOENT))
    );
    assert_eq!(
        WalkError::Root(Errno::NOENT).to_string(),
        format!("cannot open the probe's root: {}", Errno::NOENT)
    );
    let r = Refused {
        dest: "/tmp".into(),
        why: "w".into(),
    };
    assert_eq!(WalkError::Link(r).to_string(), "/tmp: w");
}

#[test]
fn every_role_has_its_own_probe_prefix_and_name() {
    assert_eq!(
        probe_name("sp-ws-s-1", Role::Workspace).as_deref(),
        Some("sp-probe-ws-s-1")
    );
    assert_eq!(
        probe_name("sp-h-s-1", Role::Harness).as_deref(),
        Some("sp-probe-h-s-1")
    );
    assert_eq!(
        probe_name("sp-infer-i-1", Role::Inference).as_deref(),
        Some("sp-probe-infer-i-1")
    );
    // Another role's name has none.
    assert_eq!(probe_name("sp-h-s-1", Role::Workspace), None);
    assert_eq!(probe_name("sp-ws-s-1", Role::Inference), None);
    assert_eq!(probe_name("sp-probe-ws-s-1", Role::Workspace), None);
}

#[test]
fn no_container_name_of_a_role_starts_with_a_probe_prefix() {
    for role in [Role::Workspace, Role::Harness, Role::Inference] {
        for other in [Role::Workspace, Role::Harness, Role::Inference] {
            assert!(
                !container_prefix(other).starts_with(probe_prefix(role)),
                "{role:?} {other:?}"
            );
            assert!(
                !probe_prefix(role).starts_with(container_prefix(other)),
                "{role:?} {other:?}"
            );
        }
    }
}

fn strings(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| (*s).to_owned()).collect()
}

#[test]
fn the_probe_argv_leaves_out_every_bind_and_the_device_and_takes_the_probe_name() {
    let args = strings(&[
        "--runtime",
        "/r",
        "create",
        "--rm",
        "--name",
        "sp-infer-i-1",
        "-v",
        "/h:/g:ro",
        "--tmpfs",
        "/tmp:rw",
        "--device",
        "nvidia.com/gpu=all",
        "-v",
        "/h2:/g2:O,upperdir=u",
        "--env",
        "A=1",
        "img@sha256:x",
        "-v",
        "--name",
        "--device",
    ]);
    assert_eq!(
        probe_argv(&args, "sp-probe-infer-i-1", "img@sha256:x"),
        strings(&[
            "--runtime",
            "/r",
            "create",
            "--rm",
            "--name",
            "sp-probe-infer-i-1",
            "--tmpfs",
            "/tmp:rw",
            "--env",
            "A=1",
            "img@sha256:x",
            "-v",
            "--name",
            "--device",
        ])
    );
}

const ID: &str = "3ab194ff0123456789abcdef0123456789abcdef0123456789abcdef01234567";

#[test]
fn the_probe_inspect_gives_a_pid_above_one_and_a_full_image_id() {
    assert_eq!(
        parse_pid_image(&format!("42 {ID}\n")),
        Some((42, ID.to_owned()))
    );
    assert_eq!(
        parse_pid_image(&format!("  2   {ID}  ")),
        Some((2, ID.to_owned()))
    );
    let upper = ID.to_uppercase();
    let short = &ID[..63];
    let long = format!("{ID}0");
    let not_hex = ID.replacen('3', "g", 1);
    for bad in [
        format!("1 {ID}"),
        format!("0 {ID}"),
        format!("-5 {ID}"),
        format!("x {ID}"),
        format!("42 {upper}"),
        format!("42 {short}"),
        format!("42 {long}"),
        format!("42 {not_hex}"),
        format!("42 {ID} 7"),
        "42".to_owned(),
        String::new(),
    ] {
        assert_eq!(parse_pid_image(&bad), None, "{bad:?}");
    }
}

#[test]
fn the_container_inspect_gives_a_full_image_id() {
    assert_eq!(parse_image(&format!("{ID}\n")), Some(ID.to_owned()));
    assert_eq!(parse_image(&format!(" {ID} ")), Some(ID.to_owned()));
    for bad in [
        String::new(),
        ID[..63].to_owned(),
        format!("{ID}0"),
        format!("{ID} {ID}"),
        ID.to_uppercase(),
        ID.replacen('a', "/", 1),
        ID.replacen('a', "`", 1),
        ID.replacen('0', "@", 1),
    ] {
        assert_eq!(parse_image(&bad), None, "{bad:?}");
    }
}

#[test]
fn the_inspect_formats_ask_for_the_pid_and_the_image_id() {
    assert_eq!(PID_IMAGE_FORMAT, "{{.State.Pid}} {{.Image}}");
    assert_eq!(IMAGE_FORMAT, "{{.Image}}");
}
