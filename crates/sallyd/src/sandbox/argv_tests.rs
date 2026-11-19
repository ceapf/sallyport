//! Unit tests of the argv builders' private helpers (moved out of `argv.rs` to keep it under the
//! file-size ceiling).
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use super::*;
use crate::egress::scratch::Scratch;

/// RT-AG-16 (#92, architect Q192): the grace is pinned as a literal, and the backstop is
/// `runtime.timeout` + grace, with overflow refused.
#[test]
fn the_backstop_is_the_timeout_plus_300_s() {
    assert_eq!(BACKSTOP_GRACE, Duration::from_secs(300));
    let at = |secs| backstop_secs(ManifestDuration::from_secs(secs));
    assert_eq!(at(60).unwrap(), 360);
    assert_eq!(at(7200).unwrap(), 7500);
    assert_eq!(at(0).unwrap(), 300);
    assert_eq!(at(u64::MAX - 300).unwrap(), u64::MAX);
    for secs in [u64::MAX - 299, u64::MAX] {
        let r = at(secs);
        assert!(
            matches!(&r, Err(ArgvError::Input(m)) if m.starts_with("runtime.timeout")),
            "{secs}: {r:?}"
        );
    }
}

/// Each character or segment that would change a `-v`/`--security-opt` argument's meaning
/// is refused on its own; the clean path is the control.
#[test]
fn path_args_refuse_every_separator_and_unclean_segment() {
    assert_eq!(path_arg(Path::new("/a/b"), "p").unwrap(), "/a/b");
    for bad in [
        "/a:b", "/a,b", "/a\nb", "/a//b", "/a/./b", "/a/../b", "/a/b/", "a/b",
    ] {
        let e = path_arg(Path::new(bad), "p").unwrap_err();
        assert!(matches!(e, ArgvError::Input(_)), "{bad:?}: {e:?}");
    }
}

/// The scanner is the only constructor of a [`GitScan`] outside this crate; the builder still
/// re-validates every entry (defense in depth) and these are its refusals.
#[test]
fn git_entries_are_plain_relative_paths_ending_in_one_git_segment() {
    for ok in [".git", "a/.git", "a/b-c/.git"] {
        assert!(git_rel(Path::new(ok), "x").is_ok(), "{ok}");
    }
    for bad in [
        "../x/.git",
        "/abs/.git",
        "a:b/.git",
        "a,ro/.git",
        "not-git",
        "a//.git",
        ".git/modules/x/.git",
        "x/./.git",
        "",
        "a/.git/",
        "a\n/.git",
    ] {
        assert!(git_rel(Path::new(bad), "x").is_err(), "{bad:?}");
    }
}

fn scan(mount: usize, dirs: &[&str], files: &[&str]) -> GitScan {
    GitScan::unchecked(
        mount,
        dirs.iter().map(PathBuf::from).collect(),
        files.iter().map(PathBuf::from).collect(),
    )
}

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

#[test]
fn scans_must_cover_each_rw_mount_exactly_once() {
    let (dir, _gone) = scratch("scans");
    let v = manifest(&dir);
    assert!(scans_by_mount(&v, &[scan(0, &[], &[])]).is_ok());
    for bad in [
        vec![scan(0, &[], &[]), scan(0, &[], &[])],
        vec![scan(0, &[], &[]), scan(1, &[".git"], &[])],
        vec![scan(0, &[], &[]), scan(7, &[".git"], &[])],
        vec![scan(0, &[".git"], &[".git"])],
    ] {
        let e = scans_by_mount(&v, &bad).unwrap_err();
        assert!(e.to_string().contains("filesystem.mounts["), "{e}");
    }
    // A missing scan is refused when the argv is built.
    let mut a = Argv {
        args: Vec::new(),
        intent: Intent::begin(
            Role::Workspace,
            crate::sandbox::UserIds { uid: 1, gid: 1 },
            dir.clone(),
        ),
        name: "sp-ws-s".into(),
    };
    let paths = SessionPaths::new(
        super::super::types::SessionId::parse("s").unwrap(),
        &dir.join("run"),
        &dir.join("data"),
    )
    .unwrap();
    let e = workspace_mounts(&mut a, &paths, &v, &BTreeMap::new()).unwrap_err();
    assert!(e.to_string().contains("rw mount has no git scan"), "{e}");
}

/// Settings whose runtime is an executable `crun` in `dir/<runtime_dir>`, which passes
/// `CheckedRuntime::check` (user-owned, under `target/`), and whose other paths are clean.
fn common_args(dir: &Path, runtime_dir: &str) -> CommonArgs {
    use std::os::unix::fs::PermissionsExt;
    let bin = dir.join(runtime_dir);
    std::fs::create_dir_all(&bin).unwrap();
    // Whatever the umask: the check refuses a group-writable directory above the binary.
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let crun = bin.join("crun");
    std::fs::write(&crun, "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(&crun, std::fs::Permissions::from_mode(0o755)).unwrap();
    CommonArgs {
        runtime: crate::sandbox::CheckedRuntime::check(&crun).unwrap(),
        ids: crate::sandbox::UserIds { uid: 1, gid: 1 },
        profiles: dir.join("profiles"),
        hooks_dir: dir.join("hooks"),
        mounts_file: dir.join("mounts.conf"),
        installation: super::super::types::Installation::parse(
            "00000000-0000-4000-8000-000000000001",
        )
        .unwrap(),
    }
}

/// Architect Q215 (a): `Argv::begin` passes the runtime, the hooks directory, the mounts file
/// and the role's seccomp profile through `path_arg`, and refuses each by its own label; the
/// clean settings are the control.
#[test]
fn begin_refuses_each_unclean_path_by_its_label() {
    let (dir, _gone) = scratch("begin");
    let ok = common_args(&dir, "bin");
    let a = Argv::begin(&ok, "sp-ws-s".to_owned(), Role::Workspace).unwrap();
    let path = |p: &Path| p.to_str().unwrap().to_owned();
    let prefix = [
        "--runtime".to_owned(),
        path(ok.runtime.path()),
        "--hooks-dir".to_owned(),
        path(&ok.hooks_dir),
        "--default-mounts-file".to_owned(),
        path(&ok.mounts_file),
        "create".to_owned(),
    ];
    assert_eq!(a.args.get(..prefix.len()), Some(&prefix[..]));
    let seccomp = format!("seccomp={}/seccomp-workspace.json", ok.profiles.display());
    for want in ["sp-ws-s", "--network=none", seccomp.as_str()] {
        assert!(a.args.iter().any(|x| x == want), "{want}: {:?}", a.args);
    }
    let bad = dir.join("a,b");
    for (label, c) in [
        ("runtime", common_args(&dir, "a,b")),
        (
            "hooks directory",
            CommonArgs {
                hooks_dir: bad.clone(),
                ..ok.clone()
            },
        ),
        (
            "mounts file",
            CommonArgs {
                mounts_file: bad.clone(),
                ..ok.clone()
            },
        ),
        (
            "seccomp profile",
            CommonArgs {
                profiles: bad.clone(),
                ..ok.clone()
            },
        ),
    ] {
        let Err(e) = Argv::begin(&c, "sp-ws-s".to_owned(), Role::Workspace) else {
            panic!("{label}: accepted");
        };
        assert!(
            matches!(&e, ArgvError::Input(m) if m.starts_with(&format!("{label}: "))),
            "{label}: {e:?}"
        );
    }
}

/// A fresh directory under `target/argv-unit`, canonical, and its guard, which removes it on drop
/// so a failing assertion leaves nothing behind.
fn scratch(tag: &str) -> (PathBuf, Scratch) {
    let guard = crate::egress::scratch::scratch("argv-unit", tag);
    (std::fs::canonicalize(&*guard).unwrap(), guard)
}
