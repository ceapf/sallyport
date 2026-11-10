//! `config.toml`: strict parsing and the pinned OCI runtime (AMENDMENTS-02 B5).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use sally_core::config::{
    Config, ConfigError, RuntimeKind, check_runtime_binary, default_runtime_path, parse_config,
};

/// A scratch dir under the target dir (not /tmp: its ancestors must pass the runtime checks),
/// restored to 0700 and removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("sally-config-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Self(d)
    }

    fn dir(&self, rel: &str, mode: u32) -> PathBuf {
        let d = self.0.join(rel);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(mode)).unwrap();
        d
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // Undo any 0777 dirs first so nothing world-writable is left behind.
        for e in walk(&self.0) {
            let _ = std::fs::set_permissions(&e, std::fs::Permissions::from_mode(0o700));
        }
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn walk(d: &Path) -> Vec<PathBuf> {
    let mut out = vec![d.to_path_buf()];
    if let Ok(rd) = std::fs::read_dir(d) {
        for e in rd.flatten() {
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                out.extend(walk(&e.path()));
            }
        }
    }
    out
}

fn exe(path: &Path, mode: u32) {
    std::fs::write(path, b"#!/bin/sh\n").unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[test]
fn empty_config_uses_the_pinned_runtime_default() {
    let c = parse_config("").unwrap();
    assert_eq!(c, Config::default());
    assert_eq!(c.sandbox.runtime, RuntimeKind::Crun);
    assert_eq!(c.sandbox.runtime_path, None);
    assert_eq!(
        default_runtime_path(Path::new("/home/u/.local/share")),
        PathBuf::from("/home/u/.local/share/sallyport/bin/crun")
    );
}

#[test]
fn runtime_path_parses_and_runsc_is_refused_in_v1() {
    let c = parse_config("[sandbox]\nruntime = \"crun\"\nruntime_path = \"/opt/crun\"\n").unwrap();
    assert_eq!(c.sandbox.runtime_path, Some(PathBuf::from("/opt/crun")));
    let e = parse_config("[sandbox]\nruntime = \"runsc\"\n").unwrap_err();
    assert!(
        matches!(
            e,
            ConfigError::Invalid {
                field: "sandbox.runtime",
                ..
            }
        ),
        "{e}"
    );
}

#[test]
fn unknown_keys_and_bad_values_are_refused_with_the_field_named() {
    for (text, field) in [
        ("[sandbox]\nruntime_pth = \"/x\"\n", "runtime_pth"),
        ("[sandbx]\n", "sandbx"),
        ("[sandbox]\nruntime = \"runc\"\n", "runc"),
        (
            "[sandbox]\nruntime_path = \"relative/crun\"\n",
            "sandbox.runtime_path",
        ),
    ] {
        let e = parse_config(text).unwrap_err().to_string();
        assert!(e.contains(field), "{text:?}: {e}");
    }
}

#[test]
fn config_size_limit_is_exact() {
    let at_max = "#".repeat(64 * 1024);
    assert_eq!(parse_config(&at_max).unwrap(), Config::default());
    assert!(matches!(
        parse_config(&format!("{at_max}#")),
        Err(ConfigError::TooLarge)
    ));
}

#[test]
fn runtime_binary_must_be_a_private_executable_file() {
    let s = Scratch::new("bin");
    let d = s.dir("bin", 0o755);
    let good = d.join("crun-1.30.1");
    exe(&good, 0o755);
    let checked = check_runtime_binary(&good).unwrap();
    assert_eq!(checked, std::fs::canonicalize(&good).unwrap());

    // The install layout: a symlink to the versioned file in the same directory.
    std::os::unix::fs::symlink("crun-1.30.1", d.join("crun")).unwrap();
    assert_eq!(check_runtime_binary(&d.join("crun")).unwrap(), checked);

    let not_exec = d.join("plain");
    exe(&not_exec, 0o644);
    let group_writable = d.join("gw");
    exe(&group_writable, 0o775);
    let world_writable = d.join("ww");
    exe(&world_writable, 0o757);
    for (p, why) in [
        (d.join("missing"), "does not exist"),
        (d.clone(), "not a regular file"),
        (not_exec, "not executable"),
        (group_writable, "is writable by group or others"),
        (world_writable, "is writable by group or others"),
    ] {
        let e = check_runtime_binary(&p).unwrap_err().to_string();
        assert!(e.contains(why), "{}: {e}", p.display());
        assert!(e.contains("sandbox.runtime_path"), "{e}");
    }
}

#[test]
fn every_directory_above_the_binary_must_be_private() {
    let s = Scratch::new("ancestors");
    // Parent fine, grandparent group-writable: renaming the parent swaps the binary.
    s.dir("gp", 0o775);
    let parent = s.dir("gp/bin", 0o755);
    let p = parent.join("crun");
    exe(&p, 0o755);
    let e = check_runtime_binary(&p).unwrap_err().to_string();
    assert!(
        e.contains("directory is writable by group or others"),
        "{e}"
    );
    assert!(e.contains("/gp:"), "names the directory: {e}");
}

#[test]
fn a_symlink_is_judged_by_where_its_target_lives() {
    let s = Scratch::new("link");
    let shared = s.dir("shared", 0o777);
    let target = shared.join("crun");
    exe(&target, 0o755);
    let private = s.dir("private", 0o700);
    std::os::unix::fs::symlink(&target, private.join("crun")).unwrap();
    let e = check_runtime_binary(&private.join("crun"))
        .unwrap_err()
        .to_string();
    assert!(
        e.contains("directory is writable by group or others"),
        "{e}"
    );
}

#[test]
fn a_root_owned_system_binary_is_acceptable() {
    // /bin/sh is root-owned in root-owned directories on every supported host.
    assert!(check_runtime_binary(Path::new("/bin/sh")).is_ok());
}
