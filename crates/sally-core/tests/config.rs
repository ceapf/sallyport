//! `config.toml`: strict parsing and the pinned OCI runtime (AMENDMENTS-02 B5).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use sally_core::config::{
    Config, ConfigError, MAX_CONFIG_BYTES, Owner, ReadConfigError, RuntimeKind, check_binary,
    check_runtime_binary, check_trusted_binary, default_runtime_path, parse_config, read_config,
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
        (
            "[sandbox]\npodman_path = \"podman\"\n",
            "sandbox.podman_path",
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

#[test]
fn podman_path_parses_and_defaults_to_none() {
    assert_eq!(parse_config("").unwrap().sandbox.podman_path, None);
    let c = parse_config("[sandbox]\npodman_path = \"/usr/bin/podman\"\n").unwrap();
    assert_eq!(
        c.sandbox.podman_path,
        Some(PathBuf::from("/usr/bin/podman"))
    );
}

/// #11: podman is resolved once and gets the same ownership checks as the runtime; the error
/// names the field it came from.
#[test]
fn trusted_binary_errors_name_their_field() {
    let s = Scratch::new("podman");
    let d = s.dir("shared", 0o777);
    let p = d.join("podman");
    exe(&p, 0o755);
    let e = check_trusted_binary(&p, "sandbox.podman_path")
        .unwrap_err()
        .to_string();
    assert!(e.starts_with("sandbox.podman_path: "), "{e}");
    assert!(e.contains("writable by group or others"), "{e}");
    assert!(check_trusted_binary(Path::new("/bin/sh"), "sandbox.podman_path").is_ok());
}

/// R1 (architect Q124): a binary found by a system search must be owned by root. The user's own
/// executable passes the root-or-user policy of a configured path and fails the root policy,
/// the error naming the field and the check.
#[test]
fn the_root_policy_refuses_a_binary_the_user_owns() {
    let s = Scratch::new("root");
    let d = s.dir("mine", 0o700);
    let p = d.join("podman");
    exe(&p, 0o755);
    assert!(check_binary(&p, "f", Owner::RootOrUser).is_ok());
    assert!(check_trusted_binary(&p, "f").is_ok());
    let e = check_binary(&p, "f", Owner::Root).unwrap_err().to_string();
    assert!(e.starts_with("f: "), "{e}");
    assert!(e.ends_with(": is not owned by root"), "{e}");
}

/// Under the root policy a symlink is judged by its target, like the runtime's: a link the user
/// owns that names a root-owned binary in root-owned directories passes.
#[test]
fn the_root_policy_accepts_a_root_owned_binary_through_a_link() {
    assert!(check_binary(Path::new("/bin/sh"), "f", Owner::Root).is_ok());
    let s = Scratch::new("root-link");
    let d = s.dir("links", 0o700);
    let link = d.join("sh");
    std::os::unix::fs::symlink("/bin/sh", &link).unwrap();
    let real = check_binary(&link, "f", Owner::Root).unwrap();
    assert_eq!(real, std::fs::canonicalize("/bin/sh").unwrap());
}

// ---- reading config.toml (sallyd at start, the CLI for its host facts) -------------------------

fn refusal(path: &Path) -> String {
    match read_config(path) {
        Err(ReadConfigError { msg, path: shown }) => {
            assert_eq!(shown, path.display().to_string());
            msg
        }
        other => panic!("{other:?}"),
    }
}

/// Security review L2: only a regular file is read; a FIFO is refused at once instead of
/// blocking the reader, and neither a symlink nor a directory is read. A missing file is the
/// defaults.
#[test]
fn the_config_is_a_regular_file_never_a_fifo_or_a_symlink() {
    let s = Scratch::new("read");
    let d = s.0.clone();
    let file = d.join("config.toml");
    assert_eq!(read_config(&file).unwrap(), Config::default(), "missing");
    std::fs::write(&file, "[sandbox]\nruntime_path = \"/opt/crun\"\n").unwrap();
    assert_eq!(
        read_config(&file).unwrap().sandbox.runtime_path,
        Some(PathBuf::from("/opt/crun"))
    );
    let link = d.join("link.toml");
    std::os::unix::fs::symlink(&file, &link).unwrap();
    assert_eq!(refusal(&link), "a symlink is not followed");
    assert_eq!(refusal(&d), "not a regular file");
    let fifo = d.join("fifo.toml");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || tx.send(refusal(&fifo)));
    let got = rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("reading a FIFO config blocked");
    assert_eq!(got, "not a regular file");
}

/// The read is bounded one byte past the cap, so a file of exactly the cap parses and one byte
/// more is refused as too large; a parse error names the file.
#[test]
fn the_config_read_is_bounded_at_the_cap() {
    let s = Scratch::new("cap");
    let file = s.0.join("config.toml");
    let at_cap = format!("#{}\n", "x".repeat(MAX_CONFIG_BYTES - 2));
    assert_eq!(at_cap.len(), MAX_CONFIG_BYTES);
    std::fs::write(&file, &at_cap).unwrap();
    assert_eq!(read_config(&file).unwrap(), Config::default());
    std::fs::write(&file, format!("{at_cap} ")).unwrap();
    assert_eq!(refusal(&file), ConfigError::TooLarge.to_string());
    std::fs::write(&file, "[nope]\n").unwrap();
    assert!(refusal(&file).starts_with("config.toml: "), "parse");
    let unreadable = s.0.join("missing-dir/config.toml");
    assert_eq!(read_config(&unreadable).unwrap(), Config::default());
}
