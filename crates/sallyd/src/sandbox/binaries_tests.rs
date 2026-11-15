#![allow(clippy::unwrap_used)]

use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};

use super::*;

/// A private directory beside the test binary (the build directory: every ancestor passes the
/// root-or-user checks, unlike `/tmp`), removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let exe = std::env::current_exe().unwrap();
        let root = exe
            .parent()
            .unwrap()
            .join(format!("sp-bin-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&root)
            .unwrap();
        Self(root)
    }

    /// An executable the user owns, 0755, in this private directory.
    fn mine(&self, name: &str) -> PathBuf {
        let p = self.0.join(name);
        std::fs::write(&p, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn paths(p: &[&str]) -> Vec<PathBuf> {
    p.iter().map(PathBuf::from).collect()
}

/// Architect Q123: the system list is `PODMAN_PATH_VAR`'s directories in its order, and
/// nothing else (no `/usr/local/bin`, never `sallyd`'s `PATH`).
#[test]
fn the_system_candidates_are_the_podman_path_directories_in_order() {
    assert_eq!(
        system_candidates("podman"),
        paths(&[
            "/usr/bin/podman",
            "/bin/podman",
            "/usr/sbin/podman",
            "/sbin/podman"
        ])
    );
}

/// Architect Q124: the first candidate that exists is checked as root-owned; one the user owns
/// is refused naming the check, and the root-owned one after it is never tried.
#[test]
fn a_user_owned_first_candidate_is_refused_without_fall_through() {
    let s = Scratch::new("mine");
    let mine = s.mine("podman");
    let e = first_root_owned("t", &[mine, PathBuf::from("/bin/sh")]).unwrap_err();
    assert!(matches!(e, PodmanError::Binary(_)), "{e}");
    let msg = e.to_string();
    assert!(msg.starts_with("t: "), "{msg}");
    assert!(msg.ends_with(": is not owned by root"), "{msg}");
}

/// Architect Q123: a dangling link exists for the search (lstat): it is checked and refused,
/// not skipped.
#[test]
fn a_dangling_link_is_checked_not_skipped() {
    let s = Scratch::new("dangling");
    let link = s.0.join("podman");
    std::os::unix::fs::symlink(s.0.join("gone"), &link).unwrap();
    let e = first_root_owned("t", &[link, PathBuf::from("/bin/sh")]).unwrap_err();
    assert!(e.to_string().ends_with(": does not exist"), "{e}");
}

/// Only "does not exist" moves the search on; any other stat error is an error.
#[test]
fn a_stat_error_other_than_absence_stops_the_search() {
    let e = first_root_owned("t", &paths(&["/bin/sh/podman", "/bin/sh"])).unwrap_err();
    assert!(matches!(e, PodmanError::Io { .. }), "{e}");
    assert!(e.to_string().starts_with("/bin/sh/podman: "), "{e}");
}

#[test]
fn missing_candidates_are_skipped_and_the_first_existing_one_is_used() {
    let p = first_root_owned("t", &paths(&["/nonexistent/a", "/bin/sh", "/usr/bin/env"])).unwrap();
    assert_eq!(p, std::fs::canonicalize("/bin/sh").unwrap());
    let e = first_root_owned("t", &paths(&["/nonexistent/a", "/nonexistent/b"])).unwrap_err();
    assert!(
        matches!(e, PodmanError::Missing("t", ref l) if l.len() == 2),
        "{e}"
    );
    assert_eq!(
        e.to_string(),
        "t: not found in any of [\"/nonexistent/a\", \"/nonexistent/b\"]"
    );
}

/// A configured podman may be the user's own (the runtime's rule); its errors name the setting.
#[test]
fn a_configured_podman_may_be_user_owned_and_its_errors_name_the_setting() {
    let s = Scratch::new("configured");
    let mine = s.mine("podman");
    let r = resolve_podman(Some(&mine)).unwrap();
    assert_eq!(r.source, PodmanSource::Configured);
    assert_eq!(r.path, std::fs::canonicalize(&mine).unwrap());
    let e = resolve_podman(Some(Path::new("/nonexistent/podman"))).unwrap_err();
    assert!(matches!(e, PodmanError::Binary(_)), "{e}");
    assert!(e.to_string().starts_with("sandbox.podman_path: "), "{e}");
}

/// A system podman is checked as root-owned, and a refusal says the setting can name another.
#[test]
fn a_system_podman_must_be_root_owned_and_its_refusal_points_at_the_setting() {
    let s = Scratch::new("system");
    let mine = s.mine("podman");
    let e = check_podman(&mine, PodmanSource::System).unwrap_err();
    assert!(matches!(e, PodmanError::System(_)), "{e}");
    let msg = e.to_string();
    assert!(msg.starts_with("podman: "), "{msg}");
    assert!(msg.contains(": is not owned by root"), "{msg}");
    assert!(
        msg.ends_with("sandbox.podman_path can name another podman"),
        "{msg}"
    );
    assert!(check_podman(&mine, PodmanSource::Configured).is_ok());
    assert!(check_podman(Path::new("/bin/sh"), PodmanSource::System).is_ok());
}

#[test]
fn each_source_has_its_name_policy_and_field() {
    assert_eq!(PodmanSource::System.as_str(), "system");
    assert_eq!(PodmanSource::Configured.as_str(), "sandbox.podman_path");
    assert_eq!(PodmanSource::System.owner(), Owner::Root);
    assert_eq!(PodmanSource::Configured.owner(), Owner::RootOrUser);
    assert_eq!(PodmanSource::System.field(), "podman");
    assert_eq!(PodmanSource::Configured.field(), "sandbox.podman_path");
}

/// Architect Q125: the daemon says when a configured podman runs only because the setting
/// names it.
#[test]
fn a_configured_podman_outside_the_system_rule_is_named() {
    assert_eq!(outside_reason(false, true), Some("not owned by root"));
    assert_eq!(outside_reason(false, false), Some("not owned by root"));
    assert_eq!(
        outside_reason(true, false),
        Some("not in a system directory")
    );
    assert_eq!(outside_reason(true, true), None);
    let s = Scratch::new("outside");
    let mine = resolve_podman(Some(&s.mine("podman"))).unwrap();
    assert_eq!(outside_system_rule(&mine), Some("not owned by root"));
    let sh = ResolvedPodman {
        path: std::fs::canonicalize("/bin/sh").unwrap(),
        source: PodmanSource::Configured,
    };
    assert_eq!(outside_system_rule(&sh), Some("not in a system directory"));
    let system = ResolvedPodman {
        source: PodmanSource::System,
        ..mine
    };
    assert_eq!(outside_system_rule(&system), None);
}

/// Architect Q126: the version is the bounded token of the first line, nothing else.
#[test]
fn a_version_line_is_parsed_strictly() {
    assert_eq!(
        parse_version("podman", b"podman version 4.9.3\n").unwrap(),
        "4.9.3"
    );
    assert_eq!(
        parse_version("crun", b"crun version 1.21\ncommit: abc\nspec: 1.0.0\n").unwrap(),
        "1.21"
    );
    assert_eq!(
        parse_version("podman", b"podman version 5.0.0-rc1+dev~x").unwrap(),
        "5.0.0-rc1+dev~x"
    );
    let max = "9".repeat(64);
    assert_eq!(
        parse_version("p", format!("p version {max}").as_bytes()).unwrap(),
        max
    );
    for bad in [
        &b""[..],
        b"\n",
        b"podman version \n",
        b"podman version 4.9.3 extra\n",
        b"podman version 4.9.3\r\n",
        b"podman version 4.9/3\n",
        b"Podman version 4.9.3\n",
        b"podman  version 4.9.3\n",
        b"crun version 1.21\n",
        b"podman version 4.\xff\n",
        b"x podman version 4.9.3\n",
    ] {
        let e = parse_version("podman", bad).unwrap_err();
        assert!(e.contains("not \"podman version <version>\""), "{e}");
    }
    let over = "9".repeat(65);
    assert!(parse_version("p", format!("p version {over}").as_bytes()).is_err());
}

/// A refusal shows at most 80 characters of what was printed.
#[test]
fn a_bad_version_line_is_shown_cut() {
    let long = format!("x{}", "y".repeat(500));
    let e = parse_version("podman", long.as_bytes()).unwrap_err();
    assert!(
        e.contains(&"y".repeat(79)) && !e.contains(&"y".repeat(80)),
        "{e}"
    );
}

fn sh(script: &str) -> tokio::process::Command {
    let mut c = tokio::process::Command::new("/bin/sh");
    // `--version` is appended: it becomes `$1` of the script.
    c.env_clear().args(["-c", script, "sh"]);
    c
}

#[tokio::test]
async fn a_probe_reads_the_version_and_refuses_failure_and_bad_output() {
    let t = Duration::from_secs(5);
    let ok = probe_version(
        sh("printf 'podman version 4.9.3\\n'; [ \"$1\" = --version ]"),
        "podman",
        t,
    )
    .await
    .unwrap();
    assert_eq!(ok, "4.9.3");
    let e = probe_version(sh("echo podman version 1; exit 3"), "podman", t)
        .await
        .unwrap_err();
    assert!(e.starts_with("--version failed: "), "{e}");
    let e = probe_version(sh("echo hello"), "podman", t)
        .await
        .unwrap_err();
    assert!(e.contains("\"hello\""), "{e}");
    let e = probe_version(
        tokio::process::Command::new("/nonexistent/podman"),
        "podman",
        t,
    )
    .await
    .unwrap_err();
    assert!(!e.is_empty());
}

/// A probe that never finishes is killed at the timeout and refused.
#[tokio::test]
async fn a_probe_that_hangs_is_refused_at_its_timeout() {
    let start = std::time::Instant::now();
    let e = probe_version(sh("exec sleep 30"), "podman", Duration::from_millis(200))
        .await
        .unwrap_err();
    assert_eq!(e, "--version timed out after 200 ms");
    assert!(start.elapsed() < Duration::from_secs(10));
}

/// Output beyond the cap is drained, not kept: a huge first line is refused, never buffered.
#[tokio::test]
async fn a_probe_keeps_at_most_the_cap() {
    let e = probe_version(
        sh("head -c 100000 /dev/zero | tr '\\0' 'a'"),
        "podman",
        Duration::from_secs(5),
    )
    .await
    .unwrap_err();
    assert!(e.contains("not \"podman version <version>\""), "{e}");
}

#[test]
fn the_probe_bounds_are_five_seconds_and_four_kib() {
    assert_eq!(VERSION_TIMEOUT, Duration::from_secs(5));
    assert_eq!(VERSION_CAP, 4096);
    assert_eq!(VERSION_TOKEN_MAX, 64);
}

#[test]
fn a_version_error_names_the_field_and_path() {
    let e = version_error(RUNTIME_FIELD, Path::new("/x/crun"), "boom".into());
    assert_eq!(e.to_string(), "sandbox.runtime_path: /x/crun: boom");
}
