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

    /// A dangling symlink in this private directory.
    fn dangling(&self, name: &str) -> PathBuf {
        let link = self.0.join(name);
        std::os::unix::fs::symlink(self.0.join("gone"), &link).unwrap();
        link
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

const HINT: &str = "sandbox.podman_path can name another podman";

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

/// Architect Q124: the system search checks its first existing candidate as root-owned; one
/// the user owns is refused naming the check and the setting, and the root-owned one after it
/// is never tried.
#[test]
fn the_system_search_refuses_a_user_owned_first_candidate_without_fall_through() {
    let s = Scratch::new("sys-mine");
    let e = resolve_in(None, &[s.mine("podman"), PathBuf::from("/bin/sh")]).unwrap_err();
    assert!(matches!(e, PodmanError::System(_)), "{e}");
    let msg = e.to_string();
    assert!(msg.starts_with("podman: "), "{msg}");
    assert!(msg.contains(": is not owned by root; "), "{msg}");
    assert!(msg.ends_with(HINT), "{msg}");
}

/// Architect Q123: a dangling link exists for the search (lstat): it is checked and refused,
/// not skipped.
#[test]
fn the_system_search_checks_a_dangling_link_and_does_not_skip_it() {
    let s = Scratch::new("sys-dangling");
    let e = resolve_in(None, &[s.dangling("podman"), PathBuf::from("/bin/sh")]).unwrap_err();
    assert!(matches!(e, PodmanError::System(_)), "{e}");
    let msg = e.to_string();
    assert!(msg.contains(": does not exist; "), "{msg}");
    assert!(msg.ends_with(HINT), "{msg}");
}

/// Absent candidates are skipped; the first root-owned one that exists is used, as `system`.
#[test]
fn the_system_search_skips_absent_candidates() {
    let r = resolve_in(None, &paths(&["/nonexistent/podman", "/bin/sh"])).unwrap();
    assert_eq!(r.source(), PodmanSource::System);
    assert_eq!(r.path(), std::fs::canonicalize("/bin/sh").unwrap());
}

/// No candidate at all: the error lists them and points at the setting.
#[test]
fn no_system_podman_points_at_the_setting() {
    let e = resolve_in(None, &paths(&["/nonexistent/a", "/nonexistent/b"])).unwrap_err();
    assert!(
        matches!(e, PodmanError::NoSystemPodman(ref l) if l.len() == 2),
        "{e}"
    );
    assert_eq!(
        e.to_string(),
        "podman: not found in any of [\"/nonexistent/a\", \"/nonexistent/b\"]; \
         sandbox.podman_path can name a podman elsewhere"
    );
}

/// Only "does not exist" moves a search on; any other stat error is an error.
#[test]
fn a_stat_error_other_than_absence_stops_the_search() {
    for e in [
        first_root_owned("t", &paths(&["/bin/sh/podman", "/bin/sh"])).unwrap_err(),
        resolve_in(None, &paths(&["/bin/sh/podman", "/bin/sh"])).unwrap_err(),
    ] {
        assert!(matches!(e, PodmanError::Io { .. }), "{e}");
        assert!(e.to_string().starts_with("/bin/sh/podman: "), "{e}");
    }
}

/// A helper search (conmon, catatonit) is root-only and never falls through either.
#[test]
fn a_helper_search_is_root_only_without_fall_through() {
    let s = Scratch::new("helper");
    let e = first_root_owned("t", &[s.mine("conmon"), PathBuf::from("/bin/sh")]).unwrap_err();
    assert!(matches!(e, PodmanError::Binary(_)), "{e}");
    let msg = e.to_string();
    assert!(msg.starts_with("t: "), "{msg}");
    assert!(msg.ends_with(": is not owned by root"), "{msg}");
    let e = first_root_owned("t", &[s.dangling("x"), PathBuf::from("/bin/sh")]).unwrap_err();
    assert!(e.to_string().ends_with(": does not exist"), "{e}");
    let p = first_root_owned("t", &paths(&["/nonexistent/a", "/bin/sh", "/usr/bin/env"])).unwrap();
    assert_eq!(p, std::fs::canonicalize("/bin/sh").unwrap());
    let e = first_root_owned("t", &paths(&["/nonexistent/a"])).unwrap_err();
    assert!(
        matches!(e, PodmanError::Missing("t", ref l) if l.len() == 1),
        "{e}"
    );
    assert_eq!(e.to_string(), "t: not found in any of [\"/nonexistent/a\"]");
}

/// A configured podman may be the user's own (the runtime's rule), the system list is not
/// looked at, and its errors name the setting.
#[test]
fn a_configured_podman_may_be_user_owned_and_its_errors_name_the_setting() {
    let s = Scratch::new("configured");
    let mine = s.mine("podman");
    let r = resolve_in(Some(&mine), &paths(&["/nonexistent/podman"])).unwrap();
    assert_eq!(r.source(), PodmanSource::Configured);
    assert_eq!(r.path(), std::fs::canonicalize(&mine).unwrap());
    assert_eq!(resolve_podman(Some(&mine)).unwrap(), r);
    let e = resolve_podman(Some(Path::new("/nonexistent/podman"))).unwrap_err();
    assert!(matches!(e, PodmanError::Binary(_)), "{e}");
    assert!(e.to_string().starts_with("sandbox.podman_path: "), "{e}");
}

/// The check of each source: system is root-only and its refusal points at the setting.
#[test]
fn each_source_is_checked_under_its_own_rule() {
    let s = Scratch::new("system");
    let mine = s.mine("podman");
    let e = check_podman(&mine, PodmanSource::System).unwrap_err();
    assert!(matches!(e, PodmanError::System(_)), "{e}");
    assert!(e.to_string().ends_with(HINT), "{e}");
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
    let sh = paths(&["/bin/sh"]);
    let mine = resolve_podman(Some(&s.mine("podman"))).unwrap();
    assert_eq!(outside_in(&mine, &sh), Some("not owned by root"));
    let configured_sh = resolve_podman(Some(Path::new("/bin/sh"))).unwrap();
    assert_eq!(outside_in(&configured_sh, &sh), None);
    assert_eq!(
        outside_in(
            &configured_sh,
            &paths(&["/nonexistent/podman", "/usr/bin/env"])
        ),
        Some("not in a system directory")
    );
    let system = resolve_in(None, &sh).unwrap();
    assert_eq!(outside_in(&system, &[]), None);
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
        assert!(matches!(e, ProbeError::Format { .. }), "{e}");
        assert!(
            e.to_string().contains("not \"podman version <version>\""),
            "{e}"
        );
    }
    let over = "9".repeat(65);
    assert!(parse_version("p", format!("p version {over}").as_bytes()).is_err());
}

/// A refusal shows at most 80 characters of what was printed, escaped.
#[test]
fn a_bad_version_line_is_shown_cut_and_escaped() {
    let long = format!("x{}", "y".repeat(500));
    let e = parse_version("podman", long.as_bytes())
        .unwrap_err()
        .to_string();
    assert!(
        e.contains(&"y".repeat(79)) && !e.contains(&"y".repeat(80)),
        "{e}"
    );
    let e = parse_version("podman", b"a\x1b[2Jb\"c")
        .unwrap_err()
        .to_string();
    assert!(e.contains(r#""a\u{1b}[2Jb\"c""#), "{e}");
}

/// `/bin/sh -c script` with only the fixed `PATH`; `--version` becomes `$1`.
fn sh(script: &str) -> tokio::process::Command {
    let mut c = tokio::process::Command::new("/bin/sh");
    c.env_clear()
        .env("PATH", PODMAN_PATH_VAR)
        .args(["-c", script, "sh"]);
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
    let e = probe_version(
        sh("echo podman version 1; echo boom >&2; exit 3"),
        "podman",
        t,
    )
    .await
    .unwrap_err();
    assert!(matches!(e, ProbeError::Failed { .. }), "{e}");
    let msg = e.to_string();
    assert!(msg.starts_with("--version failed: "), "{msg}");
    assert!(msg.ends_with(": \"boom\\n\""), "{msg}");
    let e = probe_version(sh("echo hello"), "podman", t)
        .await
        .unwrap_err();
    assert!(e.to_string().contains("\"hello\""), "{e}");
    let e = probe_version(
        tokio::process::Command::new("/nonexistent/podman"),
        "podman",
        t,
    )
    .await
    .unwrap_err();
    assert!(matches!(e, ProbeError::Spawn(_)), "{e}");
}

/// Whether `pid` is gone or a zombie.
fn ended(pid: &str) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Err(_) => true,
        Ok(stat) => stat
            .rsplit_once(") ")
            .is_some_and(|(_, rest)| rest.starts_with('Z')),
    }
}

/// A probe that never finishes is refused at its timeout, and its whole process group is
/// killed: the shell, and a child of it that holds the pipes.
#[tokio::test]
async fn a_probe_that_hangs_is_refused_and_its_process_group_killed() {
    let s = Scratch::new("hang");
    let pids = s.0.join("pids");
    let p = pids.display().to_string();
    assert!(!p.contains('\''), "single-quoted in the script");
    let script = format!("sleep 30 & echo $$ $! >'{p}'; wait");
    let e = probe_version(sh(&script), "podman", Duration::from_millis(1000))
        .await
        .unwrap_err();
    assert!(matches!(e, ProbeError::Timeout(_)), "{e}");
    assert_eq!(e.to_string(), "--version timed out after 1000 ms");
    let text = std::fs::read_to_string(&pids).unwrap();
    let ids: Vec<&str> = text.split_whitespace().collect();
    assert_eq!(ids.len(), 2, "{text}");
    let end = std::time::Instant::now() + Duration::from_secs(5);
    while !ids.iter().all(|id| ended(id)) {
        assert!(std::time::Instant::now() < end, "still running: {ids:?}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Output beyond the cap is drained, so a chatty binary cannot block on a full pipe; its long
/// first line is refused.
#[tokio::test]
async fn a_probe_drains_output_beyond_the_cap() {
    let e = probe_version(
        sh("head -c 100000 /dev/zero | tr '\\0' 'a'"),
        "podman",
        Duration::from_secs(5),
    )
    .await
    .unwrap_err();
    assert!(matches!(e, ProbeError::Format { .. }), "{e}");
}

#[test]
fn the_probe_bounds_are_five_seconds_four_kib_and_eighty_characters() {
    assert_eq!(VERSION_TIMEOUT, Duration::from_secs(5));
    assert_eq!(VERSION_CAP, 4096);
    assert_eq!(VERSION_TOKEN_MAX, 64);
    assert_eq!(SHOWN_MAX, 80);
}

#[test]
fn a_version_error_names_the_field_and_path() {
    let e = version_error(
        sally_core::config::RUNTIME_PATH_FIELD,
        Path::new("/x/crun"),
        &ProbeError::Timeout(Duration::from_millis(5)),
    );
    assert_eq!(
        e.to_string(),
        "sandbox.runtime_path: /x/crun: --version timed out after 5 ms"
    );
}
