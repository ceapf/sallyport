//! Cleanup that fails the first time, with real containers (rootless Podman): a failed launch
//! whose cleanup could not remove its container is retried until the container is gone, holding
//! the session's claim and forms until `sandbox.cleaned`; an orphan sweep removes an orphan
//! whose first removal failed while it was paused, audits a removal that failed and goes on to
//! the next. Each failure is injected by a podman wrapper.
//!
//! The fixture is `common::container`; these tests never skip.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use sallyd::sandbox::{LaunchError, Sweep};

mod common;
use common::container::*;
use common::egress::canary;
use common::*;

/// The longest a test waits for a retry it caused.
const BOUND: Duration = Duration::from_secs(60);

/// `GITHUB_TOKEN` injected on `mock.test`, so a launch registers the session's forms.
const FORMS: &str = "network:\n  mode: proxy\n  allow:\n    - host: mock.test\n\
                     secrets:\n  - name: GITHUB_TOKEN\n    inject: {host: mock.test, \
                     header: Authorization, format: \"Bearer {value}\"}\n";

/// A fresh directory for a test's podman wrapper, removed when the guard drops.
fn wrapper_dir(tag: &str) -> (PathBuf, RemoveOnDrop) {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("cleanup-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    (dir.clone(), RemoveOnDrop(dir))
}

/// A podman whose `start` fails while `<at>/start-fails` exists (the launch fails with its
/// container created, never run), and whose `rm` of a workspace container (`sp-ws-…`, never its
/// probe) fails while `<at>/rm-fails` exists, adding a line to `<at>/rm-refused` each time.
/// `start` comes third (`--default-mounts-file <file> start <id>`, `Podman::spec_args`); `rm`
/// comes first, with the container last (`rm --force … <name>`).
fn ws_rm_failing_podman(at: &Path, real: &Path) -> PathBuf {
    wrap_podman(at, real, |at, real| {
        format!(
            "#!/bin/sh\n\
             for a in \"$@\"; do last=\"$a\"; done\n\
             if [ \"$3\" = start ] && [ -e '{at}/start-fails' ]; then\n\
             echo 'start refused by the test' >&2; exit 125\n\
             fi\n\
             if [ \"$1\" = rm ] && [ -e '{at}/rm-fails' ]; then\n\
             case \"$last\" in sp-ws-*) echo x >> '{at}/rm-refused';\n\
             echo 'rm refused by the test' >&2; exit 125;; esac\n\
             fi\n\
             exec '{real}' \"$@\"\n"
        )
    })
}

/// How many `rm` calls the wrapper refused.
fn refused(at: &Path) -> usize {
    std::fs::read_to_string(at.join("rm-refused"))
        .map(|s| s.lines().count())
        .unwrap_or(0)
}

/// Waits within [`BOUND`] until `done`, naming `what` if it never is.
async fn until(what: &str, mut done: impl FnMut() -> bool) {
    let end = Instant::now() + BOUND;
    while !done() {
        assert!(Instant::now() < end, "{what}: not within {BOUND:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// A launch fails after `podman create` (its `start` is refused) and its cleanup cannot remove
/// the container. Deny leg: while `rm` keeps failing, the
/// container stays, the session stays live (the periodic sweep leaves it), its folder stays
/// claimed and its forms stay registered, and no `sandbox.cleaned` is written. Allow leg: once
/// `rm` works, the retry removes the container and the directories, and `sandbox.cleaned`
/// follows the launch's `sandbox.refuse`; while that entry waits, the claim and the forms are
/// still held (entry, then unclaim, then forget); after it both are released and the same folder
/// launches. Controls, each run by hand: without the retry task no retry comes (the deny leg's
/// wait fails); moving the unclaim before the entry lets the held-window launch through;
/// dropping the task's forget leaves the forms registered.
#[test]
fn a_failed_launch_cleanup_is_retried_until_the_container_is_gone() {
    let (dir, _gone) = wrapper_dir("retry");
    rt().block_on(async {
        let x = Lx::with_podman(|real| ws_rm_failing_podman(&dir, real));
        std::fs::write(dir.join("start-fails"), b"").unwrap();
        std::fs::write(dir.join("rm-fails"), b"").unwrap();
        let body = format!(
            "{}{FORMS}",
            mounts(&[mount("~/code/myproject", "/workspace/p", "rw")])
        );
        let v = x.f.load(&body);
        let req = x.request(&v, "kept");
        let paths = req.paths.clone();
        let id = paths.id().as_str().to_owned();
        let name = format!("sp-ws-{id}");
        let gh = canary("GITHUB_TOKEN");

        let e = x.launcher.launch_workspace(req).await.unwrap_err();
        assert!(e.to_string().contains("start refused by the test"), "{e}");
        std::fs::remove_file(dir.join("start-fails")).unwrap();
        let refuse = x.events.args("sandbox.refuse").unwrap();
        let cleanup = refuse["cleanup"].as_str().unwrap_or_default();
        assert!(cleanup.starts_with("incomplete, kept: "), "{refuse}");

        // Deny leg, after at least one retry (more refusals than the first cleanup's).
        let first = refused(&dir);
        assert!(first > 0, "the first cleanup never tried rm");
        until("a retry", || refused(&dir) > first).await;
        assert!(exists(&name), "the container went while rm failed");
        assert!(
            x.launcher
                .remove_orphans(&x.scope, Sweep::Periodic)
                .await
                .unwrap()
                .is_empty(),
            "the session stays live while its container may exist"
        );
        assert!(exists(&name));
        let e = x.launch(&v, "while-kept").await.unwrap_err();
        assert!(matches!(e, LaunchError::Overlap(_)), "{e}");
        assert!(!x.events.list().iter().any(|e| e == "sandbox.cleaned"));
        assert_eq!(x.redactors.sessions(), std::slice::from_ref(&id));
        assert_eq!(x.redacted.redact(&gh), "[REDACTED:GITHUB_TOKEN]");

        // Allow leg: rm works again; `sandbox.cleaned` is held so the window can be read.
        let unhold = x.events.held(&["sandbox.cleaned"]);
        std::fs::remove_file(dir.join("rm-fails")).unwrap();
        until("the container removed", || !exists(&name)).await;
        x.events.until_parked("sandbox.cleaned", 1).await;
        let e = x.launch(&v, "while-held").await.unwrap_err();
        assert!(
            matches!(e, LaunchError::Overlap(_)),
            "the claim was freed before sandbox.cleaned: {e}"
        );
        assert_eq!(x.redactors.sessions(), std::slice::from_ref(&id));
        assert_eq!(x.redacted.redact(&gh), "[REDACTED:GITHUB_TOKEN]");
        drop(unhold);
        until("the forms released", || x.redactors.sessions().is_empty()).await;
        assert_eq!(x.redacted.redact(&gh), gh);

        let all = x.events.all();
        let at = |event: &str| all.iter().position(|(e, _)| e == event);
        let (refuse_at, cleaned_at) = (at("sandbox.refuse").unwrap(), at("sandbox.cleaned"));
        assert!(cleaned_at.is_some_and(|c| c > refuse_at), "{all:?}");
        let cleaned = x.events.args("sandbox.cleaned").unwrap();
        assert_eq!(cleaned["role"], "workspace", "{cleaned}");
        assert_eq!(cleaned["container"], name.as_str(), "{cleaned}");
        assert!(cleaned["probe"].is_null(), "{cleaned}");
        assert_eq!(cleaned["directories"], "removed", "{cleaned}");
        // The first try and at least one retry (the deny leg's wait may end inside the retry
        // that then removes it).
        let attempts = cleaned["attempts"].as_u64().unwrap_or_default();
        assert!(attempts >= 2, "{cleaned}");
        assert_eq!(
            all.iter().filter(|(e, _)| e == "sandbox.cleaned").count(),
            1
        );
        assert!(!paths.data_root().exists() && !paths.socket_root().exists());

        let r = x.launch(&v, "after-cleaned").await.unwrap();
        x.stop(r).await;
    });
}

/// A podman whose `rm` fails while the container it names (its last argument) is paused, as
/// the real one asks: `inspect` through the real podman prints `paused`. Each refusal adds a
/// line to `<at>/rm-refused`; the message is the test's own. Anything else passes through,
/// including an `inspect` that fails or prints another state. It models a removal that fails on
/// a frozen container: on a loaded host a process can outlive podman's wait ("given PID did not
/// die within timeout"). On an idle host (podman 4.9.3, rootless, cgroup v2) a plain
/// `rm --force --time 0` was measured to remove a paused container, so the failure is injected.
fn paused_rm_failing_podman(at: &Path, real: &Path) -> PathBuf {
    wrap_podman(at, real, |at, real| {
        format!(
            "#!/bin/sh\n\
             for a in \"$@\"; do last=\"$a\"; done\n\
             if [ \"$1\" = rm ] && [ \"$('{real}' inspect --format '{{{{.State.Status}}}}' \
             \"$last\" 2>/dev/null)\" = paused ]; then\n\
             echo x >> '{at}/rm-refused'\n\
             echo 'rm refused by the test: container is paused' >&2; exit 125\n\
             fi\n\
             exec '{real}' \"$@\"\n"
        )
    })
}

/// A sweep removes an orphan the disk watchdog left paused (a `sallyd` killed in the middle
/// of a stage walk), as a stop does: through the removal that thaws and retries. The container
/// is really paused; the failure of `rm` on it is injected by the wrapper. Controls: on the
/// code before this change (a plain `rm`) the startup sweep fails with the wrapper's error;
/// without the thaw in the removal every `rm` is refused and the orphan stays.
#[test]
fn a_paused_orphan_is_removed() {
    let (dir, _gone) = wrapper_dir("paused");
    rt().block_on(async {
        let x = Lx::new();
        let v =
            x.f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", "rw")]));
        let r = x.launch(&v, "paused").await.unwrap();
        let (name, id) = (r.name().to_owned(), r.container().to_owned());
        drop(r); // the "killed" sallyd's handle; the container keeps running
        x.hermetic(&["pause".into(), id.clone()]).await;
        let status = x
            .hermetic(&[
                "inspect".into(),
                "--format".into(),
                "{{.State.Status}}".into(),
                id,
            ])
            .await;
        assert_eq!(status, "paused");
        let next = x.next_sallyd_with_podman(|real| paused_rm_failing_podman(&dir, real));
        let removed = next
            .launcher
            .remove_orphans(&x.scope, Sweep::Startup)
            .await
            .unwrap();
        assert_eq!(removed, std::slice::from_ref(&name));
        assert!(!exists(&name));
        assert_eq!(refused(&dir), 1, "the wrapper refused the paused rm once");
        assert_eq!(next.events.list(), ["sandbox.orphan_removed"]);
    });
}

/// A podman whose `rm` of the container whose full ID is in `<at>/rm-fails` fails while that
/// file exists. `rm` is the first argument the launcher passes and the container its last.
fn id_rm_failing_podman(at: &Path, real: &Path) -> PathBuf {
    wrap_podman(at, real, |at, real| {
        format!(
            "#!/bin/sh\n\
             for a in \"$@\"; do last=\"$a\"; done\n\
             if [ \"$1\" = rm ] && [ -e '{at}/rm-fails' ] && \
             [ \"$last\" = \"$(cat '{at}/rm-fails')\" ]; then\n\
             echo 'rm refused by the test' >&2; exit 125\n\
             fi\n\
             exec '{real}' \"$@\"\n"
        )
    })
}

/// `podman create` of a session-named container of `installation`, out of band; its full ID.
fn orphan(name: &str, installation: &str) -> String {
    let image = test_image();
    let label = format!("sallyport.installation={installation}");
    let made = podman(&[
        "create",
        "--pull=never",
        "--network=none",
        "--name",
        name,
        "--label",
        &label,
        image.as_str(),
    ]);
    assert!(
        made.status.success(),
        "{}",
        String::from_utf8_lossy(&made.stderr)
    );
    String::from_utf8_lossy(&made.stdout).trim().to_owned()
}

/// One orphan's removal fails. The sweep audits it after its
/// `sandbox.orphan_removed` as `sandbox.orphan_remove_failed` (with the error), writes one
/// oplog error line, removes the other orphan anyway, and then returns one error naming the
/// counts and the first name. The next sweep, with `rm` working, removes the one left.
/// Controls: the other orphan's removal (the sweep went on); the second sweep (the failure was
/// the wrapper's, not the container's).
#[test]
fn a_failed_orphan_removal_is_audited_and_the_sweep_goes_on() {
    let (dir, _gone) = wrapper_dir("orphans");
    rt().block_on(async {
        let x = Lx::with_podman(|real| id_rm_failing_podman(&dir, real));
        let (stuck, other) = (
            format!("sp-ws-{}-stuck", x.scope),
            format!("sp-ws-{}-other", x.scope),
        );
        let stuck_id = orphan(&stuck, x.installation.as_str());
        orphan(&other, x.installation.as_str());
        std::fs::write(dir.join("rm-fails"), &stuck_id).unwrap();

        let e = x
            .launcher
            .remove_orphans(&x.scope, Sweep::Periodic)
            .await
            .unwrap_err();
        match &e {
            LaunchError::Command { verb: "rm", msg } => assert_eq!(
                msg,
                &format!("1 of 2 orphaned containers not removed; first: {stuck}")
            ),
            other => panic!("{other}"),
        }
        assert!(exists(&stuck), "the failing removal removed it");
        assert!(!exists(&other), "the sweep stopped at the failure");
        let all = x.events.all();
        let named = |event: &str, container: &str| {
            all.iter()
                .filter(|(e, a)| e == event && a["container"] == container)
                .count()
        };
        assert_eq!(named("sandbox.orphan_removed", &stuck), 1, "{all:?}");
        assert_eq!(named("sandbox.orphan_removed", &other), 1, "{all:?}");
        assert_eq!(named("sandbox.orphan_remove_failed", &stuck), 1, "{all:?}");
        assert_eq!(all.len(), 3, "{all:?}");
        let failed_at = all
            .iter()
            .position(|(e, _)| e == "sandbox.orphan_remove_failed")
            .unwrap();
        let before = all
            .iter()
            .position(|(e, a)| e == "sandbox.orphan_removed" && a["container"] == stuck.as_str())
            .unwrap();
        assert!(before < failed_at, "{all:?}");
        let failed = x.events.args("sandbox.orphan_remove_failed").unwrap();
        assert_eq!(failed["id"], stuck_id.as_str(), "{failed}");
        assert_eq!(failed["sweep"], "periodic", "{failed}");
        let detail = failed["detail"].as_str().unwrap_or_default();
        assert!(detail.contains("rm refused by the test"), "{failed}");
        let log = x.oplog_lines.text();
        let lines: Vec<_> = log
            .lines()
            .filter(|l| l.contains("orphan") && l.contains(&stuck))
            .collect();
        assert_eq!(lines.len(), 1, "{log}");

        std::fs::remove_file(dir.join("rm-fails")).unwrap();
        let removed = x
            .launcher
            .remove_orphans(&x.scope, Sweep::Periodic)
            .await
            .unwrap();
        assert_eq!(removed, std::slice::from_ref(&stuck));
        assert!(!exists(&stuck));
    });
}
