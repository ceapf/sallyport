//! Cleanup that fails the first time, with real containers (rootless Podman): a failed launch
//! whose cleanup could not remove its container is retried, backed off and capped, holding the
//! session's claim and forms until `sandbox.cleaned`, and its claim past the cap
//! (`sandbox.cleanup_abandoned`); an orphan sweep never thaws a paused orphan, audits a
//! removal that failed and goes on to the next. Each failure is injected by a podman wrapper.
//!
//! The fixture is `common::container`; these tests never skip.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use sallyd::sandbox::{CLEANUP_TRIES, CleanupSchedule, LaunchError, Sweep};

mod common;
use common::container::*;
use common::egress::canary;
use common::*;

/// The longest a test waits for a retry it caused.
const BOUND: Duration = Duration::from_secs(60);

/// A failed launch's cleanup schedule for the tests that wait through its tries: the
/// production one's ten tries, with 100 ms pauses. A try whose `rm` keeps failing still takes
/// the removal's own attempts, about 6 s.
const SHORT: CleanupSchedule = CleanupSchedule::with_pauses([Duration::from_millis(100); 9]);

/// [`SHORT`] for the first five pauses, then 30 s: a test that waits for six tries and then
/// lets the removal work has a whole pause to read the deny leg before the seventh try, and
/// three more tries after it before the cap.
const SIX_THEN_SLOW: CleanupSchedule = CleanupSchedule::with_pauses([
    Duration::from_millis(100),
    Duration::from_millis(100),
    Duration::from_millis(100),
    Duration::from_millis(100),
    Duration::from_millis(100),
    Duration::from_secs(30),
    Duration::from_secs(30),
    Duration::from_secs(30),
    Duration::from_secs(30),
]);

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

/// The longest a test waits for six, or all ten, tries of a cleanup whose `rm` keeps failing
/// (each try is the removal's four attempts two seconds apart and about ten podman calls, then
/// the pause: about 7 s idle, ten tries about 70 s; this leaves room for parallel test runs).
const LONG_BOUND: Duration = Duration::from_secs(300);

/// Waits within [`BOUND`] until `done`, naming `what` if it never is.
async fn until(x: &Lx, what: &str, done: impl FnMut() -> bool) {
    until_within(x, what, BOUND, done).await;
}

/// Waits within `bound` until `done`, naming `what` if it never is. A panic in a task `x`'s
/// launcher spawned (the retried cleanup) fails the wait at once, with its text.
async fn until_within(x: &Lx, what: &str, bound: Duration, mut done: impl FnMut() -> bool) {
    let end = Instant::now() + bound;
    while !done() {
        x.assert_no_crash();
        assert!(Instant::now() < end, "{what}: not within {bound:?}");
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
        let x = Lx::with_podman_and_cleanup(|real| ws_rm_failing_podman(&dir, real), SIX_THEN_SLOW);
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

        // Deny leg, past the last try a cleanup that took the container for gone could make:
        // three bounded tries after the first try that saw it "gone", which is try 4 when both
        // checks misjudge and try 5 when only the retry task's does. Each try refuses `first`
        // removals, so a refusal beyond `first * 5` is a sixth try, and the claim is still held.
        let first = refused(&dir);
        assert!(first > 0, "the first cleanup never tried rm");
        let past_the_bound = first * 5;
        until_within(&x, "a sixth try", LONG_BOUND, || {
            refused(&dir) > past_the_bound
        })
        .await;
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
        assert_eq!(
            x.launcher.unconfirmed_containers(),
            std::slice::from_ref(&id)
        );
        assert_eq!(x.redactors.sessions(), std::slice::from_ref(&id));
        assert_eq!(x.redacted.redact(&gh), "[REDACTED:GITHUB_TOKEN]");

        // Allow leg: rm works again; `sandbox.cleaned` is held so the window can be read.
        let unhold = x.events.held(&["sandbox.cleaned"]);
        std::fs::remove_file(dir.join("rm-fails")).unwrap();
        until(&x, "the container removed", || !exists(&name)).await;
        x.events.until_parked("sandbox.cleaned", 1).await;
        let e = x.launch(&v, "while-held").await.unwrap_err();
        assert!(
            matches!(e, LaunchError::Overlap(_)),
            "the claim was freed before sandbox.cleaned: {e}"
        );
        assert_eq!(x.redactors.sessions(), std::slice::from_ref(&id));
        assert_eq!(x.redacted.redact(&gh), "[REDACTED:GITHUB_TOKEN]");
        drop(unhold);
        until(&x, "the forms released", || {
            x.redactors.sessions().is_empty()
        })
        .await;
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
        // At least the six tries the deny leg waited for (its wait may end inside the sixth,
        // which then removes it), and within the cap.
        let attempts = cleaned["attempts"].as_u64().unwrap_or_default();
        assert!((6..=CLEANUP_TRIES as u64).contains(&attempts), "{cleaned}");
        assert!(x.launcher.unconfirmed_containers().is_empty());
        assert_eq!(
            all.iter().filter(|(e, _)| e == "sandbox.cleaned").count(),
            1
        );
        assert!(!paths.data_root().exists() && !paths.socket_root().exists());

        let r = x.launch(&v, "after-cleaned").await.unwrap();
        x.stop(r).await;
    });
}

/// RT-AG-08b, a failed launch's leftover: a launch that fails after `podman create` and whose
/// container cannot be removed keeps its folder claimed for as long as that container may
/// run, while its cleanup backs off and stops at its cap.
///
/// Control (its messages start `control:`): a removal that fails at the launch's own cleanup
/// try and then works is followed by `sandbox.cleaned`, and the same folder then launches.
///
/// Product: the removal keeps failing. The same folder is refused `overlap` during the retries
/// and after `sandbox.cleanup_abandoned` (denied, naming the container, ten tries, the
/// directories kept, the last error); no `sandbox.cleaned` follows; the session is still live
/// (the periodic sweep leaves its container) and among the unconfirmed containers; no try comes
/// after the cap. Hand check: an unclaim added at the cap fails the "after" leg.
#[test]
fn rt_ag_08b_a_failed_launch_keeps_its_claim_through_the_capped_cleanup() {
    let (dir, _gone) = wrapper_dir("rt08b");
    rt().block_on(async {
        let x = Lx::with_podman_and_cleanup(|real| ws_rm_failing_podman(&dir, real), SHORT);
        let v =
            x.f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", "rw")]));
        let mark = |m: &str| std::fs::write(dir.join(m), b"").unwrap();
        let unmark = |m: &str| std::fs::remove_file(dir.join(m)).unwrap();
        let cleaned = || {
            x.events
                .list()
                .iter()
                .filter(|e| *e == "sandbox.cleaned")
                .count()
        };

        mark("start-fails");
        mark("rm-fails");
        let e = x.launch(&v, "control").await.unwrap_err();
        assert!(e.to_string().contains("start refused"), "control: {e}");
        assert!(
            refused(&dir) > 0,
            "control: the first cleanup never tried rm"
        );
        unmark("rm-fails");
        until(&x, "control: sandbox.cleaned", || cleaned() == 1).await;
        unmark("start-fails");
        let r = x.launch(&v, "control-after").await;
        let r = r.unwrap_or_else(|e| panic!("control: the folder is still refused: {e}"));
        x.stop(r).await;

        mark("start-fails");
        mark("rm-fails");
        let req = x.request(&v, "capped");
        let id = req.paths.id().as_str().to_owned();
        let name = format!("sp-ws-{id}");
        let e = x.launcher.launch_workspace(req).await.unwrap_err();
        assert!(e.to_string().contains("start refused"), "{e}");
        unmark("start-fails");
        let e = x.launch(&v, "during").await.unwrap_err();
        assert!(
            matches!(e, LaunchError::Overlap(_)),
            "during the retries: {e}"
        );
        until_within(&x, "sandbox.cleanup_abandoned", LONG_BOUND, || {
            x.events
                .list()
                .iter()
                .any(|e| e == "sandbox.cleanup_abandoned")
        })
        .await;
        let abandoned = x.events.args("sandbox.cleanup_abandoned").unwrap();
        assert_eq!(abandoned["container"], name.as_str(), "{abandoned}");
        assert!(abandoned["probe"].is_null(), "{abandoned}");
        assert_eq!(abandoned["attempts"], CLEANUP_TRIES, "{abandoned}");
        assert_eq!(abandoned["directories"], "kept", "{abandoned}");
        let detail = abandoned["detail"].as_str().unwrap_or_default();
        assert!(detail.contains("rm refused by the test"), "{abandoned}");
        let debug = x.events.debug();
        let entry = debug
            .iter()
            .find(|d| d.contains("\"sandbox.cleanup_abandoned\""))
            .unwrap();
        assert!(entry.contains("decision: Some(\"deny\")"), "{entry}");
        assert!(entry.contains(&format!("\"{id}\"")), "{entry}");

        let e = x.launch(&v, "after").await.unwrap_err();
        assert!(matches!(e, LaunchError::Overlap(_)), "after the cap: {e}");
        assert!(exists(&name), "the container went while rm failed");
        let swept = x
            .launcher
            .remove_orphans(&x.scope, Sweep::Periodic)
            .await
            .unwrap();
        assert!(swept.is_empty(), "the session is no longer live: {swept:?}");
        assert!(exists(&name));
        assert_eq!(
            x.launcher.unconfirmed_containers(),
            std::slice::from_ref(&id)
        );
        assert_eq!(cleaned(), 1, "a sandbox.cleaned for the abandoned launch");
        let at_cap = refused(&dir);
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert_eq!(refused(&dir), at_cap, "a try after the cap");
        unmark("rm-fails");
    });
}

/// A podman whose `start` fails while `<at>/start-fails` exists, and whose `unshare rm` (how the
/// launcher removes a session's directories) fails while `<at>/unshare-fails` exists, adding a
/// line to `<at>/unshare-refused` each time and naming that count in its message.
fn dirs_failing_podman(at: &Path, real: &Path) -> PathBuf {
    wrap_podman(at, real, |at, real| {
        format!(
            "#!/bin/sh\n\
             if [ \"$3\" = start ] && [ -e '{at}/start-fails' ]; then\n\
             echo 'start refused by the test' >&2; exit 125\n\
             fi\n\
             if [ \"$1\" = unshare ] && [ \"$2\" = rm ] && [ -e '{at}/unshare-fails' ]; then\n\
             echo x >> '{at}/unshare-refused'\n\
             echo \"unshare rm refused by the test: try $(wc -l < '{at}/unshare-refused')\" >&2\n\
             exit 125\n\
             fi\n\
             exec '{real}' \"$@\"\n"
        )
    })
}

/// A launch fails after `podman create` and its cleanup removes the container but not the
/// directories. They get three more tries, then the cleanup ends: `sandbox.cleaned` with
/// `directories: kept` and four attempts, one oplog line carrying the last try's error (not the
/// first's), and the claim freed (the same folder launches). A second launch whose
/// `sandbox.cleaned` cannot be written still frees its claim, with an oplog line naming the
/// event. Controls: an unbounded directory phase never writes the entry; keeping the first
/// error fails the oplog check; a task that skips the unclaim after a failed append leaves the
/// folder refused.
#[test]
fn a_failed_launch_gives_up_its_directories_after_three_more_tries() {
    let (dir, _gone) = wrapper_dir("kept");
    rt().block_on(async {
        let x = Lx::with_podman(|real| dirs_failing_podman(&dir, real));
        let v =
            x.f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", "rw")]));
        for marker in ["start-fails", "unshare-fails"] {
            std::fs::write(dir.join(marker), b"").unwrap();
        }
        let req = x.request(&v, "dirs");
        let name = format!("sp-ws-{}", req.paths.id().as_str());
        let e = x.launcher.launch_workspace(req).await.unwrap_err();
        assert!(e.to_string().contains("start refused by the test"), "{e}");
        until(&x, "sandbox.cleaned", || {
            x.events.list().iter().any(|e| e == "sandbox.cleaned")
        })
        .await;
        let cleaned = x.events.args("sandbox.cleaned").unwrap();
        assert_eq!(cleaned["directories"], "kept", "{cleaned}");
        assert_eq!(cleaned["attempts"], 4, "{cleaned}");
        assert_eq!(cleaned["container"], name.as_str(), "{cleaned}");
        assert!(!exists(&name));
        // The oplog is written by its own thread: wait for the line, then read it exactly.
        until(&x, "the kept line", || {
            x.oplog_lines
                .text()
                .lines()
                .any(|l| l.contains("directories not removed"))
        })
        .await;
        let log = x.oplog_lines.text();
        let lines = |what: &str| -> Vec<String> {
            log.lines()
                .filter(|l| l.contains(what))
                .map(str::to_owned)
                .collect()
        };
        let kept = lines("directories not removed");
        assert_eq!(kept.len(), 1, "{log}");
        assert!(kept.iter().all(|l| l.contains("try 4")), "{log}");
        // When the retries started, with the first try's error.
        let started = lines("cleanup is retried");
        assert_eq!(started.len(), 1, "{log}");
        assert!(started.iter().all(|l| l.contains("try 1")), "{log}");
        let e = x.launch(&v, "while-unshare-fails").await.unwrap_err();
        assert!(
            e.to_string().contains("start refused"),
            "the claim was not freed: {e}"
        );

        // The same with the entry's append refused: the claim is freed all the same.
        x.events.fail(&["sandbox.cleaned"]);
        until(&x, "the second sandbox.cleaned attempt", || {
            x.oplog_lines
                .text()
                .lines()
                .any(|l| l.contains("audit entry not written") && l.contains("sandbox.cleaned"))
        })
        .await;
        x.events.fail(&[]);
        for marker in ["start-fails", "unshare-fails"] {
            std::fs::remove_file(dir.join(marker)).unwrap();
        }
        // The unclaim follows that oplog line at once; a launch in between is refused overlap.
        let end = Instant::now() + BOUND;
        let mut n = 0_u32;
        let r = loop {
            n += 1;
            match x.launch(&v, &format!("after-kept-{n}")).await {
                Ok(r) => break r,
                Err(LaunchError::Overlap(_)) if Instant::now() < end => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(e) => panic!("the claim was not freed after a refused append: {e}"),
            }
        };
        x.stop(r).await;
    });
}

/// A podman whose `rm` fails while the container it names (its last argument) is paused, as
/// the real one asks: `inspect` through the real podman prints `paused`. Each refusal adds a
/// line to `<at>/rm-refused`; the message is the test's own. Every call's verb (its first
/// argument) is added to `<at>/calls`. Anything else passes through, including an `inspect`
/// that fails or prints another state. It models a removal that fails on a frozen container:
/// on a loaded host a process can outlive podman's wait ("given PID did not die within
/// timeout"). On an idle host (podman 4.9.3, rootless, cgroup v2) a plain
/// `rm --force --time 0` was measured to remove a paused container, so the failure is injected.
fn paused_rm_failing_podman(at: &Path, real: &Path) -> PathBuf {
    wrap_podman(at, real, |at, real| {
        format!(
            "#!/bin/sh\n\
             echo \"$1\" >> '{at}/calls'\n\
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

/// A sweep never thaws an orphan the disk watchdog left paused (a `sallyd` killed in the middle
/// of a stage walk): when its removal fails, it stays paused, so inert, until a later sweep
/// removes it. The container is really paused; the failure of `rm` on it is injected by the
/// wrapper. The sweep fails naming it, `sandbox.orphan_remove_failed` follows its
/// `sandbox.orphan_removed`, and the wrapper saw no `unpause`. Control, run by hand: routing
/// the sweep through the stop's removal (which thaws and retries) removes the orphan, so the
/// sweep succeeds and the test fails at its first assertion.
#[test]
fn a_paused_orphan_whose_removal_fails_stays_paused() {
    let (dir, _gone) = wrapper_dir("paused");
    rt().block_on(async {
        let x = Lx::new();
        let v =
            x.f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", "rw")]));
        let r = x.launch(&v, "paused").await.unwrap();
        let (name, id) = (r.name().to_owned(), r.container().to_owned());
        x.drop_as_killed(r); // the "killed" sallyd's handle; the container keeps running
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
        // Still paused right before the sweep: the dropped handle's watchdog, cancelled
        // asynchronously, could thaw it if a stage walk were in flight.
        let status = x
            .hermetic(&[
                "inspect".into(),
                "--format".into(),
                "{{.State.Status}}".into(),
                name.clone(),
            ])
            .await;
        assert_eq!(status, "paused", "thawed before the sweep");
        let e = next
            .launcher
            .remove_orphans(&x.scope, Sweep::Startup)
            .await
            .unwrap_err();
        match &e {
            LaunchError::Command { verb: "rm", msg } => assert_eq!(
                msg,
                &format!("1 of 1 orphaned containers not removed; first: {name}")
            ),
            other => panic!("{other}"),
        }
        assert_eq!(refused(&dir), 1, "one plain rm, no retry inside the sweep");
        let calls = std::fs::read_to_string(dir.join("calls")).unwrap_or_default();
        assert!(!calls.lines().any(|c| c == "unpause"), "{calls}");
        let status = x
            .hermetic(&[
                "inspect".into(),
                "--format".into(),
                "{{.State.Status}}".into(),
                name.clone(),
            ])
            .await;
        assert_eq!(status, "paused", "the sweep thawed it");
        assert_eq!(
            next.events.list(),
            ["sandbox.orphan_removed", "sandbox.orphan_remove_failed"]
        );
        let failed = next.events.args("sandbox.orphan_remove_failed").unwrap();
        assert_eq!(failed["container"], name.as_str(), "{failed}");
        assert_eq!(failed["sweep"], "startup", "{failed}");
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
/// oplog error line, removes the other orphans anyway, and then returns one error naming the
/// counts and the first name. The next sweep, with `rm` working, removes the one left.
/// Controls: the other orphans' removal (the sweep went on: one was created and named before the
/// stuck one and one after, so whether podman lists them by creation time or by name, either
/// way round, one comes after it); the second sweep (the failure was the wrapper's, not the
/// container's).
#[test]
fn a_failed_orphan_removal_is_audited_and_the_sweep_goes_on() {
    let (dir, _gone) = wrapper_dir("orphans");
    rt().block_on(async {
        let x = Lx::with_podman(|real| id_rm_failing_podman(&dir, real));
        let (before_it, stuck, after_it) = (
            format!("sp-ws-{}-a", x.scope),
            format!("sp-ws-{}-b-stuck", x.scope),
            format!("sp-ws-{}-c", x.scope),
        );
        orphan(&before_it, x.installation.as_str());
        let stuck_id = orphan(&stuck, x.installation.as_str());
        orphan(&after_it, x.installation.as_str());
        std::fs::write(dir.join("rm-fails"), &stuck_id).unwrap();

        let e = x
            .launcher
            .remove_orphans(&x.scope, Sweep::Periodic)
            .await
            .unwrap_err();
        match &e {
            LaunchError::Command { verb: "rm", msg } => assert_eq!(
                msg,
                &format!("1 of 3 orphaned containers not removed; first: {stuck}")
            ),
            other => panic!("{other}"),
        }
        assert!(exists(&stuck), "the failing removal removed it");
        for other in [&before_it, &after_it] {
            assert!(
                !exists(other),
                "the sweep stopped at the failure: {other} left"
            );
        }
        let all = x.events.all();
        let named = |event: &str, container: &str| {
            all.iter()
                .filter(|(e, a)| e == event && a["container"] == container)
                .count()
        };
        for name in [&before_it, &stuck, &after_it] {
            assert_eq!(named("sandbox.orphan_removed", name), 1, "{all:?}");
        }
        assert_eq!(named("sandbox.orphan_remove_failed", &stuck), 1, "{all:?}");
        assert_eq!(all.len(), 4, "{all:?}");
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
