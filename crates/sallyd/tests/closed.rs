//! #94 (architect Q242–Q246) with real containers: `session.closed`, a session's last entry,
//! written once its teardown has finished (the container confirmed gone, the session released),
//! exactly once per `Running` the registry received, and never for a launch the launcher refused.
//!
//! The fixture is `common::container`; these tests never skip.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sally_core::audit::{Actor, NewEntry};
use sallyd::sandbox::{AuditSink, CLEANUP_TRIES, CleanupSchedule, LaunchError};
use sallyd::session::{Registry, SessionInfo, SessionState, StopOutcome, StopReason};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod common;
use common::container::*;
use common::egress::{canary, public};
use common::intercept::connect;
use common::{mount, mounts};

/// A proxy-mode session allowed `mock2.test`, which is spliced (no grant): its tunnel stays open
/// until the session stops.
const SPLICED: &str = "network:\n  mode: proxy\n  allow:\n    - host: mock2.test\n";

/// `GITHUB_TOKEN` injected on `mock.test`, so the session's forms are in the logs' redactors.
const GRANT: &str = "network:\n  mode: proxy\n  allow:\n    - host: mock.test\n\
                     secrets:\n  - name: GITHUB_TOKEN\n    inject: {host: mock.test, \
                     header: Authorization, format: \"Bearer {value}\"}\n";

/// The longest a test waits for something that follows a stop.
const BOUND: Duration = Duration::from_secs(60);

fn registry(x: &Lx) -> Arc<Registry> {
    x.registry(x.events.clone() as Arc<dyn AuditSink>, Some(test_image()))
}

/// The positions of `event` in `all`.
fn at(all: &[(String, Value)], event: &str) -> Vec<usize> {
    all.iter()
        .enumerate()
        .filter(|(_, (e, _))| e == event)
        .map(|(i, _)| i)
        .collect()
}

/// The `Debug` form of `session.closed` for session `id`: its exact shape, args aside (actor
/// `sallyd`, a session, no decision).
fn closed_shape(id: &str) -> String {
    format!(
        "{:?}",
        NewEntry::new(Actor::Sallyd, "session.closed").session(id)
    )
}

/// Asserts that `session.closed` is the last entry, written once, with `{reason}` and the exact
/// shape of [`closed_shape`].
fn assert_closed_last(x: &Lx, id: &str, reason: &str) {
    let all = x.events.all();
    let closed = at(&all, "session.closed");
    assert_eq!(
        closed,
        [all.len() - 1],
        "session.closed once, last: {all:#?}"
    );
    assert_eq!(all[closed[0]].1, json!({"reason": reason}), "{all:#?}");
    assert_eq!(
        x.events.debug().last().unwrap(),
        &closed_shape(id),
        "the entry's shape"
    );
}

/// RT-AUD-03 (#94, architect Q246): nothing of a session follows its `session.closed`. A session
/// stopped with a tunnel still open writes `session.stop`, the teardown's `sandbox.stop` and the
/// tunnel's `egress.close` (`session-stopped`) first; `session.closed {reason}` comes last,
/// exactly once, and nothing is written after it.
///
/// Control (hand-checked once, uncommitted): `session.closed` appended before `Launcher::stop`
/// in `retry_stop`, or before `egress.shutdown` in `Launcher::stop`, fails the order assertion.
/// Residual (Q244, Q251, #156): entries of the egress and watchdog writers still outstanding at
/// teardown may land after it: an append whose task was aborted while it waited for or ran its
/// blocking write, and an `egress.response` started from a body's drop on a detached task (#72).
#[test]
fn rt_aud_03_nothing_of_a_session_follows_session_closed() {
    rt().block_on(async {
        let x = Lx::new();
        // Not the TLS upstream: the fake dialer echoes, so the spliced tunnel stays open.
        x.egress.resolver.set("mock2.test", vec![vec![public(1)]]);
        let reg = registry(&x);
        let s = reg.start(Arc::new(x.f.validated(SPLICED))).await.unwrap();
        let sock = x.session_paths(&s.id).workspace_sockets().join("net.sock");
        let mut tunnel = connect(&sock, "mock2.test").await;
        tunnel.write_all(b"ping").await.unwrap();
        let mut back = [0_u8; 4];
        tunnel.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"ping", "the tunnel is open");
        assert_eq!(
            reg.stop(&s.id, StopReason::Request).await,
            Some(StopOutcome::Stopped)
        );
        drop(tunnel);
        let all = x.events.all();
        let stop = at(&all, "session.stop");
        let sandbox_stop = at(&all, "sandbox.stop");
        let egress_close: Vec<usize> = at(&all, "egress.close");
        assert_eq!(stop.len(), 1, "{all:#?}");
        assert_eq!(sandbox_stop.len(), 1, "{all:#?}");
        assert_eq!(egress_close.len(), 1, "{all:#?}");
        assert_eq!(all[egress_close[0]].1["end"], "session-stopped", "{all:#?}");
        assert_closed_last(&x, &s.id, "request");
        let closed = all.len() - 1;
        assert!(stop[0] < sandbox_stop[0], "{all:#?}");
        assert!(
            sandbox_stop[0] < closed && egress_close[0] < closed,
            "{all:#?}"
        );
        // Nothing lands later either: the egress grace has passed with the stop.
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(
            x.events.all().len(),
            all.len(),
            "an entry followed session.closed"
        );
    });
}

/// RT-AUD-03, failed start (Q245): a workspace whose session never started (`session.start`
/// and its best-effort `session.stop` both refused by the sink) ends `sandbox.launch`,
/// `sandbox.stop`, `session.closed {reason: start-failed}`; a launch the launcher refused
/// (`no_default_image_starts_nothing` in `tests/session.rs`) writes none.
#[test]
fn rt_aud_03_a_failed_start_ends_with_session_closed() {
    rt().block_on(async {
        let x = Lx::new();
        let reg = registry(&x);
        x.events.fail(&["session.start", "session.stop"]);
        reg.start(Arc::new(x.f.validated(""))).await.unwrap_err();
        assert!(reg.list().is_empty(), "{:?}", reg.list());
        assert_eq!(
            x.events.list(),
            ["sandbox.launch", "sandbox.stop", "session.closed"]
        );
        let id = x
            .events
            .debug()
            .first()
            .and_then(|d| d.split("session: Some(\"").nth(1))
            .and_then(|d| d.split('"').next())
            .expect("the session id")
            .to_owned();
        assert_closed_last(&x, &id, "start-failed");
    });
}

/// Q250 (amending Q243's order): a session stays listed until its `session.closed` is written,
/// so a shutdown and a stop asked while that append runs both wait for it, and both are then
/// answered `Stopped`, with `session.closed` written once. Control: with the session removed
/// from the live set before `close` (the old order), the shutdown returns at once and the
/// listing is empty while `session.closed` waits.
#[test]
fn a_session_stays_listed_until_its_session_closed_is_written() {
    rt().block_on(async {
        let x = Lx::new();
        let reg = registry(&x);
        let s = reg.start(Arc::new(x.f.validated(""))).await.unwrap();
        let _unhold = x.events.held(&["session.closed"]);
        let ask = |reg: &Arc<Registry>| {
            let (reg, id) = (Arc::clone(reg), s.id.clone());
            tokio::spawn(async move { reg.stop(&id, StopReason::Request).await })
        };
        let stopping = ask(&reg);
        x.events.until_parked("session.closed", 1).await;
        assert_eq!(reg.list().len(), 1, "unlisted before its last entry");
        let shutdown = {
            let reg = Arc::clone(&reg);
            tokio::spawn(async move { reg.shutdown().await })
        };
        let asked = ask(&reg);
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(
            !shutdown.is_finished(),
            "shutdown returned before session.closed"
        );
        assert!(
            !asked.is_finished(),
            "a stop was answered before session.closed"
        );
        assert!(
            !stopping.is_finished(),
            "the stop was answered before session.closed"
        );
        x.events.hold(&[]);
        for done in [stopping, asked] {
            let outcome = tokio::time::timeout(BOUND, done).await.unwrap().unwrap();
            assert_eq!(outcome, Some(StopOutcome::Stopped));
        }
        let unconfirmed = tokio::time::timeout(BOUND, shutdown)
            .await
            .unwrap()
            .unwrap();
        assert!(unconfirmed.is_empty(), "{unconfirmed:?}");
        assert!(reg.list().is_empty());
        assert_closed_last(&x, &s.id, "request");
    });
}

/// Q245: a launch the launcher refused after its egress loaded the session's forms (here
/// `sandbox.launch` cannot be written, the same `refused` path as any failure after `prepare`)
/// writes no `session.closed`: `sandbox.refuse` stays its last entry, and the forms are released.
#[test]
fn a_launch_refused_after_its_egress_started_writes_no_session_closed() {
    rt().block_on(async {
        let x = Lx::new();
        let reg = registry(&x);
        x.events.fail(&["sandbox.launch"]);
        reg.start(Arc::new(x.f.validated(GRANT))).await.unwrap_err();
        // The grant's [data-can-leave] warning is recorded before anything is launched.
        assert_eq!(x.events.list(), ["manifest.warn", "sandbox.refuse"]);
        assert!(x.redactors.sessions().is_empty(), "the forms stayed");
        assert!(reg.list().is_empty(), "{:?}", reg.list());
    });
}

/// Q243: a refused `session.closed` append still answers `Stopped` and releases the session's
/// forms; one oplog line names only the session and the event, and carries no secret.
#[test]
fn a_refused_session_closed_still_answers_stopped_and_releases_the_forms() {
    rt().block_on(async {
        let x = Lx::new();
        let reg = registry(&x);
        let s = reg.start(Arc::new(x.f.validated(GRANT))).await.unwrap();
        assert_eq!(x.redactors.sessions(), std::slice::from_ref(&s.id));
        x.events.fail(&["session.closed"]);
        assert_eq!(
            reg.stop(&s.id, StopReason::Request).await,
            Some(StopOutcome::Stopped)
        );
        assert!(x.redactors.sessions().is_empty(), "the forms stayed");
        assert!(!x.events.list().contains(&"session.closed".to_owned()));
        assert!(x.oplog.flush(BOUND));
        let text = x.oplog_lines.text();
        let lines: Vec<&str> = text
            .lines()
            .filter(|l| l.contains("session.closed"))
            .collect();
        assert_eq!(lines.len(), 1, "{text}");
        assert!(lines[0].contains("audit entry not written"), "{text}");
        assert!(lines[0].contains(&s.id), "{text}");
        let gh = canary("GITHUB_TOKEN");
        assert!(!text.contains(&gh), "a secret in the oplog");
        assert!(!lines[0].contains("REDACTED"), "{text}");
    });
}

/// A podman that fails every `rm` while `<at>/fail-rm` exists, so a container cannot be
/// confirmed gone, and only a workspace's (`sp-ws-…`, the last argument) while
/// `<at>/fail-rm-ws` exists, so a launch's own probe container is still removed; every
/// `unshare rm` while `<at>/fail-unshare` exists, so a stop fails at the scratch removal after
/// the container is gone; and every `container` command (the probe `container exists` among
/// them) while `<at>/probe-unknown` exists, so the probe answers neither present nor absent.
/// Otherwise the real one.
fn rm_failing_podman(at: &Path, real: &Path) -> PathBuf {
    wrap_podman(at, real, |at, real| {
        format!(
            "#!/bin/sh\nv=; skip=; l=; r=\nfor a; do\n\
             l=$a; [ \"$a\" = rm ] && r=1\n\
             if [ -n \"$skip\" ]; then skip=; continue; fi\n\
             case \"$a\" in --*) [ -z \"$v\" ] && skip=1 ;; *) [ -z \"$v\" ] && v=$a ;; esac\n\
             done\n\
             if [ \"$v\" = rm ] && [ -e '{at}/fail-rm' ]; then exit 125; fi\n\
             if [ \"$v\" = rm ] && [ -e '{at}/fail-rm-ws' ]; then\n\
             case \"$l\" in sp-ws-*) exit 125 ;; esac; fi\n\
             if [ \"$v\" = unshare ] && [ -n \"$r\" ] && [ -e '{at}/fail-unshare' ]; then exit 125; fi\n\
             if [ \"$v\" = container ] && [ -e '{at}/probe-unknown' ]; then exit 125; fi\n\
             exec '{real}' \"$@\"\n"
        )
    })
}

/// Q246: a container not confirmed gone writes no `session.closed`, neither at its failed stop
/// nor at a shutdown that still cannot confirm it (#96); once a later stop confirms it gone,
/// exactly one, with the stop's first reason.
#[test]
fn an_unconfirmed_container_gets_session_closed_only_once_it_is_gone() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("closed-rm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let _cleanup = RemoveOnDrop(dir.clone());
    rt().block_on(async {
        let x = Lx::with_podman(|real| rm_failing_podman(&dir, real));
        let reg = registry(&x);
        let s = reg.start(Arc::new(x.f.validated(""))).await.unwrap();
        std::fs::write(dir.join("fail-rm"), b"").unwrap();
        assert!(matches!(
            reg.stop(&s.id, StopReason::Request).await,
            Some(StopOutcome::Failed(_))
        ));
        assert!(
            exists(&s.container),
            "control: the container is still there"
        );
        assert!(!x.events.list().contains(&"session.closed".to_owned()));
        assert_eq!(reg.shutdown().await, std::slice::from_ref(&s.id));
        assert!(!x.events.list().contains(&"session.closed".to_owned()));
        std::fs::remove_file(dir.join("fail-rm")).unwrap();
        assert!(reg.shutdown().await.is_empty());
        assert!(!exists(&s.container));
        assert_closed_last(&x, &s.id, "request");
    });
}

/// Short pauses between a failed stop's rounds (and a failed launch's cleanup tries), passed in
/// as `sallyd` passes its own schedule.
const SHORT: CleanupSchedule = CleanupSchedule::with_pauses([Duration::from_millis(100); 9]);

/// How long the session runs before its timeout begins the stop (the least the manifest allows),
/// and then at most how long until that stop's first round has failed.
const TIMEOUT_AND_ROUND: Duration = Duration::from_secs(150);

/// Long enough for several more stop rounds at [`SHORT`] pauses, each round three attempts two
/// seconds apart.
const MORE_ROUNDS: Duration = Duration::from_secs(20);

/// The entries named `event`.
fn count(x: &Lx, event: &str) -> usize {
    x.events.list().iter().filter(|e| *e == event).count()
}

/// RT-AUD-03: a stop begun by the session's timeout, with no
/// requester, whose container cannot be confirmed gone writes one `sandbox.stop_failed`
/// (denied, naming the role, the container and the attempts) and exactly one `sandbox.stop`,
/// however many rounds it takes; the session's folder stays refused; and the supervisor
/// retries by itself, so once the container can be removed `session.closed` follows, last,
/// with no stop request. Control: the folder launches once the stop is confirmed.
#[test]
fn rt_aud_03_a_stop_that_cannot_be_confirmed_is_audited_and_retried_until_it_is() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("closed-stop-failed-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let _cleanup = RemoveOnDrop(dir.clone());
    rt().block_on(async {
        let x = Lx::with_podman_and_cleanup(|real| rm_failing_podman(&dir, real), SHORT);
        let reg = registry(&x);
        let folder = mounts(&[mount("~/code/myproject", "/workspace/p", "rw")]);
        let timed = format!("{folder}runtime:\n  timeout: 1m\n");
        let s = reg.start(Arc::new(x.f.validated(&timed))).await.unwrap();
        std::fs::write(dir.join("fail-rm"), b"").unwrap();
        until(&x, "sandbox.stop_failed", TIMEOUT_AND_ROUND, || {
            count(&x, "sandbox.stop_failed") > 0
        })
        .await;
        let failed = x.events.args("sandbox.stop_failed").unwrap();
        assert_eq!(failed["role"], "workspace", "{failed}");
        assert_eq!(failed["container"], format!("sp-ws-{}", s.id), "{failed}");
        assert_eq!(failed["attempts"], 3, "{failed}");
        let shape = x
            .events
            .debug()
            .into_iter()
            .find(|d| d.contains("\"sandbox.stop_failed\""))
            .unwrap();
        assert!(shape.contains("decision: Some(\"deny\")"), "{shape}");
        tokio::time::sleep(MORE_ROUNDS).await;
        assert_eq!(count(&x, "sandbox.stop_failed"), 1, "{:?}", x.events.list());
        assert_eq!(count(&x, "sandbox.stop"), 1, "{:?}", x.events.list());
        assert_eq!(count(&x, "session.closed"), 0, "{:?}", x.events.list());
        assert!(exists(&s.container), "the container is still there");
        let v = x.f.load(&folder);
        let refused = x.launch(&v, "while-unconfirmed").await;
        assert!(
            matches!(refused, Err(LaunchError::Overlap(_))),
            "the folder is refused while the stop is unconfirmed: {:?}",
            refused.map(|r| r.name().to_owned())
        );
        std::fs::remove_file(dir.join("fail-rm")).unwrap();
        until(&x, "session.closed with no stop request", BOUND, || {
            count(&x, "session.closed") > 0
        })
        .await;
        assert!(!exists(&s.container));
        assert_closed_last(&x, &s.id, "timeout");
        let r = x
            .launch(&v, "after-confirmed")
            .await
            .expect("control: the folder launches once the stop is confirmed");
        x.stop(r).await;
    });
}

/// RT-AUD-03: a stop round that fails writes `sandbox.stop_failed` only when the container may
/// still be there. The probe answers present (control: the entry, naming the container), absent
/// (the stop failed at the scratch removal after the container went: no entry), or neither (the
/// entry). Each session's stop then succeeds at a request once podman works again.
#[test]
fn rt_aud_03_a_failed_stop_is_audited_only_while_the_container_may_be_there() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("closed-stop-probe-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let _cleanup = RemoveOnDrop(dir.clone());
    rt().block_on(async {
        let x = Lx::with_podman_and_cleanup(|real| rm_failing_podman(&dir, real), LONG);
        let reg = registry(&x);

        let present = failed_stop(&x, &reg, &dir, &["fail-rm"]).await;
        assert!(exists(&present.container), "the container is still there");
        assert_eq!(
            count(&x, "sandbox.stop_failed"),
            1,
            "control: a stop failed with the container there is audited: {:?}",
            x.events.list()
        );
        let entry = x.events.args("sandbox.stop_failed").unwrap();
        assert_eq!(entry["container"], present.container, "{entry}");
        let again = stop_with(&reg, &dir, &present.id, &["fail-rm"]).await;
        assert!(matches!(again, Some(StopOutcome::Failed(_))), "{again:?}");
        assert_eq!(
            count(&x, "sandbox.stop_failed"),
            1,
            "a later failed round of the same stop writes no second entry: {:?}",
            x.events.list()
        );

        let gone = failed_stop(&x, &reg, &dir, &["fail-unshare"]).await;
        assert!(
            !exists(&gone.container),
            "the container went before the failure"
        );
        assert_eq!(
            count(&x, "sandbox.stop_failed"),
            1,
            "a stop failed after the container went writes no entry: {:?}",
            x.events.list()
        );

        let unknown = failed_stop(&x, &reg, &dir, &["fail-rm", "probe-unknown"]).await;
        assert!(exists(&unknown.container), "the container is still there");
        assert_eq!(
            count(&x, "sandbox.stop_failed"),
            2,
            "a stop whose probe answers neither way is audited: {:?}",
            x.events.list()
        );
        let entry = x.events.args("sandbox.stop_failed").unwrap();
        assert_eq!(entry["container"], unknown.container, "{entry}");
        assert!(
            entry["detail"]
                .as_str()
                .unwrap()
                .contains("container exists"),
            "container commands failed during the stop: {entry}"
        );

        for s in [&present, &gone, &unknown] {
            let outcome = reg.stop(&s.id, StopReason::Request).await;
            assert!(
                matches!(outcome, Some(StopOutcome::Stopped)),
                "{} stops once podman works: {outcome:?}",
                s.id
            );
            assert!(!exists(&s.container));
        }
    });
}

/// RT-AUD-03, failed start: a workspace whose session never started and whose stop then fails
/// writes `sandbox.stop_failed` while the container is there (once: a later failed round writes
/// none), and none when the container went before the failure. Each is listed stop-failed and
/// stops at a request once podman works.
#[test]
fn a_failed_starts_failed_stop_is_audited_once_while_the_container_is_there() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("closed-discard-probe-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let _cleanup = RemoveOnDrop(dir.clone());
    rt().block_on(async {
        let x = Lx::with_podman_and_cleanup(|real| rm_failing_podman(&dir, real), LONG);
        let reg = registry(&x);
        x.events.fail(&["session.start", "session.stop"]);
        // (flags, entries so far, whether the container is still there after the failure): the
        // first leg writes the one entry, the second none.
        for (flags, entries, there) in [
            (&["fail-rm-ws"][..], 1, true),
            (&["fail-unshare"][..], 1, false),
        ] {
            {
                let _flags = Flags::set(&dir, flags);
                reg.start(Arc::new(x.f.validated(""))).await.unwrap_err();
            }
            let listed = reg.list();
            assert_eq!(listed.len(), 1, "{flags:?}: {listed:?}");
            let s = &listed[0];
            assert_eq!(s.state, SessionState::StopFailed, "{flags:?}");
            assert_eq!(exists(&s.container), there, "{flags:?}");
            assert_eq!(
                count(&x, "sandbox.stop_failed"),
                entries,
                "{flags:?}: {:?}",
                x.events.list()
            );
            let again = stop_with(&reg, &dir, &s.id, flags).await;
            assert!(matches!(again, Some(StopOutcome::Failed(_))), "{again:?}");
            assert_eq!(
                count(&x, "sandbox.stop_failed"),
                entries,
                "{flags:?}: a later failed round writes none: {:?}",
                x.events.list()
            );
            let outcome = reg.stop(&s.id, StopReason::Request).await;
            assert!(matches!(outcome, Some(StopOutcome::Stopped)), "{outcome:?}");
            assert!(!exists(&s.container));
        }
    });
}

/// Pauses between a failed stop's rounds long enough that only requests drive them.
const LONG: CleanupSchedule =
    CleanupSchedule::with_pauses([Duration::from_secs(600); CLEANUP_TRIES - 1]);

/// Flag files of [`rm_failing_podman`] in a folder, present while this lives.
struct Flags<'a>(&'a Path, &'a [&'a str]);

impl<'a> Flags<'a> {
    fn set(dir: &'a Path, flags: &'a [&'a str]) -> Self {
        let set = Self(dir, flags);
        for f in flags {
            std::fs::write(dir.join(f), b"").unwrap();
        }
        set
    }
}

impl Drop for Flags<'_> {
    fn drop(&mut self) {
        for f in self.1 {
            let _ = std::fs::remove_file(self.0.join(f));
        }
    }
}

/// A stop of session `id` at a request, with `flags` set in `dir` while it runs.
async fn stop_with(
    reg: &Arc<Registry>,
    dir: &Path,
    id: &str,
    flags: &[&str],
) -> Option<StopOutcome> {
    let _flags = Flags::set(dir, flags);
    reg.stop(id, StopReason::Request).await
}

/// Starts a session, then stops it at a request with `flags` set (see [`rm_failing_podman`]);
/// the stop must fail.
async fn failed_stop(x: &Lx, reg: &Arc<Registry>, dir: &Path, flags: &[&str]) -> SessionInfo {
    let s = reg.start(Arc::new(x.f.validated(""))).await.unwrap();
    let outcome = stop_with(reg, dir, &s.id, flags).await;
    assert!(
        matches!(outcome, Some(StopOutcome::Failed(_))),
        "{flags:?}: {outcome:?}"
    );
    s
}

/// Polls `done` every 100 ms until it holds; fails the test naming `what` after `bound`.
async fn until(x: &Lx, what: &str, bound: Duration, mut done: impl FnMut() -> bool) {
    let end = std::time::Instant::now() + bound;
    while !done() {
        x.assert_no_crash();
        assert!(
            std::time::Instant::now() < end,
            "{what}: not within {bound:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
