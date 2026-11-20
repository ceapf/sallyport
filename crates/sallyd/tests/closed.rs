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
use sallyd::sandbox::AuditSink;
use sallyd::session::{Registry, StopOutcome, StopReason};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod common;
use common::container::*;
use common::egress::{canary, public};
use common::intercept::connect;

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
/// confirmed gone; otherwise the real one.
fn rm_failing_podman(at: &Path, real: &Path) -> PathBuf {
    wrap_podman(at, real, |at, real| {
        format!(
            "#!/bin/sh\nv=; skip=\nfor a; do\n\
             if [ -n \"$skip\" ]; then skip=; continue; fi\n\
             case \"$a\" in --*) [ -z \"$v\" ] && skip=1 ;; *) [ -z \"$v\" ] && v=$a ;; esac\n\
             done\n\
             if [ \"$v\" = rm ] && [ -e '{at}/fail-rm' ]; then exit 125; fi\n\
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
