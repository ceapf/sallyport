//! #85 over the real launcher and registry (architect Q219, Q220): a session's secret forms
//! reach the logs' redactors once its egress has loaded them, and leave them only after the
//! session's last entry: `sandbox.refuse` for a refused launch, `session.stop` and the teardown
//! for a session. The test sink never applies the redactor ([`Swapped`] keeps the last one
//! swapped in), so these tests read what production's audit writer and oplog would apply.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use sallyd::sandbox::{AuditSink, WorkspaceRequest};
use sallyd::session::StopReason;

mod common;
use common::container::*;
use common::egress::canary;
use common::*;

/// `GITHUB_TOKEN` injected on `mock.test`: a session CA session, so its values are loaded.
const ONE: &str = "network:\n  mode: proxy\n  allow:\n    - host: mock.test\n\
                   secrets:\n  - name: GITHUB_TOKEN\n    inject: {host: mock.test, \
                   header: Authorization, format: \"Bearer {value}\"}\n";

/// [`ONE`] plus `MOCK3_TOKEN` on `mock3.test`.
const TWO: &str = "network:\n  mode: proxy\n  allow:\n    - host: mock.test\n    \
                   - host: mock3.test\n\
                   secrets:\n  - name: GITHUB_TOKEN\n    inject: {host: mock.test, \
                   header: Authorization, format: \"Bearer {value}\"}\n  \
                   - name: MOCK3_TOKEN\n    inject: {host: mock3.test, \
                   header: X-Api-Key, format: \"{value}\"}\n";

fn manifest(x: &Lx, body: &str) -> Arc<sally_core::manifest::ValidatedManifest> {
    Arc::new(x.f.load(body))
}

/// A started session's values are redacted while it lives, and in the clear once its stop
/// is answered; a shared value stays redacted until the last session granting it is stopped.
#[test]
fn a_sessions_secrets_are_redacted_from_start_until_its_stop() {
    rt().block_on(async {
        let x = Lx::new();
        let reg = x.registry(x.events.clone() as Arc<dyn AuditSink>, Some(test_image()));
        let (gh, m3) = (canary("GITHUB_TOKEN"), canary("MOCK3_TOKEN"));
        // Control: before any session, nothing is redacted.
        assert_eq!(x.redacted.redact(&gh), gh);
        let a = reg.start(manifest(&x, ONE)).await.unwrap();
        assert_eq!(x.redactors.sessions(), std::slice::from_ref(&a.id));
        assert_eq!(x.redacted.redact(&gh), "[REDACTED:GITHUB_TOKEN]");
        let b = reg.start(manifest(&x, TWO)).await.unwrap();
        assert_eq!(x.redacted.redact(&m3), "[REDACTED:MOCK3_TOKEN]");
        reg.stop(&a.id, StopReason::Request).await.unwrap();
        assert_eq!(x.redactors.sessions(), std::slice::from_ref(&b.id));
        assert_eq!(
            x.redacted.redact(&gh),
            "[REDACTED:GITHUB_TOKEN]",
            "b grants it too"
        );
        reg.stop(&b.id, StopReason::Request).await.unwrap();
        assert!(x.redactors.sessions().is_empty());
        assert_eq!(
            x.redacted.redact(&format!("{gh} {m3}")),
            format!("{gh} {m3}")
        );
    });
}

/// The longest a test waits for a release that follows a lifted hold.
const BOUND: std::time::Duration = std::time::Duration::from_secs(60);

/// Waits within [`BOUND`] until no session's secrets are registered.
async fn until_released(x: &Lx) {
    let end = std::time::Instant::now() + BOUND;
    while !x.redactors.sessions().is_empty() {
        assert!(std::time::Instant::now() < end, "never released");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

/// A stopped session's values stay redacted through its stop's own entries (`session.stop`,
/// then the teardown's `sandbox.stop`), and leave only after them (security review M1).
#[test]
fn a_stopped_sessions_secrets_stay_redacted_through_its_last_entries() {
    rt().block_on(async {
        let x = Lx::new();
        let reg = x.registry(x.events.clone() as Arc<dyn AuditSink>, Some(test_image()));
        let gh = canary("GITHUB_TOKEN");
        let a = reg.start(manifest(&x, ONE)).await.unwrap();
        x.events.hold(&["sandbox.stop"]);
        let stopping = {
            let (reg, id) = (Arc::clone(&reg), a.id.clone());
            tokio::spawn(async move { reg.stop(&id, StopReason::Request).await })
        };
        x.events.until_parked("sandbox.stop", 1).await;
        assert_eq!(x.redactors.sessions(), std::slice::from_ref(&a.id));
        assert_eq!(x.redacted.redact(&gh), "[REDACTED:GITHUB_TOKEN]");
        x.events.hold(&[]);
        tokio::time::timeout(BOUND, stopping)
            .await
            .expect("the stop ends")
            .unwrap()
            .unwrap();
        assert!(x.redactors.sessions().is_empty());
        assert_eq!(x.redacted.redact(&gh), gh);
    });
}

/// The oplog line of a session task's panic reported during the session's stop.
const PANICKED: &str = "session task panicked during its stop";

/// Architect Q228 (security review LOW-1): a crash a session task reports during the session's
/// stop is logged while the session's secrets are still redacted. Its payload, a value the
/// session holds, reaches the oplog as the placeholder, never in the clear. Controls: the
/// session is still registered while the stop is parked, and released after it.
#[test]
fn a_crash_reported_during_a_stop_is_logged_redacted() {
    rt().block_on(async {
        let x = Lx::new();
        let reg = x.registry_logged(
            x.events.clone() as Arc<dyn AuditSink>,
            Some(test_image()),
            x.oplog.clone(),
        );
        let gh = canary("GITHUB_TOKEN");
        let a = reg.start(manifest(&x, ONE)).await.unwrap();
        let reporter = reg.reporter(&a.id).expect("a live session's reporter");
        x.events.hold(&["sandbox.stop"]);
        let stopping = {
            let (reg, id) = (Arc::clone(&reg), a.id.clone());
            tokio::spawn(async move { reg.stop(&id, StopReason::Request).await })
        };
        x.events.until_parked("sandbox.stop", 1).await;
        let payload = gh.clone();
        let panicked = tokio::spawn(async move { panic!("{payload}") })
            .await
            .unwrap_err();
        reporter.joined("tool", panicked);
        assert_eq!(x.redactors.sessions(), std::slice::from_ref(&a.id));
        assert!(x.oplog.flush(BOUND));
        assert!(!x.oplog_lines.text().contains(PANICKED), "not logged yet");
        x.events.hold(&[]);
        tokio::time::timeout(BOUND, stopping)
            .await
            .expect("the stop ends")
            .unwrap()
            .unwrap();
        assert!(x.oplog.flush(BOUND));
        let text = x.oplog_lines.text();
        let lines: Vec<&str> = text.lines().filter(|l| l.contains(PANICKED)).collect();
        assert_eq!(lines.len(), 1, "{text}");
        assert!(
            lines[0].contains("tool") && lines[0].contains("[REDACTED:GITHUB_TOKEN]"),
            "{}",
            lines[0]
        );
        assert!(!text.contains(&gh), "{text}");
        assert!(x.redactors.sessions().is_empty(), "control: released");
        assert!(
            !x.events.all().iter().any(|(e, _)| e == "session.crash"),
            "late: an oplog line only"
        );
    });
}

/// A start that fails after its workspace launched (here: `session.start` cannot be written)
/// keeps the values redacted until the workspace's `sandbox.stop`, then releases them (Rust
/// review M2: the registry's `discard`).
#[test]
fn a_failed_start_releases_its_secrets_after_sandbox_stop() {
    rt().block_on(async {
        let x = Lx::new();
        let reg = x.registry(x.events.clone() as Arc<dyn AuditSink>, Some(test_image()));
        let gh = canary("GITHUB_TOKEN");
        x.events.fail(&["session.start"]);
        x.events.hold(&["sandbox.stop"]);
        let starting = {
            let (reg, m) = (Arc::clone(&reg), manifest(&x, ONE));
            tokio::spawn(async move { reg.start(m).await })
        };
        x.events.until_parked("sandbox.stop", 1).await;
        assert_eq!(x.redactors.sessions().len(), 1);
        assert_eq!(x.redacted.redact(&gh), "[REDACTED:GITHUB_TOKEN]");
        x.events.hold(&[]);
        let started = tokio::time::timeout(BOUND, starting)
            .await
            .expect("the start ends")
            .unwrap();
        assert!(started.is_err(), "the start fails");
        assert!(x.redactors.sessions().is_empty());
        assert_eq!(x.redacted.redact(&gh), gh);
    });
}

/// A launch whose caller went away before it finished stops its workspace and releases the
/// values (Rust review M2: the orphaned launch in `launch_workspace`).
#[test]
fn an_orphaned_launch_releases_its_secrets() {
    rt().block_on(async {
        let x = Lx::new();
        x.events.hold(&["sandbox.launch"]);
        let paths = x.paths("orphan");
        let id = paths.id().as_str().to_owned();
        let req = WorkspaceRequest {
            paths,
            manifest: manifest(&x, ONE),
            default_image: Some(test_image()),
            crash: sallyd::daemon::crash::CrashReporter::channel().0,
        };
        let launcher = Arc::clone(&x.launcher);
        let launch = tokio::spawn(async move { launcher.launch_workspace(req).await });
        x.events.until_parked("sandbox.launch", 1).await;
        assert_eq!(x.redactors.sessions(), [id]);
        launch.abort();
        assert!(launch.await.unwrap_err().is_cancelled());
        x.events.hold(&[]);
        until_released(&x).await;
        assert!(
            x.events.all().iter().any(|(e, _)| e == "sandbox.stop"),
            "the orphan was stopped"
        );
    });
}

/// A launch refused after its egress loaded the values (here: `sandbox.launch` cannot be
/// written, which takes the same path as any failure after `prepare`, a `net.sock` bind
/// failure included): the values are redacted while `sandbox.refuse` is written, and released
/// after it. Q129 (one launch path, every Err through `refused()`) is what makes this one
/// refusal stand for the bind failure (architect Q225).
#[test]
fn a_refused_launch_releases_its_secrets_after_sandbox_refuse() {
    rt().block_on(async {
        let x = Lx::new();
        x.events.fail(&["sandbox.launch"]);
        x.events.hold(&["sandbox.refuse"]);
        let gh = canary("GITHUB_TOKEN");
        let paths = x.paths("refused");
        let id = paths.id().as_str().to_owned();
        let req = WorkspaceRequest {
            paths,
            manifest: manifest(&x, ONE),
            default_image: Some(test_image()),
            crash: sallyd::daemon::crash::CrashReporter::channel().0,
        };
        let launcher = Arc::clone(&x.launcher);
        let launch = tokio::spawn(async move { launcher.launch_workspace(req).await });
        x.events.until_parked("sandbox.refuse", 1).await;
        assert_eq!(x.redactors.sessions(), [id]);
        assert_eq!(x.redacted.redact(&gh), "[REDACTED:GITHUB_TOKEN]");
        x.events.hold(&[]);
        let refused = tokio::time::timeout(BOUND, launch)
            .await
            .expect("the refusal ends")
            .unwrap();
        assert!(refused.is_err(), "the launch is refused");
        assert!(x.redactors.sessions().is_empty());
        assert_eq!(x.redacted.redact(&gh), gh);
        let refused = x.events.all();
        assert!(
            refused
                .iter()
                .any(|(e, a)| e == "sandbox.refuse" && a["reason"].is_string()),
            "{refused:?}"
        );
    });
}

/// A session with no secret grant registers nothing.
#[test]
fn a_session_without_grants_registers_nothing() {
    rt().block_on(async {
        let x = Lx::new();
        let reg = x.registry(x.events.clone() as Arc<dyn AuditSink>, Some(test_image()));
        let s = reg.start(manifest(&x, PROXY)).await.unwrap();
        assert!(x.redactors.sessions().is_empty());
        reg.stop(&s.id, StopReason::Request).await.unwrap();
    });
}
