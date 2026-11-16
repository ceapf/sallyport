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
        assert!(launch.await.unwrap().is_err(), "the launch is refused");
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
