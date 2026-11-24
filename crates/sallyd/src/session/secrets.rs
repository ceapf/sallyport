//! The live sessions' secrets, for the audit and operational logs' redactors (#85; architect
//! Q219, Q220).
//!
//! A session's secret values are loaded once, by the egress starter's `prepare`, which builds
//! their forms ([`SessionForms`]: each value's `secret_forms`, each grant's rendered header value
//! and `{basic}` blob). The launcher registers that same [`Arc`] here right after `prepare`
//! returns, before `net.sock` is bound or any container exists; whoever writes the session's
//! last entry unregisters it (the launcher after `sandbox.refuse`, or after `sandbox.cleaned`
//! or `sandbox.cleanup_abandoned` when a failed launch's cleanup was retried; for a session,
//! `Launcher::close` right after `session.closed`, which follows `session.stop` and the
//! teardown, #94). Every change rebuilds
//! one [`Redactor`] over the union of the registered sets and swaps it into each
//! [`RedactorTarget`], under one lock, so the audit log and the operational log always redact
//! the same set. A value two live sessions share stays
//! redacted until both are unregistered. Nothing here loads a value, and nothing is copied: the
//! redactors read the forms in place, and the last holder's drop wipes them.
//!
//! Residuals (security review of #85; architect Q244, Q251): `session.closed` is a session's
//! last entry except entries of the egress and watchdog writers still outstanding at teardown:
//! an append whose task was aborted while it waited for or ran its blocking write, and an
//! `egress.response` started from a body's drop on a detached task (#72). Such an entry may
//! land after `session.closed` and after the release (TODO(#156): a sealable per-session
//! teardown handle). It holds the sandbox's own request text (host, target), redacted with the
//! session's own forms by [`SessionRedacted`] whenever it lands (Q249), plus counts and secret
//! names: the release changes nothing about what is redacted, which is forms only (Q253);
//! watchdog entries hold no sandbox text. A launch or start task that panics after
//! registering never releases its session's forms (TODO(#113)): its values stay redacted, and
//! in `sallyd`'s memory, until the daemon exits.

use std::sync::{Arc, Mutex};

use sally_core::audit::{AuditError, NewEntry, Redactor, SessionForms};
use sally_core::manifest::AuditLevel;

use crate::egress::redact::Redaction;
use crate::oplog::Oplog;
use crate::sandbox::{AuditSink, SharedAudit};

/// The egress audit sink of a proxy session with secret grants (interception): every egress
/// entry of such a session passes here (architect Q277). A session without grants is not
/// wrapped and has no forms. Each entry is redacted with that session's own forms before it
/// goes on to the audit log, which redacts it again with the live sessions' union (Q249). It
/// reads the session's [`Redaction`], the same patterns
/// [`crate::egress::authority::own_masked`] masks with (Q278). An egress entry can land after
/// the session's `session.closed` and the release of its forms (an append aborted mid-write, a
/// dropped body's report; Q251, #156); its sandbox-chosen text is still redacted with the
/// session's forms. A target and a method are declared masked by `own_masked` already (this
/// pass masks declared texts too, uncut; Q276); this pass is the only one after the release for
/// the `host` of `egress.resolve`, `egress.allow` and `egress.close` (a host a wildcard rule
/// allowed, which no builder masks) and for any field a later builder adds without
/// `own_masked` (Q266). The
/// launcher wraps the session's sink right after its egress
/// loaded the forms. Append-only: it swaps no redactor.
pub(crate) struct SessionRedacted {
    inner: Arc<dyn AuditSink>,
    redaction: Arc<Redaction>,
}

impl SessionRedacted {
    /// `inner` with every entry redacted by `redaction`'s audit patterns first.
    #[must_use]
    pub(crate) const fn over(inner: Arc<dyn AuditSink>, redaction: Arc<Redaction>) -> Self {
        Self { inner, redaction }
    }
}

impl AuditSink for SessionRedacted {
    fn append(&self, entry: NewEntry, level: AuditLevel) -> Result<(), AuditError> {
        self.inner
            .append(entry.redacted(self.redaction.audit()), level)
    }
}

/// A log whose redactor [`Redactors`] replaces. Implemented by the audit writer behind
/// [`SharedAudit`] and by the [`Oplog`]; `AuditSink` itself stays append-only, so no holder of
/// the sink can swap the redactor (architect Q220).
pub trait RedactorTarget: Send + Sync {
    /// Replaces the redactor applied to every later entry or line.
    fn set_redactor(&self, redactor: Redactor);
}

impl RedactorTarget for SharedAudit {
    fn set_redactor(&self, redactor: Redactor) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .set_redactor(redactor);
    }
}

impl RedactorTarget for Oplog {
    fn set_redactor(&self, redactor: Redactor) {
        Oplog::set_redactor(self, Arc::new(redactor));
    }
}

/// The registered sessions' forms and the logs they are redacted from. Shared as an [`Arc`]
/// by the launcher (which registers and, after a refusal, unregisters) and, through it, the
/// registry.
pub struct Redactors {
    /// Session id and its forms, in registration order.
    live: Mutex<Vec<(String, Arc<SessionForms>)>>,
    targets: Vec<Arc<dyn RedactorTarget>>,
}

impl std::fmt::Debug for Redactors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Redactors")
            .field("sessions", &self.sessions())
            .field("targets", &self.targets.len())
            .finish()
    }
}

impl Redactors {
    /// No session registered; every change is swapped into each of `targets`.
    #[must_use]
    pub fn new(targets: Vec<Arc<dyn RedactorTarget>>) -> Self {
        Self {
            live: Mutex::new(Vec::new()),
            targets,
        }
    }

    /// The daemon's redactors: over `audit`, the writer the launcher and the registry append
    /// to, and over `oplog` (architect Q220). `serve` builds them only through this.
    #[must_use]
    pub fn for_logs(audit: &Arc<SharedAudit>, oplog: &Oplog) -> Self {
        let audit = Arc::clone(audit) as Arc<dyn RedactorTarget>;
        let oplog = Arc::new(oplog.clone()) as Arc<dyn RedactorTarget>;
        Self::new(vec![audit, oplog])
    }

    /// Adds session `id`'s forms (replacing any it had) and swaps in the new union.
    pub fn register(&self, id: &str, forms: Arc<SessionForms>) {
        let mut live = self.lock();
        live.retain(|(s, _)| s != id);
        live.push((id.to_owned(), forms));
        self.swap(&live);
    }

    /// Drops session `id`'s forms, if it has any, and swaps in the union of the others. Safe to
    /// call more than once.
    pub fn unregister(&self, id: &str) {
        let mut live = self.lock();
        live.retain(|(s, _)| s != id);
        self.swap(&live);
    }

    /// The ids registered now, in registration order (no secret: names and values stay out).
    #[must_use]
    pub fn sessions(&self) -> Vec<String> {
        self.lock().iter().map(|(s, _)| s.clone()).collect()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<(String, Arc<SessionForms>)>> {
        self.live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// One redactor per target over the union of `live` (built from the same sets, so they
    /// agree), swapped while the caller holds the lock.
    fn swap(&self, live: &[(String, Arc<SessionForms>)]) {
        for t in &self.targets {
            t.set_redactor(Redactor::from_forms(
                live.iter().map(|(_, f)| Arc::clone(f)),
            ));
        }
    }
}

#[cfg(test)]
#[path = "secrets_tests.rs"]
mod tests;
