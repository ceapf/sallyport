//! The live sessions' secrets, for the audit and operational logs' redactors (#85; architect
//! Q219, Q220).
//!
//! A session's secret values are loaded once, by the egress starter's `prepare`, which builds
//! their forms ([`SessionForms`]: each value's `secret_forms`, each grant's rendered header value
//! and `{basic}` blob). The launcher registers that same [`Arc`] here right after `prepare`
//! returns, before `net.sock` is bound or any container exists; whoever writes the session's
//! last entry unregisters it (the launcher after `sandbox.refuse`, the registry after
//! `session.stop` and teardown). Every change rebuilds one [`Redactor`] over the union of the
//! registered sets and swaps it into each [`RedactorTarget`], under one lock, so the audit log
//! and the operational log always redact the same set. A value two live sessions share stays
//! redacted until both are unregistered. Nothing here loads a value, and nothing is copied: the
//! redactors read the forms in place, and the last holder's drop wipes them.
//!
//! Residuals (security review of #85): an egress connection whose shutdown grace ran out may
//! finish an audit append after the release; such entries carry hosts, counts and secret names,
//! never a value. A launch or start task that panics after registering never releases its
//! session's forms (TODO(#113)): its values stay redacted, and in `sallyd`'s memory, until the
//! daemon exits.

use std::sync::{Arc, Mutex};

use sally_core::audit::{Redactor, SessionForms};

use crate::oplog::Oplog;
use crate::sandbox::SharedAudit;

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
