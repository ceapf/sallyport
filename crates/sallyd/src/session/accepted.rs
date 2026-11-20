//! What a launch records of what its manifest's validation accepted (SI-4, SI-5): one
//! `manifest.acknowledged_risk` per acknowledgement in effect, in the validator's order, and one
//! `manifest.warn` listing the validator's warnings by code and field. The registry writes them
//! in the session's log after the session id exists and before anything is launched, so they
//! precede `sandbox.launch` and `session.start`. A warning's message text is never recorded:
//! only the code and the field path the validator produced.
//!
//! A failed append, or an append whose task failed, refuses the start with nothing launched.
//! The session's log then holds the entries written before the failure and no `sandbox.launch`
//! or `sandbox.refuse` after them: a refused start. The control log's `session.refuse`
//! (`start-failed`) names the session (`id`) and, in its detail, the entry that failed.

use sally_core::audit::{Actor, NewEntry};
use sally_core::manifest::Validated;
use serde_json::{Value, json};

/// The most warnings one `manifest.warn` lists; its `count` is always the total.
pub const MAX_LISTED_WARNINGS: usize = 32;

/// The entries for session `session` started from `v`, in the order they are written: the
/// acknowledged risks (decision `allow`), then the warnings, if any (no decision).
#[must_use]
pub fn entries(session: &str, v: &Validated) -> Vec<NewEntry> {
    let risks = v.manifest.acknowledged_risks().iter().map(|risk| {
        NewEntry::new(Actor::Sallyd, "manifest.acknowledged_risk")
            .session(session)
            .decision("allow")
            .args(json!({ "risk": risk }))
    });
    let warn = (!v.warnings.is_empty()).then(|| {
        let listed: Vec<Value> = v
            .warnings
            .iter()
            .take(MAX_LISTED_WARNINGS)
            .map(|w| json!({"code": w.code.to_string(), "path": w.path}))
            .collect();
        NewEntry::new(Actor::Sallyd, "manifest.warn")
            .session(session)
            .args(json!({"count": v.warnings.len(), "warnings": listed}))
    });
    risks.chain(warn).collect()
}

#[cfg(test)]
#[path = "accepted_tests.rs"]
mod tests;
