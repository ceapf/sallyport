//! The `egress.response` entry of an intercepted exchange (Task 9a-3; the maintainer's approval
//! of the label's removal, architect Q13): which secrets the response's redaction covered and
//! how many bytes, names and counts only. One entry per response whose head is forwarded,
//! `redacted: []` when nothing was covered. It is written before the body's end reaches the
//! client; a failed append turns that end into an error and the tunnel ends `error`; a body
//! dropped before its end still gets its entry, with the counts so far. Every way the entry can
//! fail to be written fails closed: the append's own task marks the tunnel `error`, whether or
//! not anybody still waits for it (re-review H1, M1).

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use hyper::http::StatusCode;
use sally_core::audit::NewEntry;
use sally_core::manifest::AuditLevel;
use serde_json::{Value, json};

use super::State;
use crate::egress::authority::{Authority, escape_target};
use crate::egress::redact::{Ending, OnRedacted, Redaction, Report, Tally};
use crate::egress::tunnel::End;

/// Appends one response's `egress.response` entry, once, when its body ends.
pub(super) struct ResponseReport {
    pub(super) state: Arc<State>,
    /// The entry, taken by the first end reported.
    pub(super) entry: Mutex<Option<NewEntry>>,
    pub(super) target: String,
    pub(super) status: StatusCode,
    pub(super) redaction: Arc<Redaction>,
    pub(super) sink: Arc<dyn crate::sandbox::AuditSink>,
    pub(super) level: AuditLevel,
}

impl ResponseReport {
    /// The append of the entry for an end `how` that redacted `tally`. `None` only when the end
    /// was reported already; a lock or runtime that cannot run it fails (marks the tunnel).
    fn start(&self, how: Ending, tally: &Tally) -> Option<Report> {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return Some(self.failed());
        };
        let Ok(mut slot) = self.entry.lock() else {
            return Some(self.failed());
        };
        let entry = slot.take()?;
        drop(slot);
        let end = match how {
            Ending::Complete => "complete",
            Ending::Cut => self.state.end().map_or("error", End::as_str),
            Ending::Dropped => "dropped",
        };
        let args = response_args(
            &self.state.auth,
            &self.target,
            self.status,
            end,
            &self.redaction,
            tally,
        );
        let entry = entry.args(args);
        let (sink, level, st) = (Arc::clone(&self.sink), self.level, Arc::clone(&self.state));
        // TODO(#72): a dropped body's entry may land after `egress.close`.
        let h = runtime.spawn_blocking(move || {
            let ok = sink.append(entry, level).is_ok();
            if !ok {
                // TODO(#49): log an entry that could not be written; the tunnel ends `error`.
                st.held_failed.store(true, Ordering::Relaxed);
            }
            ok
        });
        Some(Box::pin(async move { matches!(h.await, Ok(true)) }))
    }

    /// The tunnel ends `error`; the end waiting for this report does not go out.
    fn failed(&self) -> Report {
        self.state.held_failed.store(true, Ordering::Relaxed);
        Box::pin(async { false })
    }
}

impl OnRedacted for ResponseReport {
    fn ended(&self, how: Ending, tally: Tally) -> Option<Report> {
        let work = self.start(how, &tally)?;
        // A dropped body has nobody to wait: the append runs on its own blocking task.
        (how != Ending::Dropped).then_some(work)
    }
}

/// `egress.response`'s arguments: the exchange, how its body ended, and per secret (in grant
/// order, `secret:NAME` as in `injected`) the bytes its forms covered, with the total.
pub(super) fn response_args(
    a: &Authority,
    target: &str,
    status: StatusCode,
    end: &str,
    r: &Redaction,
    tally: &Tally,
) -> Value {
    let (text, bytes, cut) = escape_target(target.as_bytes());
    let redacted: Vec<Value> = r
        .named(tally)
        .into_iter()
        .map(|(name, n)| json!({"secret": format!("secret:{name}"), "bytes": n}))
        .collect();
    json!({
        "host": a.host,
        "port": a.port,
        "target": text,
        "target_bytes": bytes,
        "target_cut": cut,
        "status": status.as_u16(),
        "end": end,
        "redacted_bytes": tally.total(),
        "redacted": redacted,
    })
}
