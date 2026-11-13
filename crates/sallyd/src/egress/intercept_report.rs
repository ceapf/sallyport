//! The `egress.response` entry of an intercepted exchange (Task 9a-3; the maintainer's approval
//! of the label's removal, architect Q13): which secrets the response's redaction covered and
//! how many bytes, names and counts only. One entry per response whose head is forwarded,
//! `redacted: []` when nothing was covered. It is written before the body's end reaches the
//! client; a failed append turns that end into an error and the tunnel ends `error`; a body
//! dropped before its end still gets its entry, with the counts so far.

use sally_core::manifest::AuditLevel;

use super::super::super::redact::{Ending, OnRedacted, Redaction, Report, Tally};
use super::super::super::tunnel::End;
use super::{
    Arc, Authority, Mutex, NewEntry, Ordering, State, StatusCode, Value, escape_target, json,
};

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
    /// Starts the append of the entry for an end `how` that redacted `tally`; `None` when it
    /// was reported already or no runtime can run the append.
    fn start(&self, how: Ending, tally: &Tally) -> Option<Report> {
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
        let entry = self.entry.lock().ok()?.take()?.args(args);
        let (sink, level) = (Arc::clone(&self.sink), self.level);
        let runtime = tokio::runtime::Handle::try_current().ok()?;
        // TODO(#72): a dropped body's entry may land after `egress.close`.
        let h = runtime.spawn_blocking(move || sink.append(entry, level));
        let st = Arc::clone(&self.state);
        Some(Box::pin(async move {
            let ok = matches!(h.await, Ok(Ok(())));
            if !ok {
                // TODO(#49): log an entry that could not be written; the tunnel ends `error`.
                st.held_failed.store(true, Ordering::Relaxed);
            }
            ok
        }))
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
