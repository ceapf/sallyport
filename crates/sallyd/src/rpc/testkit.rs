//! Test doubles shared by the socket servers' unit tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, Mutex};

use sally_core::audit::{AuditError, NewEntry};
use sally_core::manifest::AuditLevel;
use serde_json::Value;

use super::record::Recorder;
use crate::sandbox::AuditSink;

/// One recorded entry.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    pub event: String,
    pub decision: Option<String>,
    pub args: Value,
    /// The entry's `Debug` text (it names the session and the detail level).
    pub debug: String,
}

/// Records every entry; `fail` refuses every append.
#[derive(Default)]
pub struct Sink {
    rows: Mutex<Vec<Row>>,
    pub fail: std::sync::atomic::AtomicBool,
    /// Appends still to refuse before appends succeed again.
    pub fail_next: std::sync::atomic::AtomicUsize,
    /// When non-zero: every append fails once this many rows are recorded.
    pub fail_from: std::sync::atomic::AtomicUsize,
    /// While set, appends wait (an audit write that takes a while).
    held: Mutex<bool>,
    unheld: std::sync::Condvar,
}

impl AuditSink for Sink {
    fn append(&self, e: NewEntry, _: AuditLevel) -> Result<(), AuditError> {
        use std::sync::atomic::Ordering::SeqCst;
        let once = self
            .fail_next
            .try_update(SeqCst, SeqCst, |n| n.checked_sub(1))
            .is_ok();
        let mut held = self.held.lock().unwrap();
        while *held {
            held = self.unheld.wait(held).unwrap();
        }
        drop(held);
        let from = self.fail_from.load(SeqCst);
        let full = from > 0 && self.rows.lock().unwrap().len() >= from;
        if once || full || self.fail.load(SeqCst) {
            return Err(AuditError::InvalidEntry("fake failure"));
        }
        self.rows.lock().unwrap().push(Row {
            event: e.event().to_owned(),
            decision: e.decision_value().map(str::to_owned),
            args: e.arguments().clone(),
            debug: format!("{e:?}"),
        });
        Ok(())
    }
}

impl Sink {
    pub fn rows(&self) -> Vec<Row> {
        self.rows.lock().unwrap().clone()
    }

    pub fn events(&self) -> Vec<String> {
        self.rows().into_iter().map(|r| r.event).collect()
    }

    /// The arguments of the last entry named `event`.
    pub fn last(&self, event: &str) -> Value {
        let rows = self.rows();
        rows.iter()
            .rev()
            .find(|r| r.event == event)
            .map_or(Value::Null, |r| r.args.clone())
    }

    /// Makes appends wait (`true`) or lets them through (`false`).
    pub fn hold(&self, on: bool) {
        *self.held.lock().unwrap() = on;
        self.unheld.notify_all();
    }

    pub fn set_failing(&self, fail: bool) {
        self.fail.store(fail, std::sync::atomic::Ordering::SeqCst);
    }

    /// Holds appends until the guard is dropped, also when the test panics: a write blocked in
    /// the sink never outlives the test, whose runtime would wait for it.
    pub fn held(self: &Arc<Self>) -> Held {
        self.hold(true);
        Held(Arc::clone(self))
    }
}

/// See [`Sink::held`].
pub struct Held(Arc<Sink>);

impl Drop for Held {
    fn drop(&mut self) {
        self.0.hold(false);
    }
}

/// A sink and a recorder for `session` writing into it.
pub fn recorder(session: &str) -> (Arc<Sink>, Recorder) {
    let sink = Arc::new(Sink::default());
    let r = Recorder::new(
        Arc::clone(&sink) as Arc<dyn AuditSink>,
        session.to_owned(),
        AuditLevel::Full,
    );
    (sink, r)
}
