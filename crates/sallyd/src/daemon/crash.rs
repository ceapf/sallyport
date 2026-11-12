//! Panics in background tasks (architect Q47). Each session has a [`CrashReporter`] that its
//! tasks (the `agent.sock` and `llm.sock` accept loops and their connections, the disk watchdog)
//! report a panic through; the session registry owns the receiving end and answers a crash with
//! `session.crash`, then a normal teardown with `session.stop reason "crash"`. The daemon's own
//! tasks (`control.sock`) have a daemon-wide reporter: a panic there stops every session and
//! `sallyd` exits non-zero.
//!
//! A task that is aborted (a stopping session, a dropped handle) is not a crash.

use std::any::Any;

use tokio::sync::mpsc;
use tokio::task::{AbortHandle, JoinError};

/// Largest panic message carried (the oplog and the audit entry cap it again).
pub const MAX_PAYLOAD: usize = 1024;

/// One panicked task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Crash {
    /// Which task (`agent.sock`, `watchdog`, …).
    pub task: &'static str,
    /// The panic message, cut at [`MAX_PAYLOAD`] bytes (raw: escape before showing it).
    pub payload: String,
}

/// The sending half, cloned into every task of one session (or of the daemon).
#[derive(Debug, Clone)]
pub struct CrashReporter {
    tx: mpsc::UnboundedSender<Crash>,
}

/// The receiving half, held by whoever answers the crash.
pub type CrashReceiver = mpsc::UnboundedReceiver<Crash>;

impl CrashReporter {
    /// A reporter and its receiver.
    #[must_use]
    pub fn channel() -> (Self, CrashReceiver) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Self { tx }, rx)
    }

    /// Reports `e` for `task` when it is a panic; a cancelled task is not reported. Never blocks;
    /// a receiver that is gone (the session already ended) drops the report.
    pub fn joined(&self, task: &'static str, e: JoinError) {
        if let Ok(panic) = e.try_into_panic() {
            let _ = self.tx.send(Crash {
                task,
                payload: payload(panic.as_ref()),
            });
        }
    }

    /// Spawns `fut` as `task`; a panic in it is reported. The handle aborts it (no report).
    pub fn spawn<F>(&self, task: &'static str, fut: F) -> AbortHandle
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let inner = tokio::spawn(fut);
        let abort = inner.abort_handle();
        let me = self.clone();
        tokio::spawn(async move {
            if let Err(e) = inner.await {
                me.joined(task, e);
            }
        });
        abort
    }
}

/// The text of a panic payload (`&str` or `String`; anything else is named as such), cut at
/// [`MAX_PAYLOAD`] bytes on a character boundary.
#[must_use]
pub fn payload(p: &(dyn Any + Send)) -> String {
    let text = p
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| p.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("non-text panic payload");
    let mut end = text.len().min(MAX_PAYLOAD);
    while !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    text.get(..end).unwrap_or_default().to_owned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn payloads_are_text_and_capped_on_a_character_boundary() {
        assert_eq!(payload(&"boom"), "boom");
        assert_eq!(payload(&String::from("bang")), "bang");
        assert_eq!(payload(&42_u32), "non-text panic payload");
        let long = "é".repeat(MAX_PAYLOAD);
        let cut = payload(&long);
        assert!(cut.len() <= MAX_PAYLOAD && cut.len() >= MAX_PAYLOAD - 1);
        assert!(cut.chars().all(|c| c == 'é'));
        let exact = "a".repeat(MAX_PAYLOAD);
        assert_eq!(payload(&exact), exact);
    }

    #[tokio::test]
    async fn a_panicking_task_is_reported_with_its_name() {
        let (r, mut rx) = CrashReporter::channel();
        r.spawn("watchdog", async { panic!("disk on fire") });
        let c = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            c,
            Crash {
                task: "watchdog",
                payload: "disk on fire".into()
            }
        );
    }

    #[tokio::test]
    async fn an_aborted_or_finished_task_is_not_a_crash() {
        let (r, mut rx) = CrashReporter::channel();
        let h = r.spawn("watchdog", std::future::pending());
        h.abort();
        r.spawn("other", async {});
        drop(r);
        // Every sender is gone once both watchers end, with nothing sent.
        let got = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap();
        assert_eq!(got, None);
    }

    #[tokio::test]
    async fn a_report_after_the_receiver_is_gone_is_dropped() {
        let (r, rx) = CrashReporter::channel();
        drop(rx);
        let h = tokio::spawn(async { panic!("late") });
        r.joined("agent.sock", h.await.unwrap_err());
    }
}
