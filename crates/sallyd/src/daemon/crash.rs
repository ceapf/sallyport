//! Panics in background tasks (architect Q47). Each session has a [`CrashReporter`] that its
//! tasks (the `agent.sock` and `llm.sock` accept loops and their connections, the disk watchdog)
//! report a panic through; the session registry owns the receiving end and answers a crash with
//! `session.crash`, then a normal teardown with `session.stop reason "crash"`. The daemon's own
//! tasks (`control.sock`) have a daemon-wide reporter: a panic there stops every session and
//! `sallyd` exits non-zero.
//!
//! A task that is aborted (a stopping session, a dropped handle) is not a crash.
//!
//! A panic message can quote data the sandbox sent (std's own panics and `expect` on an error
//! do), so it is never cut before the logs mask it (architect Q293): it is held whole up to
//! [`MAX_HELD`] bytes or withheld whole; `session.crash` declares it and the writer masks it
//! before its cut at [`MAX_PAYLOAD`]; the oplog masks it before its own cap.

use std::any::Any;

use sally_core::audit::NewEntry;
use sally_core::text::Style;
use serde_json::json;
use tokio::sync::mpsc;
use tokio::task::{AbortHandle, JoinError};

/// Largest panic message a `session.crash` entry shows, cut by the writer once masked.
pub const MAX_PAYLOAD: usize = 1024;
/// Largest panic message held: a longer one is withheld whole, never cut (a cut before the mask
/// could split a form). Above every sink's cut, so the sinks cut what they show.
pub const MAX_HELD: usize = 64 * 1024;
const _: () = assert!(MAX_HELD >= crate::oplog::MAX_VALUE && MAX_HELD >= MAX_PAYLOAD);
/// How `session.crash` shows the payload: cut at [`MAX_PAYLOAD`] on a character boundary, `…`
/// after a cut, unescaped (the writer's JSON escapes it).
pub const PAYLOAD_STYLE: Style = Style::Plain { max: MAX_PAYLOAD };

/// One panicked task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Crash {
    /// Which task (`agent.sock`, `watchdog`, …).
    pub task: &'static str,
    /// The panic message: raw, whole, at most [`MAX_HELD`] bytes, never cut here (see
    /// [`payload`]); escape it before showing it.
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

/// The text of a panic payload (`&str` or `String`; anything else is named as such): whole up
/// to [`MAX_HELD`] bytes, and past it a literal naming its size, never a cut (architect Q293).
#[must_use]
pub fn payload(p: &(dyn Any + Send)) -> String {
    let text = p
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| p.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("non-text panic payload");
    if text.len() <= MAX_HELD {
        text.to_owned()
    } else {
        format!("panic payload of {} bytes withheld", text.len())
    }
}

/// What a log says of a task that panicked when it was joined (architect Q297): its message is
/// only in the oplog's panic line, held whole by [`payload`] and masked there.
pub const JOIN_PANICKED: &str = "the task panicked (its message is in the oplog's panic line)";
/// What a log says of a task that was cancelled when it was joined.
pub const JOIN_CANCELLED: &str = "the task was cancelled";

/// A failed join as a log shows it: a daemon-chosen literal, never tokio's text, which quotes
/// the panic message escaped (`{:?}`) where no mask after it can match (architect Q297).
#[must_use]
pub fn join_text(e: &JoinError) -> &'static str {
    if e.is_panic() {
        JOIN_PANICKED
    } else {
        JOIN_CANCELLED
    }
}

/// `e` as the `session.crash` of `c`: the task and the reason as args, the payload declared in
/// [`PAYLOAD_STYLE`], so the writer masks it whole before it cuts it (architect Q293).
#[must_use]
pub fn crash_entry(e: NewEntry, c: &Crash) -> NewEntry {
    e.args(json!({"task": c.task, "reason": "panic"})).text(
        "payload",
        c.payload.as_str(),
        PAYLOAD_STYLE,
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Architect Q293 (1): a payload is held whole up to [`MAX_HELD`] bytes and withheld whole
    /// past it, never cut: the sinks mask it before they cut it.
    #[test]
    fn payloads_are_text_held_whole_or_withheld_whole() {
        assert_eq!(payload(&"boom"), "boom");
        assert_eq!(payload(&String::from("bang")), "bang");
        assert_eq!(payload(&42_u32), "non-text panic payload");
        let exact = "z".repeat(MAX_HELD);
        assert_eq!(payload(&exact), exact);
        let wide = "é".repeat(MAX_HELD / 2);
        assert_eq!(payload(&wide), wide);
        let over = "z".repeat(MAX_HELD + 1);
        let withheld = payload(&over);
        assert_eq!(
            withheld,
            format!("panic payload of {} bytes withheld", MAX_HELD + 1)
        );
        assert!(!withheld.contains('z'));
    }

    const FORM: &str = "q\"u\\o\x01te-secret-value-0123456789";

    fn redactor() -> sally_core::audit::Redactor {
        sally_core::audit::Redactor::new([("Y", FORM)])
    }

    /// No 8-byte run of `FORM` raw or in any escape a sink writes.
    fn assert_no_run(shown: &str) {
        let spellings = [
            FORM.to_owned(),
            sally_core::text::escape_quoted_capped(FORM.as_bytes(), usize::MAX),
            sally_core::text::escape(FORM.as_bytes()),
        ];
        for s in &spellings {
            for w in s.as_bytes().windows(8) {
                let w = std::str::from_utf8(w).unwrap();
                assert!(!shown.contains(w), "{w:?} in ...{:?}", tail(shown));
            }
        }
    }

    fn tail(s: &str) -> &str {
        s.get(s.len().saturating_sub(80)..).unwrap_or(s)
    }

    fn crash(text: &str) -> Crash {
        Crash {
            task: "watchdog",
            payload: payload(&text.to_owned()),
        }
    }

    /// The `session.crash` payload as the writer resolves it with `FORM` registered.
    fn audited(c: &Crash) -> String {
        let e = sally_core::audit::NewEntry::new(sally_core::audit::Actor::Sallyd, "session.crash");
        let v = crash_entry(e, c).resolved(&redactor());
        assert_eq!(v["task"], "watchdog");
        assert_eq!(v["reason"], "panic");
        v["payload"]
            .as_str()
            .expect("the payload is logged")
            .to_owned()
    }

    /// The payload as an oplog line shows it, with `FORM` registered.
    fn oplogged(c: &Crash) -> String {
        #[derive(Clone, Default)]
        struct Buf(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Buf {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let buf = Buf::default();
        let log = crate::oplog::Oplog::new(buf.clone());
        log.set_redactor(std::sync::Arc::new(redactor()));
        log.error("test", "task panicked", &[("payload", &c.payload)]);
        assert!(log.flush(Duration::from_secs(10)));
        String::from_utf8_lossy(&buf.0.lock().unwrap()).into_owned()
    }

    /// Architect Q293 (2, 3, 4): a form straddling the audit entry's 1024-byte cut and one
    /// straddling the oplog's 4096-byte cap are masked whole before the cut, and a payload of
    /// [`MAX_HELD`] bytes of forms leaves no remnant in either sink. Control: the old cut at
    /// 1024 bytes in `payload()`.
    #[test]
    fn a_payloads_forms_are_masked_before_either_sink_cuts_it() {
        let audit = crash(&format!("{}{FORM} tail", "p".repeat(MAX_PAYLOAD - 12)));
        let shown = audited(&audit);
        assert!(shown.contains("[REDACTED:Y]"), "{}", tail(&shown));
        assert_no_run(&shown);
        let line = oplogged(&crash(&format!("{}{FORM} tail", "p".repeat(4096 - 30))));
        assert!(line.contains("[REDACTED:Y]"), "{}", tail(&line));
        assert_no_run(&line);
        let full = FORM.repeat(MAX_HELD / FORM.len());
        let held = crash(&full);
        assert_eq!(held.payload, full, "held whole at the stated max");
        for shown in [audited(&held), oplogged(&held)] {
            assert!(shown.contains("[REDACTED:Y]"));
            assert_no_run(&shown);
        }
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

    /// Architect Q297: a failed join says only which way it failed. tokio's own text quotes the
    /// panic message escaped (`{:?}`), which no mask after it can match.
    #[tokio::test]
    async fn a_failed_join_is_a_literal_with_no_byte_of_the_message() {
        let message = "sp-q\"u\\o\u{1}te-vvvvvvvvvvvv";
        let h = tokio::task::spawn_blocking(move || panic!("{message}"));
        let e = h.await.unwrap_err();
        assert!(e.to_string().contains("sp-q\\\"u"), "tokio's text: {e}");
        assert_eq!(join_text(&e), JOIN_PANICKED);
        let h = tokio::spawn(std::future::pending::<()>());
        h.abort();
        assert_eq!(join_text(&h.await.unwrap_err()), JOIN_CANCELLED);
        assert_ne!(JOIN_PANICKED, JOIN_CANCELLED);
    }
}
