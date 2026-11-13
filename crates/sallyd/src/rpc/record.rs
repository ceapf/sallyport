//! Audit entries of the broker sockets (SI-4; architect ruling Q9). Every entry is appended off
//! the runtime before the reply it covers; a failed append means no effect and no reply. Strings
//! the peer chose (a method, a path, a field name, an id) are escaped and cut before they are
//! written.

use std::fmt::Write as _;
use std::sync::{Arc, Mutex, PoisonError};

use sally_core::audit::{Actor, NewEntry};
use sally_core::manifest::AuditLevel;
use tokio::sync::watch;

use crate::oplog::Oplog;
use crate::sandbox::AuditSink;

/// Bytes of a peer-chosen string kept in an entry.
pub const LOGGED_BYTES: usize = 64;

/// Where one session's socket entries go. Clones share one [`seal`](Recorder::seal): once it
/// has written the session's last entry, no clone writes again.
#[derive(Clone)]
pub struct Recorder {
    audit: Arc<dyn AuditSink>,
    session: String,
    level: AuditLevel,
    seal: Arc<Seal>,
    /// Where a write the seal refused is noted (session and event name only).
    log: Option<Oplog>,
}

/// What [`Recorder::seal`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sealed {
    /// Whether the last entry was written.
    pub written: bool,
    /// Writes still in flight when the bound ran out: each lands before the last entry or
    /// fails.
    pub late: usize,
}

/// A session's audit handle state (architect, PR A part 4 ruling 1): `closing` refuses new
/// writes and `writing` counts those in flight; `order` is held across each write to the sink,
/// and is `true` once the last entry has been written.
struct Seal {
    state: watch::Sender<Count>,
    order: Mutex<bool>,
}

#[derive(Debug, Default, Clone, Copy)]
struct Count {
    closing: bool,
    writing: usize,
}

/// One write in flight; ending it (or dropping it) takes it off the count.
struct Writing(Arc<Seal>);

impl Drop for Writing {
    fn drop(&mut self) {
        self.0
            .state
            .send_modify(|c| c.writing = c.writing.saturating_sub(1));
    }
}

impl Seal {
    fn new() -> Self {
        Self {
            state: watch::Sender::new(Count::default()),
            order: Mutex::new(false),
        }
    }

    /// A write may begin, unless the handle is closing.
    fn begin(self: &Arc<Self>) -> Option<Writing> {
        let mut admitted = false;
        self.state.send_modify(|c| {
            if !c.closing {
                c.writing += 1;
                admitted = true;
            }
        });
        admitted.then(|| Writing(Arc::clone(self)))
    }

    /// Appends under `order`, unless the last entry is already written. A poisoned `order`
    /// reads as sealed.
    fn write(&self, sink: &dyn AuditSink, entry: NewEntry, level: AuditLevel) -> Wrote {
        let Ok(sealed) = self.order.lock() else {
            return Wrote::Sealed;
        };
        if *sealed {
            Wrote::Sealed
        } else if sink.append(entry, level).is_ok() {
            Wrote::Yes
        } else {
            Wrote::Failed
        }
    }

    /// Writes `last` under `order` and seals, unless already sealed (then nothing is written).
    fn last(&self, sink: &dyn AuditSink, last: NewEntry, level: AuditLevel) -> bool {
        let mut sealed = self.order.lock().unwrap_or_else(PoisonError::into_inner);
        if *sealed {
            return false;
        }
        *sealed = true;
        sink.append(last, level).is_ok()
    }
}

/// How one write ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Wrote {
    Yes,
    Failed,
    /// Refused: the session's last entry is written.
    Sealed,
}

impl std::fmt::Debug for Recorder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Recorder")
            .field("session", &self.session)
            .field("level", &self.level)
            .finish_non_exhaustive()
    }
}

impl Recorder {
    /// A recorder for `session` at `level`.
    #[must_use]
    pub fn new(audit: Arc<dyn AuditSink>, session: String, level: AuditLevel) -> Self {
        Self {
            audit,
            session,
            level,
            seal: Arc::new(Seal::new()),
            log: None,
        }
    }

    /// A new entry of this session (none for an empty session id: the control socket's).
    #[must_use]
    pub fn entry(&self, actor: Actor, event: &str, decision: Option<&str>) -> NewEntry {
        let e = NewEntry::new(actor, event);
        let e = if self.session.is_empty() {
            e
        } else {
            e.session(self.session.clone())
        };
        match decision {
            Some(d) => e.decision(d),
            None => e,
        }
    }

    /// Appends off the runtime; whether the entry was written. Never once the session's last
    /// entry is (or is being) written: the caller then has no effect. A caller that goes away
    /// leaves its write running, still counted by [`seal`](Self::seal).
    pub async fn append(&self, entry: NewEntry) -> bool {
        let event = entry.event().to_owned();
        let Some(writing) = self.seal.begin() else {
            self.refused(&event);
            return false;
        };
        let (sink, level) = (Arc::clone(&self.audit), self.level);
        let wrote = tokio::task::spawn_blocking(move || {
            let w = writing;
            w.0.write(sink.as_ref(), entry, level)
        })
        .await;
        match wrote {
            Ok(Wrote::Yes) => true,
            Ok(Wrote::Sealed) => {
                self.refused(&event);
                false
            }
            Ok(Wrote::Failed) | Err(_) => false,
        }
    }

    /// The oplog line of a write the seal refused: the session and the event, nothing else.
    fn refused(&self, event: &str) {
        if let Some(log) = &self.log {
            log.error(
                "audit",
                "entry refused after session.stop",
                &[("session", &self.session), ("event", event)],
            );
        }
    }

    /// The session id (empty for the control socket's).
    #[must_use]
    pub fn session(&self) -> &str {
        &self.session
    }

    /// Notes each write the seal refuses on `log`.
    #[must_use]
    pub fn logging(self, log: Oplog) -> Self {
        Self {
            log: Some(log),
            ..self
        }
    }

    /// Writes the session's last entry (`session.stop`) and closes the handle: no new write
    /// begins; those in flight get up to `bound` to end; then `last` is written, and every
    /// write after it fails, in this recorder and all its clones. A write still in flight at
    /// the bound either landed before `last` or fails. Sealed even when `last` is not written.
    /// A second seal writes nothing; so does the control socket's recorder (no session), which
    /// is never sealed.
    pub async fn seal(&self, last: NewEntry, bound: std::time::Duration) -> Sealed {
        if self.session.is_empty() {
            return Sealed {
                written: false,
                late: 0,
            };
        }
        self.seal.state.send_modify(|c| c.closing = true);
        let mut count = self.seal.state.subscribe();
        let drained = tokio::time::timeout(bound, count.wait_for(|c| c.writing == 0))
            .await
            .is_ok();
        let late = if drained { 0 } else { count.borrow().writing };
        let (seal, sink, level) = (Arc::clone(&self.seal), Arc::clone(&self.audit), self.level);
        let written =
            tokio::task::spawn_blocking(move || seal.last(sink.as_ref(), last, level)).await;
        Sealed {
            written: matches!(written, Ok(true)),
            late,
        }
    }
}

/// `raw` for an audit entry: printable ASCII other than `\` and `"` as is, every other byte as
/// `\xNN`; at most [`LOGGED_BYTES`] input bytes, then `…(+N)` with the number left out.
#[must_use]
pub fn escape(raw: &[u8]) -> String {
    let shown = raw.get(..LOGGED_BYTES).unwrap_or(raw);
    let mut out = String::with_capacity(shown.len());
    for &b in shown {
        if (0x20..0x7f).contains(&b) && b != b'\\' && b != b'"' {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "\\x{b:02x}");
        }
    }
    if raw.len() > shown.len() {
        let _ = write!(out, "…(+{})", raw.len() - shown.len());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_names_the_session_and_level_only() {
        let (_, rec) = crate::rpc::testkit::recorder("sess-a");
        assert_eq!(
            format!("{rec:?}"),
            r#"Recorder { session: "sess-a", level: Full, .. }"#
        );
    }

    fn note(rec: &Recorder, event: &str) -> NewEntry {
        rec.entry(Actor::Sallyd, event, None)
    }

    /// Waits until `n` writes of `rec` are in flight.
    async fn writing(rec: &Recorder, n: usize) {
        let mut seen = rec.seal.state.subscribe();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            seen.wait_for(|s| s.writing == n),
        )
        .await
        .unwrap()
        .unwrap();
    }

    #[tokio::test]
    async fn after_the_seal_no_entry_of_the_session_is_written() {
        let (sink, rec) = crate::rpc::testkit::recorder("sess-a");
        assert!(rec.append(note(&rec, "tool.run")).await);
        let sealed = rec
            .seal(
                note(&rec, "session.stop"),
                std::time::Duration::from_secs(1),
            )
            .await;
        assert_eq!(
            sealed,
            Sealed {
                written: true,
                late: 0
            }
        );
        assert!(!rec.append(note(&rec, "tool.result")).await);
        assert!(!rec.clone().append(note(&rec, "approval.decide")).await);
        assert_eq!(sink.events(), ["tool.run", "session.stop"]);
    }

    #[tokio::test]
    async fn a_write_in_flight_at_the_seal_lands_before_the_last_entry() {
        let (sink, rec) = crate::rpc::testkit::recorder("sess-a");
        sink.hold(true);
        let slow = tokio::spawn({
            let rec = rec.clone();
            async move { rec.append(note(&rec, "approval.withdraw")).await }
        });
        writing(&rec, 1).await;
        let seal = tokio::spawn({
            let rec = rec.clone();
            async move {
                rec.seal(
                    note(&rec, "session.stop"),
                    std::time::Duration::from_secs(5),
                )
                .await
            }
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            !seal.is_finished(),
            "the seal waits for the write in flight"
        );
        sink.hold(false);
        assert!(slow.await.unwrap());
        assert_eq!(
            seal.await.unwrap(),
            Sealed {
                written: true,
                late: 0
            }
        );
        assert_eq!(sink.events(), ["approval.withdraw", "session.stop"]);
    }

    #[tokio::test]
    async fn a_dropped_caller_still_counts_until_its_write_ends() {
        let (sink, rec) = crate::rpc::testkit::recorder("sess-a");
        sink.hold(true);
        let caller = tokio::spawn({
            let rec = rec.clone();
            async move { rec.append(note(&rec, "tool.result")).await }
        });
        writing(&rec, 1).await;
        caller.abort();
        let _ = caller.await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert_eq!(
            rec.seal.state.borrow().writing,
            1,
            "the write is still running"
        );
        sink.hold(false);
        writing(&rec, 0).await;
        assert_eq!(sink.events(), ["tool.result"]);
    }

    #[tokio::test]
    async fn past_the_bound_a_write_not_yet_begun_fails_and_never_follows_the_last_entry() {
        let (sink, rec) = crate::rpc::testkit::recorder("sess-a");
        // One write waits inside the sink holding the order; a second waits behind it.
        sink.hold(true);
        let first = tokio::spawn({
            let rec = rec.clone();
            async move { rec.append(note(&rec, "tool.run")).await }
        });
        writing(&rec, 1).await;
        let second = tokio::spawn({
            let rec = rec.clone();
            async move { rec.append(note(&rec, "tool.result")).await }
        });
        writing(&rec, 2).await;
        let seal = tokio::spawn({
            let rec = rec.clone();
            async move {
                rec.seal(
                    note(&rec, "session.stop"),
                    std::time::Duration::from_millis(50),
                )
                .await
            }
        });
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        sink.hold(false);
        let sealed = seal.await.unwrap();
        assert!(sealed.written);
        assert_eq!(sealed.late, 2, "both were still in flight at the bound");
        assert!(first.await.unwrap(), "a write already in the sink lands");
        let second = second.await.unwrap();
        let events = sink.events();
        assert_eq!(
            events.last().map(String::as_str),
            Some("session.stop"),
            "{events:?}"
        );
        assert_eq!(
            second,
            events.contains(&"tool.result".to_owned()),
            "{events:?}"
        );
    }

    #[test]
    fn a_write_that_began_before_the_seal_but_runs_after_it_fails() {
        let (sink, rec) = crate::rpc::testkit::recorder("sess-a");
        let seal = Seal::new();
        let e = || NewEntry::new(Actor::Sallyd, "tool.result");
        assert_eq!(seal.write(sink.as_ref(), e(), AuditLevel::Full), Wrote::Yes);
        sink.set_failing(true);
        assert_eq!(
            seal.write(sink.as_ref(), e(), AuditLevel::Full),
            Wrote::Failed
        );
        sink.set_failing(false);
        *seal.order.lock().unwrap() = true;
        assert_eq!(
            seal.write(sink.as_ref(), e(), AuditLevel::Full),
            Wrote::Sealed
        );
        assert_eq!(sink.events(), ["tool.result"]);
        drop(rec);
    }

    #[test]
    fn a_poisoned_order_reads_as_sealed() {
        let (sink, _) = crate::rpc::testkit::recorder("sess-a");
        let seal = Arc::new(Seal::new());
        let s = Arc::clone(&seal);
        let _ = std::thread::spawn(move || {
            let _held = s.order.lock().unwrap();
            panic!("a write panicked");
        })
        .join();
        let e = NewEntry::new(Actor::Sallyd, "tool.result");
        assert_eq!(
            seal.write(sink.as_ref(), e, AuditLevel::Full),
            Wrote::Sealed
        );
        assert!(sink.events().is_empty());
    }

    #[tokio::test]
    async fn a_second_seal_writes_nothing() {
        let (sink, rec) = crate::rpc::testkit::recorder("sess-a");
        let bound = std::time::Duration::from_secs(1);
        assert!(rec.seal(note(&rec, "session.stop"), bound).await.written);
        let again = rec.clone().seal(note(&rec, "session.stop"), bound).await;
        assert_eq!(
            again,
            Sealed {
                written: false,
                late: 0
            }
        );
        assert_eq!(sink.events(), ["session.stop"]);
    }

    #[tokio::test]
    async fn the_control_recorder_is_never_sealed() {
        let (sink, rec) = crate::rpc::testkit::recorder("");
        let bound = std::time::Duration::from_secs(1);
        let sealed = rec.seal(note(&rec, "session.stop"), bound).await;
        assert_eq!(
            sealed,
            Sealed {
                written: false,
                late: 0
            }
        );
        assert!(rec.append(note(&rec, "control.request")).await);
        assert_eq!(sink.events(), ["control.request"]);
    }

    /// An oplog writer the test reads back.
    #[derive(Clone, Default)]
    struct Lines(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Lines {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn a_refused_write_is_an_oplog_line_naming_only_the_session_and_event() {
        let (_, rec) = crate::rpc::testkit::recorder("sess-a");
        let lines = Lines::default();
        let log = Oplog::new(lines.clone());
        let rec = rec.logging(log.clone());
        let bound = std::time::Duration::from_secs(1);
        assert!(rec.seal(note(&rec, "session.stop"), bound).await.written);
        let late = note(&rec, "tool.result").args(serde_json::json!({"secret-ish": "canary-77"}));
        assert!(!rec.append(late).await);
        assert!(log.flush(std::time::Duration::from_secs(5)));
        let text = String::from_utf8(lines.0.lock().unwrap().clone()).unwrap();
        assert_eq!(text.lines().count(), 1, "{text}");
        assert!(text.contains("entry refused after session.stop"), "{text}");
        assert!(
            text.contains("sess-a") && text.contains("tool.result"),
            "{text}"
        );
        assert!(!text.contains("canary-77"), "{text}");
    }

    /// A write admitted before the seal that reaches the sink after it: refused and noted.
    // The test holds `order` while the write waits for it on the blocking pool, on purpose.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn a_write_overtaken_by_the_seal_is_refused_and_noted() {
        let (sink, rec) = crate::rpc::testkit::recorder("sess-a");
        let lines = Lines::default();
        let log = Oplog::new(lines.clone());
        let rec = rec.logging(log.clone());
        let mut held = rec.seal.order.lock().unwrap();
        let write = tokio::spawn({
            let rec = rec.clone();
            async move { rec.append(note(&rec, "approval.decide")).await }
        });
        writing(&rec, 1).await;
        *held = true;
        drop(held);
        assert!(!write.await.unwrap());
        assert!(sink.events().is_empty());
        assert!(log.flush(std::time::Duration::from_secs(5)));
        let text = String::from_utf8(lines.0.lock().unwrap().clone()).unwrap();
        assert!(text.contains("approval.decide"), "{text}");
    }

    #[tokio::test]
    async fn a_failed_last_entry_still_seals() {
        let (sink, rec) = crate::rpc::testkit::recorder("sess-a");
        sink.set_failing(true);
        let sealed = rec
            .seal(
                note(&rec, "session.stop"),
                std::time::Duration::from_secs(1),
            )
            .await;
        assert_eq!(
            sealed,
            Sealed {
                written: false,
                late: 0
            }
        );
        sink.set_failing(false);
        assert!(!rec.append(note(&rec, "tool.run")).await);
        assert!(sink.events().is_empty());
    }

    #[test]
    fn printable_text_is_kept() {
        assert_eq!(escape(b"tools/list"), "tools/list");
        assert_eq!(escape(b""), "");
    }

    #[test]
    fn controls_quotes_backslashes_and_high_bytes_are_escaped() {
        assert_eq!(
            escape(b"a\x1b[2J\r\n\"\\\x7f\xe2\x80\xae"),
            "a\\x1b[2J\\x0d\\x0a\\x22\\x5c\\x7f\\xe2\\x80\\xae"
        );
    }

    #[test]
    fn long_input_is_cut_with_a_count() {
        let exact = vec![b'a'; LOGGED_BYTES];
        assert_eq!(escape(&exact), "a".repeat(LOGGED_BYTES));
        let long = vec![b'a'; LOGGED_BYTES + 3];
        assert_eq!(escape(&long), format!("{}…(+3)", "a".repeat(LOGGED_BYTES)));
    }
}
