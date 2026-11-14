//! The daemon-wide approver (architect Q73): every session's desk tells the hub, and the hub
//! tells every control connection that called `approvals.watch`. Such a connection is what
//! "attached" means (ARCHITECTURE §4.1); with none, every prompt is denied `no-approver`.
//!
//! The hub never blocks a session: each watcher has a bounded queue, and a watcher whose queue
//! is full is dropped at once (its connection then closes), never waited for. A watcher leaves
//! when its [`Watch`] is dropped; the attached count changes in the same step as the list.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tokio::sync::mpsc;

use super::queue::Approver;
use super::render::Prompt;

/// Notifications queued per watcher before it is dropped as too slow.
pub const WATCH_QUEUE: usize = 64;

/// What a watcher is told.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Note {
    /// A prompt is waiting (`approval.requested`).
    Requested(Arc<Prompt>),
    /// A session started a flood episode (`approval.flood`).
    Flood(String),
    /// The shown prompt is gone (`approval.closed`).
    Closed(String),
}

struct Watcher {
    id: u64,
    tx: mpsc::Sender<Note>,
}

/// The daemon's one approver. Shared as `Arc<Hub>`.
#[derive(Default)]
pub struct Hub {
    watchers: Mutex<Vec<Watcher>>,
    /// `watchers.len()`, written under that lock, read without it ([`Approver::attached`]).
    attached: AtomicUsize,
    next: AtomicU64,
}

impl std::fmt::Debug for Hub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hub")
            .field("attached", &self.attached.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

/// One attached watcher: its notifications arrive on `rx`. Dropping it detaches it.
#[derive(Debug)]
pub struct Watch {
    hub: Arc<Hub>,
    id: u64,
    /// The notifications; `None` once the hub dropped this watcher as too slow.
    pub rx: mpsc::Receiver<Note>,
}

impl Drop for Watch {
    fn drop(&mut self) {
        let id = self.id;
        self.hub.retain(|w| w.id != id);
    }
}

impl Hub {
    /// Attaches a watcher: from now on prompts wait for an answer instead of being denied
    /// `no-approver`. The caller lists the prompts already pending after this, so none is
    /// missed (one may arrive twice; clients de-duplicate by id).
    #[must_use]
    pub fn watch(self: &Arc<Self>) -> Watch {
        let (tx, rx) = mpsc::channel(WATCH_QUEUE);
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        let mut ws = self.lock();
        ws.push(Watcher { id, tx });
        self.attached.store(ws.len(), Ordering::SeqCst);
        drop(ws);
        Watch {
            hub: Arc::clone(self),
            id,
            rx,
        }
    }

    /// How many watchers are attached.
    #[cfg(test)]
    pub(crate) fn count(&self) -> usize {
        self.attached.load(Ordering::SeqCst)
    }

    fn lock(&self) -> MutexGuard<'_, Vec<Watcher>> {
        self.watchers.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Keeps the watchers `keep` accepts; the count follows in the same step.
    fn retain(&self, keep: impl FnMut(&Watcher) -> bool) {
        let mut ws = self.lock();
        ws.retain(keep);
        self.attached.store(ws.len(), Ordering::SeqCst);
    }

    /// Queues `note` for every watcher; one that cannot take it now is dropped.
    fn tell(&self, note: &Note) {
        self.retain(|w| w.tx.try_send(note.clone()).is_ok());
    }
}

impl Approver for Hub {
    fn attached(&self) -> bool {
        self.attached.load(Ordering::SeqCst) > 0
    }

    fn requested(&self, prompt: &Prompt) {
        self.tell(&Note::Requested(Arc::new(prompt.clone())));
    }

    fn flood(&self, session: &str) {
        self.tell(&Note::Flood(session.to_owned()));
    }

    fn closed(&self, id: &str) {
        self.tell(&Note::Closed(id.to_owned()));
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn hub() -> Arc<Hub> {
        Arc::new(Hub::default())
    }

    #[test]
    fn its_debug_names_how_many_are_attached() {
        let h = hub();
        let _w = h.watch();
        assert_eq!(format!("{h:?}"), "Hub { attached: 1, .. }");
    }

    fn prompt(id: &str) -> Prompt {
        Prompt {
            id: id.to_owned(),
            session: "s-1".to_owned(),
            call: 1,
            tool: "shell".to_owned(),
            action: "run".to_owned(),
            truncated: false,
            full: "run".to_owned(),
            digest: "d".to_owned(),
            note: None,
            risk_tags: Vec::new(),
        }
    }

    #[test]
    fn attached_while_a_watch_lives() {
        let h = hub();
        assert!(!h.attached());
        let a = h.watch();
        let b = h.watch();
        assert!(h.attached());
        drop(a);
        assert!(h.attached(), "one watcher is left");
        drop(b);
        assert!(!h.attached());
    }

    #[test]
    fn every_watcher_is_told_everything_in_order() {
        let h = hub();
        let mut a = h.watch();
        let mut b = h.watch();
        h.requested(&prompt("p1"));
        h.flood("s-1");
        h.closed("p1");
        for w in [&mut a, &mut b] {
            assert_eq!(
                w.rx.try_recv().unwrap(),
                Note::Requested(Arc::new(prompt("p1")))
            );
            assert_eq!(w.rx.try_recv().unwrap(), Note::Flood("s-1".into()));
            assert_eq!(w.rx.try_recv().unwrap(), Note::Closed("p1".into()));
            assert!(w.rx.try_recv().is_err());
        }
    }

    /// A watcher that does not read is dropped when its queue is full, without blocking the
    /// teller: it then reads what was queued, then the end; the others keep being told.
    #[test]
    fn a_full_watcher_is_dropped_and_never_waited_for() {
        let h = hub();
        let mut slow = h.watch();
        let mut fast = h.watch();
        for i in 0..WATCH_QUEUE {
            h.closed(&format!("p{i}"));
            assert!(fast.rx.try_recv().is_ok());
        }
        assert_eq!(h.attached.load(Ordering::SeqCst), 2);
        h.closed("one-too-many");
        assert_eq!(h.attached.load(Ordering::SeqCst), 1, "the slow one is gone");
        assert_eq!(
            fast.rx.try_recv().unwrap(),
            Note::Closed("one-too-many".into())
        );
        for _ in 0..WATCH_QUEUE {
            assert!(slow.rx.try_recv().is_ok());
        }
        assert_eq!(
            slow.rx.try_recv(),
            Err(mpsc::error::TryRecvError::Disconnected)
        );
        // Dropping an already-dropped watcher changes nothing.
        drop(slow);
        assert!(h.attached());
    }

    #[test]
    fn the_queue_holds_64() {
        assert_eq!(WATCH_QUEUE, 64);
    }
}
