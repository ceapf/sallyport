//! The tool operations of one session in flight, and its stop (architect Q59).
//!
//! Once a session's stop returns, nothing from that session can have any further effect. So the
//! stop first closes the session's [`Ops`] (no operation enters after it: the call is denied
//! `session-stopping`), then raises the stop signal (a running shell is killed; a write or delete
//! that has not begun aborts), then waits at most [`STOP_DRAIN`] for the operations inside to
//! end. Each of them writes its own `tool.result`, completed or aborted. A file operation already
//! inside its blocking call runs to its end: it is never cut between two syscalls.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

/// How long a stop waits for the operations in flight.
pub const STOP_DRAIN: Duration = Duration::from_secs(5);
/// Why a shell was killed, or a write aborted, by its session's stop (`tool.result`).
pub const SESSION_STOP: &str = "session-stop";

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct State {
    closed: bool,
    stopping: bool,
    count: usize,
}

/// One session's operations. Cheap to clone; every clone is the same tracker.
#[derive(Debug, Clone)]
pub struct Ops {
    state: Arc<watch::Sender<State>>,
}

impl Default for Ops {
    fn default() -> Self {
        Self::new()
    }
}

/// One operation in flight; dropping it (also while unwinding) ends it.
#[derive(Debug)]
pub struct Op {
    ops: Ops,
}

impl Drop for Op {
    fn drop(&mut self) {
        self.ops
            .state
            .send_modify(|s| s.count = s.count.saturating_sub(1));
    }
}

impl Ops {
    /// An open tracker with nothing in flight.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Arc::new(watch::Sender::new(State::default())),
        }
    }

    /// Starts an operation, or `None` once the tracker is closed.
    #[must_use]
    pub fn enter(&self) -> Option<Op> {
        let mut entered = false;
        self.state.send_modify(|s| {
            if !s.closed {
                s.count = s.count.saturating_add(1);
                entered = true;
            }
        });
        entered.then(|| Op { ops: self.clone() })
    }

    /// No operation enters from now on. Idempotent.
    pub fn close(&self) {
        self.state.send_modify(|s| s.closed = true);
    }

    /// Whether [`close`](Self::close) (or [`stop`](Self::stop)) was called.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.state.borrow().closed
    }

    /// Closes and raises the stop signal: operations in flight end as soon as they can.
    pub fn stop(&self) {
        self.state.send_modify(|s| {
            s.closed = true;
            s.stopping = true;
        });
    }

    /// Resolves once [`stop`](Self::stop) was called.
    pub async fn stopped(&self) {
        let mut rx = self.state.subscribe();
        // The sender lives as long as `self`, so this only ends by the condition.
        let _ = rx.wait_for(|s| s.stopping).await;
    }

    /// Operations in flight now.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.state.borrow().count
    }

    /// Resolves once nothing is in flight.
    pub async fn idle(&self) {
        let mut rx = self.state.subscribe();
        let _ = rx.wait_for(|s| s.count == 0).await;
    }

    /// Waits at most `bound` for nothing to be in flight; how many still are.
    pub async fn drained(&self, bound: Duration) -> usize {
        let _ = tokio::time::timeout(bound, self.idle()).await;
        self.in_flight()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn the_drain_bound_is_five_seconds() {
        assert_eq!(STOP_DRAIN, Duration::from_secs(5));
    }

    #[test]
    fn nothing_enters_once_closed_and_closing_twice_changes_nothing() {
        let ops = Ops::new();
        assert!(!ops.is_closed());
        let a = ops.enter().unwrap();
        assert_eq!(ops.in_flight(), 1);
        ops.close();
        assert!(ops.is_closed());
        assert!(ops.enter().is_none());
        assert_eq!(ops.in_flight(), 1, "a refused enter counts nothing");
        ops.close();
        assert!(ops.is_closed() && ops.enter().is_none());
        drop(a);
        assert_eq!(ops.in_flight(), 0);
    }

    #[test]
    fn a_clone_is_the_same_tracker() {
        let ops = Ops::default();
        let other = ops.clone();
        let _a = other.enter().unwrap();
        assert_eq!(ops.in_flight(), 1);
        ops.close();
        assert!(other.is_closed());
    }

    #[tokio::test]
    async fn stop_closes_and_wakes_the_waiters() {
        let ops = Ops::new();
        let waiting = tokio::spawn({
            let ops = ops.clone();
            async move { ops.stopped().await }
        });
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        ops.stop();
        tokio::time::timeout(Duration::from_secs(5), waiting)
            .await
            .unwrap()
            .unwrap();
        assert!(ops.is_closed());
        assert!(ops.enter().is_none());
        // Stopping again, or closing a stopped tracker, keeps it stopped.
        ops.stop();
        ops.close();
        tokio::time::timeout(Duration::from_secs(1), ops.stopped())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn close_alone_raises_no_stop() {
        let ops = Ops::new();
        ops.close();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), ops.stopped())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn the_drain_ends_at_zero_and_times_out_while_one_is_held() {
        let ops = Ops::new();
        assert_eq!(ops.drained(Duration::from_secs(5)).await, 0);
        let (a, b) = (ops.enter().unwrap(), ops.enter().unwrap());
        ops.stop();
        let start = tokio::time::Instant::now();
        assert_eq!(ops.drained(Duration::from_millis(50)).await, 2);
        assert!(start.elapsed() >= Duration::from_millis(50));
        drop(a);
        let ends = tokio::spawn({
            let ops = ops.clone();
            async move { ops.drained(Duration::from_secs(5)).await }
        });
        tokio::task::yield_now().await;
        drop(b);
        assert_eq!(ends.await.unwrap(), 0);
    }

    #[test]
    fn a_holder_that_panics_still_ends_its_operation() {
        let ops = Ops::new();
        let inside = ops.clone();
        let r = std::panic::catch_unwind(move || {
            let _op = inside.enter().unwrap();
            panic!("tool");
        });
        assert!(r.is_err());
        assert_eq!(ops.in_flight(), 0);
    }
}
