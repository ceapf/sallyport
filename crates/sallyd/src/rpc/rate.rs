//! A request-rate limit (generic cell rate algorithm): on average `rate` per second, with bursts
//! of up to `burst` back to back. Integer arithmetic on the tokio clock, so tests can pause time.

use std::time::Duration;

use tokio::time::Instant;

/// A rate limit shared by everything that draws on it (callers wrap it in a mutex).
#[derive(Debug, Clone)]
pub struct Rate {
    /// Time one request costs: 1 s / rate.
    interval: Duration,
    /// How far ahead of now the schedule may run: (burst − 1) intervals.
    tolerance: Duration,
    /// When the schedule next frees a slot (the theoretical arrival time).
    tat: Instant,
}

impl Rate {
    /// `rate` requests per second on average, `burst` at once. Both are at least 1.
    #[must_use]
    pub fn new(rate: u32, burst: u32) -> Self {
        Self::every(Duration::from_secs(1) / rate.max(1), burst)
    }

    /// One request per `interval` on average (at least 1 ns), `burst` (at least 1) at once.
    #[must_use]
    pub fn every(interval: Duration, burst: u32) -> Self {
        let interval = interval.max(Duration::from_nanos(1));
        Self {
            interval,
            tolerance: interval.saturating_mul(burst.max(1).saturating_sub(1)),
            tat: Instant::now(),
        }
    }

    /// Whether every slot of the burst is free now.
    #[must_use]
    pub fn full(&self) -> bool {
        self.tat <= Instant::now()
    }

    /// Takes one slot if the limit allows it now; whether it did.
    #[cfg(test)]
    pub(crate) fn allow(&mut self) -> bool {
        self.take().is_ok()
    }

    /// Takes one slot now, or says how long until one is free.
    ///
    /// # Errors
    /// The time to wait before asking again.
    pub fn take(&mut self) -> Result<(), Duration> {
        let now = Instant::now();
        let start = self.tat.max(now);
        let ahead = start.saturating_duration_since(now);
        if ahead > self.tolerance {
            return Err(ahead.saturating_sub(self.tolerance));
        }
        self.tat = start + self.interval;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn burst(r: &mut Rate) -> usize {
        std::iter::from_fn(|| r.allow().then_some(()))
            .take(10_000)
            .count()
    }

    #[tokio::test(start_paused = true)]
    async fn a_full_bucket_allows_exactly_the_burst() {
        let mut r = Rate::new(10, 4);
        assert_eq!(burst(&mut r), 4);
    }

    #[tokio::test(start_paused = true)]
    async fn slots_come_back_at_the_rate() {
        let mut r = Rate::new(10, 4);
        burst(&mut r);
        tokio::time::advance(Duration::from_millis(99)).await;
        assert!(!r.allow());
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(r.allow());
        assert!(!r.allow());
        tokio::time::advance(Duration::from_millis(250)).await;
        assert_eq!(burst(&mut r), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn an_idle_limit_never_saves_more_than_the_burst() {
        let mut r = Rate::new(10, 4);
        tokio::time::advance(Duration::from_secs(60)).await;
        assert_eq!(burst(&mut r), 4);
    }

    #[tokio::test(start_paused = true)]
    async fn sustained_use_holds_the_rate() {
        let mut r = Rate::new(20, 1);
        let mut allowed = 0;
        for _ in 0..1000 {
            allowed += usize::from(r.allow());
            tokio::time::advance(Duration::from_millis(10)).await;
        }
        // 10 s at 20/s.
        assert_eq!(allowed, 200);
    }

    #[tokio::test(start_paused = true)]
    async fn a_refusal_says_how_long_to_wait() {
        let mut r = Rate::new(10, 2);
        assert_eq!(r.take(), Ok(()));
        assert_eq!(r.take(), Ok(()));
        assert_eq!(r.take(), Err(Duration::from_millis(100)));
        tokio::time::advance(Duration::from_millis(40)).await;
        assert_eq!(r.take(), Err(Duration::from_millis(60)));
        tokio::time::advance(Duration::from_millis(60)).await;
        assert_eq!(r.take(), Ok(()));
    }

    #[tokio::test(start_paused = true)]
    async fn one_slot_per_interval_with_a_burst() {
        let mut r = Rate::every(Duration::from_secs(2), 3);
        assert!(r.full());
        assert_eq!(burst(&mut r), 3);
        assert!(!r.full());
        tokio::time::advance(Duration::from_millis(1999)).await;
        assert!(!r.allow());
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(r.allow());
        // Full again once every slot has come back: three intervals after the last take.
        tokio::time::advance(Duration::from_millis(5999)).await;
        assert!(!r.full());
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(r.full());
        assert_eq!(burst(&mut r), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn a_zero_interval_or_burst_still_limits() {
        let mut r = Rate::every(Duration::ZERO, 0);
        assert_eq!(burst(&mut r), 1);
        tokio::time::advance(Duration::from_nanos(1)).await;
        assert!(r.allow());
    }

    #[tokio::test(start_paused = true)]
    async fn zero_settings_mean_one() {
        let mut r = Rate::new(0, 0);
        assert_eq!(burst(&mut r), 1);
        tokio::time::advance(Duration::from_millis(999)).await;
        assert!(!r.allow());
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(r.allow());
    }
}
