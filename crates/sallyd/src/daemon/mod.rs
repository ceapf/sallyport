//! The `sallyd` process itself (Task 12, architect Q42): startup hardening, the single-instance
//! lock, the crash reporter and the runtime.

pub mod crash;
pub mod process;
pub mod serve;
pub mod startup;

/// tokio's blocking-pool size for the daemon. Stuck name lookups take at most
/// [`crate::egress::net::MAX_LOOKUPS`] of these threads; audit appends, file walks and the rest
/// share the remainder, so the pool stays well above the lookup cap (architect Q44).
pub const MAX_BLOCKING_THREADS: usize = 512;

/// The daemon's runtime: one scheduler thread, I/O and timers, and [`MAX_BLOCKING_THREADS`].
///
/// # Errors
/// The runtime's build error.
pub fn runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(MAX_BLOCKING_THREADS)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress::net::MAX_LOOKUPS;

    #[test]
    fn the_blocking_pool_stays_well_above_the_lookup_cap() {
        const { assert!(MAX_BLOCKING_THREADS >= 4 * MAX_LOOKUPS) };
        assert_eq!(MAX_BLOCKING_THREADS, 512);
    }
}
