//! The `sallyd` process itself (Task 12, architect Q42): startup hardening, the single-instance
//! lock, the crash reporter and the runtime.

pub mod crash;
pub mod install;
pub mod process;
pub mod serve;
pub mod stale;
pub mod startup;
pub mod sweep;

/// tokio's blocking-pool size for the daemon. Stuck name lookups take at most
/// [`crate::egress::net::MAX_LOOKUPS`] of these threads; audit appends, file walks and the rest
/// share the remainder, so the pool stays well above the lookup cap (architect Q44).
pub const MAX_BLOCKING_THREADS: usize = 512;

/// Shutdown's verdict (#239): the ids whose containers were not confirmed gone, from the
/// sessions' stops and from the launcher's removals not finished at that moment (a failed
/// launch's cleanup, the stop of a container nobody holds), merged, sorted and each once.
/// Empty: a clean stop.
#[must_use]
pub fn not_stopped_cleanly(sessions: Vec<String>, cleanups: Vec<String>) -> Vec<String> {
    let all: std::collections::BTreeSet<String> = sessions.into_iter().chain(cleanups).collect();
    all.into_iter().collect()
}

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

    fn ids(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    /// Allow: nothing left from either source is a clean stop.
    #[test]
    fn nothing_left_is_a_clean_stop() {
        assert!(not_stopped_cleanly(Vec::new(), Vec::new()).is_empty());
    }

    /// Deny: a failed launch's unfinished cleanup alone makes the stop unclean, as a session
    /// whose stop failed does; both lists are kept, sorted, each id once.
    #[test]
    fn a_failed_launch_left_alone_makes_the_stop_unclean() {
        assert_eq!(not_stopped_cleanly(Vec::new(), ids(&["f"])), ids(&["f"]));
        assert_eq!(not_stopped_cleanly(ids(&["s"]), Vec::new()), ids(&["s"]));
        assert_eq!(
            not_stopped_cleanly(ids(&["z", "b"]), ids(&["c", "b", "a"])),
            ids(&["a", "b", "c", "z"])
        );
    }

    /// The unclean exit names every kind of id it can carry: a session's, a failed launch's,
    /// and that of a launch nobody holds (RT-AG-08b).
    #[test]
    fn the_unclean_exit_names_what_it_covers() {
        let e = serve::DaemonError::Unconfirmed(ids(&["s-1", "i-2"]));
        assert_eq!(
            e.to_string(),
            "containers not confirmed gone (sessions, failed launches or launches nobody \
             holds): [\"s-1\", \"i-2\"]"
        );
    }
}
