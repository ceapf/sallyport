//! The daemon's file-descriptor budget (#48, architect Q45). `sallyd` raises its soft
//! `RLIMIT_NOFILE` to the hard limit at startup; half of the raised limit is shared by the live
//! sessions, the other half stays for the daemon itself (control connections, audit, podman
//! pipes). A session reserves its worst case together with its overlap claim
//! ([`super::Sessions::reserve`]) and frees it on release, so the sum over sessions can never run
//! the daemon out of descriptors (one session's EMFILE would hit every session).

use crate::egress::server::ADMISSION_EXTRA;

/// Descriptors a session holds besides its egress connections: its listeners (`agent.sock`,
/// `llm.sock`, `net.sock`), the connections on `agent.sock` and `llm.sock`, a running `shell`
/// command's pipes and process handles, and the watchdog's init directory and cgroup event
/// files. Rounded up well past their sum (`fixed_part_covers_every_holder`).
pub(crate) const SESSION_FIXED_FDS: u64 = 64;

/// The budget the live sessions share: half of the raised soft `RLIMIT_NOFILE`.
#[must_use]
pub(crate) const fn session_budget(nofile: u64) -> u64 {
    nofile / 2
}

/// A session's worst case: two descriptors per egress connection (the sandbox's side and the
/// upstream's), for `max_connections` plus the [`ADMISSION_EXTRA`] answered 429, plus
/// [`SESSION_FIXED_FDS`].
#[must_use]
pub(crate) fn session_cost(max_connections: u32) -> u64 {
    let extra = u64::try_from(ADMISSION_EXTRA).unwrap_or(u64::MAX);
    u64::from(max_connections)
        .saturating_add(extra)
        .saturating_mul(2)
        .saturating_add(SESSION_FIXED_FDS)
}

/// A session refused because its worst case does not fit (`sandbox.refuse reason "fd-budget"`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "the session needs {needed} file descriptors, {free} of the daemon's session budget of {limit} \
     are free (half of RLIMIT_NOFILE; lower network.max_connections or stop a session)"
)]
pub struct FdRefusal {
    /// The session's worst case.
    pub needed: u64,
    /// What the live sessions leave free.
    pub free: u64,
    /// The whole session budget.
    pub limit: u64,
}

/// Admits `needed` when it fits in what `used` leaves of `limit`; a limit too low for even one
/// session is the same refusal.
///
/// # Errors
/// [`FdRefusal`] naming the three numbers.
pub(crate) fn admit(limit: u64, used: u64, needed: u64) -> Result<(), FdRefusal> {
    let free = limit.saturating_sub(used);
    if needed <= free {
        Ok(())
    } else {
        Err(FdRefusal {
            needed,
            free,
            limit,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm::server::MAX_CONNECTIONS as LLM_CONNECTIONS;
    use crate::rpc::agent::MAX_CONNECTIONS as AGENT_CONNECTIONS;

    #[test]
    fn fixed_part_covers_every_holder() {
        // Listeners: agent.sock, llm.sock, net.sock. Shell: stdin, stdout, stderr, pidfd and the
        // podman pipes. Watchdog: init dir and the two cgroup event files.
        let listeners = 3;
        let shell = 8;
        let watchdog = 3;
        let conns = u64::try_from(AGENT_CONNECTIONS + LLM_CONNECTIONS).unwrap_or(u64::MAX);
        assert!(SESSION_FIXED_FDS >= conns + listeners + shell + watchdog);
    }

    #[test]
    fn the_cost_counts_both_ends_of_every_admitted_connection() {
        assert_eq!(session_cost(0), 2 * 64 + SESSION_FIXED_FDS);
        assert_eq!(session_cost(32), 2 * (32 + 64) + SESSION_FIXED_FDS);
        // The issue's case: 1024 connections need about 1088 + 1024 descriptors and more.
        assert_eq!(session_cost(1024), 2 * 1088 + SESSION_FIXED_FDS);
        assert_eq!(session_cost(u32::MAX), 2 * (u64::from(u32::MAX) + 64) + 64);
    }

    #[test]
    fn the_budget_is_half_the_limit() {
        assert_eq!(session_budget(1024), 512);
        assert_eq!(session_budget(1025), 512);
        assert_eq!(session_budget(524_288), 262_144);
        assert_eq!(session_budget(0), 0);
    }

    #[test]
    fn a_session_that_fits_is_admitted_up_to_the_last_descriptor() {
        assert_eq!(admit(1000, 0, 1000), Ok(()));
        assert_eq!(admit(1000, 400, 600), Ok(()));
        assert_eq!(admit(1000, 999, 1), Ok(()));
        assert_eq!(admit(1000, 1000, 0), Ok(()));
    }

    #[test]
    fn a_session_past_the_budget_is_refused_naming_the_numbers() {
        let e = admit(1000, 400, 601).unwrap_err();
        assert_eq!(
            e,
            FdRefusal {
                needed: 601,
                free: 600,
                limit: 1000
            }
        );
        let msg = e.to_string();
        assert!(
            msg.contains("601") && msg.contains("600") && msg.contains("1000"),
            "{msg}"
        );
        // Over-committed (cannot happen, but never wraps): nothing is free.
        assert_eq!(admit(1000, 1200, 1).unwrap_err().free, 0);
    }

    #[test]
    fn a_limit_too_low_for_one_session_refuses_it() {
        let needed = session_cost(32);
        let limit = session_budget(256);
        assert_eq!(
            admit(limit, 0, needed),
            Err(FdRefusal {
                needed,
                free: limit,
                limit
            })
        );
    }
}
