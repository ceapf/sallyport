//! The startup calls that change the `sallyd` process for good (architect Q42 steps 1–3 and 7).
//! A test process cannot make them and keep working (a non-dumpable process cannot read its own
//! `/proc/self/…` files as other tests do), so the binary's tests in `tests/daemon.rs` cover
//! them; the decisions are the pure functions of `startup.rs`.

use rustix::fs::Mode;
use rustix::process::{DumpableBehavior, Resource, Rlimit};

use super::startup::{StartError, check_ids, nofile_target};

/// Steps 1–2: umask 077, no core dumps, not dumpable. Runs first, before the runtime, secrets
/// and the audit log exist.
///
/// # Errors
/// [`StartError::Harden`] naming the call.
pub fn harden() -> Result<(), StartError> {
    rustix::process::umask(Mode::from_raw_mode(0o077));
    let none = Rlimit {
        current: Some(0),
        maximum: Some(0),
    };
    rustix::process::setrlimit(Resource::Core, none).map_err(|e| StartError::Harden {
        what: "setrlimit(RLIMIT_CORE)",
        source: e.into(),
    })?;
    rustix::process::set_dumpable_behavior(DumpableBehavior::NotDumpable).map_err(|e| {
        StartError::Harden {
            what: "prctl(PR_SET_DUMPABLE)",
            source: e.into(),
        }
    })
}

/// Step 3 for this process.
///
/// # Errors
/// As [`check_ids`].
pub fn check_own_ids() -> Result<(), StartError> {
    use rustix::process::{getegid, geteuid, getgid, getuid};
    check_ids(
        getuid().as_raw(),
        geteuid().as_raw(),
        getgid().as_raw(),
        getegid().as_raw(),
    )
}

/// Step 7: raises the soft `NOFILE` toward the hard limit; the limit now in force.
///
/// # Errors
/// [`StartError::Harden`].
pub fn raise_nofile() -> Result<u64, StartError> {
    let now = rustix::process::getrlimit(Resource::Nofile);
    let target = nofile_target(now.current, now.maximum);
    rustix::process::setrlimit(
        Resource::Nofile,
        Rlimit {
            current: Some(target),
            maximum: now.maximum,
        },
    )
    .map_err(|e| StartError::Harden {
        what: "setrlimit(RLIMIT_NOFILE)",
        source: e.into(),
    })?;
    Ok(target)
}
