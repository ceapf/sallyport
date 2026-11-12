//! Which processes a `shell` call started, and which to kill (architect ruling Q32). Pure: a
//! snapshot of the container's processes in, pids out; `exec.rs` takes the snapshots from
//! `/proc` and sends the signals.
//!
//! Probed on Podman 4.9.3 with crun (`docs/dev/PROBE_NOTES.md`): an exec'd process's parent is
//! the exec session's `conmon`, outside the container's pid namespace, and crun gives each exec
//! its own session. So the process a call started is the new one in the namespace whose parent is
//! not in it; what belongs to the call is that process, its descendants, and the members of its
//! session (an orphan keeps its session when it is reparented to the container's init). The
//! container's init and anything in the init's session are never selected. A process that calls
//! `setsid` and reparents to init escapes the selection until teardown (THREAT_MODEL residual).

use std::collections::{HashMap, HashSet};

/// The fields of `/proc/<pid>/stat` used here (host pid numbers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stat {
    /// Field 1.
    pub pid: i32,
    /// Field 4.
    pub ppid: i32,
    /// Field 6.
    pub session: i32,
}

/// Longest `/proc/<pid>/stat` text parsed (the kernel's is well below it).
pub const MAX_STAT: usize = 4096;

/// Parses `/proc/<pid>/stat`. The command name (field 2, in parentheses) is chosen by the
/// process and may hold spaces and `)`, so parsing starts after the last `)`.
#[must_use]
pub fn parse_stat(text: &[u8]) -> Option<Stat> {
    if text.len() > MAX_STAT {
        return None;
    }
    let open = text.iter().position(|&b| b == b'(')?;
    let close = text.iter().rposition(|&b| b == b')')?;
    let pid = number(text.get(..open)?.trim_ascii())?;
    // After ") ": state, ppid, pgrp, session.
    let rest = std::str::from_utf8(text.get(close.checked_add(1)?..)?).ok()?;
    let mut f = rest.split_ascii_whitespace();
    let _state = f.next()?;
    let ppid = f.next().and_then(|s| number(s.as_bytes()))?;
    let _pgrp = f.next()?;
    let session = f.next().and_then(|s| number(s.as_bytes()))?;
    Some(Stat { pid, ppid, session })
}

/// A non-negative decimal `i32`, digits only.
fn number(b: &[u8]) -> Option<i32> {
    if b.is_empty() || !b.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(b).ok()?.parse().ok()
}

/// The processes in the container's pid namespace, from one snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    /// Every process in the namespace.
    pub procs: Vec<Stat>,
}

impl Snapshot {
    fn pids(&self) -> HashSet<i32> {
        self.procs.iter().map(|p| p.pid).collect()
    }

    /// The process with `pid`, if it is in the namespace.
    #[must_use]
    pub fn get(&self, pid: i32) -> Option<Stat> {
        self.procs.iter().copied().find(|p| p.pid == pid)
    }
}

/// The processes a new exec started: not in `before`, in the namespace, with a parent outside
/// it (the exec session's `conmon`).
#[must_use]
pub fn started(before: &Snapshot, now: &Snapshot) -> Vec<Stat> {
    let old = before.pids();
    let inside = now.pids();
    now.procs
        .iter()
        .copied()
        .filter(|p| !old.contains(&p.pid) && !inside.contains(&p.ppid))
        .collect()
}

/// What to kill for the call whose top process is `top`: `top`, its descendants, and the
/// members of its session unless that is the init's; never `init` itself.
#[must_use]
pub fn kill_set(now: &Snapshot, top: Stat, init: Stat) -> Vec<i32> {
    let parent: HashMap<i32, i32> = now.procs.iter().map(|p| (p.pid, p.ppid)).collect();
    let own_session = top.session != init.session;
    let mut out: Vec<i32> = now
        .procs
        .iter()
        .filter(|p| p.pid != init.pid)
        .filter(|p| (own_session && p.session == top.session) || descends(&parent, p.pid, top.pid))
        .map(|p| p.pid)
        .collect();
    out.sort_unstable();
    out
}

/// Whether `pid` is `top` or below it, following parents through the snapshot only (a cycle or
/// a chain longer than the snapshot ends the walk).
fn descends(parent: &HashMap<i32, i32>, pid: i32, top: i32) -> bool {
    let mut at = pid;
    for _ in 0..=parent.len() {
        if at == top {
            return true;
        }
        match parent.get(&at) {
            Some(&p) => at = p,
            None => return false,
        }
    }
    false
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn st(pid: i32, ppid: i32, session: i32) -> Stat {
        Stat { pid, ppid, session }
    }

    #[test]
    fn stat_is_parsed_from_after_the_last_parenthesis() {
        let line = b"1224962 (sleep) S 1224959 1224961 1224961 0 -1 4194560 92 0 0 0";
        assert_eq!(parse_stat(line), Some(st(1_224_962, 1_224_959, 1_224_961)));
        // A command name with spaces and parentheses cannot shift the fields.
        let evil = b"42 (a) S 1 1 1 (b) R 7 8 9 0) S 5 6 7 0 0";
        assert_eq!(parse_stat(evil), Some(st(42, 5, 7)));
        assert_eq!(parse_stat(b"42 () Z 0 0 0 0"), Some(st(42, 0, 0)));
    }

    #[test]
    fn malformed_stat_is_refused() {
        for bad in [
            &b""[..],
            b"42",
            b"42 (x",
            b"42 x) S 1 2 3",
            b"(x) S 1 2 3",
            b"-1 (x) S 1 2 3",
            b"4x (x) S 1 2 3",
            b"42 (x) S",
            b"42 (x) S 1 2",
            b"42 (x) S -1 2 3",
            b"42 (x) S 1 2 x",
            b"42 (x) S 99999999999 2 3",
            b"42 (x) S 1 2 \xff",
        ] {
            assert_eq!(parse_stat(bad), None, "{:?}", String::from_utf8_lossy(bad));
        }
        let mut long = b"42 (x) S 1 2 3 ".to_vec();
        long.resize(MAX_STAT, b'0');
        assert!(parse_stat(&long).is_some());
        long.push(b'0');
        assert_eq!(parse_stat(&long), None);
    }

    #[test]
    fn the_started_process_is_the_new_one_whose_parent_is_outside() {
        let before = Snapshot {
            procs: vec![st(10, 5, 10), st(11, 10, 10)],
        };
        let now = Snapshot {
            procs: vec![
                st(10, 5, 10),
                st(11, 10, 10),
                // forked by a running command: its parent is inside
                st(12, 11, 10),
                // the new exec, under its conmon (99, outside)
                st(20, 99, 19),
                st(21, 20, 19),
            ],
        };
        assert_eq!(started(&before, &now), vec![st(20, 99, 19)]);
        assert!(started(&now, &now).is_empty());
        assert_eq!(now.get(21), Some(st(21, 20, 19)));
        assert_eq!(now.get(5), None);
    }

    #[test]
    fn the_kill_set_is_the_call_and_never_the_init_or_another_call() {
        let init = st(10, 5, 10);
        let top = st(20, 99, 19);
        let now = Snapshot {
            procs: vec![
                init,
                st(11, 10, 10), // the entry, in init's session
                top,
                st(21, 20, 19), // child
                st(22, 21, 19), // grandchild
                st(23, 10, 19), // orphan reparented to init, same session
                st(24, 10, 24), // orphan that called setsid: escapes (documented)
                st(30, 98, 29), // another call
                st(31, 30, 29),
            ],
        };
        assert_eq!(kill_set(&now, top, init), vec![20, 21, 22, 23]);
    }

    #[test]
    fn a_call_in_the_inits_session_is_killed_by_descent_only() {
        let init = st(10, 5, 10);
        let top = st(20, 99, 10);
        let now = Snapshot {
            procs: vec![init, st(11, 10, 10), top, st(21, 20, 10), st(22, 21, 10)],
        };
        assert_eq!(kill_set(&now, top, init), vec![20, 21, 22]);
        // Even a top that is the init is never selected itself; only its descendants are (20
        // hangs under a conmon outside the namespace, not under the init).
        assert_eq!(kill_set(&now, init, init), vec![11]);
    }

    #[test]
    fn a_parent_cycle_ends_the_walk() {
        let init = st(1, 0, 1);
        let top = st(20, 99, 1);
        let now = Snapshot {
            procs: vec![top, st(30, 31, 1), st(31, 30, 1)],
        };
        assert_eq!(kill_set(&now, top, init), vec![20]);
    }
}
