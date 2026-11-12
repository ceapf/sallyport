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
    /// Field 22, the start time in clock ticks since boot: with the pid, it names one process
    /// even across pid reuse (rust review LOW 2).
    pub start: u64,
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
    // After ") ": field 3 (state) onwards.
    let rest = std::str::from_utf8(text.get(close.checked_add(1)?..)?).ok()?;
    let f: Vec<&str> = rest.split_ascii_whitespace().take(STARTTIME + 1).collect();
    // A zombie or dead process runs nothing: it is no process to find or kill.
    if matches!(*f.first()?, "Z" | "X" | "x") {
        return None;
    }
    let field = |n: usize| f.get(n).map(|s| s.as_bytes());
    let ppid = number(field(PPID)?)?;
    let session = number(field(SESSION)?)?;
    let start = field(STARTTIME)
        .filter(|b| !b.is_empty() && b.iter().all(u8::is_ascii_digit))
        .and_then(|b| std::str::from_utf8(b).ok()?.parse().ok())?;
    Some(Stat {
        pid,
        ppid,
        session,
        start,
    })
}

/// Positions after the command name: field 3 (state) is 0.
const PPID: usize = 1;
const SESSION: usize = 3;
const STARTTIME: usize = 19;

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
/// it (the exec session's `conmon`), and in a session no process of `before` had. A running
/// call can fork with `CLONE_PARENT` and give a child a parent outside the namespace; that child
/// keeps its call's session, which existed before (security review LOW-5).
#[must_use]
pub fn started(before: &Snapshot, now: &Snapshot) -> Vec<Stat> {
    let old = before.pids();
    let old_sessions: HashSet<i32> = before.procs.iter().map(|p| p.session).collect();
    let inside = now.pids();
    now.procs
        .iter()
        .copied()
        .filter(|p| {
            !old.contains(&p.pid) && !inside.contains(&p.ppid) && !old_sessions.contains(&p.session)
        })
        .collect()
}

/// The session of a call whose started process was never seen (it exited too soon), from what
/// it left: the one session found only among processes new since `before`, other than the
/// init's. The caller holds the exec gate from `before` on, so no other call started meanwhile;
/// a process forked by one already running shares a session that existed in `before`. `None`
/// when no such session or more than one is found.
#[must_use]
pub fn new_session(before: &Snapshot, now: &Snapshot, init: Stat) -> Option<i32> {
    let old_pids = before.pids();
    let old: HashSet<i32> = before.procs.iter().map(|p| p.session).collect();
    let mut found: Option<i32> = None;
    for p in &now.procs {
        if old_pids.contains(&p.pid) || old.contains(&p.session) || p.session == init.session {
            continue;
        }
        match found {
            None => found = Some(p.session),
            Some(s) if s == p.session => {}
            Some(_) => return None,
        }
    }
    found
}

/// One call's processes, as far as they were seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Call {
    /// The started process, if it was found alive.
    pub top: Option<i32>,
    /// The session crun gave the exec (shared by the started process and what it forks, also
    /// once the started process is gone).
    pub session: i32,
}

/// What to kill for `call`: its top process, the top's descendants, and the members of its
/// session unless that is the init's; never `init` itself.
#[must_use]
pub fn kill_set(now: &Snapshot, call: Call, init: Stat) -> Vec<i32> {
    let parent: HashMap<i32, i32> = now.procs.iter().map(|p| (p.pid, p.ppid)).collect();
    let own_session = call.session != init.session;
    let mut out: Vec<i32> = now
        .procs
        .iter()
        .filter(|p| p.pid != init.pid)
        .filter(|p| {
            (own_session && p.session == call.session)
                || call.top.is_some_and(|top| descends(&parent, p.pid, top))
        })
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
        Stat {
            pid,
            ppid,
            session,
            start: 0,
        }
    }

    /// A `/proc/<pid>/stat` line: fields 3..=22 after the name are `state ppid pgrp session`,
    /// fourteen zeros, `starttime`; then a tail like the kernel's.
    fn line(head: &str, state: &str, ppid: &str, session: &str, start: &str) -> String {
        format!("{head} {state} {ppid} 9 {session} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {start} 1 2 3")
    }

    #[test]
    fn stat_is_parsed_from_after_the_last_parenthesis() {
        let real = "1224962 (sleep) S 1224959 1224961 1224961 0 -1 4194560 92 0 0 0 0 0 0 0 20 \
                    0 1 0 8835722 1695744 98 18446744073709551615";
        let want = Stat {
            pid: 1_224_962,
            ppid: 1_224_959,
            session: 1_224_961,
            start: 8_835_722,
        };
        assert_eq!(parse_stat(real.as_bytes()), Some(want));
        // A command name with spaces and parentheses cannot shift the fields.
        let evil = line("42 (a) S 1 1 1 (b) R 7 8 9 0)", "S", "5", "7", "11");
        let want = Stat {
            pid: 42,
            ppid: 5,
            session: 7,
            start: 11,
        };
        assert_eq!(parse_stat(evil.as_bytes()), Some(want));
        assert_eq!(
            parse_stat(line("42 ()", "R", "0", "0", "0").as_bytes()),
            Some(st(42, 0, 0))
        );
        for dead in ["Z", "X", "x"] {
            let l = line("42 (sh)", dead, "1", "3", "0");
            assert_eq!(parse_stat(l.as_bytes()), None, "{dead}");
        }
        assert_eq!(
            parse_stat(line("42 (sh)", "S", "1", "3", "0").as_bytes()),
            Some(st(42, 1, 3))
        );
    }

    #[test]
    fn malformed_stat_is_refused() {
        let ok = |h: &str| line(h, "S", "1", "3", "4");
        for bad in [
            String::new(),
            "42".into(),
            "42 (x".into(),
            ok("42 x)"),
            ok("(x)"),
            ok("-1 (x)"),
            ok("4x (x)"),
            "42 (x) S".into(),
            "42 (x) S 1 9 3 0 0 0 0 0 0 0 0 0 0 0 0 0 0".into(),
            line("42 (x)", "S", "-1", "3", "4"),
            line("42 (x)", "S", "1", "x", "4"),
            line("42 (x)", "S", "99999999999", "3", "4"),
            line("42 (x)", "S", "1", "3", "-4"),
            line("42 (x)", "S", "1", "3", "4x"),
            // `str::parse` would take a sign: the field is digits only.
            line("42 (x)", "S", "1", "3", "+4"),
            line("42 (x)", "S", "1", "3", "99999999999999999999999"),
        ] {
            assert_eq!(parse_stat(bad.as_bytes()), None, "{bad:?}");
        }
        assert_eq!(parse_stat(b"42 (x) S 1 2 \xff"), None);
        let mut long = ok("42 (x)").into_bytes();
        long.push(b' ');
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

    /// Security review LOW-5: a running call's `CLONE_PARENT` child has a parent outside the
    /// namespace, but its call's session existed before the new exec.
    #[test]
    fn a_running_calls_clone_parent_child_is_not_a_new_start() {
        let before = Snapshot {
            procs: vec![st(10, 5, 10), st(30, 98, 29)],
        };
        let mut now = before.clone();
        now.procs.push(st(31, 98, 29));
        assert!(started(&before, &now).is_empty());
        now.procs.push(st(40, 97, 39));
        assert_eq!(started(&before, &now), vec![st(40, 97, 39)]);
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
        assert_eq!(
            kill_set(&now, call(Some(20), 19), init),
            vec![20, 21, 22, 23]
        );
        // The top already gone: its session still names what it left behind.
        let after = Snapshot {
            procs: now.procs.iter().copied().filter(|p| p.pid != 20).collect(),
        };
        assert_eq!(kill_set(&after, call(None, 19), init), vec![21, 22, 23]);
        assert_eq!(kill_set(&after, call(Some(20), 19), init), vec![21, 22, 23]);
    }

    #[test]
    fn a_quick_calls_session_is_the_one_new_session() {
        let init = st(10, 5, 10);
        let before = Snapshot {
            procs: vec![init, st(11, 10, 10), st(30, 98, 29)],
        };
        let mut now = before.clone();
        // Forked by the running call 30 meanwhile: its session existed before.
        now.procs.push(st(31, 30, 29));
        // Forked into init's session: never a call's.
        now.procs.push(st(12, 10, 10));
        assert_eq!(new_session(&before, &now, init), None);
        // What the quick call left, reparented to init, in its own session.
        now.procs.push(st(40, 10, 39));
        now.procs.push(st(41, 40, 39));
        assert_eq!(new_session(&before, &now, init), Some(39));
        // Two new sessions: not ours to guess.
        now.procs.push(st(50, 10, 50));
        assert_eq!(new_session(&before, &now, init), None);
        // A process already there before is never new, whatever its session.
        let mut moved = before.clone();
        moved.procs.push(st(60, 10, 59));
        let mut later = moved.clone();
        later.procs.push(st(61, 10, 59));
        assert_eq!(new_session(&moved, &later, init), None);
        let mut renamed = moved.clone();
        renamed.procs[3] = st(60, 10, 61);
        assert_eq!(new_session(&moved, &renamed, init), None);
    }

    fn call(top: Option<i32>, session: i32) -> Call {
        Call { top, session }
    }

    #[test]
    fn a_call_in_the_inits_session_is_killed_by_descent_only() {
        let init = st(10, 5, 10);
        let now = Snapshot {
            procs: vec![
                init,
                st(11, 10, 10),
                st(20, 99, 10),
                st(21, 20, 10),
                st(22, 21, 10),
            ],
        };
        assert_eq!(kill_set(&now, call(Some(20), 10), init), vec![20, 21, 22]);
        assert!(kill_set(&now, call(None, 10), init).is_empty());
        // Even a top that is the init is never selected itself; only its descendants are (20
        // hangs under a conmon outside the namespace, not under the init).
        assert_eq!(kill_set(&now, call(Some(10), 10), init), vec![11]);
    }

    #[test]
    fn a_parent_cycle_ends_the_walk() {
        let init = st(1, 0, 1);
        let now = Snapshot {
            procs: vec![st(20, 99, 1), st(30, 31, 1), st(31, 30, 1)],
        };
        assert_eq!(kill_set(&now, call(Some(20), 1), init), vec![20]);
    }
}
