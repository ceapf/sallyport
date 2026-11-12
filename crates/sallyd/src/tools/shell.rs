//! The `shell` tool's pure parts (ARCHITECTURE §4.3; maintainer's Task 11 decision 3; architect
//! ruling Q32): the `podman exec` argv, the limits, and the capped capture of an output stream.
//! The runner that starts, watches and kills the process is `exec.rs`; tests stand in for it
//! through [`Runner`].
//!
//! The argv is fixed: `exec --workdir=<cwd> <container id> <argv…>`. Nothing from the harness
//! precedes the container id except the absolute working directory, joined to its flag so it is
//! never read as one; podman parses nothing after the container id. No `-i` (stdin is null), no
//! `-t`, no `--env`, `--user` or `--privileged`: the command gets the container's own
//! environment, set at create, and its user.

use std::future::Future;
use std::time::Duration;

/// A command that runs longer is killed (`killed: timeout`).
pub const TIME_LIMIT: Duration = Duration::from_secs(300);
/// The started process must be found within this, or the call is killed (`killed:
/// start-timeout`).
pub const START_LIMIT: Duration = Duration::from_secs(10);
/// Bytes kept per output stream; the rest is read and counted.
pub const OUTPUT_CAP: usize = 64 * 1024;

/// The `podman exec` arguments (after the `podman` binary) that run `argv` in `cwd`.
#[must_use]
pub fn exec_argv(container: &str, cwd: &str, argv: &[String]) -> Vec<String> {
    let mut a = vec![
        "exec".to_owned(),
        format!("--workdir={cwd}"),
        container.to_owned(),
    ];
    a.extend(argv.iter().cloned());
    a
}

/// One output stream, capped at [`OUTPUT_CAP`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Captured {
    /// The first bytes, at most [`OUTPUT_CAP`].
    pub kept: Vec<u8>,
    /// Every byte read.
    pub total: u64,
}

impl Captured {
    /// Takes `chunk`: counts all of it, keeps what fits.
    pub fn push(&mut self, chunk: &[u8]) {
        let room = OUTPUT_CAP.saturating_sub(self.kept.len());
        self.kept
            .extend_from_slice(chunk.get(..chunk.len().min(room)).unwrap_or_default());
        self.total = self
            .total
            .saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
    }

    /// Whether bytes were dropped.
    #[must_use]
    pub fn cut(&self) -> bool {
        self.total > u64::try_from(self.kept.len()).unwrap_or(u64::MAX)
    }
}

/// How a command ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// `podman exec`'s exit code: the command's, 126/127 when it could not start, 128+N for a
    /// signal.
    Exited(i32),
    /// The broker killed it: `timeout` or `start-timeout`.
    Killed(&'static str),
    /// `podman exec` itself could not be run.
    Failed(String),
}

/// A command's result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    /// How it ended.
    pub status: Status,
    /// Its stdout.
    pub stdout: Captured,
    /// Its stderr.
    pub stderr: Captured,
}

/// Runs a command in the workspace. Production: `exec::PodmanExec`. A runner holds the session's
/// exec gate only while starting the process (#24) and kills what it started on its time limit
/// and when dropped (#62).
pub trait Runner: Send + Sync + 'static {
    /// Runs `argv` in the guest directory `cwd`.
    fn run(&self, argv: &[String], cwd: &str) -> impl Future<Output = Output> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_exec_argv_puts_nothing_of_the_harness_before_the_container_but_the_workdir() {
        let argv = vec!["--privileged".to_owned(), "-u".to_owned(), "0".to_owned()];
        assert_eq!(
            exec_argv("c0ffee", "/workspace/p", &argv),
            [
                "exec",
                "--workdir=/workspace/p",
                "c0ffee",
                "--privileged",
                "-u",
                "0"
            ]
        );
        assert_eq!(
            exec_argv("c", "/", &["ls".to_owned()]),
            ["exec", "--workdir=/", "c", "ls"]
        );
    }

    #[test]
    fn a_capture_keeps_the_cap_and_counts_everything() {
        let mut c = Captured::default();
        assert!(!c.cut());
        c.push(&vec![b'a'; OUTPUT_CAP - 1]);
        assert!(!c.cut());
        c.push(b"bc");
        assert_eq!(c.kept.len(), OUTPUT_CAP);
        assert_eq!(c.kept.last(), Some(&b'b'));
        assert_eq!(c.total, u64::try_from(OUTPUT_CAP).unwrap() + 1);
        assert!(c.cut());
        c.push(b"");
        c.push(b"more");
        assert_eq!(c.kept.len(), OUTPUT_CAP);
        assert_eq!(c.total, u64::try_from(OUTPUT_CAP).unwrap() + 5);
        let mut exact = Captured::default();
        exact.push(&vec![b'x'; OUTPUT_CAP]);
        assert!(!exact.cut());
    }

    #[test]
    fn the_limits_are_the_ruled_numbers() {
        assert_eq!(TIME_LIMIT, Duration::from_secs(300));
        assert_eq!(START_LIMIT, Duration::from_secs(10));
        assert_eq!(OUTPUT_CAP, 65_536);
    }
}
