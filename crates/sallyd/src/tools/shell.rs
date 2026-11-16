//! The `shell` tool's pure parts (ARCHITECTURE §4.3; maintainer's Task 11 decision 3; architect
//! ruling Q32): the `podman exec` argv, the limits, and the capped capture of an output stream.
//! The runner that starts, watches and kills the process is `exec.rs`; tests stand in for it
//! through [`Runner`].
//!
//! The argv is fixed: `exec --workdir=<cwd> <container id> <argv…>`. Nothing from the harness
//! precedes the container id except the absolute working directory, joined to its flag so it is
//! never read as one; podman parses nothing after the container id. No `-t`, no `--env`,
//! `--user` or `--privileged`: the command gets the container's own environment, set at create,
//! and its user. The shell tool's command has no `-i` (stdin is null); only a command attached
//! by `sessions.attach` gets `-i`, before the container id ([`Stdin::Piped`]; architect Q49,
//! Q145).

use std::future::Future;
use std::time::Duration;

use sally_proto::{MAX_OUTPUT_CHUNK, Stream};
use tokio::sync::{mpsc, oneshot, watch};

/// A command that runs longer is killed (`killed: timeout`).
pub const TIME_LIMIT: Duration = Duration::from_secs(300);
/// The started process must be found within this, or the call is killed (`killed:
/// start-timeout`).
pub const START_LIMIT: Duration = Duration::from_secs(10);
/// Bytes kept per output stream; the rest is read and counted.
pub const OUTPUT_CAP: usize = 64 * 1024;

/// Where a command's standard input comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stdin {
    /// Nothing: the shell tool's commands.
    Null,
    /// A pipe `sallyd` writes `sessions.input` to: an attached command (`-i`; architect Q49).
    Piped,
}

/// The `podman exec` arguments (after the `podman` binary) that run `argv` in `cwd`.
#[must_use]
pub fn exec_argv(container: &str, cwd: &str, argv: &[String], stdin: Stdin) -> Vec<String> {
    let mut a = vec!["exec".to_owned()];
    if stdin == Stdin::Piped {
        a.push("-i".to_owned());
    }
    a.push(format!("--workdir={cwd}"));
    a.push(container.to_owned());
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

/// A piece of an attached command's output: at most [`MAX_OUTPUT_CHUNK`] bytes of one stream,
/// escaped by that stream's `StreamEscaper` (architect Q100, Q101).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    /// The stream.
    pub stream: Stream,
    /// The escaped text: printable ASCII and newline.
    pub text: String,
}

/// One `sessions.input` for an attached command.
#[derive(Debug)]
pub struct Input {
    /// The bytes to write.
    pub data: Vec<u8>,
    /// Close the command's standard input after them.
    pub eof: bool,
    /// Told whether they were written; dropped unanswered when the command ended first.
    pub done: oneshot::Sender<bool>,
}

/// An attached command's ends (architect Q101, Q145).
#[derive(Debug)]
pub struct AttachIo {
    /// Its standard input.
    pub input: mpsc::Receiver<Input>,
    /// Where its output goes; a full queue pauses the reading of the pipes.
    pub output: mpsc::Sender<Chunk>,
    /// Becomes `true`, or its sender is dropped, when the attached connection is gone.
    pub disconnect: watch::Receiver<bool>,
}

/// What an attached command did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ran {
    /// How it ended.
    pub status: Status,
    /// Bytes written to its standard input.
    pub stdin: u64,
    /// Bytes read from its standard output.
    pub stdout: u64,
    /// Bytes read from its standard error.
    pub stderr: u64,
}

/// Runs an attached command, its output streamed. Production: `exec::PodmanExec`, the same
/// runner as the shell tool's (architect Q101: no second copy); tests stand in for it.
pub trait Streamer: Send + Sync + 'static {
    /// Runs `argv` in the guest directory `cwd` with `io`, with no time limit of its own: the
    /// session's stop or the connection's end kills it.
    fn attach(&self, argv: &[String], cwd: &str, io: AttachIo) -> impl Future<Output = Ran> + Send;
}

/// How many bytes to read from a pipe next, so that with the `held` bytes its escaper carries
/// the chunk is at most [`MAX_OUTPUT_CHUNK`] bytes of source (architect Q101).
#[must_use]
pub fn read_len(held: usize) -> usize {
    MAX_OUTPUT_CHUNK.saturating_sub(held)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_exec_argv_puts_nothing_of_the_harness_before_the_container_but_the_workdir() {
        let argv = vec!["--privileged".to_owned(), "-u".to_owned(), "0".to_owned()];
        assert_eq!(
            exec_argv("c0ffee", "/workspace/p", &argv, Stdin::Null),
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
            exec_argv("c", "/", &["ls".to_owned()], Stdin::Null),
            ["exec", "--workdir=/", "c", "ls"]
        );
    }

    /// Architect Q145: only an attached command gets `-i`, and it comes before the container id,
    /// so podman reads it as its own flag; the shell tool's command never has it.
    #[test]
    fn only_an_attached_command_keeps_stdin_open() {
        let argv = vec!["sh".to_owned(), "-i".to_owned()];
        assert_eq!(
            exec_argv("c", "/w", &argv, Stdin::Piped),
            ["exec", "-i", "--workdir=/w", "c", "sh", "-i"]
        );
        let tool = exec_argv("c", "/w", &argv, Stdin::Null);
        assert_eq!(tool, ["exec", "--workdir=/w", "c", "sh", "-i"]);
        let before_id = tool.iter().take_while(|a| *a != "c").collect::<Vec<_>>();
        assert!(!before_id.iter().any(|a| a.as_str() == "-i"));
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
    fn a_read_leaves_room_for_the_carry() {
        assert_eq!(read_len(0), MAX_OUTPUT_CHUNK);
        assert_eq!(read_len(3), MAX_OUTPUT_CHUNK - 3);
        assert_eq!(read_len(MAX_OUTPUT_CHUNK + 1), 0);
    }

    #[test]
    fn the_limits_are_the_ruled_numbers() {
        assert_eq!(TIME_LIMIT, Duration::from_secs(300));
        assert_eq!(START_LIMIT, Duration::from_secs(10));
        assert_eq!(OUTPUT_CAP, 65_536);
    }
}
