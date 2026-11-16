//! The pipe work of an attached command (architect Q101, Q145, Q152), apart from the runner in
//! `exec.rs` so it is tested without a container: each output pipe read, escaped per stream
//! (RT-CLI-01) and queued with backpressure; the inputs written to stdin in order; why a run
//! must end. `exec.rs` starts these on the `podman exec` client's pipes.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sally_core::text::StreamEscaper;
use sally_proto::Stream;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::{mpsc, watch};

use super::ops::{DISCONNECT, Ops, SESSION_STOP};
use super::shell::{Chunk, Input, read_len};

/// How long output is still read after the client exited (a background process can hold the
/// pipes open): the shell tool's readers in all, an attached command's per pipe of idleness.
pub const DRAIN_LIMIT: Duration = Duration::from_millis(500);

/// Bytes an attached command moved, counted as they go.
#[derive(Debug, Default)]
pub struct Counts {
    /// Written to its stdin.
    pub stdin: AtomicU64,
    /// Read from its stdout.
    pub stdout: AtomicU64,
    /// Read from its stderr.
    pub stderr: AtomicU64,
}

/// The two marks a reader watches: `halt` (stop reading at once: a stop or a disconnect) and
/// `exited` (the client exited: the idle bound starts).
pub type Marks = (watch::Receiver<bool>, watch::Receiver<bool>);

/// Resolves with why the run must end: its session stopped, or (attach only) its connection
/// is gone. A stop wins when both hold. A disconnect watch whose sender is gone is a
/// disconnect: the attach's guard fires on drop.
pub async fn ended(ops: &Ops, disconnect: Option<watch::Receiver<bool>>) -> &'static str {
    let gone = async move {
        match disconnect {
            Some(mut d) => {
                let _ = d.wait_for(|gone| *gone).await;
            }
            None => std::future::pending().await,
        }
    };
    tokio::select! {
        biased;
        () = ops.stopped() => SESSION_STOP,
        () = gone => DISCONNECT,
    }
}

/// `f` within `limit`; no limit: `f` to its end.
///
/// # Errors
/// [`Elapsed`](tokio::time::error::Elapsed) when `limit` passed first.
pub async fn within<F: Future>(
    limit: Option<Duration>,
    f: F,
) -> Result<F::Output, tokio::time::error::Elapsed> {
    match limit {
        Some(l) => tokio::time::timeout(l, f).await,
        None => Ok(f.await),
    }
}

/// Reads one pipe of an attached command to its end: each read at most what keeps the chunk
/// with its carry within [`sally_proto::MAX_OUTPUT_CHUNK`], escaped by this stream's own
/// escaper (the RT-CLI-01 control), and queued, waiting for room. Ends at the pipe's end (a
/// read error is one), at [`DRAIN_LIMIT`] of idleness once the client exited, or when halted.
pub async fn stream(
    mut r: impl AsyncRead + Unpin + Send + 'static,
    which: Stream,
    tx: mpsc::Sender<Chunk>,
    (mut halt, mut exited): Marks,
    counts: Arc<Counts>,
) {
    let mut esc = StreamEscaper::default();
    let mut buf = vec![0u8; sally_proto::MAX_OUTPUT_CHUNK];
    let counter = match which {
        Stream::Stdout => &counts.stdout,
        Stream::Stderr => &counts.stderr,
    };
    loop {
        let want = read_len(esc.held());
        let Some(space) = buf.get_mut(..want) else {
            return;
        };
        let idle = async {
            let _ = exited.wait_for(|e| *e).await;
            tokio::time::sleep(DRAIN_LIMIT).await;
        };
        let n = tokio::select! {
            biased;
            () = until(&mut halt) => return,
            r = r.read(space) => match r {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            },
            () = idle => break,
        };
        counter.fetch_add(u64::try_from(n).unwrap_or(u64::MAX), Ordering::Relaxed);
        let text = esc.push(buf.get(..n).unwrap_or_default());
        if !send(&tx, which, text, &mut halt).await {
            return;
        }
    }
    let rest = esc.finish();
    let _ = send(&tx, which, rest, &mut halt).await;
}

/// Queues `text` (nothing when empty), waiting for room; `false` once halted or the queue's
/// reader is gone.
pub async fn send(
    tx: &mpsc::Sender<Chunk>,
    stream: Stream,
    text: String,
    halt: &mut watch::Receiver<bool>,
) -> bool {
    if text.is_empty() {
        return true;
    }
    tokio::select! {
        biased;
        () = until(halt) => false,
        r = tx.send(Chunk { stream, text }) => r.is_ok(),
    }
}

/// Resolves once `w` is `true` or its sender is gone.
pub async fn until(w: &mut watch::Receiver<bool>) {
    let _ = w.wait_for(|v| *v).await;
}

/// Writes each input to the command's standard input in order and tells whether it was
/// written; closes the pipe after an input with `eof`. Once a write failed or the pipe was
/// closed, every later input is answered `false` (its connection says `input-closed`).
pub async fn write_input(
    w: impl AsyncWrite + Unpin + Send,
    mut rx: mpsc::Receiver<Input>,
    counts: Arc<Counts>,
) {
    let mut w = Some(w);
    while let Some(input) = rx.recv().await {
        let ok = match w.as_mut() {
            Some(pipe) => pipe.write_all(&input.data).await.is_ok() && pipe.flush().await.is_ok(),
            None => false,
        };
        if ok {
            let n = u64::try_from(input.data.len()).unwrap_or(u64::MAX);
            counts.stdin.fetch_add(n, Ordering::Relaxed);
        }
        if !ok || input.eof {
            w = None;
        }
        let _ = input.done.send(ok);
    }
}

#[cfg(test)]
#[path = "pipe_tests.rs"]
mod tests;
