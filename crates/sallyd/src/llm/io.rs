//! The stream hyper serves on `llm.sock`. It replays the bytes the broker already read (the head
//! it checked, and whatever arrived with it), then reads the peer. Its writes are gated: until
//! the request has its audit entry, whatever hyper writes is dropped (hyper answers some bad
//! requests by itself: `probe_tests.rs`), so no reply ever precedes its entry. A write the peer
//! does not take within the stall limit fails the connection.

use std::future::Future as _;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Sleep;

/// Opened once the request's entry is written; shared with the service.
#[derive(Debug, Clone, Default)]
pub struct Gate(Arc<AtomicBool>);

impl Gate {
    /// Lets writes through from now on.
    pub fn open(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// Whether writes go through.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// `inner`, after `prefix`, with gated and time-limited writes.
pub struct Io<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
    gate: Gate,
    stall: Duration,
    stalled: Option<Pin<Box<Sleep>>>,
}

impl<S> Io<S> {
    /// Wraps `inner`; `prefix` is read first.
    pub fn new(prefix: Vec<u8>, inner: S, gate: Gate, stall: Duration) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
            gate,
            stall,
            stalled: None,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Io<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        let rest = me.prefix.get(me.pos..).unwrap_or_default();
        if rest.is_empty() {
            return Pin::new(&mut me.inner).poll_read(cx, buf);
        }
        let n = rest.len().min(buf.remaining());
        buf.put_slice(rest.get(..n).unwrap_or_default());
        me.pos = me.pos.saturating_add(n);
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> Io<S> {
    /// Fails the write once it has been pending for the stall limit.
    fn pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Error> {
        let stall = self.stall;
        let sleep = self
            .stalled
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(stall)));
        sleep
            .as_mut()
            .poll(cx)
            .map(|()| io::Error::from(io::ErrorKind::TimedOut))
    }

    fn settle<T>(&mut self, cx: &mut Context<'_>, r: Poll<io::Result<T>>) -> Poll<io::Result<T>> {
        match r {
            Poll::Pending => self.pending(cx).map(Err),
            ready => {
                self.stalled = None;
                ready
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Io<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        if !me.gate.is_open() {
            return Poll::Ready(Ok(buf.len()));
        }
        let r = Pin::new(&mut me.inner).poll_write(cx, buf);
        me.settle(cx, r)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        let r = Pin::new(&mut me.inner).poll_flush(cx);
        me.settle(cx, r)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        let r = Pin::new(&mut me.inner).poll_shutdown(cx);
        me.settle(cx, r)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn the_prefix_is_read_before_the_stream() {
        let (mut peer, inner) = tokio::io::duplex(64);
        peer.write_all(b"rest").await.unwrap();
        drop(peer);
        let mut io = Io::new(
            b"head:".to_vec(),
            inner,
            Gate::default(),
            Duration::from_secs(1),
        );
        let mut out = String::new();
        io.read_to_string(&mut out).await.unwrap();
        assert_eq!(out, "head:rest");
    }

    #[tokio::test]
    async fn a_small_buffer_reads_the_prefix_in_parts() {
        let (peer, inner) = tokio::io::duplex(64);
        drop(peer);
        let mut io = Io::new(
            b"abcde".to_vec(),
            inner,
            Gate::default(),
            Duration::from_secs(1),
        );
        let mut b = [0u8; 2];
        let mut got = Vec::new();
        loop {
            let n = io.read(&mut b).await.unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&b[..n]);
        }
        assert_eq!(got, b"abcde");
    }

    #[tokio::test]
    async fn writes_are_dropped_until_the_gate_opens() {
        let (mut peer, inner) = tokio::io::duplex(64);
        let gate = Gate::default();
        let mut io = Io::new(Vec::new(), inner, gate.clone(), Duration::from_secs(1));
        io.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            .await
            .unwrap();
        gate.open();
        io.write_all(b"ok").await.unwrap();
        io.shutdown().await.unwrap();
        let mut out = Vec::new();
        peer.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"ok");
    }

    #[tokio::test]
    async fn a_flush_reaches_the_inner_stream() {
        let (mut peer, inner) = tokio::io::duplex(64);
        let gate = Gate::default();
        gate.open();
        let buffered = tokio::io::BufWriter::new(inner);
        let mut io = Io::new(Vec::new(), buffered, gate, Duration::from_secs(1));
        io.write_all(b"ok").await.unwrap();
        io.flush().await.unwrap();
        let mut b = [0u8; 2];
        tokio::time::timeout(Duration::from_secs(5), peer.read_exact(&mut b))
            .await
            .expect("the flush stayed in the buffer")
            .unwrap();
        assert_eq!(&b, b"ok");
    }

    #[tokio::test(start_paused = true)]
    async fn a_write_the_peer_never_takes_times_out() {
        let (_peer, inner) = tokio::io::duplex(8);
        let gate = Gate::default();
        gate.open();
        let mut io = Io::new(Vec::new(), inner, gate, Duration::from_secs(3));
        let started = tokio::time::Instant::now();
        let e = io.write_all(&[0u8; 64]).await.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        assert_eq!(started.elapsed(), Duration::from_secs(3));
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_but_moving_reader_resets_the_limit() {
        let (mut peer, inner) = tokio::io::duplex(8);
        let gate = Gate::default();
        gate.open();
        let mut io = Io::new(Vec::new(), inner, gate, Duration::from_secs(3));
        let reader = tokio::spawn(async move {
            let mut b = [0u8; 8];
            let mut total = 0;
            while total < 64 {
                tokio::time::sleep(Duration::from_secs(2)).await;
                total += peer.read(&mut b).await.unwrap();
            }
            total
        });
        io.write_all(&[0u8; 64]).await.unwrap();
        assert_eq!(reader.await.unwrap(), 64);
    }
}
