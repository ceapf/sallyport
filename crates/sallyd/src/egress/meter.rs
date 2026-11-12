//! Byte meters and capped bodies of an intercepted tunnel (Task 9a-2).
//!
//! [`Meter`] wraps a stream: it counts what was read and written and marks activity for the
//! idle limit, and it first replays bytes the client sent after its CONNECT head (they belong to
//! the TLS handshake). [`Capped`] wraps a message body: it forwards data frames, drops trailers
//! (architect Q41), counts payload bytes against a cap (Q49) and reports how the body ended.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, ready};

use hyper::body::{Body, Bytes, Frame, SizeHint};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::tunnel::Activity;

/// Error type of the bodies the proxy forwards.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Counters a [`Meter`] adds to.
#[derive(Debug, Clone, Default)]
pub struct Counts {
    /// Bytes read from the wrapped stream (replayed bytes included).
    pub read: Arc<AtomicU64>,
    /// Bytes written to the wrapped stream.
    pub written: Arc<AtomicU64>,
}

impl Counts {
    /// Bytes read so far.
    #[must_use]
    pub fn read(&self) -> u64 {
        self.read.load(Ordering::Relaxed)
    }

    /// Bytes written so far.
    #[must_use]
    pub fn written(&self) -> u64 {
        self.written.load(Ordering::Relaxed)
    }
}

/// A stream that counts its bytes, touches an [`Activity`], and reads `replay` first.
pub struct Meter<S> {
    inner: S,
    replay: Vec<u8>,
    at: usize,
    counts: Counts,
    act: Option<Arc<Activity>>,
    max_read: Option<usize>,
}

impl<S> Meter<S> {
    /// Wraps `inner`; `replay` is read before anything from `inner`.
    pub fn new(inner: S, replay: Vec<u8>, counts: Counts, act: Option<Arc<Activity>>) -> Self {
        Self {
            inner,
            replay,
            at: 0,
            counts,
            act,
            max_read: None,
        }
    }

    /// Hands at most `n` bytes (at least one) to each read. Defense in depth: hyper 1.12 checks
    /// its head-size limit on complete heads too, so this is not what bounds a head; should a
    /// hyper version check only partial heads, it bounds how far one read can carry a head past
    /// that limit (architect, Task 9a-2 part 2).
    #[must_use]
    pub fn max_read(self, n: usize) -> Self {
        Self {
            max_read: Some(n.max(1)),
            ..self
        }
    }

    /// Counts `n` bytes and marks activity (an end-of-stream read counts nothing, and marking it
    /// as activity only moves the idle clock for a stream that is ending anyway).
    fn moved(&self, counter: &AtomicU64, n: usize) {
        counter.fetch_add(u64::try_from(n).unwrap_or(u64::MAX), Ordering::Relaxed);
        if let Some(a) = &self.act {
            a.touch();
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Meter<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let pending = this.replay.get(this.at..).unwrap_or_default();
        if !pending.is_empty() {
            let n = pending.len().min(buf.remaining());
            buf.put_slice(pending.get(..n).unwrap_or_default());
            this.at = this.at.saturating_add(n);
            this.moved(&this.counts.read, n);
            return Poll::Ready(Ok(()));
        }
        let n = match this.max_read {
            Some(max) => {
                let take = buf.remaining().min(max);
                let mut part = ReadBuf::new(buf.initialize_unfilled_to(take));
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut part))?;
                let n = part.filled().len();
                buf.advance(n);
                n
            }
            None => {
                let before = buf.filled().len();
                ready!(Pin::new(&mut this.inner).poll_read(cx, buf))?;
                buf.filled().len().saturating_sub(before)
            }
        };
        this.moved(&this.counts.read, n);
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Meter<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let n = ready!(Pin::new(&mut this.inner).poll_write(cx, data))?;
        this.moved(&this.counts.written, n);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// How a [`Capped`] body ended, for the one who built it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyEnd {
    /// Every data frame was forwarded.
    Complete,
    /// The payload went past the cap; the body stopped with an error (a cut).
    OverCap,
    /// The inner body failed (for a response: the upstream closed mid-body).
    Failed,
}

/// Called once when a [`Capped`] body ends, or is dropped before it ended (as `None`). For
/// [`BodyEnd::OverCap`] it returns a future that must finish before the cut (the audit entry).
pub trait OnEnd: Send + Sync + 'static {
    /// The body ended. The returned future, if any, runs before the body reports its error.
    fn ended(&self, how: Option<BodyEnd>) -> Option<Pin<Box<dyn Future<Output = ()> + Send>>>;
}

/// A body forwarded with a payload cap. Trailers are never forwarded.
pub struct Capped<B> {
    inner: B,
    cap: u64,
    seen: u64,
    on_end: Arc<dyn OnEnd>,
    reported: bool,
    before_cut: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
}

impl<B> Capped<B> {
    /// Wraps `inner`; at most `cap` payload bytes pass (at the cap passes, one more is a cut).
    pub fn new(inner: B, cap: u64, on_end: Arc<dyn OnEnd>) -> Self {
        Self {
            inner,
            cap,
            seen: 0,
            on_end,
            reported: false,
            before_cut: None,
        }
    }

    /// Payload bytes forwarded so far.
    #[must_use]
    pub fn seen(&self) -> u64 {
        self.seen
    }

    fn report(&mut self, how: BodyEnd) -> Option<Pin<Box<dyn Future<Output = ()> + Send>>> {
        if self.reported {
            return None;
        }
        self.reported = true;
        self.on_end.ended(Some(how))
    }
}

impl<B> Drop for Capped<B> {
    fn drop(&mut self) {
        if !self.reported {
            self.reported = true;
            drop(self.on_end.ended(None));
        }
    }
}

/// The error a [`Capped`] body stops with past its cap.
#[derive(Debug, thiserror::Error)]
#[error("body over its cap")]
pub struct OverCap;

impl<B> Body for Capped<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = self.get_mut();
        if let Some(f) = this.before_cut.as_mut() {
            ready!(f.as_mut().poll(cx));
            this.before_cut = None;
            return Poll::Ready(Some(Err(Box::new(OverCap))));
        }
        loop {
            match ready!(Pin::new(&mut this.inner).poll_frame(cx)) {
                None => {
                    drop(this.report(BodyEnd::Complete));
                    return Poll::Ready(None);
                }
                Some(Err(e)) => {
                    drop(this.report(BodyEnd::Failed));
                    return Poll::Ready(Some(Err(e.into())));
                }
                Some(Ok(frame)) => {
                    let Ok(data) = frame.into_data() else {
                        continue; // trailers are dropped
                    };
                    let n = u64::try_from(data.len()).unwrap_or(u64::MAX);
                    this.seen = this.seen.saturating_add(n);
                    if this.seen > this.cap {
                        return match this.report(BodyEnd::OverCap) {
                            Some(f) => {
                                this.before_cut = Some(f);
                                Pin::new(this).poll_frame(cx)
                            }
                            None => Poll::Ready(Some(Err(Box::new(OverCap)))),
                        };
                    }
                    return Poll::Ready(Some(Ok(Frame::data(data))));
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.before_cut.is_none() && self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
#[path = "meter_tests.rs"]
mod tests;
