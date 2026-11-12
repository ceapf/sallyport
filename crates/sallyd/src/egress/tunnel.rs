//! The tunnel after `200 Connection Established` (decision 7): bytes copied both ways through one
//! fixed buffer per direction, half-close propagated, byte counters, and one idle limit shared by
//! both directions (the tunnel is idle when neither side moved a byte for that long).

use std::future::Future;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

/// Bytes per direction a tunnel buffers at most: the shim's size. At the manifest's largest
/// `max_connections` (1024) two of them per tunnel stay near 32 MiB (architect ruling Q12).
pub const BUF_BYTES: usize = 16 * 1024;
/// How long a tunnel may carry nothing in either direction before the proxy closes it.
pub const IDLE_LIMIT: Duration = Duration::from_secs(300);

/// How a tunnel ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum End {
    /// Both sides closed their sending half.
    Closed,
    /// Neither side sent anything within the idle limit.
    IdleTimeout,
    /// A read or write failed on either side.
    Error,
    /// The session stopped while the tunnel was open.
    SessionStopped,
    /// No pinned address accepted the connection; there was no tunnel.
    ConnectFailed,
    /// Intercepted: the upstream TLS handshake or verification failed (before the `200`).
    UpstreamTlsFailed,
    /// Intercepted: the client's TLS handshake failed or timed out.
    ClientTlsFailed,
    /// Intercepted: a request was refused (`egress.deny`).
    Refused,
    /// Intercepted: a limit ended the tunnel (`egress.limit`).
    Limit,
    /// Intercepted: the upstream closed during an exchange.
    UpstreamClosed,
}

impl End {
    /// The audit form (`egress.close` `end`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::IdleTimeout => "idle-timeout",
            Self::Error => "error",
            Self::SessionStopped => "session-stopped",
            Self::ConnectFailed => "connect-failed",
            Self::UpstreamTlsFailed => "upstream-tls-failed",
            Self::ClientTlsFailed => "client-tls-failed",
            Self::Refused => "refused",
            Self::Limit => "limit",
            Self::UpstreamClosed => "upstream-closed",
        }
    }
}

impl Default for Activity {
    fn default() -> Self {
        Self::new()
    }
}

/// What a tunnel carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Totals {
    /// Bytes from the client to the upstream.
    pub up: u64,
    /// Bytes from the upstream to the client.
    pub down: u64,
    /// How it ended.
    pub end: End,
}

/// The time of the last byte moved in either direction, as milliseconds since `start`.
#[derive(Debug)]
pub struct Activity {
    start: Instant,
    last_ms: AtomicU64,
}

impl Activity {
    /// Activity starting now.
    #[must_use]
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
            last_ms: AtomicU64::new(0),
        }
    }

    /// A byte moved now.
    pub fn touch(&self) {
        let ms = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_ms.fetch_max(ms, Ordering::Relaxed);
    }

    /// When the last byte moved.
    #[must_use]
    pub fn last(&self) -> Instant {
        self.start + Duration::from_millis(self.last_ms.load(Ordering::Relaxed))
    }
}

/// Copies `r` to `w` until `r` ends, then closes `w`'s sending half. Counts what was written.
async fn pump<R, W>(mut r: R, mut w: W, count: &AtomicU64, act: &Activity) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; BUF_BYTES];
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            return w.shutdown().await;
        }
        // Activity twice: when bytes arrive, and when a write that waited on a slow reader
        // completes, so a long blocked write is not mistaken for an idle tunnel.
        act.touch();
        w.write_all(buf.get(..n).unwrap_or_default()).await?;
        count.fetch_add(u64::try_from(n).unwrap_or(u64::MAX), Ordering::Relaxed);
        act.touch();
    }
}

/// Resolves once `idle` passed since the last byte moved.
async fn idle_out(act: &Activity, idle: Duration) {
    loop {
        let deadline = act.last() + idle;
        if Instant::now() >= deadline {
            return;
        }
        tokio::time::sleep_until(deadline).await;
    }
}

/// Runs the tunnel between `client` and `upstream` until both directions finished, either side
/// failed, nothing moved for `idle`, or `stop` resolved.
pub(crate) async fn run<C, U>(
    client: C,
    upstream: U,
    idle: Duration,
    stop: impl Future<Output = ()>,
) -> Totals
where
    C: AsyncRead + AsyncWrite,
    U: AsyncRead + AsyncWrite,
{
    let (cr, cw) = tokio::io::split(client);
    let (ur, uw) = tokio::io::split(upstream);
    let (up, down) = (AtomicU64::new(0), AtomicU64::new(0));
    let act = Activity::new();
    let both = async {
        tokio::try_join!(pump(cr, uw, &up, &act), pump(ur, cw, &down, &act))
            .map_or(End::Error, |_| End::Closed)
    };
    let end = tokio::select! {
        end = both => end,
        () = idle_out(&act, idle) => End::IdleTimeout,
        () = stop => End::SessionStopped,
    };
    Totals {
        up: up.load(Ordering::Relaxed),
        down: down.load(Ordering::Relaxed),
        end,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::future::pending;
    use tokio::io::duplex;

    #[tokio::test]
    async fn stopping_the_session_ends_an_open_tunnel_with_its_counts() {
        let (mut client, proxy_c) = duplex(64);
        let (proxy_u, mut upstream) = duplex(64);
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let tunnel = tokio::spawn(run(proxy_c, proxy_u, IDLE_LIMIT, async {
            let _ = rx.await;
        }));
        client.write_all(b"abc").await.unwrap();
        let mut got = [0u8; 3];
        upstream.read_exact(&mut got).await.unwrap();
        tx.send(()).unwrap();
        let t = tunnel.await.unwrap();
        assert_eq!(
            t,
            Totals {
                up: 3,
                down: 0,
                end: End::SessionStopped
            }
        );
    }

    #[tokio::test]
    async fn bytes_flow_both_ways_and_half_close_propagates() {
        let (mut client, proxy_c) = duplex(1024);
        let (proxy_u, mut upstream) = duplex(1024);
        let tunnel = tokio::spawn(run(proxy_c, proxy_u, IDLE_LIMIT, pending()));
        client.write_all(b"hello").await.unwrap();
        client.shutdown().await.unwrap();
        let mut got = Vec::new();
        upstream.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"hello");
        upstream.write_all(b"world!").await.unwrap();
        upstream.shutdown().await.unwrap();
        let mut back = Vec::new();
        client.read_to_end(&mut back).await.unwrap();
        assert_eq!(back, b"world!");
        let t = tunnel.await.unwrap();
        assert_eq!(
            t,
            Totals {
                up: 5,
                down: 6,
                end: End::Closed
            }
        );
    }

    #[tokio::test]
    async fn more_than_one_buffer_is_carried_whole() {
        let (mut client, proxy_c) = duplex(BUF_BYTES * 4);
        let (proxy_u, mut upstream) = duplex(BUF_BYTES * 4);
        let tunnel = tokio::spawn(run(proxy_c, proxy_u, IDLE_LIMIT, pending()));
        let body: Vec<u8> = (0..BUF_BYTES * 3 + 7).map(|i| (i % 251) as u8).collect();
        let sent = body.clone();
        let writer = tokio::spawn(async move {
            client.write_all(&sent).await.unwrap();
            client.shutdown().await.unwrap();
            client
        });
        let mut got = Vec::new();
        upstream.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, body);
        drop(upstream);
        let _client = writer.await.unwrap();
        let t = tunnel.await.unwrap();
        assert_eq!(t.up, u64::try_from(body.len()).unwrap());
        assert_eq!(t.down, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_tunnel_idle_in_both_directions_is_closed_at_the_limit() {
        let (_client, proxy_c) = duplex(64);
        let (proxy_u, _upstream) = duplex(64);
        let started = Instant::now();
        let t = run(proxy_c, proxy_u, IDLE_LIMIT, pending()).await;
        assert_eq!(t.end, End::IdleTimeout);
        assert_eq!(started.elapsed(), IDLE_LIMIT);
    }

    #[tokio::test(start_paused = true)]
    async fn traffic_in_one_direction_keeps_the_whole_tunnel_alive() {
        let (_client, proxy_c) = duplex(64);
        let (proxy_u, mut upstream) = duplex(64);
        let started = Instant::now();
        let tunnel = tokio::spawn(run(proxy_c, proxy_u, IDLE_LIMIT, pending()));
        let feeder = tokio::spawn(async move {
            for _ in 0..3 {
                tokio::time::sleep(IDLE_LIMIT - Duration::from_secs(1)).await;
                upstream.write_all(b"x").await.unwrap();
            }
            upstream
        });
        let t = tunnel.await.unwrap();
        let _upstream = feeder.await.unwrap();
        assert_eq!(t.end, End::IdleTimeout);
        assert_eq!(t.down, 3);
        assert!(
            started.elapsed() >= IDLE_LIMIT * 3,
            "{:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn a_failing_side_ends_the_tunnel_as_an_error() {
        struct Broken;
        impl AsyncRead for Broken {
            fn poll_read(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
                _: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<io::Result<()>> {
                std::task::Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()))
            }
        }
        impl AsyncWrite for Broken {
            fn poll_write(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
                _: &[u8],
            ) -> std::task::Poll<io::Result<usize>> {
                std::task::Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()))
            }
            fn poll_flush(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
            ) -> std::task::Poll<io::Result<()>> {
                std::task::Poll::Ready(Ok(()))
            }
            fn poll_shutdown(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
            ) -> std::task::Poll<io::Result<()>> {
                std::task::Poll::Ready(Ok(()))
            }
        }
        let (_client, proxy_c) = duplex(64);
        let t = run(proxy_c, Broken, IDLE_LIMIT, pending()).await;
        assert_eq!(t.end, End::Error);
    }

    #[test]
    fn ends_have_their_audit_form_and_the_limits_are_pinned() {
        assert_eq!(End::Closed.as_str(), "closed");
        assert_eq!(End::IdleTimeout.as_str(), "idle-timeout");
        assert_eq!(End::Error.as_str(), "error");
        assert_eq!(End::SessionStopped.as_str(), "session-stopped");
        assert_eq!(End::ConnectFailed.as_str(), "connect-failed");
        assert_eq!(End::UpstreamTlsFailed.as_str(), "upstream-tls-failed");
        assert_eq!(End::ClientTlsFailed.as_str(), "client-tls-failed");
        assert_eq!(End::Refused.as_str(), "refused");
        assert_eq!(End::Limit.as_str(), "limit");
        assert_eq!(End::UpstreamClosed.as_str(), "upstream-closed");
        assert_eq!(BUF_BYTES, 16_384);
        assert_eq!(IDLE_LIMIT, Duration::from_secs(300));
    }
}
