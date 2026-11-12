//! The per-connection handler of the egress proxy. Its network effects go through the resolver,
//! dialer and host-address source it is built with (Task 8 decision 10), so every decision is
//! tested without containers; `net.rs` holds the real ones.
//!
//! Order (decision 3, architect Q1/Q8): admission, head, CONNECT only, authority, policy (host,
//! port, grant), the host's own addresses, one lookup, the address filter over every address,
//! `egress.allow`, connect to the pinned addresses in order, `200`, tunnel, `egress.close`. Every
//! refusal is audited before its reply; a failed audit append closes without a reply or a dial.

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use sally_core::audit::{Actor, NewEntry};
use sally_core::manifest::AuditLevel;
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Semaphore, watch};

use super::addr;
use super::authority::{self, Authority, AuthorityError, escape_target};
use super::head::{self, MAX_HEAD, Parsed};
use super::policy::{Policy, Reason};
use super::tunnel::{self, End, IDLE_LIMIT, Totals};
use crate::sandbox::AuditSink;

/// Time a client gets to send a complete request head (decision 8).
pub const HEAD_TIMEOUT: Duration = Duration::from_secs(10);
/// Time the one lookup of a name may take (decision 4).
pub const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);
/// Time each connect attempt may take (decision 4).
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Time a reply may take to write; a client that does not read is closed (architect Q10).
pub const REPLY_TIMEOUT: Duration = Duration::from_secs(2);
/// Pinned addresses tried at most, in the resolver's order (decision 4).
pub const MAX_DIALS: usize = 3;
/// Addresses kept from one lookup (all are filtered; architect Q9 bounds the audit entry).
pub const MAX_ADDRS: usize = 16;
/// Addresses one lookup may return at all (architect Q21). Checked on the raw answer, before
/// duplicates are dropped and before the filter: a longer answer is `resolve-failed`. Every one of
/// up to this many is filtered; only the first [`MAX_ADDRS`] distinct ones are kept.
pub const MAX_ANSWER: usize = 64;
/// Connections accepted past `max_connections` at one time, each only to be answered 429 (architect
/// Q20). Beyond the sum, the accept loop stops accepting until one ends.
// TODO(#48): raise RLIMIT_NOFILE and cap connections across sessions; one session at 1024 needs
// about 1088 + 1024 descriptors.
pub const ADMISSION_EXTRA: usize = 64;
/// The reply that opens a tunnel.
pub const ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
/// `filter` value of a refusal made because the host's own addresses could not be read.
pub const HOST_ADDRS_UNAVAILABLE: &str = "host-addresses-unavailable";

/// Looks a name up once. Only the addresses are used; their ports are ignored.
pub trait Resolver: Send + Sync + 'static {
    /// The addresses of `host`, in preference order.
    fn resolve(
        &self,
        host: &str,
        port: u16,
    ) -> impl Future<Output = io::Result<Vec<SocketAddr>>> + Send;
}

/// Opens the upstream connection to one pinned address.
pub trait Dialer: Send + Sync + 'static {
    /// The connected stream.
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;
    /// Connects to `addr` (never a name).
    fn dial(&self, addr: SocketAddr) -> impl Future<Output = io::Result<Self::Stream>> + Send;
}

/// The addresses this host itself owns (decision 5: refused like loopback).
pub trait HostAddrs: Send + Sync + 'static {
    /// The current list. An error refuses the connection (fail closed).
    fn own(&self) -> impl Future<Output = io::Result<Vec<IpAddr>>> + Send;
}

impl<T: Resolver> Resolver for Arc<T> {
    fn resolve(
        &self,
        host: &str,
        port: u16,
    ) -> impl Future<Output = io::Result<Vec<SocketAddr>>> + Send {
        (**self).resolve(host, port)
    }
}

impl<T: Dialer> Dialer for Arc<T> {
    type Stream = T::Stream;
    fn dial(&self, addr: SocketAddr) -> impl Future<Output = io::Result<Self::Stream>> + Send {
        (**self).dial(addr)
    }
}

impl<T: HostAddrs> HostAddrs for Arc<T> {
    fn own(&self) -> impl Future<Output = io::Result<Vec<IpAddr>>> + Send {
        (**self).own()
    }
}

/// Time and count limits of one session's proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// [`HEAD_TIMEOUT`].
    pub head: Duration,
    /// [`RESOLVE_TIMEOUT`].
    pub resolve: Duration,
    /// [`CONNECT_TIMEOUT`], per address.
    pub connect: Duration,
    /// [`IDLE_LIMIT`].
    pub idle: Duration,
    /// Live connections (the manifest's `network.max_connections`).
    pub max_connections: usize,
}

impl Limits {
    /// The documented limits, with the session's connection cap.
    #[must_use]
    pub fn new(max_connections: usize) -> Self {
        Self {
            head: HEAD_TIMEOUT,
            resolve: RESOLVE_TIMEOUT,
            connect: CONNECT_TIMEOUT,
            idle: IDLE_LIMIT,
            max_connections,
        }
    }

    /// Accepted connections in flight at most: the cap plus [`ADMISSION_EXTRA`], within what a
    /// semaphore can hold.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        permits(self.max_connections.saturating_add(ADMISSION_EXTRA))
    }
}

/// `n`, clamped to what a [`Semaphore`] can hold.
fn permits(n: usize) -> usize {
    n.min(Semaphore::MAX_PERMITS)
}

/// What the proxy intercepts grant hosts with (Task 9a): the session CA's leaves and the upstream
/// trust roots. It holds no secret store and no credential (architect Q27 (1)).
#[derive(Debug)]
pub struct Interception {
    /// The session CA and one leaf per grant host; the CA key is already gone.
    pub tls: super::ca::SessionTls,
    /// The upstream verifier's roots.
    pub roots: super::roots::Roots,
}

/// What a session's proxy is built from.
pub struct Parts<R, D, H> {
    /// The session's policy.
    pub policy: Policy,
    /// Name lookups.
    pub resolver: R,
    /// Upstream connections.
    pub dialer: D,
    /// The host's own addresses.
    pub host: H,
    /// The audit log.
    pub audit: Arc<dyn AuditSink>,
    /// The session id the entries carry.
    pub session: String,
    /// The session's audit level.
    pub level: AuditLevel,
    /// Limits.
    pub limits: Limits,
    /// The session CA and trust roots of a session with secret grants; `None` otherwise.
    // TODO(#45): Task 9a-2 serves grant hosts with it; until then they are refused.
    pub interception: Option<Interception>,
}

/// One session's proxy. Shared as `Arc<Proxy<…>>`; [`Proxy::serve`] runs once per accepted
/// stream, and [`Proxy::stop`] ends every connection (open tunnels with `session-stopped`).
pub struct Proxy<R, D, H> {
    policy: Policy,
    resolver: R,
    dialer: D,
    host: H,
    audit: Arc<dyn AuditSink>,
    session: String,
    level: AuditLevel,
    limits: Limits,
    interception: Option<Interception>,
    slots: Arc<Semaphore>,
    stop: watch::Sender<bool>,
}

/// What of a refused request goes into its audit entry.
#[derive(Clone, Copy)]
enum Seen<'a> {
    /// Nothing was read (admission).
    Nothing,
    /// A head that never became one: only its size.
    Bytes(usize),
    /// The request-target, escaped and cut.
    Target(&'a [u8]),
}

/// A refusal before anything was dialled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Refusal {
    reason: Reason,
    /// Which part of the address filter could not be evaluated, if that was why.
    filter: Option<&'static str>,
}

impl From<Reason> for Refusal {
    fn from(reason: Reason) -> Self {
        Self {
            reason,
            filter: None,
        }
    }
}

/// A request that passed every check: where it may go, and the bytes sent after its head.
struct Cleared {
    auth: Authority,
    pinned: Vec<SocketAddr>,
    rest: Vec<u8>,
}

impl<R: Resolver, D: Dialer, H: HostAddrs> Proxy<R, D, H> {
    /// A proxy.
    #[must_use]
    pub fn new(p: Parts<R, D, H>) -> Self {
        Self {
            slots: Arc::new(Semaphore::new(permits(p.limits.max_connections))),
            policy: p.policy,
            resolver: p.resolver,
            dialer: p.dialer,
            host: p.host,
            audit: p.audit,
            session: p.session,
            level: p.level,
            limits: p.limits,
            interception: p.interception,
            stop: watch::Sender::new(false),
        }
    }

    /// The session's limits.
    #[must_use]
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// The session CA and trust roots, for a session with secret grants.
    #[must_use]
    pub fn interception(&self) -> Option<&Interception> {
        self.interception.as_ref()
    }

    /// Ends every connection: those still being checked close without a reply, open tunnels
    /// end with `session-stopped`. Connections served after this close at once.
    pub fn stop(&self) {
        self.stop.send_replace(true);
    }

    /// Resolves once [`Proxy::stop`] was called.
    fn stopped(&self) -> impl Future<Output = ()> + Send + 'static {
        until_true(self.stop.subscribe())
    }

    /// Handles one client stream to its end. Client input never panics it; every refusal is
    /// audited before the connection closes.
    pub async fn serve<C: AsyncRead + AsyncWrite + Unpin + Send>(&self, mut client: C) {
        let Ok(_slot) = Arc::clone(&self.slots).try_acquire_owned() else {
            self.refuse(
                &mut client,
                Reason::TooManyConnections.into(),
                Seen::Nothing,
            )
            .await;
            return;
        };
        let cleared = tokio::select! {
            biased;
            () = self.stopped() => None,
            c = self.clear(&mut client) => c,
        };
        if let Some(c) = cleared {
            self.connect(client, c).await;
        }
    }

    /// Reads and checks the request; refuses it (audited, answered) or clears it.
    async fn clear<C: AsyncRead + AsyncWrite + Unpin>(&self, client: &mut C) -> Option<Cleared> {
        let mut buf = Box::new([0u8; MAX_HEAD]);
        let filled = match read_head(client, &mut buf, self.limits.head).await {
            Ok(n) => n,
            Err((reason, n)) => {
                self.refuse(client, reason.into(), Seen::Bytes(n)).await;
                return None;
            }
        };
        let window = buf.get(..filled).unwrap_or_default();
        let Parsed::Complete(h) = head::parse(window) else {
            self.refuse(client, Reason::Malformed.into(), Seen::Bytes(filled))
                .await;
            return None;
        };
        let target = Seen::Target(h.target.as_bytes());
        let checked = match authority::parse(h.target) {
            _ if !h.connect => Err(Reason::PlainHttpUnsupported.into()),
            Err(AuthorityError::IpLiteral) => Err(Reason::IpLiteral.into()),
            Err(AuthorityError::Malformed) => Err(Reason::Malformed.into()),
            Ok(auth) => self.check(&auth).await.map(|pinned| (auth, pinned)),
        };
        match checked {
            Ok((auth, pinned)) => Some(Cleared {
                auth,
                pinned,
                rest: window.get(h.len..).unwrap_or_default().to_vec(),
            }),
            Err(refusal) => {
                self.refuse(client, refusal, target).await;
                None
            }
        }
    }

    /// Policy, the host's own addresses, the one lookup, the address filter: the pinned
    /// addresses, in order.
    async fn check(&self, a: &Authority) -> Result<Vec<SocketAddr>, Refusal> {
        self.policy.decide(a)?;
        let own = self.host.own().await.map_err(|_| Refusal {
            reason: Reason::IpRangeDenied,
            filter: Some(HOST_ADDRS_UNAVAILABLE),
        })?;
        let lookup = self.resolver.resolve(&a.host, a.port);
        let found = match tokio::time::timeout(self.limits.resolve, lookup).await {
            Ok(Ok(found)) if !found.is_empty() && found.len() <= MAX_ANSWER => found,
            _ => return Err(Reason::ResolveFailed.into()),
        };
        if found.iter().any(|s| addr::is_denied(s.ip(), &own)) {
            return Err(Reason::IpRangeDenied.into());
        }
        Ok(pinned(&found, a.port))
    }

    /// `egress.allow`, then the connect attempts, the tunnel and `egress.close`.
    async fn connect<C: AsyncRead + AsyncWrite + Unpin + Send>(&self, mut client: C, c: Cleared) {
        let ips: Vec<String> = c.pinned.iter().map(|s| s.ip().to_string()).collect();
        let (host, port) = (&c.auth.host, c.auth.port);
        let allow = self
            .entry("egress.allow", Some("allow"))
            .args(json!({"host": host, "port": port, "addresses": ips}));
        if !self.append(allow).await {
            return;
        }
        let dialled = tokio::select! {
            biased;
            () = self.stopped() => Err(End::SessionStopped),
            d = self.dial(&c.pinned) => d.ok_or(End::ConnectFailed),
        };
        let (upstream, used) = match dialled {
            Ok(d) => d,
            Err(end) => {
                let none = Totals {
                    up: 0,
                    down: 0,
                    end,
                };
                if self.close(&c.auth, None, none).await && end == End::ConnectFailed {
                    write_reply(&mut client, Reason::ConnectFailed).await;
                }
                return;
            }
        };
        let totals = self.tunnel(client, upstream, &c.rest).await;
        // TODO(#49): log a close entry that could not be written.
        let _ = self.close(&c.auth, Some(used), totals).await;
    }

    /// `200`, the bytes sent after the head, then the tunnel.
    async fn tunnel<C, U>(&self, mut client: C, mut upstream: U, rest: &[u8]) -> Totals
    where
        C: AsyncRead + AsyncWrite + Unpin + Send,
        U: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let opened = async {
            client.write_all(ESTABLISHED).await?;
            upstream.write_all(rest).await
        };
        if !matches!(
            tokio::time::timeout(REPLY_TIMEOUT, opened).await,
            Ok(Ok(()))
        ) {
            return Totals {
                up: 0,
                down: 0,
                end: End::Error,
            };
        }
        let t = tunnel::run(client, upstream, self.limits.idle, self.stopped()).await;
        let sent = u64::try_from(rest.len()).unwrap_or(u64::MAX);
        Totals {
            up: t.up.saturating_add(sent),
            ..t
        }
    }

    /// Tries the first [`MAX_DIALS`] pinned addresses in order.
    async fn dial(&self, pinned: &[SocketAddr]) -> Option<(D::Stream, SocketAddr)> {
        for &to in pinned.iter().take(MAX_DIALS) {
            let attempt = tokio::time::timeout(self.limits.connect, self.dialer.dial(to));
            if let Ok(Ok(s)) = attempt.await {
                return Some((s, to));
            }
        }
        None
    }

    /// Appends `egress.close`; whether it was written.
    async fn close(&self, a: &Authority, used: Option<SocketAddr>, t: Totals) -> bool {
        self.append(
            self.entry("egress.close", None)
                .args(close_args(a, used, t)),
        )
        .await
    }

    /// Audits a refusal, then replies (except `head-timeout`, which closes) and closes. When the
    /// entry cannot be written the connection closes without a reply.
    async fn refuse<C: AsyncWrite + Unpin>(&self, client: &mut C, r: Refusal, seen: Seen<'_>) {
        let event = if r.reason.is_limit() {
            "egress.limit"
        } else {
            "egress.deny"
        };
        let entry = self.entry(event, Some("deny")).args(refusal_args(r, seen));
        if self.append(entry).await && r.reason != Reason::HeadTimeout {
            write_reply(client, r.reason).await;
        }
    }

    fn entry(&self, event: &str, decision: Option<&str>) -> NewEntry {
        let e = NewEntry::new(Actor::Sallyd, event).session(self.session.clone());
        match decision {
            Some(d) => e.decision(d),
            None => e,
        }
    }

    /// Appends off the runtime; whether the entry was written.
    async fn append(&self, entry: NewEntry) -> bool {
        let (sink, level) = (Arc::clone(&self.audit), self.level);
        matches!(
            tokio::task::spawn_blocking(move || sink.append(entry, level)).await,
            Ok(Ok(()))
        )
    }
}

/// Resolves once `rx` holds `true`, or its sender is gone. Owns its receiver, so the future is
/// `Send + 'static` and can be pinned before a `select!` loop.
pub(crate) async fn until_true(mut rx: watch::Receiver<bool>) {
    let _ = rx.wait_for(|s| *s).await.map(drop);
}

/// Writes the reply to `reason` within [`REPLY_TIMEOUT`], then closes the sending half.
async fn write_reply<C: AsyncWrite + Unpin>(client: &mut C, reason: Reason) {
    let send = async {
        client.write_all(reply(reason).as_bytes()).await?;
        client.shutdown().await
    };
    let _ = tokio::time::timeout(REPLY_TIMEOUT, send).await;
}

/// The first [`MAX_ADDRS`] distinct resolved addresses with the requested port, order kept.
fn pinned(found: &[SocketAddr], port: u16) -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = Vec::with_capacity(MAX_ADDRS);
    for s in found {
        let to = SocketAddr::new(s.ip(), port);
        if out.len() < MAX_ADDRS && !out.contains(&to) {
            out.push(to);
        }
    }
    out
}

/// Arguments of an `egress.deny` / `egress.limit` entry.
fn refusal_args(r: Refusal, seen: Seen<'_>) -> Value {
    let mut v = json!({"reason": r.reason.as_str()});
    if let Some(obj) = v.as_object_mut() {
        match seen {
            Seen::Nothing => {}
            Seen::Bytes(n) => {
                obj.insert("head_bytes".into(), json!(n));
            }
            Seen::Target(raw) => {
                let (target, bytes, cut) = escape_target(raw);
                obj.insert("target".into(), json!(target));
                obj.insert("target_bytes".into(), json!(bytes));
                obj.insert("target_cut".into(), json!(cut));
            }
        }
        if let Some(f) = r.filter {
            obj.insert("filter".into(), json!(f));
        }
    }
    v
}

/// Arguments of an `egress.close` entry: the address used (or `connected: false`), the byte
/// counts and how it ended.
fn close_args(a: &Authority, used: Option<SocketAddr>, t: Totals) -> Value {
    let mut v = json!({
        "host": a.host,
        "port": a.port,
        "connected": used.is_some(),
        "bytes_up": t.up,
        "bytes_down": t.down,
        "end": t.end.as_str(),
    });
    if let (Some(obj), Some(used)) = (v.as_object_mut(), used) {
        obj.insert("address".into(), json!(used.ip().to_string()));
    }
    v
}

/// The reply to a refused request: status, the reason code as the body, `Connection: close`.
/// The target is never echoed.
#[must_use]
pub(crate) fn reply(reason: Reason) -> String {
    let code = reason.as_str();
    let allow = if reason == Reason::PlainHttpUnsupported {
        "Allow: CONNECT\r\n"
    } else {
        ""
    };
    format!(
        "HTTP/1.1 {} {}\r\n{allow}Content-Type: text/plain\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{code}\n",
        reason.status(),
        phrase(reason.status()),
        code.len() + 1,
    )
}

fn phrase(status: u16) -> &'static str {
    match status {
        400 => "Bad Request",
        403 => "Forbidden",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        502 => "Bad Gateway",
        _ => "Error",
    }
}

/// Reads a request head from `client` into `buf`, within `limit`. Returns how many bytes of `buf`
/// are filled: the complete head, plus any bytes the client sent after it (they belong to the
/// tunnel).
///
/// # Errors
/// The reason and the bytes received: [`Reason::HeadTooLarge`] past 8 KiB, 100 header lines or
/// [`MAX_PARSES`] parses,
/// [`Reason::HeadTimeout`] when `limit` passes first, [`Reason::Malformed`] for a head that is not
/// HTTP/1.x or a client that closes or fails before completing one.
pub(crate) async fn read_head<S: AsyncRead + Unpin>(
    client: &mut S,
    buf: &mut [u8; MAX_HEAD],
    limit: Duration,
) -> Result<usize, (Reason, usize)> {
    let mut filled = 0;
    let reading = async {
        let (mut fresh, mut parses) = (0..0, 0);
        loop {
            let window = buf.get(..filled).unwrap_or_default();
            if worth_parsing(window, &fresh) {
                parses += 1;
                if parses > MAX_PARSES {
                    return Err(Reason::HeadTooLarge);
                }
                match head::parse(window) {
                    Parsed::Complete(_) => return Ok(()),
                    Parsed::TooLarge => return Err(Reason::HeadTooLarge),
                    Parsed::Malformed => return Err(Reason::Malformed),
                    Parsed::Partial => {}
                }
            }
            let free = buf.get_mut(filled..).ok_or(Reason::HeadTooLarge)?;
            let n = client.read(free).await.map_err(|_| Reason::Malformed)?;
            if n == 0 {
                return Err(Reason::Malformed);
            }
            fresh = filled..filled + n;
            filled += n;
        }
    };
    let got = tokio::time::timeout(limit, reading)
        .await
        .unwrap_or(Err(Reason::HeadTimeout));
    got.map(|()| filled).map_err(|r| (r, filled))
}

/// Parses of one request head at most (Rust review M2). The head is parsed after the first read,
/// after a read that brought a line end, and when the buffer is full, so parsing costs at most
/// this many passes over 8 KiB, not one per byte. A head has at most 102 lines (request line, 100
/// headers, blank line); a client that needs more parses than this is refused as too large.
pub const MAX_PARSES: usize = 128;

/// Whether the head in `window` could have changed state with the bytes at `fresh`: the first
/// read (garbage is refused at once), a read with a line end (the head may now be complete), or
/// a full buffer (it is now too large). Bytes in the middle of a line change nothing.
fn worth_parsing(window: &[u8], fresh: &std::ops::Range<usize>) -> bool {
    let first = fresh.start == 0;
    let full = window.len() >= MAX_HEAD;
    first
        || full
        || window
            .get(fresh.clone())
            .is_some_and(|b| b.contains(&b'\n'))
}

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;
