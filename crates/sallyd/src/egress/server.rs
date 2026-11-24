//! The per-connection handler of the egress proxy. Its network effects go through the resolver,
//! dialer and host-address source it is built with (Task 8 decision 10), so every decision is
//! tested without containers; `net.rs` holds the real ones.
//!
//! Order (decision 3, architect Q1/Q8): admission (the in-flight slot and the admission rate, in
//! `net.rs`; a connection over the rate is closed unread and only counted), head, CONNECT only,
//! authority, policy (host, port, grant), the host's own addresses and connected networks,
//! `egress.resolve`, one lookup, the address filter over every address, `egress.allow`, connect
//! to the pinned addresses in order, `200`, tunnel, `egress.close`. Every refusal is audited
//! before its reply; a failed audit append closes without a reply, a lookup or a dial.
//!
//! Latch (RT-AUD-04): once any append of the session has failed, egress stays closed. Every
//! later connection is closed unread, without a reply, after one best-effort `egress.deny`
//! (`audit-failed`), and no entry that would permit an effect (`egress.resolve`, `egress.allow`,
//! an in-tunnel `egress.request`) is written: no lookup, dial or forwarded request follows.

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use sally_core::audit::{Actor, NewEntry, Redactor};
use sally_core::manifest::AuditLevel;
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Semaphore, watch};

use super::addr::{self, HostNets, Rule};
use super::authority::{self, Authority, AuthorityError};
use super::head::{self, MAX_HEAD, Parsed};
use super::hostaddrs::HostAddrsError;
use super::policy::{Policy, Reason, Route};
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
/// After a reply, the proxy reads and discards what the client still sends, at most this many
/// bytes, before it closes (#71): closing on a client still sending failed the client's send,
/// and the shim then tore down its TCP side before the reply was relayed.
pub const DRAIN_BYTES: u64 = 256 * 1024;
/// ... and for at most this long.
pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(1);
/// Pinned addresses tried at most, in the resolver's order (decision 4).
pub const MAX_DIALS: usize = 3;
/// Addresses kept from one lookup (all are filtered; architect Q9 bounds the audit entry).
pub const MAX_ADDRS: usize = 16;
/// Addresses one lookup may return at all (architect Q21). Checked on the raw answer, before
/// duplicates are dropped and before the filter: a longer answer is `resolve-failed`. Every one of
/// up to this many is filtered; only the first [`MAX_ADDRS`] distinct ones are kept.
pub const MAX_ANSWER: usize = 64;
/// Connections accepted past `max_connections` at one time, each only to be answered 429 (architect
/// Q20). Beyond the sum, the accept loop stops accepting until one ends. Descriptors across
/// sessions are bounded at the daemon: `daemon::process::raise_nofile` raises `RLIMIT_NOFILE`
/// (`daemon::startup::nofile_target`) at start, and a launch is admitted only while its
/// `sandbox::budget::session_cost`, added to the live sessions', fits half of it
/// (`sandbox::budget::session_budget`, `sandbox::budget::admit`).
pub const ADMISSION_EXTRA: usize = 64;
/// Connections a session's `net.sock` admits per second on average (`net.rs`); the ones over the
/// rate are closed unread and counted in `egress.shed`. The same figures as `agent.sock`'s request
/// rate, by choice.
// TODO(#228): requests inside an admitted intercepted tunnel each have their entries and are not
// held by this rate.
pub const ADMISSION_RATE: u32 = 20;
/// Connections a session's `net.sock` admits back to back before [`ADMISSION_RATE`] applies; at
/// least the manifest's default `max_connections`, so a session can fill its cap in one burst.
pub const ADMISSION_BURST: u32 = 40;
/// The reply that opens a tunnel.
pub const ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
/// `filter` value of a refusal made because the host's own addresses and connected networks
/// could not be read.
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

/// The addresses this host itself owns and the networks it is directly connected to (decision
/// 5: refused like loopback).
pub trait HostAddrs: Send + Sync + 'static {
    /// The current tables. An error refuses the connection (fail closed).
    fn own(&self) -> impl Future<Output = Result<HostNets, HostAddrsError>> + Send;
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
    fn own(&self) -> impl Future<Output = Result<HostNets, HostAddrsError>> + Send {
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
    /// Body bytes of one intercepted request at most (`network.max_request_bytes`).
    pub max_request: u64,
    /// Body bytes of one intercepted response at most (`network.max_response_bytes`).
    pub max_response: u64,
    /// [`ADMISSION_RATE`].
    pub admission_rate: u32,
    /// [`ADMISSION_BURST`].
    pub admission_burst: u32,
}

impl Limits {
    /// The documented limits, with the session's connection cap and the manifest's default
    /// body caps.
    #[must_use]
    pub fn new(max_connections: usize) -> Self {
        Self::documented(max_connections)
    }

    /// [`Self::new`]'s work, in a function cargo-mutants mutates (it leaves `new` alone; #87).
    fn documented(max_connections: usize) -> Self {
        let net = sally_core::manifest::Network::default();
        Self {
            head: HEAD_TIMEOUT,
            resolve: RESOLVE_TIMEOUT,
            connect: CONNECT_TIMEOUT,
            idle: IDLE_LIMIT,
            max_connections,
            max_request: net.max_request_bytes.bytes(),
            max_response: net.max_response_bytes.bytes(),
            admission_rate: ADMISSION_RATE,
            admission_burst: ADMISSION_BURST,
        }
    }

    /// A session's limits: the documented ones with its connection cap and its own body caps
    /// `(max_request, max_response)` (`network.max_request_bytes`, `max_response_bytes`).
    #[must_use]
    pub fn of_session(max_connections: usize, body_caps: (u64, u64)) -> Self {
        Self {
            max_request: body_caps.0,
            max_response: body_caps.1,
            ..Self::documented(max_connections)
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

#[path = "intercept.rs"]
mod intercept;
#[path = "intercept_tls.rs"]
mod intercept_tls;
/// The `egress.request` builder, for RT-SEC-15 (`session/cross_session_tests.rs`).
#[cfg(test)]
pub(crate) use intercept::request_entry;
pub use intercept::{MAX_REQUEST_HEAD, MAX_RESPONSE_HEAD, Summary, upstream_builder};
pub use intercept_tls::{Interception, trusting, upstream_client};

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
    /// The session CA and trust roots of a session with secret grants; `None` otherwise (grant
    /// hosts are then refused `grant-host-unavailable`).
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
    /// Set by the first append that fails; never cleared (RT-AUD-04).
    latch: Arc<AtomicBool>,
}

/// The `reason` of the `egress.deny` of a connection closed by the latch.
const AUDIT_FAILED: &str = "audit-failed";

/// Why a request was not cleared: refused (audited, answered), or closed without a reply
/// because the entry that must precede its lookup was not written.
enum Stop {
    Refused(Refusal),
    Closed,
}

impl From<Refusal> for Stop {
    fn from(r: Refusal) -> Self {
        Self::Refused(r)
    }
}

impl From<Reason> for Stop {
    fn from(reason: Reason) -> Self {
        Self::Refused(reason.into())
    }
}

/// What of a refused request goes into its audit entry.
#[derive(Clone, Copy)]
enum Seen<'a> {
    /// Nothing was read (admission).
    Nothing,
    /// A head that never became one: only its size.
    Bytes(usize),
    /// The request-target, declared by [`authority::with_target`].
    Target(&'a str),
}

/// A refusal before anything was dialled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Refusal {
    reason: Reason,
    detail: Detail,
}

/// What the address filter adds to a refusal's entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Detail {
    /// Nothing beyond the reason.
    Plain,
    /// The host's tables could not be read or understood, and why.
    Unavailable(HostAddrsError),
    /// The first resolved address the filter refused, and the rule it met.
    Denied(IpAddr, Rule),
}

impl From<Reason> for Refusal {
    fn from(reason: Reason) -> Self {
        Self {
            reason,
            detail: Detail::Plain,
        }
    }
}

/// A request that passed every check: where it may go, how, and the bytes sent after its head.
struct Cleared {
    auth: Authority,
    pinned: Vec<SocketAddr>,
    /// For a grant host, the TLS configurations to intercept it with; `None` splices.
    intercept: Option<intercept_tls::HostTls>,
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
            latch: Arc::default(),
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
    /// end with `session-stopped`. Connections served after this close at once, except that a
    /// reply already being written (429, connect-failed, a pre-`200` 502) finishes and drains,
    /// within [`REPLY_TIMEOUT`] + [`DRAIN_TIMEOUT`] (#71).
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
        if self.latched() {
            // RT-AUD-04: closed unread, no reply; recorded when the log takes it.
            let deny = self.entry("egress.deny", Some("deny"));
            let _ = self
                .append(deny.args(json!({"reason": AUDIT_FAILED})))
                .await;
            return;
        }
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
        let target = Seen::Target(h.target);
        let checked = match authority::parse(h.target) {
            _ if !h.connect => Err(Reason::PlainHttpUnsupported.into()),
            Err(AuthorityError::IpLiteral) => Err(Reason::IpLiteral.into()),
            Err(AuthorityError::Malformed) => Err(Reason::Malformed.into()),
            Ok(auth) => self.check(&auth).await.map(|cleared| (auth, cleared)),
        };
        match checked {
            Ok((auth, (pinned, intercept))) => Some(Cleared {
                auth,
                pinned,
                intercept,
                rest: window.get(h.len..).unwrap_or_default().to_vec(),
            }),
            Err(Stop::Refused(refusal)) => {
                self.refuse(client, refusal, target).await;
                None
            }
            Err(Stop::Closed) => None,
        }
    }

    /// Policy (and, for a grant host, a session-CA leaf to present), the host's own addresses,
    /// `egress.resolve`, the one lookup, the address filter: the pinned addresses, in order, and
    /// for a grant host the TLS configurations to intercept it with. Nothing fallible sits
    /// between the entry and the lookup; without the entry there is no lookup (RT-AUD-04).
    async fn check(
        &self,
        a: &Authority,
    ) -> Result<(Vec<SocketAddr>, Option<intercept_tls::HostTls>), Stop> {
        let tls = match self.policy.decide(a)? {
            Route::Splice => None,
            Route::Intercept => Some(
                self.interception
                    .as_ref()
                    .and_then(|i| i.host_tls(&a.host))
                    .ok_or(Reason::GrantHostUnavailable)?,
            ),
        };
        let host = self.host.own().await.map_err(|e| Refusal {
            reason: Reason::IpRangeDenied,
            detail: Detail::Unavailable(e),
        })?;
        let resolve = self
            .entry("egress.resolve", None)
            .args(json!({"host": a.host, "port": a.port}));
        if !self.gated(resolve).await {
            return Err(Stop::Closed);
        }
        let lookup = self.resolver.resolve(&a.host, a.port);
        let found = match tokio::time::timeout(self.limits.resolve, lookup).await {
            Ok(Ok(found)) if !found.is_empty() && found.len() <= MAX_ANSWER => found,
            _ => return Err(Reason::ResolveFailed.into()),
        };
        let denied = found
            .iter()
            .find_map(|s| addr::denied_by(s.ip(), &host).map(|rule| (s.ip(), rule)));
        if let Some((ip, rule)) = denied {
            return Err(Stop::Refused(Refusal {
                reason: Reason::IpRangeDenied,
                detail: Detail::Denied(ip, rule),
            }));
        }
        Ok((pinned(&found, a.port), tls))
    }

    /// `egress.allow`, then the connect attempts, the tunnel and `egress.close`.
    async fn connect<C: AsyncRead + AsyncWrite + Unpin + Send>(
        &self,
        mut client: C,
        mut c: Cleared,
    ) {
        let ips: Vec<String> = c.pinned.iter().map(|s| s.ip().to_string()).collect();
        let (host, port) = (&c.auth.host, c.auth.port);
        let intercept = c.intercept.is_some();
        let allow = self
            .entry("egress.allow", Some("allow"))
            .args(json!({"host": host, "port": port, "addresses": ips, "intercept": intercept}));
        if !self.gated(allow).await {
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
                let summary = intercept.then(Summary::default);
                if self.close_with(&c.auth, None, none, summary).await && end == End::ConnectFailed
                {
                    write_reply(&mut client, Reason::ConnectFailed).await;
                }
                return;
            }
        };
        if let Some(tls) = c.intercept.take() {
            // Boxed: inline, the intercepted tunnel's state (TLS sessions, hyper on both sides)
            // would size every connection's future, spliced ones too (+14 KiB a tunnel,
            // RT-NET-09).
            Box::pin(self.intercept(client, c, tls, upstream, used)).await;
            return;
        }
        let totals = self.tunnel(client, upstream, &c.rest).await;
        // TODO(#49): log a close entry that could not be written.
        let _ = self.close_with(&c.auth, Some(used), totals, None).await;
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

    /// Appends `egress.close`, with the request summary of an intercepted tunnel; whether it was
    /// written.
    async fn close_with(
        &self,
        a: &Authority,
        used: Option<SocketAddr>,
        t: Totals,
        summary: Option<Summary>,
    ) -> bool {
        self.append(
            self.entry("egress.close", None)
                .args(close_args(a, used, t, summary)),
        )
        .await
    }

    /// Audits a refusal, then replies (except `head-timeout`, which closes) and closes. When the
    /// entry cannot be written the connection closes without a reply.
    async fn refuse<C: AsyncRead + AsyncWrite + Unpin>(
        &self,
        client: &mut C,
        r: Refusal,
        seen: Seen<'_>,
    ) {
        let event = if r.reason.is_limit() {
            "egress.limit"
        } else {
            "egress.deny"
        };
        let forms = self
            .interception
            .as_ref()
            .map(|i| i.credentials().redaction().audit());
        let entry = refusal_entry(self.entry(event, Some("deny")), r, seen, forms);
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

    /// The audit sink of the connection on this task: entries of a broker-originated connection
    /// carry its origin (`local.rs`). Taken on the connection's task, before any `spawn_blocking`.
    fn sink(&self) -> Arc<dyn AuditSink> {
        super::local::latching(super::local::sink(&self.audit), &self.latch)
    }

    /// Whether an append of this session has failed (RT-AUD-04).
    fn latched(&self) -> bool {
        self.latch.load(Ordering::SeqCst)
    }

    /// Appends an entry that permits an effect (a lookup, a dial, a forwarded request) unless the
    /// latch is set; whether the effect may follow (RT-AUD-04).
    async fn gated(&self, entry: NewEntry) -> bool {
        !self.latched() && self.append(entry).await
    }

    /// Writes `egress.shed`: `closed` connections over the admission rate were closed unread in
    /// the last `window_ms` milliseconds (`net.rs`). Whether the entry was written.
    pub(super) async fn shed(&self, closed: u64, window_ms: u64) -> bool {
        let args = json!({"reason": "rate", "closed": closed, "window_ms": window_ms});
        self.append(self.entry("egress.shed", Some("deny")).args(args))
            .await
    }

    /// Appends off the runtime; whether the entry was written.
    async fn append(&self, entry: NewEntry) -> bool {
        let (sink, level) = (self.sink(), self.level);
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

/// Writes the reply to `reason` within [`REPLY_TIMEOUT`] and closes the sending half; then, once
/// the reply is out, discards what the client still sends until its end, [`DRAIN_BYTES`] or
/// [`DRAIN_TIMEOUT`] (#71). `copy` buffers on the heap only while it drains, so no connection's
/// future grows (RT-NET-09). Past the drain, the shim keeps relaying the reply while the client
/// sends on, for at most its linger (#76).
async fn write_reply<C: AsyncRead + AsyncWrite + Unpin>(client: &mut C, reason: Reason) {
    let send = async {
        client.write_all(reply(reason).as_bytes()).await?;
        client.shutdown().await
    };
    if !matches!(tokio::time::timeout(REPLY_TIMEOUT, send).await, Ok(Ok(()))) {
        return;
    }
    let mut rest = (&mut *client).take(DRAIN_BYTES);
    let mut sink = tokio::io::sink();
    let _ = tokio::time::timeout(DRAIN_TIMEOUT, tokio::io::copy(&mut rest, &mut sink)).await;
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

/// An `egress.deny` / `egress.limit` entry. A target is declared as [`authority::with_target`]
/// does, masked with `forms`, the session's secret forms (`None` for a session without secret
/// grants), and then by the writer with every live session's forms, before it is cut (architect
/// Q253, Q276).
fn refusal_entry(e: NewEntry, r: Refusal, seen: Seen<'_>, forms: Option<&Redactor>) -> NewEntry {
    let mut v = json!({"reason": r.reason.as_str()});
    let mut target = None;
    if let Some(obj) = v.as_object_mut() {
        match seen {
            Seen::Nothing => {}
            Seen::Bytes(n) => {
                obj.insert("head_bytes".into(), json!(n));
            }
            Seen::Target(raw) => target = Some(raw),
        }
        match r.detail {
            Detail::Plain => {}
            Detail::Unavailable(cause) => {
                obj.insert("filter".into(), json!(HOST_ADDRS_UNAVAILABLE));
                obj.insert("cause".into(), json!(cause.to_string()));
            }
            Detail::Denied(ip, rule) => {
                obj.insert("address".into(), json!(ip.to_string()));
                obj.insert("rule".into(), json!(rule.as_str()));
            }
        }
    }
    match target {
        Some(raw) => authority::with_target(e, v, raw, forms),
        None => e.args(v),
    }
}

/// Arguments of an `egress.close` entry: the address used (or `connected: false`), the byte
/// counts, how it ended, whether it was intercepted and, if so, its requests and status classes
/// (architect Q34). The `host` is the parsed authority, which no cut or escape touches before
/// the writer masks it, so it stays a plain arg and is not declared (architect Q289).
fn close_args(a: &Authority, used: Option<SocketAddr>, t: Totals, s: Option<Summary>) -> Value {
    let mut v = json!({
        "host": a.host,
        "port": a.port,
        "connected": used.is_some(),
        "bytes_up": t.up,
        "bytes_down": t.down,
        "end": t.end.as_str(),
        "intercept": s.is_some(),
    });
    if let Some(obj) = v.as_object_mut() {
        if let Some(used) = used {
            obj.insert("address".into(), json!(used.ip().to_string()));
        }
        if let Some(s) = s {
            obj.insert("requests".into(), json!(s.requests));
            obj.insert("statuses".into(), s.statuses_json());
        }
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
        413 => "Content Too Large",
        421 => "Misdirected Request",
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
