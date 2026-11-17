//! The intercepted tunnel to a grant host (Task 9a-2; decisions 2–6, architect Q27–Q53).
//!
//! After `egress.allow` and the dial: upstream TLS (real verification against the session's
//! trust roots, SNI = host, before the `200`; failure is `upstream-tls-failed`, Q28), the `200`,
//! the client's TLS handshake with the host's session-CA leaf (ALPN `http/1.1` only), then HTTP/1.1
//! exchanges through hyper: one upstream connection per tunnel, used for one request at a time,
//! never replayed. Each request head is checked and rewritten by [`super::super::rewrite`],
//! audited (`egress.request`) and forwarded; each response head is checked and its body streamed
//! back under the response cap. Every refusal is audited before its reply and ends the tunnel,
//! except a head hyper refuses itself (too large, unparsable): hyper answers first, and the entry
//! follows when its connection future returns (architect Q45, a recorded deviation).
//!
//! Task 9a-3: the grant headers are built from the session's [`Credentials`] before the request's
//! `egress.request` entry and set only after that entry is written (architect D13, ruling Q4),
//! and every response head and body goes through the credentials' redaction (decisions 2 and 3;
//! architect D2, D4, D5). Secret values stay inside `Credentials` and the redaction; this module
//! never reads one.
//!
//! One tunnel's state machine is kept together here (architect Q3): `State`, every `Proxy` method
//! and the idle watch. The body-end hooks, the hyper builders, the refusal reply and the entry
//! builders are in `intercept_parts.rs` (#179); the TLS setup is in `intercept_tls.rs` (#73).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hyper::body::{Body, Bytes, Frame, Incoming, SizeHint};
use hyper::http::{Request, Response, StatusCode};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ServerConfig};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use super::super::authority::Authority;
use super::super::head::MAX_HEAD;
use super::super::inject::Credentials;
use super::super::meter::{BoxError, Capped, Counts, Meter};
use super::super::policy::Reason;
use super::super::redact::{self, Ending, OnRedacted, Redacted};
use super::super::rewrite;
use super::super::tunnel::{Activity, End, Totals};
use super::intercept_tls::HostTls;
use super::{Cleared, Dialer, ESTABLISHED, HostAddrs, Proxy, REPLY_TIMEOUT, Resolver, write_reply};
pub(crate) use parts::request_entry;
pub use parts::upstream_builder;
use parts::{
    RequestEnd, ResponseEnd, Sender, client_builder, inside_entry, reply_response, upstream_request,
};
use report::ResponseReport;

/// Largest upstream response head (architect Q45); more is `response-too-large`.
pub const MAX_RESPONSE_HEAD: usize = 64 * 1024;
/// Header lines a head may have, either way.
const MAX_HEADERS: usize = 100;
/// Most plaintext bytes hyper gets per read, client side and upstream side; hyper's head limit
/// (`max_header_size`) is set this much below the bound. hyper 1.12 checks that limit on a
/// partial head and on a complete one, so the cut is exact: a request head passes iff it is at
/// most `MAX_HEAD - REQUEST_READ` (7168) bytes, a response head iff at most
/// `MAX_RESPONSE_HEAD - RESPONSE_READ` (61440). The read cap is defense in depth (architect,
/// Task 9a-2 part 2): should a hyper version check only partial heads, a head still never passes
/// [`MAX_HEAD`] or [`MAX_RESPONSE_HEAD`].
const REQUEST_READ: usize = 1024;
const RESPONSE_READ: usize = 4096;
/// Largest request head an intercepted tunnel passes on (exact, see above): the `fetch` tool
/// refuses at prepare a request whose head would not fit (architect ruling Q3).
pub const MAX_REQUEST_HEAD: usize = MAX_HEAD - REQUEST_READ;

/// What an intercepted tunnel's `egress.close` adds: its requests and their status classes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Summary {
    /// Requests forwarded upstream.
    pub requests: u64,
    /// Responses per status class, `1xx` to `5xx`.
    pub statuses: [u64; 5],
}

impl Summary {
    /// The `statuses` object: non-zero classes only.
    #[must_use]
    pub fn statuses_json(&self) -> Value {
        let mut m = serde_json::Map::new();
        for (i, n) in self.statuses.iter().enumerate() {
            if *n > 0 {
                m.insert(format!("{}xx", i + 1), json!(n));
            }
        }
        Value::Object(m)
    }
}

/// One intercepted tunnel's shared state.
struct State {
    auth: Authority,
    used: SocketAddr,
    /// The header names of the host's grants: every client copy is dropped (Q40).
    grants: Vec<String>,
    /// The session's credentials and their redaction.
    credentials: Arc<Credentials>,
    raw: Counts,
    plain: Counts,
    act: Arc<Activity>,
    busy: AtomicBool,
    /// Plaintext bytes read when the last exchange finished (architect Q53).
    mark: AtomicU64,
    request_over: AtomicBool,
    /// The client's request body failed before its end (architect ruling R3).
    request_broken: AtomicBool,
    requests: AtomicU64,
    statuses: [AtomicU64; 5],
    end: Mutex<Option<End>>,
    /// A body cap's `egress.limit` could not be written (architect ruling RQ2).
    held_failed: AtomicBool,
    closed: AtomicBool,
}

impl State {
    fn new(
        auth: Authority,
        used: SocketAddr,
        grants: Vec<String>,
        credentials: Arc<Credentials>,
        act: Arc<Activity>,
    ) -> Self {
        Self {
            auth,
            used,
            grants,
            credentials,
            raw: Counts::default(),
            plain: Counts::default(),
            act,
            busy: AtomicBool::new(false),
            mark: AtomicU64::new(0),
            request_over: AtomicBool::new(false),
            request_broken: AtomicBool::new(false),
            requests: AtomicU64::new(0),
            statuses: Default::default(),
            end: Mutex::new(None),
            held_failed: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        }
    }

    fn begin(&self) {
        self.act.touch();
        self.busy.store(true, Ordering::Relaxed);
    }

    fn finish(&self) {
        self.mark.store(self.plain.read(), Ordering::Relaxed);
        self.busy.store(false, Ordering::Relaxed);
    }

    fn busy(&self) -> bool {
        self.busy.load(Ordering::Relaxed)
    }

    /// Whether plaintext bytes arrived since the handshake or the last finished exchange.
    fn head_started(&self) -> bool {
        self.plain.read() > self.mark.load(Ordering::Relaxed)
    }

    /// Records how the tunnel ends; the first reason wins.
    fn set_end(&self, end: End) {
        if let Ok(mut e) = self.end.lock() {
            e.get_or_insert(end);
        }
    }

    /// How the tunnel ends: `error` once a held entry failed (RQ2), else the first reason set.
    fn end(&self) -> Option<End> {
        if self.held_failed.load(Ordering::Relaxed) {
            return Some(End::Error);
        }
        self.end.lock().ok().and_then(|e| *e)
    }

    fn count(&self, status: StatusCode) {
        let class = usize::from(status.as_u16() / 100).saturating_sub(1);
        if let Some(n) = self.statuses.get(class) {
            n.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn summary(&self) -> Summary {
        let mut statuses = [0; 5];
        for (out, n) in statuses.iter_mut().zip(&self.statuses) {
            *out = n.load(Ordering::Relaxed);
        }
        Summary {
            requests: self.requests.load(Ordering::Relaxed),
            statuses,
        }
    }

    fn totals(&self, end: End) -> Totals {
        Totals {
            up: self.raw.read(),
            down: self.raw.written(),
            end,
        }
    }
}

/// A response body: a refusal's text, or the upstream's body under the response cap, redacted.
enum Out {
    Reply(Option<Bytes>),
    Upstream(Box<Redacted<Capped<Incoming>>>),
}

impl Body for Out {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        match self.get_mut() {
            Self::Reply(b) => std::task::Poll::Ready(b.take().map(|b| Ok(Frame::data(b)))),
            Self::Upstream(c) => std::pin::Pin::new(c).poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Reply(b) => b.is_none(),
            Self::Upstream(c) => c.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Reply(b) => SizeHint::with_exact(
                b.as_ref()
                    .map_or(0, |b| u64::try_from(b.len()).unwrap_or(0)),
            ),
            Self::Upstream(c) => c.size_hint(),
        }
    }
}

impl<R: Resolver, D: Dialer, H: HostAddrs> Proxy<R, D, H> {
    /// Upstream TLS, the `200`, the client's TLS and the exchanges, then `egress.close` (unless
    /// an `upstream-closed` exchange already wrote it, Q43).
    pub(super) async fn intercept<C>(
        &self,
        mut client: C,
        c: Cleared,
        host_tls: HostTls,
        upstream: D::Stream,
        used: SocketAddr,
    ) where
        C: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let HostTls {
            server,
            upstream: client_cfg,
            credentials,
        } = host_tls;
        let act = Arc::new(Activity::new());
        let upstream = Meter::new(
            upstream,
            Vec::new(),
            Counts::default(),
            Some(Arc::clone(&act)),
        );
        let tls = match self.upstream_tls(&c.auth.host, client_cfg, upstream).await {
            Ok(tls) => tls,
            Err(end) => return self.never_opened(client, &c.auth, used, end).await,
        };
        let opened = tokio::time::timeout(REPLY_TIMEOUT, client.write_all(ESTABLISHED)).await;
        let grants = self.policy.grant_headers(&c.auth.host);
        let st = Arc::new(State::new(
            c.auth,
            used,
            grants,
            credentials,
            Arc::clone(&act),
        ));
        let end = if matches!(opened, Ok(Ok(()))) {
            let raw = Meter::new(client, c.rest, st.raw.clone(), Some(act));
            tokio::select! {
                biased;
                () = self.stopped() => End::SessionStopped,
                e = self.exchanges(raw, tls, server, &st) => e,
            }
        } else {
            End::Error
        };
        if !st.closed.load(Ordering::Relaxed) {
            // TODO(#49): log a close entry that could not be written.
            let _ = self
                .close_with(&st.auth, Some(st.used), st.totals(end), Some(st.summary()))
                .await;
        }
    }

    /// A tunnel that ended before its `200`: `egress.close` first, then (for
    /// `upstream-tls-failed` only) the 502 (Q28).
    async fn never_opened<C>(&self, mut client: C, auth: &Authority, used: SocketAddr, end: End)
    where
        C: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let none = Totals {
            up: 0,
            down: 0,
            end,
        };
        let closed = self
            .close_with(auth, Some(used), none, Some(Summary::default()))
            .await;
        if closed && end == End::UpstreamTlsFailed {
            write_reply(&mut client, Reason::UpstreamTlsFailed).await;
        }
    }

    /// The upstream TLS handshake within `limits.connect` (real verification, SNI = `host`,
    /// architect Q28), raced against the session stop.
    async fn upstream_tls<U>(
        &self,
        host: &str,
        cfg: Arc<ClientConfig>,
        upstream: U,
    ) -> Result<tokio_rustls::client::TlsStream<U>, End>
    where
        U: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let handshake = async {
            let name = ServerName::try_from(host.to_owned()).ok()?;
            TlsConnector::from(cfg).connect(name, upstream).await.ok()
        };
        tokio::select! {
            biased;
            () = self.stopped() => Err(End::SessionStopped),
            t = tokio::time::timeout(self.limits.connect, handshake) => {
                t.ok().flatten().ok_or(End::UpstreamTlsFailed)
            }
        }
    }

    /// The client's TLS handshake, then hyper on both sides until the tunnel ends.
    ///
    /// When the upstream connection ends (architect ruling R1), hyper's server finishes the
    /// response in flight, if any, then closes: the client learns from that close, not from a
    /// `Connection: close` header. A request already read gets the upstream-closed 502 in
    /// `forward`, unforwarded. A head hyper refuses after the upstream ended is still audited and
    /// ends `limit` or `refused` through [`Self::served`] (R1 amended, architect ruling RQ1).
    async fn exchanges<C, U>(
        &self,
        raw: Meter<C>,
        upstream: tokio_rustls::client::TlsStream<Meter<U>>,
        server: Arc<ServerConfig>,
        st: &Arc<State>,
    ) -> End
    where
        C: AsyncRead + AsyncWrite + Unpin + Send,
        U: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let accept = tokio::time::timeout(self.limits.head, TlsAcceptor::from(server).accept(raw));
        let Ok(Ok(tls)) = accept.await else {
            return End::ClientTlsFailed;
        };
        let plain = Meter::new(tls, Vec::new(), st.plain.clone(), None).max_read(REQUEST_READ);
        let upstream =
            Meter::new(upstream, Vec::new(), Counts::default(), None).max_read(RESPONSE_READ);
        let Ok((sender, conn)) = upstream_builder().handshake(TokioIo::new(upstream)).await else {
            return End::Error;
        };
        // Driven here, not spawned: the upstream connection and its TLS stream are dropped with
        // this future, so the tunnel's end closes them by ownership (architect, 9a-2 part 2).
        // Dropped as soon as it completes, too: only then does `ready()` fail for a request read
        // afterwards (an ended but kept connection future leaves it ready or pending; rust
        // re-review H1).
        let mut conn = Some(Box::pin(conn));
        let sender = tokio::sync::Mutex::new(sender);
        let svc = service_fn(|req| self.exchange(req, st, &sender));
        let served = client_builder(self.limits.head).serve_connection(TokioIo::new(plain), svc);
        tokio::pin!(served);
        let idle = idle_out(&st.act, self.limits.idle, st);
        tokio::pin!(idle);
        loop {
            tokio::select! {
                r = &mut served => return self.served(r, st).await,
                _ = async { conn.as_mut()?.await.ok() }, if conn.is_some() => {
                    conn = None;
                    served.as_mut().graceful_shutdown();
                }
                () = &mut idle => return End::IdleTimeout,
            }
        }
    }

    /// How the client side ended (Q53, and the item-5 mapping for heads hyper refused itself).
    async fn served(&self, r: Result<(), hyper::Error>, st: &State) -> End {
        if let Some(end) = st.end() {
            return end;
        }
        let Err(e) = r else {
            return End::Closed;
        };
        let (reason, end) = if e.is_timeout() {
            if !st.head_started() {
                return End::IdleTimeout;
            }
            (Reason::HeadTimeout, End::Limit)
        } else if e.is_parse_too_large() {
            (Reason::HeadTooLarge, End::Limit)
        } else if e.is_parse() {
            (Reason::Malformed, End::Refused)
        } else if e.is_incomplete_message() {
            return End::Closed; // the client closed mid-head or mid-body
        } else {
            return End::Error;
        };
        let event = if reason.is_limit() {
            "egress.limit"
        } else {
            "egress.deny"
        };
        let args = json!({"reason": reason.as_str(), "host": st.auth.host, "port": st.auth.port});
        // TODO(#49): log a refusal entry that could not be written.
        let _ = self
            .append(self.entry(event, Some("deny")).args(args))
            .await;
        end
    }

    /// One exchange: check, audit, forward, check the response, stream it back.
    async fn exchange(
        &self,
        req: Request<Incoming>,
        st: &Arc<State>,
        sender: &Sender,
    ) -> Result<Response<Out>, BoxError> {
        st.begin();
        let (parts, body) = req.into_parts();
        let target = parts.uri.to_string();
        let head = match rewrite::request(
            &parts.method,
            parts.version,
            &parts.uri,
            &parts.headers,
            &st.auth,
            &st.grants,
        ) {
            Ok(h) => h,
            Err(reason) => return self.refuse_inside(st, reason, &target, None).await,
        };
        if !rewrite::within(head.length, self.limits.max_request) {
            return self
                .refuse_inside(st, Reason::RequestTooLarge, &target, None)
                .await;
        }
        self.forward(st, sender, parts, body, head.headers, &target)
            .await
    }

    /// Forwards a checked request. The sender lock is held from `ready()` to `send_request`: a
    /// request is audited and counted only once the upstream connection is known to take it
    /// (architect ruling R1). The grant headers are built before its `egress.request` entry
    /// (which names exactly them) and set only once that entry is written, right before the
    /// request is built (architect D13, ruling Q4); a failed append drops them unsent.
    async fn forward(
        &self,
        st: &Arc<State>,
        sender: &Sender,
        parts: hyper::http::request::Parts,
        body: Incoming,
        mut headers: hyper::http::HeaderMap,
        target: &str,
    ) -> Result<Response<Out>, BoxError> {
        let mut sender = sender.lock().await;
        if let Some(reply) = self.upstream_ready(st, &mut sender).await {
            return reply;
        }
        let grants = st.credentials.prepare(&st.auth.host);
        let audited = request_entry(
            self.entry("egress.request", Some("allow")),
            &st.auth,
            &parts.method,
            target,
            grants.names(),
            st.credentials.redaction(),
        );
        // TODO(#72): on a session stop this append may land after `egress.close`.
        if !self.append(audited).await {
            st.set_end(End::Error);
            return Err("audit append failed".into());
        }
        st.requests.fetch_add(1, Ordering::Relaxed);
        grants.apply(&mut headers);
        let capped = Capped::new(body, self.limits.max_request, self.request_end(st, target));
        let up = upstream_request(capped, parts, headers)?;
        let sent = sender.send_request(up).await;
        drop(sender);
        self.outcome(st, sent, target).await
    }

    /// Waits until the upstream connection takes a request. If it is gone, the request is
    /// neither audited nor counted: the upstream-closed reply (close entry first) comes back
    /// instead of `None`.
    async fn upstream_ready(
        &self,
        st: &State,
        sender: &mut hyper::client::conn::http1::SendRequest<Capped<Incoming>>,
    ) -> Option<Result<Response<Out>, BoxError>> {
        match sender.ready().await {
            Ok(()) => None,
            Err(_) => Some(self.upstream_closed(st).await),
        }
    }

    /// The request body's end handler, holding its `egress.limit` entry (architect ruling R2).
    fn request_end(&self, st: &Arc<State>, target: &str) -> Arc<RequestEnd> {
        let over = inside_entry(
            self.entry("egress.limit", Some("deny")),
            &st.auth,
            Reason::RequestTooLarge,
            target,
            None,
            st.credentials.redaction(),
        );
        Arc::new(RequestEnd {
            state: Arc::clone(st),
            limit: Mutex::new(Some((over, self.sink()))),
            level: self.level,
        })
    }

    /// What the client gets once the upstream answered or the exchange failed.
    async fn outcome(
        &self,
        st: &Arc<State>,
        sent: Result<Response<Incoming>, hyper::Error>,
        target: &str,
    ) -> Result<Response<Out>, BoxError> {
        match sent {
            Ok(resp) => self.respond(st, resp, target).await,
            // Already audited and marked `limit` by RequestEnd, before hyper saw the cut; when
            // that entry could not be written, no 413 (architect ruling RQ2).
            Err(e) if st.request_over.load(Ordering::Relaxed) => {
                if st.held_failed.load(Ordering::Relaxed) {
                    return Err(e.into());
                }
                Ok(reply_response(Reason::RequestTooLarge))
            }
            // The client broke off its body: the tunnel ends `closed`, nothing to answer.
            Err(e) if st.request_broken.load(Ordering::Relaxed) => Err(e.into()),
            Err(e) if e.is_parse_too_large() => {
                self.refuse_inside(st, Reason::ResponseTooLarge, target, Some("head"))
                    .await
            }
            Err(e) if e.is_parse() => {
                self.refuse_inside(st, Reason::UpstreamMalformed, target, None)
                    .await
            }
            Err(_) => self.upstream_closed(st).await,
        }
    }

    /// The response head: checked (Q30), its headers redacted (architect D5), its declared length
    /// against the cap (Q35), then the body streamed back under the cap and redacted (decisions
    /// 2 and 3). The declared length is the one hyper decoded (none for HEAD, 204 or 304,
    /// whatever their `Content-Length` says: architect ruling R5). The upstream's reason phrase
    /// is never forwarded: the client gets hyper's canonical one.
    async fn respond(
        &self,
        st: &Arc<State>,
        resp: Response<Incoming>,
        target: &str,
    ) -> Result<Response<Out>, BoxError> {
        let (rp, body) = resp.into_parts();
        let headers = match rewrite::response(rp.status, &rp.headers) {
            Ok(h) => h,
            Err(reason) => return self.refuse_inside(st, reason, target, None).await,
        };
        let redaction = st.credentials.redaction();
        let Ok((headers, head_tally)) = redact::headers(redaction, &headers) else {
            return self
                .refuse_inside(st, Reason::UpstreamEchoedSecret, target, None)
                .await;
        };
        if !rewrite::within(body.size_hint().exact(), self.limits.max_response) {
            return self
                .refuse_inside(st, Reason::ResponseTooLarge, target, Some("body"))
                .await;
        }
        st.count(rp.status);
        let over = inside_entry(
            self.entry("egress.limit", Some("deny")),
            &st.auth,
            Reason::ResponseTooLarge,
            target,
            Some("body"),
            redaction,
        );
        let on_end = ResponseEnd {
            state: Arc::clone(st),
            limit: Mutex::new(Some((over, self.sink()))),
            level: self.level,
        };
        let capped = Capped::new(body, self.limits.max_response, Arc::new(on_end));
        let report = Arc::new(ResponseReport {
            state: Arc::clone(st),
            entry: Mutex::new(Some(self.entry("egress.response", None))),
            target: target.to_owned(),
            status: rp.status,
            redaction: Arc::clone(redaction),
            sink: self.sink(),
            level: self.level,
        });
        // A body known empty now (HEAD, 204, 304) is never polled: its entry is written here,
        // before the head goes out (architect Q13).
        let empty = capped.is_end_stream();
        if empty
            && let Some(work) = report.ended(Ending::Complete, head_tally.clone())
            && !work.await
        {
            return Err(Box::new(redact::Unreported));
        }
        let body = Redacted::new(capped, redaction, head_tally, report);
        let body = if empty { body.reported() } else { body };
        let mut out = Response::new(Out::Upstream(Box::new(body)));
        *out.status_mut() = rp.status;
        *out.headers_mut() = headers;
        Ok(out)
    }

    /// A refusal inside the tunnel: audited first (`egress.deny` or `egress.limit`), answered
    /// with `Connection: close`, and the tunnel ends. A failed append closes without a reply.
    async fn refuse_inside(
        &self,
        st: &State,
        reason: Reason,
        target: &str,
        part: Option<&str>,
    ) -> Result<Response<Out>, BoxError> {
        let event = if reason.is_limit() {
            "egress.limit"
        } else {
            "egress.deny"
        };
        let entry = inside_entry(
            self.entry(event, Some("deny")),
            &st.auth,
            reason,
            target,
            part,
            st.credentials.redaction(),
        );
        if !self.append(entry).await {
            st.set_end(End::Error);
            return Err("audit append failed".into());
        }
        st.set_end(if reason.is_limit() {
            End::Limit
        } else {
            End::Refused
        });
        Ok(reply_response(reason))
    }

    /// The upstream closed before a response head: `egress.close` first, then the 502 (Q43).
    ///
    /// Cancellation: `closed` is set before the first await, so `intercept` never writes a second
    /// close entry; the append itself is spawned on this future's first poll and finishes even if
    /// the tunnel's future is dropped (a stop) while it runs.
    async fn upstream_closed(&self, st: &State) -> Result<Response<Out>, BoxError> {
        st.set_end(End::UpstreamClosed);
        st.closed.store(true, Ordering::Relaxed);
        let t = st.totals(End::UpstreamClosed);
        if !self
            .close_with(&st.auth, Some(st.used), t, Some(st.summary()))
            .await
        {
            return Err("audit append failed".into());
        }
        Ok(reply_response(Reason::UpstreamClosed))
    }
}

/// Resolves once an exchange in flight moved nothing for `idle` (Q53: between exchanges the
/// head timer governs).
async fn idle_out(act: &Activity, idle: Duration, st: &State) {
    while let Some(wake) = idle_wake(Instant::now(), act.last(), idle, st.busy()) {
        tokio::time::sleep_until(wake).await;
    }
}

/// When the idle watch looks next, or `None` when it fires: an exchange in flight moved nothing
/// for `idle`. Past the deadline with no exchange in flight it looks again `idle` later, never
/// at once (that would spin between exchanges).
fn idle_wake(now: Instant, last: Instant, idle: Duration, busy: bool) -> Option<Instant> {
    let deadline = last + idle;
    if now < deadline {
        Some(deadline)
    } else if busy {
        None
    } else {
        Some(now + idle)
    }
}

#[path = "intercept_parts.rs"]
mod parts;

#[path = "intercept_report.rs"]
mod report;

#[cfg(test)]
#[path = "intercept_tests.rs"]
mod tests;
