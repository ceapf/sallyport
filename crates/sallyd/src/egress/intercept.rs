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
//! No secret reaches this module (Q27 (1)): the proxy holds the leaves' keys and header names
//! only. Task 9a-3 adds injection here, constructible only together with response redaction.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hyper::body::{Body, Bytes, Frame, Incoming, SizeHint};
use hyper::http::{HeaderValue, Method, Request, Response, StatusCode, Version, header};
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use rustls::{ClientConfig, ServerConfig};
use sally_core::audit::NewEntry;
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use super::super::authority::{Authority, escape_target};
use super::super::ca::{CaError, Leaf, SessionTls};
use super::super::head::MAX_HEAD;
use super::super::meter::{BodyEnd, BoxError, Capped, Counts, Meter, OnEnd};
use super::super::policy::Reason;
use super::super::rewrite;
use super::super::roots::Roots;
use super::super::tunnel::{Activity, End, Totals};
use super::{Cleared, Dialer, ESTABLISHED, HostAddrs, Proxy, REPLY_TIMEOUT, Resolver, write_reply};

/// The only ALPN protocol offered either way (decision 4).
const HTTP_1_1: &[u8] = b"http/1.1";
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

/// What the proxy intercepts grant hosts with (Task 9a): the session CA's leaves and the upstream
/// trust roots, and the TLS configurations built from them. It holds no secret store and no
/// credential (architect Q27 (1)).
#[derive(Debug)]
pub struct Interception {
    /// The session CA and one leaf per grant host; the CA key is already gone.
    pub tls: SessionTls,
    /// The upstream verifier's roots.
    pub roots: Roots,
    upstream: Arc<ClientConfig>,
    servers: Vec<(String, Arc<ServerConfig>)>,
}

impl Interception {
    /// Builds the upstream client configuration (rustls defaults: TLS 1.2 and 1.3, the given
    /// roots, ALPN `http/1.1`) and one server configuration per leaf.
    ///
    /// # Errors
    /// [`CaError::Generate`] when rustls refuses a configuration or a leaf.
    pub fn new(tls: SessionTls, roots: Roots) -> Result<Self, CaError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut upstream = ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .map_err(tls_error)?
            .with_root_certificates(Arc::clone(&roots.store))
            .with_no_client_auth();
        upstream.alpn_protocols = vec![HTTP_1_1.to_vec()];
        let mut servers = Vec::with_capacity(tls.leaves.len());
        for leaf in &tls.leaves {
            let mut cfg = ServerConfig::builder_with_provider(Arc::clone(&provider))
                .with_safe_default_protocol_versions()
                .map_err(tls_error)?
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified(leaf)?)));
            cfg.alpn_protocols = vec![HTTP_1_1.to_vec()];
            servers.push((leaf.host.clone(), Arc::new(cfg)));
        }
        Ok(Self {
            tls,
            roots,
            upstream: Arc::new(upstream),
            servers,
        })
    }

    /// The server configuration presenting `host`'s leaf, if the session CA made one.
    #[must_use]
    pub fn server(&self, host: &str) -> Option<Arc<ServerConfig>> {
        self.servers
            .iter()
            .find(|(h, _)| h == host)
            .map(|(_, c)| Arc::clone(c))
    }

    /// What intercepting `host` takes, if the session CA made its leaf.
    pub(super) fn host_tls(&self, host: &str) -> Option<HostTls> {
        Some(HostTls {
            server: self.server(host)?,
            upstream: Arc::clone(&self.upstream),
        })
    }
}

/// The TLS configurations a cleared grant host is intercepted with: its leaf toward the client,
/// the verifying client configuration toward the upstream.
pub(super) struct HostTls {
    server: Arc<ServerConfig>,
    upstream: Arc<ClientConfig>,
}

/// The leaf and its signing key, read from the leaf's DER key in place (architect ruling R7):
/// the proxy makes no copy of the key bytes of its own; the only plain copy outside ring is the
/// leaf's `Secret`, wiped when the session ends. ring's parsed key and rustls's objects built
/// from it are freed, not wiped (THREAT_MODEL, Session CA limits (3); TODO(#69)).
fn certified(leaf: &Leaf) -> Result<CertifiedKey, CaError> {
    let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf.key.expose().as_slice()));
    let key = rustls::crypto::ring::sign::any_supported_type(&der).map_err(tls_error)?;
    let ck = CertifiedKey::new(vec![leaf.cert.clone()], key);
    ck.keys_match().map_err(tls_error)?;
    Ok(ck)
}

fn tls_error(e: rustls::Error) -> CaError {
    CaError::Generate(e.to_string())
}

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
    grants: Vec<String>,
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
    closed: AtomicBool,
}

impl State {
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

    fn end(&self) -> Option<End> {
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

/// A response body: a refusal's text, or the upstream's body under the response cap.
enum Out {
    Reply(Option<Bytes>),
    Upstream(Capped<Incoming>),
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

/// An `egress.limit` entry a body's end appends, at most once.
type HeldEntry = Mutex<Option<(NewEntry, Arc<dyn crate::sandbox::AuditSink>)>>;
/// What [`OnEnd::ended`] returns: the work that must finish before the body reports its cut.
type BeforeCut = Option<std::pin::Pin<Box<dyn Future<Output = ()> + Send>>>;

/// Appends the held entry (the first call only); the returned future finishes with the append.
fn append_held(held: &HeldEntry, level: sally_core::manifest::AuditLevel) -> BeforeCut {
    let (entry, sink) = held.lock().ok()?.take()?;
    let h = tokio::task::spawn_blocking(move || sink.append(entry, level));
    Some(Box::pin(async move {
        // TODO(#49): log a limit entry that could not be written; the cut happens regardless.
        let _ = h.await;
    }))
}

/// The request body's end (Q35; architect rulings R2 and R3). Past the cap: the tunnel ends
/// `limit` at once, and `egress.limit request-too-large` is appended before hyper's client sees
/// the cut, whether or not a response head was already forwarded (the 413, when there is one,
/// adds no second entry). A body the client broke off ends the tunnel `closed`: no entry, no
/// reply.
struct RequestEnd {
    state: Arc<State>,
    limit: HeldEntry,
    level: sally_core::manifest::AuditLevel,
}

impl OnEnd for RequestEnd {
    fn ended(&self, how: Option<BodyEnd>) -> BeforeCut {
        match how {
            Some(BodyEnd::OverCap) => {
                self.state.request_over.store(true, Ordering::Relaxed);
                self.state.set_end(End::Limit);
                append_held(&self.limit, self.level)
            }
            Some(BodyEnd::Failed) => {
                self.state.request_broken.store(true, Ordering::Relaxed);
                self.state.set_end(End::Closed);
                None
            }
            None | Some(BodyEnd::Complete) => None,
        }
    }
}

/// The response body's end: complete (the exchange is over), past the cap (audited, then cut),
/// or failed (the upstream closed mid-body: cut, Q43).
struct ResponseEnd {
    state: Arc<State>,
    limit: HeldEntry,
    level: sally_core::manifest::AuditLevel,
}

impl OnEnd for ResponseEnd {
    fn ended(&self, how: Option<BodyEnd>) -> BeforeCut {
        match how {
            None | Some(BodyEnd::Complete) => {
                self.state.finish();
                None
            }
            Some(BodyEnd::Failed) => {
                self.state.set_end(End::UpstreamClosed);
                None
            }
            Some(BodyEnd::OverCap) => {
                self.state.set_end(End::Limit);
                append_held(&self.limit, self.level)
            }
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
        } = host_tls;
        let act = Arc::new(Activity::new());
        let upstream = Meter::new(
            upstream,
            Vec::new(),
            Counts::default(),
            Some(Arc::clone(&act)),
        );
        let handshake = async {
            let name = ServerName::try_from(c.auth.host.clone()).ok()?;
            TlsConnector::from(client_cfg)
                .connect(name, upstream)
                .await
                .ok()
        };
        let tls = tokio::select! {
            biased;
            () = self.stopped() => Err(End::SessionStopped),
            t = tokio::time::timeout(self.limits.connect, handshake) => {
                t.ok().flatten().ok_or(End::UpstreamTlsFailed)
            }
        };
        let tls = match tls {
            Ok(tls) => tls,
            Err(end) => {
                let none = Totals {
                    up: 0,
                    down: 0,
                    end,
                };
                let closed = self
                    .close_with(&c.auth, Some(used), none, Some(Summary::default()))
                    .await;
                if closed && end == End::UpstreamTlsFailed {
                    write_reply(&mut client, Reason::UpstreamTlsFailed).await;
                }
                return;
            }
        };
        let opened = tokio::time::timeout(REPLY_TIMEOUT, client.write_all(ESTABLISHED)).await;
        let st = Arc::new(State {
            grants: self.policy.grant_headers(&c.auth.host),
            auth: c.auth,
            used,
            raw: Counts::default(),
            plain: Counts::default(),
            act: Arc::clone(&act),
            busy: AtomicBool::new(false),
            mark: AtomicU64::new(0),
            request_over: AtomicBool::new(false),
            request_broken: AtomicBool::new(false),
            requests: AtomicU64::new(0),
            statuses: Default::default(),
            end: Mutex::new(None),
            closed: AtomicBool::new(false),
        });
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

    /// The client's TLS handshake, then hyper on both sides until the tunnel ends.
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
        let accept = TlsAcceptor::from(server).accept(raw);
        let Ok(Ok(tls)) = tokio::time::timeout(self.limits.head, accept).await else {
            return End::ClientTlsFailed;
        };
        let plain = Meter::new(tls, Vec::new(), st.plain.clone(), None).max_read(REQUEST_READ);
        let upstream =
            Meter::new(upstream, Vec::new(), Counts::default(), None).max_read(RESPONSE_READ);
        let mut client_side = hyper::client::conn::http1::Builder::new();
        client_side
            .max_buf_size(MAX_RESPONSE_HEAD)
            .max_header_size(MAX_RESPONSE_HEAD - RESPONSE_READ)
            .max_headers(MAX_HEADERS);
        let Ok((sender, conn)) = client_side.handshake(TokioIo::new(upstream)).await else {
            return End::Error;
        };
        // Driven here, not spawned: the upstream connection and its TLS stream are dropped with
        // this future, so the tunnel's end closes them by ownership (architect, 9a-2 part 2).
        tokio::pin!(conn);
        let sender = tokio::sync::Mutex::new(sender);
        let svc = service_fn(|req| self.exchange(req, st, &sender));
        let mut server_side = hyper::server::conn::http1::Builder::new();
        // Half-close as in a spliced tunnel: a client that shuts its sending side after the
        // request still gets the response.
        server_side
            .half_close(true)
            .timer(TokioTimer::new())
            .header_read_timeout(self.limits.head)
            .max_buf_size(MAX_HEAD)
            .max_header_size(MAX_HEAD - REQUEST_READ)
            .max_headers(MAX_HEADERS);
        let served = server_side.serve_connection(TokioIo::new(plain), svc);
        tokio::pin!(served);
        let idle = idle_out(&st.act, self.limits.idle, st);
        tokio::pin!(idle);
        let mut upstream_open = true;
        loop {
            tokio::select! {
                r = &mut served => {
                    if upstream_open {
                        return self.served(r, st).await;
                    }
                    // hyper's server ended because the upstream did: no refusal mapping.
                    return st.end().unwrap_or(End::Closed);
                }
                _ = &mut conn, if upstream_open => {
                    upstream_open = false;
                    // The upstream connection is gone (architect ruling R1): hyper's server
                    // finishes the response in flight, if any, then closes. The client learns
                    // from that close, not from a `Connection: close` header. A request already
                    // read gets the upstream-closed 502 in `exchange`, never forwarded.
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
        sender: &tokio::sync::Mutex<hyper::client::conn::http1::SendRequest<Capped<Incoming>>>,
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
        // Held from `ready()` to `send_request`: a request is audited and counted only once the
        // upstream connection is known to take it (architect ruling R1).
        let mut sender = sender.lock().await;
        if sender.ready().await.is_err() {
            return self.upstream_closed(st).await;
        }
        let audited = self
            .entry("egress.request", Some("allow"))
            .args(request_args(&st.auth, &parts.method, &target));
        if !self.append(audited).await {
            st.set_end(End::Error);
            return Err("audit append failed".into());
        }
        st.requests.fetch_add(1, Ordering::Relaxed);
        let over = self.entry("egress.limit", Some("deny")).args(inside_args(
            &st.auth,
            Reason::RequestTooLarge,
            &target,
            None,
        ));
        let on_end = RequestEnd {
            state: Arc::clone(st),
            limit: Mutex::new(Some((over, Arc::clone(&self.audit)))),
            level: self.level,
        };
        let capped = Capped::new(body, self.limits.max_request, Arc::new(on_end));
        let mut up = Request::new(capped);
        *up.method_mut() = parts.method;
        *up.uri_mut() = parts
            .uri
            .path_and_query()
            .map_or_else(|| "/".parse(), |p| p.as_str().parse())?;
        *up.version_mut() = Version::HTTP_11;
        *up.headers_mut() = head.headers;
        let sent = sender.send_request(up).await;
        drop(sender);
        match sent {
            Ok(resp) => self.respond(st, resp, &target).await,
            // Already audited and marked `limit` by RequestEnd, before hyper saw the cut.
            Err(_) if st.request_over.load(Ordering::Relaxed) => {
                Ok(reply_response(Reason::RequestTooLarge))
            }
            // The client broke off its body: the tunnel ends `closed`, nothing to answer.
            Err(e) if st.request_broken.load(Ordering::Relaxed) => Err(e.into()),
            Err(e) if e.is_parse_too_large() => {
                self.refuse_inside(st, Reason::ResponseTooLarge, &target, Some("head"))
                    .await
            }
            Err(e) if e.is_parse() => {
                self.refuse_inside(st, Reason::UpstreamMalformed, &target, None)
                    .await
            }
            Err(_) => self.upstream_closed(st).await,
        }
    }

    /// The response head: checked (Q30), its declared length against the cap (Q35), then the
    /// body streamed back under the cap. The declared length is the one hyper decoded (none for
    /// HEAD, 204 or 304, whatever their `Content-Length` says: architect ruling R5).
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
        if !rewrite::within(body.size_hint().exact(), self.limits.max_response) {
            return self
                .refuse_inside(st, Reason::ResponseTooLarge, target, Some("body"))
                .await;
        }
        st.count(rp.status);
        let over = self.entry("egress.limit", Some("deny")).args(inside_args(
            &st.auth,
            Reason::ResponseTooLarge,
            target,
            Some("body"),
        ));
        let on_end = ResponseEnd {
            state: Arc::clone(st),
            limit: Mutex::new(Some((over, Arc::clone(&self.audit)))),
            level: self.level,
        };
        let mut out = Response::new(Out::Upstream(Capped::new(
            body,
            self.limits.max_response,
            Arc::new(on_end),
        )));
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
        let entry = self
            .entry(event, Some("deny"))
            .args(inside_args(&st.auth, reason, target, part));
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

/// The reply to a refusal inside the tunnel: as Task 8's [`super::reply`], closing the tunnel.
fn reply_response(reason: Reason) -> Response<Out> {
    let body = format!("{}\n", reason.as_str());
    let mut r = Response::new(Out::Reply(Some(Bytes::from(body))));
    *r.status_mut() = StatusCode::from_u16(reason.status()).unwrap_or(StatusCode::BAD_GATEWAY);
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    h.insert(header::CONNECTION, HeaderValue::from_static("close"));
    r
}

/// Arguments of `egress.request` (Q34). Nothing is injected in Task 9a-2.
fn request_args(a: &Authority, method: &Method, target: &str) -> Value {
    let (method, _, _) = escape_target(method.as_str().as_bytes());
    let (text, bytes, cut) = escape_target(target.as_bytes());
    json!({
        "host": a.host,
        "port": a.port,
        "method": method,
        "target": text,
        "target_bytes": bytes,
        "target_cut": cut,
        "injected": [],
    })
}

/// Arguments of a refusal inside the tunnel (Q34): reason, host, port, escaped target.
fn inside_args(a: &Authority, reason: Reason, target: &str, part: Option<&str>) -> Value {
    let (text, bytes, cut) = escape_target(target.as_bytes());
    let mut v = json!({
        "reason": reason.as_str(),
        "host": a.host,
        "port": a.port,
        "target": text,
        "target_bytes": bytes,
        "target_cut": cut,
    });
    if let (Some(obj), Some(p)) = (v.as_object_mut(), part) {
        obj.insert("part".into(), json!(p));
    }
    v
}

#[cfg(test)]
#[path = "intercept_tests.rs"]
mod tests;
