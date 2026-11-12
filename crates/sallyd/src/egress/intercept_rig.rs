//! The rig for the intercepted-tunnel tests (Task 9a-2; split out of `intercept_tests.rs` by
//! architect ruling R9): a real proxy, a raw TLS mock upstream that records the bytes it
//! receives, a TLS client that trusts the session CA only, and bounded waits.

use std::io;
use std::sync::Mutex;

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sally_core::audit::AuditError;
use sally_core::manifest::{AuditLevel, parse_host_pattern};
use tokio::io::DuplexStream;

use super::*;
use crate::egress::ca::SessionTls;
use crate::egress::policy::{Grant, Policy, Rule};
use crate::egress::server::{Interception, Parts};
use crate::sandbox::AuditSink;

pub(super) const HOST: &str = "a.mock.test";

/// What the mock upstream answers: the response bytes for one request, or `None` to close.
pub(super) type Handler = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

pub(super) fn canned(req: &str) -> Option<String> {
    let path = req.split(' ').nth(1).unwrap_or("/");
    let ok = |body: &str| {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    };
    Some(match path {
        "/close" => return None,
        // Read, never answered, never closed.
        "/hang" => String::new(),
        "/redirect" => {
            "HTTP/1.1 302 Found\r\nLocation: https://b.mock.test/\r\nContent-Length: 0\r\n\r\n"
                .into()
        }
        "/gzip" => {
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 6\r\n\r\nGZBODY".into()
        }
        "/switch" => {
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
                .into()
        }
        "/garbage" => "NOT HTTP AT ALL\r\n\r\n".into(),
        // Framed two ways, or with two lengths (architect ruling R4).
        "/te-cl" => "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n\
                     6\r\nSMUGGL\r\n0\r\n\r\n"
            .into(),
        "/cl-twice" => {
            "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nContent-Length: 6\r\n\r\nSMUGGL".into()
        }
        "/cl-differ" => {
            "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nContent-Length: 7\r\n\r\nSMUGGL".into()
        }
        "/cl-list" => "HTTP/1.1 200 OK\r\nContent-Length: 6, 6\r\n\r\nSMUGGL".into(),
        // The upstream ends its connection with the response (architect ruling R1); the slow
        // one pauses mid-body.
        "/close-after" => {
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok".into()
        }
        "/close-slow" => {
            format!("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 4\r\n\r\nok{PAUSE}ok")
        }
        "/early" => "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n".into(),
        // A length over the test cap (16) with no body: the answer to a HEAD, or a 304.
        "/head-only" => "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n".into(),
        "/not-modified" => "HTTP/1.1 304 Not Modified\r\nContent-Length: 100\r\n\r\n".into(),
        "/bighead" => format!(
            "HTTP/1.1 200 OK\r\nX-Big: {}\r\nContent-Length: 0\r\n\r\n",
            "a".repeat(MAX_RESPONSE_HEAD + 1)
        ),
        "/okhead" => format!(
            "HTTP/1.1 200 OK\r\nX-Big: {}\r\nContent-Length: 2\r\n\r\nok",
            "a".repeat(MAX_RESPONSE_HEAD - RESPONSE_READ - 100)
        ),
        "/trailer" => "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Late\r\n\r\n\
                       2\r\nok\r\n0\r\nX-Late: trailer-value\r\n\r\n"
            .into(),
        p if p.starts_with("/head/") => {
            let n: usize = p.trim_start_matches("/head/").parse().unwrap();
            sized_head("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n", n)
        }
        // As `/head/`, sent in two writes: all but the last 100 bytes, then the rest
        // (see `split_at`).
        p if p.starts_with("/splithead/") => {
            let n: usize = p.trim_start_matches("/splithead/").parse().unwrap();
            let head = sized_head("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n", n);
            let at = split_at(n);
            format!("{}{PAUSE}{}", &head[..at], &head[at..])
        }
        p if p.starts_with("/len/") => {
            let n: usize = p.trim_start_matches("/len/").parse().unwrap();
            ok(&"b".repeat(n))
        }
        p if p.starts_with("/chunks/") => {
            let n: usize = p.trim_start_matches("/chunks/").parse().unwrap();
            format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{n:x}\r\n{}\r\n0\r\n\r\n",
                "c".repeat(n)
            )
        }
        _ => ok("ok"),
    })
}

/// In a mock response, where the mock flushes and pauses before writing on.
pub(super) const PAUSE: &str = "\u{0}pause\u{0}";

/// Where to split a head of `total` bytes: all but its last 100 bytes, then the rest, so the
/// head completes in a short read instead of a run of full ones (the cut must not depend on
/// where reads end).
pub(super) fn split_at(total: usize) -> usize {
    total.saturating_sub(100)
}

/// `start` (a first line and headers) plus one filler header and the blank line: exactly `total`
/// bytes.
pub(super) fn sized_head(start: &str, total: usize) -> String {
    let base = start.len() + "X-Big: \r\n\r\n".len();
    format!("{start}X-Big: {}\r\n\r\n", "a".repeat(total - base))
}

/// A CA and a leaf for `name`, as an upstream would have.
fn upstream_pki(name: &str) -> (CertificateDer<'static>, Arc<rustls::ServerConfig>) {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.distinguished_name
        .push(DnType::CommonName, "mock upstream CA");
    let ca_cert = ca.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::new(ca, ca_key);
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec![name.to_owned()])
        .unwrap()
        .signed_by(&leaf_key, &issuer)
        .unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![leaf.der().clone()], key)
    .unwrap();
    (ca_cert.der().clone(), Arc::new(cfg))
}

/// Reads one request (head and body, by `Content-Length` or chunked) from `s`. A request for
/// `/early` is taken at its head: the mock answers before the body arrives.
async fn read_request<S: AsyncRead + Unpin>(s: &mut S, buf: &mut Vec<u8>) -> Option<String> {
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end + 4]).to_ascii_lowercase();
            let body_end = if head.starts_with("post /early ") {
                Some(end + 4)
            } else if head.contains("transfer-encoding: chunked") {
                buf[end + 4..]
                    .windows(5)
                    .position(|w| w == b"0\r\n\r\n")
                    .map(|p| end + 4 + p + 5)
            } else {
                let n = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length: "))
                    .map_or(0, |v| v.trim().parse::<usize>().unwrap());
                (buf.len() >= end + 4 + n).then_some(end + 4 + n)
            };
            if let Some(b) = body_end {
                let req: Vec<u8> = buf.drain(..b).collect();
                return Some(String::from_utf8_lossy(&req).into_owned());
            }
        }
        let mut chunk = [0u8; 4096];
        match s.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

#[derive(Clone)]
pub(super) struct Upstream {
    tls: Arc<rustls::ServerConfig>,
    handler: Handler,
    seen: Arc<Mutex<Vec<String>>>,
    dials: Arc<Mutex<usize>>,
    /// Upstream connections that saw the proxy's side end, or hung up themselves.
    ended: Arc<Mutex<usize>>,
    /// Never answers the TLS handshake.
    stall: bool,
    /// When notified, closes (`close_notify`) without having read a request.
    hangup: Option<Arc<tokio::sync::Notify>>,
}

impl Upstream {
    async fn answer(&self, far: DuplexStream) {
        if self.stall {
            std::future::pending::<()>().await;
        }
        let Ok(mut tls) = tokio_rustls::TlsAcceptor::from(Arc::clone(&self.tls))
            .accept(far)
            .await
        else {
            return;
        };
        if let Some(hangup) = &self.hangup {
            hangup.notified().await;
            let _ = tls.shutdown().await;
            *self.ended.lock().unwrap() += 1;
            return;
        }
        let mut buf = Vec::new();
        while let Some(req) = read_request(&mut tls, &mut buf).await {
            self.seen.lock().unwrap().push(req.clone());
            let Some(resp) = (self.handler)(&req) else {
                return;
            };
            for (i, part) in resp.split(PAUSE).enumerate() {
                if i > 0 {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                if tls.write_all(part.as_bytes()).await.is_err() || tls.flush().await.is_err() {
                    return;
                }
            }
            // A keep-alive response, then the upstream closes (an upstream idle timeout).
            if req.starts_with("GET /then-eof ") {
                let _ = tls.shutdown().await;
                return;
            }
        }
        *self.ended.lock().unwrap() += 1;
    }
}

impl Dialer for Upstream {
    type Stream = DuplexStream;
    async fn dial(&self, _: SocketAddr) -> io::Result<DuplexStream> {
        *self.dials.lock().unwrap() += 1;
        let (near, far) = duplex(1 << 20);
        let up = self.clone();
        tokio::spawn(async move { up.answer(far).await });
        Ok(near)
    }
}

pub(super) struct Public;

impl Resolver for Public {
    async fn resolve(&self, _: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        Ok(vec![SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(93, 184, 215, 9)),
            port,
        )])
    }
}

pub(super) struct NoOwn;

impl HostAddrs for NoOwn {
    async fn own(&self) -> io::Result<Vec<IpAddr>> {
        Ok(vec![])
    }
}

#[derive(Default)]
pub(super) struct Sink {
    rows: Mutex<Vec<(String, Value)>>,
    fail_on: Option<&'static str>,
}

impl AuditSink for Sink {
    fn append(&self, e: NewEntry, _: AuditLevel) -> Result<(), AuditError> {
        if self.fail_on == Some(e.event()) {
            return Err(AuditError::InvalidEntry("fake failure"));
        }
        self.rows
            .lock()
            .unwrap()
            .push((e.event().to_owned(), e.arguments().clone()));
        Ok(())
    }
}

impl Sink {
    pub(super) fn events(&self) -> Vec<String> {
        self.rows
            .lock()
            .unwrap()
            .iter()
            .map(|r| r.0.clone())
            .collect()
    }
    pub(super) fn args(&self, event: &str) -> Value {
        let rows = self.rows.lock().unwrap();
        rows.iter()
            .find(|r| r.0 == event)
            .map_or(Value::Null, |r| r.1.clone())
    }
}

pub(super) struct Rig {
    pub(super) proxy: Arc<Proxy<Public, Upstream, NoOwn>>,
    pub(super) sink: Arc<Sink>,
    seen: Arc<Mutex<Vec<String>>>,
    pub(super) dials: Arc<Mutex<usize>>,
    pub(super) ended: Arc<Mutex<usize>>,
    session_ca: CertificateDer<'static>,
}

pub(super) struct Opts {
    pub(super) handler: Handler,
    pub(super) limits: Limits,
    pub(super) upstream_name: &'static str,
    pub(super) fail_on: Option<&'static str>,
    pub(super) stall: bool,
    pub(super) hangup: Option<Arc<tokio::sync::Notify>>,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            handler: Arc::new(canned),
            limits: Limits {
                head: Duration::from_millis(300),
                idle: Duration::from_secs(2),
                max_request: 16,
                max_response: 16,
                ..Limits::new(8)
            },
            upstream_name: HOST,
            fail_on: None,
            stall: false,
            hangup: None,
        }
    }
}

pub(super) fn rig(o: Opts) -> Rig {
    let (up_ca, up_tls) = upstream_pki(o.upstream_name);
    let mut store = RootCertStore::empty();
    store.add(up_ca).unwrap();
    let roots = crate::egress::roots::Roots {
        store: Arc::new(store),
        pem: String::new(),
        skipped: 0,
        path: "/test-roots.pem".into(),
    };
    let v = Validity::for_session(std::time::SystemTime::now(), Duration::from_secs(600)).unwrap();
    let tls = SessionTls::mint(&[HOST.to_owned()], v).unwrap();
    let session_ca = tls.ca.clone();
    let rule = Rule {
        host: parse_host_pattern("*.mock.test").unwrap(),
        ports: vec![443, 8443],
    };
    let grant = Grant {
        host: HOST.into(),
        header: "Authorization".into(),
    };
    let up = Upstream {
        tls: up_tls,
        handler: o.handler,
        seen: Arc::default(),
        dials: Arc::default(),
        ended: Arc::default(),
        stall: o.stall,
        hangup: o.hangup,
    };
    let (seen, dials, ended) = (
        Arc::clone(&up.seen),
        Arc::clone(&up.dials),
        Arc::clone(&up.ended),
    );
    let sink = Arc::new(Sink {
        fail_on: o.fail_on,
        ..Sink::default()
    });
    let proxy = Arc::new(Proxy::new(Parts {
        policy: Policy::new(vec![rule], vec![grant]),
        resolver: Public,
        dialer: up,
        host: NoOwn,
        audit: Arc::clone(&sink) as Arc<dyn AuditSink>,
        session: "s-i".into(),
        level: AuditLevel::default(),
        limits: o.limits,
        interception: Some(Interception::new(tls, roots).unwrap()),
    }));
    Rig {
        proxy,
        sink,
        seen,
        dials,
        ended,
        session_ca,
    }
}

type Client = tokio_rustls::client::TlsStream<DuplexStream>;

impl Rig {
    /// CONNECT through the proxy; returns the reply head and, after a `200`, the client's TLS
    /// stream to the session-CA leaf. Bounded.
    pub(super) async fn open(
        &self,
        port: u16,
    ) -> (String, Option<Client>, tokio::task::JoinHandle<()>) {
        bounded("CONNECT and the TLS handshake", self.open_unbounded(port)).await
    }

    async fn open_unbounded(
        &self,
        port: u16,
    ) -> (String, Option<Client>, tokio::task::JoinHandle<()>) {
        let (mut c, s) = duplex(1 << 20);
        let proxy = Arc::clone(&self.proxy);
        let task = tokio::spawn(async move { proxy.serve(s).await });
        let target = format!("{HOST}:{port}");
        c.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if c.read(&mut byte).await.unwrap() == 0 {
                break;
            }
            head.push(byte[0]);
        }
        let head = String::from_utf8_lossy(&head).into_owned();
        if !head.starts_with("HTTP/1.1 200 ") {
            let mut rest = Vec::new();
            let _ = c.read_to_end(&mut rest).await;
            return (head + &String::from_utf8_lossy(&rest), None, task);
        }
        let mut roots = RootCertStore::empty();
        roots.add(self.session_ca.clone()).unwrap();
        let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let name = rustls::pki_types::ServerName::try_from(HOST).unwrap();
        let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
            .connect(name, c)
            .await
            .expect("the session-CA leaf verifies for the grant host");
        (head, Some(tls), task)
    }

    /// Sends `raw` inside the tunnel, closes the sending half, returns what came back (a cut
    /// ends the read early; what arrived is kept).
    pub(super) async fn talk(&self, raw: &str) -> String {
        self.talk_split(raw, raw.len()).await
    }

    /// As [`Self::talk`], with `raw` sent in two writes split at `at`, 50 ms apart.
    pub(super) async fn talk_split(&self, raw: &str, at: usize) -> String {
        let (head, tls, task) = self.open(443).await;
        let mut tls = tls.unwrap_or_else(|| panic!("not opened: {head}"));
        let (first, rest) = raw.as_bytes().split_at(at);
        bounded("writing the request", async {
            tls.write_all(first).await.unwrap();
            if !rest.is_empty() {
                tls.flush().await.unwrap();
                tokio::time::sleep(Duration::from_millis(50)).await;
                // A refusal may already have closed the tunnel; its reply is still read below.
                let _ = tls.write_all(rest).await;
            }
            let _ = tls.shutdown().await;
        })
        .await;
        let out = drain(&mut tls).await;
        join(task).await;
        out
    }

    pub(super) fn seen(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }
}

/// The bound on every step a test awaits from the proxy. A mutant that hangs a tunnel then fails
/// its test in seconds instead of timing out the whole mutation run (9a-2 part 2: 11 timeouts).
const STEP: Duration = Duration::from_secs(5);

/// `f`, or a panic naming `what` once [`STEP`] passes without it finishing.
pub(super) async fn bounded<F: std::future::Future>(what: &str, f: F) -> F::Output {
    tokio::time::timeout(STEP, f)
        .await
        .unwrap_or_else(|_| panic!("{what}: not done within {STEP:?}"))
}

/// Waits (bounded) for a tunnel's task to finish.
pub(super) async fn join(task: tokio::task::JoinHandle<()>) {
    bounded("the tunnel's task", task).await.unwrap();
}

/// Everything `s` sends until it ends (bounded).
pub(super) async fn drain<S: AsyncRead + Unpin>(s: &mut S) -> String {
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    bounded("reading to the end", async {
        loop {
            match s.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => out.extend_from_slice(&chunk[..n]),
            }
        }
    })
    .await;
    String::from_utf8_lossy(&out).into_owned()
}

/// Waits (bounded) until `done` holds, polling every 10 ms.
pub(super) async fn until(what: &str, done: impl Fn() -> bool) {
    bounded(what, async {
        while !done() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
}

pub(super) fn get(path: &str, extra: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: {HOST}\r\n{extra}\r\n")
}
