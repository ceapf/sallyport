//! Intercepted tunnels without containers (Task 9a-2): a real proxy, a raw TLS mock upstream
//! that records the bytes it receives, and a TLS client that trusts the session CA only.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sally_core::audit::AuditError;
use sally_core::manifest::{AuditLevel, parse_host_pattern};
use tokio::io::{AsyncReadExt, DuplexStream, duplex};

use super::super::{Limits, Parts};
use super::*;
use crate::egress::ca::Validity;
use crate::egress::policy::{Grant, Policy, Rule};
use crate::sandbox::AuditSink;

const HOST: &str = "a.mock.test";

/// What the mock upstream answers: the response bytes for one request, or `None` to close.
type Handler = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

fn canned(req: &str) -> Option<String> {
    let path = req.split(' ').nth(1).unwrap_or("/");
    let ok = |body: &str| {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    };
    Some(match path {
        "/close" => return None,
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

/// Reads one request (head and body, by `Content-Length` or chunked) from `s`.
async fn read_request<S: AsyncRead + Unpin>(s: &mut S, buf: &mut Vec<u8>) -> Option<String> {
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end + 4]).to_ascii_lowercase();
            let body_end = if head.contains("transfer-encoding: chunked") {
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
struct Upstream {
    tls: Arc<rustls::ServerConfig>,
    handler: Handler,
    seen: Arc<Mutex<Vec<String>>>,
    dials: Arc<Mutex<usize>>,
}

impl Dialer for Upstream {
    type Stream = DuplexStream;
    async fn dial(&self, _: SocketAddr) -> io::Result<DuplexStream> {
        *self.dials.lock().unwrap() += 1;
        let (near, far) = duplex(1 << 20);
        let up = self.clone();
        tokio::spawn(async move {
            let Ok(mut tls) = tokio_rustls::TlsAcceptor::from(up.tls).accept(far).await else {
                return;
            };
            let mut buf = Vec::new();
            while let Some(req) = read_request(&mut tls, &mut buf).await {
                up.seen.lock().unwrap().push(req.clone());
                let Some(resp) = (up.handler)(&req) else {
                    return;
                };
                if tls.write_all(resp.as_bytes()).await.is_err() || tls.flush().await.is_err() {
                    return;
                }
            }
        });
        Ok(near)
    }
}

struct Public;

impl Resolver for Public {
    async fn resolve(&self, _: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        Ok(vec![SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(93, 184, 215, 9)),
            port,
        )])
    }
}

struct NoOwn;

impl HostAddrs for NoOwn {
    async fn own(&self) -> io::Result<Vec<IpAddr>> {
        Ok(vec![])
    }
}

#[derive(Default)]
struct Sink {
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
    fn events(&self) -> Vec<String> {
        self.rows
            .lock()
            .unwrap()
            .iter()
            .map(|r| r.0.clone())
            .collect()
    }
    fn args(&self, event: &str) -> Value {
        let rows = self.rows.lock().unwrap();
        rows.iter()
            .find(|r| r.0 == event)
            .map_or(Value::Null, |r| r.1.clone())
    }
}

struct Rig {
    proxy: Arc<Proxy<Public, Upstream, NoOwn>>,
    sink: Arc<Sink>,
    seen: Arc<Mutex<Vec<String>>>,
    dials: Arc<Mutex<usize>>,
    session_ca: CertificateDer<'static>,
}

struct Opts {
    handler: Handler,
    limits: Limits,
    upstream_name: &'static str,
    fail_on: Option<&'static str>,
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
        }
    }
}

fn rig(o: Opts) -> Rig {
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
    };
    let (seen, dials) = (Arc::clone(&up.seen), Arc::clone(&up.dials));
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
        session_ca,
    }
}

type Client = tokio_rustls::client::TlsStream<DuplexStream>;

impl Rig {
    /// CONNECT through the proxy; returns the reply head and, after a `200`, the client's TLS
    /// stream to the session-CA leaf.
    async fn open(&self, port: u16) -> (String, Option<Client>, tokio::task::JoinHandle<()>) {
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
    async fn talk(&self, raw: &str) -> String {
        let (head, tls, task) = self.open(443).await;
        let mut tls = tls.unwrap_or_else(|| panic!("not opened: {head}"));
        tls.write_all(raw.as_bytes()).await.unwrap();
        let _ = tls.shutdown().await;
        let out = drain(&mut tls).await;
        task.await.unwrap();
        out
    }

    fn seen(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }
}

async fn drain<S: AsyncRead + Unpin>(s: &mut S) -> String {
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match s.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => out.extend_from_slice(&chunk[..n]),
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn get(path: &str, extra: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: {HOST}\r\n{extra}\r\n")
}

#[tokio::test]
async fn a_grant_host_is_intercepted_rewritten_forwarded_and_audited_in_order() {
    let r = rig(Opts::default());
    let out = r
        .talk(&get(
            "/echo",
            "Authorization: Bearer attacker\r\nauthorization: Bearer two\r\n\
             Accept-Encoding: gzip\r\nProxy-Authorization: Basic eA==\r\n\
             Connection: keep-alive, X-Hop\r\nX-Hop: 1\r\nX-Kept: yes\r\n",
        ))
        .await;
    assert!(out.starts_with("HTTP/1.1 200 OK\r\n"), "{out}");
    assert!(out.ends_with("ok"), "{out}");
    let seen = r.seen();
    assert_eq!(seen.len(), 1);
    let up = seen[0].to_ascii_lowercase();
    assert!(up.starts_with("get /echo http/1.1\r\n"), "{up}");
    assert!(up.contains("host: a.mock.test\r\n"), "{up}");
    assert!(up.contains("x-kept: yes\r\n"), "{up}");
    for gone in [
        "authorization",
        "accept-encoding",
        "proxy-",
        "x-hop",
        "connection: keep",
    ] {
        assert!(!up.contains(gone), "{gone} reached the upstream: {up}");
    }
    assert_eq!(
        r.sink.events(),
        ["egress.allow", "egress.request", "egress.close"]
    );
    assert_eq!(r.sink.args("egress.allow")["intercept"], json!(true));
    assert_eq!(
        r.sink.args("egress.request"),
        json!({"host": HOST, "port": 443, "method": "GET", "target": "/echo",
               "target_bytes": 5, "target_cut": false, "injected": []})
    );
    let close = r.sink.args("egress.close");
    assert_eq!(close["intercept"], json!(true));
    assert_eq!(close["requests"], json!(1));
    assert_eq!(close["statuses"], json!({"2xx": 1}));
    assert_eq!(close["end"], json!("closed"));
    assert_eq!(close["connected"], json!(true));
    assert!(close["bytes_up"].as_u64().unwrap() > 0);
    assert!(close["bytes_down"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn keep_alive_requests_share_one_upstream_connection() {
    let r = rig(Opts::default());
    let out = r.talk(&(get("/echo", "") + &get("/redirect", ""))).await;
    assert_eq!(out.matches("HTTP/1.1 ").count(), 2, "{out}");
    assert_eq!(*r.dials.lock().unwrap(), 1);
    assert_eq!(r.seen().len(), 2);
    let close = r.sink.args("egress.close");
    assert_eq!(close["requests"], json!(2));
    assert_eq!(close["statuses"], json!({"2xx": 1, "3xx": 1}));
}

#[tokio::test]
async fn a_redirect_is_returned_unfollowed() {
    let r = rig(Opts::default());
    let out = r.talk(&get("/redirect", "")).await;
    assert!(out.starts_with("HTTP/1.1 302 Found\r\n"), "{out}");
    assert!(out.contains("location: https://b.mock.test/"), "{out}");
    assert_eq!(r.seen().len(), 1);
    assert_eq!(*r.dials.lock().unwrap(), 1);
}

/// One refusal inside the tunnel: status, the audited event and reason, nothing upstream.
async fn refused_inside(raw: &str, status: &str, event: &str, reason: &str) -> Rig {
    let r = rig(Opts::default());
    let out = r.talk(raw).await;
    assert!(
        out.starts_with(&format!("HTTP/1.1 {status} ")),
        "{raw:?}: {out}"
    );
    assert!(out.contains("connection: close\r\n"), "{out}");
    assert!(out.ends_with(&format!("{reason}\n")), "{out}");
    assert!(r.seen().is_empty(), "{raw:?} reached the upstream");
    let args = r.sink.args(event);
    assert_eq!(args["reason"], json!(reason), "{raw:?}");
    assert_eq!(
        (args["host"].clone(), args["port"].clone()),
        (json!(HOST), json!(443))
    );
    let events = r.sink.events();
    assert_eq!(events.last().map(String::as_str), Some("egress.close"));
    assert!(!events.contains(&"egress.request".to_owned()), "{events:?}");
    r
}

#[tokio::test]
async fn a_host_header_naming_another_authority_is_421() {
    let raw = "GET /echo HTTP/1.1\r\nHost: b.mock.test\r\n\r\n";
    let r = refused_inside(raw, "421", "egress.deny", "host-mismatch").await;
    assert_eq!(r.sink.args("egress.deny")["target"], json!("/echo"));
    assert_eq!(r.sink.args("egress.close")["end"], json!("refused"));
}

#[tokio::test]
async fn heads_the_proxy_cannot_forward_as_they_are_are_400() {
    for raw in [
        "GET http://a.mock.test/x HTTP/1.1\r\nHost: a.mock.test\r\n\r\n",
        "GET /x HTTP/1.1\r\nHost: a.mock.test\r\nHost: a.mock.test\r\n\r\n",
        "GET /x HTTP/1.1\r\n\r\n",
        "GET /x HTTP/1.0\r\nHost: a.mock.test\r\n\r\n",
        "OPTIONS * HTTP/1.1\r\nHost: a.mock.test\r\n\r\n",
        "POST /x HTTP/1.1\r\nHost: a.mock.test\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n",
        "GET /x HTTP/1.1\r\nHost: a.mock.test\r\nExpect: nothing\r\n\r\n",
    ] {
        let r = rig(Opts::default());
        let out = r.talk(raw).await;
        assert!(out.contains(" 400 "), "{raw:?}: {out}");
        assert!(r.seen().is_empty(), "{raw:?}");
        assert_eq!(
            r.sink.args("egress.deny")["reason"],
            json!("malformed"),
            "{raw:?}"
        );
    }
}

#[tokio::test]
async fn upgrades_are_refused_403() {
    let raw = get("/ws", "Connection: Upgrade\r\nUpgrade: websocket\r\n");
    refused_inside(&raw, "403", "egress.deny", "upgrade-refused").await;
}

#[tokio::test]
async fn an_encoded_or_switching_response_is_502_and_never_forwarded() {
    for path in ["/gzip", "/switch"] {
        let r = rig(Opts::default());
        let out = r.talk(&get(path, "")).await;
        assert!(out.starts_with("HTTP/1.1 502 "), "{path}: {out}");
        assert!(out.ends_with("upstream-encoded\n"), "{out}");
        assert!(!out.contains("GZBODY"), "{out}");
        assert_eq!(
            r.sink.args("egress.deny")["reason"],
            json!("upstream-encoded")
        );
        assert_eq!(r.sink.args("egress.close")["end"], json!("refused"));
    }
}

#[tokio::test]
async fn response_bodies_pass_at_the_cap_and_are_refused_one_over() {
    let r = rig(Opts::default());
    let out = r.talk(&get("/len/16", "")).await;
    assert!(out.ends_with(&"b".repeat(16)), "{out}");
    let r = rig(Opts::default());
    let out = r.talk(&get("/len/17", "")).await;
    assert!(out.starts_with("HTTP/1.1 502 "), "{out}");
    assert!(!out.contains("bbbb"), "{out}");
    let limit = r.sink.args("egress.limit");
    assert_eq!(limit["reason"], json!("response-too-large"));
    assert_eq!(limit["part"], json!("body"));
}

#[tokio::test]
async fn a_streamed_response_one_over_the_cap_is_cut_after_its_audit_entry() {
    let r = rig(Opts::default());
    let out = r.talk(&get("/chunks/16", "")).await;
    assert!(out.ends_with("0\r\n\r\n"), "{out}");
    let r = rig(Opts::default());
    let out = r.talk(&get("/chunks/17", "")).await;
    assert!(out.starts_with("HTTP/1.1 200 OK\r\n"), "{out}");
    assert!(
        !out.ends_with("0\r\n\r\n"),
        "a cut sends no last chunk: {out}"
    );
    assert_eq!(
        r.sink.args("egress.limit")["reason"],
        json!("response-too-large")
    );
    let events = r.sink.events();
    assert_eq!(
        events,
        [
            "egress.allow",
            "egress.request",
            "egress.limit",
            "egress.close"
        ]
    );
    assert_eq!(r.sink.args("egress.close")["end"], json!("limit"));
}

#[tokio::test]
async fn response_trailers_are_never_forwarded() {
    let r = rig(Opts::default());
    let out = r.talk(&get("/trailer", "")).await;
    assert!(out.contains("ok"), "{out}");
    assert!(!out.to_ascii_lowercase().contains("x-late"), "{out}");
    assert!(!out.contains("trailer-value"), "{out}");
}

#[tokio::test]
async fn request_bodies_pass_at_the_cap_and_are_refused_one_over() {
    let body = "q".repeat(16);
    let r = rig(Opts::default());
    let out = r
        .talk(&format!(
            "POST /echo HTTP/1.1\r\nHost: {HOST}\r\nContent-Length: 16\r\n\r\n{body}"
        ))
        .await;
    assert!(out.starts_with("HTTP/1.1 200 "), "{out}");
    assert!(r.seen()[0].ends_with(&body));
    let raw = format!("POST /echo HTTP/1.1\r\nHost: {HOST}\r\nContent-Length: 17\r\n\r\n{body}q");
    refused_inside(&raw, "413", "egress.limit", "request-too-large").await;
}

#[tokio::test]
async fn a_chunked_request_crossing_the_cap_is_413() {
    let r = rig(Opts::default());
    let raw = format!(
        "POST /echo HTTP/1.1\r\nHost: {HOST}\r\nTransfer-Encoding: chunked\r\n\r\n\
         10\r\n{}\r\n1\r\nq\r\n0\r\n\r\n",
        "q".repeat(16)
    );
    let out = r.talk(&raw).await;
    assert!(out.starts_with("HTTP/1.1 413 "), "{out}");
    assert_eq!(
        r.sink.args("egress.limit")["reason"],
        json!("request-too-large")
    );
    assert_eq!(r.sink.args("egress.close")["end"], json!("limit"));
}

#[tokio::test]
async fn request_trailers_and_client_framing_never_reach_the_upstream() {
    let r = rig(Opts::default());
    let raw = format!(
        "POST /echo HTTP/1.1\r\nHost: {HOST}\r\nTransfer-Encoding: chunked\r\n\r\n\
         3\r\nabc\r\n0\r\nAuthorization: Bearer late\r\n\r\n"
    );
    let out = r.talk(&raw).await;
    assert!(out.starts_with("HTTP/1.1 200 "), "{out}");
    let up = r.seen()[0].to_ascii_lowercase();
    assert!(!up.contains("authorization"), "{up}");
    assert!(up.contains("abc"), "{up}");
}

/// Architect Q51: framing hyper resolves itself before the proxy sees the head. The upstream
/// gets exactly one framing header, set by the proxy's own client, and the decoded body; or
/// nothing at all when hyper answered 400 itself.
#[tokio::test]
async fn ambiguous_client_framing_never_reaches_the_upstream() {
    let te_cl = format!(
        "POST /echo HTTP/1.1\r\nHost: {HOST}\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n\
         3\r\nabc\r\n0\r\n\r\n"
    );
    let dup = format!(
        "POST /echo HTTP/1.1\r\nHost: {HOST}\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc"
    );
    for raw in [te_cl, dup] {
        let r = rig(Opts::default());
        let out = r.talk(&raw).await;
        assert!(out.starts_with("HTTP/1.1 200 "), "{raw:?}: {out}");
        let up = r.seen()[0].to_ascii_lowercase();
        let framing =
            up.matches("content-length:").count() + up.matches("transfer-encoding:").count();
        assert_eq!(framing, 1, "{up}");
        assert!(up.contains("abc"), "{up}");
    }
    for cl in [
        "Content-Length: 3\r\nContent-Length: 4",
        "Content-Length: 3, 3",
        "Content-Length: +3",
    ] {
        let r = rig(Opts::default());
        let out = r
            .talk(&format!(
                "POST /echo HTTP/1.1\r\nHost: {HOST}\r\n{cl}\r\n\r\nabcd"
            ))
            .await;
        assert!(out.starts_with("HTTP/1.1 400 "), "{cl}: {out}");
        assert!(r.seen().is_empty(), "{cl}");
        assert_eq!(r.sink.args("egress.deny")["reason"], json!("malformed"));
        assert_eq!(r.sink.args("egress.close")["end"], json!("refused"));
    }
}

#[tokio::test]
async fn an_oversized_request_head_is_a_limit() {
    let r = rig(Opts::default());
    let out = r
        .talk(&get("/x", &format!("X-Big: {}\r\n", "a".repeat(9000))))
        .await;
    assert!(out.starts_with("HTTP/1.1 431 "), "{out}");
    assert_eq!(
        r.sink.args("egress.limit")["reason"],
        json!("head-too-large")
    );
    assert_eq!(r.sink.args("egress.close")["end"], json!("limit"));
}

#[tokio::test]
async fn a_request_head_under_its_guaranteed_size_passes() {
    let r = rig(Opts::default());
    let filler = format!("X-Big: {}\r\n", "a".repeat(MAX_HEAD - REQUEST_READ - 200));
    let out = r.talk(&get("/x", &filler)).await;
    assert!(
        out.starts_with("HTTP/1.1 200 "),
        "{}",
        &out[..out.len().min(80)]
    );
}

#[tokio::test]
async fn upstream_heads_too_large_or_unparsable_are_502() {
    let r = rig(Opts::default());
    let out = r.talk(&get("/okhead", "")).await;
    assert!(
        out.starts_with("HTTP/1.1 200 "),
        "{}",
        &out[..out.len().min(80)]
    );
    let r = rig(Opts::default());
    let out = r.talk(&get("/bighead", "")).await;
    assert!(out.starts_with("HTTP/1.1 502 "), "{out}");
    let limit = r.sink.args("egress.limit");
    assert_eq!(
        (limit["reason"].clone(), limit["part"].clone()),
        (json!("response-too-large"), json!("head"))
    );
    let r = rig(Opts::default());
    let out = r.talk(&get("/garbage", "")).await;
    assert!(out.starts_with("HTTP/1.1 502 "), "{out}");
    assert_eq!(
        r.sink.args("egress.deny")["reason"],
        json!("upstream-malformed")
    );
}

/// Architect Q43: the close entry first, then the 502; the request is never replayed.
#[tokio::test]
async fn an_upstream_that_closes_before_answering_gets_close_first_then_502() {
    let r = rig(Opts::default());
    let out = r.talk(&get("/close", "")).await;
    assert!(out.starts_with("HTTP/1.1 502 "), "{out}");
    assert!(out.ends_with("upstream-closed\n"), "{out}");
    assert_eq!(r.seen().len(), 1, "never replayed");
    assert_eq!(*r.dials.lock().unwrap(), 1);
    assert_eq!(
        r.sink.events(),
        ["egress.allow", "egress.request", "egress.close"]
    );
    let close = r.sink.args("egress.close");
    assert_eq!(close["end"], json!("upstream-closed"));
    assert_eq!(close["connected"], json!(true));
}

/// Architect Q28: upstream verification before the `200`; failure is audited, then 502.
#[tokio::test]
async fn an_upstream_that_fails_verification_gets_no_200() {
    let r = rig(Opts {
        upstream_name: "wrong.mock.test",
        ..Opts::default()
    });
    let (reply, tls, task) = r.open(443).await;
    task.await.unwrap();
    assert!(tls.is_none());
    assert!(reply.starts_with("HTTP/1.1 502 "), "{reply}");
    assert!(reply.ends_with("upstream-tls-failed\n"), "{reply}");
    assert_eq!(r.sink.events(), ["egress.allow", "egress.close"]);
    let close = r.sink.args("egress.close");
    assert_eq!(
        (
            close["end"].clone(),
            close["connected"].clone(),
            close["intercept"].clone()
        ),
        (json!("upstream-tls-failed"), json!(true), json!(true))
    );
}

#[tokio::test]
async fn a_client_that_does_not_speak_tls_ends_client_tls_failed() {
    let r = rig(Opts::default());
    let (mut c, s) = duplex(1 << 16);
    let proxy = Arc::clone(&r.proxy);
    let task = tokio::spawn(async move { proxy.serve(s).await });
    let connect =
        format!("CONNECT {HOST}:443 HTTP/1.1\r\nHost: {HOST}:443\r\n\r\nGET / HTTP/1.1\r\n\r\n");
    c.write_all(connect.as_bytes()).await.unwrap();
    let out = drain(&mut c).await;
    task.await.unwrap();
    assert!(out.starts_with("HTTP/1.1 200 "), "{out}");
    assert_eq!(
        r.sink.args("egress.close")["end"],
        json!("client-tls-failed")
    );
    assert!(r.seen().is_empty());
}

/// Architect Q53: silence after the handshake or after a response is an idle close, a started
/// head that stalls is a limit.
#[tokio::test]
async fn head_timeouts_are_limits_only_once_a_head_started() {
    let r = rig(Opts::default());
    let (_, tls, task) = r.open(443).await;
    let mut tls = tls.unwrap();
    let _ = drain(&mut tls).await;
    task.await.unwrap();
    assert_eq!(r.sink.args("egress.close")["end"], json!("idle-timeout"));
    assert!(!r.sink.events().contains(&"egress.limit".to_owned()));

    let r = rig(Opts::default());
    let (_, tls, task) = r.open(443).await;
    let mut tls = tls.unwrap();
    tls.write_all(b"GET /echo HT").await.unwrap();
    tls.flush().await.unwrap();
    let _ = drain(&mut tls).await;
    task.await.unwrap();
    assert_eq!(r.sink.args("egress.limit")["reason"], json!("head-timeout"));
    assert_eq!(r.sink.args("egress.close")["end"], json!("limit"));

    let r = rig(Opts::default());
    let (_, tls, task) = r.open(443).await;
    let mut tls = tls.unwrap();
    tls.write_all(get("/echo", "").as_bytes()).await.unwrap();
    let out = drain(&mut tls).await;
    task.await.unwrap();
    assert!(out.starts_with("HTTP/1.1 200 "), "{out}");
    assert_eq!(r.sink.args("egress.close")["end"], json!("idle-timeout"));
    assert!(!r.sink.events().contains(&"egress.limit".to_owned()));
}

#[tokio::test]
async fn an_exchange_idle_past_the_limit_ends_idle_timeout() {
    // Five of the ten promised bytes, then nothing: the response body stalls.
    let hang: Handler =
        Arc::new(|_| Some("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort".into()));
    let r = rig(Opts {
        handler: hang,
        limits: Limits {
            head: Duration::from_secs(5),
            idle: Duration::from_millis(300),
            max_request: 16,
            max_response: 16,
            ..Limits::new(8)
        },
        ..Opts::default()
    });
    let started = Instant::now();
    let out = r.talk(&get("/echo", "")).await;
    assert!(out.contains("short"), "{out}");
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(r.sink.args("egress.close")["end"], json!("idle-timeout"));
}

#[tokio::test]
async fn a_failed_request_entry_closes_without_a_reply_or_an_upstream_request() {
    let r = rig(Opts {
        fail_on: Some("egress.request"),
        ..Opts::default()
    });
    let out = r.talk(&get("/echo", "")).await;
    assert!(out.is_empty(), "{out}");
    assert!(r.seen().is_empty());
    assert_eq!(r.sink.args("egress.close")["end"], json!("error"));
}

#[tokio::test]
async fn stopping_the_session_ends_an_intercepted_tunnel() {
    let r = rig(Opts {
        limits: Limits {
            head: Duration::from_secs(30),
            max_request: 16,
            max_response: 16,
            ..Limits::new(8)
        },
        ..Opts::default()
    });
    let (_, tls, task) = r.open(443).await;
    let mut tls = tls.unwrap();
    r.proxy.stop();
    let _ = drain(&mut tls).await;
    task.await.unwrap();
    assert_eq!(r.sink.args("egress.close")["end"], json!("session-stopped"));
}

#[tokio::test]
async fn an_intercepted_tunnel_on_another_allowed_port_names_it_in_host() {
    let r = rig(Opts::default());
    let (_, tls, task) = r.open(8443).await;
    let mut tls = tls.unwrap();
    tls.write_all(format!("GET /echo HTTP/1.1\r\nHost: {HOST}:8443\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let _ = tls.shutdown().await;
    let out = drain(&mut tls).await;
    task.await.unwrap();
    assert!(out.starts_with("HTTP/1.1 200 "), "{out}");
    assert!(
        r.seen()[0]
            .to_ascii_lowercase()
            .contains("host: a.mock.test:8443\r\n")
    );
}

#[test]
fn summaries_list_non_zero_status_classes_only() {
    let s = Summary {
        requests: 3,
        statuses: [0, 2, 0, 1, 0],
    };
    assert_eq!(s.statuses_json(), json!({"2xx": 2, "4xx": 1}));
    assert_eq!(Summary::default().statuses_json(), json!({}));
}
