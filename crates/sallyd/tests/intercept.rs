//! Red-team rows RT-SEC-09 and RT-SEC-13 (Task 9a-2), and the secret-free parts of RT-SEC-04,
//! 05 and 06b as plain-named tests (architect Q48: their `rt_sec_0x` forms, with every PASS
//! assertion, land with injection in Task 9a-3).
//!
//! Each test launches a real workspace session with a secret grant on `mock.test` (launcher,
//! session CA, CA files). TLS legs run host-side over the session's `net.sock`, the socket the
//! shim relays to (architect Q47: the test image has no TLS client); the route decision and leaf
//! selection under test sit in `sallyd`, identical from either end of the socket. The upstream is
//! the in-process TLS mock of `common/egress.rs`, verified against a test CA.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use common::container::{Lx, SHIM_LOG, exec, net_image, rt};
use common::egress::tls_upstream;
use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use sallyd::sandbox::{Running, WorkspaceRequest};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio_rustls::client::TlsStream;

/// `mock.test` (grant host) and `mock2.test` (allowed, no grant) on 443.
const MANIFEST: &str = "network:\n  mode: proxy\n  allow:\n    - host: mock.test\n    \
                        - host: mock2.test\n\
                        secrets:\n  - name: GITHUB_TOKEN\n    inject: {host: mock.test, \
                        header: Authorization, format: \"Bearer {value}\"}\n";

async fn session(lx: &Lx, tag: &str) -> Running {
    let req = WorkspaceRequest {
        paths: lx.paths(tag),
        manifest: Arc::new(lx.f.load(MANIFEST)),
        default_image: net_image(),
    };
    let r = lx.launcher.launch_workspace(req).await.expect("launch");
    for _ in 0..100 {
        let (_, log) = exec(&r, &format!("cat {SHIM_LOG} 2>/dev/null")).await;
        if log.contains("sally-shim: listening on 127.0.0.1:3128") {
            for host in ["mock.test", "mock2.test"] {
                lx.egress.resolver.set(host, vec![vec![tls_upstream()]]);
            }
            return r;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the shim never became ready");
}

/// The session CA exactly as the workspace container sees it (`/run/sallyport/session-ca.pem`;
/// the 9a-1 container test proves the bytes equal).
fn session_ca(lx: &Lx, tag: &str) -> CertificateDer<'static> {
    let pem = std::fs::read(lx.paths(tag).workspace_sockets().join("session-ca.pem")).unwrap();
    CertificateDer::from_pem_slice(&pem).unwrap()
}

fn test_ca(lx: &Lx) -> CertificateDer<'static> {
    CertificateDer::from_pem_slice(lx.egress.dialer.pki.ca_pem.as_bytes()).unwrap()
}

/// `CONNECT host:443` over `net.sock`; the stream after the `200`. The socket directory's path is
/// longer than `sun_path` allows, so the connect goes through an open descriptor of it.
async fn connect(sock: &Path, host: &str) -> UnixStream {
    use std::os::fd::AsRawFd;
    let dir = std::fs::File::open(sock.parent().unwrap()).unwrap();
    let short = format!("/proc/self/fd/{}/net.sock", dir.as_raw_fd());
    let mut s = UnixStream::connect(short).await.unwrap();
    drop(dir);
    let req = format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        assert_eq!(s.read(&mut b).await.unwrap(), 1, "closed: {head:?}");
        head.push(b[0]);
    }
    let head = String::from_utf8_lossy(&head);
    assert!(head.starts_with("HTTP/1.1 200 "), "{head}");
    s
}

/// TLS over `s`, verifying the server for `name` against `root` alone.
async fn tls(
    s: UnixStream,
    name: &str,
    root: &CertificateDer<'static>,
) -> std::io::Result<TlsStream<UnixStream>> {
    let mut roots = RootCertStore::empty();
    roots.add(root.clone()).unwrap();
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let name = ServerName::try_from(name.to_owned()).unwrap();
    tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(name, s)
        .await
}

/// Sends `raw` and returns everything until the server closes.
async fn exchange(t: &mut TlsStream<UnixStream>, raw: &str) -> String {
    t.write_all(raw.as_bytes()).await.unwrap();
    let _ = t.shutdown().await;
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match tokio::time::timeout(Duration::from_secs(15), t.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => out.extend_from_slice(&chunk[..n]),
            _ => break,
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn allow_routes(lx: &Lx) -> Vec<(String, bool)> {
    lx.events
        .all()
        .into_iter()
        .filter(|(e, _)| e == "egress.allow")
        .map(|(_, a)| {
            (
                a["host"].as_str().unwrap().to_owned(),
                a["intercept"].as_bool().unwrap(),
            )
        })
        .collect()
}

/// RT-SEC-09. Controls: the route decision (`policy::decide` → `Route::Intercept` only for grant
/// hosts) and the leaf selection (`Interception::server`). Splicing the grant host fails the
/// session-CA handshake; intercepting the other host fails the byte-equal leaf assertion.
#[test]
fn rt_sec_09_a_grant_host_gets_a_session_ca_leaf_and_any_other_host_its_own_chain() {
    rt().block_on(async {
        let lx = Lx::new();
        let r = session(&lx, "sec09").await;
        let sock = lx.paths("sec09").workspace_sockets().join("net.sock");
        let ca = session_ca(&lx, "sec09");

        let t = tls(connect(&sock, "mock.test").await, "mock.test", &ca)
            .await
            .expect("grant host: the leaf verifies against the container's session CA");
        let chain = t.get_ref().1.peer_certificates().unwrap().to_vec();
        assert_ne!(
            chain[0], lx.egress.dialer.pki.leaf,
            "the upstream's own leaf"
        );
        let other = tls(connect(&sock, "mock.test").await, "other.mock.test", &ca).await;
        assert!(
            other.is_err(),
            "the session-CA leaf verified for another name"
        );

        let t = tls(
            connect(&sock, "mock2.test").await,
            "mock2.test",
            &test_ca(&lx),
        )
        .await
        .expect("non-grant host: the upstream's own chain");
        let chain = t.get_ref().1.peer_certificates().unwrap().to_vec();
        assert_eq!(
            chain[0], lx.egress.dialer.pki.leaf,
            "not the upstream's leaf"
        );
        assert!(
            chain.iter().all(|c| *c != ca),
            "the session CA is in the chain"
        );
        let by_session = tls(connect(&sock, "mock2.test").await, "mock2.test", &ca).await;
        assert!(
            by_session.is_err(),
            "a non-grant leaf verified against the session CA"
        );

        let routes = allow_routes(&lx);
        assert!(
            routes.contains(&("mock.test".to_owned(), true)),
            "{routes:?}"
        );
        assert!(
            routes.contains(&("mock2.test".to_owned(), false)),
            "{routes:?}"
        );
        assert!(
            routes.iter().all(|(h, i)| *i == (h == "mock.test")),
            "{routes:?}"
        );
        lx.stop(r).await;
    });
}

/// RT-SEC-13 (Task 8 changed it: plain HTTP is refused for every host). Control: the 405 before
/// policy in `Proxy::clear`. Without it the request would reach policy, a lookup and a dial.
#[test]
fn rt_sec_13_plain_http_to_a_grant_host_is_405_with_no_lookup_or_dial() {
    rt().block_on(async {
        let lx = Lx::new();
        let r = session(&lx, "sec13").await;
        let req = "GET http://mock.test/echo-headers HTTP/1.1\\r\\nHost: mock.test\\r\\n\\r\\n";
        let (_, out) = exec(&r, &format!("printf '{req}' | nc -w 3 127.0.0.1 3128")).await;
        assert!(out.starts_with("HTTP/1.1 405 "), "{out}");
        assert!(out.contains("plain-http-unsupported"), "{out}");
        assert!(lx.egress.resolver.lookups().is_empty(), "looked up");
        assert!(lx.egress.dialer.dials().is_empty(), "dialled");
        assert!(
            lx.egress.dialer.seen().is_empty(),
            "the upstream saw a request"
        );
        let deny: Vec<_> = lx
            .events
            .all()
            .into_iter()
            .filter(|(e, _)| e == "egress.deny")
            .map(|(_, a)| a)
            .collect();
        assert_eq!(deny.len(), 1, "{deny:?}");
        assert_eq!(deny[0]["reason"], json!("plain-http-unsupported"));
        assert_eq!(deny[0]["target"], json!("http://mock.test/echo-headers"));
        lx.stop(r).await;
    });
}

/// Secret-free part of RT-SEC-04/05/06b on the grant host: every client copy of the grant
/// header and `Accept-Encoding` are dropped; a redirect comes back unfollowed (no dial to its
/// target); a gzip response is refused and never forwarded.
#[test]
fn an_intercepted_grant_host_drops_client_headers_returns_redirects_and_refuses_gzip() {
    rt().block_on(async {
        let lx = Lx::new();
        let r = session(&lx, "sec04").await;
        let sock = lx.paths("sec04").workspace_sockets().join("net.sock");
        let ca = session_ca(&lx, "sec04");
        let mut t = tls(connect(&sock, "mock.test").await, "mock.test", &ca)
            .await
            .unwrap();
        let out = exchange(
            &mut t,
            "GET /echo-headers HTTP/1.1\r\nHost: mock.test\r\nAuthorization: Bearer attacker\r\n\
             authorization: Bearer second\r\nAccept-Encoding: gzip\r\nX-Kept: 1\r\n\r\n\
             GET /redirect HTTP/1.1\r\nHost: mock.test\r\n\r\n\
             GET /echo-gzip HTTP/1.1\r\nHost: mock.test\r\nAccept-Encoding: gzip\r\n\r\n",
        )
        .await;
        let seen = lx.egress.dialer.seen();
        assert_eq!(seen.len(), 3, "{seen:?}");
        let first = seen[0].to_ascii_lowercase();
        assert!(first.contains("x-kept: 1"), "{first}");
        assert!(!first.contains("authorization"), "{first}");
        assert!(!first.contains("accept-encoding"), "{first}");
        assert!(!seen[2].to_ascii_lowercase().contains("accept-encoding"));
        assert!(out.contains("HTTP/1.1 302 Found"), "{out}");
        assert!(
            out.contains("location: https://mock2.test/echo-headers"),
            "{out}"
        );
        assert!(out.contains("HTTP/1.1 502 "), "{out}");
        assert!(out.contains("upstream-encoded"), "{out}");
        assert!(!out.contains("GZIPPED"), "{out}");
        assert_eq!(lx.egress.dialer.dials().len(), 1, "a redirect was followed");
        lx.stop(r).await;
    });
}

/// Secret-free part of RT-SEC-04 on an allowed host without a grant: spliced, so the client's
/// own headers reach the upstream unchanged.
#[test]
fn a_spliced_host_receives_the_clients_headers_unchanged() {
    rt().block_on(async {
        let lx = Lx::new();
        let r = session(&lx, "sec04b").await;
        let sock = lx.paths("sec04b").workspace_sockets().join("net.sock");
        let mut t = tls(
            connect(&sock, "mock2.test").await,
            "mock2.test",
            &test_ca(&lx),
        )
        .await
        .unwrap();
        let out = exchange(
            &mut t,
            "GET /echo-headers HTTP/1.1\r\nHost: mock2.test\r\nAuthorization: Bearer attacker\r\n\
             Accept-Encoding: gzip\r\n\r\n",
        )
        .await;
        assert!(out.starts_with("HTTP/1.1 200 OK"), "{out}");
        let seen = lx.egress.dialer.seen();
        assert!(
            seen[0].contains("Authorization: Bearer attacker\r\n"),
            "{seen:?}"
        );
        assert!(seen[0].contains("Accept-Encoding: gzip\r\n"), "{seen:?}");
        lx.stop(r).await;
    });
}
