//! Red-team rows RT-SEC-09 and RT-SEC-13 (Task 9a-2; RT-SEC-10 is in `session_ca.rs`), and
//! RT-SEC-03, 04, 05, 06, 06b, 07 and 11 (Task 9a-3: injection and response redaction).
//!
//! Each test launches a real workspace session with secret grants on `mock.test` and
//! `mock3.test` (launcher, session CA, CA files, and the credentials from the production
//! secrets store file over a temporary 0600 store: architect D12; the canaries are built at
//! runtime by `common::egress::canary`). TLS legs run host-side over the session's `net.sock`, the socket the
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

/// `mock.test` and `mock3.test` (grant hosts, a secret each) and `mock2.test` (allowed, no
/// grant) on 443.
const MANIFEST: &str = "network:\n  mode: proxy\n  allow:\n    - host: mock.test\n    \
                        - host: mock2.test\n    - host: mock3.test\n\
                        secrets:\n  - name: GITHUB_TOKEN\n    inject: {host: mock.test, \
                        header: Authorization, format: \"Bearer {value}\"}\n  \
                        - name: MOCK3_TOKEN\n    inject: {host: mock3.test, \
                        header: X-Api-Key, format: \"{value}\"}\n";

async fn session(lx: &Lx, tag: &str) -> Running {
    session_of(lx, tag, MANIFEST).await
}

async fn session_of(lx: &Lx, tag: &str, manifest: &str) -> Running {
    let req = WorkspaceRequest {
        paths: lx.paths(tag),
        manifest: Arc::new(lx.f.load(manifest)),
        default_image: net_image(),
    };
    let r = lx.launcher.launch_workspace(req).await.expect("launch");
    for _ in 0..100 {
        let (_, log) = exec(&r, &format!("cat {SHIM_LOG} 2>/dev/null")).await;
        if log.contains("sally-shim: listening on 127.0.0.1:3128") {
            for host in ["mock.test", "mock2.test", "mock3.test"] {
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
/// hosts) and the leaf selection (`Interception::server`, by the CONNECT host). Splicing a grant
/// host fails the session-CA handshake; intercepting the other host fails the byte-equal leaf
/// assertion; presenting one grant host's leaf for the other (say, the first leaf for every
/// host) fails that host's own-name handshake.
#[test]
fn rt_sec_09_a_grant_host_gets_a_session_ca_leaf_and_any_other_host_its_own_chain() {
    rt().block_on(async {
        let lx = Lx::new();
        let r = session(&lx, "sec09").await;
        let sock = lx.paths("sec09").workspace_sockets().join("net.sock");
        let ca = session_ca(&lx, "sec09");

        for (grant, other_grant) in [("mock.test", "mock3.test"), ("mock3.test", "mock.test")] {
            let t = tls(connect(&sock, grant).await, grant, &ca)
                .await
                .unwrap_or_else(|e| panic!("{grant}: its leaf must verify: {e}"));
            let chain = t.get_ref().1.peer_certificates().unwrap().to_vec();
            assert_ne!(
                chain[0], lx.egress.dialer.pki.leaf,
                "{grant}: the upstream's own leaf"
            );
            for name in [other_grant, "other.mock.test"] {
                let wrong = tls(connect(&sock, grant).await, name, &ca).await;
                assert!(
                    wrong.is_err(),
                    "{grant}: its session-CA leaf verified for {name}"
                );
            }
        }

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
        for (host, intercept) in [
            ("mock.test", true),
            ("mock3.test", true),
            ("mock2.test", false),
        ] {
            assert!(routes.contains(&(host.to_owned(), intercept)), "{routes:?}");
        }
        assert!(
            routes
                .iter()
                .all(|(h, i)| *i == (h == "mock.test" || h == "mock3.test")),
            "{routes:?}"
        );
        lx.stop(r).await;
    });
}

/// RT-SEC-13, rewritten with `inject-requires-tls` deleted (#59): plaintext never reaches a grant
/// host, either way a client tries it.
/// - Proxy-form `GET http://…`. Control: the 405 before policy in `Proxy::clear`. Without it the
///   request would reach policy, a lookup and a dial.
/// - `CONNECT` to the grant host, then plaintext where the TLS handshake belongs. Control: the
///   client handshake in `intercept::exchanges`, before hyper serves anything. Without it the
///   plaintext request would be parsed and forwarded (`egress.request`, the upstream sees it).
///
/// No credential can be attached on either path: nothing is forwarded at all.
#[test]
fn rt_sec_13_plain_http_to_a_grant_host_is_never_forwarded() {
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

        let sock = lx.paths("sec13").workspace_sockets().join("net.sock");
        let mut s = connect(&sock, "mock.test").await;
        s.write_all(b"GET /echo-headers HTTP/1.1\r\nHost: mock.test\r\n\r\n")
            .await
            .unwrap();
        let mut back = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(15), s.read_to_end(&mut back)).await;
        assert!(matches!(read, Ok(Ok(_))), "the tunnel stayed open");
        assert!(
            !String::from_utf8_lossy(&back).contains("HTTP/"),
            "an HTTP answer to plaintext: {back:?}"
        );
        assert!(
            lx.egress.dialer.seen().is_empty(),
            "the upstream saw a request"
        );
        // The failed handshake drops the client before the close entry is written.
        let mut close = None;
        for _ in 0..100 {
            close = lx.events.args("egress.close");
            if close.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let close = close.expect("egress.close");
        let events = lx.events.list();
        assert!(!events.iter().any(|e| e == "egress.request"), "{events:?}");
        assert_eq!(close["end"], json!("client-tls-failed"), "{close}");
        assert_eq!(close["requests"], json!(0), "{close}");
        lx.stop(r).await;
    });
}

/// One request on a fresh `CONNECT host:443` + TLS: grant hosts verified against the session CA,
/// `mock2.test` (spliced) against the upstream's test CA. Everything the server sent back.
async fn over(lx: &Lx, tag: &str, host: &str, raw: &str) -> String {
    let sock = lx.paths(tag).workspace_sockets().join("net.sock");
    let root = if host == "mock2.test" {
        test_ca(lx)
    } else {
        session_ca(lx, tag)
    };
    let mut t = tls(connect(&sock, host).await, host, &root)
        .await
        .unwrap_or_else(|e| panic!("{host}: {e}"));
    exchange(&mut t, raw).await
}

fn get_req(host: &str, path: &str, extra: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n{extra}\r\n")
}

/// The values of every `name` header line in a raw request or response head.
fn header_values(raw: &str, name: &str) -> Vec<String> {
    let head = raw.split("\r\n\r\n").next().unwrap_or_default();
    head.split("\r\n")
        .filter_map(|l| {
            let (n, v) = l.split_once(':')?;
            n.eq_ignore_ascii_case(name).then(|| v.trim().to_owned())
        })
        .collect()
}

/// A response's body and its declared length.
fn body_and_length(resp: &str) -> (&str, usize) {
    let body = resp.split_once("\r\n\r\n").map_or("", |(_, b)| b);
    let n = header_values(resp, "content-length")[0].parse().unwrap();
    (body, n)
}

fn gh() -> String {
    common::egress::canary("GITHUB_TOKEN")
}

fn mock3() -> String {
    common::egress::canary("MOCK3_TOKEN")
}

const LABEL: &str = "[REDACTED:GITHUB_TOKEN]";

/// RT-SEC-03: injection scope. Controls: `Credentials::set`, called with the tunnel's own host
/// (`intercept::forward`); the route decision (`Route::Splice` for `mock2.test`); the redaction
/// of the response (`redact::Redacted`). Setting every grant on every host fails the mock2/mock3
/// assertions; skipping the redaction fails the label assertion.
#[test]
fn rt_sec_03_a_credential_reaches_only_its_own_grant_host() {
    rt().block_on(async {
        let lx = Lx::new();
        let r = session(&lx, "sec03").await;
        let out = over(
            &lx,
            "sec03",
            "mock.test",
            &get_req("mock.test", "/echo-headers", ""),
        )
        .await;
        let _ = over(
            &lx,
            "sec03",
            "mock2.test",
            &get_req("mock2.test", "/echo-headers", ""),
        )
        .await;
        let _ = over(
            &lx,
            "sec03",
            "mock3.test",
            &get_req("mock3.test", "/echo-headers", ""),
        )
        .await;
        let seen = lx.egress.dialer.seen();
        assert_eq!(seen.len(), 3, "{seen:?}");
        // Positive control: the grant host's upstream got the real credential, once.
        assert_eq!(
            header_values(&seen[0], "authorization"),
            [format!("Bearer {}", gh())]
        );
        assert!(!seen[0].contains(&mock3()), "{}", seen[0]);
        // The allowed host without a grant got none.
        assert!(
            header_values(&seen[1], "authorization").is_empty(),
            "{}",
            seen[1]
        );
        assert!(!seen[1].contains(&gh()) && !seen[1].contains(&mock3()));
        // The other grant host got its own credential only.
        assert_eq!(header_values(&seen[2], "x-api-key"), [mock3()]);
        assert!(!seen[2].contains(&gh()), "{}", seen[2]);
        // The sandbox's view of the echo: redacted, same length as the upstream sent.
        assert!(out.starts_with("HTTP/1.1 200 OK"), "{out}");
        assert!(!out.contains(&gh()), "{out}");
        assert!(out.contains(LABEL), "{out}");
        let (body, n) = body_and_length(&out);
        assert_eq!((body.len(), n), (seen[0].len(), seen[0].len()));
        lx.stop(r).await;
    });
}

/// RT-SEC-04: a client-supplied copy of the grant header. Controls: the grant-header drop in
/// `rewrite::request` (architect Q40) and `Credentials::set`'s `insert` (one value). Without the
/// drop, or with `append`, the upstream gets two `Authorization` lines.
#[test]
fn rt_sec_04_a_client_copy_of_the_grant_header_never_reaches_the_grant_host() {
    rt().block_on(async {
        let lx = Lx::new();
        let r = session(&lx, "sec04").await;
        let attack = "Authorization: Bearer attacker\r\nauthorization: Bearer second\r\n\
                      X-Api-Key: attacker\r\nX-Kept: 1\r\n";
        let _ = over(
            &lx,
            "sec04",
            "mock.test",
            &get_req("mock.test", "/echo-headers", attack),
        )
        .await;
        let _ = over(
            &lx,
            "sec04",
            "mock3.test",
            &get_req("mock3.test", "/echo-headers", attack),
        )
        .await;
        let spliced = "Authorization: Bearer attacker\r\nAccept-Encoding: gzip\r\n";
        let out = over(
            &lx,
            "sec04",
            "mock2.test",
            &get_req("mock2.test", "/echo-headers", spliced),
        )
        .await;
        let seen = lx.egress.dialer.seen();
        assert_eq!(seen.len(), 3, "{seen:?}");
        assert_eq!(
            header_values(&seen[0], "authorization"),
            [format!("Bearer {}", gh())]
        );
        assert_eq!(header_values(&seen[0], "x-kept"), ["1"]);
        assert_eq!(header_values(&seen[1], "x-api-key"), [mock3()]);
        // mock3's grant is X-Api-Key: the client's Authorization is not its header, so it passes.
        assert_eq!(header_values(&seen[1], "authorization").len(), 2);
        // The spliced host receives the client's headers unchanged.
        assert!(out.starts_with("HTTP/1.1 200 OK"), "{out}");
        assert!(
            seen[2].contains("Authorization: Bearer attacker\r\n"),
            "{}",
            seen[2]
        );
        assert!(seen[2].contains("Accept-Encoding: gzip\r\n"), "{}", seen[2]);
        lx.stop(r).await;
    });
}

/// RT-SEC-05: a redirect is returned, never followed, and the client's own follow-up to the
/// non-grant host carries no credential. Controls: the proxy never dials a `Location` (one
/// upstream connection per tunnel, Q28) and `Credentials::set` by host.
#[test]
fn rt_sec_05_a_redirect_is_returned_unfollowed_and_its_target_gets_no_credential() {
    rt().block_on(async {
        let lx = Lx::new();
        let r = session(&lx, "sec05").await;
        let out = over(
            &lx,
            "sec05",
            "mock.test",
            &get_req("mock.test", "/redirect", ""),
        )
        .await;
        assert!(out.starts_with("HTTP/1.1 302 Found"), "{out}");
        assert_eq!(
            header_values(&out, "location"),
            ["https://mock2.test/echo-headers"]
        );
        assert_eq!(lx.egress.dialer.dials().len(), 1, "a redirect was followed");
        // Positive control: the redirecting request itself carried the credential.
        let seen = lx.egress.dialer.seen();
        assert_eq!(seen.len(), 1, "{seen:?}");
        assert!(seen[0].contains(&gh()), "{}", seen[0]);
        let _ = over(
            &lx,
            "sec05",
            "mock2.test",
            &get_req("mock2.test", "/echo-headers", ""),
        )
        .await;
        let seen = lx.egress.dialer.seen();
        assert_eq!(seen.len(), 2, "{seen:?}");
        assert!(!seen[1].contains(&gh()), "{}", seen[1]);
        assert!(header_values(&seen[1], "authorization").is_empty());
        lx.stop(r).await;
    });
}

/// RT-SEC-06: the upstream echoes the credential in its body and in a response header; both
/// reach the sandbox as same-length filler beginning with the label. Controls: `redact::headers`
/// (the header) and `redact::Redacted` (the body), with the forms built by `Credentials::new`.
#[test]
fn rt_sec_06_an_echo_in_body_and_header_is_redacted_at_the_same_length() {
    rt().block_on(async {
        let lx = Lx::new();
        let r = session(&lx, "sec06").await;
        let out = over(
            &lx,
            "sec06",
            "mock.test",
            &get_req("mock.test", "/echo-headers", ""),
        )
        .await;
        let seen = lx.egress.dialer.seen();
        // Positive control: the mock received the credential, so its echo held it.
        assert!(seen[0].contains(&gh()), "{}", seen[0]);
        assert!(!out.contains(&gh()), "{out}");
        let echoed = header_values(&out, "x-echo-authorization");
        assert_eq!(echoed.len(), 1, "{out}");
        assert!(echoed[0].starts_with(LABEL), "{out}");
        assert_eq!(echoed[0].len(), "Bearer ".len() + gh().len());
        let (body, n) = body_and_length(&out);
        assert!(body.contains(LABEL), "{body}");
        assert_eq!((body.len(), n), (seen[0].len(), seen[0].len()));
        lx.stop(r).await;
    });
}

/// RT-SEC-06b: compressed echoes. `Accept-Encoding` never reaches the grant host, so its echo
/// comes back uncompressed and redacted; a response encoded anyway is refused with 502
/// `upstream-encoded` and never forwarded (decision 1). Controls: `Accept-Encoding` in
/// `rewrite::REQUEST_DROPPED`; the `Content-Encoding` check in `rewrite::response`.
#[test]
fn rt_sec_06b_compression_is_stripped_and_an_encoded_echo_is_refused() {
    rt().block_on(async {
        let lx = Lx::new();
        let r = session(&lx, "sec06b").await;
        let gzip = "Accept-Encoding: gzip\r\n";
        let plain = over(
            &lx,
            "sec06b",
            "mock.test",
            &get_req("mock.test", "/echo-headers", gzip),
        )
        .await;
        let encoded = over(
            &lx,
            "sec06b",
            "mock.test",
            &get_req("mock.test", "/echo-gzip", gzip),
        )
        .await;
        let seen = lx.egress.dialer.seen();
        assert_eq!(seen.len(), 2, "{seen:?}");
        for s in &seen {
            assert!(header_values(s, "accept-encoding").is_empty(), "{s}");
            assert!(s.contains(&gh()), "{s}");
        }
        assert!(plain.starts_with("HTTP/1.1 200 OK"), "{plain}");
        assert!(header_values(&plain, "content-encoding").is_empty());
        assert!(plain.contains("GET /echo-headers HTTP/1.1"), "{plain}");
        assert!(plain.contains(LABEL) && !plain.contains(&gh()), "{plain}");
        assert!(encoded.starts_with("HTTP/1.1 502 "), "{encoded}");
        assert!(encoded.contains("upstream-encoded"), "{encoded}");
        assert!(!encoded.contains("GZIPPED"), "{encoded}");
        lx.stop(r).await;
    });
}

/// RT-SEC-07 (Task 9a-3 leg; 9b greps every form): after injected and echoed exchanges on both
/// grant hosts, no audit entry holds a canary, and each `egress.request` names its grant.
/// Control: `request_args` builds `injected` from grant names (`Credentials::names`), and no
/// entry is built from a header map or a body.
#[test]
fn rt_sec_07_no_audit_entry_holds_a_credential() {
    rt().block_on(async {
        let lx = Lx::new();
        let r = session(&lx, "sec07").await;
        let _ = over(
            &lx,
            "sec07",
            "mock.test",
            &get_req("mock.test", "/echo-headers", ""),
        )
        .await;
        let _ = over(
            &lx,
            "sec07",
            "mock3.test",
            &get_req("mock3.test", "/echo-headers", ""),
        )
        .await;
        let _ = over(
            &lx,
            "sec07",
            "mock2.test",
            &get_req("mock2.test", "/echo-headers", ""),
        )
        .await;
        let _ = over(
            &lx,
            "sec07",
            "mock.test",
            &get_req("mock.test", "/echo-gzip", ""),
        )
        .await;
        // Positive control: both credentials were sent.
        let seen = lx.egress.dialer.seen().concat();
        assert!(seen.contains(&gh()) && seen.contains(&mock3()));
        lx.stop(r).await;
        let all = lx.events.all();
        for (event, args) in &all {
            let text = args.to_string();
            assert!(
                !text.contains(&gh()) && !text.contains(&mock3()) && !text.contains("CANARY"),
                "{event}: {text}"
            );
        }
        let injected: Vec<(String, serde_json::Value)> = all
            .iter()
            .filter(|(e, _)| e == "egress.request")
            .map(|(_, a)| {
                (
                    a["host"].as_str().unwrap().to_owned(),
                    a["injected"].clone(),
                )
            })
            .collect();
        assert_eq!(
            injected,
            [
                ("mock.test".to_owned(), json!(["secret:GITHUB_TOKEN"])),
                ("mock3.test".to_owned(), json!(["secret:MOCK3_TOKEN"])),
                ("mock.test".to_owned(), json!(["secret:GITHUB_TOKEN"])),
            ]
        );
    });
}

/// RT-SEC-11: `expose_env` gives the workspace the public placeholder only; the grant host's
/// upstream gets the real credential in its place, the non-grant host at most the placeholder.
/// Controls: the placeholder in `argv::PLACEHOLDER` (the only value `--env` can carry) and
/// `Credentials::set` replacing the client's copy on the grant host.
#[test]
fn rt_sec_11_the_workspace_holds_only_the_placeholder() {
    rt().block_on(async {
        let lx = Lx::new();
        let manifest = MANIFEST.replace(
            "format: \"Bearer {value}\"}\n",
            "format: \"Bearer {value}\"}\n    expose_env: GH_TOKEN\n",
        );
        let r = session_of(&lx, "sec11", &manifest).await;
        let (_, env) = exec(
            &r,
            "env; for f in /proc/[0-9]*/environ; do tr '\\0' '\\n' < $f; done 2>/dev/null",
        )
        .await;
        assert!(env.contains("GH_TOKEN=sallyport-placeholder"), "{env}");
        assert!(!env.contains(&gh()) && !env.contains("CANARY"), "{env}");
        let placeholder = "Authorization: Bearer sallyport-placeholder\r\n";
        let _ = over(
            &lx,
            "sec11",
            "mock.test",
            &get_req("mock.test", "/echo-headers", placeholder),
        )
        .await;
        let _ = over(
            &lx,
            "sec11",
            "mock2.test",
            &get_req("mock2.test", "/echo-headers", placeholder),
        )
        .await;
        let seen = lx.egress.dialer.seen();
        assert_eq!(
            header_values(&seen[0], "authorization"),
            [format!("Bearer {}", gh())]
        );
        assert!(!seen[0].contains("sallyport-placeholder"), "{}", seen[0]);
        assert!(!seen[1].contains(&gh()), "{}", seen[1]);
        assert_eq!(
            header_values(&seen[1], "authorization"),
            ["Bearer sallyport-placeholder"]
        );
        lx.stop(r).await;
    });
}
