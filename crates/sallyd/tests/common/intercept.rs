//! The rig of `tests/intercept.rs`: TLS over a session's `net.sock`, raw HTTP parsing, the
//! canaries, and the checks RT-SEC-07 and RT-SEC-12 run.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio_rustls::client::TlsStream;

use super::container::Lx;
use super::forms::{Line, basic_blob, basic_forms, echo_body, echo_lines, forms_of};
use crate::common;

/// The session CA exactly as the workspace container sees it (`/run/sallyport/session-ca.pem`;
/// the 9a-1 container test proves the bytes equal).
pub(crate) fn session_ca(lx: &Lx, tag: &str) -> CertificateDer<'static> {
    let pem = std::fs::read(lx.paths(tag).workspace_sockets().join("session-ca.pem")).unwrap();
    CertificateDer::from_pem_slice(&pem).unwrap()
}

pub(crate) fn test_ca(lx: &Lx) -> CertificateDer<'static> {
    CertificateDer::from_pem_slice(lx.egress.dialer.pki.ca_pem.as_bytes()).unwrap()
}

/// `CONNECT host:443` over `net.sock`; the stream after the `200`. The socket directory's path is
/// longer than `sun_path` allows, so the connect goes through an open descriptor of it.
pub(crate) async fn connect(sock: &Path, host: &str) -> UnixStream {
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
pub(crate) async fn tls(
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

pub(crate) fn allow_routes(lx: &Lx) -> Vec<(String, bool)> {
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

/// One request on a fresh `CONNECT host:443` + TLS: grant hosts verified against the session CA,
/// `mock2.test` (spliced) against the upstream's test CA. Everything the server sent back.
pub(crate) async fn over(lx: &Lx, tag: &str, host: &str, raw: &str) -> String {
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

pub(crate) fn get_req(host: &str, path: &str, extra: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n{extra}\r\n")
}

/// The values of every `name` header line in a raw request or response head.
pub(crate) fn header_values(raw: &str, name: &str) -> Vec<String> {
    let head = raw.split("\r\n\r\n").next().unwrap_or_default();
    head.split("\r\n")
        .filter_map(|l| {
            let (n, v) = l.split_once(':')?;
            n.eq_ignore_ascii_case(name).then(|| v.trim().to_owned())
        })
        .collect()
}

/// A response's body and its declared length.
pub(crate) fn body_and_length(resp: &str) -> (&str, usize) {
    let body = resp.split_once("\r\n\r\n").map_or("", |(_, b)| b);
    let n = header_values(resp, "content-length")[0].parse().unwrap();
    (body, n)
}

pub(crate) fn gh() -> String {
    common::egress::canary("GITHUB_TOKEN")
}

pub(crate) fn mock3() -> String {
    common::egress::canary("MOCK3_TOKEN")
}

pub(crate) fn git() -> String {
    common::egress::canary("GIT_TOKEN")
}

/// A response's body, its chunked framing removed if it has one.
fn decoded_body(resp: &str) -> String {
    let body = resp.split_once("\r\n\r\n").map_or("", |(_, b)| b);
    if header_values(resp, "transfer-encoding") != ["chunked"] {
        return body.to_owned();
    }
    let mut out = String::new();
    let mut rest = body;
    loop {
        let (size, after) = rest.split_once("\r\n").expect("a chunk size line");
        let n = usize::from_str_radix(size.split(';').next().unwrap().trim(), 16).unwrap();
        if n == 0 {
            return out;
        }
        let (Some(chunk), Some(tail)) = (after.get(..n), after.get(n..)) else {
            panic!("a chunk of {n} bytes, {} left: {resp}", after.len());
        };
        out.push_str(chunk);
        rest = tail.strip_prefix("\r\n").expect("CRLF after a chunk");
    }
}

/// Every string, object key and number in `v`, as text: what a search of an entry must cover
/// whatever JSON escaping its serialization applies (architect ruling A5 condition 3).
fn texts(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::String(s) => out.push(s.clone()),
        serde_json::Value::Number(n) => out.push(n.to_string()),
        serde_json::Value::Array(a) => a.iter().for_each(|x| texts(x, out)),
        serde_json::Value::Object(o) => {
            for (k, x) in o {
                out.push(k.clone());
                texts(x, out);
            }
        }
        serde_json::Value::Bool(_) | serde_json::Value::Null => {}
    }
}

/// The first credential RT-SEC-07's search finds in one audit entry, if any: the raw canaries
/// and `CANARY` in the entry's JSON text; `CANARY` and every one of `forms` in every decoded
/// string, key and number (so JSON escaping cannot hide one). The control and the absence
/// check run this one function.
pub(crate) fn credential_in(
    event: &str,
    args: &serde_json::Value,
    forms: &[String],
) -> Option<String> {
    let text = args.to_string();
    if text.contains(&gh()) || text.contains(&mock3()) || text.contains("CANARY") {
        return Some(format!("{event}: {text}"));
    }
    let mut decoded = vec![event.to_owned()];
    texts(args, &mut decoded);
    for t in &decoded {
        if t.contains("CANARY") {
            return Some(format!("{event}: {t}"));
        }
        if let Some(f) = forms.iter().find(|f| t.contains(f.as_str())) {
            return Some(format!("{event}: {f} in {t}"));
        }
    }
    None
}

/// The GitHub grant's rendered header value, the run an echo of it covers.
pub(crate) fn rendered() -> String {
    format!("Bearer {}", gh())
}

/// `upstream` as the sandbox must see it: each echo of the rendered value replaced by the
/// session's filler (`*`: no form of these canaries holds it), at its offset, at its length.
pub(crate) fn filled(upstream: &str) -> String {
    upstream.replace(&rendered(), &"*".repeat(rendered().len()))
}

/// The `egress.response` entries of a stopped session, by host.
pub(crate) fn responses(lx: &Lx, host: &str) -> Vec<serde_json::Value> {
    lx.events
        .all()
        .into_iter()
        .filter(|(e, a)| e == "egress.response" && a["host"] == host)
        .map(|(_, a)| a)
        .collect()
}

/// RT-SEC-12's checks of one `/echo-forms` exchange: `req` is what the grant host `host` (user
/// `user`) received, `forms` what the sandbox got back. Returns the decoded body.
pub(crate) fn check_echo_forms(host: &str, user: &str, req: &str, forms: &str) -> String {
    let fill = |n: usize| "*".repeat(n);
    let blob = basic_blob(user, &git());
    let rendered = format!("Basic {blob}");
    // Positive control: the grant host got the credential computed independently.
    assert_eq!(
        header_values(req, "authorization"),
        std::slice::from_ref(&rendered),
        "{host}"
    );
    assert!(forms.starts_with("HTTP/1.1 200 OK"), "{forms}");
    let body = decoded_body(forms);
    let upstream = echo_body(&git(), &blob, req);
    assert_eq!(body.len(), upstream.len(), "{host}: {body}");
    for (o, u) in body.bytes().zip(upstream.bytes()) {
        assert!(o == u || o == b'*', "{host}: {body}");
    }
    for f in forms_of(&git()).iter().chain(&basic_forms(user, &git())) {
        assert!(!body.contains(f.as_str()), "{host}: {f} in {body}");
    }
    let out_lines: Vec<&str> = body.split('\n').collect();
    for ((up, kind), out) in echo_lines(&git(), &blob).iter().zip(&out_lines) {
        let covered = match kind {
            Line::Whole => 0..up.len(),
            Line::Core(range) => range.clone(),
            Line::AllButLast => 0..up.len() - 1,
        };
        assert_eq!(out.len(), up.len(), "{host}: {out}");
        assert_eq!(
            &out[covered.clone()],
            fill(covered.len()),
            "{host}: {up} -> {out}"
        );
    }
    // The echoed request: the whole rendered value, `Basic ` included, is filler.
    let echoed = &body[body.len() - req.len()..];
    assert_eq!(
        header_values(echoed, "authorization"),
        [fill(rendered.len())]
    );
    body
}
