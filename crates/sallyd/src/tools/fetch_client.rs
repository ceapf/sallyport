//! The `fetch` tool's client (#75; architect rulings Q1, Q5 and Q6): one request through the
//! session's own proxy over an in-memory [`Connector`] stream. `CONNECT host:port`; a reply
//! other than `200` is the proxy's refusal, read back as its reason code; after the `200`, TLS
//! with the configuration the connector chooses for the host (the session CA for an intercepted
//! host, the upstream roots for a spliced one), then one HTTP/1.1 exchange with hyper bounded like
//! the proxy's own upstream side, and at most `cap` body bytes. Whatever comes back after the
//! `200` is the response, a redirect included: nothing is followed, nothing decompressed. The
//! whole call is bounded by [`FETCH_TIMEOUT`]; past it the client half is dropped and the proxy
//! writes its own close entry.
#![deny(clippy::indexing_slicing)]

use http_body_util::{BodyExt as _, Full};
use hyper::body::Bytes;
use hyper::http::header::{CONTENT_LENGTH, HOST};
use hyper::http::{HeaderMap, Method, Request};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};
use tokio_rustls::TlsConnector;

use super::fetch::{FETCH_TIMEOUT, host_header};
use super::fetch_url::FetchUrl;
use crate::egress::local::Connector;
use crate::egress::policy::Reason;
use crate::egress::server::{REPLY_TIMEOUT, upstream_builder};

/// Longest reply head to `CONNECT` read back.
const MAX_REPLY_HEAD: usize = 1024;
/// Longest refusal body read back (a reason code and a newline).
const MAX_REFUSAL: u64 = 64;

/// What one exchange returned.
#[derive(Debug)]
pub struct Fetched {
    /// The response status.
    pub status: u16,
    /// The response headers, as the proxy passed them on (redacted for a grant host).
    pub headers: HeaderMap,
    /// At most `cap` body bytes.
    pub body: Vec<u8>,
    /// Whether the body went past `cap` and was cut.
    pub truncated: bool,
}

/// One request through the proxy; `None` is never returned for a refusal: every failure is a
/// code (`timeout`, the proxy's reason, `egress-unavailable`, `egress-refused`, `tls-failed`,
/// `upstream-failed`).
///
/// # Errors
/// The code.
pub async fn send(
    c: &dyn Connector,
    origin: Value,
    u: &FetchUrl,
    method: &str,
    headers: &[(String, String)],
    body: &[u8],
    cap: u64,
) -> Result<Fetched, &'static str> {
    tokio::time::timeout(
        FETCH_TIMEOUT,
        exchange(c, origin, u, method, headers, body, cap),
    )
    .await
    .unwrap_or(Err("timeout"))
}

async fn exchange(
    c: &dyn Connector,
    origin: Value,
    u: &FetchUrl,
    method: &str,
    headers: &[(String, String)],
    body: &[u8],
    cap: u64,
) -> Result<Fetched, &'static str> {
    let mut s = c.open(origin).map_err(|_| "egress-unavailable")?;
    let target = format!("{}:{}", u.host, u.port);
    s.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .map_err(|_| "egress-refused")?;
    let head = reply_head(&mut s).await;
    if !head.starts_with(b"HTTP/1.1 200 ") {
        return Err(refusal(&mut s).await);
    }
    let name = ServerName::try_from(u.host.clone()).map_err(|_| "bad-url")?;
    let tls = TlsConnector::from(c.client_tls(&u.host))
        .connect(name, s)
        .await
        .map_err(|_| "tls-failed")?;
    let (mut sender, conn) = upstream_builder()
        .handshake::<_, Full<Bytes>>(TokioIo::new(tls))
        .await
        .map_err(|_| "upstream-failed")?;
    let req = request(u, method, headers, body)?;
    let work = async move {
        let resp = sender
            .send_request(req)
            .await
            .map_err(|_| "upstream-failed")?;
        let status = resp.status().as_u16();
        let (parts, mut b) = resp.into_parts();
        let (kept, truncated) = read_capped(&mut b, cap).await?;
        Ok(Fetched {
            status,
            headers: parts.headers,
            body: kept,
            truncated,
        })
    };
    // The connection is driven beside the exchange and ends once the sender and the body are
    // gone, so neither outlives the call.
    let (out, _) = tokio::join!(work, conn);
    out
}

/// The request as bound: the canonical target, `Host` as the proxy expects it, the harness's
/// headers in order, and `Content-Length` unless a `GET` or `HEAD` sends nothing.
fn request(
    u: &FetchUrl,
    method: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<Request<Full<Bytes>>, &'static str> {
    let m = Method::from_bytes(method.as_bytes()).map_err(|_| "bad-arguments")?;
    let mut b = Request::builder()
        .method(m)
        .uri(u.target.as_str())
        .header(HOST, host_header(u));
    for (n, v) in headers {
        b = b.header(n.as_str(), v.as_str());
    }
    let bare = body.is_empty() && (method == "GET" || method == "HEAD");
    if !bare {
        b = b.header(CONTENT_LENGTH, body.len());
    }
    b.body(Full::new(Bytes::copy_from_slice(body)))
        .map_err(|_| "bad-arguments")
}

/// At most `cap` bytes of `b`, and whether it had more.
async fn read_capped<B>(b: &mut B, cap: u64) -> Result<(Vec<u8>, bool), &'static str>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
{
    let cap = usize::try_from(cap).unwrap_or(usize::MAX);
    let mut kept: Vec<u8> = Vec::new();
    while let Some(frame) = b.frame().await {
        let frame = frame.map_err(|_| "upstream-failed")?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        let room = cap.saturating_sub(kept.len());
        if data.len() > room {
            kept.extend_from_slice(data.get(..room).unwrap_or_default());
            return Ok((kept, true));
        }
        kept.extend_from_slice(&data);
    }
    Ok((kept, false))
}

/// The reply head to `CONNECT`, up to its blank line or [`MAX_REPLY_HEAD`] bytes.
async fn reply_head<S: AsyncRead + Unpin>(s: &mut S) -> Vec<u8> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && head.len() < MAX_REPLY_HEAD {
        match s.read(&mut byte).await {
            Ok(1) => head.extend_from_slice(&byte),
            _ => break,
        }
    }
    head
}

/// The proxy's reason from its refusal body, or `egress-refused`.
async fn refusal<S: AsyncRead + Unpin>(s: &mut S) -> &'static str {
    let mut body = Vec::new();
    // The proxy writes a refusal and closes within its reply timeout; a broken, short or late
    // read leaves what arrived, and anything unreadable is `egress-refused`.
    let mut limited = s.take(MAX_REFUSAL);
    let _ = tokio::time::timeout(REPLY_TIMEOUT, limited.read_to_end(&mut body)).await;
    std::str::from_utf8(&body)
        .ok()
        .and_then(|t| Reason::from_code(t.strip_suffix('\n').unwrap_or(t)))
        .map_or("egress-refused", Reason::as_str)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::tools::fetch_url;

    fn framing(method: &str, body: &[u8]) -> Option<String> {
        let u = fetch_url::parse("https://a.mock.test:8443/x?y").unwrap();
        let r = request(&u, method, &[("x-a".into(), "1".into())], body).unwrap();
        assert_eq!(r.uri(), "/x?y");
        assert_eq!(r.headers()[HOST], "a.mock.test:8443");
        assert_eq!(r.headers()["x-a"], "1");
        r.headers()
            .get(CONTENT_LENGTH)
            .map(|v| v.to_str().unwrap().to_owned())
    }

    #[test]
    fn only_a_get_or_head_without_a_body_goes_without_content_length() {
        assert_eq!(framing("GET", b""), None);
        assert_eq!(framing("HEAD", b""), None);
        assert_eq!(framing("GET", b"hi"), Some("2".into()));
        assert_eq!(framing("HEAD", b"hi"), Some("2".into()));
        assert_eq!(framing("POST", b""), Some("0".into()));
        assert_eq!(framing("DELETE", b"abc"), Some("3".into()));
    }

    #[tokio::test]
    async fn the_reply_head_ends_at_its_blank_line_or_the_bound() {
        let mut ok: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\nrest";
        assert_eq!(
            reply_head(&mut ok).await,
            b"HTTP/1.1 200 Connection Established\r\n\r\n"
        );
        assert_eq!(ok, b"rest", "nothing past the head is read");
        let long = vec![b'a'; MAX_REPLY_HEAD + 10];
        assert_eq!(reply_head(&mut long.as_slice()).await.len(), MAX_REPLY_HEAD);
        let mut short: &[u8] = b"HTTP/1.1 4";
        assert_eq!(reply_head(&mut short).await, b"HTTP/1.1 4");
    }

    #[tokio::test]
    async fn a_refusal_is_read_back_as_its_reason_or_egress_refused() {
        for (body, code) in [
            (&b"host-not-allowed\n"[..], "host-not-allowed"),
            (b"port-not-allowed", "port-not-allowed"),
            (b"Host-Not-Allowed\n", "egress-refused"),
            (b"anything else\n", "egress-refused"),
            (b"\xff\n", "egress-refused"),
            (b"", "egress-refused"),
        ] {
            let mut s = body;
            assert_eq!(refusal(&mut s).await, code, "{body:?}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_refusal_that_never_ends_is_read_for_the_reply_timeout_only() {
        let (mut ours, _theirs) = tokio::io::duplex(64);
        assert_eq!(refusal(&mut ours).await, "egress-refused");
    }
}
