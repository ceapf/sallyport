//! Request and response heads inside an intercepted tunnel (Task 9a-2, decision 5, architect
//! Q29/Q30/Q41). Pure: each function reads a head hyper already parsed and returns the head to
//! send on, or the reason it is refused. No secret reaches this module (Q27): the grant headers
//! arrive as names only.
//!
//! Request order (Q41): check the head as received, drop, then rebuild `Host` from the CONNECT
//! authority. Task 9a-3 sets the injected header last, so a `Connection` token can never remove
//! what the proxy adds.

use hyper::http::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::http::{Method, StatusCode, Uri, Version};

use super::authority::{self, Authority, HostHeaderError};
use super::policy::Reason;

/// Request headers dropped on the way upstream, besides `Connection`'s own tokens, every
/// `Proxy-*` header and the grant headers (Q41). Framing (`Transfer-Encoding`, `Content-Length`)
/// is dropped too: hyper's client frames the body it sends.
const REQUEST_DROPPED: [HeaderName; 10] = [
    header::CONNECTION,
    HeaderName::from_static("keep-alive"),
    header::TE,
    header::TRAILER,
    header::EXPECT,
    header::ACCEPT_ENCODING,
    header::TRANSFER_ENCODING,
    header::CONTENT_LENGTH,
    header::HOST,
    header::UPGRADE,
];

/// Response headers dropped on the way to the client, besides `Connection`'s own tokens and
/// every `Proxy-*` header. `Content-Length` stays (hyper's server frames with it).
const RESPONSE_DROPPED: [HeaderName; 6] = [
    header::CONNECTION,
    HeaderName::from_static("keep-alive"),
    header::TE,
    header::TRAILER,
    header::TRANSFER_ENCODING,
    header::UPGRADE,
];

/// The one `Expect` value a request may carry.
const CONTINUE: &str = "100-continue";

/// What a checked request head carries on: its headers, and its body length when it gave one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The headers to send upstream.
    pub headers: HeaderMap,
    /// The declared `Content-Length`, if any (a chunked body has none).
    pub length: Option<u64>,
}

/// Checks a request head received in the tunnel to `connect` and builds the one sent upstream.
/// `grants` are the lower-case header names of the host's secret grants.
///
/// # Errors
/// In this order: [`Reason::Malformed`] for the request line (`CONNECT`, not HTTP/1.1, a target
/// other than origin-form); [`Reason::Malformed`] or [`Reason::HostMismatch`] for `Host` (absent,
/// several, or naming another authority); [`Reason::MethodRefused`] for `TRACE`;
/// [`Reason::UpgradeRefused`]; [`Reason::Malformed`] for bad framing or an `Expect` other than
/// `100-continue`. Methods match ASCII case-insensitively.
pub fn request(
    method: &Method,
    version: Version,
    uri: &Uri,
    headers: &HeaderMap,
    connect: &Authority,
    grants: &[String],
) -> Result<Request, Reason> {
    if is_method(method, &Method::CONNECT) || version != Version::HTTP_11 || !origin_form(uri) {
        return Err(Reason::Malformed);
    }
    check_host(headers, connect)?;
    if is_method(method, &Method::TRACE) {
        return Err(Reason::MethodRefused);
    }
    if asks_upgrade(headers) {
        return Err(Reason::UpgradeRefused);
    }
    let length = framing(headers)?;
    check_expect(headers)?;
    let named = connection_tokens(headers);
    let mut out = HeaderMap::with_capacity(headers.len());
    for (name, value) in headers {
        let dropped = REQUEST_DROPPED.contains(name)
            || is_proxy_header(name)
            || named.iter().any(|n| n == name.as_str())
            || grants.iter().any(|g| g == name.as_str());
        if !dropped {
            out.append(name.clone(), value.clone());
        }
    }
    let host =
        HeaderValue::from_str(&authority::upstream_host(connect)).map_err(|_| Reason::Malformed)?;
    out.insert(header::HOST, host);
    Ok(Request {
        headers: out,
        length,
    })
}

/// Checks a response head from the upstream and builds the one sent to the client.
///
/// The client always gets a head without `Transfer-Encoding`: hyper's server frames the body.
///
/// # Errors
/// [`Reason::UpstreamEncoded`] for `101`, a `Content-Encoding` other than absent or one
/// `identity`, or a `Transfer-Encoding` other than absent or one `chunked` (Q30); then
/// [`Reason::UpstreamMalformed`] for `Transfer-Encoding` beside `Content-Length`, or a
/// `Content-Length` other than one decimal value (two lines, or a list such as `6, 6`, which
/// hyper accepts when the values agree: architect ruling R4, 9a-2 review).
pub fn response(status: StatusCode, headers: &HeaderMap) -> Result<HeaderMap, Reason> {
    if status == StatusCode::SWITCHING_PROTOCOLS || headers.contains_key(header::UPGRADE) {
        return Err(Reason::UpstreamEncoded);
    }
    if !at_most_one_equal(headers, &header::CONTENT_ENCODING, "identity")
        || !at_most_one_equal(headers, &header::TRANSFER_ENCODING, "chunked")
    {
        return Err(Reason::UpstreamEncoded);
    }
    if headers.contains_key(header::CONTENT_LENGTH)
        && (declared_length(headers).is_none() || headers.contains_key(header::TRANSFER_ENCODING))
    {
        return Err(Reason::UpstreamMalformed);
    }
    let named = connection_tokens(headers);
    let mut out = HeaderMap::with_capacity(headers.len());
    for (name, value) in headers {
        let dropped = RESPONSE_DROPPED.contains(name)
            || is_proxy_header(name)
            || named.iter().any(|n| n == name.as_str());
        if !dropped {
            out.append(name.clone(), value.clone());
        }
    }
    Ok(out)
}

/// The declared body length of a head, if it has exactly one decimal `Content-Length`.
#[must_use]
pub fn declared_length(headers: &HeaderMap) -> Option<u64> {
    let mut all = headers.get_all(header::CONTENT_LENGTH).iter();
    let first = all.next()?;
    if all.next().is_some() {
        return None;
    }
    decimal(first.as_bytes())
}

/// Whether a body of `declared` bytes is within `cap` (at the cap passes, Q49).
#[must_use]
pub fn within(declared: Option<u64>, cap: u64) -> bool {
    declared.is_none_or(|n| n <= cap)
}

/// Origin-form only: a path starting with `/`, no scheme and no authority (Q29). `*` and the
/// absolute and authority forms are refused.
fn origin_form(uri: &Uri) -> bool {
    uri.scheme().is_none()
        && uri.authority().is_none()
        && uri
            .path_and_query()
            .is_some_and(|p| p.as_str().starts_with('/'))
}

/// Whether `method` is `want`, ASCII case-insensitively (an upstream may treat `trace` as
/// `TRACE`).
fn is_method(method: &Method, want: &Method) -> bool {
    method.as_str().eq_ignore_ascii_case(want.as_str())
}

/// Exactly one `Host`, naming the CONNECT authority (Q29).
fn check_host(headers: &HeaderMap, connect: &Authority) -> Result<(), Reason> {
    let mut all = headers.get_all(header::HOST).iter();
    let (Some(host), None) = (all.next(), all.next()) else {
        return Err(Reason::Malformed);
    };
    authority::host_header(host.as_bytes(), connect).map_err(|e| match e {
        HostHeaderError::Malformed => Reason::Malformed,
        HostHeaderError::Mismatch => Reason::HostMismatch,
    })
}

/// Any `Upgrade` or `HTTP2-Settings` header, or a `Connection` token `upgrade` (Q41).
fn asks_upgrade(headers: &HeaderMap) -> bool {
    headers.contains_key(header::UPGRADE)
        || headers.contains_key("http2-settings")
        || connection_tokens(headers).iter().any(|t| t == "upgrade")
}

/// The request's framing (Q41): `Transfer-Encoding` must be absent or one `chunked`, never
/// beside `Content-Length`; `Content-Length` at most once and decimal. Returns the length.
fn framing(headers: &HeaderMap) -> Result<Option<u64>, Reason> {
    let te = headers.get_all(header::TRANSFER_ENCODING).iter().count();
    let cl = headers.get_all(header::CONTENT_LENGTH).iter().count();
    match (te, cl) {
        (0, 0) => Ok(None),
        (1, 0) if at_most_one_equal(headers, &header::TRANSFER_ENCODING, "chunked") => Ok(None),
        (0, 1) => declared_length(headers).map(Some).ok_or(Reason::Malformed),
        _ => Err(Reason::Malformed),
    }
}

/// `Expect` absent, or one `100-continue` (Q41).
fn check_expect(headers: &HeaderMap) -> Result<(), Reason> {
    if at_most_one_equal(headers, &header::EXPECT, CONTINUE) {
        Ok(())
    } else {
        Err(Reason::Malformed)
    }
}

/// Whether `name` is absent, or present once with the value `want` (ASCII case-insensitive).
fn at_most_one_equal(headers: &HeaderMap, name: &HeaderName, want: &str) -> bool {
    let mut all = headers.get_all(name).iter();
    match (all.next(), all.next()) {
        (None, _) => true,
        (Some(v), None) => v.as_bytes().eq_ignore_ascii_case(want.as_bytes()),
        (Some(_), Some(_)) => false,
    }
}

/// The lower-case tokens of every `Connection` header.
fn connection_tokens(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(header::CONNECTION)
        .iter()
        .flat_map(|v| v.as_bytes().split(|&b| b == b','))
        .map(|t| String::from_utf8_lossy(t.trim_ascii()).to_ascii_lowercase())
        .filter(|t| !t.is_empty())
        .collect()
}

/// `Proxy-*` (Q41: every one, not only `Proxy-Authorization` and `Proxy-Connection`).
fn is_proxy_header(name: &HeaderName) -> bool {
    name.as_str().starts_with("proxy-")
}

/// Decimal digits only, as a `u64`.
fn decimal(b: &[u8]) -> Option<u64> {
    if b.is_empty() || !b.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(b).ok()?.parse().ok()
}

#[cfg(test)]
#[path = "rewrite_tests.rs"]
mod tests;
