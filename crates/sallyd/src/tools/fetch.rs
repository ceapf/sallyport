//! The `fetch` tool's decisions (#75; ARCHITECTURE §4.3; architect rulings Q3–Q5, Q13). Pure:
//! what a call may send, how big its head gets, and what of a response the harness gets back.
//! The request itself goes through the session's own proxy (`fetch_client.rs`, `egress/local.rs`),
//! so the egress policy, the injection and the redaction stay in one copy.
//!
//! - **Request** ([`check`]): the URL ([`super::fetch_url`]); a method of 1 to [`MAX_METHOD`]
//!   upper-case letters, never `CONNECT` or `TRACE`; at most [`MAX_HEADERS`] headers, each a
//!   token name and a value of visible ASCII, spaces and tabs (no leading or trailing blank);
//!   no header the proxy would drop or refuse (its own predicate, plus `HTTP2-Settings` and the
//!   host's grant header names), so the ticket never shows a header that is not sent; a body of at
//!   most `network.max_request_bytes`; and a head that fits [`MAX_REQUEST_HEAD`] as sent.
//! - **Response** ([`reply`]): the status, the headers of [`REPLY_HEADERS`] (at most
//!   [`MAX_REPLY_HEADERS`], a value over [`MAX_REPLY_VALUE`] left out), and at most
//!   [`response_cap`] body bytes, as UTF-8 text or base64. A redirect is returned, never
//!   followed; nothing is decompressed.

use std::time::Duration;

use base64::Engine as _;
use hyper::http::HeaderMap;
use hyper::http::header::HeaderName;
use serde_json::{Value, json};

use super::args::BAD;
use super::fetch_url::{self, FetchUrl};
use crate::egress::authority::{self, Authority};
use crate::egress::rewrite::dropped_request_header;
use crate::egress::server::MAX_REQUEST_HEAD;

/// Longest method.
pub const MAX_METHOD: usize = 16;
/// Most request headers a call may give.
pub const MAX_HEADERS: usize = 64;
/// Most response body bytes a call returns.
pub const BODY_CAP: u64 = 1 << 20;
/// Most response headers a call returns.
pub const MAX_REPLY_HEADERS: usize = 32;
/// Longest response header value returned; a longer one is left out, never cut.
pub const MAX_REPLY_VALUE: usize = 1024;
/// One call, from `CONNECT` to the last body byte; past it the call fails `timeout`.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(60);

/// Response headers returned to the harness, lower-case.
pub const REPLY_HEADERS: [&str; 12] = [
    "cache-control",
    "content-encoding",
    "content-language",
    "content-length",
    "content-type",
    "date",
    "etag",
    "expires",
    "last-modified",
    "location",
    "retry-after",
    "www-authenticate",
];

/// Refused besides what the proxy drops: meaningless without the `Upgrade` the proxy refuses.
const REFUSED: [&str; 1] = ["http2-settings"];

/// Checks a call: its URL, then method, headers, body size and head size. `grants` are the
/// target host's grant header names (lower-case); `max_body` is `network.max_request_bytes`.
///
/// # Errors
/// The URL's code ([`fetch_url::UrlError::code`]), [`BAD`], `request-too-large` or
/// `head-too-large`.
pub fn check(
    url: &str,
    method: &str,
    headers: &[(String, String)],
    body_len: u64,
    max_body: u64,
    grants: &[String],
) -> Result<FetchUrl, &'static str> {
    let u = fetch_url::parse(url).map_err(fetch_url::UrlError::code)?;
    if !method_ok(method) || headers.len() > MAX_HEADERS {
        return Err(BAD);
    }
    if !headers.iter().all(|(n, v)| header_ok(n, v, grants)) {
        return Err(BAD);
    }
    if body_len > max_body {
        return Err("request-too-large");
    }
    if head_len(method, &u, headers, body_len) > MAX_REQUEST_HEAD {
        return Err("head-too-large");
    }
    Ok(u)
}

/// 1 to [`MAX_METHOD`] upper-case ASCII letters; not `CONNECT` or `TRACE`.
fn method_ok(m: &str) -> bool {
    (1..=MAX_METHOD).contains(&m.len())
        && m.bytes().all(|b| b.is_ascii_uppercase())
        && m != "CONNECT"
        && m != "TRACE"
}

/// A token name the proxy forwards, and a value of visible ASCII, spaces and tabs with no
/// leading or trailing blank.
fn header_ok(name: &str, value: &str, grants: &[String]) -> bool {
    let token = !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b));
    let Ok(parsed) = HeaderName::from_bytes(name.as_bytes()) else {
        return false;
    };
    let blank = |b: u8| b == b' ' || b == b'\t';
    let v = value.as_bytes();
    let value_ok = v.iter().all(|&b| blank(b) || (0x21..=0x7e).contains(&b))
        && !v.first().is_some_and(|&b| blank(b))
        && !v.last().is_some_and(|&b| blank(b));
    token
        && value_ok
        && !dropped_request_header(&parsed, grants)
        && !REFUSED.contains(&parsed.as_str())
}

/// The head the call sends, in bytes, at least as large as hyper writes it: the request line,
/// `Host`, the harness's headers and a `Content-Length` line, then the blank line.
#[must_use]
pub fn head_len(method: &str, u: &FetchUrl, headers: &[(String, String)], body_len: u64) -> usize {
    let host = host_header(u);
    let line = method.len() + 1 + u.target.len() + " HTTP/1.1\r\n".len();
    let fields: usize = headers.iter().map(|(n, v)| n.len() + 2 + v.len() + 2).sum();
    let length = "content-length: ".len() + body_len.to_string().len() + 2;
    line + "host: ".len() + host.len() + 2 + fields + length + 2
}

/// The `Host` value the proxy expects for `u` (its own spelling of the authority).
#[must_use]
pub fn host_header(u: &FetchUrl) -> String {
    authority::upstream_host(&Authority {
        host: u.host.clone(),
        port: u.port,
    })
}

/// Most body bytes returned: [`BODY_CAP`] or `network.max_response_bytes`, whichever is lower.
#[must_use]
pub fn response_cap(max_response: u64) -> u64 {
    BODY_CAP.min(max_response)
}

/// The response headers returned: those of [`REPLY_HEADERS`] whose value is text of at most
/// [`MAX_REPLY_VALUE`] bytes, in order, at most [`MAX_REPLY_HEADERS`].
#[must_use]
pub fn reply_headers(h: &HeaderMap) -> Vec<(String, String)> {
    h.iter()
        .filter(|(n, _)| REPLY_HEADERS.contains(&n.as_str()))
        .filter_map(|(n, v)| {
            let text = v.to_str().ok()?;
            (text.len() <= MAX_REPLY_VALUE).then(|| (n.as_str().to_owned(), text.to_owned()))
        })
        .take(MAX_REPLY_HEADERS)
        .collect()
}

/// The reply body: status, headers, the body as UTF-8 or base64, its length and whether it was
/// cut at the cap.
#[must_use]
pub fn reply(status: u16, headers: &[(String, String)], body: Vec<u8>, truncated: bool) -> Value {
    let bytes = body.len();
    let (encoding, text) = match String::from_utf8(body) {
        Ok(s) => ("utf-8", s),
        Err(e) => (
            "base64",
            base64::engine::general_purpose::STANDARD.encode(e.into_bytes()),
        ),
    };
    json!({
        "status": status, "headers": headers, "encoding": encoding, "body": text,
        "bytes": bytes, "truncated": truncated,
    })
}

#[cfg(test)]
#[path = "fetch_tests.rs"]
mod tests;
