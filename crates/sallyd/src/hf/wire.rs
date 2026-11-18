//! The request each planned hop becomes, and the head values the decision reads back.
//!
//! A request carries exactly: `Host`, `User-Agent: sallyport`, `Accept-Encoding: identity`,
//! `Range: bytes=n-` when the plan asks for one, and `Authorization: Bearer …` only when the
//! plan says the hop carries the token. The header value is marked sensitive (kept out of
//! hyper's debug output and header compression); the text it is built in is wiped as it drops.
//! No cookie is ever sent or kept.

use http_body_util::Empty;
use hyper::body::Bytes;
use hyper::http::header::{
    ACCEPT_ENCODING, AUTHORIZATION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE, HOST,
    LOCATION, RANGE, RETRY_AFTER, USER_AGENT,
};
use hyper::http::{HeaderMap, HeaderName, HeaderValue, Method};
use sally_core::hf::head::Head;
use sally_core::hf::plan::Request;
use sally_core::secrets::Secret;
use zeroize::Zeroizing;

use super::PullError;

/// The agent string: the product name, nothing about the host or its user.
const AGENT: &str = "sallyport";

/// The hyper request for `req`, with the token when the hop carries it and one is set.
pub(super) fn build(
    req: &Request,
    token: Option<&Secret<String>>,
) -> Result<hyper::Request<Empty<Bytes>>, PullError> {
    let mut b = hyper::Request::builder()
        .method(Method::GET)
        .uri(req.path())
        .header(HOST, req.host())
        .header(USER_AGENT, AGENT)
        .header(ACCEPT_ENCODING, "identity");
    if let Some(from) = req.range_from() {
        b = b.header(RANGE, format!("bytes={from}-"));
    }
    if req.carries_auth()
        && let Some(t) = token
    {
        b = b.header(AUTHORIZATION, bearer(t)?);
    }
    b.body(Empty::new()).map_err(|_| PullError::Protocol)
}

/// `Bearer <token>`, sensitive.
fn bearer(token: &Secret<String>) -> Result<HeaderValue, PullError> {
    let text = Zeroizing::new(format!("Bearer {}", token.expose()));
    let mut v = HeaderValue::from_str(&text).map_err(|_| PullError::TokenUnusable)?;
    v.set_sensitive(true);
    Ok(v)
}

/// The values of a response head the decision reads, each taken from a single header line.
#[derive(Debug)]
pub(super) struct HeadValues {
    status: u16,
    content_length: Option<String>,
    content_range: Option<String>,
    location: Option<String>,
    retry_after: Option<String>,
    content_encoding: bool,
}

impl HeadValues {
    /// Reads them from a status and its headers.
    pub(super) fn of(status: u16, h: &HeaderMap) -> Result<Self, PullError> {
        Ok(Self {
            status,
            content_length: single(h, &CONTENT_LENGTH, "Content-Length")?,
            content_range: single(h, &CONTENT_RANGE, "Content-Range")?,
            location: single(h, &LOCATION, "Location")?,
            retry_after: single(h, &RETRY_AFTER, "Retry-After")?,
            content_encoding: h.contains_key(CONTENT_ENCODING),
        })
    }

    /// The borrowed form the decision takes.
    pub(super) fn head(&self) -> Head<'_> {
        Head {
            status: self.status,
            content_length: self.content_length.as_deref(),
            content_range: self.content_range.as_deref(),
            location: self.location.as_deref(),
            retry_after: self.retry_after.as_deref(),
            content_encoding: self.content_encoding,
        }
    }
}

/// The one value of `name`: `None` when absent; refused when repeated or not visible ASCII.
fn single(
    h: &HeaderMap,
    name: &HeaderName,
    label: &'static str,
) -> Result<Option<String>, PullError> {
    let mut all = h.get_all(name).iter();
    let Some(first) = all.next() else {
        return Ok(None);
    };
    if all.next().is_some() {
        return Err(PullError::HeaderInvalid(label));
    }
    first
        .to_str()
        .map(|s| Some(s.to_owned()))
        .map_err(|_| PullError::HeaderInvalid(label))
}

#[cfg(test)]
#[path = "wire_tests.rs"]
mod tests;
