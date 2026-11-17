//! The free helpers of an intercepted tunnel (#179): the body-end hooks, the hyper builders on
//! either side, the reply to a refusal inside the tunnel and the builders of its audit entries.
//!
//! This file holds no `Proxy` method and decides no order of audit and reply: the state machine
//! in `intercept.rs` calls each of these and keeps that order (architect Q3).

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hyper::body::{Bytes, Incoming};
use hyper::http::{HeaderValue, Method, Request, Response, StatusCode, Version, header};
use hyper_util::rt::TokioTimer;
use sally_core::audit::NewEntry;
use serde_json::json;

use crate::egress::authority::{Authority, TARGET_STYLE, own_masked, with_target};
use crate::egress::head::MAX_HEAD;
use crate::egress::meter::{BodyEnd, BoxError, Capped, OnEnd};
use crate::egress::policy::Reason;
use crate::egress::redact::Redaction;
use crate::egress::tunnel::End;

use super::{MAX_HEADERS, MAX_RESPONSE_HEAD, Out, REQUEST_READ, RESPONSE_READ, State};

/// An `egress.limit` entry a body's end appends, at most once.
type HeldEntry = Mutex<Option<(NewEntry, Arc<dyn crate::sandbox::AuditSink>)>>;
/// What [`OnEnd::ended`] returns: the work that must finish before the body reports its cut.
type BeforeCut = Option<std::pin::Pin<Box<dyn Future<Output = ()> + Send>>>;

/// Appends the held entry (the first call only); the returned future finishes with the append.
/// A failed or panicked append marks the tunnel's end `error` (architect ruling RQ2).
fn append_held(
    held: &HeldEntry,
    level: sally_core::manifest::AuditLevel,
    st: &Arc<State>,
) -> BeforeCut {
    let (entry, sink) = held.lock().ok()?.take()?;
    // TODO(#72): on a session stop this append may land after `egress.close`.
    let h = tokio::task::spawn_blocking(move || sink.append(entry, level));
    let st = Arc::clone(st);
    Some(Box::pin(async move {
        // TODO(#49): log a limit entry that could not be written; the cut happens regardless.
        if !matches!(h.await, Ok(Ok(()))) {
            st.held_failed.store(true, Ordering::Relaxed);
        }
    }))
}

/// The request body's end (Q35; architect rulings R2 and R3). Past the cap: the tunnel ends
/// `limit` at once, and `egress.limit request-too-large` is appended before hyper's client sees
/// the cut, whether or not a response head was already forwarded (the 413, when there is one,
/// adds no second entry). A body the client broke off ends the tunnel `closed`: no entry, no
/// reply.
pub(super) struct RequestEnd {
    pub(super) state: Arc<State>,
    pub(super) limit: HeldEntry,
    pub(super) level: sally_core::manifest::AuditLevel,
}

impl OnEnd for RequestEnd {
    fn ended(&self, how: Option<BodyEnd>) -> BeforeCut {
        match how {
            Some(BodyEnd::OverCap) => {
                self.state.request_over.store(true, Ordering::Relaxed);
                self.state.set_end(End::Limit);
                append_held(&self.limit, self.level, &self.state)
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
pub(super) struct ResponseEnd {
    pub(super) state: Arc<State>,
    pub(super) limit: HeldEntry,
    pub(super) level: sally_core::manifest::AuditLevel,
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
                append_held(&self.limit, self.level, &self.state)
            }
        }
    }
}

/// The upstream side of an intercepted tunnel, one request at a time.
pub(super) type Sender =
    tokio::sync::Mutex<hyper::client::conn::http1::SendRequest<Capped<Incoming>>>;

/// The request sent upstream: the client's method, its origin-form target, HTTP/1.1, and the
/// rewritten headers.
pub(super) fn upstream_request(
    body: Capped<Incoming>,
    parts: hyper::http::request::Parts,
    headers: hyper::http::HeaderMap,
) -> Result<Request<Capped<Incoming>>, BoxError> {
    let mut up = Request::new(body);
    *up.method_mut() = parts.method;
    *up.uri_mut() = parts
        .uri
        .path_and_query()
        .map_or_else(|| "/".parse(), |p| p.as_str().parse())?;
    *up.version_mut() = Version::HTTP_11;
    *up.headers_mut() = headers;
    Ok(up)
}

/// hyper's client toward the upstream: response heads up to `MAX_RESPONSE_HEAD - RESPONSE_READ`
/// bytes (exact) and `MAX_HEADERS` lines. The `fetch` tool parses with it too (architect ruling
/// Q5): on a spliced host it is the only parser of the upstream's bytes.
#[must_use]
pub fn upstream_builder() -> hyper::client::conn::http1::Builder {
    let mut b = hyper::client::conn::http1::Builder::new();
    b.max_buf_size(MAX_RESPONSE_HEAD)
        .max_header_size(MAX_RESPONSE_HEAD - RESPONSE_READ)
        .max_headers(MAX_HEADERS);
    b
}

/// hyper's server toward the client: request heads up to `MAX_HEAD - REQUEST_READ` bytes (exact)
/// and `MAX_HEADERS` lines, each awaited for at most `head`. Half-close as in a spliced tunnel: a
/// client that shuts its sending side after the request still gets the response.
pub(super) fn client_builder(head: Duration) -> hyper::server::conn::http1::Builder {
    let mut b = hyper::server::conn::http1::Builder::new();
    b.half_close(true)
        .timer(TokioTimer::new())
        .header_read_timeout(head)
        .max_buf_size(MAX_HEAD)
        .max_header_size(MAX_HEAD - REQUEST_READ)
        .max_headers(MAX_HEADERS);
    b
}

/// The reply to a refusal inside the tunnel: as Task 8's [`super::super::reply`], closing the tunnel.
pub(super) fn reply_response(reason: Reason) -> Response<Out> {
    let body = format!("{}\n", reason.as_str());
    let mut r = Response::new(Out::Reply(Some(Bytes::from(body))));
    *r.status_mut() = StatusCode::from_u16(reason.status()).unwrap_or(StatusCode::BAD_GATEWAY);
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    h.insert(header::CONNECTION, HeaderValue::from_static("close"));
    r
}

/// Arguments of `egress.request` (Q34): `injected` lists the grants set on the request as
/// `egress.request` (Q34): `injected` lists the grants set on the request as `secret:NAME`,
/// never a value (Task 9a-3, architect D9, D13). The method and target are the sandbox's text,
/// declared masked with the session's own forms; the writer masks them with every live
/// session's forms before it cuts and escapes them (architect Q253, Q276). The method is cut to
/// 256 bytes like the target, but the entry does not say it was (Q256).
pub(crate) fn request_entry(
    e: NewEntry,
    a: &Authority,
    method: &Method,
    target: &str,
    injected: &[String],
    r: &Redaction,
) -> NewEntry {
    let args = json!({
        "host": a.host,
        "port": a.port,
        "injected": injected,
    });
    let method = own_masked(method.as_str(), Some(r.audit()));
    with_target(e, args, target, Some(r.audit())).text("method", method, TARGET_STYLE)
}

/// A refusal inside the tunnel (Q34): reason, host, port, and the target declared as
/// [`with_target`] does.
pub(super) fn inside_entry(
    e: NewEntry,
    a: &Authority,
    reason: Reason,
    target: &str,
    part: Option<&str>,
    r: &Redaction,
) -> NewEntry {
    let mut v = json!({
        "reason": reason.as_str(),
        "host": a.host,
        "port": a.port,
    });
    if let (Some(obj), Some(p)) = (v.as_object_mut(), part) {
        obj.insert("part".into(), json!(p));
    }
    with_target(e, v, target, Some(r.audit()))
}
