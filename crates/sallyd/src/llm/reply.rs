//! Replies on `llm.sock`: the broker's own (before hyper is involved), the error body, the
//! model list, and the streamed body. Error bodies follow the OpenAI shape with the stable
//! reason as `code` and the field path as `param`.

use std::convert::Infallible;
use std::pin::Pin;
use std::task::{Context, Poll};

use http_body_util::Full;
use http_body_util::combinators::BoxBody;
use hyper::body::{Body, Bytes, Frame};
use serde_json::{Value, json};
use tokio::sync::mpsc;

/// The body type of every hyper response.
pub type Out = BoxBody<Bytes, Infallible>;

/// The reason phrase of the statuses this server sends.
#[must_use]
pub fn phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        408 => "Request Timeout",
        411 => "Length Required",
        413 => "Content Too Large",
        431 => "Request Header Fields Too Large",
        502 => "Bad Gateway",
        _ => "Error",
    }
}

/// The JSON error body for `reason` (and the field it names, if any).
#[must_use]
pub fn error_body(reason: &str, field: Option<&str>) -> Vec<u8> {
    let kind = if reason == "backend-error" {
        "server_error"
    } else {
        "invalid_request_error"
    };
    let v = json!({"error": {"message": reason, "type": kind, "code": reason, "param": field}});
    serde_json::to_vec(&v).unwrap_or_default()
}

/// A whole response written by the broker itself, closing the connection after it.
#[must_use]
pub fn raw(status: u16, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        phrase(status),
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

/// A JSON response through hyper.
#[must_use]
pub fn json_response(status: u16, body: Vec<u8>) -> hyper::Response<Out> {
    let mut r = hyper::Response::new(BoxBody::new(Full::new(Bytes::from(body))));
    *r.status_mut() = hyper::StatusCode::from_u16(status).unwrap_or(hyper::StatusCode::BAD_GATEWAY);
    r.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/json"),
    );
    r
}

/// An event-stream response whose body is fed by `rx`.
#[must_use]
pub fn stream_response(rx: mpsc::Receiver<Bytes>) -> hyper::Response<Out> {
    let mut r = hyper::Response::new(BoxBody::new(Channel(rx)));
    r.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("text/event-stream"),
    );
    r.headers_mut().insert(
        hyper::header::CACHE_CONTROL,
        hyper::header::HeaderValue::from_static("no-cache"),
    );
    r
}

/// The `GET /v1/models` body: the session's one model.
#[must_use]
pub fn models(model: &str) -> Vec<u8> {
    let v = json!({"object": "list", "data": [
        {"id": model, "object": "model", "created": 0, "owned_by": "sallyport"}
    ]});
    serde_json::to_vec(&v).unwrap_or_default()
}

/// One server-sent event carrying `v`.
#[must_use]
pub fn event(v: &Value) -> Bytes {
    let mut b = b"data: ".to_vec();
    b.extend_from_slice(&serde_json::to_vec(v).unwrap_or_default());
    b.extend_from_slice(b"\n\n");
    Bytes::from(b)
}

/// The event that ends a stream.
pub const DONE: &[u8] = b"data: [DONE]\n\n";

/// A body fed by a channel: it ends when the sender is dropped.
struct Channel(mpsc::Receiver<Bytes>);

impl Body for Channel {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        self.get_mut()
            .0
            .poll_recv(cx)
            .map(|b| b.map(|b| Ok(Frame::data(b))))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn raw_replies_are_complete_and_close() {
        let r = String::from_utf8(raw(404, b"{}")).unwrap();
        assert_eq!(
            r,
            "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"
        );
    }

    #[test]
    fn phrases_cover_every_status_sent() {
        for (s, p) in [
            (200, "OK"),
            (400, "Bad Request"),
            (404, "Not Found"),
            (408, "Request Timeout"),
            (411, "Length Required"),
            (413, "Content Too Large"),
            (431, "Request Header Fields Too Large"),
            (502, "Bad Gateway"),
            (599, "Error"),
        ] {
            assert_eq!(phrase(s), p);
        }
    }

    #[test]
    fn error_bodies_name_the_reason_and_field() {
        let v: Value =
            serde_json::from_slice(&error_body("unknown-field", Some("logit_bias"))).unwrap();
        assert_eq!(
            v,
            json!({"error": {"message": "unknown-field", "type": "invalid_request_error", "code": "unknown-field", "param": "logit_bias"}})
        );
        let v: Value = serde_json::from_slice(&error_body("backend-error", None)).unwrap();
        assert_eq!(v["error"]["type"], json!("server_error"));
        assert_eq!(v["error"]["param"], Value::Null);
    }

    #[test]
    fn events_are_sse_frames() {
        assert_eq!(&event(&json!({"a": 1}))[..], b"data: {\"a\":1}\n\n");
        let v: Value = serde_json::from_slice(&models("m")).unwrap();
        assert_eq!(v["data"][0]["id"], json!("m"));
    }
}
