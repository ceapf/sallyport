//! The `llm.sock` server (AMENDMENTS-01 §3.2; Task 7 decisions 1, 2 and 5). HTTP/1.1 through
//! hyper, one request per connection (keep-alive off).
//!
//! Per connection (architect rulings Q8, Q9): the broker reads the head itself (at most
//! [`head::MAX_HEAD`], within [`HEAD_TIMEOUT`]), waits for a rate token, checks the route and the
//! body framing, and answers every refusal itself after its `llm.deny` entry. Only a request it
//! accepts goes to hyper, which replays the head ([`io::Io`]); hyper's writes stay gated until
//! the service has written an entry, so a request hyper refuses by itself is closed unanswered
//! and recorded `http-error`. Every decision is made on the broker's one parse: a request hyper
//! reads differently ([`agrees`]) is closed unanswered and recorded `head-mismatch`. The service
//! reads the body (at most [`body::MAX_BODY`], within [`BODY_TIMEOUT`]), checks it
//! ([`body::check`]), records `llm.request`, and only then calls the backend. `llm.response` (detail) follows the reply, like `egress.close`. A failed append
//! closes the connection without a reply or a backend call.
//!
//! The backend is a constructor argument (Task 7 decision 2). Until M3 none is wired in
//! production; the scripted mock model lives in the test tree (architect ruling Q3).
// TODO(#53): Task 12 wires no backend (llm.sock not served) until M3; never the test mock.

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http_body_util::{BodyExt, LengthLimitError, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use sally_core::audit::{Actor, Detail, NewEntry};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::{mpsc, watch};

use super::body::{self, Chat};
use super::head::{self, Head, Parsed};
use super::io::{Gate, Io};
use super::reply::{self, Out};
use crate::rpc::listen::{self, Server, until_true};
use crate::rpc::rate::Rate;
use crate::rpc::record::{Recorder, escape};

/// Connections per session at once (architect Q8).
pub const MAX_CONNECTIONS: usize = 4;
/// Time a client gets to send its request head (architect Q8).
pub const HEAD_TIMEOUT: Duration = Duration::from_secs(10);
/// Time a client gets to send its body (architect Q8).
pub const BODY_TIMEOUT: Duration = Duration::from_secs(30);
/// Time a write may stay pending before the connection fails (architect Q8).
pub const WRITE_STALL: Duration = Duration::from_secs(10);
/// Requests read per second per session, on average (architect Q8).
pub const RATE: u32 = 5;
/// Requests read back to back per session at most (architect Q8).
pub const BURST: u32 = 10;
/// Bytes of one reply body at most; a longer stream is cut.
pub const MAX_RESPONSE: usize = 16 * 1024 * 1024;
/// Events buffered between the backend and the peer.
const STREAM_BUFFER: usize = 16;
/// Bytes read at a time while the head is incomplete.
const READ_CHUNK: usize = 4096;

/// What answers a checked chat request: the model (M3), or the scripted mock model in tests.
pub trait Backend: Send + Sync + 'static {
    /// Completes `chat`; it must hold `chat.max_tokens`.
    fn complete(&self, chat: Chat) -> impl Future<Output = Result<Reply, BackendError>> + Send;
}

/// A backend's answer.
#[derive(Debug)]
pub enum Reply {
    /// One chat-completion object.
    Whole(Value),
    /// Chunk objects, sent as server-sent events, then `[DONE]`.
    Stream(mpsc::Receiver<Value>),
}

/// The backend failed (answered 502).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the model backend failed")]
pub struct BackendError;

/// A session's model settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// The model id `GET /v1/models` names.
    pub model: String,
    /// `model.context`: the bound on the token limit (architect Q2).
    pub context: u64,
}

/// The two routes served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Route {
    Models,
    Chat,
}

/// The connection was closed without a reply (a failed append).
#[derive(Debug)]
struct Closed;

impl std::fmt::Display for Closed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("closed")
    }
}

impl std::error::Error for Closed {}

/// One session's `llm.sock` server.
pub struct Llm<B> {
    backend: Arc<B>,
    record: Recorder,
    settings: Settings,
    rate: Mutex<Rate>,
    stop: watch::Sender<bool>,
}

impl<B: Backend> Llm<B> {
    /// A server for one session.
    #[must_use]
    pub fn new(backend: B, record: Recorder, settings: Settings) -> Self {
        Self {
            backend: Arc::new(backend),
            record,
            settings,
            rate: Mutex::new(Rate::new(RATE, BURST)),
            stop: watch::Sender::new(false),
        }
    }

    /// Serves `listener` (the session's `llm.sock`) for peers with `uid`.
    pub fn listen(self: Arc<Self>, listener: tokio::net::UnixListener, uid: u32) -> listen::Handle {
        listen::spawn(listener, self, MAX_CONNECTIONS, uid)
    }

    /// Serves one connection to its end, or until the server stops.
    pub async fn serve_stream<S>(self: Arc<Self>, stream: S)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let stopped = until_true(self.stop.subscribe());
        tokio::select! {
            biased;
            () = stopped => {}
            () = Arc::clone(&self).connection(stream) => {}
        }
    }

    async fn connection<S>(self: Arc<Self>, mut stream: S)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut buf = Vec::with_capacity(READ_CHUNK);
        let h = match tokio::time::timeout(HEAD_TIMEOUT, read_head(&mut stream, &mut buf)).await {
            Err(_) => return self.refuse(&mut stream, None, "head-timeout", None).await,
            Ok(None) if buf.is_empty() => return,
            Ok(None) => {
                return self
                    .refuse(&mut stream, None, "incomplete-head", None)
                    .await;
            }
            Ok(Some(Parsed::TooLarge)) => {
                return self
                    .refuse(&mut stream, Some(431), "head-too-large", None)
                    .await;
            }
            Ok(Some(Parsed::Refused(r))) => {
                return self.refuse(&mut stream, Some(400), r, None).await;
            }
            Ok(Some(Parsed::Complete(h))) => h,
            Ok(Some(Parsed::Partial)) => return,
        };
        self.throttle().await;
        let route = match (h.method.as_str(), h.path.as_str()) {
            ("GET", "/v1/models") => Route::Models,
            ("POST", "/v1/chat/completions") => Route::Chat,
            _ => {
                return self
                    .refuse(&mut stream, Some(404), "not-found", Some(&h))
                    .await;
            }
        };
        let framing = match (route, h.content_length) {
            (Route::Chat, None) => Some((411, "length-required")),
            (Route::Chat, Some(n)) if n > body::MAX_BODY as u64 => Some((413, "body-too-large")),
            (Route::Models, Some(n)) if n > 0 => Some((400, "unexpected-body")),
            _ => None,
        };
        if let Some((status, reason)) = framing {
            return self
                .refuse(&mut stream, Some(status), reason, Some(&h))
                .await;
        }
        self.hand_to_hyper(stream, buf, route, h).await;
    }

    /// Serves the accepted request through hyper on the replayed stream.
    async fn hand_to_hyper<S>(self: Arc<Self>, stream: S, prefix: Vec<u8>, route: Route, h: Head)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let gate = Gate::default();
        let mismatch = Arc::new(AtomicBool::new(false));
        let io = Io::new(prefix, stream, gate.clone(), WRITE_STALL);
        let (me, g, h, m) = (
            Arc::clone(&self),
            gate.clone(),
            Arc::new(h),
            Arc::clone(&mismatch),
        );
        let svc = service_fn(move |req: hyper::Request<Incoming>| {
            let (me, g, h, m) = (Arc::clone(&me), g.clone(), Arc::clone(&h), Arc::clone(&m));
            async move {
                if !agrees(&h, &req) {
                    m.store(true, Ordering::SeqCst);
                    return Err(Closed);
                }
                me.request(req, route, g).await
            }
        });
        let _ = http1::Builder::new()
            .keep_alive(false)
            .serve_connection(TokioIo::new(io), svc)
            .await;
        if !gate.is_open() {
            // hyper refused the request by itself, or read it differently from the broker; any
            // reply it wrote was dropped by the gate.
            let reason = if mismatch.load(Ordering::SeqCst) {
                "head-mismatch"
            } else {
                "http-error"
            };
            let _ = self.deny(reason, None, None, None).await;
        }
    }

    async fn request(
        &self,
        req: hyper::Request<Incoming>,
        route: Route,
        gate: Gate,
    ) -> Result<hyper::Response<Out>, Closed> {
        if route == Route::Models {
            let entry = self
                .record
                .entry(Actor::Harness, "llm.request", Some("allow"))
                .args(json!({"path": "/v1/models"}));
            self.append(entry).await?;
            gate.open();
            return Ok(reply::json_response(
                200,
                reply::models(&self.settings.model),
            ));
        }
        let collected = tokio::time::timeout(
            BODY_TIMEOUT,
            Limited::new(req.into_body(), body::MAX_BODY).collect(),
        )
        .await;
        let bytes = match collected {
            Err(_) => return self.refused(&gate, 408, "body-timeout", None).await,
            Ok(Err(e)) if e.downcast_ref::<LengthLimitError>().is_some() => {
                return self.refused(&gate, 413, "body-too-large", None).await;
            }
            Ok(Err(_)) => return self.refused(&gate, 400, "body-error", None).await,
            Ok(Ok(c)) => c.to_bytes(),
        };
        let chat = match body::check(&bytes, self.settings.context) {
            Ok(c) => c,
            Err(r) => {
                return self
                    .refused(&gate, 400, r.reason.as_str(), Some(&r.field))
                    .await;
            }
        };
        let entry = self
            .record
            .entry(Actor::Harness, "llm.request", Some("allow"))
            .args(json!({
                "path": "/v1/chat/completions",
                "stream": chat.stream,
                "messages": chat.messages,
                "bytes": bytes.len(),
                "sha256": sha256_hex(&bytes),
                "max_tokens": chat.max_tokens,
            }));
        self.append(entry).await?;
        gate.open();
        self.answer(chat).await
    }

    /// Calls the backend and builds the reply; `llm.response` records what was returned.
    async fn answer(&self, chat: Chat) -> Result<hyper::Response<Out>, Closed> {
        match self.backend.complete(chat).await {
            Err(BackendError) => {
                self.append(response(
                    &self.record,
                    502,
                    json!({"reason": "backend-error"}),
                ))
                .await?;
                Ok(reply::json_response(
                    502,
                    reply::error_body("backend-error", None),
                ))
            }
            Ok(Reply::Whole(v)) => {
                let out = serde_json::to_vec(&v).unwrap_or_default();
                let summary = json!({"bytes": out.len(), "sha256": sha256_hex(&out)});
                self.append(response(&self.record, 200, summary)).await?;
                Ok(reply::json_response(200, out))
            }
            Ok(Reply::Stream(rx)) => {
                let (tx, out) = mpsc::channel(STREAM_BUFFER);
                tokio::spawn(pump(rx, tx, self.record.clone()));
                Ok(reply::stream_response(out))
            }
        }
    }

    /// Records a refusal of a request hyper read, then answers it.
    async fn refused(
        &self,
        gate: &Gate,
        status: u16,
        reason: &str,
        field: Option<&str>,
    ) -> Result<hyper::Response<Out>, Closed> {
        if !self.deny(reason, Some(status), None, field).await {
            return Err(Closed);
        }
        gate.open();
        Ok(reply::json_response(
            status,
            reply::error_body(reason, field),
        ))
    }

    /// Records a refusal the broker answers itself (`status`), or closes on (`None`).
    async fn refuse<S: AsyncWrite + Unpin>(
        &self,
        stream: &mut S,
        status: Option<u16>,
        reason: &str,
        h: Option<&Head>,
    ) {
        if !self.deny(reason, status, h, None).await {
            return;
        }
        if let Some(status) = status {
            let out = reply::raw(status, &reply::error_body(reason, None));
            let send = async {
                stream.write_all(&out).await?;
                stream.shutdown().await
            };
            let _ = tokio::time::timeout(WRITE_STALL, send).await;
        }
    }

    /// Appends `llm.deny`; whether it was written.
    async fn deny(
        &self,
        reason: &str,
        status: Option<u16>,
        h: Option<&Head>,
        field: Option<&str>,
    ) -> bool {
        let mut args = json!({"reason": reason, "status": status});
        if let (Some(h), Some(a)) = (h, args.as_object_mut()) {
            a.insert("method".into(), Value::from(escape(h.method.as_bytes())));
            a.insert("path".into(), Value::from(escape(h.path.as_bytes())));
        }
        if let (Some(f), Some(a)) = (field, args.as_object_mut()) {
            a.insert("field".into(), Value::from(escape(f.as_bytes())));
        }
        let entry = self
            .record
            .entry(Actor::Sallyd, "llm.deny", Some("deny"))
            .args(args);
        self.record.append(entry).await
    }

    async fn append(&self, entry: NewEntry) -> Result<(), Closed> {
        if self.record.append(entry).await {
            Ok(())
        } else {
            Err(Closed)
        }
    }

    /// Waits until the session's rate allows another request.
    async fn throttle(&self) {
        loop {
            let wait = self
                .rate
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            match wait {
                Ok(()) => return,
                Err(d) => tokio::time::sleep(d).await,
            }
        }
    }
}

impl<B: Backend> Server for Llm<B> {
    fn serve(self: Arc<Self>, stream: UnixStream) -> impl Future<Output = ()> + Send {
        self.serve_stream(stream)
    }

    async fn refuse_peer(self: Arc<Self>, uid: Option<u32>) {
        let entry = self
            .record
            .entry(Actor::Sallyd, "llm.deny", Some("deny"))
            .args(json!({"reason": "peer-uid", "uid": uid}));
        let _ = self.record.append(entry).await;
    }

    fn stop(&self) {
        self.stop.send_replace(true);
    }
}

/// Whether hyper read the request the broker checked: the same method, request-target and
/// version, no `Transfer-Encoding`, and the same body length. Every allow or deny decision is
/// made on the broker's parse ([`head::parse`]); hyper only serves it, so a request it reads any
/// other way is closed unanswered (architect ruling on the head pre-read).
pub(super) fn agrees<B: hyper::body::Body>(h: &Head, req: &hyper::Request<B>) -> bool {
    let headers = req.headers();
    let lengths = headers
        .get_all(hyper::header::CONTENT_LENGTH)
        .iter()
        .count();
    let uri = req.uri();
    req.method().as_str() == h.method
        && uri.scheme().is_none()
        && uri.authority().is_none()
        && uri
            .path_and_query()
            .map(hyper::http::uri::PathAndQuery::as_str)
            == Some(h.path.as_str())
        && req.version() == hyper::Version::HTTP_11
        && !headers.contains_key(hyper::header::TRANSFER_ENCODING)
        && lengths == usize::from(h.content_length.is_some())
        && req.body().size_hint().exact() == Some(h.content_length.unwrap_or(0))
}

/// Reads until the head is complete, too large or refused; `None` at end of stream first.
async fn read_head<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut Vec<u8>) -> Option<Parsed> {
    let mut chunk = [0u8; READ_CHUNK];
    loop {
        match head::parse(buf) {
            Parsed::Partial => {}
            done => return Some(done),
        }
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(chunk.get(..n).unwrap_or_default());
    }
}

/// Forwards a backend stream as server-sent events (cut at [`MAX_RESPONSE`]), then records
/// `llm.response`.
async fn pump(mut rx: mpsc::Receiver<Value>, tx: mpsc::Sender<Bytes>, record: Recorder) {
    let (mut hash, mut sent, mut events, mut cut) = (Sha256::new(), 0usize, 0usize, false);
    while let Some(v) = rx.recv().await {
        let e = reply::event(&v);
        if sent.saturating_add(e.len()) > MAX_RESPONSE {
            cut = true;
            break;
        }
        hash.update(&e);
        sent = sent.saturating_add(e.len());
        events = events.saturating_add(1);
        if tx.send(e).await.is_err() {
            break;
        }
    }
    if !cut {
        let _ = tx.send(Bytes::from_static(reply::DONE)).await;
    }
    drop(tx);
    let summary = json!({"stream": true, "events": events, "bytes": sent, "sha256": hex(&hash.finalize()), "cut": cut});
    let _ = record.append(response(&record, 200, summary)).await;
}

/// `llm.response` (detail: dropped at `audit.level: actions`).
fn response(record: &Recorder, status: u16, mut summary: Value) -> NewEntry {
    if let Some(o) = summary.as_object_mut() {
        o.insert("status".into(), Value::from(status));
    }
    record
        .entry(Actor::Sallyd, "llm.response", None)
        .args(summary)
        .detail(Detail::Full)
}

fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;
