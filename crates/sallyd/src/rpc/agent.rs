//! `agent.sock`: the MCP server the harness talks to (ARCHITECTURE §4.2; Task 7 decisions 3–5).
//! Every byte on it is untrusted.
//!
//! Per connection: read one frame (at most [`MAX_FRAME`]), wait for a rate token, parse it
//! ([`message`]), classify it ([`mcp`]), audit, then reply. Order of effects (architect rulings
//! Q7–Q9):
//! - Over the rate the server stops reading until a token is free (backpressure; one frame per
//!   connection is read ahead): no request is refused for rate, so none goes unaudited. The rate
//!   and the in-flight cap are per session, shared by its connections; at most
//!   [`MAX_CONNECTIONS`] are accepted at once.
//! - Every refusal is recorded (`rpc.deny`) before its error reply; responses and refused
//!   notifications are recorded and get no reply. An oversize frame is recorded, answered and
//!   the connection closed.
//! - Every allowed request is recorded (`rpc.request`) before it is served; `tools/call` records
//!   the tool and the shape of its arguments (never their values, architect ruling Q16) before
//!   the handler runs. A failed append closes the connection without a reply or a dispatch.
//! - Each `tools/call` gets the broker's call number, unique in the session; approvals bind it,
//!   never the harness's id (architect ruling Q19).
//! - A cancel or a closed connection never drops a call: it runs to its end (so its own audit
//!   entries are written) and only its reply is suppressed; a prompt it waits on is withdrawn
//!   through the handler (#54; ruling Q27). Its in-flight slot is held until it returns. A call
//!   whose handler could not write an entry gets no reply. Session teardown does drop calls: after [`listen::STOP_GRACE`]
//!   (`Handle::shutdown`) or at once (the `Handle` dropped) (architect ruling Q17).
//! - The broker never sends a request; replies are the only messages it writes.

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sally_core::audit::Actor;
use serde_json::{Map, Value, json};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::{Semaphore, mpsc, watch};
use tokio::task::JoinSet;

use super::frame::{self, Frame};
use super::listen::{self, Server, until_true};
use super::mcp::{self, Call, Era, Note, SERVER_LIMIT, Tool, ToolOutcome};
use super::message::{
    self, INTERNAL_ERROR, INVALID_PARAMS, INVALID_REQUEST, Id, METHOD_NOT_FOUND, Message,
    PARSE_ERROR,
};
use super::rate::Rate;
use super::record::{Recorder, escape};
use crate::approvals::Withdraw;

/// Largest frame accepted (ARCHITECTURE §4: 256 KiB on the session socket).
pub const MAX_FRAME: usize = 256 * 1024;
/// `tools/call` requests running at once per session (architect Q8).
pub const MAX_IN_FLIGHT: usize = 16;
/// Frames read per second per session, on average (architect Q8).
pub const RATE: u32 = 20;
/// Frames read back to back per session at most (architect Q8).
pub const BURST: u32 = 40;
/// Connections per session at once (architect Q8).
pub const MAX_CONNECTIONS: usize = 8;
/// Time a reply may take to write; a peer that does not read is closed.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// Replies queued per connection before the reader waits for the writer.
const OUTBOX: usize = 32;
/// Argument keys a `tools/call` entry names, at most (architect ruling Q16).
pub const LOGGED_KEYS: usize = 8;

/// What `tools/call` dispatches to (Task 7 decision 4): the built-in tools (Task 11) behind
/// policy and approvals ([`crate::approvals::Gated`], Task 10). It owns every decision about a
/// tool, including unknown and ungranted names (`isError: true`, `denied: <code>`).
pub trait ToolHandler: Send + Sync + 'static {
    /// The session's tools, as `tools/list` returns them.
    fn tools(&self) -> Vec<Tool>;
    /// Runs one call. `call` is the broker's number for it, unique in the session (the
    /// harness's JSON-RPC id is unique only per connection; architect ruling Q19). It must write
    /// its own effect entry (each tool's fields, ARCHITECTURE §4.3) before the effect or the
    /// denial reply, at every `audit.level`: the `rpc.request` entry carries no argument values.
    /// `None` means an entry could not be written: nothing ran, and no reply is sent.
    ///
    /// A cancel or a closed connection never drops a call; it is told through
    /// [`withdraw`](Self::withdraw). Session teardown does drop calls: after
    /// [`listen::STOP_GRACE`] (`Handle::shutdown`) or at once (the `Handle` dropped). So a
    /// handler must be safe to drop at any await. A drop before the effect starts means nothing
    /// ran (a dropped approval wait is a deny); a drop after it started may leave the effect
    /// finished with no completion entry (blocking work is not abortable), so the entry comes
    /// first.
    // TODO(#62): Task 11's executors write their effect entries and are drop-safe.
    fn call(
        &self,
        call: u64,
        name: String,
        arguments: Map<String, Value>,
    ) -> impl Future<Output = Option<ToolOutcome>> + Send;
    /// The harness cancelled `call`, or the connection that sent it closed (#54): a prompt it
    /// is waiting on is withdrawn.
    fn withdraw(&self, call: u64, why: Withdraw) -> impl Future<Output = ()> + Send;
}

/// One session's `agent.sock` server.
pub struct Agent<T> {
    handler: Arc<T>,
    record: Recorder,
    rate: Mutex<Rate>,
    in_flight: Arc<Semaphore>,
    stop: watch::Sender<bool>,
    /// The next call number of the session.
    calls: AtomicU64,
}

/// A `tools/call` in flight on one connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InFlight {
    /// The broker's call number.
    call: u64,
    /// A cancel named it: its reply is suppressed.
    cancelled: bool,
}

/// One connection's state.
struct Conn {
    /// The connection completed `initialize`.
    legacy: bool,
    /// `tools/call` ids in flight.
    pending: Arc<Mutex<HashMap<Id, InFlight>>>,
    out: mpsc::Sender<Vec<u8>>,
    tasks: JoinSet<()>,
}

impl<T: ToolHandler> Agent<T> {
    /// A server for one session.
    #[must_use]
    pub fn new(handler: T, record: Recorder) -> Self {
        Self {
            handler: Arc::new(handler),
            record,
            rate: Mutex::new(Rate::new(RATE, BURST)),
            in_flight: Arc::new(Semaphore::new(MAX_IN_FLIGHT)),
            stop: watch::Sender::new(false),
            calls: AtomicU64::new(0),
        }
    }

    /// Serves `listener` (the session's `agent.sock`) for peers with `uid`.
    pub fn listen(self: Arc<Self>, listener: tokio::net::UnixListener, uid: u32) -> listen::Handle {
        listen::spawn(listener, self, MAX_CONNECTIONS, uid)
    }

    /// Serves one stream to its end.
    pub async fn serve_stream<S>(self: Arc<Self>, stream: S)
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (r, w) = tokio::io::split(stream);
        let (out, rx) = mpsc::channel(OUTBOX);
        let writer = tokio::spawn(write_loop(w, rx));
        let mut conn = Conn {
            legacy: false,
            pending: Arc::default(),
            out,
            tasks: JoinSet::new(),
        };
        let mut reader = BufReader::new(r);
        let stopped = until_true(self.stop.subscribe());
        tokio::pin!(stopped);
        loop {
            // One frame, then a token before it is handled: a connection idle on its read holds
            // no token, and nothing past this one frame is read until the rate allows it.
            let next = async {
                let f = frame::read(&mut reader, MAX_FRAME).await;
                self.throttle().await;
                f
            };
            let frame = tokio::select! {
                biased;
                () = &mut stopped => break,
                f = next => f,
            };
            let keep = match frame {
                Ok(Frame::Line(line)) => self.handle(&line, &mut conn).await,
                Ok(Frame::TooLarge) => {
                    self.refuse(&conn, None, None, "frame-too-large", INVALID_REQUEST)
                        .await;
                    false
                }
                Ok(Frame::Eof) | Err(_) => false,
            };
            if !keep {
                break;
            }
        }
        // Dispatched calls run to their end, though the peer is gone (rulings Q7, Q17; only
        // session teardown aborts them), but a prompt one waits on is withdrawn: nobody is
        // left to receive its result (architect ruling Q27). Then the writer drains and closes.
        let open: Vec<u64> = lock(&conn.pending).values().map(|f| f.call).collect();
        for call in open {
            self.handler.withdraw(call, Withdraw::Closed).await;
        }
        let Conn { out, mut tasks, .. } = conn;
        drop(out);
        while tasks.join_next().await.is_some() {}
        let _ = writer.await;
    }

    /// Waits until the session's rate allows another frame.
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

    /// Handles one frame; whether the connection stays open.
    async fn handle(&self, line: &[u8], conn: &mut Conn) -> bool {
        match message::parse(line) {
            Err(r) => {
                self.refuse(
                    conn,
                    r.id.as_ref(),
                    None,
                    r.reason.as_str(),
                    r.reason.code(),
                )
                .await
            }
            Ok(Message::Response) => self.deny(None, None, "unexpected-response").await,
            Ok(Message::Notification { method, params }) => {
                self.notification(&method, &params, conn).await
            }
            Ok(Message::Request { id, method, params }) => {
                self.request(id, &method, &params, conn).await
            }
        }
    }

    async fn request(
        &self,
        id: Id,
        method: &str,
        params: &Map<String, Value>,
        conn: &mut Conn,
    ) -> bool {
        if lock(&conn.pending).contains_key(&id) {
            let m = Some(method);
            return self
                .refuse(conn, Some(&id), m, "duplicate-id", INVALID_REQUEST)
                .await;
        }
        let (era, call) = match mcp::classify(method, params, conn.legacy) {
            Ok(c) => c,
            Err(r) => {
                return self.deny(Some(&id), Some(method), r.reason()).await
                    && send(conn, failure(Some(&id), r.error())).await;
            }
        };
        if let Call::ToolsCall { name, arguments } = call {
            return self.dispatch(conn, id, era, name, arguments).await;
        }
        let entry = self
            .record
            .entry(Actor::Harness, "rpc.request", Some("allow"))
            .args(json!({"method": method, "id": logged_id(&id), "lifecycle": era.as_str()}));
        if !self.record.append(entry).await {
            return false;
        }
        let result = match call {
            Call::Discover => mcp::discover_result(),
            Call::Initialize { version } => {
                conn.legacy = true;
                mcp::initialize_result(version)
            }
            Call::Ping => mcp::ping_result(),
            Call::ToolsList => mcp::tools_list_result(era, &self.handler.tools()),
            Call::ToolsCall { .. } => return false,
        };
        send(conn, success(&id, result)).await
    }

    /// `tools/call`: a session slot, the entry, then the handler in its own task.
    async fn dispatch(
        &self,
        conn: &mut Conn,
        id: Id,
        era: Era,
        name: String,
        arguments: Map<String, Value>,
    ) -> bool {
        let Ok(slot) = Arc::clone(&self.in_flight).try_acquire_owned() else {
            let m = Some("tools/call");
            return self
                .refuse(conn, Some(&id), m, "too-many-in-flight", SERVER_LIMIT)
                .await;
        };
        let entry = self
            .record
            .entry(Actor::Harness, "rpc.request", Some("allow"))
            .args(call_args(&id, era, &name, &arguments));
        if !self.record.append(entry).await {
            return false;
        }
        let call = self.calls.fetch_add(1, Ordering::Relaxed);
        let flight = InFlight {
            call,
            cancelled: false,
        };
        lock(&conn.pending).insert(id.clone(), flight);
        let (handler, pending, out) = (
            Arc::clone(&self.handler),
            Arc::clone(&conn.pending),
            conn.out.clone(),
        );
        conn.tasks.spawn(async move {
            let outcome = handler.call(call, name, arguments).await;
            let cancelled = lock(&pending).remove(&id).is_none_or(|f| f.cancelled);
            drop(slot);
            // `None`: an entry could not be written, so nothing ran and nothing is answered.
            if let (false, Some(outcome)) = (cancelled, outcome) {
                let _ = out
                    .send(success(&id, mcp::tools_call_result(era, &outcome)))
                    .await;
            }
        });
        true
    }

    async fn notification(&self, method: &str, params: &Map<String, Value>, conn: &Conn) -> bool {
        match mcp::classify_note(method, params, conn.legacy) {
            Err(r) => self.deny(None, Some(method), r.reason()).await,
            Ok(Note::Initialized) => {
                let entry = self
                    .record
                    .entry(Actor::Harness, "rpc.request", Some("allow"))
                    .args(json!({"method": method, "lifecycle": Era::Legacy.as_str()}));
                self.record.append(entry).await
            }
            Ok(Note::Cancelled { request }) => self.cancel(&request, conn).await,
        }
    }

    /// Marks an in-flight call cancelled (its reply is then suppressed). Unknown or finished ids
    /// are ignored. A call that finishes while the `rpc.cancel` entry is being written has its
    /// reply queued already: the log then shows a cancel that came too late to suppress it,
    /// which the cancellation spec allows (a cancel is best effort; the reply may still arrive).
    /// After the entry, a prompt the call waits on is withdrawn through the handler (#54).
    async fn cancel(&self, request: &Id, conn: &Conn) -> bool {
        let Some(call) = lock(&conn.pending)
            .get(request)
            .filter(|f| !f.cancelled)
            .map(|f| f.call)
        else {
            return true;
        };
        let entry = self
            .record
            .entry(Actor::Harness, "rpc.cancel", None)
            .args(json!({"id": logged_id(request)}));
        if !self.record.append(entry).await {
            return false;
        }
        if let Some(f) = lock(&conn.pending).get_mut(request) {
            f.cancelled = true;
        }
        self.handler.withdraw(call, Withdraw::Cancel).await;
        true
    }

    /// Records a refusal, then answers it with `code`.
    async fn refuse(
        &self,
        conn: &Conn,
        id: Option<&Id>,
        method: Option<&str>,
        reason: &str,
        code: i64,
    ) -> bool {
        self.deny(id, method, reason).await
            && send(conn, failure(id, error_object(code, reason))).await
    }

    /// Records `rpc.deny`; whether it was written.
    async fn deny(&self, id: Option<&Id>, method: Option<&str>, reason: &str) -> bool {
        let mut args = json!({"reason": reason});
        if let (Some(m), Some(a)) = (method, args.as_object_mut()) {
            a.insert("method".into(), Value::from(escape(m.as_bytes())));
        }
        if let (Some(i), Some(a)) = (id, args.as_object_mut()) {
            a.insert("id".into(), logged_id(i));
        }
        let entry = self
            .record
            .entry(Actor::Sallyd, "rpc.deny", Some("deny"))
            .args(args);
        self.record.append(entry).await
    }
}

impl<T: ToolHandler> Server for Agent<T> {
    fn serve(self: Arc<Self>, stream: UnixStream) -> impl Future<Output = ()> + Send {
        self.serve_stream(stream)
    }

    async fn refuse_peer(self: Arc<Self>, uid: Option<u32>) {
        let entry = self
            .record
            .entry(Actor::Sallyd, "rpc.deny", Some("deny"))
            .args(json!({"reason": "peer-uid", "uid": uid}));
        let _ = self.record.append(entry).await;
    }

    fn stop(&self) {
        self.stop.send_replace(true);
    }
}

/// Writes queued replies; stops at the first write that fails or stalls past [`WRITE_TIMEOUT`].
async fn write_loop<W: AsyncWrite + Unpin>(mut w: W, mut rx: mpsc::Receiver<Vec<u8>>) {
    while let Some(line) = rx.recv().await {
        if !matches!(
            tokio::time::timeout(WRITE_TIMEOUT, w.write_all(&line)).await,
            Ok(Ok(()))
        ) {
            return;
        }
    }
    let _ = tokio::time::timeout(WRITE_TIMEOUT, w.shutdown()).await;
}

/// Queues a reply; whether the writer is still there.
async fn send(conn: &Conn, line: Vec<u8>) -> bool {
    conn.out.send(line).await.is_ok()
}

fn lock<V>(m: &Mutex<V>) -> std::sync::MutexGuard<'_, V> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The `rpc.request` arguments of a `tools/call` (architect ruling Q16): which tool, and the
/// shape of its arguments, never their values. The handler's own entry carries each tool's
/// fields (ARCHITECTURE §4.3) before its effect. Bounded so the writer never truncates it: at
/// most [`LOGGED_KEYS`] keys, each escaped and cut like every peer string.
fn call_args(id: &Id, era: Era, name: &str, arguments: &Map<String, Value>) -> Value {
    let keys: Vec<String> = arguments
        .keys()
        .take(LOGGED_KEYS)
        .map(|k| escape(k.as_bytes()))
        .collect();
    let bytes = serde_json::to_vec(arguments).map_or(0, |b| b.len());
    json!({
        "method": "tools/call",
        "id": logged_id(id),
        "lifecycle": era.as_str(),
        "tool": escape(name.as_bytes()),
        "argument_count": arguments.len(),
        "argument_keys": keys,
        "arguments_bytes": bytes,
    })
}

/// An id as an audit entry shows it: a number as is, a string escaped and cut.
fn logged_id(id: &Id) -> Value {
    match id {
        Id::Num(n) => Value::from(*n),
        Id::Str(s) => Value::from(escape(s.as_bytes())),
    }
}

/// A JSON-RPC error object with the stable reason in `data`.
#[must_use]
pub(crate) fn error_object(code: i64, reason: &str) -> Value {
    let message = match code {
        PARSE_ERROR => "Parse error",
        INVALID_REQUEST => "Invalid Request",
        METHOD_NOT_FOUND => "Method not found",
        INVALID_PARAMS => "Invalid params",
        INTERNAL_ERROR => "Internal error",
        _ => "Server error",
    };
    json!({"code": code, "message": message, "data": {"reason": reason}})
}

/// A success reply, as one line.
#[must_use]
pub(crate) fn success(id: &Id, result: Value) -> Vec<u8> {
    line(&json!({"jsonrpc": "2.0", "id": id.to_value(), "result": result}))
}

/// An error reply, as one line; `id` is `null` when the request's could not be read.
#[must_use]
pub(crate) fn failure(id: Option<&Id>, error: Value) -> Vec<u8> {
    let id = id.map_or(Value::Null, Id::to_value);
    line(&json!({"jsonrpc": "2.0", "id": id, "error": error}))
}

/// `v` serialized on one line (JSON escapes every newline inside strings), plus `\n`.
fn line(v: &Value) -> Vec<u8> {
    let mut b = serde_json::to_vec(v).unwrap_or_default();
    b.push(b'\n');
    b
}

#[cfg(test)]
#[path = "agent_tests.rs"]
mod tests;
