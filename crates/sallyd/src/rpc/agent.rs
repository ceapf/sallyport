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
//! - Each `tools/call` gets the broker's call number from the handler, unique in the session;
//!   approvals bind it, never the harness's id (architect ruling Q19).
//! - A cancel or a closed connection never drops a call: it runs to its end (so its own audit
//!   entries are written) and only its reply is suppressed; a prompt it waits on is withdrawn
//!   through the handler (#54; ruling Q27). Its in-flight slot is held until its reply has been
//!   written or dropped, so the replies the broker holds for a session are at most
//!   [`MAX_IN_FLIGHT`], however many connections it has and whether or not they read
//!   (RT-AG-17). A call whose handler could not write an entry gets no reply. Session
//!   teardown does drop calls: after [`listen::STOP_GRACE`] (`Handle::shutdown`) or at once (the
//!   `Handle` dropped) (architect ruling Q17). Teardown ends each connection's writer too:
//!   nothing more is written to the peer (a line in mid-write is cut short, then the stream
//!   ends), and every queued reply and its slot are dropped.
//! - Finished calls are reaped as they end (RT-AG-17). A call whose task panics is reported to
//!   the session's crash reporter as `agent.call` at once (the session then stops); its id and
//!   slot are released and its connection stays open until the session's stop.
//! - The broker never sends a request; replies are the only messages it writes.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sally_core::audit::{Actor, NewEntry};
use serde_json::{Map, Value, json};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};

use super::frame::{self, Frame};
use super::listen::{self, CrashReporter, Peer, Server, until_true};
use super::mcp::{self, Call, Era, Note, SERVER_LIMIT, Tool, ToolOutcome};
use super::message::{
    self, INTERNAL_ERROR, INVALID_PARAMS, INVALID_REQUEST, Id, METHOD_NOT_FOUND, Message,
    PARSE_ERROR,
};
use super::rate::Rate;
use super::record::{Recorder, SHORT_STYLE};

/// Why a call's prompt is withdrawn ([`ToolHandler::withdraw`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Withdraw {
    /// `notifications/cancelled` named the call.
    Cancel,
    /// The connection that sent the call closed.
    Closed,
    /// The session is stopping (architect Q59).
    SessionStop,
}

/// How a driven tool call ended ([`Agent::drive_call`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Driven {
    /// The handler answered (its own denials are answers, `isError: true`).
    Done(ToolOutcome),
    /// Refused before the handler, with the `rpc.deny` reason.
    Denied(&'static str),
    /// No answer exists: an entry could not be written (before the effect, nothing ran; when
    /// the call's result entry failed, the effect happened and its answer is withheld), or the
    /// call's task panicked (reported as `agent.call`).
    Unrecorded,
}

/// Why [`Agent::admit`] did not admit a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unadmitted {
    /// Every in-flight slot is taken (`too-many-in-flight`).
    Full,
    /// The `rpc.request` entry could not be written: nothing runs, nothing is answered.
    Unrecorded,
}

/// Withdraws the prompt of a driven call whose caller went away before it ended.
struct WithdrawOnDrop<T: ToolHandler> {
    handler: Arc<T>,
    call: u64,
    armed: bool,
}

impl<T: ToolHandler> Drop for WithdrawOnDrop<T> {
    fn drop(&mut self) {
        // Without a runtime (it is shutting down) there is no prompt left to withdraw: the
        // session's stop withdraws every prompt (architect Q59).
        if let (true, Ok(rt)) = (self.armed, tokio::runtime::Handle::try_current()) {
            let (handler, call) = (Arc::clone(&self.handler), self.call);
            // TODO(#343): a bare spawn, so a panic in this withdraw is not a session crash.
            rt.spawn(async move { handler.withdraw(call, Withdraw::Closed).await });
        }
    }
}

/// Largest frame accepted (ARCHITECTURE §4: 256 KiB on the session socket).
pub const MAX_FRAME: usize = 256 * 1024;
/// `tools/call` requests running at once per session (architect Q8), counting each until its
/// reply has been written or dropped: also the most replies the broker holds for a session.
pub const MAX_IN_FLIGHT: usize = 16;
/// Frames read per second per session, on average (architect Q8).
pub const RATE: u32 = 20;
/// Frames read back to back per session at most (architect Q8).
pub const BURST: u32 = 40;
/// Connections per session at once (architect Q8).
pub const MAX_CONNECTIONS: usize = 8;
/// Time a reply may take to write; a peer that does not read is closed.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// Replies queued per connection before the reader waits for the writer. A queued `tools/call`
/// reply still holds its call's slot, so this bounds the other replies (refusals, lists).
const OUTBOX: usize = 32;
/// The crash reporter's name for a `tools/call` task, harness or driven (`agent.sock` names
/// the connection task, `listen.rs`).
const CALL_TASK: &str = "agent.call";
/// Argument keys a `tools/call` entry names, at most (architect ruling Q16).
pub const LOGGED_KEYS: usize = 8;

/// What `tools/call` dispatches to (Task 7 decision 4): the built-in tools (Task 11) behind
/// policy and approvals ([`crate::approvals::Gated`], Task 10). It owns every decision about a
/// tool, including unknown and ungranted names (`isError: true`, `denied: <code>`).
pub trait ToolHandler: Send + Sync + 'static {
    /// The session's tools, as `tools/list` returns them.
    fn tools(&self) -> Vec<Tool>;
    /// A new call starts: its number, unique in the session (the harness's JSON-RPC id is
    /// unique only per connection; architect ruling Q19). Called before the call is spawned, so
    /// a withdraw that arrives before it runs is kept; [`call`](Self::call) ends it.
    fn begin(&self) -> u64;
    /// Runs one call. `call` is the number [`begin`](Self::begin) gave it. It must write
    /// its own effect entry (each tool's fields, ARCHITECTURE §4.3) before the effect or the
    /// denial reply, at every `audit.level`: the `rpc.request` entry carries no argument values.
    /// `None` means an entry could not be written, and no reply is sent: before the effect,
    /// nothing ran; when the result entry fails, the effect happened and its reply is withheld.
    ///
    /// A cancel or a closed connection never drops a call; it is told through
    /// [`withdraw`](Self::withdraw). Session teardown does drop calls: after
    /// [`listen::STOP_GRACE`] (`Handle::shutdown`) or at once (the `Handle` dropped). So a
    /// handler must be safe to drop at any await. A drop before the effect starts means nothing
    /// ran (a dropped approval wait is a deny). The production handler (`approvals::Gated` over
    /// `tools::Tools`) runs each call's section from `tool.run` to `tool.result` as a task of its
    /// own, counted by the session's `tools::ops::Ops` (architect Q59): a dropped caller loses
    /// neither the effect nor its entry, and the session's stop withdraws prompts, kills
    /// commands and aborts writes not yet begun before it waits for that count.
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
    /// The session's reporter: connection tasks (through [`listen`]) and call tasks.
    crash: CrashReporter,
}

/// One line for the writer, with the in-flight slot of the `tools/call` it answers (`None`
/// for every other reply): the writer releases it once the line is written, or failed, or
/// timed out; a writer that gives up drops every queued line and its slot with it.
struct Out {
    line: Vec<u8>,
    slot: Option<OwnedSemaphorePermit>,
}

/// A dispatched call's id in its connection's `pending` map while the handler runs. The task
/// consumes it with [`take`](Self::take) as the handler returns; only a task that unwinds
/// removes the id by dropping it, so a panicked call's id can be sent again.
struct Pending {
    map: Arc<Mutex<HashMap<Id, InFlight>>>,
    /// `Some` until taken: a drop removes the id only then.
    id: Option<Id>,
}

impl Pending {
    /// Enters `id` as in flight with the broker's `call` number.
    fn insert(map: &Arc<Mutex<HashMap<Id, InFlight>>>, id: Id, call: u64) -> Self {
        let flight = InFlight {
            call,
            cancelled: false,
        };
        lock(map).insert(id.clone(), flight);
        Self {
            map: Arc::clone(map),
            id: Some(id),
        }
    }

    /// Removes the id as the call returns, before its reply is queued (a later call may reuse
    /// the id only then); whether its reply is suppressed because a cancel named it. Only
    /// `take` and the drop remove an entry, so it is always there here: the "gone" case
    /// (suppressed too) is defensive only.
    fn take(mut self) -> bool {
        let flight = self.id.take().and_then(|id| lock(&self.map).remove(&id));
        flight.is_none_or(|f| f.cancelled)
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            lock(&self.map).remove(&id);
        }
    }
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
    out: mpsc::Sender<Out>,
    tasks: JoinSet<()>,
}

impl Conn {
    /// A fresh connection whose replies go to `out`.
    fn new(out: mpsc::Sender<Out>) -> Self {
        Self {
            legacy: false,
            pending: Arc::default(),
            out,
            tasks: JoinSet::new(),
        }
    }
}

impl<T: ToolHandler> Agent<T> {
    /// A server for one session; a panicking connection or call is reported to `crash`, the
    /// session's reporter.
    #[must_use]
    pub fn new(handler: T, record: Recorder, crash: CrashReporter) -> Self {
        Self {
            handler: Arc::new(handler),
            record,
            rate: Mutex::new(Rate::new(RATE, BURST)),
            in_flight: Arc::new(Semaphore::new(MAX_IN_FLIGHT)),
            stop: watch::Sender::new(false),
            crash,
        }
    }

    /// Serves `listener` (the session's `agent.sock`) for peers with `uid`; a panicking
    /// connection is reported to the session's reporter as `agent.sock`.
    pub fn listen(self: Arc<Self>, listener: tokio::net::UnixListener, uid: u32) -> listen::Handle {
        let crash = self.crash.clone();
        listen::spawn(listener, self, MAX_CONNECTIONS, uid, "agent.sock", crash)
    }

    /// Serves one stream to its end. Dropping the future (session teardown) ends its writer
    /// and its calls with it.
    pub async fn serve_stream<S>(self: Arc<Self>, stream: S)
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (r, w) = tokio::io::split(stream);
        let (out, rx) = mpsc::channel(OUTBOX);
        let writer = Writer(tokio::spawn(write_loop(w, rx)));
        let mut conn = Conn::new(out);
        self.frames(r, &mut conn).await;
        self.close(conn, writer).await;
    }

    /// Reads and handles frames until the peer closes, a frame ends the connection or the
    /// server stops; reaps each call task as it ends.
    async fn frames<R: AsyncRead + Unpin>(&self, reader: R, conn: &mut Conn) {
        let stopped = until_true(self.stop.subscribe());
        tokio::pin!(stopped);
        // One frame, then a token before it is handled: a connection idle on its read holds no
        // token, and nothing past this one frame is read until the rate allows it. The future
        // owns the reader and is replaced only once it has completed, never dropped for a reap:
        // a frame half read, or read and waiting for its token, would be lost.
        let next = move |mut reader: BufReader<R>| async move {
            let f = frame::read(&mut reader, MAX_FRAME).await;
            self.throttle().await;
            (f, reader)
        };
        let mut frame = std::pin::pin!(next(BufReader::new(reader)));
        loop {
            let (got, reader) = tokio::select! {
                biased;
                () = &mut stopped => return,
                Some(r) = conn.tasks.join_next(), if !conn.tasks.is_empty() => {
                    self.reaped(r);
                    continue;
                }
                got = &mut frame => got,
            };
            let keep = match got {
                Ok(Frame::Line(line)) => self.handle(&line, conn).await,
                Ok(Frame::TooLarge) => {
                    self.refuse(conn, None, None, "frame-too-large", INVALID_REQUEST)
                        .await;
                    false
                }
                Ok(Frame::Eof) | Err(_) => false,
            };
            if !keep {
                return;
            }
            frame.set(next(reader));
        }
    }

    /// Ends a connection whose frames are done.
    async fn close(&self, conn: Conn, mut writer: Writer) {
        // Dispatched calls run to their end, though the peer is gone (rulings Q7, Q17; only
        // session teardown aborts them), but a prompt one waits on is withdrawn: nobody is
        // left to receive its result (architect ruling Q27). Then the writer drains and closes,
        // awaited through its guard, so a teardown during the drain still aborts it.
        // TODO(#343): a call that panics while this loop runs during the stop's grace, and is
        // then aborted with the listener, is dropped unreported.
        let open: Vec<u64> = lock(&conn.pending).values().map(|f| f.call).collect();
        for call in open {
            self.handler.withdraw(call, Withdraw::Closed).await;
        }
        let Conn { out, mut tasks, .. } = conn;
        drop(out);
        while let Some(r) = tasks.join_next().await {
            self.reaped(r);
        }
        // TODO(#343): the writer's join result, a panic included, is dropped.
        let _ = (&mut writer.0).await;
    }

    /// A call task's end: a panic goes to the session's reporter.
    fn reaped(&self, ended: Result<(), tokio::task::JoinError>) {
        if let Err(e) = ended {
            self.crash.joined(CALL_TASK, e);
        }
    }

    /// One tool call of a driven session (architect ruling Q117): the transport-free front half
    /// of [`dispatch`](Self::dispatch), so a driven call meets the same classifier, in-flight
    /// slot, `rpc.request` entry and handler as the harness's. Nothing here comes from a peer:
    /// the caller is the session's drive step, which got `name` and `arguments` from the script.
    /// It skips the frame throttle, which paces a peer's reads: no frame is read here, and each
    /// `sessions.drive` request passes the control socket's own admission first.
    ///
    /// The call runs in a task of its own; dropping this future (the driver went away) does not
    /// drop the call: it runs to its end with its entries, and a prompt it waits on is withdrawn
    /// ([`Withdraw::Closed`]), as for a closed `agent.sock` connection. A call that panics is
    /// reported to the session's reporter as `agent.call` (the session then stops with reason
    /// crash) and answers [`Driven::Unrecorded`].
    pub async fn drive_call(&self, name: String, arguments: Map<String, Value>) -> Driven {
        let mut params = Map::new();
        params.insert("name".into(), Value::from(name));
        params.insert("arguments".into(), Value::Object(arguments));
        let (era, name, arguments) = match mcp::classify("tools/call", &params, true) {
            Ok((era, Call::ToolsCall { name, arguments })) => (era, name, arguments),
            // `tools/call` classifies as nothing else; refused and recorded all the same.
            Ok(_) => return self.drive_denied("method-not-found").await,
            Err(r) => return self.drive_denied(r.reason()).await,
        };
        let id = Id::Str("drive".into());
        let (slot, call) = match self.admit(&id, era, &name, &arguments).await {
            Ok(admitted) => admitted,
            Err(Unadmitted::Full) => return self.drive_denied("too-many-in-flight").await,
            Err(Unadmitted::Unrecorded) => return Driven::Unrecorded,
        };
        let handler = Arc::clone(&self.handler);
        let (tx, rx) = oneshot::channel();
        // Through the reporter, so a panic is reported even after the caller went away. Its
        // abort handle is not kept: a call its caller dropped still runs to its end (only its
        // prompt is withdrawn), like a call on a closed connection.
        self.crash.spawn(CALL_TASK, {
            let handler = Arc::clone(&handler);
            async move {
                let outcome = handler.call(call, name, arguments).await;
                drop(slot);
                let _ = tx.send(outcome);
            }
        });
        let mut away = WithdrawOnDrop {
            handler,
            call,
            armed: true,
        };
        // A panicked call drops `tx`: reported, and answered as unrecorded.
        let outcome = rx.await;
        away.armed = false;
        match outcome {
            Ok(Some(o)) => Driven::Done(o),
            Ok(None) | Err(_) => Driven::Unrecorded,
        }
    }

    /// A driven call refused for `reason`: its `rpc.deny`, then [`Driven::Denied`].
    async fn drive_denied(&self, reason: &'static str) -> Driven {
        if self.deny(None, Some("tools/call"), reason).await {
            Driven::Denied(reason)
        } else {
            Driven::Unrecorded
        }
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
        let entry = with_id(
            self.record
                .entry(Actor::Harness, "rpc.request", Some("allow")),
            json!({"method": method, "lifecycle": era.as_str()}),
            &id,
        );
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

    /// The front half every `tools/call` meets, the harness's and the driver's (architect Q117):
    /// an in-flight slot, the `rpc.request` entry, then the handler's number for the call.
    async fn admit(
        &self,
        id: &Id,
        era: Era,
        name: &str,
        arguments: &Map<String, Value>,
    ) -> Result<(OwnedSemaphorePermit, u64), Unadmitted> {
        let Ok(slot) = Arc::clone(&self.in_flight).try_acquire_owned() else {
            return Err(Unadmitted::Full);
        };
        let entry = call_entry(
            self.record
                .entry(Actor::Harness, "rpc.request", Some("allow")),
            id,
            era,
            name,
            arguments,
        );
        if !self.record.append(entry).await {
            return Err(Unadmitted::Unrecorded);
        }
        Ok((slot, self.handler.begin()))
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
        let (slot, call) = match self.admit(&id, era, &name, &arguments).await {
            Ok(admitted) => admitted,
            Err(Unadmitted::Full) => {
                let m = Some("tools/call");
                return self
                    .refuse(conn, Some(&id), m, "too-many-in-flight", SERVER_LIMIT)
                    .await;
            }
            Err(Unadmitted::Unrecorded) => return false,
        };
        let pending = Pending::insert(&conn.pending, id.clone(), call);
        let (handler, out) = (Arc::clone(&self.handler), conn.out.clone());
        conn.tasks.spawn(async move {
            let outcome = handler.call(call, name, arguments).await;
            let cancelled = pending.take();
            // `None`: an entry could not be written, so nothing is answered (nothing ran, or
            // the effect happened and its result entry failed).
            // The slot leaves with the reply and is released once it is written; with no
            // reply, or a writer gone, it is released here.
            if let (false, Some(outcome)) = (cancelled, outcome) {
                let line = success(&id, mcp::tools_call_result(era, &outcome));
                let slot = Some(slot);
                let _ = out.send(Out { line, slot }).await;
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
        let entry = with_id(
            self.record.entry(Actor::Harness, "rpc.cancel", None),
            json!({}),
            request,
        );
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
        let e = self.record.entry(Actor::Sallyd, "rpc.deny", Some("deny"));
        self.record.append(deny_entry(e, id, method, reason)).await
    }
}

/// An `rpc.deny` entry: the reason, and the peer's id and method (an unknown or extension
/// method is the sandbox's text) declared raw, masked whole before their cut (architect Q276).
pub(crate) fn deny_entry(
    e: NewEntry,
    id: Option<&Id>,
    method: Option<&str>,
    reason: &str,
) -> NewEntry {
    let args = json!({"reason": reason});
    let mut entry = match id {
        Some(i) => with_id(e, args, i),
        None => e.args(args),
    };
    if let Some(m) = method {
        entry = entry.text("method", m, SHORT_STYLE);
    }
    entry
}

impl<T: ToolHandler> Server for Agent<T> {
    /// The peer passed the uid check; the session socket needs nothing more of it.
    fn serve(self: Arc<Self>, stream: UnixStream, _: Peer) -> impl Future<Output = ()> + Send {
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

/// A connection's writer task, aborted when the guard drops: a torn-down connection writes
/// nothing more, and its queued replies and their slots go with the task. Aborting a writer
/// that has already ended does nothing.
struct Writer(JoinHandle<()>);

impl Drop for Writer {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Writes queued replies; stops at the first write that fails or stalls past [`WRITE_TIMEOUT`].
/// Each line's slot is released once its write has ended, whichever way; stopping drops the
/// receiver, which releases every queued slot and fails every waiting send.
async fn write_loop<W: AsyncWrite + Unpin>(mut w: W, mut rx: mpsc::Receiver<Out>) {
    while let Some(Out { line, slot }) = rx.recv().await {
        let written = tokio::time::timeout(WRITE_TIMEOUT, w.write_all(&line)).await;
        drop(slot);
        if !matches!(written, Ok(Ok(()))) {
            return;
        }
    }
    let _ = tokio::time::timeout(WRITE_TIMEOUT, w.shutdown()).await;
}

/// Queues a reply that holds no slot; whether the writer is still there.
async fn send(conn: &Conn, line: Vec<u8>) -> bool {
    conn.out.send(Out { line, slot: None }).await.is_ok()
}

fn lock<V>(m: &Mutex<V>) -> std::sync::MutexGuard<'_, V> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The `rpc.request` arguments of a `tools/call` (architect ruling Q16): which tool, and the
/// shape of its arguments, never their values. The handler's own entry carries each tool's
/// fields (ARCHITECTURE §4.3) before its effect. Bounded so the writer never truncates it: at
/// most [`LOGGED_KEYS`] keys, each escaped and cut like every peer string. The tool name, a
/// string id and the keys (a declared list, Q291) are declared raw, so the writer masks them
/// whole before their cut (architect Q276).
pub(crate) fn call_entry(
    e: NewEntry,
    id: &Id,
    era: Era,
    name: &str,
    arguments: &Map<String, Value>,
) -> NewEntry {
    // The keys go raw to the writer, which masks each whole before it cuts and escapes it
    // (architect Q291); how many are logged is the builder's choice.
    let keys: Vec<Arc<str>> = arguments
        .keys()
        .take(LOGGED_KEYS)
        .map(|k| Arc::from(k.as_str()))
        .collect();
    let bytes = serde_json::to_vec(arguments).map_or(0, |b| b.len());
    let args = json!({
        "method": "tools/call",
        "lifecycle": era.as_str(),
        "argument_count": arguments.len(),
        "arguments_bytes": bytes,
    });
    with_id(e, args, id)
        .text("tool", name, SHORT_STYLE)
        .texts("argument_keys", keys, SHORT_STYLE)
}

/// `e` with `args` and `id` as an audit entry shows it: a number as the arg `id`, a string
/// declared in [`SHORT_STYLE`], masked whole before its cut (architect Q276).
fn with_id(e: NewEntry, mut args: Value, id: &Id) -> NewEntry {
    match id {
        Id::Num(n) => {
            if let Some(a) = args.as_object_mut() {
                a.insert("id".into(), Value::from(*n));
            }
            e.args(args)
        }
        Id::Str(s) => e.args(args).text("id", s.as_str(), SHORT_STYLE),
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
/// `v` as one newline-terminated frame.
pub(crate) fn line(v: &Value) -> Vec<u8> {
    let mut b = serde_json::to_vec(v).unwrap_or_default();
    b.push(b'\n');
    b
}

#[cfg(test)]
#[path = "agent_tests.rs"]
mod tests;
