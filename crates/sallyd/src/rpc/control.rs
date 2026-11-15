//! `control.sock`: the trusted clients' socket (the CLI, the UI bridge; ARCHITECTURE §4.1). Its
//! method table ([`CONTROL_METHODS`]) is separate from the session socket's and never shared
//! with it (architect ruling Q1). The methods are in `control_methods.rs`.
//!
//! Every request is recorded before its effect: one that is never admitted (a frame error, an
//! unknown method, invalid params) as `rpc.deny`; an admitted one as `rpc.request` with the
//! client's uid and pid from `SO_PEERCRED` (architect Q76). An entry that cannot be written
//! closes the connection with no effect and no reply. The one exception (architect Q93 ii):
//! `approvals.decide` answers `audit-failed` when the desk's own entry could not be written;
//! nothing was approved and a `deny_all_session` latch stays (the maintainer's Task 11 rule).
//!
//! A connection that called `approvals.watch` also receives `approval.*` notifications between
//! its replies; the read in progress is kept across them, so none splits a frame. A watching
//! connection should not also create or stop sessions: a watcher that falls `WATCH_QUEUE`
//! notifications behind during a long request is dropped with its connection, and the reply
//! is lost (architect Q89 f). TODO(#110): the M5 UI bridge watches on a connection of its own.

use std::future::Future;
use std::sync::{Arc, Mutex, PoisonError};

use rustix::fd::OwnedFd;
use sally_core::audit::Actor;
use sally_core::manifest::{HostEnv, SecretCatalog};
use sally_proto::{Closed, Flood, notification};
use serde_json::{Map, Value, json};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::watch;

use super::agent::{WRITE_TIMEOUT, error_object, failure, line, success};
use super::control_methods::{
    Call, Done, NotAdmitted, READ_BURST, READ_RATE, REFUSED, SessionSet, prompt, value,
};
use super::drive::{Driver, Seat};
use super::frame::{self, Frame};
use super::listen::{self, Peer, Server, until_true};
use super::message::{self, INVALID_PARAMS, INVALID_REQUEST, Id, METHOD_NOT_FOUND, Message};
use super::rate::Rate;
use super::record::{Recorder, escape};
use crate::approvals::Client;
use crate::approvals::hub::{Hub, Note, Watch};
use crate::approvals::queue::who;

pub use super::mcp::CONTROL_METHODS;

/// Largest frame accepted (ARCHITECTURE §4: 1 MiB on the control socket).
pub const MAX_FRAME: usize = sally_proto::MAX_FRAME;
/// Control connections at once.
pub const MAX_CONNECTIONS: usize = 16;

/// What the control socket is built from, once, by the daemon.
pub struct ControlParts<S> {
    /// The control audit handle (its entries carry no session).
    pub record: Recorder,
    /// The live sessions.
    pub sessions: S,
    /// The daemon's one approver: `approvals.watch` attaches to it (architect Q73).
    pub hub: Arc<Hub>,
    /// The open `sessions/` data directory, for `sessions.changes` (architect Q81).
    pub sessions_dir: Arc<OwnedFd>,
    /// The host facts a manifest is validated against, read once at start (architect Q87).
    pub env: Arc<HostEnv>,
    /// The secret names a manifest may grant. TODO(#99): the store's names; until then none.
    pub catalog: Arc<dyn SecretCatalog + Send + Sync>,
}

/// The control socket's server.
pub struct Control<S> {
    pub(super) p: ControlParts<S>,
    /// The daemon-wide read rate (architect Q77).
    rate: Mutex<Rate>,
    stop: watch::Sender<bool>,
}

/// One connection's state.
pub(crate) struct Conn {
    /// The peer, as audited and as the deciding client.
    pub(crate) client: Client,
    /// Attached by `approvals.watch`; dropped with the connection.
    pub(crate) watch: Option<Watch>,
    /// The drive seats this connection holds, one per driven session; dropped with the
    /// connection, which makes each seat gone (architect Q121). A connection with a seat is
    /// never an approver.
    pub(crate) seats: Vec<Seat>,
}

impl Conn {
    /// Whether this connection holds a drive seat.
    pub(crate) fn drives(&self) -> bool {
        !self.seats.is_empty()
    }

    /// Whether it holds the seat of `driver`.
    pub(crate) fn holds(&self, driver: &Arc<Driver>) -> bool {
        self.seat_of(driver).is_some()
    }

    /// Its seat of `driver`.
    pub(crate) fn seat_of(&self, driver: &Arc<Driver>) -> Option<&Seat> {
        self.seats.iter().find(|s| s.is_of(driver))
    }
}

impl<S: SessionSet> Control<S> {
    /// A server over `p`.
    #[must_use]
    pub fn new(p: ControlParts<S>) -> Self {
        Self {
            p,
            rate: Mutex::new(Rate::new(READ_RATE, READ_BURST)),
            stop: watch::Sender::new(false),
        }
    }

    /// Serves `listener` (`control.sock`) for peers with `uid`; a panicking connection is
    /// reported to the daemon's `crash` reporter (it stops every session).
    pub fn listen(
        self: Arc<Self>,
        listener: tokio::net::UnixListener,
        uid: u32,
        crash: listen::CrashReporter,
    ) -> listen::Handle {
        listen::spawn(listener, self, MAX_CONNECTIONS, uid, "control.sock", crash)
    }

    /// Serves one stream of `peer` to its end.
    pub async fn serve_stream<T: AsyncRead + AsyncWrite + Send + 'static>(
        self: Arc<Self>,
        stream: T,
        peer: Peer,
    ) {
        let (r, mut w) = tokio::io::split(stream);
        let mut reader = BufReader::new(r);
        let stopped = until_true(self.stop.subscribe());
        tokio::pin!(stopped);
        let mut conn = Conn {
            client: Client {
                uid: peer.uid,
                pid: peer.pid,
            },
            watch: None,
            seats: Vec::new(),
        };
        loop {
            // One read per frame, kept across notifications: it is not cancel-safe.
            let frame = {
                let read = frame::read(&mut reader, MAX_FRAME);
                tokio::pin!(read);
                loop {
                    tokio::select! {
                        biased;
                        () = &mut stopped => return,
                        f = &mut read => break f,
                        note = next_note(&mut conn.watch) => {
                            // `None`: the hub dropped this watcher as too slow (architect Q73.5).
                            let Some(note) = note else { return };
                            if !write(&mut w, &notify(&note)).await {
                                return;
                            }
                        }
                    }
                }
            };
            let reply = match frame {
                Ok(Frame::Line(l)) => match self.handle(&l, &mut conn, &mut reader).await {
                    Some(reply) => reply,
                    None => break,
                },
                Ok(Frame::TooLarge) => {
                    if self.deny(None, "frame-too-large").await {
                        let _ = write(
                            &mut w,
                            &failure(None, error_object(INVALID_REQUEST, "frame-too-large")),
                        )
                        .await;
                    }
                    break;
                }
                Ok(Frame::Eof) | Err(_) => break,
            };
            if !reply.is_empty() && !write(&mut w, &reply).await {
                break;
            }
        }
    }

    /// The reply to one frame (empty for none); `None` closes the connection. `reader` is the
    /// connection's, only watched for its end while a drive step runs.
    async fn handle<R: AsyncBufRead + Unpin>(
        &self,
        frame: &[u8],
        conn: &mut Conn,
        reader: &mut R,
    ) -> Option<Vec<u8>> {
        let (id, method, params) = match message::parse(frame) {
            Err(r) => {
                let reply = failure(
                    r.id.as_ref(),
                    error_object(r.reason.code(), r.reason.as_str()),
                );
                return self.deny(None, r.reason.as_str()).await.then_some(reply);
            }
            Ok(Message::Response) => {
                return self.deny(None, "unexpected-response").await.then(Vec::new);
            }
            Ok(Message::Notification { method, .. }) => {
                return self
                    .deny(Some(&method), "method-not-found")
                    .await
                    .then(Vec::new);
            }
            Ok(Message::Request { id, method, params }) => (id, method, params),
        };
        let call = match Call::parse(&method, params) {
            Ok(c) => c,
            Err(no) => {
                let (code, reason) = match no {
                    NotAdmitted::MethodNotFound => (METHOD_NOT_FOUND, "method-not-found"),
                    NotAdmitted::InvalidParams => (INVALID_PARAMS, "invalid-params"),
                };
                let reply = failure(Some(&id), error_object(code, reason));
                return self.deny(Some(&method), reason).await.then_some(reply);
            }
        };
        if call.rated(conn.watch.is_some()) && !self.wait_rate().await {
            return None;
        }
        if !self.request(&call, conn.client).await {
            return None;
        }
        // A drive step can wait long (on a prompt): if its driver goes away meanwhile, the step
        // is dropped, which withdraws that prompt, and the connection closes, leaving the seat
        // gone. Only a drive is raced; other methods are not drop-safe and run to their end.
        let done = if matches!(call, Call::Drive(_)) {
            tokio::select! {
                biased;
                d = self.run(call, conn) => d,
                () = closed(reader) => Done::Close,
            }
        } else {
            self.run(call, conn).await
        };
        match done {
            Done::Ok(result) => Some(success(&id, result)),
            Done::Refused(data) => Some(refused(&id, &data)),
            Done::Close => None,
        }
    }

    /// Waits for a slot of the read rate; `false` if `sallyd` stopped meanwhile.
    async fn wait_rate(&self) -> bool {
        let stopped = until_true(self.stop.subscribe());
        tokio::pin!(stopped);
        loop {
            let wait = match self
                .rate
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take()
            {
                Ok(()) => return true,
                Err(d) => d,
            };
            tokio::select! {
                biased;
                () = &mut stopped => return false,
                () = tokio::time::sleep(wait) => {}
            }
        }
    }

    /// `rpc.request` for an admitted call; whether it was written.
    async fn request(&self, call: &Call, client: Client) -> bool {
        let mut args = Map::new();
        args.insert("socket".into(), Value::from("control"));
        args.insert("method".into(), Value::from(call.method()));
        args.insert("client".into(), who(client));
        args.extend(call.request_args());
        let entry = self
            .p
            .record
            .entry(Actor::User, "rpc.request", None)
            .args(Value::Object(args));
        self.p.record.append(entry).await
    }

    async fn deny(&self, method: Option<&str>, reason: &str) -> bool {
        let mut args = json!({"socket": "control", "reason": reason});
        if let (Some(m), Some(a)) = (method, args.as_object_mut()) {
            a.insert("method".into(), Value::from(escape(m.as_bytes())));
        }
        let entry = self
            .p
            .record
            .entry(Actor::User, "rpc.deny", Some("deny"))
            .args(args);
        self.p.record.append(entry).await
    }
}

impl<S: SessionSet> Server for Control<S> {
    fn serve(self: Arc<Self>, stream: UnixStream, peer: Peer) -> impl Future<Output = ()> + Send {
        self.serve_stream(stream, peer)
    }

    async fn refuse_peer(self: Arc<Self>, uid: Option<u32>) {
        let entry = self
            .p
            .record
            .entry(Actor::Sallyd, "rpc.deny", Some("deny"))
            .args(json!({"socket": "control", "reason": "peer-uid", "uid": uid}));
        let _ = self.p.record.append(entry).await;
    }

    fn stop(&self) {
        self.stop.send_replace(true);
    }
}

/// The next notification for a watching connection; never, for one that is not watching.
async fn next_note(watch: &mut Option<Watch>) -> Option<Note> {
    match watch {
        Some(w) => w.rx.recv().await,
        None => std::future::pending().await,
    }
}

/// Returns when `reader`'s peer closed (end of stream, or a read error); never while bytes wait
/// unread: those are a next request, kept in the buffer for it. Cancel-safe (`fill_buf`).
async fn closed<R: AsyncBufRead + Unpin>(reader: &mut R) {
    match reader.fill_buf().await {
        Ok([]) | Err(_) => {}
        Ok(_) => std::future::pending().await,
    }
}

/// A notification as one frame.
pub(crate) fn notify(note: &Note) -> Vec<u8> {
    let (method, params) = match note {
        Note::Requested(p) => (notification::APPROVAL_REQUESTED, value(&prompt(p))),
        Note::Flood(session) => (
            notification::APPROVAL_FLOOD,
            value(&Flood {
                session: session.clone(),
            }),
        ),
        Note::Closed(id) => (
            notification::APPROVAL_CLOSED,
            value(&Closed { id: id.clone() }),
        ),
    };
    line(&json!({"jsonrpc": "2.0", "method": method, "params": params}))
}

/// A refusal reply, its `data` the shared [`ErrorData`](sally_proto::ErrorData).
fn refused(id: &Id, data: &sally_proto::ErrorData) -> Vec<u8> {
    let data = value(data);
    failure(
        Some(id),
        json!({"code": REFUSED, "message": "Server error", "data": data}),
    )
}

/// Writes one frame within [`WRITE_TIMEOUT`]; whether it was written.
async fn write<W: AsyncWrite + Unpin>(w: &mut W, line: &[u8]) -> bool {
    matches!(
        tokio::time::timeout(WRITE_TIMEOUT, w.write_all(line)).await,
        Ok(Ok(()))
    )
}

#[cfg(test)]
#[path = "control_tests.rs"]
mod tests;
