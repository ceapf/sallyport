//! The control socket's line mode (architect Q101, Q102, Q144–Q152): `sessions.attach`,
//! `sessions.input`, the `session.output` notifications and the deferred replies the serve loop
//! sends, and the sessions bound to a connection.
//!
//! An attach is the connection's state, like a watch: the serve loop keeps reading frames
//! while the command runs (only `sessions.input` is served then), and between frames it sends
//! the command's output, the answer to the pending input once it was written, and at the end
//! the attach's reply: after all output, after the pending input's answer (`input-closed` if
//! it was not written), and after `sandbox.exec_result`. The connection's end, a write that
//! fails or times out, and the connection's future being dropped kill the command
//! (`killed: disconnect`).
//!
//! A session created with `lifetime: "connection"` is bound to that connection from before
//! its create reply: when the connection ends (after its attach, if any, ended) it is stopped
//! with reason `disconnect`, in a task of the daemon's. A stop that fails is a `session.refuse`
//! `stop-failed` in the control log; one of a session already gone writes nothing.

use sally_core::audit::Actor;
use sally_core::text::escape_capped;
use sally_proto::{Output, method, notification};
use serde_json::json;
use tokio::io::AsyncWrite;
use tokio::sync::oneshot;

use super::agent::{line, success};
use super::attach::{self, Ended, InputState};
use super::control::{Conn, Control, refused, write};
use super::control_methods::{AttachCall, DETAIL_CHARS, Done, InputCall, SessionSet, value};
use super::line::{NotStarted, Running};
use super::message::Id;
use crate::sandbox::SessionId;
use crate::session::StopOutcome;
use crate::tools::shell::{Chunk, Input};

/// A connection's attached command.
#[derive(Debug)]
pub(crate) struct Attachment {
    /// The session.
    session: String,
    /// The attach's request id: its reply comes when the command ended.
    reply: Id,
    run: Running,
    /// The input taken and not yet written: its request id and the runner's answer.
    pending: Option<(Id, oneshot::Receiver<bool>)>,
    /// The input ended (`eof`) or a write to the pipe failed.
    closed: bool,
    /// The command's output may still bring chunks.
    output_open: bool,
}

/// What the serve loop does next for its attach.
pub(crate) enum Event {
    /// Send this output.
    Output(Chunk),
    /// Answer the input `Id`: written or not.
    Ack(Id, bool),
    /// The command ended: its reply, `None` for no reply.
    Done(Option<Ended>),
}

impl Attachment {
    /// The next thing to send; never, until there is one. Output goes first, so the reply comes
    /// after the last of it. Cancel-safe: nothing is taken until a branch is chosen.
    pub(crate) async fn next(&mut self) -> Event {
        loop {
            let pending = async {
                match self.pending.as_mut() {
                    Some((_, rx)) => rx.await.unwrap_or(false),
                    None => std::future::pending().await,
                }
            };
            let got = tokio::select! {
                biased;
                c = self.run.output.recv(), if self.output_open => c.map(Event::Output),
                ok = pending => {
                    let id = self.pending.take().map(|(id, _)| id);
                    id.map(|id| Event::Ack(id, ok))
                },
                d = &mut self.run.done => Some(Event::Done(d.ok().flatten())),
            };
            match got {
                Some(e) => return e,
                None => self.output_open = false,
            }
        }
    }

    /// Kills the command (`disconnect`) and waits for its task's end: its result entry is
    /// written by then.
    pub(crate) async fn disconnect(self) {
        self.run.disconnect.send_replace(true);
        let _ = self.run.done.await;
    }
}

/// A session bound to its connection: stopped when this is dropped.
pub(crate) struct Bound(Option<Box<dyn FnOnce() + Send>>);

impl Drop for Bound {
    fn drop(&mut self) {
        if let Some(stop) = self.0.take() {
            stop();
        }
    }
}

impl std::fmt::Debug for Bound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bound").finish_non_exhaustive()
    }
}

impl<S: SessionSet> Control<S> {
    /// `sessions.attach` on a plain connection (the state gate has passed it).
    pub(crate) async fn attach(&self, a: AttachCall, conn: &mut Conn, id: &Id) -> Done {
        let (client, m) = (conn.client, method::SESSIONS_ATTACH);
        let refuse = |why| self.driver_refused(m, Some(&a.id), why, client);
        let Some(l) = self.p.sessions.line(a.id.as_str()) else {
            return refuse("unknown-session").await;
        };
        if l.stopping() {
            return refuse(crate::tools::STOPPING).await;
        }
        let Some(claim) = l.claim() else {
            return refuse("attach-busy").await;
        };
        let cwd = match l.cwd(a.cwd.as_deref()) {
            Ok(c) => c,
            Err(why) => return refuse(why).await,
        };
        match l.start(claim, a.argv, cwd, client).await {
            Ok(run) => {
                conn.attach = Some(Attachment {
                    session: a.id.as_str().to_owned(),
                    reply: id.clone(),
                    run,
                    pending: None,
                    closed: false,
                    output_open: true,
                });
                Done::Deferred
            }
            Err(NotStarted::Stopping) => refuse(crate::tools::STOPPING).await,
            Err(NotStarted::Unaudited) => Done::Close,
        }
    }

    /// `sessions.input` on an attached connection (the state gate has passed it).
    pub(crate) async fn input(&self, i: InputCall, conn: &mut Conn, id: &Id) -> Done {
        let (client, m) = (conn.client, method::SESSIONS_INPUT);
        let Some(a) = conn.attach.as_mut() else {
            return self
                .driver_refused(m, Some(&i.id), "not-attached", client)
                .await;
        };
        let state = InputState {
            pending: a.pending.is_some(),
            closed: a.closed,
        };
        if let Err(why) = attach::admit_input(&a.session, i.id.as_str(), state) {
            return self.driver_refused(m, Some(&i.id), why, client).await;
        }
        let (done, ack) = oneshot::channel();
        let taken = a.run.input.try_send(Input {
            data: i.data.into_bytes(),
            eof: i.eof,
            done,
        });
        if taken.is_err() {
            // The command's input is gone: it ended, or its writer stopped.
            a.closed = true;
            return self
                .driver_refused(m, Some(&i.id), "input-closed", client)
                .await;
        }
        a.closed |= i.eof;
        a.pending = Some((id.clone(), ack));
        Done::Deferred
    }

    /// Sends what `event` calls for; `false` closes the connection.
    pub(crate) async fn on_event<W: AsyncWrite + Unpin>(
        &self,
        event: Event,
        conn: &mut Conn,
        w: &mut W,
    ) -> bool {
        match event {
            Event::Output(c) => {
                let Some(a) = conn.attach.as_ref() else {
                    return true;
                };
                write(w, &output(&a.session, c)).await
            }
            Event::Ack(id, ok) => {
                let Some(a) = conn.attach.as_mut() else {
                    return true;
                };
                a.closed |= !ok;
                let session = a.session.clone();
                self.ack(&id, ok, &session, conn.client, w).await
            }
            Event::Done(end) => {
                let Some(mut a) = conn.attach.take() else {
                    return true;
                };
                // Whatever output is still queued goes first, then the pending input's answer.
                while let Some(c) = a.run.output.recv().await {
                    if !write(w, &output(&a.session, c)).await {
                        return false;
                    }
                }
                if let Some((id, rx)) = a.pending.take() {
                    let ok = rx.await.unwrap_or(false);
                    if !self.ack(&id, ok, &a.session, conn.client, w).await {
                        return false;
                    }
                }
                let sid = SessionId::parse(&a.session).ok();
                let reply = match end {
                    None => return false,
                    Some(Ended::Reply(r)) => success(&a.reply, value(&r)),
                    Some(Ended::Failed) => {
                        let m = method::SESSIONS_ATTACH;
                        match self
                            .driver_refused(m, sid.as_ref(), "exec-failed", conn.client)
                            .await
                        {
                            Done::Refused(data) => refused(&a.reply, &data),
                            Done::Ok(_) | Done::Close | Done::Deferred => return false,
                        }
                    }
                };
                write(w, &reply).await
            }
        }
    }

    /// Answers input `id`: `{}` once written, else `input-closed` (its entry first).
    async fn ack<W: AsyncWrite + Unpin>(
        &self,
        id: &Id,
        ok: bool,
        session: &str,
        client: crate::approvals::Client,
        w: &mut W,
    ) -> bool {
        let reply = if ok {
            success(id, json!({}))
        } else {
            let sid = SessionId::parse(session).ok();
            let m = method::SESSIONS_INPUT;
            match self
                .driver_refused(m, sid.as_ref(), "input-closed", client)
                .await
            {
                Done::Refused(data) => refused(id, &data),
                Done::Ok(_) | Done::Close | Done::Deferred => return false,
            }
        };
        write(w, &reply).await
    }

    /// The guard that stops session `id` when its connection ends (architect Q150).
    pub(crate) fn bind(&self, id: &str) -> Bound {
        let sessions = self.p.sessions.clone();
        let record = self.p.record.clone();
        let crash = self.p.crash.clone();
        let id = id.to_owned();
        Bound(Some(Box::new(move || {
            drop(crash.spawn("session.disconnect", async move {
                let Some(StopOutcome::Failed(why)) = sessions.stop_disconnected(&id).await else {
                    return;
                };
                let detail = escape_capped(why.as_bytes(), DETAIL_CHARS);
                let args = json!({
                    "id": id, "reason": "stop-failed", "detail": detail, "cause": "disconnect",
                });
                let entry = record
                    .entry(Actor::Sallyd, "session.refuse", Some("refuse"))
                    .args(args);
                let _ = record.append(entry).await;
            }));
        })))
    }
}

/// One `session.output` notification.
fn output(session: &str, c: Chunk) -> Vec<u8> {
    let params = Output {
        id: session.to_owned(),
        stream: c.stream,
        text: c.text,
    };
    line(
        &json!({"jsonrpc": "2.0", "method": notification::SESSION_OUTPUT,
        "params": value(&params)}),
    )
}
