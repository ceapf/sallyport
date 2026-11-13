//! One session's life after its start (architect Q57, stop order amended by Q59).
//!
//! The supervisor waits for the first reason (a request, the timeout, a crash, the container's
//! exit) and ends the session once:
//! 1. the session's operations close, at once: a call arriving from now on is denied
//!    `session-stopping`, and nothing new starts;
//! 2. `session.timeout` (timeout) or `session.crash` (crash);
//! 3. every pending approval is withdrawn (`approval.withdraw`, `session-stop`);
//! 4. the stop signal: a running shell is killed, a write or delete that has not begun aborts;
//!    the agent listener shuts down meanwhile;
//! 5. at most [`STOP_DRAIN`] for the operations in flight to end, each with its `tool.result`;
//!    a panic reported meanwhile is audited `session.crash` (Q67);
//! 6. the seal (ruling 1, Q63): the session's audit handle stops admitting writes, those in
//!    flight get what is left of the same deadline, then the one `session.stop {reason,
//!    in_flight}` is written, and every later write of the handle fails (an oplog line names
//!    its session and event);
//! 7. `Launcher::stop`, retried a bounded number of times.
//!
//! So after `session.stop` no tool, approval or rpc entry of the session is written, whatever
//! its `in_flight`: a write in flight at the deadline lands before it or fails, and a failed
//! write means no effect. Teardown entries (`sandbox.*`, the watchdog's, egress closes) may
//! follow it; TODO(#94) adds `session.closed` after them. An operation still running past the
//! bound is a file operation inside its blocking call, which is never cut: the stop then
//! answers `Failed`, the session stays stop-failed with its claims and its watchdog, and the
//! supervisor removes the container by itself once the operation returns (its `tool.result` is
//! refused by the seal). A container that cannot be confirmed gone also stays stop-failed; a
//! later request retries it.

use std::time::Duration;

use sally_core::audit::Actor;
use serde_json::json;
use tokio::sync::mpsc;

use super::exit::Exit;
use super::registry::{LOG, Registry, Reply, SessionState, StopOutcome};
use super::types::StopReason;
use crate::approvals::queue::Desk;
use crate::daemon::crash::{Crash, CrashReceiver, CrashReporter};
use crate::rpc::listen::Handle;
use crate::rpc::record::Recorder;
use crate::sandbox::Running;
use crate::tools::ops::{Ops, STOP_DRAIN};

/// `Launcher::stop` attempts per stop before the session is left stop-failed.
const STOP_ATTEMPTS: u32 = 3;
/// Pause between two `Launcher::stop` attempts.
const STOP_RETRY: Duration = Duration::from_secs(2);

/// A stop request and where to answer it.
pub(super) type Request = (StopReason, Option<Reply>);

/// What a session's supervisor owns.
pub(super) struct Supervised {
    pub(super) sid: String,
    /// The session's audit handle, shared with its tools, desk and agent server.
    pub(super) record: Recorder,
    pub(super) timeout: Duration,
    pub(super) running: Running,
    pub(super) agent: Option<Handle>,
    pub(super) desk: Desk,
    pub(super) ops: Ops,
    pub(super) exit: Exit,
    /// The session's crash reporter, whose reports `crashes` receives.
    pub(super) crash: CrashReporter,
    pub(super) crashes: CrashReceiver,
    pub(super) requests: mpsc::Receiver<Request>,
    /// Set when the session must end at once (`start-failed`).
    pub(super) first: Option<StopReason>,
}

/// What ended the wait.
enum Why {
    Asked(StopReason, Option<Reply>),
    Crashed(Crash),
    Other(StopReason),
}

impl Registry {
    pub(super) async fn supervise(self: std::sync::Arc<Self>, s: Supervised) {
        let Supervised {
            sid,
            record,
            timeout,
            running,
            agent,
            desk,
            ops,
            exit,
            crash,
            mut crashes,
            mut requests,
            first,
        } = s;
        let why = match first {
            Some(r) => Why::Other(r),
            None => {
                tokio::select! {
                    r = requests.recv() => match r {
                        Some((r, reply)) => Why::Asked(r, reply),
                        None => Why::Other(StopReason::Shutdown),
                    },
                    () = tokio::time::sleep(timeout) => Why::Other(StopReason::Timeout),
                    Some(c) = crashes.recv() => Why::Crashed(c),
                    () = exit.exited() => Why::Other(StopReason::Exited),
                }
            }
        };
        // 1. Before any await.
        ops.close();
        let mut replies = Vec::new();
        let reason = match why {
            Why::Asked(r, reply) => {
                replies.extend(reply);
                r
            }
            Why::Crashed(c) => {
                self.crashed(&record, &c).await;
                StopReason::Crash
            }
            Why::Other(r) => r,
        };
        if reason == StopReason::Timeout {
            self.note(
                &record,
                "session.timeout",
                json!({"timeout_secs": timeout.as_secs()}),
            )
            .await;
        }
        // 3, 4, 5. One deadline for the drain and the seal's wait (Q63).
        if let Err(e) = desk.stop().await {
            crash.joined("approvals", e);
        }
        ops.stop();
        let deadline = tokio::time::Instant::now() + STOP_DRAIN;
        let listener = async {
            if let Some(h) = agent {
                h.shutdown().await;
            }
        };
        let ((), in_flight) = tokio::join!(listener, ops.drained(STOP_DRAIN));
        // A panic during the stop is audited before the seal (Q67); the reason stays.
        while let Ok(c) = crashes.try_recv() {
            self.crashed(&record, &c).await;
        }
        // 6. The seal: after `session.stop` no entry of the session's handle is written.
        let stop = record
            .entry(Actor::Sallyd, "session.stop", None)
            .args(json!({"reason": reason.as_str(), "in_flight": in_flight}));
        let wait = deadline.saturating_duration_since(tokio::time::Instant::now());
        let sealed = record.seal(stop, wait).await;
        if !sealed.written {
            self.p.oplog.error(
                LOG,
                "session entry not audited",
                &[("session", &sid), ("event", "session.stop")],
            );
        }
        if sealed.late > 0 {
            self.p.oplog.error(
                LOG,
                "session entries still being written at session.stop",
                &[("session", &sid), ("late", &sealed.late.to_string())],
            );
        }
        if in_flight > 0 {
            self.wait_out(&sid, &ops, &mut replies, &mut requests, in_flight)
                .await;
        }
        // 7.
        self.retry_stop(sid, running, replies, requests, reason)
            .await;
        // A crash reported after the reason was chosen is not lost.
        while let Ok(c) = crashes.try_recv() {
            self.p.oplog.error(
                LOG,
                "session task panicked during its stop",
                &[("task", c.task), ("payload", &c.payload)],
            );
        }
    }

    /// Operations still run past the drain: the session stays stop-failed, every request is
    /// answered `Failed`, until the last one returns. TODO(#96): a Shutdown request is answered
    /// `Failed` too, so the container outlives `sallyd` until the next startup sweep (Q66).
    async fn wait_out(
        &self,
        sid: &str,
        ops: &Ops,
        replies: &mut Vec<Reply>,
        requests: &mut mpsc::Receiver<Request>,
        in_flight: usize,
    ) {
        self.p.oplog.error(
            LOG,
            "session operations still running after the drain",
            &[("session", sid), ("in_flight", &in_flight.to_string())],
        );
        self.stop_failed(sid);
        let why = format!("{in_flight} operations of session {sid} still running");
        for r in replies.drain(..) {
            let _ = r.send(StopOutcome::Failed(why.clone()));
        }
        loop {
            tokio::select! {
                () = ops.idle() => return,
                r = requests.recv() => match r {
                    Some((_, Some(reply))) => {
                        let n = ops.in_flight();
                        let _ = reply.send(StopOutcome::Failed(format!(
                            "{n} operations of session {sid} still running"
                        )));
                    }
                    Some((_, None)) => {}
                    // The registry dropped the session: only the operations matter now.
                    None => {
                        ops.idle().await;
                        return;
                    }
                },
            }
        }
    }

    fn stop_failed(&self, sid: &str) {
        if let Some(l) = self.live().get_mut(sid) {
            l.info.state = SessionState::StopFailed;
        }
    }

    /// `Launcher::stop` until the container is confirmed gone: bounded attempts, then
    /// stop-failed, retried on each later request. Answers every request it has.
    pub(super) async fn retry_stop(
        &self,
        sid: String,
        running: Running,
        mut replies: Vec<Reply>,
        mut requests: mpsc::Receiver<Request>,
        reason: StopReason,
    ) {
        let mut running = running;
        loop {
            match self.stop_bounded(running).await {
                Ok(()) => {
                    self.live().remove(&sid);
                    requests.close();
                    while let Ok((_, reply)) = requests.try_recv() {
                        replies.extend(reply);
                    }
                    for r in replies.drain(..) {
                        let _ = r.send(StopOutcome::Stopped);
                    }
                    self.p.oplog.info(
                        LOG,
                        "session stopped",
                        &[("session", &sid), ("reason", reason.as_str())],
                    );
                    return;
                }
                Err(r) => {
                    running = *r;
                    self.p.oplog.error(
                        LOG,
                        "session container not confirmed gone",
                        &[("session", &sid)],
                    );
                    self.stop_failed(&sid);
                    let why = format!("the container of session {sid} could not be confirmed gone");
                    for r in replies.drain(..) {
                        let _ = r.send(StopOutcome::Failed(why.clone()));
                    }
                    match requests.recv().await {
                        Some((_, reply)) => {
                            replies.extend(reply);
                            // Requests queued meanwhile share this round (R5).
                            while let Ok((_, reply)) = requests.try_recv() {
                                replies.extend(reply);
                            }
                        }
                        // Unreachable while the registry holds the sender; retry anyway.
                        None => tokio::time::sleep(STOP_RETRY).await,
                    }
                }
            }
        }
    }

    /// `Launcher::stop`, at most [`STOP_ATTEMPTS`] times.
    pub(super) async fn stop_bounded(&self, running: Running) -> Result<(), Box<Running>> {
        let mut r = running;
        for attempt in 1..=STOP_ATTEMPTS {
            match self.p.launcher.stop(r).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    let detail = e.error.to_string();
                    self.p.oplog.warn(
                        LOG,
                        "workspace stop failed",
                        &[
                            ("session", e.running.paths().id().as_str()),
                            ("attempt", &attempt.to_string()),
                            ("detail", &detail),
                        ],
                    );
                    r = e.running;
                }
            }
            if attempt < STOP_ATTEMPTS {
                tokio::time::sleep(STOP_RETRY).await;
            }
        }
        Err(Box::new(r))
    }

    /// Q47: the oplog line, then `session.crash`. A failed append still ends the session.
    async fn crashed(&self, record: &Recorder, c: &Crash) {
        self.p.oplog.error(
            LOG,
            "session task panicked",
            &[
                ("session", record.session()),
                ("task", c.task),
                ("payload", &c.payload),
            ],
        );
        self.note(
            record,
            "session.crash",
            json!({"task": c.task, "reason": "panic", "payload": c.payload}),
        )
        .await;
    }

    /// A `deny` session entry of sallyd's, through the session's handle; a failed append is an
    /// oplog line and changes nothing else.
    async fn note(&self, record: &Recorder, event: &'static str, args: serde_json::Value) {
        let entry = record.entry(Actor::Sallyd, event, Some("deny")).args(args);
        if !record.append(entry).await {
            self.p.oplog.error(
                LOG,
                "session entry not audited",
                &[("session", record.session()), ("event", event)],
            );
        }
    }
}
