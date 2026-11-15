//! `sessions.drive`: the host drives a session whose model is a script (architect rulings
//! Q117–Q122 on R3).
//!
//! A driven session serves no `agent.sock` and no `llm.sock`. The script is untrusted data: it
//! can only name tool calls, and each goes through [`Agent::drive_call`], the same classifier,
//! slot, entry and gate as a harness's call. Nothing the driver sends picks a call: the request
//! carries the session id only.
//!
//! One connection holds the session's seat for the session's life (a [`Seat`]); when it closes
//! the seat is gone, not free. A step runs one turn: its `drive.turn` entry first (sizes and a
//! hash, never the text), then its calls in order. A step ends at the first call the classifier
//! refuses; a tool's own denial is a result, as it would be to a model.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};

use sally_core::audit::Actor;
use sally_core::text::escape_capped;
use sally_proto::{Step, StepCall, TurnKind};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::agent::Driven;
use super::record::Recorder;
use crate::llm::scripted::{Call, Turn};
use crate::tools::ops::Ops;

/// Characters of an assistant message in a step reply, after escaping.
pub const CONTENT_CHARS: usize = 16 * 1024;
/// Characters of one call's result in a step reply, after escaping.
pub const RESULT_CHARS: usize = 16 * 1024;
/// Characters of a tool name in a step reply, after escaping.
pub const NAME_CHARS: usize = 64;

/// One driven tool call, as the registry wires it to the session's agent server.
pub type CallFuture = Pin<Box<dyn Future<Output = Driven> + Send>>;
/// What the driver calls to run a tool.
pub type CallFn = Box<dyn Fn(String, Map<String, Value>) -> CallFuture + Send + Sync>;

/// Why a connection did not get the seat (`sessions.drive` refusal reasons).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeatRefusal {
    /// Another connection holds it.
    Busy,
    /// The connection that held it closed; the seat is single-use.
    Gone,
}

impl SeatRefusal {
    /// The reason code of the refusal.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            Self::Busy => "driver-busy",
            Self::Gone => "driver-gone",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SeatState {
    Free,
    Held,
    Gone,
}

/// What one [`Seat::step`] came to.
#[derive(Debug, PartialEq, Eq)]
pub enum Stepped {
    /// The turn ran; this is its reply.
    Step(Step),
    /// Refused with this reason, and nothing was written (`session-stopping`).
    Refused(&'static str),
    /// An entry could not be written: close the connection, send no reply.
    Close,
}

/// One driven session: its script, its cursor and its seat.
pub struct Driver {
    turns: Vec<Turn>,
    call: CallFn,
    record: Recorder,
    ops: Ops,
    next: tokio::sync::Mutex<usize>,
    seat: Mutex<SeatState>,
}

/// A connection's hold on a session's seat; dropping it (the connection closed) makes the
/// seat gone.
pub struct Seat(Arc<Driver>);

impl Drop for Seat {
    fn drop(&mut self) {
        *self.0.seat.lock().unwrap_or_else(PoisonError::into_inner) = SeatState::Gone;
    }
}

impl Driver {
    /// A driver for `turns`, calling tools through `call`, writing through `record` (the
    /// session's driven recorder) and refusing once `ops` is closed.
    #[must_use]
    pub fn build(turns: Vec<Turn>, call: CallFn, record: Recorder, ops: Ops) -> Arc<Self> {
        Arc::new(Self {
            turns,
            call,
            record,
            ops,
            next: tokio::sync::Mutex::new(0),
            seat: Mutex::new(SeatState::Free),
        })
    }

    /// Takes the seat for one connection.
    ///
    /// # Errors
    /// [`SeatRefusal`]: held by another connection, or gone.
    pub fn claim(self: &Arc<Self>) -> Result<Seat, SeatRefusal> {
        let mut state = self.seat.lock().unwrap_or_else(PoisonError::into_inner);
        match *state {
            SeatState::Free => {
                *state = SeatState::Held;
                Ok(Seat(Arc::clone(self)))
            }
            SeatState::Held => Err(SeatRefusal::Busy),
            SeatState::Gone => Err(SeatRefusal::Gone),
        }
    }
}

impl Seat {
    /// Whether this is the seat of `driver`.
    #[must_use]
    pub fn is_of(&self, driver: &Arc<Driver>) -> bool {
        Arc::ptr_eq(&self.0, driver)
    }

    /// Runs the next scripted turn.
    pub async fn step(&self) -> Stepped {
        let d = &*self.0;
        let mut next = d.next.lock().await;
        if d.ops.is_closed() {
            return Stepped::Refused("session-stopping");
        }
        let Some(turn) = d.turns.get(*next) else {
            return Stepped::Step(Step {
                turn: 0,
                kind: TurnKind::End,
                content: None,
                calls: Vec::new(),
                done: true,
            });
        };
        let number = u32::try_from(*next + 1).unwrap_or(u32::MAX);
        if !d.record_turn(number, turn).await {
            return Stepped::Close;
        }
        *next += 1;
        let last = *next >= d.turns.len();
        match turn {
            Turn::Content(text) => Stepped::Step(Step {
                turn: number,
                kind: TurnKind::Content,
                content: Some(escape_capped(text.as_bytes(), CONTENT_CHARS)),
                calls: Vec::new(),
                done: true,
            }),
            Turn::Fail => Stepped::Step(Step {
                turn: number,
                kind: TurnKind::Fail,
                content: None,
                calls: Vec::new(),
                done: true,
            }),
            Turn::ToolCalls(calls) => d.run_calls(number, calls, last).await,
        }
    }
}

impl Driver {
    /// The `drive.turn` entry: the turn's number and kind, its call count and, for a message,
    /// its size and SHA-256. Written before the turn's first call; whether it was written.
    async fn record_turn(&self, number: u32, turn: &Turn) -> bool {
        let args = match turn {
            Turn::Content(t) => json!({
                "turn": number, "kind": "content", "calls": 0,
                "content_bytes": t.len(), "content_sha256": hex(t.as_bytes()),
            }),
            Turn::Fail => json!({"turn": number, "kind": "fail", "calls": 0}),
            Turn::ToolCalls(c) => json!({"turn": number, "kind": "tool_calls", "calls": c.len()}),
        };
        let entry = self
            .record
            .entry(Actor::Driver, "drive.turn", Some("allow"))
            .args(args);
        self.record.append(entry).await
    }

    async fn run_calls(&self, number: u32, calls: &[Call], last: bool) -> Stepped {
        let mut out = Vec::with_capacity(calls.len());
        let mut done = last;
        for c in calls {
            let name = escape_capped(c.name.as_bytes(), NAME_CHARS);
            match (self.call)(c.name.clone(), c.arguments.clone()).await {
                Driven::Done(o) => out.push(StepCall {
                    name,
                    result: escape_capped(o.text.as_bytes(), RESULT_CHARS),
                }),
                Driven::Denied(reason) => {
                    out.push(StepCall {
                        name,
                        result: format!("denied: {reason}"),
                    });
                    done = true;
                    break;
                }
                Driven::Unrecorded => return Stepped::Close,
            }
        }
        Stepped::Step(Step {
            turn: number,
            kind: TurnKind::ToolCalls,
            content: None,
            calls: out,
            done,
        })
    }
}

fn hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
#[path = "drive_tests.rs"]
mod tests;
