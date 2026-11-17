//! The pending queue: the [`Gate`] a tool handler asks, the [`Desk`] a host client answers
//! (SI-5; maintainer's Task 10 decisions 1–7; architect rulings Q19, Q22–Q25).
//!
//! Its children: `types` (the public vocabulary), `fields` (the entries' audit fields) and
//! `decide` (deciding a shown prompt).
//!
//! - **Who answers.** [`new`] returns the two halves apart. The tool handler behind `agent.sock`
//!   holds only the `Gate` (ask, withdraw); the `Desk` (list, decide) belongs to control-side
//!   code (Task 12 wires `approvals.list`/`approvals.decide` on `control.sock`, with the client
//!   taken from `SO_PEERCRED`). Nothing the harness reaches can decide.
//! - **What is approved.** A prompt binds the [`Bound`] digest: session, the broker's call
//!   number and every byte that runs. An approval yields a [`Ticket`] holding the asker's own
//!   copy of that action; the executor runs the ticket and nothing else. Ids are 128-bit random,
//!   single use: deciding removes the entry under the lock, so a second decide is `unknown-id`.
//! - **Default deny.** No approver attached, a timeout, a dropped wait, a withdrawn call: deny.
//!   A withdraw that arrives before the call reaches the queue is kept until the call ends, so
//!   the call is never shown.
//! - **Bounds.** Per session at most `max_pending` prompts wait, and new prompts come at most one
//!   per [`REFILL`] with a burst of `max_pending`; over either bound a call is denied
//!   `approval-flood`, each with its own entry, and each flood episode is announced once
//!   (`approval.flood`). `agent.sock` runs at most 16 calls at once, so a `max_pending` above 16
//!   is never reached.
//! - **Audit.** `tool.pending` before the prompt is shown; `approval.decide` (with the deciding
//!   client) before the asker learns the answer (a `deny_all_session` latches first, so a
//!   failed entry still leaves the session latched);
//!   `approval.expire`, `approval.withdraw`, `approval.deny`, `approval.flood`, `tool.deny`
//!   before the denial is returned. A failed append is [`Refusal::Unrecorded`]: nothing runs and
//!   no reply is sent. A decision or withdraw, once it has taken an entry, finishes in its own
//!   task, so dropping its caller loses no entry. A wait dropped by teardown is invalidated at
//!   once without an entry; the session's stop entry covers it.
//! - **Poison.** A panic while the queue's lock is held latches the session: every later prompt
//!   is denied.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use sally_core::audit::{Actor, NewEntry};
use serde_json::{Value, json};
use tokio::sync::oneshot;

use super::action::{Bound, hex};
use super::policy::{Need, Policy};
use super::render::Prompt;
use crate::rpc::agent::Withdraw;
use crate::rpc::rate::Rate;
use crate::rpc::record::Recorder;
use crate::tools::STOPPING;

mod decide;
mod fields;
mod types;

pub use fields::AUDIT_ACTION_CHARS;
pub(crate) use fields::{Fields, who};
use fields::{add, call_denied};
pub use types::{Approver, Client, DecideError, Decision, Limits, Refusal, Seen};

/// One new prompt per this interval, on average (architect ruling Q22; tunable).
pub const REFILL: Duration = Duration::from_secs(2);
/// Attempts at `getrandom(2)` before an id is unavailable (it is interrupted only by signals).
const ID_ATTEMPTS: usize = 3;

/// Leave to run one action: the only input an executor takes. Not `Clone`; made only here.
#[derive(Debug, PartialEq, Eq)]
pub struct Ticket {
    bound: Bound,
    approval: Option<String>,
}

impl Ticket {
    /// The action, bound to its session and call.
    #[must_use]
    pub fn bound(&self) -> &Bound {
        &self.bound
    }

    /// The action to run.
    #[must_use]
    pub fn action(&self) -> &super::action::Action {
        &self.bound.action
    }

    /// The approval id, when a human approved it (`None`: the policy needs no approval).
    #[must_use]
    pub fn approval(&self) -> Option<&str> {
        self.approval.as_deref()
    }
}

enum Answer {
    Approve,
    Deny(&'static str),
    Withdrawn,
    Unrecorded,
}

struct Entry {
    id: String,
    call: u64,
    prompt: Arc<Prompt>,
    /// The action's audit fields, raw (architect Q288 f): never the prompt's escaped text.
    fields: Fields,
    /// `tool.pending` is written and the approver told: only then can it be decided.
    announced: bool,
    /// A withdraw arrived before it was announced.
    withdrawn: Option<Withdraw>,
    tx: oneshot::Sender<Answer>,
}

struct State {
    pending: Vec<Entry>,
    /// Calls begun and not yet ended ([`Gate::begin`] to [`Gate::forget`]).
    live: HashSet<u64>,
    /// Live calls withdrawn before they reached the queue (so at most the live ones).
    withdrawn: HashMap<u64, Withdraw>,
    latched: bool,
    /// The session is stopping: nothing queues any more (architect Q59).
    stopping: bool,
    flooding: bool,
    rate: Rate,
}

struct Inner {
    policy: Policy,
    limits: Limits,
    record: Recorder,
    session: String,
    approver: Option<Arc<dyn Approver>>,
    state: Mutex<State>,
    /// The next call number of the session.
    calls: AtomicU64,
    /// Held by one decision from its take to its last entry, so a `deny_all_session` covers
    /// every prompt shown before it latches and no other decision slips in meanwhile.
    deciding: Arc<tokio::sync::Mutex<()>>,
}

/// Why a call does not queue.
enum NotQueued {
    /// Denied with this code; `true` when a flood episode starts with it.
    Deny(&'static str, bool),
    /// Withdrawn before it was shown.
    Withdrawn(Withdraw),
}

/// The asking half (held by the tool handler).
#[derive(Clone)]
pub struct Gate {
    inner: Arc<Inner>,
}

/// The answering half (held by control-side code only): `approvals.list`, `approvals.watch`
/// and `approvals.decide` on `control.sock` read and answer it (architect Q85).
#[derive(Clone)]
pub struct Desk {
    inner: Arc<Inner>,
}

/// A session's approvals: the gate for its tool handler and the desk for its host clients.
#[must_use]
pub fn new(
    session: String,
    policy: Policy,
    limits: Limits,
    record: Recorder,
    approver: Option<Arc<dyn Approver>>,
) -> (Gate, Desk) {
    let burst = u32::try_from(limits.max_pending).unwrap_or(u32::MAX);
    let inner = Arc::new(Inner {
        policy,
        limits,
        record,
        session,
        approver,
        state: Mutex::new(State {
            pending: Vec::new(),
            live: HashSet::new(),
            withdrawn: HashMap::new(),
            latched: false,
            stopping: false,
            flooding: false,
            rate: Rate::every(REFILL, burst),
        }),
        calls: AtomicU64::new(0),
        deciding: Arc::new(tokio::sync::Mutex::new(())),
    });
    (
        Gate {
            inner: Arc::clone(&inner),
        },
        Desk { inner },
    )
}

impl Gate {
    /// The session this gate binds actions to.
    #[must_use]
    pub fn session(&self) -> &str {
        &self.inner.session
    }

    /// Decides whether `bound` may run: policy first (deny before ask), then, if it needs a
    /// human, a prompt and the wait for its answer. `note` is model text shown apart from the
    /// action; `destructive` is the shell tagger's verdict (`None`: no tagger ran).
    ///
    /// # Errors
    /// The refusal; every `Denied` has its entry written.
    pub async fn admit(
        &self,
        bound: Bound,
        note: Option<&str>,
        destructive: Option<bool>,
    ) -> Result<Ticket, Refusal> {
        match self.inner.policy.need(&bound.action, destructive) {
            Need::Run => Ok(Ticket {
                bound,
                approval: None,
            }),
            Need::Deny(code) => {
                let mut f = Fields::of(&bound);
                add(&mut f.args, "code", Value::from(code));
                let entry = self.inner.denial(Actor::Sallyd, "tool.deny");
                Err(self.inner.refused(f.on(entry), code).await)
            }
            Need::Ask => {
                let tags = if destructive == Some(true) {
                    vec!["destructive".to_owned()]
                } else {
                    Vec::new()
                };
                self.ask(bound, note, tags).await
            }
        }
    }

    async fn ask(
        &self,
        bound: Bound,
        note: Option<&str>,
        tags: Vec<String>,
    ) -> Result<Ticket, Refusal> {
        let inner = &self.inner;
        let mut f = Fields::of(&bound);
        let (id, rx) = match inner.queue(&bound, f.clone(), note, tags) {
            Ok(q) => q,
            Err(NotQueued::Withdrawn(why)) => {
                return Err(inner.withdrawn_before_shown(bound.call, None, why).await);
            }
            Err(NotQueued::Deny(code, episode)) => {
                if episode && !inner.flood_started().await {
                    return Err(Refusal::Unrecorded);
                }
                add(&mut f.args, "reason", Value::from(code));
                let entry = inner.denial(Actor::Sallyd, "approval.deny");
                return Err(inner.refused(f.on(entry), code).await);
            }
        };
        let guard = Waiting {
            inner: Arc::clone(inner),
            id: id.clone(),
        };
        if !inner.pending_entry(&id, f, note).await {
            return Err(Refusal::Unrecorded);
        }
        match inner.announce(&id) {
            Ok(()) => {}
            Err(NotQueued::Withdrawn(why)) => {
                return Err(inner
                    .withdrawn_before_shown(bound.call, Some(&id), why)
                    .await);
            }
            Err(NotQueued::Deny(code, _)) => {
                let args = json!({"id": id, "call": bound.call, "reason": code});
                return Err(inner
                    .refuse("approval.deny", Actor::Sallyd, args, code)
                    .await);
            }
        }
        let answer = inner.wait(&id, rx).await;
        drop(guard);
        match answer {
            Answer::Approve => Ok(Ticket {
                bound,
                approval: Some(id),
            }),
            Answer::Deny(code) => Err(Refusal::Denied(code)),
            Answer::Withdrawn => Err(Refusal::Denied("withdrawn")),
            Answer::Unrecorded => Err(Refusal::Unrecorded),
        }
    }

    /// Refuses a call the executor could not turn into an action: `tool.deny` with the tool's
    /// name (declared, see `call_denied`) and the code, before the denial is returned.
    pub async fn refuse_call(&self, call: u64, tool: &str, code: &'static str) -> Refusal {
        let entry = call_denied(
            self.inner.denial(Actor::Sallyd, "tool.deny"),
            call,
            tool,
            code,
        );
        self.inner.refused(entry, code).await
    }

    /// Withdraws the prompt of `call` (#54): a shown prompt leaves the queue and its asker gets
    /// `withdrawn`; a call not yet shown is never shown. Once it has taken the prompt it
    /// finishes in its own task, so dropping this future loses no entry.
    pub async fn withdraw(&self, call: u64, why: Withdraw) {
        let taken = {
            let mut st = self.inner.state();
            // The first cause is the one recorded (a cancel, then the connection closing).
            match st.pending.iter().position(|e| e.call == call) {
                None => {
                    // Only a call still running can reach the queue later; one that ended is
                    // not remembered, so the map stays bounded by the calls in flight.
                    if st.live.contains(&call) {
                        st.withdrawn.entry(call).or_insert(why);
                    }
                    return;
                }
                Some(i) if st.pending.get(i).is_some_and(|e| !e.announced) => {
                    if let Some(e) = st.pending.get_mut(i) {
                        e.withdrawn.get_or_insert(why);
                    }
                    return;
                }
                Some(i) => st.pending.remove(i),
            }
        };
        let inner = Arc::clone(&self.inner);
        let task = tokio::spawn(async move {
            let (actor, reason) = withdraw_by(why);
            let args = json!({"id": taken.id, "call": call, "reason": reason});
            let entry = inner
                .record
                .entry(actor, "approval.withdraw", Some("deny"))
                .args(args);
            let answer = if inner.record.append(entry).await {
                Answer::Withdrawn
            } else {
                Answer::Unrecorded
            };
            inner.close(taken, answer);
        });
        let _ = task.await;
    }

    /// A new call: its number, unique in the session, and live until [`forget`](Self::forget).
    #[must_use]
    pub fn begin(&self) -> u64 {
        let call = self.inner.calls.fetch_add(1, Ordering::Relaxed);
        self.inner.state().live.insert(call);
        call
    }

    /// The call ended: it is no longer live, and a withdraw kept for it is dropped.
    pub fn forget(&self, call: u64) {
        let mut st = self.inner.state();
        st.live.remove(&call);
        st.withdrawn.remove(&call);
    }

    /// How many calls are live and how many withdraws are kept (tests).
    #[cfg(test)]
    pub(crate) fn kept(&self) -> (usize, usize) {
        let st = self.inner.state();
        (st.live.len(), st.withdrawn.len())
    }
}

impl Desk {
    /// The session is stopping (architect Q59 (a) step 3): every shown prompt leaves the queue
    /// with `approval.withdraw` (`session-stop`) and its asker is denied; a prompt not yet shown
    /// never is; no call queues from now on (`approval.deny session-stopping`). Once it has
    /// taken the prompts it finishes in its own task, so dropping this future loses no entry.
    ///
    /// # Errors
    /// The task's [`JoinError`](tokio::task::JoinError) when it panicked, for the session's
    /// crash reporter (R8).
    pub async fn stop(&self) -> Result<(), tokio::task::JoinError> {
        let taken: Vec<Entry> = {
            let mut st = self.inner.state();
            st.stopping = true;
            let (shown, unshown): (Vec<Entry>, Vec<Entry>) =
                st.pending.drain(..).partition(|e| e.announced);
            st.pending = unshown;
            for e in &mut st.pending {
                e.withdrawn.get_or_insert(Withdraw::SessionStop);
            }
            shown
        };
        let inner = Arc::clone(&self.inner);
        let task = tokio::spawn(async move {
            let (actor, reason) = withdraw_by(Withdraw::SessionStop);
            for e in taken {
                let args = json!({"id": e.id, "call": e.call, "reason": reason});
                let entry = inner
                    .record
                    .entry(actor, "approval.withdraw", Some("deny"))
                    .args(args);
                let answer = if inner.record.append(entry).await {
                    Answer::Withdrawn
                } else {
                    Answer::Unrecorded
                };
                inner.close(e, answer);
            }
        });
        task.await
    }

    /// The prompts waiting for an answer.
    #[must_use]
    pub fn list(&self) -> Vec<Arc<Prompt>> {
        self.inner
            .state()
            .pending
            .iter()
            .filter(|e| e.announced)
            .map(|e| Arc::clone(&e.prompt))
            .collect()
    }
}

impl Inner {
    /// Locks the queue. A poisoned lock (a panic while it was held) latches the session.
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| {
            let mut st = p.into_inner();
            st.latched = true;
            st
        })
    }

    /// Queues a prompt for `bound` or says why not. Check order (architect ruling Q22): an
    /// earlier withdraw, the session latch, no approver, the pending bound, the rate; only a
    /// prompt actually queued takes a rate slot.
    fn queue(
        &self,
        bound: &Bound,
        fields: Fields,
        note: Option<&str>,
        tags: Vec<String>,
    ) -> Result<(String, oneshot::Receiver<Answer>), NotQueued> {
        let mut st = self.state();
        if st.flooding && st.pending.is_empty() && st.rate.full() {
            st.flooding = false;
        }
        if let Some(&why) = st.withdrawn.get(&bound.call) {
            return Err(NotQueued::Withdrawn(why));
        }
        if st.stopping {
            return Err(NotQueued::Deny(STOPPING, false));
        }
        if st.latched {
            return Err(NotQueued::Deny("session-denied", false));
        }
        if !self.approver.as_ref().is_some_and(|a| a.attached()) {
            return Err(NotQueued::Deny("no-approver", false));
        }
        if st.pending.len() >= self.limits.max_pending || st.rate.take().is_err() {
            let episode = !st.flooding;
            st.flooding = true;
            return Err(NotQueued::Deny("approval-flood", episode));
        }
        let Some(id) = new_id() else {
            return Err(NotQueued::Deny("id-unavailable", false));
        };
        let prompt = Arc::new(Prompt::new(id.clone(), bound, note, tags));
        let (tx, rx) = oneshot::channel();
        st.pending.push(Entry {
            id: id.clone(),
            call: bound.call,
            prompt,
            fields,
            announced: false,
            withdrawn: None,
            tx,
        });
        Ok((id, rx))
    }

    /// Writes `tool.pending` for the queued prompt `id`; whether it was written.
    async fn pending_entry(&self, id: &str, mut f: Fields, note: Option<&str>) -> bool {
        add(&mut f.args, "id", Value::from(id));
        if let Some(n) = note {
            add(&mut f.args, "note_bytes", Value::from(n.len()));
            add(
                &mut f.args,
                "note_sha256",
                Value::from(sha256(n.as_bytes())),
            );
        }
        let entry = f.on(self
            .record
            .entry(Actor::Harness, "tool.pending", Some("pending")));
        self.record.append(entry).await
    }

    /// Writes the episode's `approval.flood` and tells the approver; whether it was written.
    /// If it was not, the next flood starts the episode again.
    async fn flood_started(&self) -> bool {
        let entry = self
            .record
            .entry(Actor::Sallyd, "approval.flood", Some("deny"))
            .args(json!({"max_pending": self.limits.max_pending}));
        if !self.record.append(entry).await {
            self.state().flooding = false;
            return false;
        }
        if let Some(a) = &self.approver {
            a.flood(&self.session);
        }
        true
    }

    /// Makes `id` decidable and shows it, unless it was withdrawn or the session latched while
    /// its entry was written (then it leaves the queue with that reason).
    fn announce(&self, id: &str) -> Result<(), NotQueued> {
        let prompt = {
            let mut st = self.state();
            let latched = st.latched;
            let Some(i) = st.pending.iter().position(|e| e.id == id) else {
                return Err(NotQueued::Withdrawn(Withdraw::Closed));
            };
            let stop = match st.pending.get(i) {
                Some(e) => match e.withdrawn {
                    Some(why) => Some(NotQueued::Withdrawn(why)),
                    None if latched => Some(NotQueued::Deny("session-denied", false)),
                    None => None,
                },
                None => None,
            };
            if let Some(stop) = stop {
                st.pending.remove(i);
                return Err(stop);
            }
            let Some(e) = st.pending.get_mut(i) else {
                return Err(NotQueued::Withdrawn(Withdraw::Closed));
            };
            e.announced = true;
            Arc::clone(&e.prompt)
        };
        if let Some(a) = &self.approver {
            a.requested(&prompt);
        }
        Ok(())
    }

    /// The `approval.withdraw` of a call withdrawn before its prompt was shown.
    async fn withdrawn_before_shown(&self, call: u64, id: Option<&str>, why: Withdraw) -> Refusal {
        let (actor, reason) = withdraw_by(why);
        let args = json!({"id": id, "call": call, "reason": reason});
        self.refuse("approval.withdraw", actor, args, "withdrawn")
            .await
    }

    /// Waits for the answer to `id` until the timeout; on expiry the prompt leaves the queue.
    async fn wait(&self, id: &str, mut rx: oneshot::Receiver<Answer>) -> Answer {
        if let Ok(r) = tokio::time::timeout(self.limits.timeout, &mut rx).await {
            return r.unwrap_or(Answer::Unrecorded);
        }
        let expired = {
            let mut st = self.state();
            st.pending
                .iter()
                .position(|e| e.id == id)
                .map(|i| st.pending.remove(i))
        };
        let Some(e) = expired else {
            // A decision or withdraw took it first and is being written: its answer is coming.
            return rx.await.unwrap_or(Answer::Unrecorded);
        };
        // Closed at once, so a teardown during the append leaves no stale prompt.
        if let Some(a) = &self.approver {
            a.closed(&e.id);
        }
        let args = json!({"id": e.id, "call": e.call, "reason": "timeout"});
        let entry = self
            .record
            .entry(Actor::Sallyd, "approval.expire", Some("deny"))
            .args(args);
        if self.record.append(entry).await {
            Answer::Deny("timeout")
        } else {
            Answer::Unrecorded
        }
    }

    /// Sends `answer` to the asker of a taken, shown entry and tells the approver it is gone.
    fn close(&self, e: Entry, answer: Answer) {
        let _ = e.tx.send(answer);
        if let Some(a) = &self.approver {
            a.closed(&e.id);
        }
    }

    /// Writes a denial entry with `args`; the refusal to return.
    async fn refuse(&self, event: &str, actor: Actor, args: Value, code: &'static str) -> Refusal {
        self.refused(self.denial(actor, event).args(args), code)
            .await
    }

    /// A denial entry named `event`, to fill.
    fn denial(&self, actor: Actor, event: &str) -> NewEntry {
        self.record.entry(actor, event, Some("deny"))
    }

    /// Writes the denial `entry`; the refusal to return.
    async fn refused(&self, entry: NewEntry, code: &'static str) -> Refusal {
        if self.record.append(entry).await {
            Refusal::Denied(code)
        } else {
            Refusal::Unrecorded
        }
    }
}

/// A queued prompt's wait. Dropping it (teardown aborts the call) takes the prompt out of the
/// queue at once, so a later decide is `unknown-id` and nothing can run.
struct Waiting {
    inner: Arc<Inner>,
    id: String,
}

impl Drop for Waiting {
    fn drop(&mut self) {
        let gone = {
            let mut st = self.inner.state();
            st.pending
                .iter()
                .position(|e| e.id == self.id)
                .map(|i| st.pending.remove(i))
        };
        // Only a prompt the approver was shown is closed to it.
        if let (Some(e), Some(a)) = (gone, &self.inner.approver)
            && e.announced
        {
            a.closed(&e.id);
        }
    }
}

fn withdraw_by(why: Withdraw) -> (Actor, &'static str) {
    match why {
        Withdraw::Cancel => (Actor::Harness, "cancel"),
        Withdraw::Closed => (Actor::Sallyd, "closed"),
        Withdraw::SessionStop => (Actor::Sallyd, "session-stop"),
    }
}

fn sha256(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex(&Sha256::digest(b))
}

/// A fresh 128-bit id, or `None` if the kernel gives no randomness (then the call is denied).
fn new_id() -> Option<String> {
    id_from(|buf| rustix::rand::getrandom(buf, rustix::rand::GetRandomFlags::empty()))
}

/// An id from `fill`: retried while interrupted, refused on a short fill or any other error.
fn id_from(
    mut fill: impl FnMut(&mut [u8; 16]) -> Result<usize, rustix::io::Errno>,
) -> Option<String> {
    let mut buf = [0u8; 16];
    for _ in 0..ID_ATTEMPTS {
        match fill(&mut buf) {
            Ok(n) if n == buf.len() => return Some(format!("ap-{}", hex(&buf))),
            Err(rustix::io::Errno::INTR) => {}
            _ => return None,
        }
    }
    None
}

#[cfg(test)]
#[path = "queue_tests.rs"]
pub(crate) mod tests;
