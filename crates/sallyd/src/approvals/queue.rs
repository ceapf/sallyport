//! The pending queue: the [`Gate`] a tool handler asks, the [`Desk`] a host client answers
//! (SI-5; maintainer's Task 10 decisions 1–7; architect rulings Q19, Q22–Q25).
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
//!   client) before the asker learns the answer, and before a `deny_all_session` latches;
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

use sally_core::audit::Actor;
use sally_core::manifest::Approvals;
use serde_json::{Value, json};
use tokio::sync::oneshot;

use super::action::{Bound, hex};
use super::policy::{Need, Policy};
use super::render::{self, Prompt};
use crate::rpc::agent::Withdraw;
use crate::rpc::rate::Rate;
use crate::rpc::record::{Recorder, escape};

/// One new prompt per this interval, on average (architect ruling Q22; tunable).
pub const REFILL: Duration = Duration::from_secs(2);
/// Characters of action text in an audit entry: escaped ASCII doubles at most in JSON, so the
/// entry stays under the writer's 4 KiB (architect ruling Q24).
pub const AUDIT_ACTION_CHARS: usize = 1024;
/// Attempts at `getrandom(2)` before an id is unavailable (it is interrupted only by signals).
const ID_ATTEMPTS: usize = 3;

/// A human's answer to one prompt (ARCHITECTURE §4.1). v1 has no "allow for this session".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Run this one action, once.
    Approve,
    /// Deny this one action.
    Deny,
    /// Deny this action and every pending one, and deny every later prompt of the session
    /// without asking; actions that need no approval still run. It cannot be undone.
    DenyAllSession,
}

impl Decision {
    /// The wire and audit form.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Deny => "deny",
            Self::DenyAllSession => "deny_all_session",
        }
    }
}

/// The host client that decided, from `SO_PEERCRED` on `control.sock` (never from params).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Client {
    /// Peer uid.
    pub uid: u32,
    /// Peer pid.
    pub pid: i32,
}

/// Where prompts go: the UI or CLI notifier. Answers come back through the [`Desk`]. Called
/// from async code outside the queue's lock: implementations must not block.
pub trait Approver: Send + Sync + 'static {
    /// A prompt is waiting.
    fn requested(&self, prompt: &Prompt);
    /// The session started a flood episode (one call per episode).
    fn flood(&self, session: &str);
    /// The shown prompt `id` is gone (decided, expired, withdrawn or dropped).
    fn closed(&self, id: &str);
}

/// Per-session bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// How long a prompt waits; expiry = deny.
    pub timeout: Duration,
    /// Prompts waiting at once, and the burst of new prompts.
    pub max_pending: usize,
}

impl Limits {
    /// The manifest's `approvals`.
    #[must_use]
    pub fn from_manifest(a: &Approvals) -> Self {
        Self {
            timeout: Duration::from_secs(a.timeout.as_secs()),
            max_pending: usize::try_from(a.max_pending).unwrap_or(usize::MAX),
        }
    }
}

/// Why an action does not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Denied, entry written: reply `denied: <code>`.
    Denied(&'static str),
    /// An entry could not be written: nothing runs and no reply is sent.
    Unrecorded,
}

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

/// Why a decision was not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DecideError {
    /// No pending prompt has this id (never issued, decided, expired or withdrawn).
    #[error("unknown-id")]
    UnknownId,
    /// The decision could not be audited, so it was not taken (an approval becomes a refusal).
    #[error("audit-failed")]
    Unrecorded,
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

/// The answering half (held by control-side code only).
// TODO(#65): Task 12 serves `approvals.list`/`approvals.decide` on control.sock from this.
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
                let args = with(fields(&bound), "code", code);
                Err(self
                    .inner
                    .refuse("tool.deny", Actor::Sallyd, args, code)
                    .await)
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
        let (id, prompt, rx) = match inner.queue(&bound, note, tags) {
            Ok(q) => q,
            Err(NotQueued::Withdrawn(why)) => {
                return Err(inner.withdrawn_before_shown(bound.call, None, why).await);
            }
            Err(NotQueued::Deny(code, episode)) => {
                if episode && !inner.flood_started().await {
                    return Err(Refusal::Unrecorded);
                }
                let args = with(fields(&bound), "reason", code);
                return Err(inner
                    .refuse("approval.deny", Actor::Sallyd, args, code)
                    .await);
            }
        };
        let guard = Waiting {
            inner: Arc::clone(inner),
            id: id.clone(),
        };
        if !inner.pending_entry(&prompt, note).await {
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
    /// name (escaped) and the code, before the denial is returned.
    pub async fn refuse_call(&self, call: u64, tool: &str, code: &'static str) -> Refusal {
        let args = json!({"call": call, "tool": escape(tool.as_bytes()), "code": code});
        self.inner
            .refuse("tool.deny", Actor::Sallyd, args, code)
            .await
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
                Some(i) => st.pending.swap_remove(i),
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

    /// Answers prompt `id` for `client`. The entry is written before the asker learns the
    /// answer, and a `deny_all_session` latches only once its own entry is written; an approval
    /// that cannot be written is not given. Once it has taken the prompt it finishes in its own
    /// task, so dropping this future loses no entry.
    ///
    /// # Errors
    /// `UnknownId` (audited) for an id that is not waiting; `Unrecorded` if an entry failed.
    pub async fn decide(&self, id: &str, d: Decision, client: Client) -> Result<(), DecideError> {
        let inner = Arc::clone(&self.inner);
        let turn = Arc::clone(&inner.deciding).lock_owned().await;
        let Some(first) = inner.take(id) else {
            drop(turn);
            let args = json!({
                "id": escape(id.as_bytes()), "reason": "unknown-id", "client": who(client),
            });
            let entry = inner
                .record
                .entry(Actor::User, "approval.decide", Some("refuse"))
                .args(args);
            return if inner.record.append(entry).await {
                Err(DecideError::UnknownId)
            } else {
                Err(DecideError::Unrecorded)
            };
        };
        let task = tokio::spawn(async move {
            let result = inner.finish(first, d, client).await;
            drop(turn);
            result
        });
        task.await.unwrap_or(Err(DecideError::Unrecorded))
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

    /// Takes the shown prompt `id` out of the queue, so it is decided once.
    fn take(&self, id: &str) -> Option<Entry> {
        let mut st = self.state();
        let i = st.pending.iter().position(|e| e.announced && e.id == id)?;
        Some(st.pending.swap_remove(i))
    }

    /// Writes and delivers a decision on a taken prompt; for `DenyAllSession`, then latches the
    /// session and denies every other shown prompt, each with its own entry.
    async fn finish(&self, first: Entry, d: Decision, client: Client) -> Result<(), DecideError> {
        if !self.decided(&first, d, client, None).await {
            self.close(first, Answer::Unrecorded);
            return Err(DecideError::Unrecorded);
        }
        let answer = match d {
            Decision::Approve => Answer::Approve,
            Decision::Deny | Decision::DenyAllSession => Answer::Deny("denied"),
        };
        let via = first.id.clone();
        self.close(first, answer);
        if d != Decision::DenyAllSession {
            return Ok(());
        }
        let rest: Vec<Entry> = {
            let mut st = self.state();
            st.latched = true;
            let (rest, keep) = st.pending.drain(..).partition(|e| e.announced);
            st.pending = keep;
            rest
        };
        let mut result = Ok(());
        for e in rest {
            let answer = if self.decided(&e, d, client, Some(&via)).await {
                Answer::Deny("session-denied")
            } else {
                result = Err(DecideError::Unrecorded);
                Answer::Unrecorded
            };
            self.close(e, answer);
        }
        result
    }

    /// Writes one `approval.decide` entry; whether it was written.
    async fn decided(&self, e: &Entry, d: Decision, client: Client, via: Option<&str>) -> bool {
        let mut args = fields_of(&e.prompt);
        add(&mut args, "id", Value::from(e.id.as_str()));
        add(&mut args, "client", who(client));
        if let Some(v) = via {
            // Denied together with `v` by its deny_all_session.
            add(&mut args, "via", Value::from(v));
        }
        let entry = self
            .record
            .entry(Actor::User, "approval.decide", Some(d.as_str()))
            .args(args);
        self.record.append(entry).await
    }

    /// Queues a prompt for `bound` or says why not. Check order (architect ruling Q22): an
    /// earlier withdraw, the session latch, no approver, the pending bound, the rate; only a
    /// prompt actually queued takes a rate slot.
    fn queue(
        &self,
        bound: &Bound,
        note: Option<&str>,
        tags: Vec<String>,
    ) -> Result<(String, Arc<Prompt>, oneshot::Receiver<Answer>), NotQueued> {
        let mut st = self.state();
        if st.flooding && st.pending.is_empty() && st.rate.full() {
            st.flooding = false;
        }
        if let Some(&why) = st.withdrawn.get(&bound.call) {
            return Err(NotQueued::Withdrawn(why));
        }
        if st.latched {
            return Err(NotQueued::Deny("session-denied", false));
        }
        if self.approver.is_none() {
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
            prompt: Arc::clone(&prompt),
            announced: false,
            withdrawn: None,
            tx,
        });
        Ok((id, prompt, rx))
    }

    /// Writes `tool.pending` for a queued prompt; whether it was written.
    async fn pending_entry(&self, prompt: &Prompt, note: Option<&str>) -> bool {
        let mut args = fields_of(prompt);
        add(&mut args, "id", Value::from(prompt.id.as_str()));
        if let Some(n) = note {
            add(&mut args, "note_bytes", Value::from(n.len()));
            add(&mut args, "note_sha256", Value::from(sha256(n.as_bytes())));
        }
        let entry = self
            .record
            .entry(Actor::Harness, "tool.pending", Some("pending"))
            .args(args);
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
                st.pending.swap_remove(i);
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
                .map(|i| st.pending.swap_remove(i))
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

    /// Writes a denial entry; the refusal to return.
    async fn refuse(&self, event: &str, actor: Actor, args: Value, code: &'static str) -> Refusal {
        let entry = self.record.entry(actor, event, Some("deny")).args(args);
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
                .map(|i| st.pending.swap_remove(i))
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
    }
}

/// The bounded action fields of an audit entry (architect ruling Q24), from a bound action.
fn fields(b: &Bound) -> Value {
    let text = render::action_text(&b.action);
    action_fields(b.call, &b.action.tool(), &text, &b.digest())
}

/// The same fields from a prompt, which already holds the text and digest.
fn fields_of(p: &Prompt) -> Value {
    action_fields(p.call, &p.tool, &p.full, &p.digest)
}

fn action_fields(call: u64, tool: &str, text: &str, digest: &str) -> Value {
    let (action, _) = render::cut(text, AUDIT_ACTION_CHARS);
    json!({
        "call": call,
        "tool": escape(tool.as_bytes()),
        "action": action,
        "action_sha256": digest,
    })
}

fn add(v: &mut Value, key: &str, value: Value) {
    if let Some(o) = v.as_object_mut() {
        o.insert(key.to_owned(), value);
    }
}

fn with(mut v: Value, key: &str, value: &str) -> Value {
    add(&mut v, key, Value::from(value));
    v
}

fn who(c: Client) -> Value {
    json!({"uid": c.uid, "pid": c.pid})
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
mod tests;
