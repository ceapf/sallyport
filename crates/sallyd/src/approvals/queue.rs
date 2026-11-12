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
//! - **Bounds.** Per session at most `max_pending` prompts wait, and new prompts come at most one
//!   per [`REFILL`] with a burst of `max_pending`; over either bound a call is denied
//!   `approval-flood`, each with its own entry, and each flood episode is announced once
//!   (`approval.flood`). `agent.sock` runs at most 16 calls at once, so a `max_pending` above 16
//!   is never reached.
//! - **Audit.** `tool.pending` before the prompt is shown; `approval.decide` (with the deciding
//!   client) before the asker learns the answer; `approval.expire`, `approval.withdraw`,
//!   `approval.deny`, `approval.flood`, `tool.deny` before the denial is returned. A failed
//!   append is [`Refusal::Unrecorded`]: nothing runs and no reply is sent. A wait dropped by
//!   teardown is invalidated at once without an entry; the session's stop entry covers it.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use sally_core::audit::Actor;
use sally_core::manifest::Approvals;
use serde_json::{Value, json};
use tokio::sync::oneshot;

use super::action::{Action, Bound, hex};
use super::policy::{Need, Policy};
use super::render::{self, Prompt};
use crate::rpc::rate::Rate;
use crate::rpc::record::{Recorder, escape};

/// One new prompt per this interval, on average (architect ruling Q22; tunable).
pub const REFILL: Duration = Duration::from_secs(2);
/// Characters of action text in an audit entry: escaped ASCII doubles at most in JSON, so the
/// entry stays under the writer's 4 KiB (architect ruling Q24).
pub const AUDIT_ACTION_CHARS: usize = 1024;

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

/// Where prompts go: the UI or CLI notifier. Answers come back through the [`Desk`].
pub trait Approver: Send + Sync + 'static {
    /// A prompt is waiting.
    fn requested(&self, prompt: &Prompt);
    /// The session started a flood episode (one call per episode).
    fn flood(&self, session: &str);
    /// The prompt `id` is gone (decided, expired, withdrawn or dropped).
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
    pub fn action(&self) -> &Action {
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

/// Why a call's prompt is withdrawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Withdraw {
    /// `notifications/cancelled` named the call.
    Cancel,
    /// The connection that sent the call closed.
    Closed,
}

enum Answer {
    Approve,
    Deny(&'static str),
    Withdrawn,
    Unrecorded,
}

struct Entry {
    id: String,
    bound: Bound,
    prompt: Prompt,
    /// `tool.pending` is written and the approver told: only then can it be decided.
    announced: bool,
    /// A withdraw arrived before it was announced.
    cancel: bool,
    tx: Option<oneshot::Sender<Answer>>,
}

struct State {
    pending: Vec<Entry>,
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
            latched: false,
            flooding: false,
            rate: Rate::every(REFILL, burst),
        }),
    });
    (
        Gate {
            inner: Arc::clone(&inner),
        },
        Desk { inner },
    )
}

impl Gate {
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
        let id = match inner.queue(&bound, note, tags) {
            Ok(id) => id,
            Err((code, episode)) => {
                if episode && !inner.flood_started().await {
                    return Err(Refusal::Unrecorded);
                }
                let args = with(fields(&bound), "reason", code);
                return Err(inner
                    .refuse("approval.deny", Actor::Sallyd, args, code)
                    .await);
            }
        };
        let (guard, rx) = Waiting::arm(Arc::clone(inner), id.clone());
        let mut args = fields(&bound);
        add(&mut args, "id", Value::from(id.as_str()));
        if let Some(n) = note {
            add(&mut args, "note_bytes", Value::from(n.len()));
            add(&mut args, "note_sha256", Value::from(sha256(n.as_bytes())));
        }
        let entry = inner
            .record
            .entry(Actor::Harness, "tool.pending", Some("pending"))
            .args(args);
        if !inner.record.append(entry).await {
            return Err(Refusal::Unrecorded);
        }
        if let Err(code) = inner.announce(&id) {
            let event = if code == "withdrawn" {
                "approval.withdraw"
            } else {
                "approval.deny"
            };
            let args = json!({"id": id, "call": bound.call, "reason": code});
            return Err(inner.refuse(event, Actor::Sallyd, args, code).await);
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

    /// Withdraws the prompt of `call`, if one waits (#54): its asker gets `withdrawn`.
    pub async fn withdraw(&self, call: u64, why: Withdraw) {
        let inner = &self.inner;
        let taken = {
            let mut st = lock(&inner.state);
            let Some(i) = st.pending.iter().position(|e| e.bound.call == call) else {
                return;
            };
            let announced = st.pending.get(i).is_some_and(|e| e.announced);
            if !announced {
                if let Some(e) = st.pending.get_mut(i) {
                    e.cancel = true;
                }
                return;
            }
            st.pending.swap_remove(i)
        };
        let (actor, reason) = match why {
            Withdraw::Cancel => (Actor::Harness, "cancel"),
            Withdraw::Closed => (Actor::Sallyd, "closed"),
        };
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
    }
}

impl Desk {
    /// The prompts waiting for an answer.
    #[must_use]
    pub fn list(&self) -> Vec<Prompt> {
        lock(&self.inner.state)
            .pending
            .iter()
            .filter(|e| e.announced)
            .map(|e| e.prompt.clone())
            .collect()
    }

    /// Answers prompt `id` for `client`. The entry is written before the asker learns the
    /// answer; an approval that cannot be written is not given.
    ///
    /// # Errors
    /// `UnknownId` (audited) for an id that is not waiting; `Unrecorded` if an entry failed.
    pub async fn decide(&self, id: &str, d: Decision, client: Client) -> Result<(), DecideError> {
        let inner = &self.inner;
        let Some(taken) = inner.take(id, d) else {
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
        let mut result = Ok(());
        for (n, e) in taken.into_iter().enumerate() {
            let mut args = fields(&e.bound);
            add(&mut args, "id", Value::from(e.id.as_str()));
            add(&mut args, "client", who(client));
            if n > 0 {
                // Denied together with `id` by its deny_all_session.
                add(&mut args, "via", Value::from(id));
            }
            let entry = inner
                .record
                .entry(Actor::User, "approval.decide", Some(d.as_str()))
                .args(args);
            let answer = match (inner.record.append(entry).await, d, n) {
                (false, _, _) => {
                    result = Err(DecideError::Unrecorded);
                    Answer::Unrecorded
                }
                (true, Decision::Approve, _) => Answer::Approve,
                (true, Decision::Deny, _) | (true, Decision::DenyAllSession, 0) => {
                    Answer::Deny("denied")
                }
                (true, Decision::DenyAllSession, _) => Answer::Deny("session-denied"),
            };
            inner.close(e, answer);
        }
        result
    }
}

impl Inner {
    /// Takes the shown prompt `id` out of the queue (so it is decided once), and for
    /// `DenyAllSession` latches the session and takes every other shown prompt after it.
    fn take(&self, id: &str, d: Decision) -> Option<Vec<Entry>> {
        let mut st = lock(&self.state);
        let i = st.pending.iter().position(|e| e.announced && e.id == id)?;
        let mut taken = vec![st.pending.swap_remove(i)];
        if d == Decision::DenyAllSession {
            st.latched = true;
            let (rest, keep): (Vec<Entry>, Vec<Entry>) =
                st.pending.drain(..).partition(|e| e.announced);
            st.pending = keep;
            taken.extend(rest);
        }
        Some(taken)
    }

    /// Queues a prompt for `bound` or says why not: the code, and whether a flood episode
    /// starts with it. Check order (architect ruling Q22): the session latch, no approver, the
    /// pending bound, the rate; only a prompt actually queued takes a rate slot.
    fn queue(
        &self,
        bound: &Bound,
        note: Option<&str>,
        tags: Vec<String>,
    ) -> Result<String, (&'static str, bool)> {
        let mut st = lock(&self.state);
        if st.flooding && st.pending.is_empty() && st.rate.full() {
            st.flooding = false;
        }
        if st.latched {
            return Err(("session-denied", false));
        }
        if self.approver.is_none() {
            return Err(("no-approver", false));
        }
        if st.pending.len() >= self.limits.max_pending || st.rate.take().is_err() {
            let episode = !st.flooding;
            st.flooding = true;
            return Err(("approval-flood", episode));
        }
        let Some(id) = new_id() else {
            return Err(("id-unavailable", false));
        };
        let prompt = Prompt::new(id.clone(), bound, note, tags);
        st.pending.push(Entry {
            id: id.clone(),
            bound: bound.clone(),
            prompt,
            announced: false,
            cancel: false,
            tx: None,
        });
        Ok(id)
    }

    /// Writes the episode's `approval.flood` and tells the approver; whether it was written.
    async fn flood_started(&self) -> bool {
        let entry = self
            .record
            .entry(Actor::Sallyd, "approval.flood", Some("deny"))
            .args(json!({"max_pending": self.limits.max_pending}));
        if !self.record.append(entry).await {
            return false;
        }
        if let Some(a) = &self.approver {
            a.flood(&self.session);
        }
        true
    }

    /// Makes `id` decidable and shows it, unless it was withdrawn or the session latched while
    /// its entry was written (then it leaves the queue with that code).
    fn announce(&self, id: &str) -> Result<(), &'static str> {
        let prompt = {
            let mut st = lock(&self.state);
            let latched = st.latched;
            let Some(i) = st.pending.iter().position(|e| e.id == id) else {
                return Err("withdrawn");
            };
            let code = match st.pending.get(i) {
                Some(e) if e.cancel => Some("withdrawn"),
                Some(_) if latched => Some("session-denied"),
                _ => None,
            };
            if let Some(code) = code {
                st.pending.swap_remove(i);
                return Err(code);
            }
            let Some(e) = st.pending.get_mut(i) else {
                return Err("withdrawn");
            };
            e.announced = true;
            e.prompt.clone()
        };
        if let Some(a) = &self.approver {
            a.requested(&prompt);
        }
        Ok(())
    }

    /// Waits for the answer to `id` until the timeout; on expiry the prompt leaves the queue.
    async fn wait(&self, id: &str, rx: oneshot::Receiver<Answer>) -> Answer {
        let mut rx = rx;
        if let Ok(r) = tokio::time::timeout(self.limits.timeout, &mut rx).await {
            return r.unwrap_or(Answer::Unrecorded);
        }
        let expired = {
            let mut st = lock(&self.state);
            st.pending
                .iter()
                .position(|e| e.id == id)
                .map(|i| st.pending.swap_remove(i))
        };
        let Some(e) = expired else {
            // A decision took it first and is being written: its answer is coming.
            return rx.await.unwrap_or(Answer::Unrecorded);
        };
        let args = json!({"id": e.id, "call": e.bound.call, "reason": "timeout"});
        let entry = self
            .record
            .entry(Actor::Sallyd, "approval.expire", Some("deny"))
            .args(args);
        let answer = if self.record.append(entry).await {
            Answer::Deny("timeout")
        } else {
            Answer::Unrecorded
        };
        if let Some(a) = &self.approver {
            a.closed(&e.id);
        }
        answer
    }

    /// Sends `answer` to the asker of a taken entry and tells the approver it is gone.
    fn close(&self, e: Entry, answer: Answer) {
        if let Some(tx) = e.tx {
            let _ = tx.send(answer);
        }
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

impl Waiting {
    fn arm(inner: Arc<Inner>, id: String) -> (Self, oneshot::Receiver<Answer>) {
        let (tx, rx) = oneshot::channel();
        if let Some(e) = lock(&inner.state).pending.iter_mut().find(|e| e.id == id) {
            e.tx = Some(tx);
        }
        (Self { inner, id }, rx)
    }
}

impl Drop for Waiting {
    fn drop(&mut self) {
        let gone = {
            let mut st = lock(&self.inner.state);
            st.pending
                .iter()
                .position(|e| e.id == self.id)
                .map(|i| st.pending.swap_remove(i))
        };
        if let (Some(e), Some(a)) = (gone, &self.inner.approver) {
            a.closed(&e.id);
        }
    }
}

/// The bounded fields of an action for an audit entry (architect ruling Q24).
fn fields(b: &Bound) -> Value {
    let text = render::action_text(&b.action);
    let (action, _) = render::cut(&text, AUDIT_ACTION_CHARS);
    json!({
        "call": b.call,
        "tool": escape(b.action.tool().as_bytes()),
        "action": action,
        "action_sha256": b.digest(),
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
    let mut buf = [0u8; 16];
    match rustix::rand::getrandom(&mut buf, rustix::rand::GetRandomFlags::empty()) {
        Ok(n) if n == buf.len() => Some(format!("ap-{}", hex(&buf))),
        _ => None,
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
#[path = "queue_tests.rs"]
mod tests;
