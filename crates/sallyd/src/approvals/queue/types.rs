//! The queue's public vocabulary: a human's [`Decision`], the deciding [`Client`], the
//! [`Approver`] prompts go to, the per-session [`Limits`], and why an action does not run
//! ([`Refusal`]) or a decision is not taken ([`DecideError`], [`Seen`]).

use std::time::Duration;

use sally_core::manifest::Approvals;

use crate::approvals::render::Prompt;

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
///
/// [`Desk`]: super::Desk
pub trait Approver: Send + Sync + 'static {
    /// Whether a client is attached to answer (architect Q73: one that called
    /// `approvals.watch`). Called under the queue's lock: a lock-free read. With none, every
    /// prompt is denied `no-approver`.
    fn attached(&self) -> bool;
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

/// Why a decision was not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DecideError {
    /// No pending prompt has this id (never issued, decided, expired or withdrawn).
    #[error("unknown-id")]
    UnknownId,
    /// The decision could not be audited, so it was not taken (an approval becomes a refusal).
    #[error("audit-failed")]
    Unrecorded,
    /// An approve named another digest than the prompt's: it was not for this action. The
    /// prompt stays pending.
    #[error("digest-mismatch")]
    DigestMismatch,
    /// An approve of a cut prompt whose full text the client did not show, or could not be
    /// sent ([`render::FULL_WIRE_BYTES`](crate::approvals::render::FULL_WIRE_BYTES)). The prompt
    /// stays pending.
    #[error("full-text-not-shown")]
    FullTextNotShown,
}

/// What the deciding client says it showed (architect Q74), checked for an approval only: a
/// deny needs nothing but the id. `full_shown` is a trusted client's claim, a guard against
/// client bugs rather than a boundary.
#[derive(Debug, Clone, Copy)]
pub struct Seen<'a> {
    /// The digest of the prompt the client showed.
    pub digest: &'a str,
    /// The client showed the full action text of a cut prompt.
    pub full_shown: bool,
}
