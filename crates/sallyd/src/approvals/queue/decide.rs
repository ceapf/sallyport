//! Deciding a prompt: [`Desk::decide`](super::Desk::decide) takes the shown prompt once,
//! checks what the client saw on an approve, then writes each `approval.decide` entry before
//! its asker learns the answer (SI-5; architect Q74).

use std::sync::Arc;

use sally_core::audit::Actor;
use serde_json::{Value, json};

use super::{Answer, Client, DecideError, Decision, Desk, Entry, Inner, Seen, add, who};
use crate::rpc::record::escape;

/// Which prompt an `approval.decide` entry is for.
#[derive(Clone, Copy)]
enum How<'a> {
    /// The one the client answered; `full_shown` for an approval of a cut prompt.
    Asked { full_shown: bool },
    /// Another one, denied with the answered prompt `via` by its `deny_all_session`.
    Via(&'a str),
}

impl Desk {
    /// Answers prompt `id` for `client`. The entry is written before the asker learns the
    /// answer; a `deny_all_session` latches before its entry is written and stays latched if
    /// that write fails (the client is told `Unrecorded`, `audit-failed`); an approval
    /// that cannot be written is not given. Once it has taken the prompt it finishes in its own
    /// task, so dropping this future loses no entry.
    ///
    /// An approve must name the digest the client showed and, for a cut prompt, say the full
    /// text was shown (`seen`, architect Q74); refused, it leaves the prompt pending.
    ///
    /// # Errors
    /// `UnknownId`, `DigestMismatch` or `FullTextNotShown` (each audited); `Unrecorded` if an
    /// entry failed.
    pub async fn decide(
        &self,
        id: &str,
        d: Decision,
        client: Client,
        seen: Seen<'_>,
    ) -> Result<(), DecideError> {
        let inner = Arc::clone(&self.inner);
        let turn = Arc::clone(&inner.deciding).lock_owned().await;
        let first = match inner.take_checked(id, d, seen) {
            Ok(e) => e,
            Err(refused) => {
                drop(turn);
                let args = json!({
                    "id": escape(id.as_bytes()), "reason": refused.to_string(),
                    "client": who(client),
                });
                let entry = inner
                    .record
                    .entry(Actor::User, "approval.decide", Some("refuse"))
                    .args(args);
                return if inner.record.append(entry).await {
                    Err(refused)
                } else {
                    Err(DecideError::Unrecorded)
                };
            }
        };
        let full_shown = d == Decision::Approve && first.prompt.truncated;
        let task = tokio::spawn(async move {
            let result = inner.finish(first, d, client, full_shown).await;
            drop(turn);
            result
        });
        task.await.unwrap_or(Err(DecideError::Unrecorded))
    }
}

impl Inner {
    /// Takes the shown prompt `id` out of the queue, so it is decided once; an approve whose
    /// `seen` does not fit the prompt leaves it there (architect Q74).
    fn take_checked(&self, id: &str, d: Decision, seen: Seen<'_>) -> Result<Entry, DecideError> {
        let mut st = self.state();
        let i = st
            .pending
            .iter()
            .position(|e| e.announced && e.id == id)
            .ok_or(DecideError::UnknownId)?;
        if d == Decision::Approve {
            let p = &st.pending.get(i).ok_or(DecideError::UnknownId)?.prompt;
            if p.digest != seen.digest {
                return Err(DecideError::DigestMismatch);
            }
            if p.truncated && (!seen.full_shown || p.full_on_wire().is_none()) {
                return Err(DecideError::FullTextNotShown);
            }
        }
        Ok(st.pending.remove(i))
    }

    /// Writes and delivers a decision on a taken prompt. A `DenyAllSession` latches the session
    /// first (maintainer's Task 11 audit: a failed entry never leaves it open), then writes its
    /// entry and denies every other shown prompt, each with its own entry.
    /// `full_shown`: an approval of a cut prompt, whose full text the client showed; its entry
    /// records that claim.
    async fn finish(
        &self,
        first: Entry,
        d: Decision,
        client: Client,
        full_shown: bool,
    ) -> Result<(), DecideError> {
        let rest: Vec<Entry> = if d == Decision::DenyAllSession {
            let mut st = self.state();
            st.latched = true;
            let (rest, keep) = st.pending.drain(..).partition(|e| e.announced);
            st.pending = keep;
            rest
        } else {
            Vec::new()
        };
        let via = first.id.clone();
        let mut result = Ok(());
        if self
            .decided(&first, d, client, How::Asked { full_shown })
            .await
        {
            let answer = match d {
                Decision::Approve => Answer::Approve,
                Decision::Deny | Decision::DenyAllSession => Answer::Deny("denied"),
            };
            self.close(first, answer);
        } else {
            self.close(first, Answer::Unrecorded);
            result = Err(DecideError::Unrecorded);
        }
        for e in rest {
            let answer = if self.decided(&e, d, client, How::Via(&via)).await {
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
    async fn decided(&self, e: &Entry, d: Decision, client: Client, how: How<'_>) -> bool {
        let mut f = e.fields.clone();
        add(&mut f.args, "id", Value::from(e.id.as_str()));
        add(&mut f.args, "client", who(client));
        match how {
            How::Asked { full_shown: true } => add(&mut f.args, "full_shown", Value::Bool(true)),
            How::Asked { full_shown: false } => {}
            // Denied together with `v` by its deny_all_session.
            How::Via(v) => add(&mut f.args, "via", Value::from(v)),
        }
        let entry = f.on(self
            .record
            .entry(Actor::User, "approval.decide", Some(d.as_str())));
        self.record.append(entry).await
    }
}
