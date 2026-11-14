#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::sync::Mutex as StdMutex;
use std::sync::atomic::Ordering::SeqCst;

use sally_core::manifest::{ApproveGlobs, BuiltinTool, FetchWrites, MountMode, ShellPolicy};

use super::super::action::{Action, Payload, Target};
use super::super::policy::MountRule;
use super::*;
use crate::rpc::testkit::{Sink, recorder};

/// Records what an approver is told.
#[derive(Default)]
pub(crate) struct Fake {
    /// No client watches (architect Q73): `attached` answers false.
    pub detached: std::sync::atomic::AtomicBool,
    pub requested: StdMutex<Vec<Prompt>>,
    pub floods: StdMutex<Vec<String>>,
    pub closed: StdMutex<Vec<String>>,
}

/// Decides `id` as a client shown the prompt in full would: with the prompt's own digest and
/// `full_shown` (an id that is not waiting gets an empty digest, and so its own refusal).
pub(crate) async fn decide(
    desk: &Desk,
    id: &str,
    d: Decision,
    client: Client,
) -> Result<(), DecideError> {
    let digest = desk
        .list()
        .iter()
        .find(|p| p.id == id)
        .map(|p| p.digest.clone())
        .unwrap_or_default();
    let seen = Seen {
        digest: &digest,
        full_shown: true,
    };
    desk.decide(id, d, client, seen).await
}

impl Approver for Fake {
    fn attached(&self) -> bool {
        !self.detached.load(SeqCst)
    }
    fn requested(&self, p: &Prompt) {
        self.requested.lock().unwrap().push(p.clone());
    }
    fn flood(&self, s: &str) {
        self.floods.lock().unwrap().push(s.to_owned());
    }
    fn closed(&self, id: &str) {
        self.closed.lock().unwrap().push(id.to_owned());
    }
}

const ME: Client = Client { uid: 1000, pid: 42 };

fn policy() -> Policy {
    Policy {
        builtin: vec![BuiltinTool::Shell, BuiltinTool::FsWrite, BuiltinTool::Fetch],
        shell: ShellPolicy::Approve,
        destructive_requires_approval: true,
        fetch_writes: FetchWrites::Approve,
        mounts: vec![MountRule {
            guest: "/workspace/ro".to_owned(),
            mode: MountMode::Ro,
            approve: ApproveGlobs::not_applicable(),
        }],
        mcp: vec![],
    }
}

struct Fx {
    gate: Gate,
    desk: Desk,
    sink: Arc<Sink>,
    fake: Arc<Fake>,
    /// The session's audit handle, which the session's stop seals.
    rec: crate::rpc::record::Recorder,
}

fn fx(max_pending: usize) -> Fx {
    fx_with(max_pending, true)
}

fn fx_with(max_pending: usize, approver: bool) -> Fx {
    let (sink, rec) = recorder("s-1");
    let fake = Arc::new(Fake::default());
    let limits = Limits {
        timeout: Duration::from_secs(300),
        max_pending,
    };
    let a = approver.then(|| Arc::clone(&fake) as Arc<dyn Approver>);
    let (gate, desk) = new("s-1".to_owned(), policy(), limits, rec.clone(), a);
    Fx {
        gate,
        desk,
        sink,
        fake,
        rec,
    }
}

/// Writes the session's last entry, as the session's stop does.
async fn seal(f: &Fx, bound: Duration) -> crate::rpc::record::Sealed {
    let last = f.rec.entry(Actor::Sallyd, "session.stop", None);
    f.rec.seal(last, bound).await
}

fn shell(call: u64, argv: &[&str]) -> Bound {
    Bound {
        session: "s-1".to_owned(),
        call,
        action: Action::Shell {
            argv: argv.iter().map(|s| (*s).to_owned()).collect(),
            cwd: "/workspace/p".to_owned(),
        },
    }
}

fn get(call: u64) -> Bound {
    Bound {
        session: "s-1".to_owned(),
        call,
        action: Action::Fetch {
            method: "GET".to_owned(),
            url: "https://h/".to_owned(),
            headers: vec![],
            body: Payload::new(vec![]),
        },
    }
}

/// Polls until `cond` holds (paused time moves 1 ms per poll).
async fn until(what: &str, mut cond: impl FnMut() -> bool) {
    for _ in 0..2000 {
        if cond() {
            return;
        }
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    panic!("never: {what}");
}

/// Starts an ask in its own task and waits until its prompt is shown.
async fn asking(f: &Fx, b: Bound) -> (String, tokio::task::JoinHandle<Result<Ticket, Refusal>>) {
    let before = f.fake.requested.lock().unwrap().len();
    let gate = f.gate.clone();
    let h = tokio::spawn(async move { gate.admit(b, None, None).await });
    until("prompt shown", || {
        f.fake.requested.lock().unwrap().len() > before
    })
    .await;
    let id = f.fake.requested.lock().unwrap()[before].id.clone();
    (id, h)
}

fn count(sink: &Sink, event: &str) -> usize {
    sink.events().iter().filter(|e| *e == event).count()
}

#[tokio::test]
async fn an_action_that_needs_no_approval_gets_a_ticket_without_a_prompt() {
    let f = fx(5);
    assert_eq!(f.gate.session(), "s-1");
    let t = f.gate.admit(get(1), None, None).await.unwrap();
    assert_eq!(t.bound(), &get(1));
    assert_eq!(t.action(), &get(1).action);
    assert_eq!(t.approval(), None);
    assert!(f.fake.requested.lock().unwrap().is_empty());
    assert!(f.sink.rows().is_empty());
}

#[tokio::test]
async fn a_policy_denial_is_audited_before_it_is_returned() {
    let f = fx(5);
    let b = Bound {
        session: "s-1".to_owned(),
        call: 2,
        action: Action::FsWrite {
            target: Target {
                mount: "/workspace/ro".to_owned(),
                rel: "a".to_owned(),
                host: "/h/a".to_owned(),
            },
            content: Payload::new(b"x".to_vec()),
        },
    };
    let r = f.gate.admit(b.clone(), None, None).await;
    assert_eq!(r, Err(Refusal::Denied("read-only")));
    let args = f.sink.last("tool.deny");
    assert_eq!(args["code"], "read-only");
    assert_eq!(args["call"], 2);
    assert_eq!(args["tool"], "fs_write");
    assert_eq!(args["action_sha256"], b.digest());
    f.sink.set_failing(true);
    assert_eq!(f.gate.admit(b, None, None).await, Err(Refusal::Unrecorded));
}

#[tokio::test]
async fn with_no_approver_every_prompt_is_denied_and_audited() {
    let f = fx_with(5, false);
    let r = f.gate.admit(shell(1, &["ls"]), None, None).await;
    assert_eq!(r, Err(Refusal::Denied("no-approver")));
    assert_eq!(f.sink.last("approval.deny")["reason"], "no-approver");
    assert!(f.desk.list().is_empty());
}

/// An approver with no client attached is no approver (architect Q73): the prompt is denied
/// `no-approver`, audited, at the same place in the check order; attached again, it asks.
#[tokio::test]
async fn an_approver_with_no_client_attached_denies_no_approver() {
    let f = fx(5);
    f.fake.detached.store(true, SeqCst);
    let r = f.gate.admit(shell(1, &["ls"]), None, None).await;
    assert_eq!(r, Err(Refusal::Denied("no-approver")));
    assert_eq!(f.sink.last("approval.deny")["reason"], "no-approver");
    assert!(f.fake.requested.lock().unwrap().is_empty());
    f.fake.detached.store(false, SeqCst);
    let (id, h) = asking(&f, shell(2, &["ls"])).await;
    decide(&f.desk, &id, Decision::Deny, ME).await.unwrap();
    assert!(h.await.unwrap().is_err());
}

fn seen(digest: &str, full_shown: bool) -> Seen<'_> {
    Seen { digest, full_shown }
}

/// An approval binds the digest the client was shown (architect Q74): a mismatch is refused and
/// audited, the prompt stays pending, and a later approve with the right digest runs it. A deny
/// needs only the id.
#[tokio::test]
async fn an_approve_with_another_digest_is_refused_and_leaves_the_prompt() {
    let f = fx(5);
    let b = shell(1, &["touch", "/workspace/x"]);
    let (id, h) = asking(&f, b.clone()).await;
    let wrong = f
        .desk
        .decide(
            &id,
            Decision::Approve,
            ME,
            seen("0".repeat(64).as_str(), true),
        )
        .await;
    assert_eq!(wrong, Err(DecideError::DigestMismatch));
    let last = f.sink.rows().pop().unwrap();
    assert_eq!(
        (last.event.as_str(), last.decision.as_deref()),
        ("approval.decide", Some("refuse"))
    );
    assert_eq!(last.args["reason"], "digest-mismatch");
    assert_eq!(last.args["id"], id.as_str());
    assert_eq!(last.args["client"], json!({"uid": 1000, "pid": 42}));
    assert_eq!(f.desk.list().len(), 1, "still pending");
    let digest = b.digest();
    f.desk
        .decide(&id, Decision::Approve, ME, seen(&digest, false))
        .await
        .unwrap();
    assert_eq!(h.await.unwrap().unwrap().bound(), &b);
    // A deny with a wrong digest still denies.
    let (id, h) = asking(&f, shell(2, &["ls"])).await;
    f.desk
        .decide(&id, Decision::Deny, ME, seen("x", false))
        .await
        .unwrap();
    assert_eq!(h.await.unwrap(), Err(Refusal::Denied("denied")));
}

/// A cut prompt is approved only after its full text was shown (architect Q74, RT-UI-03 for the
/// CLI): without `full_shown` the approve is refused and the prompt stays; with it, the entry
/// records `full_shown`. A deny never needs it.
#[tokio::test]
async fn a_cut_prompt_is_approved_only_after_its_full_text_was_shown() {
    let f = fx(5);
    let long = "y".repeat(render::ACTION_CHARS);
    let b = shell(1, &["echo", &long]);
    let (id, h) = asking(&f, b.clone()).await;
    assert!(f.desk.list()[0].truncated);
    let digest = b.digest();
    let r = f
        .desk
        .decide(&id, Decision::Approve, ME, seen(&digest, false))
        .await;
    assert_eq!(r, Err(DecideError::FullTextNotShown));
    assert_eq!(
        f.sink.last("approval.decide")["reason"],
        "full-text-not-shown"
    );
    assert_eq!(f.desk.list().len(), 1, "still pending");
    f.desk
        .decide(&id, Decision::Approve, ME, seen(&digest, true))
        .await
        .unwrap();
    assert!(h.await.unwrap().is_ok());
    assert_eq!(f.sink.last("approval.decide")["full_shown"], true);
    // An approve of a whole prompt records no claim.
    let (id, h) = asking(&f, shell(2, &["ls"])).await;
    decide(&f.desk, &id, Decision::Approve, ME).await.unwrap();
    assert!(h.await.unwrap().is_ok());
    assert!(f.sink.last("approval.decide").get("full_shown").is_none());
    // A cut prompt is denied without the claim.
    let (id, h) = asking(&f, shell(3, &["echo", &long])).await;
    f.desk
        .decide(&id, Decision::Deny, ME, seen("", false))
        .await
        .unwrap();
    assert!(h.await.unwrap().is_err());
}

/// A full text over the wire cap is never sent, so the prompt cannot be approved at all; it can
/// only be denied (architect Q74 (b)).
#[tokio::test]
async fn a_prompt_whose_full_text_is_over_the_wire_cap_is_deny_only() {
    let f = fx(5);
    let huge = "y".repeat(render::FULL_WIRE_BYTES);
    let b = shell(1, &["echo", &huge]);
    let (id, h) = asking(&f, b.clone()).await;
    assert!(f.desk.list()[0].full_on_wire().is_none());
    let digest = b.digest();
    let r = f
        .desk
        .decide(&id, Decision::Approve, ME, seen(&digest, true))
        .await;
    assert_eq!(r, Err(DecideError::FullTextNotShown));
    assert_eq!(f.desk.list().len(), 1);
    decide(&f.desk, &id, Decision::Deny, ME).await.unwrap();
    assert!(h.await.unwrap().is_err());
}

#[tokio::test]
async fn approve_once_runs_the_askers_own_copy_and_the_id_is_single_use() {
    let f = fx(5);
    let b = shell(1, &["touch", "/workspace/x"]);
    let (id, h) = asking(&f, b.clone()).await;
    // The entry precedes the prompt; the prompt binds the digest.
    let pending = f.sink.last("tool.pending");
    assert_eq!(pending["id"], id.as_str());
    assert_eq!(pending["action_sha256"], b.digest());
    let listed = f.desk.list();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].digest, b.digest());
    decide(&f.desk, &id, Decision::Approve, ME).await.unwrap();
    let t = h.await.unwrap().unwrap();
    assert_eq!(t.bound(), &b);
    assert_eq!(t.approval(), Some(id.as_str()));
    let d = f.sink.last("approval.decide");
    assert_eq!(d["id"], id.as_str());
    assert_eq!(d["client"], json!({"uid": 1000, "pid": 42}));
    assert_eq!(d["action_sha256"], b.digest());
    // Replay: the id is gone, and the refusal is audited.
    let again = decide(&f.desk, &id, Decision::Approve, ME).await;
    assert_eq!(again, Err(DecideError::UnknownId));
    let last = f.sink.rows().pop().unwrap();
    assert_eq!(
        (last.event.as_str(), last.decision.as_deref()),
        ("approval.decide", Some("refuse"))
    );
    assert_eq!(last.args["reason"], "unknown-id");
    assert!(f.desk.list().is_empty());
    assert_eq!(f.fake.closed.lock().unwrap().as_slice(), [id]);
}

#[tokio::test]
async fn two_decisions_at_once_on_one_id_take_it_once() {
    let f = fx(5);
    let (id, h) = asking(&f, shell(1, &["ls"])).await;
    let (a, b) = tokio::join!(
        decide(&f.desk, &id, Decision::Approve, ME),
        decide(&f.desk, &id, Decision::Approve, ME)
    );
    let oks = [a, b].iter().filter(|r| r.is_ok()).count();
    assert_eq!(oks, 1);
    assert!([a, b].contains(&Err(DecideError::UnknownId)));
    assert!(h.await.unwrap().is_ok());
    let approvals = f
        .sink
        .rows()
        .into_iter()
        .filter(|r| r.decision.as_deref() == Some("approve"))
        .count();
    assert_eq!(approvals, 1);
}

#[tokio::test]
async fn an_identical_later_call_asks_again_under_a_new_id() {
    let f = fx(5);
    let (first, h) = asking(&f, shell(1, &["ls"])).await;
    decide(&f.desk, &first, Decision::Approve, ME)
        .await
        .unwrap();
    h.await.unwrap().unwrap();
    let (second, h) = asking(&f, shell(2, &["ls"])).await;
    assert_ne!(first, second);
    decide(&f.desk, &second, Decision::Deny, ME).await.unwrap();
    assert_eq!(h.await.unwrap(), Err(Refusal::Denied("denied")));
    assert_eq!(f.sink.last("approval.decide")["id"], second.as_str());
}

#[tokio::test]
async fn ids_are_128_bit_hex_and_unique() {
    let ids: std::collections::HashSet<String> = (0..64).map(|_| new_id().unwrap()).collect();
    assert_eq!(ids.len(), 64);
    for id in ids {
        let hex = id.strip_prefix("ap-").unwrap();
        assert_eq!(hex.len(), 32);
        assert!(hex.bytes().all(|b| b.is_ascii_hexdigit()));
    }
}

#[test]
fn an_id_is_retried_while_interrupted_and_refused_on_a_short_or_failed_fill() {
    use rustix::io::Errno;
    let mut tries = 0;
    let id = id_from(|b| {
        tries += 1;
        if tries < ID_ATTEMPTS {
            return Err(Errno::INTR);
        }
        b.fill(0xab);
        Ok(b.len())
    });
    assert_eq!(id, Some(format!("ap-{}", "ab".repeat(16))));
    assert_eq!(id_from(|_| Err(Errno::INTR)), None);
    assert_eq!(id_from(|_| Ok(15)), None);
    assert_eq!(id_from(|_| Err(Errno::NOSYS)), None);
}

#[tokio::test(start_paused = true)]
async fn a_prompt_nobody_answers_expires_as_a_denial() {
    let f = fx(5);
    let (id, h) = asking(&f, shell(1, &["ls"])).await;
    tokio::time::advance(Duration::from_secs(290)).await;
    assert_eq!(f.desk.list().len(), 1);
    tokio::time::advance(Duration::from_secs(10)).await;
    assert_eq!(h.await.unwrap(), Err(Refusal::Denied("timeout")));
    let e = f.sink.last("approval.expire");
    assert_eq!(e["id"], id.as_str());
    assert_eq!(e["reason"], "timeout");
    assert_eq!(
        decide(&f.desk, &id, Decision::Approve, ME).await,
        Err(DecideError::UnknownId)
    );
    assert!(f.fake.closed.lock().unwrap().contains(&id));
}

#[tokio::test(start_paused = true)]
async fn an_expiry_that_cannot_be_written_is_unrecorded() {
    let f = fx(5);
    let (_, h) = asking(&f, shell(1, &["ls"])).await;
    f.sink.set_failing(true);
    tokio::time::advance(Duration::from_secs(300)).await;
    assert_eq!(h.await.unwrap(), Err(Refusal::Unrecorded));
}

#[tokio::test]
async fn a_failed_pending_entry_shows_nothing_and_runs_nothing() {
    let f = fx(5);
    f.sink.set_failing(true);
    // Bounded: if the failed entry were taken as written, the prompt would wait for a decision.
    let r = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        f.gate.admit(shell(1, &["ls"]), None, None),
    )
    .await
    .expect("the admission waited: the failed pending entry was taken as written");
    assert_eq!(r, Err(Refusal::Unrecorded));
    assert!(f.fake.requested.lock().unwrap().is_empty());
    // The approver was never shown it, so it is not told it closed.
    assert!(f.fake.closed.lock().unwrap().is_empty());
    assert!(f.desk.list().is_empty());
}

#[tokio::test]
async fn an_approval_that_cannot_be_written_is_not_given() {
    let f = fx(5);
    let (id, h) = asking(&f, shell(1, &["ls"])).await;
    f.sink.set_failing(true);
    let r = decide(&f.desk, &id, Decision::Approve, ME).await;
    assert_eq!(r, Err(DecideError::Unrecorded));
    assert_eq!(h.await.unwrap(), Err(Refusal::Unrecorded));
    // And an unknown id whose refusal cannot be written says so.
    assert_eq!(
        decide(&f.desk, "ap-x", Decision::Deny, ME).await,
        Err(DecideError::Unrecorded)
    );
}

#[tokio::test]
async fn a_decision_whose_caller_is_dropped_still_completes() {
    let f = fx(5);
    let (id, h) = asking(&f, shell(1, &["ls"])).await;
    // The decision's entry cannot be written yet, so the caller is still waiting when dropped.
    f.sink.hold(true);
    let desk = f.desk.clone();
    let d = id.clone();
    let caller = tokio::spawn(async move { decide(&desk, &d, Decision::Deny, ME).await });
    until("prompt taken", || f.desk.list().is_empty()).await;
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    f.sink.hold(false);
    assert_eq!(h.await.unwrap(), Err(Refusal::Denied("denied")));
    assert_eq!(f.sink.last("approval.decide")["id"], id.as_str());
    assert!(f.fake.closed.lock().unwrap().contains(&id));
}

#[tokio::test]
async fn deny_all_session_denies_every_pending_prompt_and_every_later_one() {
    let f = fx(5);
    let (a, ha) = asking(&f, shell(1, &["a"])).await;
    let (b, hb) = asking(&f, shell(2, &["b"])).await;
    decide(&f.desk, &a, Decision::DenyAllSession, ME)
        .await
        .unwrap();
    assert_eq!(ha.await.unwrap(), Err(Refusal::Denied("denied")));
    assert_eq!(hb.await.unwrap(), Err(Refusal::Denied("session-denied")));
    let rows: Vec<_> = f
        .sink
        .rows()
        .into_iter()
        .filter(|r| r.event == "approval.decide")
        .collect();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].args["id"], a.as_str());
    assert!(rows[0].args.get("via").is_none());
    assert_eq!(rows[1].args["id"], b.as_str());
    assert_eq!(rows[1].args["via"], a.as_str());
    assert!(
        rows.iter()
            .all(|r| r.decision.as_deref() == Some("deny_all_session"))
    );
    // Latched: no prompt, denied and audited; an action needing no approval still runs.
    let shown = f.fake.requested.lock().unwrap().len();
    let r = f.gate.admit(shell(3, &["c"]), None, None).await;
    assert_eq!(r, Err(Refusal::Denied("session-denied")));
    assert_eq!(f.fake.requested.lock().unwrap().len(), shown);
    assert_eq!(f.sink.last("approval.deny")["reason"], "session-denied");
    assert!(f.gate.admit(get(4), None, None).await.is_ok());
}

// Maintainer's Task 11 audit: the latch comes first, so a failed entry never leaves the session
// open; the client is told `audit-failed` (`Unrecorded`).
#[tokio::test]
async fn deny_all_session_latches_first_and_stays_latched_when_its_entry_fails() {
    let f = fx(5);
    let (a, ha) = asking(&f, shell(1, &["a"])).await;
    let (b, hb) = asking(&f, shell(2, &["b"])).await;
    f.sink.fail_next.store(1, SeqCst);
    let r = decide(&f.desk, &a, Decision::DenyAllSession, ME).await;
    assert_eq!(r, Err(DecideError::Unrecorded));
    assert_eq!(ha.await.unwrap(), Err(Refusal::Unrecorded));
    // Latched all the same: the other prompt is denied with its own entry, and nothing new is
    // shown.
    assert_eq!(hb.await.unwrap(), Err(Refusal::Denied("session-denied")));
    assert_eq!(f.sink.last("approval.decide")["id"], b.as_str());
    assert_eq!(f.sink.last("approval.decide")["via"], a.as_str());
    assert!(f.desk.list().is_empty());
    let shown = f.fake.requested.lock().unwrap().len();
    let r = f.gate.admit(shell(3, &["c"]), None, None).await;
    assert_eq!(r, Err(Refusal::Denied("session-denied")));
    assert_eq!(f.fake.requested.lock().unwrap().len(), shown);
}

#[tokio::test]
async fn deny_all_session_reports_an_entry_it_could_not_write_for_another_prompt() {
    let f = fx(5);
    let (a, ha) = asking(&f, shell(1, &["a"])).await;
    let (_, hb) = asking(&f, shell(2, &["b"])).await;
    // The decision entry for `a` is written; the one for `b` is not.
    f.sink.fail_from.store(f.sink.rows().len() + 1, SeqCst);
    let r = decide(&f.desk, &a, Decision::DenyAllSession, ME).await;
    assert_eq!(r, Err(DecideError::Unrecorded));
    assert_eq!(ha.await.unwrap(), Err(Refusal::Denied("denied")));
    assert_eq!(hb.await.unwrap(), Err(Refusal::Unrecorded));
    // The session is latched all the same: `a`'s decision was recorded.
    f.sink.fail_from.store(0, SeqCst);
    let r = f.gate.admit(shell(3, &["c"]), None, None).await;
    assert_eq!(r, Err(Refusal::Denied("session-denied")));
}

#[tokio::test]
async fn deny_all_session_on_a_stale_id_sets_nothing() {
    let f = fx(5);
    let r = decide(&f.desk, "ap-0", Decision::DenyAllSession, ME).await;
    assert_eq!(r, Err(DecideError::UnknownId));
    let (id, h) = asking(&f, shell(1, &["ls"])).await;
    decide(&f.desk, &id, Decision::Approve, ME).await.unwrap();
    assert!(h.await.unwrap().is_ok());
}

#[tokio::test]
async fn a_withdrawn_call_leaves_the_queue_audited_and_cannot_be_approved() {
    let f = fx(5);
    let (id, h) = asking(&f, shell(7, &["ls"])).await;
    f.gate.withdraw(7, Withdraw::Cancel).await;
    assert_eq!(h.await.unwrap(), Err(Refusal::Denied("withdrawn")));
    let w = f.sink.last("approval.withdraw");
    assert_eq!(w["id"], id.as_str());
    assert_eq!(w["call"], 7);
    assert_eq!(w["reason"], "cancel");
    assert!(f.sink.rows().last().unwrap().debug.contains("Harness"));
    assert_eq!(
        decide(&f.desk, &id, Decision::Approve, ME).await,
        Err(DecideError::UnknownId)
    );
    let (_, h) = asking(&f, shell(8, &["ls"])).await;
    f.gate.withdraw(8, Withdraw::Closed).await;
    assert_eq!(h.await.unwrap(), Err(Refusal::Denied("withdrawn")));
    assert_eq!(f.sink.last("approval.withdraw")["reason"], "closed");
    assert!(f.sink.rows().last().unwrap().debug.contains("Sallyd"));
}

#[tokio::test]
async fn a_withdraw_that_cannot_be_written_is_unrecorded() {
    let f = fx(5);
    let (_, h) = asking(&f, shell(7, &["ls"])).await;
    f.sink.set_failing(true);
    f.gate.withdraw(7, Withdraw::Cancel).await;
    assert_eq!(h.await.unwrap(), Err(Refusal::Unrecorded));
}

#[tokio::test]
async fn a_withdraw_before_the_call_reaches_the_queue_keeps_it_from_being_shown() {
    let f = fx(5);
    let (other, call) = (f.gate.begin(), f.gate.begin());
    assert_ne!(other, call);
    // Another call's withdraw changes nothing for this one; the first cause is the one kept.
    f.gate.withdraw(other, Withdraw::Closed).await;
    f.gate.withdraw(call, Withdraw::Cancel).await;
    f.gate.withdraw(call, Withdraw::Closed).await;
    assert_eq!(f.gate.kept(), (2, 2));
    let r = f.gate.admit(shell(call, &["ls"]), None, None).await;
    assert_eq!(r, Err(Refusal::Denied("withdrawn")));
    let w = f.sink.last("approval.withdraw");
    assert_eq!(
        (w["call"].as_u64(), w["reason"].as_str()),
        (Some(call), Some("cancel"))
    );
    assert!(w["id"].is_null());
    assert!(f.sink.rows().last().unwrap().debug.contains("Harness"));
    assert!(f.fake.requested.lock().unwrap().is_empty());
    // Once the calls end, nothing is kept.
    f.gate.forget(call);
    f.gate.forget(other);
    assert_eq!(f.gate.kept(), (0, 0));
}

#[tokio::test]
async fn a_withdraw_for_a_call_that_ended_or_never_began_is_not_kept() {
    let f = fx(5);
    // Never begun: a harness cannot grow the map with made-up or finished calls.
    for n in 1000..1100 {
        f.gate.withdraw(n, Withdraw::Cancel).await;
    }
    assert_eq!(f.gate.kept(), (0, 0));
    let call = f.gate.begin();
    f.gate.forget(call);
    f.gate.withdraw(call, Withdraw::Cancel).await;
    assert_eq!(f.gate.kept(), (0, 0));
    // An ended call's number asks normally if it ever came again (it does not: numbers are
    // never reused), so nothing stale can deny a later call.
    let (id, h) = asking(&f, shell(call, &["ls"])).await;
    decide(&f.desk, &id, Decision::Deny, ME).await.unwrap();
    let _ = h.await;
}

#[tokio::test]
async fn a_withdraw_on_a_queued_prompt_keeps_its_first_cause() {
    let f = fx(5);
    let b = shell(5, &["ls"]);
    let Ok((id, _, _rx)) = f.gate.inner.queue(&b, None, vec![]) else {
        panic!("not queued");
    };
    f.gate.withdraw(5, Withdraw::Cancel).await;
    f.gate.withdraw(5, Withdraw::Closed).await;
    assert!(matches!(
        f.gate.inner.announce(&id),
        Err(NotQueued::Withdrawn(Withdraw::Cancel))
    ));
}

/// The held append blocks a blocking-pool thread, never the runtime.
#[tokio::test]
async fn no_decision_slips_in_while_a_deny_all_session_is_written() {
    let f = fx(5);
    let (a, ha) = asking(&f, shell(1, &["a"])).await;
    let (b, hb) = asking(&f, shell(2, &["b"])).await;
    f.sink.hold(true);
    let desk = f.desk.clone();
    let all = tokio::spawn(async move { decide(&desk, &a, Decision::DenyAllSession, ME).await });
    // The latch comes first: `a` is taken and `b` drained before `a`'s entry is written.
    until("a taken, b drained", || f.desk.list().is_empty()).await;
    let desk = f.desk.clone();
    let bb = b.clone();
    let approve = tokio::spawn(async move { decide(&desk, &bb, Decision::Approve, ME).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !approve.is_finished(),
        "an approval ran during a deny_all_session"
    );
    f.sink.hold(false);
    assert_eq!(all.await.unwrap(), Ok(()));
    assert_eq!(approve.await.unwrap(), Err(DecideError::UnknownId));
    assert_eq!(ha.await.unwrap(), Err(Refusal::Denied("denied")));
    assert_eq!(hb.await.unwrap(), Err(Refusal::Denied("session-denied")));
}

/// Q59 (a) step 3: the session's stop takes every shown prompt out of the queue with
/// `approval.withdraw session-stop` (sallyd's), its asker is denied, a later approve of it is
/// refused, and from then on no call queues: `approval.deny session-stopping`, never shown.
#[tokio::test]
async fn the_session_stop_withdraws_every_prompt_and_queues_no_more() {
    let f = fx(5);
    let (a, ha) = asking(&f, shell(7, &["ls"])).await;
    let (b, hb) = asking(&f, shell(8, &["ls"])).await;
    f.desk.stop().await.unwrap();
    assert!(f.desk.list().is_empty());
    for h in [ha, hb] {
        assert_eq!(h.await.unwrap(), Err(Refusal::Denied("withdrawn")));
    }
    assert_eq!(count(&f.sink, "approval.withdraw"), 2);
    let w = f.sink.last("approval.withdraw");
    assert_eq!(w["reason"], "session-stop");
    assert!(f.sink.rows().last().unwrap().debug.contains("Sallyd"));
    for id in [&a, &b] {
        assert_eq!(
            decide(&f.desk, id, Decision::Approve, ME).await,
            Err(DecideError::UnknownId)
        );
    }
    let shown = f.fake.requested.lock().unwrap().len();
    let r = f.gate.admit(shell(9, &["ls"]), None, None).await;
    assert_eq!(r, Err(Refusal::Denied("session-stopping")));
    assert_eq!(f.sink.last("approval.deny")["reason"], "session-stopping");
    assert_eq!(f.fake.requested.lock().unwrap().len(), shown, "never shown");
    // Stopping twice changes nothing.
    f.desk.stop().await.unwrap();
    assert_eq!(count(&f.sink, "approval.withdraw"), 2);
}

/// Security re-review S1 (ruling 1, PR A part 4): an approve whose `approval.decide` is being
/// written when the session's last entry comes lands before `session.stop`, never after it.
#[tokio::test]
async fn an_approve_being_written_at_the_seal_lands_before_session_stop() {
    let f = fx(5);
    let (a, ha) = asking(&f, shell(7, &["ls"])).await;
    f.sink.hold(true);
    let desk = f.desk.clone();
    let approve = tokio::spawn(async move { decide(&desk, &a, Decision::Approve, ME).await });
    until("the prompt is taken", || f.desk.list().is_empty()).await;
    let sealing = {
        let rec = f.rec.clone();
        tokio::spawn(async move {
            let last = rec.entry(Actor::Sallyd, "session.stop", None);
            rec.seal(last, Duration::from_secs(5)).await
        })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!sealing.is_finished(), "the seal waits for the decide");
    f.sink.hold(false);
    assert_eq!(approve.await.unwrap(), Ok(()));
    assert!(ha.await.unwrap().is_ok());
    assert!(sealing.await.unwrap().written);
    let events = f.sink.events();
    assert_eq!(events.last().map(String::as_str), Some("session.stop"));
    assert!(events.contains(&"approval.decide".to_owned()), "{events:?}");
}

/// S1: a decide or a withdraw after the session's last entry writes nothing and has no effect:
/// the approve is `Unrecorded`, its asker is denied, and the withdraw leaves no entry.
#[tokio::test]
async fn after_the_seal_a_decide_or_withdraw_writes_nothing_and_runs_nothing() {
    let f = fx(5);
    let (a, ha) = asking(&f, shell(7, &["ls"])).await;
    let (b, hb) = asking(&f, shell(8, &["ls"])).await;
    assert!(seal(&f, Duration::from_secs(1)).await.written);
    assert_eq!(
        decide(&f.desk, &a, Decision::Approve, ME).await,
        Err(DecideError::Unrecorded)
    );
    assert_eq!(ha.await.unwrap(), Err(Refusal::Unrecorded));
    f.gate.withdraw(8, Withdraw::Closed).await;
    let _ = hb.await.unwrap().unwrap_err();
    let events = f.sink.events();
    assert_eq!(events.last().map(String::as_str), Some("session.stop"));
    drop(b);
}

/// A prompt queued but not yet shown when the stop comes is never shown: its asker leaves with
/// the stop's reason.
#[tokio::test]
async fn a_prompt_not_yet_shown_at_the_stop_is_never_shown() {
    let f = fx(5);
    let b = shell(5, &["ls"]);
    let Ok((id, _, _rx)) = f.gate.inner.queue(&b, None, vec![]) else {
        panic!("not queued");
    };
    f.desk.stop().await.unwrap();
    assert!(matches!(
        f.gate.inner.announce(&id),
        Err(NotQueued::Withdrawn(Withdraw::SessionStop))
    ));
    assert!(f.fake.requested.lock().unwrap().is_empty());
    assert_eq!(
        f.gate
            .inner
            .withdrawn_before_shown(5, Some(&id), Withdraw::SessionStop)
            .await,
        Refusal::Denied("withdrawn")
    );
    assert_eq!(f.sink.last("approval.withdraw")["reason"], "session-stop");
}

#[tokio::test]
async fn a_withdraw_before_the_prompt_is_shown_keeps_its_reason() {
    let f = fx(5);
    let b = shell(5, &["ls"]);
    let Ok((id, _, _rx)) = f.gate.inner.queue(&b, None, vec![]) else {
        panic!("not queued");
    };
    f.gate.withdraw(5, Withdraw::Closed).await;
    assert!(matches!(
        f.gate.inner.announce(&id),
        Err(NotQueued::Withdrawn(Withdraw::Closed))
    ));
    assert!(f.desk.list().is_empty());
    assert!(f.fake.requested.lock().unwrap().is_empty());
    assert!(matches!(
        f.gate.inner.announce("ap-none"),
        Err(NotQueued::Withdrawn(Withdraw::Closed))
    ));
}

#[tokio::test]
async fn a_latch_set_while_the_entry_is_written_denies_the_prompt() {
    let f = fx(5);
    let b = shell(5, &["ls"]);
    let Ok((id, _, _rx)) = f.gate.inner.queue(&b, None, vec![]) else {
        panic!("not queued");
    };
    f.gate.inner.state().latched = true;
    assert!(matches!(
        f.gate.inner.announce(&id),
        Err(NotQueued::Deny("session-denied", false))
    ));
    assert!(f.gate.inner.state().pending.is_empty());
}

fn listed(f: &Fx) -> Vec<String> {
    f.desk.list().iter().map(|p| p.id.clone()).collect()
}

/// Q84, Q97: the list stays oldest first when the oldest prompt leaves, whichever way it
/// leaves (a list cut at its budget keeps a prefix, so order decides what is shown).
#[tokio::test(start_paused = true)]
async fn the_oldest_prompt_leaving_keeps_the_rest_in_order() {
    for how in ["decide", "withdraw", "expire", "drop"] {
        let f = fx(5);
        let (a, ha) = asking(&f, shell(1, &["ls"])).await;
        if how == "expire" {
            tokio::time::advance(Duration::from_secs(100)).await;
        }
        let (b, _hb) = asking(&f, shell(2, &["ls"])).await;
        let (c, _hc) = asking(&f, shell(3, &["ls"])).await;
        assert_eq!(listed(&f), [a.clone(), b.clone(), c.clone()], "{how}");
        match how {
            "decide" => decide(&f.desk, &a, Decision::Deny, ME).await.unwrap(),
            "withdraw" => f.gate.withdraw(1, Withdraw::Cancel).await,
            "expire" => {
                tokio::time::advance(Duration::from_secs(200)).await;
                assert_eq!(ha.await.unwrap(), Err(Refusal::Denied("timeout")));
            }
            _ => {
                ha.abort();
                let _ = ha.await;
            }
        }
        until(how, || listed(&f).len() == 2).await;
        assert_eq!(listed(&f), [b, c], "{how}");
    }
}

/// A decision takes the prompt it names, not the first shown one.
#[tokio::test(start_paused = true)]
async fn a_decision_takes_the_prompt_it_names() {
    let f = fx(5);
    let (a, _ha) = asking(&f, shell(1, &["ls"])).await;
    let (b, hb) = asking(&f, shell(2, &["ls"])).await;
    decide(&f.desk, &b, Decision::Deny, ME).await.unwrap();
    assert_eq!(hb.await.unwrap(), Err(Refusal::Denied("denied")));
    assert_eq!(listed(&f), [a]);
}

/// Q97, the fifth removal site (security re-review LOW3): a prompt withdrawn before it is shown
/// leaves at its announce, and the shown ones behind it keep their order.
#[tokio::test(start_paused = true)]
async fn a_prompt_leaving_unshown_keeps_the_rest_in_order() {
    let f = fx(5);
    let Ok((x, _, _rx)) = f.gate.inner.queue(&shell(9, &["ls"]), None, vec![]) else {
        panic!("not queued");
    };
    let (a, _ha) = asking(&f, shell(1, &["ls"])).await;
    let (b, _hb) = asking(&f, shell(2, &["ls"])).await;
    f.gate.withdraw(9, Withdraw::Cancel).await;
    assert!(f.gate.inner.announce(&x).is_err());
    assert_eq!(listed(&f), [a, b]);
}

#[tokio::test]
async fn a_dropped_wait_invalidates_the_id_at_once() {
    let f = fx(5);
    let (id, h) = asking(&f, shell(1, &["ls"])).await;
    h.abort();
    let _ = h.await;
    assert!(f.desk.list().is_empty());
    assert!(f.fake.closed.lock().unwrap().contains(&id));
    assert_eq!(
        decide(&f.desk, &id, Decision::Approve, ME).await,
        Err(DecideError::UnknownId)
    );
}

#[tokio::test]
async fn a_panic_under_the_lock_latches_the_session() {
    let f = fx(5);
    let inner = Arc::clone(&f.gate.inner);
    let _ = std::thread::spawn(move || {
        let _st = inner.state.lock().unwrap();
        panic!("poison");
    })
    .join();
    let r = f.gate.admit(shell(1, &["ls"]), None, None).await;
    assert_eq!(r, Err(Refusal::Denied("session-denied")));
}

#[tokio::test(start_paused = true)]
async fn a_flood_episode_is_announced_once_and_again_after_it_ends() {
    let f = fx(2);
    let (a, ha) = asking(&f, shell(1, &["a"])).await;
    let (b, hb) = asking(&f, shell(2, &["b"])).await;
    for call in 3..6 {
        let r = f.gate.admit(shell(call, &["x"]), None, None).await;
        assert_eq!(r, Err(Refusal::Denied("approval-flood")));
    }
    assert_eq!(count(&f.sink, "approval.flood"), 1);
    assert_eq!(count(&f.sink, "approval.deny"), 3);
    assert_eq!(f.fake.floods.lock().unwrap().as_slice(), ["s-1"]);
    assert_eq!(f.sink.last("approval.deny")["reason"], "approval-flood");
    // The episode ends once the queue is empty and the rate is full again.
    decide(&f.desk, &a, Decision::Deny, ME).await.unwrap();
    decide(&f.desk, &b, Decision::Deny, ME).await.unwrap();
    let _ = (ha.await, hb.await);
    tokio::time::advance(REFILL * 2).await;
    let (c, hc) = asking(&f, shell(6, &["c"])).await;
    let (d, hd) = asking(&f, shell(7, &["d"])).await;
    let r = f.gate.admit(shell(8, &["e"]), None, None).await;
    assert_eq!(r, Err(Refusal::Denied("approval-flood")));
    assert_eq!(f.fake.floods.lock().unwrap().len(), 2);
    for id in [c, d] {
        decide(&f.desk, &id, Decision::Deny, ME).await.unwrap();
    }
    let _ = (hc.await, hd.await);
}

#[tokio::test(start_paused = true)]
async fn the_pending_bound_alone_refuses_and_refused_calls_take_no_rate_slot() {
    let f = fx(2);
    let (a, ha) = asking(&f, shell(1, &["a"])).await;
    let (b, hb) = asking(&f, shell(2, &["b"])).await;
    // The rate is full again; only the pending bound can refuse now, and refusals take no slot.
    tokio::time::advance(REFILL * 4).await;
    for call in 3..10 {
        let r = f.gate.admit(shell(call, &["x"]), None, None).await;
        assert_eq!(r, Err(Refusal::Denied("approval-flood")));
    }
    decide(&f.desk, &a, Decision::Deny, ME).await.unwrap();
    decide(&f.desk, &b, Decision::Deny, ME).await.unwrap();
    let _ = (ha.await, hb.await);
    // Both slots are still there.
    let (c, hc) = asking(&f, shell(10, &["c"])).await;
    let (d, hd) = asking(&f, shell(11, &["d"])).await;
    for id in [c, d] {
        decide(&f.desk, &id, Decision::Deny, ME).await.unwrap();
    }
    let _ = (hc.await, hd.await);
}

#[tokio::test(start_paused = true)]
async fn new_prompts_come_at_most_one_per_refill_after_the_burst() {
    let f = fx(3);
    for call in 0..3 {
        let (id, h) = asking(&f, shell(call, &["x"])).await;
        decide(&f.desk, &id, Decision::Deny, ME).await.unwrap();
        let _ = h.await;
    }
    // Queue empty, burst spent: the rate alone refuses.
    let r = f.gate.admit(shell(9, &["y"]), None, None).await;
    assert_eq!(r, Err(Refusal::Denied("approval-flood")));
    // The helper's polling moves paused time by a few ms; the exact boundary is rate.rs's test.
    tokio::time::advance(REFILL / 2).await;
    let r = f.gate.admit(shell(10, &["y"]), None, None).await;
    assert_eq!(r, Err(Refusal::Denied("approval-flood")));
    tokio::time::advance(REFILL / 2).await;
    let (id, h) = asking(&f, shell(11, &["y"])).await;
    decide(&f.desk, &id, Decision::Approve, ME).await.unwrap();
    assert!(h.await.unwrap().is_ok());
}

#[tokio::test]
async fn a_flood_announcement_that_cannot_be_written_is_announced_again() {
    let f = fx(1);
    let (id, h) = asking(&f, shell(1, &["a"])).await;
    f.sink.fail_next.store(1, SeqCst);
    let r = f.gate.admit(shell(2, &["b"]), None, None).await;
    assert_eq!(r, Err(Refusal::Unrecorded));
    assert!(f.fake.floods.lock().unwrap().is_empty());
    let r = f.gate.admit(shell(3, &["c"]), None, None).await;
    assert_eq!(r, Err(Refusal::Denied("approval-flood")));
    assert_eq!(count(&f.sink, "approval.flood"), 1);
    assert_eq!(f.fake.floods.lock().unwrap().len(), 1);
    decide(&f.desk, &id, Decision::Deny, ME).await.unwrap();
    let _ = h.await;
}

/// Spawns `n` asks for calls `from..from + n`.
fn spawn_asks(
    f: &Fx,
    tasks: &mut tokio::task::JoinSet<Result<Ticket, Refusal>>,
    from: u64,
    n: u64,
) {
    for call in from..from + n {
        let gate = f.gate.clone();
        tasks.spawn(async move { gate.admit(shell(call, &["touch", "x"]), None, None).await });
    }
}

/// RT-AG-03 at the gate: 1 000 shell calls in four waves, so that each bound is the only
/// thing between the flood and a prompt in at least one wave.
#[tokio::test(start_paused = true)]
async fn rt_ag_03_a_thousand_asks_leave_at_most_max_pending_and_run_nothing() {
    let f = fx(5);
    let shown = || f.fake.requested.lock().unwrap().len();
    let mut tasks = tokio::task::JoinSet::new();
    // Wave 1: the burst fills the queue; the rest flood.
    spawn_asks(&f, &mut tasks, 0, 400);
    until("5 shown", || shown() == 5).await;
    until("395 denied", || count(&f.sink, "approval.deny") == 395).await;
    assert_eq!(f.desk.list().len(), 5);
    // Wave 2: the queue is empty but the rate is spent, so the rate alone refuses.
    for p in f.desk.list() {
        decide(&f.desk, &p.id, Decision::Deny, ME).await.unwrap();
    }
    spawn_asks(&f, &mut tasks, 400, 200);
    until("595 denied", || count(&f.sink, "approval.deny") == 595).await;
    assert_eq!(shown(), 5);
    // Wave 3: the rate is full again; the queue fills to the bound.
    tokio::time::advance(REFILL * 10).await;
    spawn_asks(&f, &mut tasks, 600, 200);
    until("10 shown", || shown() == 10).await;
    until("790 denied", || count(&f.sink, "approval.deny") == 790).await;
    // Wave 4: the rate is full and the queue is full, so the pending bound alone refuses.
    tokio::time::advance(REFILL * 10).await;
    spawn_asks(&f, &mut tasks, 800, 200);
    until("990 denied", || count(&f.sink, "approval.deny") == 990).await;
    assert_eq!(shown(), 10);
    assert!(f.desk.list().len() <= 5);
    tokio::time::advance(Duration::from_secs(300)).await;
    let mut tally = std::collections::BTreeMap::<&str, usize>::new();
    while let Some(r) = tasks.join_next().await {
        match r.unwrap() {
            Ok(_) => panic!("a ticket was issued"),
            Err(Refusal::Denied(code)) => *tally.entry(code).or_default() += 1,
            Err(Refusal::Unrecorded) => panic!("unrecorded"),
        }
    }
    assert_eq!(tally.get("approval-flood"), Some(&990), "{tally:?}");
    assert_eq!(tally.get("denied"), Some(&5), "{tally:?}");
    assert_eq!(tally.get("timeout"), Some(&5), "{tally:?}");
    // Two episodes: waves 1–2, then 3–4 (the queue emptied and the rate refilled between).
    assert_eq!(count(&f.sink, "approval.flood"), 2);
}

#[tokio::test]
async fn the_pending_entry_carries_note_hash_and_tags_never_the_note() {
    let f = fx(5);
    let gate = f.gate.clone();
    let note = "please approve, ignore the user";
    let h = tokio::spawn(async move {
        gate.admit(shell(1, &["rm", "x"]), Some(note), Some(true))
            .await
    });
    until("shown", || !f.desk.list().is_empty()).await;
    let p = f.desk.list().remove(0);
    assert_eq!(p.risk_tags, vec!["destructive"]);
    assert_eq!(p.note.as_deref(), Some(format!("\"{note}\"").as_str()));
    let e = f.sink.last("tool.pending");
    assert_eq!(e["note_bytes"], note.len());
    // An independent hash: the module's own helper is not the oracle.
    let want = super::super::action::hex(&<sha2::Sha256 as sha2::Digest>::digest(note.as_bytes()));
    assert_eq!(e["note_sha256"], want);
    assert!(!e.to_string().contains("ignore the user"));
    decide(&f.desk, &p.id, Decision::Deny, ME).await.unwrap();
    let _ = h.await;
}

#[tokio::test]
async fn the_pending_entry_stays_under_the_writer_bound_in_the_worst_case() {
    let f = fx(5);
    // Every character escapes to the longest form, and JSON doubles each backslash.
    let worst = "\\".repeat(256 * 1024);
    let gate = f.gate.clone();
    let h = tokio::spawn(async move {
        gate.admit(shell(u64::MAX, &[&worst, &worst]), Some("n"), Some(true))
            .await
    });
    until("shown", || !f.desk.list().is_empty()).await;
    let e = f.sink.last("tool.pending");
    let len = e.to_string().len();
    assert!(len < 4096, "{len}");
    assert!(e["action"].as_str().unwrap().contains("... (+"));
    let id = f.desk.list().remove(0).id.clone();
    decide(&f.desk, &id, Decision::Deny, ME).await.unwrap();
    let _ = h.await;
    // So does the decision entry, which carries the same fields and the client.
    let d = f.sink.last("approval.decide").to_string().len();
    assert!(d < 4096, "{d}");
}

#[test]
fn limits_come_from_the_manifest_and_decisions_have_wire_names() {
    let a = Approvals {
        timeout: sally_core::manifest::Duration::from_secs(90),
        max_pending: 7,
    };
    assert_eq!(
        Limits::from_manifest(&a),
        Limits {
            timeout: Duration::from_secs(90),
            max_pending: 7
        }
    );
    assert_eq!(Decision::Approve.as_str(), "approve");
    assert_eq!(Decision::Deny.as_str(), "deny");
    assert_eq!(Decision::DenyAllSession.as_str(), "deny_all_session");
    assert_eq!(DecideError::UnknownId.to_string(), "unknown-id");
    assert_eq!(DecideError::Unrecorded.to_string(), "audit-failed");
}
