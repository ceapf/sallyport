#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::sync::Mutex as StdMutex;

use sally_core::manifest::{ApproveGlobs, BuiltinTool, FetchWrites, MountMode, ShellPolicy};

use super::super::action::{Payload, Target};
use super::super::policy::MountRule;
use super::*;
use crate::rpc::testkit::{Sink, recorder};

/// Records what an approver is told.
#[derive(Default)]
pub(crate) struct Fake {
    pub requested: StdMutex<Vec<Prompt>>,
    pub floods: StdMutex<Vec<String>>,
    pub closed: StdMutex<Vec<String>>,
}

impl Approver for Fake {
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
    let (gate, desk) = new("s-1".to_owned(), policy(), limits, rec, a);
    Fx {
        gate,
        desk,
        sink,
        fake,
    }
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

/// Starts an ask in its own task and waits until its prompt is shown.
async fn asking(f: &Fx, b: Bound) -> (String, tokio::task::JoinHandle<Result<Ticket, Refusal>>) {
    let before = f.fake.requested.lock().unwrap().len();
    let gate = f.gate.clone();
    let h = tokio::spawn(async move { gate.admit(b, None, None).await });
    for _ in 0..1000 {
        if f.fake.requested.lock().unwrap().len() > before {
            break;
        }
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let id = f.fake.requested.lock().unwrap()[before].id.clone();
    (id, h)
}

fn decisions(sink: &Sink) -> Vec<(String, Option<String>)> {
    sink.rows()
        .into_iter()
        .map(|r| (r.event, r.decision))
        .collect()
}

#[tokio::test]
async fn an_action_that_needs_no_approval_gets_a_ticket_without_a_prompt() {
    let f = fx(5);
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
    f.desk.decide(&id, Decision::Approve, ME).await.unwrap();
    let t = h.await.unwrap().unwrap();
    assert_eq!(t.bound(), &b);
    assert_eq!(t.approval(), Some(id.as_str()));
    let d = f.sink.last("approval.decide");
    assert_eq!(d["id"], id.as_str());
    assert_eq!(d["client"], json!({"uid": 1000, "pid": 42}));
    assert_eq!(d["action_sha256"], b.digest());
    // Replay: the id is gone, and the refusal is audited.
    let again = f.desk.decide(&id, Decision::Approve, ME).await;
    assert_eq!(again, Err(DecideError::UnknownId));
    let rows = decisions(&f.sink);
    assert_eq!(
        rows.last().unwrap(),
        &("approval.decide".to_owned(), Some("refuse".to_owned()))
    );
    assert_eq!(f.sink.last("approval.decide")["reason"], "unknown-id");
    assert!(f.desk.list().is_empty());
    assert_eq!(f.fake.closed.lock().unwrap().as_slice(), [id]);
}

#[tokio::test]
async fn an_identical_later_call_asks_again_under_a_new_id() {
    let f = fx(5);
    let (first, h) = asking(&f, shell(1, &["ls"])).await;
    f.desk.decide(&first, Decision::Approve, ME).await.unwrap();
    h.await.unwrap().unwrap();
    let (second, h) = asking(&f, shell(2, &["ls"])).await;
    assert_ne!(first, second);
    f.desk.decide(&second, Decision::Deny, ME).await.unwrap();
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

#[tokio::test(start_paused = true)]
async fn a_prompt_nobody_answers_expires_as_a_denial() {
    let f = fx(5);
    let (id, h) = asking(&f, shell(1, &["ls"])).await;
    tokio::time::advance(Duration::from_secs(299)).await;
    assert_eq!(f.desk.list().len(), 1);
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(h.await.unwrap(), Err(Refusal::Denied("timeout")));
    let e = f.sink.last("approval.expire");
    assert_eq!(e["id"], id.as_str());
    assert_eq!(e["reason"], "timeout");
    assert_eq!(
        f.desk.decide(&id, Decision::Approve, ME).await,
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
    let r = f.gate.admit(shell(1, &["ls"]), None, None).await;
    assert_eq!(r, Err(Refusal::Unrecorded));
    assert!(f.fake.requested.lock().unwrap().is_empty());
    assert!(f.desk.list().is_empty());
}

#[tokio::test]
async fn an_approval_that_cannot_be_written_is_not_given() {
    let f = fx(5);
    let (id, h) = asking(&f, shell(1, &["ls"])).await;
    f.sink.set_failing(true);
    let r = f.desk.decide(&id, Decision::Approve, ME).await;
    assert_eq!(r, Err(DecideError::Unrecorded));
    assert_eq!(h.await.unwrap(), Err(Refusal::Unrecorded));
    // And an unknown id whose refusal cannot be written says so.
    assert_eq!(
        f.desk.decide("ap-x", Decision::Deny, ME).await,
        Err(DecideError::Unrecorded)
    );
}

#[tokio::test]
async fn deny_all_session_denies_every_pending_prompt_and_every_later_one() {
    let f = fx(5);
    let (a, ha) = asking(&f, shell(1, &["a"])).await;
    let (b, hb) = asking(&f, shell(2, &["b"])).await;
    f.desk
        .decide(&a, Decision::DenyAllSession, ME)
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

#[tokio::test]
async fn deny_all_session_on_a_stale_id_sets_nothing() {
    let f = fx(5);
    let r = f.desk.decide("ap-0", Decision::DenyAllSession, ME).await;
    assert_eq!(r, Err(DecideError::UnknownId));
    let (id, h) = asking(&f, shell(1, &["ls"])).await;
    f.desk.decide(&id, Decision::Approve, ME).await.unwrap();
    assert!(h.await.unwrap().is_ok());
}

#[tokio::test]
async fn a_withdrawn_call_leaves_the_queue_audited_and_cannot_be_approved() {
    let f = fx(5);
    let (id, h) = asking(&f, shell(7, &["ls"])).await;
    f.gate.withdraw(99, Withdraw::Cancel).await;
    assert_eq!(f.desk.list().len(), 1);
    f.gate.withdraw(7, Withdraw::Cancel).await;
    assert_eq!(h.await.unwrap(), Err(Refusal::Denied("withdrawn")));
    let w = f.sink.last("approval.withdraw");
    assert_eq!(
        (w["id"].as_str(), w["call"].as_u64()),
        (Some(id.as_str()), Some(7))
    );
    assert_eq!(w["reason"], "cancel");
    assert!(f.sink.rows().last().unwrap().debug.contains("Harness"));
    assert_eq!(
        f.desk.decide(&id, Decision::Approve, ME).await,
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
async fn a_withdraw_before_the_prompt_is_shown_still_withdraws_it() {
    let f = fx(5);
    let b = shell(5, &["ls"]);
    let id = f.gate.inner.queue(&b, None, vec![]).unwrap();
    f.gate.withdraw(5, Withdraw::Cancel).await;
    assert_eq!(f.gate.inner.announce(&id), Err("withdrawn"));
    assert!(f.desk.list().is_empty());
    assert!(f.fake.requested.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_latch_set_while_the_entry_is_written_denies_the_prompt() {
    let f = fx(5);
    let b = shell(5, &["ls"]);
    let id = f.gate.inner.queue(&b, None, vec![]).unwrap();
    lock(&f.gate.inner.state).latched = true;
    assert_eq!(f.gate.inner.announce(&id), Err("session-denied"));
    assert!(lock(&f.gate.inner.state).pending.is_empty());
    assert_eq!(f.gate.inner.announce("ap-none"), Err("withdrawn"));
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
        f.desk.decide(&id, Decision::Approve, ME).await,
        Err(DecideError::UnknownId)
    );
}

#[tokio::test(start_paused = true)]
async fn the_pending_bound_denies_each_extra_call_and_announces_the_episode_once() {
    let f = fx(2);
    let (a, ha) = asking(&f, shell(1, &["a"])).await;
    let (b, hb) = asking(&f, shell(2, &["b"])).await;
    for call in 3..6 {
        let r = f.gate.admit(shell(call, &["x"]), None, None).await;
        assert_eq!(r, Err(Refusal::Denied("approval-flood")));
    }
    let events = f.sink.events();
    assert_eq!(events.iter().filter(|e| *e == "approval.flood").count(), 1);
    assert_eq!(events.iter().filter(|e| *e == "approval.deny").count(), 3);
    assert_eq!(f.fake.floods.lock().unwrap().as_slice(), ["s-1"]);
    assert_eq!(f.sink.last("approval.deny")["reason"], "approval-flood");
    // The episode ends once the queue is empty and the rate is full again.
    f.desk.decide(&a, Decision::Deny, ME).await.unwrap();
    f.desk.decide(&b, Decision::Deny, ME).await.unwrap();
    let _ = (ha.await, hb.await);
    tokio::time::advance(REFILL * 2).await;
    let (c, hc) = asking(&f, shell(6, &["c"])).await;
    let (_, _hd) = asking(&f, shell(7, &["d"])).await;
    let r = f.gate.admit(shell(8, &["e"]), None, None).await;
    assert_eq!(r, Err(Refusal::Denied("approval-flood")));
    assert_eq!(f.fake.floods.lock().unwrap().len(), 2);
    f.desk.decide(&c, Decision::Deny, ME).await.unwrap();
    let _ = hc.await;
}

#[tokio::test(start_paused = true)]
async fn new_prompts_come_at_most_one_per_refill_after_the_burst() {
    let f = fx(3);
    for call in 0..3 {
        let (id, h) = asking(&f, shell(call, &["x"])).await;
        f.desk.decide(&id, Decision::Deny, ME).await.unwrap();
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
    f.desk.decide(&id, Decision::Approve, ME).await.unwrap();
    assert!(h.await.unwrap().is_ok());
}

#[tokio::test(start_paused = true)]
async fn a_denial_over_the_bound_does_not_take_a_rate_slot() {
    let f = fx(1);
    let (id, h) = asking(&f, shell(1, &["a"])).await;
    for call in 2..20 {
        let _ = f.gate.admit(shell(call, &["x"]), None, None).await;
    }
    f.desk.decide(&id, Decision::Deny, ME).await.unwrap();
    let _ = h.await;
    tokio::time::advance(REFILL).await;
    // One slot came back and the refused calls took none of it.
    let (id, h) = asking(&f, shell(30, &["b"])).await;
    f.desk.decide(&id, Decision::Deny, ME).await.unwrap();
    let _ = h.await;
}

#[tokio::test]
async fn a_flood_announcement_that_cannot_be_written_is_unrecorded() {
    let f = fx(1);
    let (_, _h) = asking(&f, shell(1, &["a"])).await;
    f.sink.set_failing(true);
    let r = f.gate.admit(shell(2, &["b"]), None, None).await;
    assert_eq!(r, Err(Refusal::Unrecorded));
    assert!(f.fake.floods.lock().unwrap().is_empty());
}

/// RT-AG-03 at the gate: 1 000 shell calls at once.
#[tokio::test(start_paused = true)]
async fn rt_ag_03_a_thousand_asks_leave_at_most_max_pending_and_run_nothing() {
    let f = fx(5);
    let mut tasks = tokio::task::JoinSet::new();
    for call in 0..1000 {
        let gate = f.gate.clone();
        tasks.spawn(async move { gate.admit(shell(call, &["touch", "x"]), None, None).await });
    }
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
    assert_eq!(f.desk.list().len(), 5);
    tokio::time::advance(Duration::from_secs(300)).await;
    let mut flood = 0;
    while let Some(r) = tasks.join_next().await {
        match r.unwrap() {
            Ok(_) => panic!("a ticket was issued"),
            Err(Refusal::Denied("approval-flood")) => flood += 1,
            Err(Refusal::Denied("timeout")) => {}
            Err(other) => panic!("{other:?}"),
        }
    }
    assert_eq!(flood, 995);
    let events = f.sink.events();
    assert_eq!(events.iter().filter(|e| *e == "approval.flood").count(), 1);
    assert_eq!(events.iter().filter(|e| *e == "approval.deny").count(), 995);
    assert_eq!(events.iter().filter(|e| *e == "approval.expire").count(), 5);
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
    for _ in 0..100 {
        if !f.desk.list().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let p = f.desk.list().remove(0);
    assert_eq!(p.risk_tags, vec!["destructive"]);
    assert_eq!(p.note.as_deref(), Some(note));
    let e = f.sink.last("tool.pending");
    assert_eq!(e["note_bytes"], note.len());
    assert_eq!(e["note_sha256"], sha256(note.as_bytes()));
    assert!(!e.to_string().contains("ignore the user"));
    f.desk.decide(&p.id, Decision::Deny, ME).await.unwrap();
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
    for _ in 0..100 {
        if !f.desk.list().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let e = f.sink.last("tool.pending");
    let len = e.to_string().len();
    assert!(len < 4096, "{len}");
    assert!(e["action"].as_str().unwrap().contains("… (+"));
    let id = f.desk.list().remove(0).id;
    f.desk.decide(&id, Decision::Deny, ME).await.unwrap();
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
