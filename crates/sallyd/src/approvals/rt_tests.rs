//! Red-team rows RT-AG-02, -03 and the fetch half of -14, proven at the gate (architect ruling
//! Q18): a real `agent.sock` server serves the production [`Gated`] handler, decisions go
//! through the [`Desk`], and a recording executor stands in for Task 11's. The shell clauses
//! with the real executor (a file absent or created) are `tests/tools.rs`; the fetch seen
//! upstream is #75.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use sally_core::manifest::{ApproveGlobs, BuiltinTool, FetchWrites, MountMode, ShellPolicy};
use serde_json::{Map, Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, ReadHalf, WriteHalf};

use super::action::{Action, Bound, Payload};
use super::handler::{Executor, Gated, Prepared};
use super::policy::{MountRule, Policy};
use super::queue::tests::decide;
use super::queue::{self, Approver, Client, DecideError, Decision, Desk, Limits, Ticket};
use super::render::Prompt;
use crate::rpc::agent::{Agent, MAX_FRAME};
use crate::rpc::mcp::{META_CAPABILITIES, META_VERSION, MODERN, Tool, ToolOutcome};
use crate::rpc::testkit::{Sink, recorder};

const ME: Client = Client { uid: 1000, pid: 7 };

/// Stands in for Task 11's executors: builds actions from arguments and records what it runs.
// TODO(#75): the fetch executor re-runs RT-AG-14's fetch half on the wire.
#[derive(Default)]
struct Recording {
    ran: StdMutex<Vec<Bound>>,
    prepared: AtomicUsize,
    /// A call with `"hold": true` waits in `prepare` until released (a slow path resolution).
    release: tokio::sync::Notify,
}

fn strings(v: Option<&Value>) -> Option<Vec<String>> {
    v?.as_array()?
        .iter()
        .map(|s| s.as_str().map(str::to_owned))
        .collect()
}

impl Executor for std::sync::Arc<Recording> {
    fn tools(&self) -> Vec<Tool> {
        vec![]
    }

    async fn prepare(&self, name: &str, a: &Map<String, Value>) -> Result<Prepared, &'static str> {
        self.prepared.fetch_add(1, Ordering::SeqCst);
        if a.get("hold") == Some(&Value::Bool(true)) {
            self.release.notified().await;
        }
        let action = match name {
            "shell" => Action::Shell {
                argv: strings(a.get("cmd")).ok_or("bad-arguments")?,
                cwd: "/workspace/p".to_owned(),
            },
            "fetch" => Action::Fetch {
                method: a
                    .get("method")
                    .and_then(Value::as_str)
                    .unwrap_or("GET")
                    .to_owned(),
                url: a
                    .get("url")
                    .and_then(Value::as_str)
                    .ok_or("bad-arguments")?
                    .to_owned(),
                headers: vec![],
                body: Payload::new(
                    a.get("body")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .as_bytes()
                        .to_vec(),
                ),
            },
            _ => return Err("unknown-tool"),
        };
        let note = a.get("reason").and_then(Value::as_str).map(str::to_owned);
        Ok(Prepared {
            action,
            note,
            destructive: None,
        })
    }

    async fn run(&self, ticket: Ticket) -> Option<ToolOutcome> {
        self.ran.lock().unwrap().push(ticket.bound().clone());
        Some(ToolOutcome {
            is_error: false,
            text: "ran".to_owned(),
        })
    }
}

#[derive(Default)]
struct Shown {
    prompts: StdMutex<Vec<Prompt>>,
    floods: AtomicUsize,
}

impl Approver for Shown {
    fn attached(&self) -> bool {
        true
    }
    fn requested(&self, p: &Prompt) {
        self.prompts.lock().unwrap().push(p.clone());
    }
    fn flood(&self, _: &str) {
        self.floods.fetch_add(1, Ordering::SeqCst);
    }
    fn closed(&self, _: &str) {}
}

struct Fx {
    agent: std::sync::Arc<Agent<Gated<std::sync::Arc<Recording>>>>,
    desk: Desk,
    /// A handle on the handler's gate, to see what it keeps.
    gate: queue::Gate,
    exec: std::sync::Arc<Recording>,
    shown: std::sync::Arc<Shown>,
    sink: std::sync::Arc<Sink>,
}

fn fx(timeout: Duration, max_pending: usize) -> Fx {
    let (sink, rec) = recorder("s-rt");
    let shown = std::sync::Arc::new(Shown::default());
    let policy = Policy {
        builtin: vec![BuiltinTool::Shell, BuiltinTool::Fetch],
        shell: ShellPolicy::Approve,
        destructive_requires_approval: true,
        fetch_writes: FetchWrites::Approve,
        // A mount is present: fetch can carry private data (RT-AG-14).
        mounts: vec![MountRule {
            guest: "/workspace/p".to_owned(),
            mode: MountMode::Rw,
            approve: ApproveGlobs::not_applicable(),
        }],
        mcp: vec![],
    };
    let limits = Limits {
        timeout,
        max_pending,
    };
    let approver = std::sync::Arc::clone(&shown) as std::sync::Arc<dyn Approver>;
    let (gate, desk) = queue::new(
        "s-rt".to_owned(),
        policy,
        limits,
        rec.clone(),
        Some(approver),
    );
    let exec = std::sync::Arc::new(Recording::default());
    let handler = Gated::new(gate.clone(), std::sync::Arc::clone(&exec));
    let agent = std::sync::Arc::new(Agent::new(handler, rec));
    Fx {
        agent,
        desk,
        gate,
        exec,
        shown,
        sink,
    }
}

struct Conn {
    r: BufReader<ReadHalf<DuplexStream>>,
    w: WriteHalf<DuplexStream>,
}

impl Conn {
    async fn send(&mut self, v: &Value) {
        self.w
            .write_all(&serde_json::to_vec(v).unwrap())
            .await
            .unwrap();
        self.w.write_all(b"\n").await.unwrap();
    }

    async fn recv(&mut self) -> Value {
        let mut line = String::new();
        let n = tokio::time::timeout(Duration::from_secs(3600), self.r.read_line(&mut line))
            .await
            .expect("no reply")
            .unwrap();
        assert!(n > 0, "closed");
        serde_json::from_str(&line).unwrap()
    }
}

fn open(f: &Fx) -> Conn {
    let (client, server) = tokio::io::duplex(4 * MAX_FRAME);
    tokio::spawn(std::sync::Arc::clone(&f.agent).serve_stream(server));
    let (r, w) = tokio::io::split(client);
    Conn {
        r: BufReader::new(r),
        w,
    }
}

fn call(id: i64, tool: &str, arguments: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {
        "name": tool, "arguments": arguments,
        "_meta": {META_VERSION: MODERN, META_CAPABILITIES: {}},
    }})
}

fn touch(id: i64) -> Value {
    call(id, "shell", json!({"cmd": ["touch", "/workspace/x"]}))
}

fn text(reply: &Value) -> &str {
    reply["result"]["content"][0]["text"].as_str().unwrap()
}

/// Waits until `n` prompts have been shown; the last one.
async fn shown(f: &Fx, n: usize) -> Prompt {
    for _ in 0..10_000 {
        if let Some(p) = f.shown.prompts.lock().unwrap().get(n - 1) {
            return p.clone();
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    panic!("prompt {n} never shown");
}

/// Polls until `cond` holds.
async fn until(what: &str, mut cond: impl FnMut() -> bool) {
    for _ in 0..10_000 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    panic!("never: {what}");
}

/// A cancel (or a closed connection) that lands while the call is still being prepared, before
/// it reaches the queue: the call is never shown and never runs (#54; reviews of Task 10).
#[tokio::test]
async fn rt_ag_02_c_a_cancel_during_preparation_keeps_the_call_from_ever_being_shown() {
    let f = fx(Duration::from_secs(300), 5);
    let mut c = open(&f);
    c.send(&call(
        1,
        "shell",
        json!({"cmd": ["touch", "/workspace/x"], "hold": true}),
    ))
    .await;
    until("preparing", || f.exec.prepared.load(Ordering::SeqCst) == 1).await;
    c.send(
        &json!({"jsonrpc": "2.0", "method": "notifications/cancelled",
                   "params": {"requestId": 1}}),
    )
    .await;
    // The gate holds the withdraw for the live call before the preparation ends.
    until("withdraw kept", || f.gate.kept() == (1, 1)).await;
    f.exec.release.notify_one();
    until("withdraw written", || {
        f.sink.events().iter().any(|e| e == "approval.withdraw")
    })
    .await;
    let w = f.sink.last("approval.withdraw");
    assert_eq!(
        (w["call"].as_u64(), w["reason"].as_str()),
        (Some(0), Some("cancel"))
    );
    assert!(f.shown.prompts.lock().unwrap().is_empty());
    assert!(ran(&f).is_empty());
    // When the call ends, nothing is kept for it.
    until("call ended", || f.gate.kept() == (0, 0)).await;
    // The connection still works, and a later call with the same id is asked normally.
    c.send(&touch(1)).await;
    let p = shown(&f, 1).await;
    decide(&f.desk, &p.id, Decision::Deny, ME).await.unwrap();
    assert_eq!(text(&c.recv().await), "denied: denied");
    assert_eq!(f.gate.kept(), (0, 0));
}

/// A cancel that comes after its call has ended is not kept (a harness cannot grow the map).
#[tokio::test]
async fn a_cancel_for_a_call_that_has_ended_leaves_nothing_behind() {
    let f = fx(Duration::from_secs(300), 5);
    let mut c = open(&f);
    let cancel = |id| json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": id}});
    for id in 1..20 {
        c.send(&call(id, "nope", json!({}))).await;
        c.send(&cancel(id)).await;
    }
    c.send(&call(99, "nope", json!({}))).await;
    loop {
        let r = c.recv().await;
        if r["id"] == 99 {
            break;
        }
    }
    until("all ended", || f.gate.kept() == (0, 0)).await;
}

#[tokio::test]
async fn rt_ag_02_c_a_close_during_preparation_keeps_the_call_from_ever_being_shown() {
    let f = fx(Duration::from_secs(300), 5);
    let mut c = open(&f);
    c.send(&call(
        1,
        "shell",
        json!({"cmd": ["touch", "/workspace/x"], "hold": true}),
    ))
    .await;
    until("preparing", || f.exec.prepared.load(Ordering::SeqCst) == 1).await;
    c.w.shutdown().await.unwrap();
    // The close is seen and the withdraw kept before the preparation ends.
    until("withdraw kept", || f.gate.kept() == (1, 1)).await;
    f.exec.release.notify_one();
    until("withdraw written", || {
        f.sink.events().iter().any(|e| e == "approval.withdraw")
    })
    .await;
    assert_eq!(f.sink.last("approval.withdraw")["reason"], "closed");
    assert!(f.shown.prompts.lock().unwrap().is_empty());
    assert!(ran(&f).is_empty());
    until("call ended", || f.gate.kept() == (0, 0)).await;
}

fn ran(f: &Fx) -> Vec<Bound> {
    f.exec.ran.lock().unwrap().clone()
}

#[tokio::test(start_paused = true)]
async fn rt_ag_02_a_a_call_nobody_answers_times_out_and_never_runs() {
    let f = fx(Duration::from_secs(30), 5);
    let mut c = open(&f);
    c.send(&touch(1)).await;
    let p = shown(&f, 1).await;
    let r = c.recv().await;
    assert_eq!(text(&r), "denied: timeout");
    assert_eq!(r["result"]["isError"], true);
    assert!(ran(&f).is_empty());
    assert_eq!(f.sink.last("approval.expire")["id"], p.id.as_str());
    assert_eq!(
        decide(&f.desk, &p.id, Decision::Approve, ME).await,
        Err(DecideError::UnknownId)
    );
    assert!(ran(&f).is_empty());
}

#[tokio::test]
async fn rt_ag_02_b_a_denied_call_never_runs() {
    let f = fx(Duration::from_secs(300), 5);
    let mut c = open(&f);
    c.send(&touch(1)).await;
    let p = shown(&f, 1).await;
    decide(&f.desk, &p.id, Decision::Deny, ME).await.unwrap();
    assert_eq!(text(&c.recv().await), "denied: denied");
    assert!(ran(&f).is_empty());
}

#[tokio::test]
async fn rt_ag_02_c_an_approval_runs_once_and_is_never_reused() {
    let f = fx(Duration::from_secs(300), 5);
    let mut c = open(&f);
    c.send(&touch(1)).await;
    let first = shown(&f, 1).await;
    decide(&f.desk, &first.id, Decision::Approve, ME)
        .await
        .unwrap();
    assert_eq!(text(&c.recv().await), "ran");
    assert_eq!(ran(&f).len(), 1);
    // Replaying the decision is refused and audited; nothing runs again.
    assert_eq!(
        decide(&f.desk, &first.id, Decision::Approve, ME).await,
        Err(DecideError::UnknownId)
    );
    assert_eq!(f.sink.last("approval.decide")["reason"], "unknown-id");
    // An identical later call asks again, under a new id.
    c.send(&touch(2)).await;
    let second = shown(&f, 2).await;
    assert_ne!(second.id, first.id);
    assert_eq!(second.full, first.full);
    decide(&f.desk, &second.id, Decision::Deny, ME)
        .await
        .unwrap();
    assert_eq!(text(&c.recv().await), "denied: denied");
    // A cancelled call's prompt is withdrawn; an identical call after it inherits nothing.
    c.send(&touch(3)).await;
    let third = shown(&f, 3).await;
    c.send(
        &json!({"jsonrpc": "2.0", "method": "notifications/cancelled",
                   "params": {"requestId": 3}}),
    )
    .await;
    // The prompt leaves the queue before its entry is written: wait for the entry.
    until("withdraw written", || {
        f.sink.events().iter().any(|e| e == "approval.withdraw")
    })
    .await;
    assert!(f.desk.list().is_empty());
    assert_eq!(f.sink.last("approval.withdraw")["id"], third.id.as_str());
    assert_eq!(
        decide(&f.desk, &third.id, Decision::Approve, ME).await,
        Err(DecideError::UnknownId)
    );
    c.send(&touch(4)).await;
    let fourth = shown(&f, 4).await;
    assert_ne!(fourth.id, third.id);
    decide(&f.desk, &fourth.id, Decision::Deny, ME)
        .await
        .unwrap();
    assert_eq!(text(&c.recv().await), "denied: denied");
    assert_eq!(ran(&f).len(), 1);
}

#[tokio::test]
async fn rt_ag_02_d_other_arguments_under_the_same_id_never_run_as_the_approved_ones() {
    let f = fx(Duration::from_secs(300), 5);
    let mut a = open(&f);
    let mut b = open(&f);
    a.send(&call(5, "shell", json!({"cmd": ["echo", "approved"]})))
        .await;
    let approved = shown(&f, 1).await;
    // Same id, other arguments, same connection: refused before any handler sees it.
    a.send(&call(
        5,
        "shell",
        json!({"cmd": ["rm", "-rf", "/workspace"]}),
    ))
    .await;
    let dup = a.recv().await;
    assert_eq!(dup["error"]["code"], -32600);
    assert_eq!(f.exec.prepared.load(Ordering::SeqCst), 1);
    // Same id on another connection: a call of its own, with its own prompt and digest.
    b.send(&call(
        5,
        "shell",
        json!({"cmd": ["rm", "-rf", "/workspace"]}),
    ))
    .await;
    let other = shown(&f, 2).await;
    assert_ne!(other.digest, approved.digest);
    assert!(other.action.contains("\"rm\" \"-rf\""));
    assert!(approved.action.contains("\"echo\" \"approved\""));
    // Same id and the same arguments on a third connection: still its own call number, so
    // its own digest (ruling Q19): approving call 1 can never stand for it.
    let mut c = open(&f);
    c.send(&call(5, "shell", json!({"cmd": ["echo", "approved"]})))
        .await;
    let twin = shown(&f, 3).await;
    assert_eq!(twin.full, approved.full);
    assert_ne!(twin.call, approved.call);
    assert_ne!(twin.digest, approved.digest);
    decide(&f.desk, &approved.id, Decision::Approve, ME)
        .await
        .unwrap();
    assert_eq!(text(&a.recv().await), "ran");
    decide(&f.desk, &other.id, Decision::Deny, ME)
        .await
        .unwrap();
    assert_eq!(text(&b.recv().await), "denied: denied");
    decide(&f.desk, &twin.id, Decision::Deny, ME).await.unwrap();
    assert_eq!(text(&c.recv().await), "denied: denied");
    // What ran is exactly what was approved: the executed digest is the approved one.
    let ran = ran(&f);
    assert_eq!(ran.len(), 1);
    assert_eq!(ran[0].digest(), approved.digest);
    let decided: Vec<Value> = f
        .sink
        .rows()
        .into_iter()
        .filter(|r| r.event == "approval.decide" && r.decision.as_deref() == Some("approve"))
        .map(|r| r.args)
        .collect();
    assert_eq!(decided.len(), 1);
    assert_eq!(decided[0]["action_sha256"], approved.digest.as_str());
}

/// RT-AG-03 through the socket: 1 000 `shell` calls as fast as `agent.sock` reads them.
#[tokio::test(start_paused = true)]
async fn rt_ag_03_a_call_flood_through_agent_sock_runs_nothing() {
    let f = fx(Duration::from_secs(300), 5);
    let c = open(&f);
    let Conn { mut r, mut w } = c;
    let reader = tokio::spawn(async move {
        let mut replies = Vec::new();
        let mut line = String::new();
        while replies.len() < 1000 {
            line.clear();
            if r.read_line(&mut line).await.unwrap() == 0 {
                break;
            }
            replies.push(serde_json::from_str::<Value>(&line).unwrap());
        }
        replies
    });
    for id in 0..1000 {
        let frame = serde_json::to_vec(&touch(id)).unwrap();
        w.write_all(&frame).await.unwrap();
        w.write_all(b"\n").await.unwrap();
    }
    let replies = tokio::time::timeout(Duration::from_secs(3600), reader)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(replies.len(), 1000);
    let mut counts = std::collections::BTreeMap::<String, usize>::new();
    for r in &replies {
        let k = match r.get("error") {
            Some(e) => format!("error {}", e["message"]),
            None => text(r).to_owned(),
        };
        *counts.entry(k).or_default() += 1;
    }
    assert!(ran(&f).is_empty(), "{counts:?}");
    // Exactly max_pending prompts were ever shown; every other call was refused.
    assert_eq!(f.shown.prompts.lock().unwrap().len(), 5, "{counts:?}");
    assert_eq!(counts.get("denied: timeout"), Some(&5), "{counts:?}");
    let flooded = counts.get("denied: approval-flood").copied().unwrap_or(0);
    assert!(flooded > 0, "{counts:?}");
    assert_eq!(f.shown.floods.load(Ordering::SeqCst), 1);
    let events = f.sink.events();
    assert_eq!(events.iter().filter(|e| *e == "approval.flood").count(), 1);
    assert_eq!(
        events.iter().filter(|e| *e == "approval.deny").count(),
        flooded
    );
    // Every call that reached the gate has its entry: pending or denied.
    assert_eq!(
        events.iter().filter(|e| *e == "tool.pending").count() + flooded,
        f.exec.prepared.load(Ordering::SeqCst)
    );
}

#[tokio::test(start_paused = true)]
async fn rt_ag_14_a_fetch_write_waits_for_approval_and_is_denied_on_timeout() {
    let f = fx(Duration::from_secs(30), 5);
    let mut c = open(&f);
    let post = |id| {
        call(
            id,
            "fetch",
            json!({"url": "https://api.mock.test/gists", "method": "POST",
                                "body": "secret notes"}),
        )
    };
    c.send(&post(1)).await;
    let p = shown(&f, 1).await;
    assert!(
        p.action
            .starts_with("fetch \"POST\" \"https://api.mock.test/gists\"")
    );
    assert!(ran(&f).is_empty());
    decide(&f.desk, &p.id, Decision::Approve, ME).await.unwrap();
    assert_eq!(text(&c.recv().await), "ran");
    c.send(&post(2)).await;
    shown(&f, 2).await;
    assert_eq!(text(&c.recv().await), "denied: timeout");
    assert_eq!(ran(&f).len(), 1);
    // A read needs no approval.
    let get = call(3, "fetch", json!({"url": "https://api.mock.test/gists"}));
    c.send(&get).await;
    assert_eq!(text(&c.recv().await), "ran");
    assert_eq!(f.shown.prompts.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn a_call_the_executor_cannot_prepare_is_denied_and_audited() {
    let f = fx(Duration::from_secs(30), 5);
    let mut c = open(&f);
    c.send(&call(1, "nope\x1b", json!({}))).await;
    assert_eq!(text(&c.recv().await), "denied: unknown-tool");
    let e = f.sink.last("tool.deny");
    assert_eq!(e["code"], "unknown-tool");
    assert_eq!(e["tool"], "nope\\x1b");
    c.send(&call(2, "shell", json!({"cmd": "not a list"})))
        .await;
    assert_eq!(text(&c.recv().await), "denied: bad-arguments");
}

#[tokio::test]
async fn a_refusal_that_cannot_be_written_sends_no_reply() {
    use crate::rpc::agent::ToolHandler;
    let exec = std::sync::Arc::new(Recording::default());
    let handler = |failing: bool| {
        let (sink, rec) = recorder("s-rt");
        sink.set_failing(failing);
        let none = Policy {
            builtin: vec![],
            shell: ShellPolicy::Deny,
            destructive_requires_approval: true,
            fetch_writes: FetchWrites::Approve,
            mounts: vec![],
            mcp: vec![],
        };
        let limits = Limits {
            timeout: Duration::from_secs(1),
            max_pending: 1,
        };
        let (gate, _) = queue::new("s-rt".to_owned(), none, limits, rec, None);
        Gated::new(gate, std::sync::Arc::clone(&exec))
    };
    let ls = || -> Map<String, Value> { [("cmd".to_owned(), json!(["ls"]))].into_iter().collect() };
    // Written: a preparation refusal and a policy refusal are answered.
    let h = handler(false);
    let out = h.call(0, "shell".to_owned(), Map::new()).await;
    assert_eq!(out.unwrap().text, "denied: bad-arguments");
    let out = h.call(1, "shell".to_owned(), ls()).await;
    assert_eq!(out.unwrap().text, "denied: tool_not_granted");
    // Not written: nothing is answered and nothing runs.
    let h = handler(true);
    assert_eq!(h.call(2, "nope".to_owned(), Map::new()).await, None);
    assert_eq!(h.call(3, "shell".to_owned(), ls()).await, None);
    assert!(exec.ran.lock().unwrap().is_empty());
}
