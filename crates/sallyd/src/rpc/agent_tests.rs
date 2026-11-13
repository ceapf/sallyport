#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use super::*;
use crate::rpc::mcp::{META_CAPABILITIES, META_VERSION, MODERN};
use crate::rpc::testkit::{Sink, recorder};

/// Waits until `counter` reaches `n`; panics after 10 s of wall time. A call that is never
/// dispatched (say every append fails) fails the test instead of spinning for ever.
async fn reach(counter: &AtomicUsize, n: usize) {
    let end = std::time::Instant::now() + Duration::from_secs(10);
    while counter.load(Ordering::SeqCst) < n {
        assert!(
            std::time::Instant::now() < end,
            "the counter never reached {n}"
        );
        tokio::task::yield_now().await;
    }
}

/// A handler that answers `echo` at once and holds `block` until released.
#[derive(Default)]
struct Fake {
    calls: AtomicUsize,
    done: AtomicUsize,
    /// Calls that ended, finished or dropped mid-way (`ended > done`: one was dropped).
    ended: AtomicUsize,
    release: Notify,
    seen: Mutex<Vec<(String, Map<String, Value>)>>,
    /// The call numbers the handler was given, in order.
    numbers: Mutex<Vec<u64>>,
    /// The withdrawals it was told about.
    withdrawn: Mutex<Vec<(u64, Withdraw)>>,
    /// Calls begun.
    begun: AtomicUsize,
}

/// Counts a call's end, also when it is dropped mid-way.
struct Ended(Arc<Fake>);

impl Drop for Ended {
    fn drop(&mut self) {
        self.0.ended.fetch_add(1, Ordering::SeqCst);
    }
}

impl ToolHandler for Arc<Fake> {
    fn tools(&self) -> Vec<Tool> {
        vec![Tool {
            name: "echo",
            description: "Echo.",
            input_schema: json!({"type": "object"}),
        }]
    }

    async fn call(
        &self,
        call: u64,
        name: String,
        arguments: Map<String, Value>,
    ) -> Option<ToolOutcome> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.numbers.lock().unwrap().push(call);
        self.seen.lock().unwrap().push((name.clone(), arguments));
        let _ended = Ended(Arc::clone(self));
        if name == "block" {
            self.release.notified().await;
        }
        self.done.fetch_add(1, Ordering::SeqCst);
        // `unrecorded`: the handler's entry failed, so it answers nothing.
        (name != "unrecorded").then(|| ToolOutcome {
            is_error: false,
            text: format!("ran {name}"),
        })
    }

    fn begin(&self) -> u64 {
        // Odd numbers from 101, so a test can tell them from any count the server keeps.
        101 + 2 * self.begun.fetch_add(1, Ordering::SeqCst) as u64
    }

    async fn withdraw(&self, call: u64, why: Withdraw) {
        self.withdrawn.lock().unwrap().push((call, why));
    }
}

struct Client {
    r: tokio::io::BufReader<ReadHalf<DuplexStream>>,
    w: WriteHalf<DuplexStream>,
    server: JoinHandle<()>,
}

impl Client {
    async fn send(&mut self, v: &Value) {
        self.raw(&serde_json::to_vec(v).unwrap()).await;
    }

    async fn raw(&mut self, b: &[u8]) {
        self.w.write_all(b).await.unwrap();
        self.w.write_all(b"\n").await.unwrap();
    }

    /// The next reply, or `None` if the server closed.
    async fn recv(&mut self) -> Option<Value> {
        let mut line = String::new();
        let n = tokio::time::timeout(Duration::from_secs(10), self.r.read_line(&mut line))
            .await
            .expect("no reply within 10 s")
            .unwrap();
        (n > 0).then(|| serde_json::from_str(&line).unwrap())
    }

    /// Whether a reply arrives within 200 ms.
    async fn quiet(&mut self) -> bool {
        let mut line = String::new();
        tokio::time::timeout(Duration::from_millis(200), self.r.read_line(&mut line))
            .await
            .is_err()
    }

    async fn call(&mut self, v: &Value) -> Value {
        self.send(v).await;
        self.recv().await.expect("closed")
    }
}

fn start(agent: &Arc<Agent<Arc<Fake>>>) -> Client {
    let (client, server) = tokio::io::duplex(4 * MAX_FRAME);
    let server = tokio::spawn(Arc::clone(agent).serve_stream(server));
    let (r, w) = tokio::io::split(client);
    Client {
        r: tokio::io::BufReader::new(r),
        w,
        server,
    }
}

fn setup() -> (Arc<Agent<Arc<Fake>>>, Arc<Fake>, Arc<Sink>) {
    let fake = Arc::new(Fake::default());
    let (sink, rec) = recorder("sess-a");
    (Arc::new(Agent::new(Arc::clone(&fake), rec)), fake, sink)
}

fn meta() -> Value {
    json!({META_VERSION: MODERN, META_CAPABILITIES: {}})
}

fn req(id: i64, method: &str, mut params: Value) -> Value {
    params["_meta"] = meta();
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

fn bare(id: i64, method: &str, params: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

fn call(id: i64, tool: &str) -> Value {
    req(
        id,
        "tools/call",
        json!({"name": tool, "arguments": {"a": 1}}),
    )
}

fn denies(sink: &Sink) -> Vec<String> {
    sink.rows()
        .into_iter()
        .filter(|r| r.event == "rpc.deny")
        .map(|r| r.args["reason"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn the_2026_lifecycle_lists_and_calls_tools() {
    let (agent, fake, sink) = setup();
    let mut c = start(&agent);
    let d = c.call(&req(1, "server/discover", json!({}))).await;
    assert_eq!(d["id"], json!(1));
    assert_eq!(d["result"]["resultType"], json!("complete"));
    let l = c.call(&req(2, "tools/list", json!({}))).await;
    assert_eq!(l["result"]["tools"][0]["name"], json!("echo"));
    assert_eq!(l["result"]["cacheScope"], json!("private"));
    let r = c.call(&call(3, "echo")).await;
    assert_eq!(
        r["result"],
        json!({"resultType": "complete", "content": [{"type": "text", "text": "ran echo"}], "isError": false})
    );
    assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
    assert_eq!(sink.events(), ["rpc.request", "rpc.request", "rpc.request"]);
    let last = sink.last("rpc.request");
    assert_eq!(
        last,
        json!({"method": "tools/call", "id": 3, "lifecycle": "2026", "tool": "echo",
               "argument_count": 1, "argument_keys": ["a"], "arguments_bytes": 7})
    );
    assert!(sink.rows()[0].debug.contains("\"sess-a\""));
}

#[tokio::test]
async fn the_legacy_lifecycle_needs_initialize() {
    let (agent, _, sink) = setup();
    let mut c = start(&agent);
    let e = c.call(&bare(1, "tools/list", json!({}))).await;
    assert_eq!(e["error"]["code"], json!(-32602));
    assert_eq!(
        e["error"]["data"]["reason"],
        json!("missing-protocol-version")
    );
    let i = c
        .call(&bare(
            2,
            "initialize",
            json!({"protocolVersion": "2025-06-18", "capabilities": {}}),
        ))
        .await;
    assert_eq!(i["result"]["protocolVersion"], json!("2025-06-18"));
    c.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .await;
    let p = c.call(&bare(3, "ping", json!({}))).await;
    assert_eq!(p["result"], json!({}));
    let l = c.call(&bare(4, "tools/list", json!({}))).await;
    assert_eq!(
        l["result"],
        json!({"tools": [{"name": "echo", "description": "Echo.", "inputSchema": {"type": "object"}}]})
    );
    let r = c
        .call(&bare(5, "tools/call", json!({"name": "echo"})))
        .await;
    assert!(r["result"].get("resultType").is_none());
    let again = c
        .call(&bare(
            6,
            "initialize",
            json!({"protocolVersion": "2025-11-25", "capabilities": {}}),
        ))
        .await;
    assert_eq!(again["error"]["code"], json!(-32600));
    assert_eq!(
        denies(&sink),
        ["missing-protocol-version", "second-initialize"]
    );
    // initialize, initialized, ping, tools/list, tools/call.
    assert_eq!(
        sink.events().iter().filter(|e| *e == "rpc.request").count(),
        5
    );
}

#[tokio::test]
async fn legacy_state_belongs_to_one_connection() {
    let (agent, _, _) = setup();
    let mut a = start(&agent);
    let mut b = start(&agent);
    a.call(&bare(
        1,
        "initialize",
        json!({"protocolVersion": "2025-11-25", "capabilities": {}}),
    ))
    .await;
    assert!(
        a.call(&bare(2, "tools/list", json!({})))
            .await
            .get("result")
            .is_some()
    );
    let e = b.call(&bare(2, "tools/list", json!({}))).await;
    assert_eq!(
        e["error"]["data"]["reason"],
        json!("missing-protocol-version")
    );
}

/// RT-AG-06: control-plane methods on the session socket are not found, and audited.
#[tokio::test]
async fn rt_ag_06_control_methods_on_agent_sock_are_not_found() {
    let (agent, fake, sink) = setup();
    let mut c = start(&agent);
    let methods = [
        "secrets.set",
        "sessions.create",
        "infer.load",
        "approvals.decide",
        "manifests.save",
        "audit.tail",
        "audit.note",
    ];
    for (i, m) in (0..).zip(methods) {
        for msg in [
            req(i, m, json!({"name": "x", "value": "y"})),
            bare(i, m, json!({})),
        ] {
            let e = c.call(&msg).await;
            assert_eq!(e["id"], json!(i));
            assert_eq!(e["error"]["code"], json!(-32601), "{m}");
        }
    }
    let rows = sink.rows();
    assert_eq!(rows.len(), 2 * methods.len());
    for (r, m) in rows.iter().zip(methods.iter().flat_map(|m| [m, m])) {
        assert_eq!(r.event, "rpc.deny");
        assert_eq!(r.decision.as_deref(), Some("deny"));
        assert_eq!(r.args["method"], json!(m));
        assert_eq!(r.args["reason"], json!("method-not-found"));
    }
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
}

/// RT-AG-13: resources, prompts, sampling, logging, unknown methods, batches and oversize frames
/// are refused with `rpc.deny`; `tools/list` works in both lifecycles (above).
#[tokio::test]
async fn rt_ag_13_mcp_surface_abuse_is_refused_and_audited() {
    let (agent, fake, sink) = setup();
    let mut c = start(&agent);
    let refused = [
        "resources/list",
        "resources/read",
        "resources/subscribe",
        "prompts/list",
        "prompts/get",
        "sampling/createMessage",
        "elicitation/create",
        "roots/list",
        "logging/setLevel",
        "completion/complete",
        "subscriptions/listen",
        "tasks/get",
        "x/unknown",
    ];
    for (i, m) in (0..).zip(refused) {
        let e = c.call(&req(i, m, json!({}))).await;
        assert_eq!(e["error"]["code"], json!(-32601), "{m}");
        assert_eq!(e["error"]["data"]["reason"], json!("method-not-found"));
    }
    // ping is gone in 2026.
    let e = c.call(&req(50, "ping", json!({}))).await;
    assert_eq!(e["error"]["data"]["reason"], json!("wrong-lifecycle"));
    // A batch: refused with a null id, nothing inside it runs.
    let batch = json!([call(60, "echo"), req(61, "tools/list", json!({}))]);
    let e = c.call(&batch).await;
    assert_eq!(
        (e["id"].clone(), e["error"]["code"].clone()),
        (Value::Null, json!(-32600))
    );
    // Malformed frames.
    for (raw, reason) in [
        (&b"{"[..], "parse-error"),
        (b"\"x\"", "not-object"),
        (
            br#"{"jsonrpc":"2.0","id":null,"method":"tools/list"}"#,
            "bad-id",
        ),
    ] {
        c.raw(raw).await;
        let e = c.recv().await.unwrap();
        assert_eq!(e["error"]["data"]["reason"], json!(reason));
    }
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
    let mut expected = vec!["method-not-found"; refused.len()];
    expected.extend([
        "wrong-lifecycle",
        "batch",
        "parse-error",
        "not-object",
        "bad-id",
    ]);
    assert_eq!(denies(&sink), expected);
    // A 1 MiB frame: recorded, answered with a null id, and the connection closed.
    let mut big = vec![b'a'; 1024 * 1024];
    big[0] = b'"';
    let _ = c.w.write_all(&big).await;
    let e = c.recv().await.unwrap();
    assert_eq!(e["error"]["data"]["reason"], json!("frame-too-large"));
    assert_eq!(c.recv().await, None);
    assert_eq!(denies(&sink).last().unwrap(), "frame-too-large");
}

#[tokio::test]
async fn a_frame_of_exactly_the_limit_is_read() {
    let (agent, _, sink) = setup();
    let mut c = start(&agent);
    let mut v = serde_json::to_vec(&req(1, "tools/list", json!({}))).unwrap();
    // Pad with whitespace inside the object up to exactly MAX_FRAME.
    let pad = MAX_FRAME - v.len();
    v.splice(1..1, std::iter::repeat_n(b' ', pad));
    assert_eq!(v.len(), MAX_FRAME);
    c.raw(&v).await;
    assert!(c.recv().await.unwrap().get("result").is_some());
    v.insert(1, b' ');
    c.raw(&v).await;
    let e = c.recv().await.unwrap();
    assert_eq!(e["error"]["data"]["reason"], json!("frame-too-large"));
    assert_eq!(sink.events(), ["rpc.request", "rpc.deny"]);
}

#[tokio::test]
async fn responses_and_unknown_notifications_get_no_reply() {
    let (agent, _, sink) = setup();
    let mut c = start(&agent);
    c.send(&json!({"jsonrpc": "2.0", "id": 9, "result": {}}))
        .await;
    c.send(&json!({"jsonrpc": "2.0", "method": "notifications/roots/list_changed"}))
        .await;
    c.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
        .await;
    c.send(&json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {}}))
        .await;
    assert!(c.quiet().await, "a notification or response was answered");
    assert_eq!(
        denies(&sink),
        [
            "unexpected-response",
            "method-not-found",
            "wrong-lifecycle",
            "bad-params"
        ]
    );
}

#[tokio::test]
async fn a_cancel_suppresses_the_reply_but_never_stops_the_handler() {
    let (agent, fake, sink) = setup();
    let mut c = start(&agent);
    c.send(&call(7, "block")).await;
    reach(&fake.calls, 1).await;
    c.send(
        &json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 7}}),
    )
    .await;
    // Cancels for unknown or finished ids are ignored.
    c.send(&json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 99}}))
        .await;
    // The cancel was recorded; the slot is still held while the handler runs.
    let p = c.call(&req(8, "tools/list", json!({}))).await;
    assert!(p.get("result").is_some());
    assert_eq!(sink.last("rpc.cancel"), json!({"id": 7}));
    assert_eq!(
        sink.events().iter().filter(|e| *e == "rpc.cancel").count(),
        1
    );
    assert_eq!(agent.in_flight.available_permits(), MAX_IN_FLIGHT - 1);
    assert_eq!(fake.done.load(Ordering::SeqCst), 0);
    // The handler was told, by the broker's call number, after the entry (#54).
    assert_eq!(
        fake.withdrawn.lock().unwrap().as_slice(),
        [(101, Withdraw::Cancel)]
    );
    fake.release.notify_one();
    // The handler ran to its end; its reply never comes; the slot comes back only now.
    reach(&fake.done, 1).await;
    assert!(c.quiet().await, "a cancelled call was answered");
    assert_eq!(agent.in_flight.available_permits(), MAX_IN_FLIGHT);
    // The id is free again.
    let r = c.call(&call(7, "echo")).await;
    assert_eq!(r["id"], json!(7));
}

#[tokio::test]
async fn a_closed_connection_still_lets_its_calls_finish() {
    let (agent, fake, _) = setup();
    let mut c = start(&agent);
    c.send(&call(1, "block")).await;
    reach(&fake.calls, 1).await;
    c.w.shutdown().await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !c.server.is_finished(),
        "the connection ended before its call"
    );
    // Its prompt, if any, is withdrawn: nobody is left to receive the result.
    assert_eq!(
        fake.withdrawn.lock().unwrap().as_slice(),
        [(101, Withdraw::Closed)]
    );
    fake.release.notify_one();
    tokio::time::timeout(Duration::from_secs(5), c.server)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fake.done.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_closed_connection_withdraws_only_its_unfinished_calls() {
    let (agent, fake, _) = setup();
    let mut c = start(&agent);
    let _ = c.call(&call(1, "echo")).await;
    c.w.shutdown().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), c.server)
        .await
        .unwrap()
        .unwrap();
    assert!(fake.withdrawn.lock().unwrap().is_empty());
    // A second cancel of the same call is not passed on twice.
    let mut c = start(&agent);
    c.send(&call(2, "block")).await;
    reach(&fake.calls, 2).await;
    let cancel =
        json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 2}});
    c.send(&cancel).await;
    c.send(&cancel).await;
    let _ = c.call(&req(3, "tools/list", json!({}))).await;
    assert_eq!(
        fake.withdrawn.lock().unwrap().as_slice(),
        [(103, Withdraw::Cancel)]
    );
    fake.release.notify_one();
}

#[tokio::test]
async fn each_call_begins_once_and_runs_under_the_number_it_was_given() {
    let (agent, fake, _) = setup();
    let mut a = start(&agent);
    let mut b = start(&agent);
    // The same JSON-RPC id on two connections is two calls with two numbers (ruling Q19).
    let _ = a.call(&call(1, "echo")).await;
    let _ = b.call(&call(1, "echo")).await;
    let _ = a.call(&call(1, "echo")).await;
    assert_eq!(fake.numbers.lock().unwrap().as_slice(), [101, 103, 105]);
    // A refused call (a reused in-flight id) never begins.
    a.send(&call(9, "block")).await;
    reach(&fake.calls, 4).await;
    let dup = a.call(&call(9, "echo")).await;
    assert_eq!(dup["error"]["code"], json!(INVALID_REQUEST));
    assert_eq!(fake.begun.load(Ordering::SeqCst), 4);
    fake.release.notify_one();
}

#[tokio::test]
async fn a_call_whose_handler_could_not_write_an_entry_gets_no_reply() {
    let (agent, fake, _) = setup();
    let mut c = start(&agent);
    c.send(&call(1, "unrecorded")).await;
    reach(&fake.done, 1).await;
    assert!(c.quiet().await, "an unrecorded call was answered");
    // The connection and the slot are fine.
    let r = c.call(&call(2, "echo")).await;
    assert_eq!(r["id"], json!(2));
    assert_eq!(agent.in_flight.available_permits(), MAX_IN_FLIGHT);
}

#[tokio::test]
async fn a_reused_in_flight_id_is_refused() {
    let (agent, fake, sink) = setup();
    let mut c = start(&agent);
    c.send(&call(5, "block")).await;
    let e = c.call(&call(5, "echo")).await;
    assert_eq!(
        (e["id"].clone(), e["error"]["code"].clone()),
        (json!(5), json!(-32600))
    );
    let e = c.call(&req(5, "tools/list", json!({}))).await;
    assert_eq!(e["error"]["data"]["reason"], json!("duplicate-id"));
    assert_eq!(denies(&sink), ["duplicate-id", "duplicate-id"]);
    fake.release.notify_one();
    assert_eq!(c.recv().await.unwrap()["id"], json!(5));
    assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn in_flight_calls_are_capped_per_session() {
    let (agent, fake, sink) = setup();
    let mut a = start(&agent);
    let mut b = start(&agent);
    for i in 0..MAX_IN_FLIGHT as i64 / 2 {
        a.send(&call(i, "block")).await;
        b.send(&call(i, "block")).await;
    }
    reach(&fake.calls, MAX_IN_FLIGHT).await;
    // The 17th, on either connection, is refused before it is dispatched.
    let e = b.call(&call(100, "echo")).await;
    assert_eq!(e["error"]["code"], json!(SERVER_LIMIT));
    assert_eq!(e["error"]["data"]["reason"], json!("too-many-in-flight"));
    assert_eq!(fake.calls.load(Ordering::SeqCst), MAX_IN_FLIGHT);
    assert_eq!(denies(&sink), ["too-many-in-flight"]);
    // One returns, on whichever connection sent it; its slot is freed before its reply is
    // queued, so one more call may run once the reply is in.
    fake.release.notify_one();
    let reply = tokio::select! {
        r = a.recv() => r,
        r = b.recv() => r,
    };
    let reply = reply.expect("the finished call was not answered");
    assert_eq!(reply["result"]["content"][0]["text"], json!("ran block"));
    assert_eq!(fake.done.load(Ordering::SeqCst), 1);
    let r = a.call(&call(200, "echo")).await;
    assert_eq!(r["result"]["content"][0]["text"], json!("ran echo"));
    for _ in 0..MAX_IN_FLIGHT {
        fake.release.notify_one();
    }
}

#[tokio::test]
async fn a_failed_append_means_no_dispatch_and_no_reply() {
    let (agent, fake, sink) = setup();
    let mut c = start(&agent);
    sink.set_failing(true);
    c.send(&call(1, "echo")).await;
    assert_eq!(
        c.recv().await,
        None,
        "the connection must close without a reply"
    );
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
    for msg in [
        req(1, "tools/list", json!({})),
        req(2, "secrets.set", json!({})),
    ] {
        let mut c = start(&agent);
        c.send(&msg).await;
        assert_eq!(c.recv().await, None, "{msg}");
    }
    // A refused frame with a failed append closes without the error reply too.
    let mut c = start(&agent);
    c.raw(b"{").await;
    assert_eq!(c.recv().await, None);
}

/// RT-AUD-02 (rewritten, ruling Q4/Q8): a flood of denied requests is slowed, not dropped: the
/// server reads at most BURST frames at once and RATE per second after, so the audit log of one
/// session grows by at most that, and every refusal still has its entry before its reply.
#[tokio::test(start_paused = true)]
async fn rt_aud_02_a_request_flood_is_read_at_the_session_rate() {
    let (agent, _, sink) = setup();
    let mut c = start(&agent);
    let started = tokio::time::Instant::now();
    let n = 100;
    for i in 0..n {
        c.send(&req(i, "audit.note", json!({"text": "x".repeat(4096)})))
            .await;
    }
    for i in 0..n {
        let e = c.recv().await.unwrap();
        assert_eq!(e["id"], json!(i));
        let elapsed = started.elapsed().as_secs_f64();
        let bound = f64::from(BURST) + f64::from(RATE) * elapsed;
        assert!(
            (sink.rows().len() as f64) <= bound + 1e-9,
            "audit grew past the bound"
        );
    }
    // (n − BURST) frames at RATE per second.
    let expect = Duration::from_secs((n as u64 - u64::from(BURST)) / u64::from(RATE));
    let took = started.elapsed();
    assert!(
        took >= expect && took < expect + Duration::from_millis(100),
        "{took:?}"
    );
    assert_eq!(
        denies(&sink).len(),
        n as usize,
        "every refusal has its own entry"
    );
}

#[tokio::test(start_paused = true)]
async fn the_rate_is_shared_by_a_sessions_connections() {
    let (agent, _, _) = setup();
    let mut a = start(&agent);
    let mut b = start(&agent);
    let started = tokio::time::Instant::now();
    for i in 0..i64::from(BURST) {
        a.send(&req(i, "tools/list", json!({}))).await;
        a.recv().await.unwrap();
    }
    assert_eq!(started.elapsed(), Duration::ZERO);
    // The burst is spent: the other connection waits too.
    b.call(&req(1, "tools/list", json!({}))).await;
    let waited = started.elapsed();
    assert!(waited >= Duration::from_secs(1) / RATE, "{waited:?}");
}

/// RT-AG-08 (foreign-id clause, ruling Q4): each session's server serves only that session. A
/// request on A's socket naming B's session id, in params, `_meta` or an extra member, reaches
/// only A's handler, and every entry carries A's id. Nothing here routes by session id, so the
/// controls this pins are the envelope's member check (message 3), `tools/call`'s parameter
/// check (message 2) and the recorder's session stamping; B's server is built but not served.
/// The same requests through the session registry with B live: `tests/session.rs`.
#[tokio::test]
async fn rt_ag_08_a_foreign_session_id_reaches_only_its_own_session() {
    let (sink, rec_a) = recorder("sess-a");
    let rec_b = Recorder::new(
        Arc::clone(&sink) as Arc<dyn crate::sandbox::AuditSink>,
        "sess-b".into(),
        sally_core::manifest::AuditLevel::Full,
    );
    let (fa, fb) = (Arc::new(Fake::default()), Arc::new(Fake::default()));
    let a = Arc::new(Agent::new(Arc::clone(&fa), rec_a));
    let _b = Arc::new(Agent::new(Arc::clone(&fb), rec_b));
    let mut c = start(&a);
    let mut m = meta();
    m["session"] = json!("sess-b");
    m["io.modelcontextprotocol/sessionId"] = json!("sess-b");
    let msgs = [
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
               "params": {"_meta": m, "name": "echo", "arguments": {"session": "sess-b"}}}),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
               "params": {"_meta": meta(), "name": "echo", "session": "sess-b"}}),
        json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "session": "sess-b",
               "params": {"_meta": meta(), "name": "echo"}}),
    ];
    for msg in &msgs {
        c.call(msg).await;
    }
    assert_eq!(
        fa.calls.load(Ordering::SeqCst),
        1,
        "only the first is a valid call"
    );
    assert_eq!(fb.calls.load(Ordering::SeqCst), 0);
    let rows = sink.rows();
    assert_eq!(rows.len(), 3);
    assert!(
        rows.iter()
            .all(|r| r.debug.contains("session: Some(\"sess-a\")"))
    );
    assert!(!rows.iter().any(|r| r.debug.contains("Some(\"sess-b\")")));
}

#[tokio::test]
async fn the_server_stop_ends_a_live_connection() {
    let (agent, _, _) = setup();
    let c = start(&agent);
    tokio::task::yield_now().await;
    Server::stop(&*agent);
    tokio::time::timeout(Duration::from_secs(5), c.server)
        .await
        .expect("stop left the connection open")
        .unwrap();
}

#[tokio::test]
async fn stop_ends_the_connection() {
    let (agent, _, _) = setup();
    let mut c = start(&agent);
    c.call(&req(1, "tools/list", json!({}))).await;
    agent.stop.send_replace(true);
    assert_eq!(c.recv().await, None);
}

#[tokio::test]
async fn a_peer_with_another_uid_is_refused_and_recorded() {
    let dir = std::env::temp_dir().join(format!("sp-agent-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("agent.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let (agent, fake, sink) = setup();
    let me = rustix::process::getuid().as_raw();
    let (crash, _crashes) = crate::rpc::listen::CrashReporter::channel();
    let h = Arc::clone(&agent).listen(listener, me.wrapping_add(1), crash);
    let mut s = UnixStream::connect(&path).await.unwrap();
    let msg = serde_json::to_vec(&call(1, "echo")).unwrap();
    let _ = s.write_all(&msg).await;
    let _ = s.write_all(b"\n").await;
    let mut buf = Vec::new();
    let n = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::io::AsyncReadExt::read_to_end(&mut s, &mut buf),
    )
    .await
    .unwrap()
    .unwrap_or(0);
    assert_eq!(n, 0, "a refused peer got bytes back");
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
    assert_eq!(sink.events(), ["rpc.deny"]);
    assert_eq!(
        sink.last("rpc.deny"),
        json!({"reason": "peer-uid", "uid": me})
    );
    h.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Architect ruling Q16: the request entry names the tool and the arguments' shape, never their
/// values, so a large body neither lands in the log nor hides the tool behind the writer's
/// truncation.
#[tokio::test]
async fn a_large_call_is_recorded_without_its_values() {
    let (agent, fake, sink) = setup();
    let mut c = start(&agent);
    let secret_ish = "v".repeat(8 * 1024);
    let r = c
        .call(&req(
            1,
            "tools/call",
            json!({"name": "echo", "arguments": {"path": "a.md", "content_b64": secret_ish}}),
        ))
        .await;
    assert!(r.get("result").is_some(), "{r}");
    assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
    let args = sink.last("rpc.request");
    assert_eq!(args["tool"], json!("echo"));
    assert_eq!(args["argument_count"], json!(2));
    assert_eq!(args["argument_keys"], json!(["content_b64", "path"]));
    assert!(args["arguments_bytes"].as_u64().unwrap() > 8 * 1024);
    assert!(!args.to_string().contains("vvvv"), "a value was logged");
}

/// Architect ruling Q16, the worst case: keys, id and tool name made of bytes that escape to
/// `\xNN` each, and more keys than are named. The entry stays under the writer's cap with room
/// for redaction to lengthen it, so the tool name is never truncated away.
#[tokio::test]
async fn the_worst_case_call_entry_stays_under_the_writer_cap() {
    let (agent, _, sink) = setup();
    let mut c = start(&agent);
    // The longer lifecycle name.
    c.call(&bare(
        0,
        "initialize",
        json!({"protocolVersion": "2025-11-25", "capabilities": {}}),
    ))
    .await;
    // Each named key: 64 shown bytes that escape to `\xNN`, then filler for the longest
    // `…(+N)` tails one frame allows (two of six digits, the rest of five and four). They sort
    // first; the unnamed extra keys sort after them.
    let shown = "\u{1}".repeat(crate::rpc::record::LOGGED_BYTES);
    let mut arguments = Map::new();
    for (i, filler) in [
        100_000, 100_000, 10_000, 10_000, 10_000, 10_000, 10_000, 1_000,
    ]
    .into_iter()
    .enumerate()
    {
        let tag = char::from(b'a' + u8::try_from(i).unwrap());
        arguments.insert(format!("{shown}{tag}{}", "f".repeat(filler)), json!(1));
    }
    for i in 0..4 {
        arguments.insert(format!("z{i}"), json!(1));
    }
    let id = "\u{1}".repeat(crate::rpc::message::MAX_ID_BYTES);
    let name = "\u{1}".repeat(crate::rpc::mcp::MAX_TOOL_NAME);
    let msg = json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
                     "params": {"name": name, "arguments": arguments}});
    assert!(serde_json::to_vec(&msg).unwrap().len() < MAX_FRAME);
    let r = c.call(&msg).await;
    assert!(r.get("result").is_some(), "{r}");
    let args = sink.last("rpc.request");
    assert_eq!(args["argument_keys"].as_array().unwrap().len(), LOGGED_KEYS);
    assert_eq!(args["argument_count"], json!(LOGGED_KEYS + 4));
    assert_eq!(args["lifecycle"], json!("legacy"));
    assert!(args["tool"].as_str().unwrap().starts_with("\\x01"));
    assert!(
        args["argument_keys"][0]
            .as_str()
            .unwrap()
            .ends_with("…(+100001)")
    );
    let size = serde_json::to_vec(&args).unwrap().len();
    assert!(
        size <= sally_core::audit::MAX_ARGS_BYTES - 512,
        "{size} bytes"
    );
}

/// Architect ruling Q17: session teardown drops in-flight calls. A dropped handle aborts a
/// blocked call at once and frees its slot; an orderly shutdown waits STOP_GRACE first.
#[tokio::test(start_paused = true)]
async fn session_teardown_drops_in_flight_calls() {
    let dir = std::env::temp_dir().join(format!("sp-agent-down-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    let me = rustix::process::getuid().as_raw();
    for orderly in [false, true] {
        let path = dir.join(format!("agent-{orderly}.sock"));
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let (agent, fake, _) = setup();
        let (crash, _crashes) = crate::rpc::listen::CrashReporter::channel();
        let h = Arc::clone(&agent).listen(listener, me, crash);
        let mut s = UnixStream::connect(&path).await.unwrap();
        let mut msg = serde_json::to_vec(&call(1, "block")).unwrap();
        msg.push(b'\n');
        s.write_all(&msg).await.unwrap();
        reach(&fake.calls, 1).await;
        assert_eq!(agent.in_flight.available_permits(), MAX_IN_FLIGHT - 1);
        if orderly {
            let down = tokio::spawn(h.shutdown());
            tokio::time::sleep(listen::STOP_GRACE - Duration::from_millis(100)).await;
            assert_eq!(
                fake.ended.load(Ordering::SeqCst),
                0,
                "dropped before the grace"
            );
            down.await.unwrap();
        } else {
            drop(h);
            tokio::task::yield_now().await;
        }
        // The abort is synchronous for the task tree, but give it a turn to unwind.
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert_eq!(fake.ended.load(Ordering::SeqCst), 1, "orderly: {orderly}");
        assert_eq!(fake.done.load(Ordering::SeqCst), 0, "orderly: {orderly}");
        assert_eq!(agent.in_flight.available_permits(), MAX_IN_FLIGHT);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn replies_are_single_lines() {
    let l = success(&Id::Str("a\nb".into()), json!({"t": "x\ny"}));
    assert_eq!(l.iter().filter(|&&b| b == b'\n').count(), 1);
    assert_eq!(l.last(), Some(&b'\n'));
    let f = failure(None, error_object(-32700, "parse-error"));
    assert_eq!(
        serde_json::from_slice::<Value>(&f).unwrap(),
        json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": "Parse error", "data": {"reason": "parse-error"}}})
    );
}

#[test]
fn error_messages_follow_their_codes() {
    for (code, m) in [
        (-32700, "Parse error"),
        (-32600, "Invalid Request"),
        (-32601, "Method not found"),
        (-32602, "Invalid params"),
        (-32603, "Internal error"),
        (-32000, "Server error"),
    ] {
        assert_eq!(error_object(code, "r")["message"], json!(m));
    }
}

#[test]
fn logged_ids_are_escaped() {
    assert_eq!(logged_id(&Id::Num(-3)), json!(-3));
    assert_eq!(logged_id(&Id::Str("a\u{1b}".into())), json!("a\\x1b"));
}
