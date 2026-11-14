#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex as StdMutex;
use std::time::Duration;

use sally_core::manifest::{FetchWrites, ShellPolicy, ValidatedManifest};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, DuplexStream, ReadHalf, WriteHalf, split};

use super::*;
use crate::approvals::action::{Action, Bound};
use crate::approvals::policy::Policy;
use crate::approvals::render::{ACTION_CHARS, FULL_WIRE_BYTES, NOTE_CHARS, Prompt};
use crate::approvals::{Approver, Desk, Gate, Limits};
use crate::rpc::control_methods::{
    DETAIL_CHARS, ID_CHARS, MAX_ERROR_LINES, REPLY_BYTES, error_lines, fit,
};
use crate::rpc::testkit::{Row, Sink, recorder};
use crate::sandbox::LaunchError;
use crate::session::{SessionInfo, SessionState, StartError, StopOutcome};

const PEER: Peer = Peer {
    uid: 1000,
    pid: 4242,
};

/// The sessions, as the control socket sees them: set by each test.
#[derive(Default)]
struct Fake {
    live: StdMutex<Vec<(SessionInfo, Option<Desk>)>>,
    started: StdMutex<Vec<String>>,
    start_err: StdMutex<Option<StartError>>,
    /// What a stop of a listed session answers (`None`: stopped).
    stop_fails: StdMutex<Option<String>>,
    stopped: StdMutex<Vec<String>>,
}

fn info(id: &str) -> SessionInfo {
    SessionInfo {
        id: id.to_owned(),
        manifest: "t".to_owned(),
        container: format!("sp-w-{id}"),
        state: SessionState::Running,
    }
}

impl SessionSet for Arc<Fake> {
    fn list(&self) -> Vec<SessionInfo> {
        self.live
            .lock()
            .unwrap()
            .iter()
            .map(|(i, _)| i.clone())
            .collect()
    }

    fn desk(&self, id: &str) -> Option<Desk> {
        let live = self.live.lock().unwrap();
        live.iter()
            .find(|(i, _)| i.id == id)
            .and_then(|(_, d)| d.clone())
    }

    fn start(
        &self,
        manifest: Arc<ValidatedManifest>,
    ) -> impl Future<Output = Result<SessionInfo, StartError>> + Send {
        let r = match self.start_err.lock().unwrap().take() {
            Some(e) => Err(e),
            None => {
                let name = manifest.manifest().name.clone();
                self.started.lock().unwrap().push(name);
                Ok(info("s-new"))
            }
        };
        async move { r }
    }

    fn stop(&self, id: &str) -> impl Future<Output = Option<StopOutcome>> + Send {
        let known = self.live.lock().unwrap().iter().any(|(i, _)| i.id == id);
        let r = known.then(|| {
            self.stopped.lock().unwrap().push(id.to_owned());
            match self.stop_fails.lock().unwrap().clone() {
                Some(why) => StopOutcome::Failed(why),
                None => StopOutcome::Stopped,
            }
        });
        async move { r }
    }
}

/// A scratch directory under target/ (the denylist refuses `/tmp` for mounts).
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let p = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/control-unit")
            .join(format!("{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Fx {
    control: Arc<Control<Arc<Fake>>>,
    fake: Arc<Fake>,
    sink: Arc<Sink>,
    hub: Arc<Hub>,
    scratch: Scratch,
    /// The gates of the sessions' desks, kept alive.
    gates: StdMutex<Vec<Gate>>,
}

fn env() -> HostEnv {
    HostEnv {
        home: "/nonexistent/home".into(),
        other_homes: Vec::new(),
        xdg_config_home: None,
        xdg_data_home: None,
        xdg_runtime_dir: None,
        podman_storage: Vec::new(),
        nproc: 8,
        mem_bytes: 16 << 30,
    }
}

fn fx(tag: &str) -> Fx {
    fx_with(tag, BTreeSet::new())
}

fn fx_with(tag: &str, catalog: BTreeSet<String>) -> Fx {
    let scratch = Scratch::new(tag);
    let sessions_dir = crate::sandbox::open_sessions(&scratch.0.join("state")).unwrap();
    let (sink, record) = recorder("");
    let fake = Arc::new(Fake::default());
    let hub = Arc::new(Hub::default());
    let control = Arc::new(Control::new(ControlParts {
        record,
        sessions: Arc::clone(&fake),
        hub: Arc::clone(&hub),
        sessions_dir: Arc::new(sessions_dir),
        env: Arc::new(env()),
        catalog: Arc::new(catalog),
    }));
    Fx {
        control,
        fake,
        sink,
        hub,
        scratch,
        gates: StdMutex::new(Vec::new()),
    }
}

/// A socket path short enough for `SUN_LEN` (target/ is too deep), removed with the guard.
struct SockDir(PathBuf);

impl SockDir {
    fn new(tag: &str) -> Self {
        let d = std::env::temp_dir().join(format!("sp-ctl-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir(&d).unwrap();
        Self(d)
    }
}

impl Drop for SockDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl Fx {
    fn sessions(&self) -> PathBuf {
        self.scratch.0.join("state/sessions")
    }

    /// Adds live session `id` whose shell calls need approval, its prompts going to the hub.
    fn session(&self, id: &str) -> Arc<Sink> {
        let (sink, rec) = recorder(id);
        let policy = Policy {
            builtin: vec![sally_core::manifest::BuiltinTool::Shell],
            shell: ShellPolicy::Approve,
            destructive_requires_approval: true,
            fetch_writes: FetchWrites::Approve,
            mounts: vec![],
            mcp: vec![],
        };
        let limits = Limits {
            timeout: Duration::from_secs(300),
            max_pending: 5,
        };
        let approver = Arc::clone(&self.hub) as Arc<dyn Approver>;
        let (gate, desk) =
            crate::approvals::new(id.to_owned(), policy, limits, rec, Some(approver));
        self.gates.lock().unwrap().push(gate);
        self.fake.live.lock().unwrap().push((info(id), Some(desk)));
        sink
    }

    /// Asks for `argv` in session `id` (its gate) in a task of its own.
    fn ask(
        &self,
        id: &str,
        call: u64,
        argv: &[&str],
    ) -> tokio::task::JoinHandle<Result<crate::approvals::Ticket, crate::approvals::Refusal>> {
        let gates = self.gates.lock().unwrap();
        let gate = gates.iter().find(|g| g.session() == id).unwrap().clone();
        let bound = Bound {
            session: id.to_owned(),
            call,
            action: Action::Shell {
                argv: argv.iter().map(|s| (*s).to_owned()).collect(),
                cwd: "/workspace".to_owned(),
            },
        };
        tokio::spawn(async move { gate.admit(bound, None, None).await })
    }

    fn connect(&self) -> Wire {
        let (client, server) = tokio::io::duplex(4 * MAX_FRAME);
        let task = tokio::spawn(Arc::clone(&self.control).serve_stream(server, PEER));
        let (r, w) = split(client);
        Wire {
            r: BufReader::new(r),
            w,
            next: 1,
            task,
        }
    }

    fn rows(&self) -> Vec<Row> {
        self.sink.rows()
    }

    fn events(&self) -> Vec<String> {
        self.sink.events()
    }
}

/// One client connection.
struct Wire {
    r: BufReader<ReadHalf<DuplexStream>>,
    w: WriteHalf<DuplexStream>,
    next: i64,
    task: tokio::task::JoinHandle<()>,
}

impl Wire {
    async fn send(&mut self, method: &str, params: Value) {
        let id = self.next;
        self.next += 1;
        let req = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        self.w.write_all(&line(&req)).await.unwrap();
    }

    /// The next frame, `None` at the end of the stream.
    async fn frame(&mut self) -> Option<Value> {
        let mut l = String::new();
        let n = tokio::time::timeout(Duration::from_secs(30), self.r.read_line(&mut l))
            .await
            .expect("no frame")
            .unwrap();
        (n > 0).then(|| serde_json::from_str(&l).unwrap())
    }

    async fn call(&mut self, method: &str, params: Value) -> Value {
        self.send(method, params).await;
        self.frame().await.expect("the connection closed")
    }

    /// The reply to `method`, past any notifications.
    async fn reply(&mut self, method: &str, params: Value) -> Value {
        self.send(method, params).await;
        loop {
            let f = self.frame().await.expect("the connection closed");
            if f.get("id").is_some() {
                return f;
            }
        }
    }

    async fn ended(mut self) {
        assert_eq!(self.frame().await, None, "the connection is still open");
        self.task.await.unwrap();
    }
}

fn reason(reply: &Value) -> &str {
    reply["error"]["data"]["reason"].as_str().unwrap()
}

const CLIENT: &str = r#"{"uid":1000,"pid":4242}"#;

fn client() -> Value {
    serde_json::from_str(CLIENT).unwrap()
}

const MANIFEST: &str = "apiVersion: sallyport/v1\nkind: Manifest\nname: t\nmodel:\n  ref: any\n";

async fn exchange(lines: &[&[u8]]) -> (Vec<Value>, Vec<Row>) {
    let f = fx("exchange");
    let (client, server) = tokio::io::duplex(4 * MAX_FRAME);
    let task = tokio::spawn(Arc::clone(&f.control).serve_stream(server, PEER));
    let (r, mut w) = split(client);
    for l in lines {
        w.write_all(l).await.unwrap();
        w.write_all(b"\n").await.unwrap();
    }
    w.shutdown().await.unwrap();
    let mut replies = Vec::new();
    let mut r = BufReader::new(r);
    let mut l = String::new();
    while r.read_line(&mut l).await.unwrap() > 0 {
        replies.push(serde_json::from_str(&l).unwrap());
        l.clear();
    }
    task.await.unwrap();
    (replies, f.rows())
}

/// Architect Q72: exactly these seven, in this order, and the CLI's names are the same ones.
#[test]
fn the_control_table_is_exactly_the_seven_methods() {
    assert_eq!(
        CONTROL_METHODS,
        [
            "sessions.create",
            "sessions.list",
            "sessions.stop",
            "sessions.changes",
            "approvals.list",
            "approvals.decide",
            "approvals.watch",
        ]
    );
    assert_eq!(CONTROL_METHODS, sally_proto::method::ALL);
}

#[test]
fn frames_are_capped_at_1_mib() {
    assert_eq!(MAX_FRAME, 1_048_576);
    // A refusal's code is JSON-RPC's first implementation-defined server error.
    assert_eq!(REFUSED, -32_000);
}

/// Every method parses with its own params, names itself, and only the three reads are rated.
#[test]
fn every_method_parses_names_itself_and_only_reads_are_rated() {
    let params = [
        json!({"manifest": MANIFEST}),
        json!({}),
        json!({"id": "s-1"}),
        json!({"id": "s-1"}),
        json!({}),
        json!({"id": "a", "decision": "deny", "digest": "d"}),
        json!({}),
    ];
    let mut rated = Vec::new();
    let mut rated_watching = Vec::new();
    for (m, p) in CONTROL_METHODS.iter().zip(params) {
        let Value::Object(p) = p else { unreachable!() };
        let call = Call::parse(m, p).unwrap();
        assert_eq!(call.method(), *m);
        if call.rated(false) {
            rated.push(*m);
        }
        if call.rated(true) {
            rated_watching.push(*m);
        }
    }
    assert_eq!(
        rated,
        ["sessions.list", "sessions.changes", "approvals.list"]
    );
    // Architect Q94: on a connection that already watches, a watch is a re-list.
    assert_eq!(
        rated_watching,
        [
            "sessions.list",
            "sessions.changes",
            "approvals.list",
            "approvals.watch"
        ]
    );
    assert_eq!(
        Call::parse("secrets.set", Map::new()).unwrap_err(),
        NotAdmitted::MethodNotFound
    );
}

/// Architect Q71, Q95: the create's request entry has the manifest's size and hash, never its
/// text; a stop or a listing adds the session id; no other call adds anything.
#[test]
fn only_a_create_records_the_manifest_size_and_hash() {
    let Value::Object(p) = json!({"manifest": "abc"}) else {
        unreachable!()
    };
    let args = Call::parse("sessions.create", p).unwrap().request_args();
    assert_eq!(
        Value::Object(args),
        json!({
            "manifest_bytes": 3,
            "manifest_sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        })
    );
    for m in ["sessions.list", "approvals.list", "approvals.watch"] {
        let c = Call::parse(m, Map::new()).unwrap();
        assert!(c.request_args().is_empty(), "{m}");
    }
    let Value::Object(d) = json!({"id": "ap-1", "decision": "deny", "digest": "d"}) else {
        unreachable!()
    };
    let decide = Call::parse("approvals.decide", d).unwrap();
    assert!(decide.request_args().is_empty());
    // Architect Q95: a stop and a listing name their (parsed, canonical) session.
    for m in ["sessions.stop", "sessions.changes"] {
        let Value::Object(p) = json!({"id": "s-1"}) else {
            unreachable!()
        };
        let args = Call::parse(m, p).unwrap().request_args();
        assert_eq!(Value::Object(args), json!({"id": "s-1"}), "{m}");
    }
}

#[tokio::test]
async fn stop_ends_a_live_connection() {
    let f = fx("stop");
    let wire = f.connect();
    tokio::task::yield_now().await;
    Server::stop(&*f.control);
    tokio::time::timeout(Duration::from_secs(5), wire.ended())
        .await
        .expect("stop left the connection open");
}

#[tokio::test]
async fn a_peer_with_another_uid_is_refused_and_recorded() {
    let f = fx("peer");
    let dir = SockDir::new("peer");
    let path = dir.0.join("control.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let me = rustix::process::getuid().as_raw();
    let (crash, _crashes) = crate::rpc::listen::CrashReporter::channel();
    let h = crate::rpc::listen::spawn(
        listener,
        Arc::clone(&f.control),
        1,
        me.wrapping_add(1),
        "control.sock",
        crash,
    );
    let mut s = UnixStream::connect(&path).await.unwrap();
    let _ = s.write_all(b"{}\n").await;
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out)).await;
    assert!(out.is_empty());
    assert_eq!(
        f.sink.last("rpc.deny"),
        json!({"socket": "control", "reason": "peer-uid", "uid": me})
    );
    h.shutdown().await;
}

/// Architect Q76: the client in the entry is the peer from `SO_PEERCRED`, over a real socket.
#[tokio::test]
async fn the_request_entry_names_the_real_peer() {
    let f = fx("real-peer");
    let dir = SockDir::new("real-peer");
    let path = dir.0.join("control.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let me = rustix::process::getuid().as_raw();
    let (crash, _crashes) = crate::rpc::listen::CrashReporter::channel();
    let h = crate::rpc::listen::spawn(
        listener,
        Arc::clone(&f.control),
        1,
        me,
        "control.sock",
        crash,
    );
    let mut s = UnixStream::connect(&path).await.unwrap();
    s.write_all(br#"{"jsonrpc":"2.0","id":1,"method":"sessions.list"}"#)
        .await
        .unwrap();
    s.write_all(b"\n").await.unwrap();
    let mut r = BufReader::new(s);
    let mut l = String::new();
    r.read_line(&mut l).await.unwrap();
    assert_eq!(
        f.sink.last("rpc.request")["client"],
        json!({"uid": me, "pid": std::process::id()})
    );
    h.shutdown().await;
}

#[tokio::test]
async fn other_methods_are_not_found_and_recorded() {
    let (replies, rows) = exchange(&[
        br#"{"jsonrpc":"2.0","id":1,"method":"secrets.set","params":{}}"#,
        br#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        br#"{"jsonrpc":"2.0","method":"sessions.stop"}"#,
        br#"{"jsonrpc":"2.0","id":3,"result":{}}"#,
        b"[1]",
    ])
    .await;
    let codes: Vec<_> = replies
        .iter()
        .map(|r| (r["id"].clone(), r["error"]["code"].clone()))
        .collect();
    assert_eq!(
        codes,
        [
            (json!(1), json!(-32601)),
            (json!(2), json!(-32601)),
            (Value::Null, json!(-32600)),
        ]
    );
    let reasons: Vec<_> = rows
        .iter()
        .map(|r| r.args["reason"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        reasons,
        [
            "method-not-found",
            "method-not-found",
            "method-not-found",
            "unexpected-response",
            "batch"
        ]
    );
    assert!(
        rows.iter()
            .all(|r| r.event == "rpc.deny" && r.args["socket"] == json!("control"))
    );
    assert!(rows.iter().all(|r| r.debug.contains("session: None")));
    assert_eq!(rows[0].args["method"], json!("secrets.set"));
}

#[tokio::test]
async fn frames_up_to_one_mib_are_read() {
    let mut exact = br#"{"jsonrpc":"2.0","id":1,"method":"m"}"#.to_vec();
    exact.splice(1..1, std::iter::repeat_n(b' ', MAX_FRAME - exact.len()));
    let mut over = exact.clone();
    over.insert(1, b' ');
    let (replies, rows) = exchange(&[&exact, &over]).await;
    assert_eq!(reason(&replies[0]), "method-not-found");
    assert_eq!(reason(&replies[1]), "frame-too-large");
    assert_eq!(
        replies.len(),
        2,
        "the connection closes after an oversize frame"
    );
    assert_eq!(rows.len(), 2);
}

/// Strict params (architect Q71, Q76, Q81): an unknown field, a missing one, a malformed id, a
/// `model`/`task` before PR C, a `client` in decide: `invalid-params`, `rpc.deny`, no request
/// entry, no effect.
#[tokio::test]
async fn params_are_strict_and_a_refusal_is_never_admitted() {
    let f = fx("params");
    f.session("s-1");
    let mut w = f.connect();
    let bad = [
        (
            "sessions.create",
            json!({"manifest": MANIFEST, "model": "m"}),
        ),
        (
            "sessions.create",
            json!({"manifest": MANIFEST, "task": "t"}),
        ),
        ("sessions.create", json!({})),
        ("sessions.list", json!({"all": true})),
        ("sessions.stop", json!({"id": "S-1"})),
        ("sessions.stop", json!({"id": "s-1", "force": true})),
        ("sessions.changes", json!({"id": "../s-1"})),
        ("sessions.changes", json!({"id": ""})),
        ("approvals.list", json!({"x": 1})),
        (
            "approvals.decide",
            json!({"id": "a", "decision": "deny", "digest": "d", "client": {"uid": 0}}),
        ),
        (
            "approvals.decide",
            json!({"id": "a", "decision": "allow", "digest": "d"}),
        ),
        ("approvals.watch", json!({"x": 1})),
    ];
    for (m, p) in &bad {
        let r = w.call(m, p.clone()).await;
        assert_eq!(r["error"]["code"], json!(-32602), "{m} {p}");
        assert_eq!(reason(&r), "invalid-params");
    }
    let rows = f.rows();
    assert_eq!(rows.len(), bad.len());
    for (row, (m, _)) in rows.iter().zip(&bad) {
        assert_eq!(row.event, "rpc.deny");
        assert_eq!(
            row.args,
            json!({"socket": "control", "reason": "invalid-params", "method": m})
        );
    }
    assert!(f.fake.started.lock().unwrap().is_empty());
    assert!(f.fake.stopped.lock().unwrap().is_empty());
    assert_eq!(f.hub.count(), 0, "a refused watch attaches nothing");
}

#[tokio::test]
async fn sessions_list_records_the_request_then_lists() {
    let f = fx("list");
    f.session("s-2");
    f.session("s-1");
    let mut w = f.connect();
    let r = w.call("sessions.list", json!({})).await;
    assert_eq!(
        r["result"]["sessions"][1],
        json!({"id": "s-1", "manifest": "t", "container": "sp-w-s-1", "state": "running"})
    );
    let rows = f.rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].event, "rpc.request");
    assert_eq!(rows[0].decision, None);
    assert_eq!(
        rows[0].args,
        json!({"socket": "control", "method": "sessions.list", "client": client()})
    );
    assert!(rows[0].debug.contains("session: None"));
}

/// A request entry that cannot be written: no effect, no reply, the connection closes.
#[tokio::test]
async fn an_unwritten_request_entry_closes_with_no_effect() {
    let f = fx("unwritten");
    f.sink.fail.store(true, std::sync::atomic::Ordering::SeqCst);
    let mut w = f.connect();
    w.send("sessions.create", json!({"manifest": MANIFEST}))
        .await;
    w.ended().await;
    assert!(f.fake.started.lock().unwrap().is_empty());
}

/// Architect Q71: a rejected manifest is exactly [rpc.request, manifest.refuse]; nothing starts;
/// the client is told every error.
#[tokio::test]
async fn an_invalid_manifest_is_refused_and_nothing_starts() {
    let f = fx("invalid");
    let mut w = f.connect();
    let text = "apiVersion: sallyport/v1\nkind: Manifest\nname: t\nmodel:\n  ref: any\nbogus: 1\n";
    let r = w.call("sessions.create", json!({"manifest": text})).await;
    assert_eq!(r["error"]["code"], json!(REFUSED));
    assert_eq!(reason(&r), "manifest-invalid");
    let errors = r["error"]["data"]["errors"].as_array().unwrap();
    assert!(!errors.is_empty());
    assert!(errors[0].as_str().unwrap().contains("bogus"), "{errors:?}");
    assert_eq!(f.events(), ["rpc.request", "manifest.refuse"]);
    let rows = f.rows();
    assert_eq!(rows[0].args["manifest_bytes"], json!(text.len()));
    assert!(rows[0].args.get("manifest").is_none());
    assert_eq!(rows[1].decision.as_deref(), Some("refuse"));
    assert!(rows[1].debug.contains("Sallyd"));
    assert!(
        rows[1].args["error"].as_str().unwrap().contains("bogus"),
        "{:?}",
        rows[1].args
    );
    assert!(f.fake.started.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_valid_manifest_starts_a_session() {
    let f = fx("valid");
    let mut w = f.connect();
    let r = w
        .call("sessions.create", json!({"manifest": MANIFEST}))
        .await;
    assert_eq!(r["result"]["id"], json!("s-new"));
    assert_eq!(r["result"]["state"], json!("running"));
    assert_eq!(*f.fake.started.lock().unwrap(), ["t"]);
    assert_eq!(f.events(), ["rpc.request"]);
}

/// Architect Q87: until #99 no secret name is known, so a grant is refused at validation; a
/// catalog that names it lets the manifest through.
#[tokio::test]
async fn a_secret_grant_needs_the_name_in_the_catalog() {
    let text = format!(
        "{MANIFEST}network:\n  mode: proxy\n  allow:\n    - {{host: api.example.com, ports: [443]}}\nsecrets:\n  - {{name: X_KEY, inject: {{host: api.example.com, header: X-Key, format: \"{{value}}\"}}}}\n"
    );
    let f = fx("secret-none");
    let r = f
        .connect()
        .call("sessions.create", json!({"manifest": text}))
        .await;
    assert_eq!(reason(&r), "manifest-invalid");
    assert_eq!(f.events(), ["rpc.request", "manifest.refuse"]);
    let f = fx_with(
        "secret-named",
        std::iter::once("X_KEY".to_owned()).collect(),
    );
    let r = f
        .connect()
        .call("sessions.create", json!({"manifest": text}))
        .await;
    assert_eq!(r["result"]["id"], json!("s-new"), "{r}");
}

/// Architect Q88 (ii): a launch refusal is told with the launcher's reason and the very detail
/// it audited; the launcher's entry is the only refusal entry.
#[tokio::test]
async fn a_launch_refusal_tells_the_launchers_reason_and_detail() {
    for (e, code) in [
        (LaunchError::NoDefaultImage, "no-default-image"),
        (LaunchError::ImageMissing("img\n".into()), "digest-mismatch"),
    ] {
        let detail = e.detail();
        let f = fx("launch");
        *f.fake.start_err.lock().unwrap() = Some(StartError::Launch(e));
        let r = f
            .connect()
            .call("sessions.create", json!({"manifest": MANIFEST}))
            .await;
        assert_eq!(reason(&r), code);
        assert_eq!(
            r["error"]["data"]["detail"],
            json!(sally_core::text::escape_capped(
                detail.as_bytes(),
                DETAIL_CHARS
            ))
        );
        assert_eq!(f.events(), ["rpc.request"]);
    }
}

/// Architect Q88 (iii): any other start failure gets its own `session.refuse`.
#[tokio::test]
async fn another_start_failure_is_refused_and_recorded() {
    for (e, code) in [
        (StartError::ShuttingDown, "shutting-down"),
        (
            StartError::Id(std::io::Error::other("no entropy")),
            "start-failed",
        ),
    ] {
        let detail = e.to_string();
        let f = fx("start-failed");
        *f.fake.start_err.lock().unwrap() = Some(e);
        let r = f
            .connect()
            .call("sessions.create", json!({"manifest": MANIFEST}))
            .await;
        assert_eq!(reason(&r), code);
        assert_eq!(r["error"]["data"]["detail"], json!(detail));
        assert_eq!(f.events(), ["rpc.request", "session.refuse"]);
        assert_eq!(
            f.sink.last("session.refuse"),
            json!({"method": "sessions.create", "reason": code, "detail": detail, "client": client()})
        );
    }
}

#[tokio::test]
async fn sessions_stop_stops_a_known_session_and_refuses_an_unknown_one() {
    let f = fx("stop-method");
    f.session("s-1");
    let mut w = f.connect();
    let r = w.call("sessions.stop", json!({"id": "s-1"})).await;
    assert_eq!(r["result"], json!({"id": "s-1"}));
    assert_eq!(*f.fake.stopped.lock().unwrap(), ["s-1"]);
    let r = w.call("sessions.stop", json!({"id": "s-9"})).await;
    assert_eq!(reason(&r), "unknown-session");
    assert_eq!(f.events(), ["rpc.request", "rpc.request", "session.refuse"]);
    assert_eq!(
        f.sink.last("session.refuse"),
        json!({"method": "sessions.stop", "id": "s-9", "reason": "unknown-session", "client": client()})
    );
    *f.fake.stop_fails.lock().unwrap() = Some("container\x1b[2J stuck".to_owned());
    let r = w.call("sessions.stop", json!({"id": "s-1"})).await;
    assert_eq!(reason(&r), "stop-failed");
    let detail = "container\\x1b[2J stuck";
    assert_eq!(r["error"]["data"]["detail"], json!(detail));
    // Architect Q95: the failure has its own entry before the reply; the request names the id.
    let rows = f.rows();
    let tail: Vec<_> = rows.iter().rev().take(2).rev().collect();
    assert_eq!(tail[0].event, "rpc.request");
    assert_eq!(tail[0].args["id"], json!("s-1"));
    assert_eq!(tail[1].event, "session.refuse");
    assert_eq!(
        tail[1].args,
        json!({"method": "sessions.stop", "id": "s-1", "reason": "stop-failed",
               "detail": detail, "client": client()})
    );
}

/// Architect Q95: a stop failure whose entry cannot be written gets no reply.
#[tokio::test]
async fn an_unwritten_stop_failure_closes_with_no_reply() {
    let f = fx("stop-unwritten");
    f.session("s-1");
    *f.fake.stop_fails.lock().unwrap() = Some("stuck".to_owned());
    f.sink
        .fail_from
        .store(1, std::sync::atomic::Ordering::SeqCst);
    let mut w = f.connect();
    w.send("sessions.stop", json!({"id": "s-1"})).await;
    w.ended().await;
    assert_eq!(f.events(), ["rpc.request"]);
}

fn lost() -> StartError {
    StartError::Launch(LaunchError::Lost(
        crate::sandbox::SessionId::parse("s-7").unwrap(),
    ))
}

/// Architect Q98: a launch whose task ended without a result has no launcher entry, so the
/// control socket writes its own `session.refuse`, naming the session, before the reply.
#[tokio::test]
async fn a_lost_launch_is_refused_with_its_own_entry() {
    let f = fx("lost");
    *f.fake.start_err.lock().unwrap() = Some(lost());
    let mut w = f.connect();
    let r = w
        .call("sessions.create", json!({"manifest": MANIFEST}))
        .await;
    let detail = "the launch task ended without a result";
    assert_eq!(reason(&r), "start-failed");
    assert_eq!(r["error"]["code"], json!(REFUSED));
    assert_eq!(r["error"]["data"]["detail"], json!(detail));
    assert_eq!(f.events(), ["rpc.request", "session.refuse"]);
    assert_eq!(
        f.sink.last("session.refuse"),
        json!({"method": "sessions.create", "id": "s-7", "reason": "start-failed",
               "detail": detail, "client": client()})
    );
    let r = w.call("sessions.list", json!({})).await;
    assert!(r["result"]["sessions"].is_array(), "the connection stays");
    // Its entry unwritten: no reply.
    let f = fx("lost-unwritten");
    *f.fake.start_err.lock().unwrap() = Some(lost());
    f.sink
        .fail_from
        .store(1, std::sync::atomic::Ordering::SeqCst);
    let mut w = f.connect();
    w.send("sessions.create", json!({"manifest": MANIFEST}))
        .await;
    w.ended().await;
    assert_eq!(f.events(), ["rpc.request"]);
}

/// Architect Q98: any other launch error keeps the launcher's entry and gets no second one.
#[tokio::test]
async fn an_internal_launch_error_has_only_the_launchers_entry() {
    let f = fx("internal");
    *f.fake.start_err.lock().unwrap() = Some(StartError::Launch(LaunchError::Internal(
        "task\npanicked".into(),
    )));
    let r = f
        .connect()
        .call("sessions.create", json!({"manifest": MANIFEST}))
        .await;
    assert_eq!(reason(&r), "internal");
    assert_eq!(
        r["error"]["data"]["detail"],
        json!("internal: task\\x0apanicked")
    );
    assert_eq!(f.events(), ["rpc.request"]);
}

/// Architect Q93 (i): a launch refusal whose own entry failed gets no reply; one whose
/// `sandbox.refuse` was written but whose launch failed on the log is told `audit`.
#[tokio::test]
async fn a_launch_refusal_that_was_not_audited_closes_with_no_reply() {
    let failed = || LaunchError::Audit(sally_core::audit::AuditError::InvalidEntry("x"));
    let f = fx("unaudited");
    *f.fake.start_err.lock().unwrap() = Some(StartError::Launch(LaunchError::Unaudited {
        original: Box::new(LaunchError::NoDefaultImage),
        audit: Box::new(failed()),
    }));
    let mut w = f.connect();
    w.send("sessions.create", json!({"manifest": MANIFEST}))
        .await;
    w.ended().await;
    assert_eq!(f.events(), ["rpc.request"]);
    let f = fx("audit");
    *f.fake.start_err.lock().unwrap() = Some(StartError::Launch(failed()));
    let r = f
        .connect()
        .call("sessions.create", json!({"manifest": MANIFEST}))
        .await;
    assert_eq!(reason(&r), "audit");
}

fn mkdirs(p: &Path) {
    use std::os::unix::fs::DirBuilderExt as _;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(p)
        .unwrap();
}

/// Architect Q75, Q81: paths escaped at the source, live or stopped (the listing needs no
/// session in the registry); an unknown session and a bad stage are refused and recorded.
#[tokio::test]
async fn sessions_changes_lists_escaped_paths_and_refuses_what_it_cannot_list() {
    use std::os::unix::ffi::OsStrExt as _;
    let f = fx("changes");
    let upper = f.sessions().join("s-1/stage/0/upper");
    mkdirs(&upper);
    std::fs::write(upper.join("new.txt"), b"x").unwrap();
    let hostile = std::ffi::OsStr::from_bytes(b"a\n\x1b[2J\xff");
    std::fs::write(upper.join(hostile), b"x").unwrap();
    mkdirs(&f.sessions().join("s-2/stage/01"));
    let mut w = f.connect();
    let r = w.call("sessions.changes", json!({"id": "s-1"})).await;
    assert_eq!(
        r["result"],
        json!({
            "changes": [
                {"mount": 0, "kind": "written", "path": "a\\x0a\\x1b[2J\\xff"},
                {"mount": 0, "kind": "written", "path": "new.txt"},
            ],
            "complete": true,
            "total": 2,
        })
    );
    let r = w.call("sessions.changes", json!({"id": "s-9"})).await;
    assert_eq!(reason(&r), "unknown-session");
    let r = w.call("sessions.changes", json!({"id": "s-2"})).await;
    assert_eq!(reason(&r), "listing-failed");
    let detail = r["error"]["data"]["detail"].as_str().unwrap().to_owned();
    assert!(detail.contains("01"), "{detail}");
    assert_eq!(
        f.events(),
        [
            "rpc.request",
            "rpc.request",
            "session.refuse",
            "rpc.request",
            "session.refuse"
        ]
    );
    let rows = f.rows();
    assert_eq!(
        rows[2].args,
        json!({"method": "sessions.changes", "id": "s-9", "reason": "unknown-session", "client": client()})
    );
    assert_eq!(
        rows[4].args,
        json!({
            "method": "sessions.changes", "id": "s-2", "reason": "listing-failed",
            "error": detail, "client": client(),
        })
    );
}

#[test]
fn fit_keeps_a_prefix_within_the_budget_and_counts_everything() {
    // `"ab"` is 4 bytes, plus 1 for its separator.
    let items = ["ab", "cd", "e", "fg"];
    assert_eq!(fit(items, 10), (vec!["ab", "cd"], false, 4));
    assert_eq!(fit(items, 9), (vec!["ab"], false, 4));
    assert_eq!(fit(["ab", "cd"], 10), (vec!["ab", "cd"], true, 2));
    // "e" alone would still fit after "cd" is cut; it is not kept.
    assert_eq!(
        fit(["ab", "cd", "e"], 9),
        (vec!["ab"], false, 3),
        "never past a cut"
    );
    assert_eq!(fit(Vec::<&str>::new(), 0), (vec![], true, 0));
}

#[test]
fn a_rejected_manifest_tells_at_most_32_errors_each_capped() {
    let mut lines: Vec<String> = (0..MAX_ERROR_LINES + 2).map(|i| format!("e{i}")).collect();
    lines[0] = format!("x\n{}", "y".repeat(2 * DETAIL_CHARS));
    let out = error_lines(&lines);
    assert_eq!(out.len(), MAX_ERROR_LINES + 1);
    assert_eq!(
        out[0],
        sally_core::text::escape_capped(lines[0].as_bytes(), DETAIL_CHARS)
    );
    assert_eq!(
        out[MAX_ERROR_LINES - 1],
        format!("e{}", MAX_ERROR_LINES - 1)
    );
    assert_eq!(out[MAX_ERROR_LINES], "... 2 more");
    assert_eq!(
        error_lines(&lines[..MAX_ERROR_LINES]).len(),
        MAX_ERROR_LINES
    );
    assert_eq!(MAX_ERROR_LINES, 32);
    assert_eq!(DETAIL_CHARS, 1024);
}

fn raw_prompt(action: String, full: String, truncated: bool) -> Prompt {
    Prompt {
        id: "p".repeat(64),
        session: "s".repeat(64),
        call: u64::MAX,
        tool: "\"".repeat(64),
        action,
        truncated,
        full,
        digest: "d".repeat(64),
        note: Some("\"".repeat(NOTE_CHARS)),
        risk_tags: vec!["destructive".to_owned()],
    }
}

#[test]
fn a_prompt_carries_its_full_text_only_when_cut_and_it_fits_the_wire() {
    let whole = prompt(&raw_prompt("a".into(), "a".into(), false));
    assert_eq!((whole.full, whole.full_unavailable), (None, false));
    assert!(whole.text.contains("action: a"));
    let fits = prompt(&raw_prompt("a".into(), "b".repeat(FULL_WIRE_BYTES), true));
    assert_eq!(fits.full.as_deref().map(str::len), Some(FULL_WIRE_BYTES));
    assert!(!fits.full_unavailable);
    let over = prompt(&raw_prompt(
        "a".into(),
        "b".repeat(FULL_WIRE_BYTES + 1),
        true,
    ));
    assert_eq!((over.full, over.full_unavailable), (None, true));
}

/// Architect Q84: the largest prompt (every character one JSON doubles) fits the reply budget,
/// and a full reply or a notification of it fits the client's frame cap.
#[test]
fn the_largest_prompt_fits_the_budget_and_the_budget_fits_a_frame() {
    let worst = raw_prompt(
        "\\".repeat(ACTION_CHARS),
        "\\".repeat(FULL_WIRE_BYTES),
        true,
    );
    let wire = prompt(&worst);
    assert!(wire.full.is_some());
    let one = serde_json::to_vec(&wire).unwrap().len() + 1;
    assert!(one > 2 * FULL_WIRE_BYTES, "the worst case doubles: {one}");
    assert!(one <= REPLY_BYTES, "{one} > {REPLY_BYTES}");
    let reply = success(
        &Id::Str("i".repeat(256)),
        json!({"prompts": [wire], "complete": false, "total": usize::MAX}),
    );
    // The envelope around a budget-full list.
    let envelope = reply.len() - (one - 1);
    assert!(REPLY_BYTES + envelope < MAX_FRAME, "{envelope}");
    assert!(notify(&Note::Requested(Arc::new(worst))).len() < MAX_FRAME);
    assert_eq!(REPLY_BYTES, 786_432);
}

/// Waits for the next notification, skipping nothing.
async fn note(w: &mut Wire) -> Value {
    let n = w.frame().await.expect("the connection closed");
    assert!(n.get("id").is_none(), "a reply, not a notification: {n}");
    n
}

/// Architect Q73, Q74: watch attaches then lists; a prompt is notified, listed elsewhere, and
/// approved with the digest shown; its close is notified.
#[tokio::test]
async fn a_watcher_hears_a_prompt_and_approves_it() {
    let f = fx("watch");
    let desk_sink = f.session("s-1");
    let mut w = f.connect();
    let r = w.call("approvals.watch", json!({})).await;
    assert_eq!(
        r["result"],
        json!({"prompts": [], "complete": true, "total": 0})
    );
    assert_eq!(f.hub.count(), 1);
    let asked = f.ask("s-1", 1, &["rm", "-rf", "x"]);
    let n = note(&mut w).await;
    assert_eq!(n["method"], json!("approval.requested"));
    let p = n["params"].clone();
    assert_eq!(p["session"], json!("s-1"));
    assert!(
        p["text"]
            .as_str()
            .unwrap()
            .contains(r#"run ["rm" "-rf" "x"]"#),
        "{p}"
    );
    let listed = f.connect().call("approvals.list", json!({})).await;
    assert_eq!(listed["result"]["prompts"][0], p);
    assert_eq!(listed["result"]["total"], json!(1));
    let id = p["id"].as_str().unwrap();
    let r = w
        .call(
            "approvals.decide",
            json!({"id": id, "decision": "approve", "digest": p["digest"]}),
        )
        .await;
    // The close may come before the reply.
    let (reply, closed) = if r.get("id").is_some() {
        (r, note(&mut w).await)
    } else {
        (w.frame().await.unwrap(), r)
    };
    assert_eq!(reply["result"], json!({}));
    assert_eq!(
        closed,
        json!({"jsonrpc": "2.0", "method": "approval.closed", "params": {"id": id}})
    );
    assert!(asked.await.unwrap().is_ok());
    let decided = desk_sink
        .rows()
        .into_iter()
        .rfind(|r| r.event == "approval.decide")
        .unwrap();
    assert_eq!(decided.decision.as_deref(), Some("approve"));
    assert_eq!(decided.args["client"], client());
    assert_eq!(
        f.events(),
        ["rpc.request", "rpc.request", "rpc.request"],
        "the control socket writes requests only; the desk writes the decision"
    );
}

/// Architect Q85: an id no live desk holds is refused by the control socket itself; a refusal by
/// the desk (a digest that is not the prompt's) is the desk's entry only.
#[tokio::test]
async fn decide_refuses_an_unknown_id_and_leaves_desk_refusals_to_the_desk() {
    let f = fx("decide");
    let desk_sink = f.session("s-1");
    let mut w = f.connect();
    w.call("approvals.watch", json!({})).await;
    let long = format!("x\n{}", "y".repeat(2 * ID_CHARS));
    let r = w
        .call(
            "approvals.decide",
            json!({"id": long, "decision": "deny", "digest": "d"}),
        )
        .await;
    assert_eq!(reason(&r), "unknown-id");
    assert_eq!(
        f.events(),
        ["rpc.request", "rpc.request", "approval.decide"]
    );
    let row = f.rows().pop().unwrap();
    assert_eq!(row.decision.as_deref(), Some("refuse"));
    assert!(row.debug.contains("User"));
    assert_eq!(
        row.args,
        json!({
            "id": sally_core::text::escape_capped(long.as_bytes(), ID_CHARS),
            "reason": "unknown-id", "client": client(),
        })
    );
    let _asked = f.ask("s-1", 1, &["ls"]);
    let p = note(&mut w).await["params"].clone();
    let r = w
        .call(
            "approvals.decide",
            json!({"id": p["id"], "decision": "approve", "digest": "0".repeat(64)}),
        )
        .await;
    assert_eq!(reason(&r), "digest-mismatch");
    assert_eq!(f.events().len(), 4, "only the request: {:?}", f.events());
    assert_eq!(
        desk_sink.last("approval.decide")["reason"],
        json!("digest-mismatch")
    );
}

/// Architect Q93 (ii): a decision the desk could not write is told `audit-failed` (the
/// maintainer's Task 11 rule): nothing was approved, the asker is told so, the connection stays.
#[tokio::test]
async fn an_unwritten_decision_is_told_audit_failed_and_nothing_runs() {
    let f = fx("unrecorded");
    let desk_sink = f.session("s-1");
    let mut w = f.connect();
    w.call("approvals.watch", json!({})).await;
    let asked = f.ask("s-1", 1, &["ls"]);
    let p = note(&mut w).await["params"].clone();
    desk_sink.set_failing(true);
    let params = json!({"id": p["id"], "decision": "approve", "digest": p["digest"]});
    let r = w.reply("approvals.decide", params).await;
    assert_eq!(reason(&r), "audit-failed");
    assert_eq!(
        asked.await.unwrap(),
        Err(crate::approvals::Refusal::Unrecorded)
    );
    let r = w.reply("sessions.list", json!({})).await;
    assert!(
        r["result"]["sessions"].is_array(),
        "the connection stays: {r}"
    );
}

/// Architect Q94: a watch on a connection that already watches draws on the read rate; a
/// first watch never waits for it.
#[tokio::test(start_paused = true)]
async fn a_repeated_watch_is_rated_and_a_first_one_is_not() {
    let f = fx("watch-rate");
    let mut w = f.connect();
    let t0 = tokio::time::Instant::now();
    for _ in 0..READ_BURST {
        w.call("sessions.list", json!({})).await;
    }
    assert_eq!(t0.elapsed(), Duration::ZERO);
    w.call("approvals.watch", json!({})).await;
    assert_eq!(t0.elapsed(), Duration::ZERO, "a first watch does not wait");
    w.call("approvals.watch", json!({})).await;
    assert_eq!(t0.elapsed(), Duration::from_millis(50), "a second one does");
    assert_eq!(f.hub.count(), 1);
    // The second watch took a token: the next read waits a full interval more.
    let t1 = tokio::time::Instant::now();
    w.call("sessions.list", json!({})).await;
    assert_eq!(t1.elapsed(), Duration::from_millis(50));
}

/// Architect Q89 (c): a second watch on a connection lists again and keeps its one watcher; the
/// watcher leaves with the connection (Q73.5).
#[tokio::test]
async fn one_watcher_per_connection_gone_with_it() {
    let f = fx("rewatch");
    f.session("s-1");
    let mut w = f.connect();
    w.call("approvals.watch", json!({})).await;
    let _asked = f.ask("s-1", 1, &["ls"]);
    note(&mut w).await;
    let again = w.call("approvals.watch", json!({})).await;
    assert_eq!(again["result"]["total"], json!(1));
    assert_eq!(f.hub.count(), 1);
    w.w.shutdown().await.unwrap();
    w.task.await.unwrap();
    assert_eq!(f.hub.count(), 0);
    assert!(!f.hub.attached());
}

/// Architect Q73.5, Q89 (d): a watcher the hub dropped as too slow has its connection closed.
#[tokio::test]
async fn a_dropped_watcher_closes_its_connection() {
    let f = fx("slow");
    f.session("s-1");
    let mut w = f.connect();
    w.call("approvals.watch", json!({})).await;
    // One more than the watcher's queue holds, told before the connection's task runs again.
    for i in 0..=crate::approvals::hub::WATCH_QUEUE {
        Approver::closed(&*f.hub, &format!("p{i}"));
    }
    assert_eq!(f.hub.count(), 0, "the hub dropped the watcher");
    let mut seen = 0;
    while let Some(n) = w.frame().await {
        assert_eq!(n["method"], json!("approval.closed"));
        seen += 1;
    }
    assert_eq!(seen, crate::approvals::hub::WATCH_QUEUE);
    w.task.await.unwrap();
}

/// Architect Q84: a prompt list is held to the reply budget, a prefix, with the total.
#[tokio::test]
async fn a_prompt_list_over_the_budget_is_cut_and_says_so() {
    let f = fx("budget");
    for s in ["s-1", "s-2", "s-3", "s-4"] {
        f.session(s);
    }
    let mut w = f.connect();
    w.call("approvals.watch", json!({})).await;
    // Each prompt about 200 KiB on the wire (its full text): three fit 768 KiB, the fourth
    // does not.
    let big = "a".repeat(200 * 1024);
    let mut asks = Vec::new();
    for (i, s) in ["s-1", "s-2", "s-3", "s-4"].iter().enumerate() {
        asks.push(f.ask(s, i as u64, &["echo", &big]));
        note(&mut w).await;
    }
    let r = f.connect().call("approvals.list", json!({})).await;
    let res = &r["result"];
    assert_eq!(res["complete"], json!(false));
    assert_eq!(res["total"], json!(4));
    let sessions: Vec<_> = res["prompts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["session"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(sessions, ["s-1", "s-2", "s-3"]);
    assert!(res["prompts"][0]["full"].is_string());
}

/// Architect Q97: after the oldest prompt is answered, a cut list still shows the oldest of
/// the rest, never the newest in its place.
#[tokio::test]
async fn a_cut_list_keeps_the_oldest_after_a_take() {
    let f = fx("oldest");
    f.session("s-1");
    let mut w = f.connect();
    w.call("approvals.watch", json!({})).await;
    let big = "a".repeat(200 * 1024);
    let mut ids = Vec::new();
    let mut asks = Vec::new();
    // Five prompts of about 200 KiB: after one is answered, three of the four fit the budget.
    for call in 1..=5 {
        asks.push(f.ask("s-1", call, &["echo", &big]));
        ids.push(note(&mut w).await["params"]["id"].clone());
    }
    let mut other = f.connect();
    let r = other
        .call(
            "approvals.decide",
            json!({"id": ids[0], "decision": "deny", "digest": ""}),
        )
        .await;
    assert_eq!(r["result"], json!({}));
    let r = other.call("approvals.list", json!({})).await;
    let res = &r["result"];
    assert_eq!(
        (&res["complete"], &res["total"]),
        (&json!(false), &json!(4))
    );
    let listed: Vec<_> = res["prompts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["id"].clone())
        .collect();
    assert_eq!(listed, ids[1..4]);
}

/// Architect Q77: 40 reads at once, then one per 50 ms; the wait ends with `sallyd`.
#[tokio::test(start_paused = true)]
async fn reads_are_rated_daemon_wide() {
    assert_eq!((READ_RATE, READ_BURST), (20, 40));
    let f = fx("rate");
    let mut w = f.connect();
    let t0 = tokio::time::Instant::now();
    for _ in 0..40 {
        w.call("sessions.list", json!({})).await;
    }
    assert_eq!(t0.elapsed(), Duration::ZERO);
    // A create does not draw on the rate.
    w.call("sessions.create", json!({"manifest": MANIFEST}))
        .await;
    assert_eq!(t0.elapsed(), Duration::ZERO);
    // Another connection shares it.
    let mut other = f.connect();
    other.call("approvals.list", json!({})).await;
    assert_eq!(t0.elapsed(), Duration::from_millis(50));
    let rows = f.rows().len();
    // Waiting: no entry yet; stopping ends the connection.
    other.send("sessions.changes", json!({"id": "s-1"})).await;
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        f.rows().len(),
        rows,
        "the wait comes before the request entry"
    );
    Server::stop(&*f.control);
    other.ended().await;
    assert_eq!(f.rows().len(), rows);
}
