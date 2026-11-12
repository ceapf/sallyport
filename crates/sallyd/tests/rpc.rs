//! Task 7 with a real harness-role container (architect ruling Q5): one test per socket, each
//! through the static shim the way a harness reaches the broker. The broker side runs in this
//! process: the sockets are bound owner-only (0600) in the session's harness directory, which
//! the harness argv mounts read-only at `/run/sallyport`, and served with the production peer-UID
//! check (keep-id: the container's user is the host user, ARCHITECTURE §4).
//!
//! Rows: RT-FS-10 (Task 7 part: the harness directory holds exactly `agent.sock` and `llm.sock`),
//! and the peer-UID check passing for the harness (ruling Q1). The fixture is
//! `common::container`; these tests never skip.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use sally_core::manifest::AuditLevel;
use sallyd::egress::net::bind;
use sallyd::llm::server::{Llm, Settings};
use sallyd::rpc::agent::{Agent, ToolHandler};
use sallyd::rpc::listen::Handle;
use sallyd::rpc::mcp::{Tool, ToolOutcome};
use sallyd::rpc::record::Recorder;
use sallyd::sandbox::{AuditSink, SessionDirs, harness_argv};
use serde_json::{Map, Value, json};

mod common;
use common::container::*;
use common::mock_model::{Backed, MockModel, Turn};

/// The harness's loopback port for `llm.sock` (ARCHITECTURE §2.1, the shim row).
const LLM_PORT: u16 = 8080;
/// Where the llm.sock shim's stderr (its readiness line) goes.
const LLM_SHIM_LOG: &str = "/tmp/llm-shim.log";

/// The harness's one tool here: answers at once with what it was given.
struct Echo;

impl ToolHandler for Echo {
    fn tools(&self) -> Vec<Tool> {
        vec![Tool {
            name: "echo",
            description: "Echo.",
            input_schema: json!({"type": "object"}),
        }]
    }

    async fn call(&self, name: String, arguments: Map<String, Value>) -> ToolOutcome {
        ToolOutcome {
            is_error: false,
            text: format!("{name} {}", Value::Object(arguments)),
        }
    }
}

/// A started harness container and the broker serving its two sockets.
struct Harness {
    container: String,
    agent: Handle,
    llm: Handle,
    model: Arc<MockModel>,
}

/// Starts a harness container with `agent.sock` and `llm.sock` served.
async fn harness(x: &Lx, tag: &str, script: &str) -> Harness {
    let paths = x.paths(tag);
    let dirs = SessionDirs::create(&paths, &x.xdg, &[], 0).unwrap();
    let sockets = paths.harness_sockets();
    let uid = ids().uid;
    let session = paths.id().as_str().to_owned();
    let sink: Arc<dyn AuditSink> = x.events.clone();
    let record = Recorder::new(sink, session, AuditLevel::Full);
    let agent = Arc::new(Agent::new(Echo, record.clone()))
        .listen(bind(&sockets.join("agent.sock")).unwrap(), uid);
    let model = MockModel::load(script);
    let settings = Settings {
        model: "local-model".into(),
        context: 4096,
    };
    let llm = Arc::new(Llm::new(Backed(Arc::clone(&model)), record, settings))
        .listen(bind(&sockets.join("llm.sock")).unwrap(), uid);
    let v = x.f.load("");
    // The net image carries the static shim; its own entry's net.sock listener finds no socket
    // in a harness and stays idle. The harness's llm.sock listener starts here.
    let argv = harness_argv(&x.common_args(&dirs), &paths, &v, &net_image()).unwrap();
    let container = x.create_and_start(argv).await;
    let start =
        format!("{SHIM} --listen 127.0.0.1:{LLM_PORT}=/run/sallyport/llm.sock 2>{LLM_SHIM_LOG}");
    let out = podman(&["exec", "-d", &container, "sh", "-c", &start]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    for _ in 0..100 {
        let (_, log) = sh(&container, &format!("cat {LLM_SHIM_LOG} 2>/dev/null")).await;
        if log.contains(&format!("sally-shim: listening on 127.0.0.1:{LLM_PORT}")) {
            return Harness {
                container,
                agent,
                llm,
                model,
            };
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the shim never became ready");
}

/// `sh -c <script>` in the container, off the runtime (the broker serves on it meanwhile).
async fn sh(container: &str, script: &str) -> (i32, String) {
    let (c, s) = (container.to_owned(), script.to_owned());
    tokio::task::spawn_blocking(move || exec_in(&c, &["sh", "-c", &s]))
        .await
        .unwrap()
}

/// Sends `lines` through `sally-shim --stdio /run/sallyport/agent.sock`; the replies, parsed.
async fn agent_exchange(h: &Harness, lines: &[Value]) -> Vec<Value> {
    let args: Vec<String> = lines.iter().map(|l| format!("'{l}'")).collect();
    let script = format!(
        "printf '%s\\n' {} | {SHIM} --stdio /run/sallyport/agent.sock",
        args.join(" ")
    );
    let (code, out) = sh(&h.container, &script).await;
    assert_eq!(code, 0, "{out}");
    out.lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{l:?}: {e}")))
        .collect()
}

fn meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
    })
}

/// RT-FS-10 (Task 7 part), from inside the harness: `/run/sallyport` lists exactly the two
/// sockets, each a socket the harness's user owns with mode 0600.
async fn sockets_are_exactly_the_two(h: &Harness) {
    let (code, out) = sh(&h.container, "ls -A /run/sallyport").await;
    assert_eq!(code, 0, "{out}");
    let mut names: Vec<&str> = out.lines().collect();
    names.sort_unstable();
    assert_eq!(names, ["agent.sock", "llm.sock"]);
    let (_, modes) = sh(&h.container, "stat -c '%F %a %u' /run/sallyport/*.sock").await;
    let want = format!("socket 600 {}", ids().uid);
    assert_eq!(modes.lines().collect::<Vec<_>>(), [&want, &want], "{modes}");
}

/// agent.sock through the shim's stdio mode, in both lifecycles (architect ruling Q6), with the
/// peer-UID check passing for the harness (ruling Q1).
#[test]
fn rt_fs_10_agent_sock_serves_the_harness_in_both_lifecycles() {
    rt().block_on(async {
        let x = Lx::new();
        let h = harness(&x, "agent", "hello.jsonl").await;
        sockets_are_exactly_the_two(&h).await;
        // The 2026-07-28 form: every request carries its own `_meta`.
        let modern = agent_exchange(
            &h,
            &[
                json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"_meta": meta()}}),
                json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                       "params": {"_meta": meta(), "name": "echo", "arguments": {"a": 1}}}),
            ],
        )
        .await;
        assert_eq!(modern.len(), 2, "{modern:?}");
        assert_eq!(modern[0]["result"]["tools"][0]["name"], json!("echo"));
        assert_eq!(modern[0]["result"]["resultType"], json!("complete"));
        assert_eq!(
            modern[1]["result"]["content"][0]["text"],
            json!("echo {\"a\":1}")
        );
        // The legacy form: initialize first, then plain requests.
        let legacy = agent_exchange(
            &h,
            &[
                json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                       "params": {"protocolVersion": "2025-06-18", "capabilities": {}}}),
                json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
                json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                       "params": {"name": "echo", "arguments": {}}}),
            ],
        )
        .await;
        assert_eq!(legacy.len(), 2, "{legacy:?}");
        assert_eq!(legacy[0]["result"]["protocolVersion"], json!("2025-06-18"));
        assert!(legacy[1]["result"].get("resultType").is_none());
        // Off the allowlist: an error, and an entry.
        let control = agent_exchange(
            &h,
            &[json!({"jsonrpc": "2.0", "id": 9, "method": "session.launch",
                     "params": {"_meta": meta()}})],
        )
        .await;
        assert_eq!(control[0]["error"]["code"], json!(-32601));
        let events = x.events.list();
        assert!(events.iter().any(|e| e == "rpc.deny"), "{events:?}");
        assert!(
            x.events
                .all()
                .iter()
                .all(|(_, a)| a.get("reason") != Some(&json!("peer-uid"))),
            "the harness failed the peer-UID check"
        );
        h.agent.shutdown().await;
        h.llm.shutdown().await;
    });
}

/// llm.sock through the shim's listener (`127.0.0.1:8080`) with busybox `wget`, answered by the
/// scripted mock model; the peer-UID check passes for the harness.
#[test]
fn rt_fs_10_llm_sock_serves_the_harness_through_the_shim() {
    rt().block_on(async {
        let x = Lx::new();
        let h = harness(&x, "llm", "hello.jsonl").await;
        sockets_are_exactly_the_two(&h).await;
        let base = format!("http://127.0.0.1:{LLM_PORT}");
        let (code, out) = sh(&h.container, &format!("wget -q -O - {base}/v1/models")).await;
        assert_eq!(code, 0, "{out}");
        let models: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(models["data"][0]["id"], json!("local-model"));
        let body = json!({"model": "../../models/x.gguf",
                          "messages": [{"role": "user", "content": "hi"}]});
        let post = |extra: &str| {
            format!(
                "wget -q -O - --header 'Content-Type: application/json' --post-data '{}' \
                 {base}/v1/chat/completions",
                extra
            )
        };
        let (code, out) = sh(&h.container, &post(&body.to_string())).await;
        assert_eq!(code, 0, "{out}");
        let reply: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            reply["choices"][0]["message"]["content"],
            json!("hello from the mock model")
        );
        let mut streamed = body.clone();
        streamed["stream"] = json!(true);
        let (code, out) = sh(&h.container, &post(&streamed.to_string())).await;
        assert_eq!(code, 0, "{out}");
        assert!(
            out.contains("streamed hello") && out.ends_with("data: [DONE]\n\n"),
            "{out}"
        );
        // A refused request is answered by the broker: wget sees the error status.
        let (code, _) = sh(&h.container, &post(r#"{"messages": [], "n": 2}"#)).await;
        assert_ne!(code, 0);
        // The model the harness named never reached the backend (RT-INF-03).
        let seen = h.model.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 2);
        assert!(seen.iter().all(|c| !c.body.contains_key("model")));
        assert_eq!(h.model.left(), 0);
        let events = x.events.list();
        for e in ["llm.request", "llm.response", "llm.deny"] {
            assert!(events.iter().any(|x| x == e), "{e}: {events:?}");
        }
        assert!(
            x.events
                .all()
                .iter()
                .all(|(_, a)| a.get("reason") != Some(&json!("peer-uid"))),
            "the harness failed the peer-UID check"
        );
        h.agent.shutdown().await;
        h.llm.shutdown().await;
    });
}

#[test]
fn mock_model_scripts_parse_strictly() {
    for name in ["hello.jsonl", "read_ssh_key.jsonl"] {
        assert!(MockModel::load(name).left() > 0, "{name}");
    }
    assert_eq!(Turn::parse(r#"{"fail": true}"#), Ok(Turn::Fail));
    for bad in [
        r#"{"content": "hi", "extra": 1}"#,
        r#"{"tool_calls": [{"name": "x"}]}"#,
        r#"{"tool_calls": [{"name": "x", "arguments": [], }]}"#,
        r#"{"fail": false}"#,
        r#"{"nothing": 1}"#,
        "[]",
    ] {
        assert!(Turn::parse(bad).is_err(), "{bad}");
    }
}
