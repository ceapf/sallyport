//! `control.sock`'s methods over the real registry (architect Q86): what the unit tests' fake
//! stands in for. `sessions.create` starts a container, `sessions.list` shows it,
//! `sessions.changes` lists what it staged live and after `sessions.stop`, and a prompt of the
//! live session is answered through `approvals.watch` / `approvals.decide`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use sally_core::manifest::AuditLevel;
use sallyd::approvals::hub::Hub;
use sallyd::rpc::control::{Control, ControlParts};
use sallyd::rpc::listen::Peer;
use sallyd::rpc::record::Recorder;
use sallyd::sandbox::{AuditSink, open_sessions};
use sallyd::session::{AGENT_SOCK, Registry};
use serde_json::{Value, json};
use tokio::io::{
    AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, ReadHalf, WriteHalf, split,
};

mod common;
use common::container::*;
use common::*;

struct Cx {
    x: Lx,
    control: Arc<Control<Arc<Registry>>>,
}

fn cx() -> Cx {
    let x = Lx::new();
    let audit = x.events.clone() as Arc<dyn AuditSink>;
    let hub = Arc::new(Hub::default());
    let reg = x.registry_hub(
        Arc::clone(&audit),
        Some(test_image()),
        sallyd::oplog::Oplog::new(std::io::sink()),
        Arc::clone(&hub),
    );
    let sessions_dir = open_sessions(&x.f.root.join("home/.local/share/sallyport")).unwrap();
    let control = Arc::new(Control::new(ControlParts {
        record: Recorder::new(audit, String::new(), AuditLevel::default()),
        sessions: reg,
        hub,
        sessions_dir: Arc::new(sessions_dir),
        env: Arc::new(x.f.env.clone()),
        catalog: Arc::new(BTreeSet::<String>::new()),
    }));
    Cx { x, control }
}

/// One control connection, as the peer `PEER`.
struct Wire {
    r: BufReader<ReadHalf<DuplexStream>>,
    w: WriteHalf<DuplexStream>,
    next: i64,
}

const PEER: Peer = Peer { uid: 1000, pid: 7 };

impl Cx {
    fn connect(&self) -> Wire {
        let (client, server) = tokio::io::duplex(4 << 20);
        tokio::spawn(Arc::clone(&self.control).serve_stream(server, PEER));
        let (r, w) = split(client);
        Wire {
            r: BufReader::new(r),
            w,
            next: 1,
        }
    }
}

impl Wire {
    async fn frame(&mut self) -> Value {
        let mut l = String::new();
        let n = tokio::time::timeout(Duration::from_secs(120), self.r.read_line(&mut l))
            .await
            .expect("no frame")
            .unwrap();
        assert!(n > 0, "the connection closed");
        serde_json::from_str(&l).unwrap()
    }

    async fn call(&mut self, method: &str, params: Value) -> Value {
        let req = json!({"jsonrpc": "2.0", "id": self.next, "method": method, "params": params});
        self.next += 1;
        self.w
            .write_all(format!("{req}\n").as_bytes())
            .await
            .unwrap();
        self.frame().await
    }
}

/// Runs `script` in `container` off the runtime.
async fn sh(container: &str, script: &str) {
    let (c, s) = (container.to_owned(), script.to_owned());
    let (code, out) = tokio::task::spawn_blocking(move || exec_in(&c, &["sh", "-c", &s]))
        .await
        .unwrap();
    assert_eq!(code, 0, "{out}");
}

#[test]
fn a_session_runs_from_create_to_stop_over_control() {
    rt().block_on(async {
        let c = cx();
        std::fs::create_dir_all(c.x.f.root.join("home/code/ctl")).unwrap();
        let text = format!(
            "{HEADER}{}",
            mounts(&[mount("~/code/ctl", "/workspace/p", "staged")])
        );
        let mut w = c.connect();
        let r = w.call("sessions.create", json!({"manifest": text})).await;
        let s = r["result"].clone();
        let id = s["id"].as_str().expect("created").to_owned();
        assert_eq!(s["state"], json!("running"));
        let listed = w.call("sessions.list", json!({})).await;
        assert_eq!(listed["result"]["sessions"], json!([s]));
        sh(
            s["container"].as_str().unwrap(),
            "echo x > /workspace/p/new.txt",
        )
        .await;
        let want = json!({
            "changes": [{"mount": 0, "kind": "written", "path": "new.txt"}],
            "complete": true, "total": 1,
        });
        let live = w.call("sessions.changes", json!({"id": id})).await;
        assert_eq!(live["result"], want, "while it runs");
        let stopped = w.call("sessions.stop", json!({"id": id})).await;
        assert_eq!(stopped["result"], json!({"id": id}));
        let after = w.call("sessions.changes", json!({"id": id})).await;
        assert_eq!(after["result"], want, "after the stop (the stage is kept)");
        let again = w.call("sessions.stop", json!({"id": id})).await;
        assert_eq!(again["error"]["data"]["reason"], json!("unknown-session"));
        let listed = w.call("sessions.list", json!({})).await;
        assert_eq!(listed["result"]["sessions"], json!([]));
        let all = c.x.events.all();
        let requests: Vec<_> = all
            .iter()
            .filter(|(e, _)| e == "rpc.request")
            .map(|(_, a)| a["method"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            requests,
            [
                "sessions.create",
                "sessions.list",
                "sessions.changes",
                "sessions.stop",
                "sessions.changes",
                "sessions.stop",
                "sessions.list",
            ]
        );
        let create = all
            .iter()
            .position(|(e, _)| e == "rpc.request")
            .expect("rpc.request");
        let start = all
            .iter()
            .position(|(e, _)| e == "session.start")
            .expect("session.start");
        assert!(create < start, "the request is recorded before its effect");
        assert_eq!(
            all[create].1["client"],
            json!({"uid": PEER.uid, "pid": PEER.pid})
        );
        assert!(
            all.iter()
                .any(|(e, a)| e == "session.refuse" && a["reason"] == json!("unknown-session"))
        );
    });
}

/// RT-FS-15 through the CLI, live and after the stop (architect Q79, Q81, Q90): a name the
/// sandbox chose (`\n`, an escape sequence, a byte that is not UTF-8) is listed by the CLI's own
/// code over a real `control.sock` (its peer check runs) as exactly the escaped bytes `sally
/// session changes` prints. Controls: `sallyd`'s path escaping (`control_methods::change`); the
/// CLI's clean-check has its own test (sally-cli `tests/cli.rs`).
/// TODO(#106): the same through the `sallyd` binary once a daemon test can have an image.
#[test]
fn rt_fs_15_a_live_session_s_changes_are_listed_escaped_through_the_cli() {
    let c = cx();
    std::fs::create_dir_all(c.x.f.root.join("home/code/fs15")).unwrap();
    let dir = std::env::temp_dir().join(format!("sp-ctl-fs15-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("control.sock");
    let me = rustix::process::getuid().as_raw();
    // The server on a runtime of its own; the CLI (blocking) on this thread.
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let (control, sock) = (Arc::clone(&c.control), path.clone());
    let server = std::thread::spawn(move || {
        rt().block_on(async move {
            let (crash, _crashes) = sallyd::daemon::crash::CrashReporter::channel();
            let l = tokio::net::UnixListener::bind(&sock).unwrap();
            let h = control.listen(l, me, crash);
            ready_tx.send(()).unwrap();
            let _ = stop_rx.await;
            h.shutdown().await;
        });
    });
    ready_rx.recv().unwrap();
    let mut client = sally_cli::client::Client::connect(&path).unwrap();
    let text = format!(
        "{HEADER}{}",
        mounts(&[mount("~/code/fs15", "/workspace/p", "staged")])
    );
    let s = client
        .call("sessions.create", json!({"manifest": text}))
        .unwrap();
    let id = s["id"].as_str().unwrap().to_owned();
    let container = s["container"].as_str().unwrap().to_owned();
    let (code, out) = exec_in(
        &container,
        &[
            "sh",
            "-c",
            "touch \"/workspace/p/$(printf 'a\\n\\033[2J\\377')\"",
        ],
    );
    assert_eq!(code, 0, "{out}");
    let list = |client: &mut sally_cli::client::Client| {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let mut o = sally_cli::commands::Out {
            out: &mut out,
            err: &mut err,
        };
        let code = sally_cli::commands::session_changes(client, &id, &mut o);
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    };
    let want = "written mounts[0] a\\x0a\\x1b[2J\\xff\n";
    let (code, out, err) = list(&mut client);
    assert_eq!(
        (code, out.as_str()),
        (sally_cli::EXIT_OK, want),
        "live: {err}"
    );
    let stopped = client.call("sessions.stop", json!({"id": id})).unwrap();
    assert_eq!(stopped["id"], json!(id));
    let (code, out, err) = list(&mut client);
    assert_eq!(
        (code, out.as_str()),
        (sally_cli::EXIT_OK, want),
        "after the stop: {err}"
    );
    drop(client);
    stop_tx.send(()).unwrap();
    server.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// A connection to `sock` through a short `/proc/self/fd` path, and the directory fd that keeps
/// the path valid.
async fn agent(sock: &Path) -> (tokio::net::UnixStream, std::fs::File) {
    let dir = std::fs::File::open(sock.parent().unwrap()).unwrap();
    let short = Path::new("/proc/self/fd")
        .join(std::os::fd::AsRawFd::as_raw_fd(&dir).to_string())
        .join(AGENT_SOCK);
    (tokio::net::UnixStream::connect(&short).await.unwrap(), dir)
}

#[test]
fn a_prompt_of_a_live_session_is_answered_over_control() {
    rt().block_on(async {
        let c = cx();
        let text = format!("{HEADER}tools:\n  builtin: [shell]\n  shell: approve\n");
        let mut w = c.connect();
        let r = w.call("sessions.create", json!({"manifest": text})).await;
        let id = r["result"]["id"].as_str().expect("created").to_owned();
        let watched = w.call("approvals.watch", json!({})).await;
        assert_eq!(watched["result"]["total"], json!(0));
        let sock = c.x.session_paths(&id).harness_sockets().join(AGENT_SOCK);
        let (conn, _dir) = agent(&sock).await;
        let (rd, mut wr) = conn.into_split();
        let meta = json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
        });
        let call = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"_meta": meta, "name": "shell",
                       "arguments": {"cmd": ["touch", "/tmp/ran"], "cwd": "/workspace"}}});
        wr.write_all(format!("{call}\n").as_bytes()).await.unwrap();
        let note = w.frame().await;
        assert_eq!(note["method"], json!("approval.requested"));
        let p = note["params"].clone();
        assert_eq!(p["session"], json!(id));
        let listed = c.connect().call("approvals.list", json!({})).await;
        assert_eq!(listed["result"]["prompts"], json!([p]));
        let first = w
            .call(
                "approvals.decide",
                json!({"id": p["id"], "decision": "deny", "digest": p["digest"]}),
            )
            .await;
        let second = w.frame().await;
        let (reply, closed) = if first.get("id").is_some() {
            (first, second)
        } else {
            (second, first)
        };
        assert_eq!(reply["result"], json!({}));
        assert_eq!(closed["method"], json!("approval.closed"));
        assert_eq!(closed["params"]["id"], p["id"]);
        let mut answer = String::new();
        tokio::time::timeout(
            Duration::from_secs(30),
            BufReader::new(rd).read_line(&mut answer),
        )
        .await
        .expect("no answer to the call")
        .unwrap();
        let v: Value = serde_json::from_str(&answer).unwrap();
        assert!(
            v.get("error").is_some() || v["result"]["isError"] == json!(true),
            "a denied call ran: {v}"
        );
        let decided =
            c.x.events
                .all()
                .into_iter()
                .find(|(e, _)| e == "approval.decide")
                .expect("approval.decide");
        assert_eq!(
            decided.1["client"],
            json!({"uid": PEER.uid, "pid": PEER.pid})
        );
        let stopped = w.call("sessions.stop", json!({"id": id})).await;
        assert_eq!(stopped["result"], json!({"id": id}));
    });
}
