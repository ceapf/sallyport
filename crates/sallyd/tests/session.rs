//! Task 12 (architect Q57) with real containers: the session registry's start order, its stop
//! reasons, and exactly one `session.stop` per `session.start`.
//!
//! The fixture is `common::container`; these tests never skip.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sally_core::audit::{AuditError, NewEntry};
use sally_core::manifest::AuditLevel;
use sallyd::sandbox::{AuditSink, LaunchError};
use sallyd::session::{AGENT_SOCK, Registry, SessionState, StartError, StopOutcome, StopReason};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

mod common;
use common::container::*;
use common::egress::tls_upstream;
use common::*;

type Hook = Box<dyn Fn(&Path) -> Result<(), AuditError> + Send + Sync>;

/// The registry's audit sink: forwards to the fixture's events, keeps every entry's `Debug`
/// form (which shows its session id), and runs `hook` (with the sessions' socket root) when
/// `session.start` is appended, before it is recorded.
struct Hooked {
    events: Arc<Events>,
    sockets: PathBuf,
    hook: Mutex<Option<Hook>>,
    debug: Mutex<Vec<String>>,
}

impl AuditSink for Hooked {
    fn append(&self, e: NewEntry, level: AuditLevel) -> Result<(), AuditError> {
        if e.event() == "session.start"
            && let Some(h) = self.hook.lock().unwrap().as_ref()
        {
            h(&self.sockets)?;
        }
        self.debug.lock().unwrap().push(format!("{e:?}"));
        self.events.append(e, level)
    }
}

struct Rx {
    x: Lx,
    reg: Arc<Registry>,
    sink: Arc<Hooked>,
    /// The registry's operational log.
    log: Lines,
}

impl Rx {
    /// Waits until the operational log holds `needle`; panics after 10 s.
    async fn until_logged(&self, needle: &str) {
        until(needle, Duration::from_secs(10), || {
            String::from_utf8_lossy(&self.log.0.lock().unwrap()).contains(needle)
        })
        .await;
    }
}

fn registry() -> Rx {
    registry_with(Some(test_image()))
}

fn registry_with(default_image: Option<sallyd::sandbox::ImageRef>) -> Rx {
    let x = Lx::new();
    let sink = Arc::new(Hooked {
        events: x.events.clone(),
        sockets: x.xdg.join("sallyport/sessions"),
        hook: Mutex::new(None),
        debug: Mutex::new(Vec::new()),
    });
    let log = Lines::default();
    let reg = x.registry_logged(
        sink.clone(),
        default_image,
        sallyd::oplog::Oplog::new(log.clone()),
    );
    Rx { x, reg, sink, log }
}

/// The `agent.sock` files under `root` (`sessions/<id>/harness/agent.sock`).
fn agent_socks(root: &Path) -> Vec<PathBuf> {
    let Ok(dirs) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    dirs.filter_map(|d| {
        let p = d.ok()?.path().join("harness").join(AGENT_SOCK);
        p.exists().then_some(p)
    })
    .collect()
}

/// The events of session-level entries, in order.
fn session_events(x: &Lx) -> Vec<String> {
    x.events
        .list()
        .into_iter()
        .filter(|e| e.starts_with("session.") || e.starts_with("sandbox."))
        .collect()
}

fn stops(x: &Lx) -> Vec<String> {
    x.events
        .all()
        .into_iter()
        .filter(|(e, _)| e == "session.stop")
        .map(|(_, a)| a["reason"].as_str().unwrap().to_owned())
        .collect()
}

async fn until(what: &str, limit: Duration, mut f: impl FnMut() -> bool) {
    let end = std::time::Instant::now() + limit;
    while std::time::Instant::now() < end {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for {what}");
}

/// Q57 order: `sandbox.launch` and `session.start` are written before `agent.sock` exists; the
/// socket is 0600; a requested stop writes one `session.stop` before `sandbox.stop` and removes
/// the container.
#[test]
fn a_session_starts_in_order_and_stops_once_on_request() {
    rt().block_on(async {
        let r = registry();
        let seen = Arc::new(Mutex::new(None));
        let s = Arc::clone(&seen);
        *r.sink.hook.lock().unwrap() = Some(Box::new(move |root| {
            *s.lock().unwrap() = Some(agent_socks(root).len());
            Ok(())
        }));
        let v = Arc::new(r.x.f.load(""));
        let info = r.reg.start(v).await.unwrap();
        assert_eq!(
            *seen.lock().unwrap(),
            Some(0),
            "agent.sock before session.start"
        );
        assert!(
            info.id.starts_with(&format!("{}-", r.x.scope)),
            "{}",
            info.id
        );
        let socks = agent_socks(&r.sink.sockets);
        assert_eq!(socks.len(), 1);
        let mode = std::fs::metadata(&socks[0]).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(exists(&info.container));
        assert_eq!(r.reg.list(), std::slice::from_ref(&info));
        assert!(r.reg.desk(&info.id).is_some());
        let a = r.x.events.args("session.start").unwrap();
        assert_eq!(a["model"]["kind"], "none");

        let out = r.reg.stop(&info.id, StopReason::Request).await;
        assert_eq!(out, Some(StopOutcome::Stopped));
        assert!(!exists(&info.container));
        assert!(r.reg.list().is_empty());
        assert!(r.reg.desk(&info.id).is_none());
        assert_eq!(r.reg.stop(&info.id, StopReason::Request).await, None);
        assert_eq!(
            session_events(&r.x),
            [
                "sandbox.launch",
                "session.start",
                "session.stop",
                "sandbox.stop"
            ]
        );
        assert_eq!(stops(&r.x), ["request"]);
    });
}

/// A failed `session.start` append binds nothing and stops the workspace. Its entry may have
/// reached the log before the error, so a best-effort `session.stop` (`start-failed`) follows
/// (security review L6): never a `session.start` without its stop.
#[test]
fn an_unaudited_session_start_binds_nothing_and_stops_the_workspace() {
    rt().block_on(async {
        let r = registry();
        *r.sink.hook.lock().unwrap() =
            Some(Box::new(|_| Err(AuditError::InvalidEntry("fake failure"))));
        let v = Arc::new(r.x.f.load(""));
        let e = r.reg.start(v).await.unwrap_err();
        assert!(matches!(e, StartError::Audit(_)), "{e}");
        assert!(agent_socks(&r.sink.sockets).is_empty());
        assert!(r.reg.list().is_empty());
        assert_eq!(
            session_events(&r.x),
            ["sandbox.launch", "session.stop", "sandbox.stop"]
        );
        assert_eq!(stops(&r.x), ["start-failed"]);
        let names = podman(&["ps", "-a", "--format", "{{.Names}}"]);
        let names = String::from_utf8_lossy(&names.stdout);
        assert!(!names.contains(&r.x.scope), "{names}");
    });
}

/// Rust review HIGH: the workspace of a failed start that cannot be confirmed gone is not left to
/// an untracked retry loop. It stays listed as stop-failed (with no desk: its session never
/// started); a stop request retries it, and shutdown counts it while it still fails and clears
/// it once it stops.
#[test]
fn a_failed_starts_workspace_not_confirmed_gone_stays_listed_and_is_retried() {
    rt().block_on(async {
        let r = registry();
        r.x.events
            .fail(&["session.start", "session.stop", "sandbox.stop"]);
        let v = Arc::new(r.x.f.load(""));
        let e = r.reg.start(v).await.unwrap_err();
        assert!(matches!(e, StartError::Audit(_)), "{e}");
        let listed = r.reg.list();
        assert_eq!(listed.len(), 1, "{listed:?}");
        assert_eq!(listed[0].state, SessionState::StopFailed);
        let id = listed[0].id.clone();
        assert!(r.reg.desk(&id).is_none() && r.reg.reporter(&id).is_none());
        assert!(matches!(
            r.reg.stop(&id, StopReason::Request).await,
            Some(StopOutcome::Failed(_))
        ));
        assert_eq!(r.reg.shutdown().await, std::slice::from_ref(&id));
        r.x.events.fail(&[]);
        assert!(r.reg.shutdown().await.is_empty());
        assert!(r.reg.list().is_empty());
        assert!(
            !session_events(&r.x)
                .iter()
                .any(|e| e.starts_with("session."))
        );
    });
}

/// Architect Q58: with no bundled image, a manifest without `runtime.image` fails at the
/// launcher: no `session.start`, no socket, nothing listed.
#[test]
fn no_default_image_starts_nothing() {
    rt().block_on(async {
        let r = registry_with(None);
        let v = Arc::new(r.x.f.load(""));
        let e = r.reg.start(v).await.unwrap_err();
        assert!(
            matches!(e, StartError::Launch(LaunchError::NoDefaultImage)),
            "{e}"
        );
        assert_eq!(session_events(&r.x), ["sandbox.refuse"]);
        assert!(agent_socks(&r.sink.sockets).is_empty());
        assert!(r.reg.list().is_empty());
    });
}

/// A bind failure after `session.start` ends the session `start-failed`, exactly once.
#[test]
fn a_bind_failure_ends_the_session_start_failed() {
    rt().block_on(async {
        let r = registry();
        // Occupies the socket's name, so the bind fails with EADDRINUSE.
        *r.sink.hook.lock().unwrap() = Some(Box::new(|root| {
            for d in std::fs::read_dir(root).unwrap() {
                std::fs::write(d.unwrap().path().join("harness").join(AGENT_SOCK), b"").unwrap();
            }
            Ok(())
        }));
        let v = Arc::new(r.x.f.load(""));
        let e = r.reg.start(v).await.unwrap_err();
        assert!(matches!(e, StartError::Socket(_)), "{e}");
        assert!(r.reg.list().is_empty());
        assert_eq!(
            session_events(&r.x),
            [
                "sandbox.launch",
                "session.start",
                "session.stop",
                "sandbox.stop"
            ]
        );
        assert_eq!(stops(&r.x), ["start-failed"]);
    });
}

/// A container that ends on its own ends its session `exited`, and the dead session gives back
/// its claims: the same writable mount launches again.
#[test]
fn a_container_that_exits_ends_its_session_and_frees_its_mounts() {
    rt().block_on(async {
        let r = registry();
        let v = Arc::new(
            r.x.f
                .load(&mounts(&[mount("~/code/myproject", "/workspace/p", "rw")])),
        );
        let info = r.reg.start(Arc::clone(&v)).await.unwrap();
        r.x.hermetic(&["kill".to_owned(), info.container.clone()])
            .await;
        until("the session to end", Duration::from_secs(20), || {
            r.reg.list().is_empty()
        })
        .await;
        assert_eq!(stops(&r.x), ["exited"]);
        let again = r.reg.start(v).await.unwrap();
        assert_eq!(
            r.reg.stop(&again.id, StopReason::Request).await,
            Some(StopOutcome::Stopped)
        );
        assert_eq!(stops(&r.x), ["exited", "request"]);
    });
}

/// Q47: a panicking session task ends that session with `session.crash` then `session.stop
/// crash`; another session stays live.
#[test]
fn a_panicking_session_task_ends_only_its_session() {
    rt().block_on(async {
        let r = registry();
        let v = Arc::new(r.x.f.load(""));
        let a = r.reg.start(Arc::clone(&v)).await.unwrap();
        let b = r.reg.start(v).await.unwrap();
        r.reg
            .reporter(&a.id)
            .unwrap()
            .spawn("agent.sock", async { panic!("boom") });
        until("session A to end", Duration::from_secs(20), || {
            r.reg.list().len() == 1
        })
        .await;
        assert_eq!(r.reg.list(), std::slice::from_ref(&b));
        assert!(exists(&b.container));
        assert!(!exists(&a.container));
        let crash = r.x.events.args("session.crash").unwrap();
        assert_eq!(crash["task"], "agent.sock");
        assert_eq!(crash["reason"], "panic");
        assert_eq!(crash["payload"], "boom");
        let all = session_events(&r.x);
        let at = all.iter().position(|e| e == "session.crash").unwrap();
        assert_eq!(all.get(at + 1).map(String::as_str), Some("session.stop"));
        assert_eq!(stops(&r.x), ["crash"]);
        assert_eq!(
            r.reg.stop(&b.id, StopReason::Request).await,
            Some(StopOutcome::Stopped)
        );
    });
}

/// `runtime.timeout` (1m, the least the manifest allows): `session.timeout` before
/// `session.stop timeout`, and the container is gone.
#[test]
fn a_session_past_its_timeout_is_stopped() {
    rt().block_on(async {
        let r = registry();
        let v = Arc::new(r.x.f.load("runtime:\n  timeout: 1m\n"));
        let info = r.reg.start(v).await.unwrap();
        until("the timeout", Duration::from_secs(90), || {
            r.reg.list().is_empty()
        })
        .await;
        assert!(!exists(&info.container));
        let all = session_events(&r.x);
        let at = all.iter().position(|e| e == "session.timeout").unwrap();
        assert_eq!(all.get(at + 1).map(String::as_str), Some("session.stop"));
        assert_eq!(stops(&r.x), ["timeout"]);
        assert_eq!(
            r.x.events.args("session.timeout").unwrap()["timeout_secs"],
            60
        );
    });
}

/// Shutdown stops every live session `shutdown` and refuses new ones.
#[test]
fn shutdown_stops_every_session_and_refuses_new_ones() {
    rt().block_on(async {
        let r = registry();
        let v = Arc::new(r.x.f.load(""));
        let a = r.reg.start(Arc::clone(&v)).await.unwrap();
        let b = r.reg.start(Arc::clone(&v)).await.unwrap();
        assert!(r.reg.shutdown().await.is_empty());
        assert!(r.reg.list().is_empty());
        assert!(!exists(&a.container) && !exists(&b.container));
        assert_eq!(stops(&r.x), ["shutdown", "shutdown"]);
        let e = r.reg.start(v).await.unwrap_err();
        assert!(matches!(e, StartError::ShuttingDown), "{e}");
    });
}

/// Sends each of `lines` on `sock` and reads one reply line for each. Connects through an open
/// fd of the socket's directory: the fixture's paths are longer than `SUN_LEN`.
async fn exchange(sock: &Path, lines: &[Value]) -> Vec<Value> {
    let dir = std::fs::File::open(sock.parent().unwrap()).unwrap();
    let short = Path::new("/proc/self/fd")
        .join(std::os::fd::AsRawFd::as_raw_fd(&dir).to_string())
        .join(sock.file_name().unwrap());
    let s = tokio::net::UnixStream::connect(&short).await.unwrap();
    let (r, mut w) = s.into_split();
    let mut r = BufReader::new(r);
    let mut replies = Vec::new();
    for l in lines {
        w.write_all(format!("{l}\n").as_bytes()).await.unwrap();
        let mut reply = String::new();
        tokio::time::timeout(Duration::from_secs(10), r.read_line(&mut reply))
            .await
            .unwrap()
            .unwrap();
        replies.push(serde_json::from_str(&reply).unwrap());
    }
    replies
}

/// RT-AG-08 (foreign-id clause) through the registry, B live (#61): a request on A's
/// `agent.sock` naming B's session id in the arguments, in `_meta`, in `params` or as an extra
/// member reaches only A's tool handler, and every entry it causes carries A's id, never B's.
/// A and B grant `fs_list` over different directories at the same guest path, so the listing
/// shows whose tools served the call.
#[test]
fn rt_ag_08_a_foreign_session_id_reaches_only_its_own_session() {
    rt().block_on(async {
        let r = registry();
        let session = |dir: &str, file: &str| {
            let at = r.x.f.root.join(format!("home/code/{dir}"));
            std::fs::create_dir_all(&at).unwrap();
            std::fs::write(at.join(file), b"x").unwrap();
            Arc::new(r.x.f.load(&format!(
                "{}tools:\n  builtin: [fs_list]\n",
                mounts(&[mount(&format!("~/code/{dir}"), "/workspace/p", "ro")])
            )))
        };
        let a = r.reg.start(session("rt-a", "only-a.txt")).await.unwrap();
        let b = r.reg.start(session("rt-b", "only-b.txt")).await.unwrap();
        let sock = r.x.session_paths(&a.id).harness_sockets().join(AGENT_SOCK);
        let meta = json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
        });
        let mut foreign = meta.clone();
        foreign["session"] = json!(b.id);
        foreign["io.modelcontextprotocol/sessionId"] = json!(b.id);
        let mark = r.sink.debug.lock().unwrap().len();
        let replies = exchange(
            &sock,
            &[
                json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"_meta": foreign, "name": "fs_list",
                                  "arguments": {"path": "/workspace/p"}}}),
                json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                       "params": {"_meta": meta, "name": "fs_list",
                                  "arguments": {"path": "/workspace/p", "session": b.id}}}),
                json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                       "params": {"_meta": meta, "name": "fs_list", "session": b.id}}),
                json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "session": b.id,
                       "params": {"_meta": meta, "name": "fs_list"}}),
            ],
        )
        .await;
        // B's id in `_meta`: served by A's tools over A's mount. In the arguments: a denied call
        // (the tool's arguments are strict). In `params` or the request: malformed.
        assert_eq!(replies[0]["result"]["isError"], json!(false), "{replies:?}");
        let listing = replies[0]["result"]["content"][0]["text"].as_str().unwrap();
        assert!(listing.contains("only-a.txt"), "{listing}");
        assert!(!listing.contains("only-b.txt"), "{listing}");
        assert_eq!(replies[1]["result"]["isError"], json!(true), "{replies:?}");
        assert!(replies[2].get("error").is_some(), "{replies:?}");
        assert!(replies[3].get("error").is_some(), "{replies:?}");
        let caused: Vec<String> = r.sink.debug.lock().unwrap()[mark..].to_vec();
        assert!(caused.len() >= 4, "{caused:#?}");
        let own = format!("session: Some({:?})", a.id);
        assert!(caused.iter().all(|d| d.contains(&own)), "{caused:#?}");
        let theirs = format!("session: Some({:?})", b.id);
        assert!(!caused.iter().any(|d| d.contains(&theirs)), "{caused:#?}");
        for s in [&a, &b] {
            assert_eq!(
                r.reg.stop(&s.id, StopReason::Request).await,
                Some(StopOutcome::Stopped)
            );
        }
    });
}

/// #103 (architect ruling on #75 part 2): production hands each session's tools its own proxy's
/// connector. (a) A proxy-mode session granting `fetch` lists it; (b) a GET through `agent.sock`
/// reaches the fixture's TLS upstream, and the proxy's `egress.allow` carries `origin` under
/// this session's id: so the connector is this session's proxy, not merely `Some`. (c) Fetch
/// granted with `network.mode: none` (no proxy, so no connector): unlisted, a call is
/// `tool_unavailable` with `tool.deny`. (d) Not granted in proxy mode: unlisted. Fails without
/// the `fetch:` expression in `Registry::agent` (a, b) or with `Running::fetch_connector`
/// answering `None` (a, b); (c) fails if it ever answers `Some` without a proxy.
#[test]
fn a_session_fetches_through_its_own_proxy_and_only_with_one() {
    rt().block_on(async {
        let r = registry();
        r.x.egress
            .resolver
            .set("mock.test", vec![vec![tls_upstream()]]);
        let list = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list",
                          "params": {"_meta": meta()}});
        let get = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                         "params": {"_meta": meta(), "name": "fetch",
                                    "arguments": {"url": "https://mock.test/"}}});
        let names = |reply: &Value| -> Vec<String> {
            reply["result"]["tools"]
                .as_array()
                .unwrap()
                .iter()
                .map(|t| t["name"].as_str().unwrap().to_owned())
                .collect()
        };
        let start = |body: &str| r.reg.start(Arc::new(r.x.f.load(body)));
        let sock = |id: &str| r.x.session_paths(id).harness_sockets().join(AGENT_SOCK);

        // (a), (b)
        let net = "network:\n  mode: proxy\n  allow:\n    - host: mock.test\n";
        let a = start(&format!("{net}tools:\n  builtin: [fetch]\n"))
            .await
            .unwrap();
        let mark = r.sink.debug.lock().unwrap().len();
        let replies = exchange(&sock(&a.id), &[list.clone(), get.clone()]).await;
        assert_eq!(names(&replies[0]), ["fetch"], "{replies:?}");
        assert_eq!(replies[1]["result"]["isError"], json!(false), "{replies:?}");
        let text = replies[1]["result"]["content"][0]["text"].as_str().unwrap();
        let out: Value = serde_json::from_str(text).unwrap();
        assert_eq!(out["status"], json!(200), "{out}");
        assert_eq!(out["body"], json!("ok"), "{out}");
        // The proxy writes through the launcher's sink (`r.x.events`), the tools through the
        // registry's (`r.sink`). One `egress.allow` in all, the fetch's, and it is A's.
        let allows: Vec<Value> =
            r.x.events
                .all()
                .into_iter()
                .filter(|(e, _)| e == "egress.allow")
                .map(|(_, a)| a)
                .collect();
        assert_eq!(allows.len(), 1, "{allows:#?}");
        assert_eq!(allows[0]["origin"]["tool"], json!("fetch"), "{allows:#?}");
        assert!(allows[0]["origin"]["call"].is_u64(), "{allows:#?}");
        let own = format!("session: Some({:?})", a.id);
        let debug = r.x.events.debug();
        let allow = debug.iter().find(|d| d.contains("\"egress.allow\""));
        assert!(allow.is_some_and(|d| d.contains(&own)), "{debug:#?}");
        let caused: Vec<String> = r.sink.debug.lock().unwrap()[mark..].to_vec();
        assert!(caused.iter().all(|d| d.contains(&own)), "{caused:#?}");

        // (c)
        let c = start("tools:\n  builtin: [fetch]\n").await.unwrap();
        let replies = exchange(&sock(&c.id), &[list.clone(), get.clone()]).await;
        assert!(names(&replies[0]).is_empty(), "{replies:?}");
        assert_eq!(replies[1]["result"]["isError"], json!(true), "{replies:?}");
        let text = replies[1]["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("tool_unavailable"), "{text}");
        assert!(
            r.x.events
                .all()
                .iter()
                .any(|(e, a)| e == "tool.deny" && a.to_string().contains("tool_unavailable")),
            "{:#?}",
            r.x.events.all()
        );

        // (d)
        let d = start(&format!("{net}tools:\n  builtin: [fs_list]\n"))
            .await
            .unwrap();
        let replies = exchange(&sock(&d.id), &[list]).await;
        assert_eq!(names(&replies[0]), ["fs_list"], "{replies:?}");

        for s in [&a, &c, &d] {
            assert_eq!(
                r.reg.stop(&s.id, StopReason::Request).await,
                Some(StopOutcome::Stopped)
            );
        }
    });
}

/// RT-AG-15 (architect Q59; the maintainer's rule: once stop returns, nothing from the session
/// has any further effect): a command running when the stop comes is killed by it, and its
/// `tool.result` (`killed: session-stop`) is written before the session's `session.stop
/// {in_flight: 0}`; after that entry no tool, approval or rpc entry of the session follows, and
/// no process of the call is left. TODO(#65): a prompt pending at the stop joins this test once
/// PR B gives the desk an approver (until then every prompt is denied `no-approver`); the
/// withdraw and the parked write are unit-tested (`approvals::queue_tests`, `tools::tests`).
#[test]
fn rt_ag_15_nothing_of_a_session_follows_its_stop() {
    rt().block_on(async {
        let r = registry();
        let at = r.x.f.root.join("home/code/rt15");
        std::fs::create_dir_all(&at).unwrap();
        let v = Arc::new(r.x.f.load(&format!(
            "{}tools:\n  builtin: [fs_list, fs_write, shell]\n  shell: allow\n",
            mounts(&[mount("~/code/rt15", "/workspace/p", "rw")])
        )));
        let s = r.reg.start(v).await.unwrap();
        let sock = r.x.session_paths(&s.id).harness_sockets().join(AGENT_SOCK);
        let dir = std::fs::File::open(sock.parent().unwrap()).unwrap();
        let short = Path::new("/proc/self/fd")
            .join(std::os::fd::AsRawFd::as_raw_fd(&dir).to_string())
            .join(AGENT_SOCK);
        let mut conn = tokio::net::UnixStream::connect(&short).await.unwrap();
        let meta = json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
        });
        let call = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"_meta": meta, "name": "shell",
                       "arguments": {"cmd": ["sleep", "307"], "cwd": "/workspace/p"}}});
        conn.write_all(format!("{call}\n").as_bytes())
            .await
            .unwrap();
        until("the command runs", Duration::from_secs(30), || {
            let (_, ps) = exec_in(&s.container, &["ps", "-o", "args"]);
            ps.lines().any(|l| l.trim() == "sleep 307")
        })
        .await;
        assert_eq!(
            r.reg.stop(&s.id, StopReason::Request).await,
            Some(StopOutcome::Stopped)
        );
        let all = r.x.events.all();
        let stop = all
            .iter()
            .position(|(e, _)| e == "session.stop")
            .expect("session.stop");
        assert_eq!(all[stop].1["in_flight"], 0, "{all:#?}");
        let result = all
            .iter()
            .position(|(e, a)| e == "tool.result" && a["tool"] == "shell")
            .expect("the command's tool.result");
        assert!(result < stop, "{all:#?}");
        assert_eq!(all[result].1["killed"], "session-stop");
        let after: Vec<&String> = all[stop + 1..].iter().map(|(e, _)| e).collect();
        assert!(
            after.iter().all(|e| e.starts_with("sandbox.")),
            "entries after session.stop: {after:?}"
        );
        assert!(!exists(&s.container));
        let left = std::fs::read_dir("/proc")
            .unwrap()
            .flatten()
            .filter_map(|e| std::fs::read(e.path().join("cmdline")).ok())
            .filter(|c| c.as_slice() == b"sleep\x00307\x00")
            .count();
        assert_eq!(left, 0, "a process of the call is left");
        drop(conn);
    });
}

/// Entries the harness's own actions cause (sealed at `session.stop`, ruling 1 / Q63).
fn agent_originated(event: &str) -> bool {
    ["tool.", "approval.", "rpc."]
        .iter()
        .any(|p| event.starts_with(p))
}

/// The agent-originated entries after `session.stop`, which must be none.
fn after_stop(x: &Lx) -> (usize, Vec<String>) {
    let all = x.events.list();
    let stop = all
        .iter()
        .position(|e| e == "session.stop")
        .expect("session.stop");
    let after = all[stop + 1..]
        .iter()
        .filter(|e| agent_originated(e))
        .cloned()
        .collect();
    (stop, after)
}

/// A connection to `sock` through a short `/proc/self/fd` path, and the directory fd that keeps
/// the path valid.
async fn connect(sock: &Path) -> (tokio::net::UnixStream, std::fs::File) {
    let dir = std::fs::File::open(sock.parent().unwrap()).unwrap();
    let short = Path::new("/proc/self/fd")
        .join(std::os::fd::AsRawFd::as_raw_fd(&dir).to_string())
        .join(AGENT_SOCK);
    (tokio::net::UnixStream::connect(&short).await.unwrap(), dir)
}

fn meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
    })
}

/// #91 (ruling 1, Q63): a connection task's `rpc.request` whose append is still running when the
/// listener aborts the task at its grace lands before `session.stop`, never after it. Control:
/// the seal (`session.stop` written through the session's handle after its writes in flight).
#[test]
fn rt_ag_15_an_rpc_entry_being_written_at_the_stop_lands_before_session_stop() {
    rt().block_on(async {
        let r = registry();
        let v = Arc::new(r.x.f.load("tools:\n  builtin: [fs_list]\n"));
        let s = r.reg.start(v).await.unwrap();
        let sock = r.x.session_paths(&s.id).harness_sockets().join(AGENT_SOCK);
        let (mut conn, _dir) = connect(&sock).await;
        r.x.events.hold(&["rpc.request"]);
        let call = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list",
                          "params": {"_meta": meta()}});
        conn.write_all(format!("{call}\n").as_bytes())
            .await
            .unwrap();
        r.x.events.until_parked("rpc.request", 1).await;
        let reg = Arc::clone(&r.reg);
        let id = s.id.clone();
        let stop = tokio::spawn(async move { reg.stop(&id, StopReason::Request).await });
        // Past the listener's grace (2 s), which aborts the connection task.
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert!(
            !r.x.events.list().contains(&"session.stop".to_owned()),
            "session.stop was written while an entry of the session was still being written"
        );
        r.x.events.hold(&[]);
        assert_eq!(stop.await.unwrap(), Some(StopOutcome::Stopped));
        let (stop_at, after) = after_stop(&r.x);
        let all = r.x.events.list();
        let request = all
            .iter()
            .position(|e| e == "rpc.request")
            .expect("rpc.request");
        assert!(request < stop_at, "{all:?}");
        assert!(after.is_empty(), "after session.stop: {after:?}");
        drop(conn);
    });
}

/// Security re-review S6, architect Q68: the session's operations close before anything else
/// in its stop (Q59 step 1). Two-phase hold: the `shell` call's `rpc.request` is held first, so
/// the call is past its last write before the tools when the stop comes; then the supervisor is
/// held in its `session.crash` append (step 2), with the listener still up, while that
/// `rpc.request` lands. The call reaches the tools during step 2 and is denied
/// `session-stopping`: no `tool.run`, no effect, and its `tool.deny` precedes `session.stop`.
/// Control: `ops.close()` before the first await in `session/supervise.rs` (without it the call
/// enters, and `tool.run` is written). Each held write holds the seal's order, so the call's
/// later entries are checked after the release.
#[test]
fn rt_ag_15_a_call_during_the_stop_is_denied_before_anything_runs() {
    rt().block_on(async {
        let r = registry();
        let at = r.x.f.root.join("home/code/rt15c");
        std::fs::create_dir_all(&at).unwrap();
        let v = Arc::new(r.x.f.load(&format!(
            "{}tools:\n  builtin: [shell]\n  shell: allow\n",
            mounts(&[mount("~/code/rt15c", "/workspace/p", "rw")])
        )));
        let s = r.reg.start(v).await.unwrap();
        let sock = r.x.session_paths(&s.id).harness_sockets().join(AGENT_SOCK);
        let (mut conn, _dir) = connect(&sock).await;
        // Phase 1: the call's `rpc.request` waits in the sink, holding the seal's order.
        r.x.events.hold(&["rpc.request", "session.crash"]);
        let call = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"_meta": meta(), "name": "shell",
                       "arguments": {"cmd": ["touch", "/workspace/p/made"],
                                     "cwd": "/workspace/p"}}});
        conn.write_all(format!("{call}\n").as_bytes())
            .await
            .unwrap();
        r.x.events.until_parked("rpc.request", 1).await;
        // The stop: the supervisor closes the operations; its `session.crash` waits for the order.
        let crash = r.reg.reporter(&s.id).expect("the session's reporter");
        crash.spawn("tool", async { panic!("a session task panicked") });
        // The supervisor closes the operations (step 1, before any await), then logs the panic
        // and appends `session.crash`, which waits for the order the parked `rpc.request` holds
        // (so it cannot park yet): the oplog line shows step 1 is done.
        r.until_logged("session task panicked").await;
        // Phase 2: `rpc.request` lands; `session.crash` takes the order and waits in the sink,
        // so the supervisor is held in step 2 while the call goes on to the tools.
        r.x.events.hold(&["session.crash"]);
        until(
            "the call's rpc.request lands",
            Duration::from_secs(10),
            || r.x.events.list().iter().any(|e| e == "rpc.request"),
        )
        .await;
        r.x.events.until_parked("session.crash", 1).await;
        // The call goes on to the tools meanwhile; its entries wait for the order, so there is
        // nothing to observe until the release: give it the time.
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert!(!r.x.events.list().contains(&"session.stop".to_owned()));
        r.x.events.hold(&[]);
        until("the session ends", Duration::from_secs(60), || {
            !exists(&s.container)
        })
        .await;
        let all = r.x.events.all();
        let (stop_at, after) = after_stop(&r.x);
        assert!(after.is_empty(), "after session.stop: {after:?}");
        assert_eq!(all[stop_at].1["reason"], "crash", "{all:#?}");
        let denied = all
            .iter()
            .position(|(e, a)| e == "tool.deny" && a["code"] == "session-stopping")
            .unwrap_or_else(|| panic!("no tool.deny session-stopping: {all:#?}"));
        assert!(denied < stop_at, "{all:#?}");
        assert!(
            !all.iter().any(|(e, _)| e == "tool.run"),
            "the call ran: {all:#?}"
        );
        assert!(!at.join("made").exists(), "the command had an effect");
        drop(conn);
    });
}

/// An oplog writer the test reads back.
#[derive(Clone, Default)]
struct Lines(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Lines {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Ruling 1 with `in_flight > 0` (Q63), and Q67. A write whose `tool.run` append is still
/// running past the drain keeps the operation in flight: `session.stop {in_flight: 1}` follows
/// that `tool.run`, the stop answers failed, the write aborts without touching the file, and its
/// `tool.result` is refused by the seal (an oplog line names it). A session task that panics
/// during this request stop is audited `session.crash` before `session.stop`, whose reason stays
/// `request`. Nothing agent-originated follows `session.stop`; the supervisor then removes the
/// container by itself.
#[test]
fn rt_ag_15_an_operation_past_the_drain_and_a_panic_during_the_stop_end_before_session_stop() {
    rt().block_on(async {
        let x = Lx::new();
        let sink = Arc::new(Hooked {
            events: x.events.clone(),
            sockets: x.xdg.join("sallyport/sessions"),
            hook: Mutex::new(None),
            debug: Mutex::new(Vec::new()),
        });
        let lines = Lines::default();
        let log = sallyd::oplog::Oplog::new(lines.clone());
        let reg = x.registry_logged(sink, Some(test_image()), log.clone());
        let at = x.f.root.join("home/code/rt15b");
        std::fs::create_dir_all(&at).unwrap();
        let v = Arc::new(x.f.load(&format!(
            "{}tools:\n  builtin: [fs_write]\n",
            mounts(&[mount("~/code/rt15b", "/workspace/p", "rw")])
        )));
        let s = reg.start(v).await.unwrap();
        let sock = x.session_paths(&s.id).harness_sockets().join(AGENT_SOCK);
        let (mut conn, _dir) = connect(&sock).await;
        x.events.hold(&["tool.run"]);
        let call = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"_meta": meta(), "name": "fs_write",
                       "arguments": {"path": "/workspace/p/late.txt", "content_b64": "bGF0ZQ=="}}});
        conn.write_all(format!("{call}\n").as_bytes())
            .await
            .unwrap();
        until("the write's section runs", Duration::from_secs(10), || {
            x.events
                .list()
                .iter()
                .filter(|e| *e == "rpc.request")
                .count()
                == 1
        })
        .await;
        x.events.until_parked("tool.run", 1).await;
        let stopping = {
            let reg = Arc::clone(&reg);
            let id = s.id.clone();
            tokio::spawn(async move { reg.stop(&id, StopReason::Request).await })
        };
        tokio::time::sleep(Duration::from_millis(500)).await;
        let crash = reg.reporter(&s.id).expect("the session's reporter");
        crash.spawn("tool", async {
            panic!("a tool task panicked during the stop")
        });
        // Past the drain (5 s): the operation is still in flight, its entry still being written.
        tokio::time::sleep(Duration::from_secs(6)).await;
        assert!(!x.events.list().contains(&"session.stop".to_owned()));
        x.events.hold(&[]);
        let outcome = stopping.await.unwrap();
        assert!(
            matches!(outcome, Some(StopOutcome::Failed(ref w)) if w.contains("1 operations")),
            "{outcome:?}"
        );
        until("the container is gone", Duration::from_secs(60), || {
            !exists(&s.container)
        })
        .await;
        let all = x.events.all();
        let (stop_at, after) = after_stop(&x);
        assert!(after.is_empty(), "after session.stop: {after:?}");
        assert_eq!(all[stop_at].1["in_flight"], 1, "{all:#?}");
        assert_eq!(all[stop_at].1["reason"], "request", "{all:#?}");
        let run = all
            .iter()
            .position(|(e, _)| e == "tool.run")
            .expect("tool.run");
        let crashed = all
            .iter()
            .position(|(e, _)| e == "session.crash")
            .expect("session.crash");
        assert!(run < stop_at && crashed < stop_at, "{all:#?}");
        assert_eq!(all[crashed].1["task"], "tool");
        assert!(
            !at.join("late.txt").exists(),
            "the aborted write touched the file"
        );
        // Its `tool.result` races the seal for the order once the hold ends: either it landed
        // before `session.stop` (as aborted) or the seal refused it with an oplog line (the
        // refusal itself is pinned in `rpc::record`'s unit tests).
        assert!(log.flush(Duration::from_secs(5)));
        let text = String::from_utf8(lines.0.lock().unwrap().clone()).unwrap();
        let refused = text
            .lines()
            .any(|l| l.contains("entry refused after session.stop") && l.contains("tool.result"));
        match all.iter().position(|(e, _)| e == "tool.result") {
            Some(i) => {
                assert!(i < stop_at, "{all:#?}");
                assert_eq!(all[i].1["outcome"], "aborted", "{all:#?}");
            }
            None => assert!(refused, "{text}"),
        }
        drop(conn);
    });
}
