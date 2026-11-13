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
use sallyd::session::{AGENT_SOCK, Registry, StartError, StopOutcome, StopReason};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

mod common;
use common::container::*;
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
    let reg = x.registry(sink.clone(), default_image);
    Rx { x, reg, sink }
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

/// A failed `session.start` append binds nothing and stops the workspace; with no
/// `session.start` there is no `session.stop`.
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
        assert_eq!(session_events(&r.x), ["sandbox.launch", "sandbox.stop"]);
        let names = podman(&["ps", "-a", "--format", "{{.Names}}"]);
        let names = String::from_utf8_lossy(&names.stdout);
        assert!(!names.contains(&r.x.scope), "{names}");
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
#[test]
fn rt_ag_08_a_foreign_session_id_reaches_only_its_own_session() {
    rt().block_on(async {
        let r = registry();
        let v = Arc::new(r.x.f.load(""));
        let a = r.reg.start(Arc::clone(&v)).await.unwrap();
        let b = r.reg.start(v).await.unwrap();
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
                                  "arguments": {"session": b.id}}}),
                json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                       "params": {"_meta": meta, "name": "fs_list", "session": b.id}}),
                json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "session": b.id,
                       "params": {"_meta": meta, "name": "fs_list"}}),
            ],
        )
        .await;
        // The first is a call (A's tools deny an ungranted tool); the others are malformed.
        assert_eq!(replies[0]["result"]["isError"], json!(true), "{replies:?}");
        assert!(replies[1].get("error").is_some(), "{replies:?}");
        assert!(replies[2].get("error").is_some(), "{replies:?}");
        let caused: Vec<String> = r.sink.debug.lock().unwrap()[mark..].to_vec();
        assert!(caused.len() >= 3, "{caused:#?}");
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
