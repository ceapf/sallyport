//! The built-in tools behind the approvals gate (ARCHITECTURE §4.3; Task 11): `fs_list`,
//! `fs_read`, `fs_write`, `fs_delete` and `shell`, as one [`Executor`].
//!
//! - **List.** `tools/list` shows the tools the manifest grants, never `fetch` (#75).
//! - **Prepare** (no effect): the grant first, so an ungranted tool is `tool_not_granted` and no
//!   existence oracle (architect ruling Q28); then the arguments (`args.rs`), the path
//!   (`path.rs`), a `.git` component for writes and deletes (`protected-path`, #19), and the
//!   file system as the effect will see it (`fs.rs`), so nobody is asked about an action that
//!   cannot run. `shell` gets its `destructive` tag (`tag.rs`).
//! - **Run** (the ticket only): reads write `tool.read` (path, size, bytes, sha256; never the
//!   content) once the bytes are in memory and before the reply; writes, deletes and commands
//!   write `tool.run` before the effect and `tool.result` after it, at every `audit.level`
//!   (architect ruling Q34). A failed append runs nothing more and answers nothing (`None`).
//!   Writes and deletes on `rw`/`staged` mounts hold the session's exec gate for the whole
//!   operation, so the disk watchdog never walks a tree the broker is changing (ruling Q29).

pub mod args;
pub mod dac;
pub mod exec;
pub mod fetch;
pub mod fetch_client;
pub mod fetch_url;
pub mod fs;
pub mod ops;
pub mod path;
pub mod procs;
pub mod shell;
pub mod tag;

use std::path::PathBuf;
use std::sync::Arc;

use base64::Engine as _;
use rustix::fd::OwnedFd;
use sally_core::audit::Actor;
use sally_core::manifest::{BuiltinTool, MountMode, ValidatedManifest};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};

use crate::approvals::action::{Action, Bound, Payload, Target, hex};
use crate::approvals::queue::fields;
use crate::approvals::{Executor, Prepared, Ticket};
use crate::daemon::crash::CrashReporter;
use crate::egress::local::Connector;
use crate::rpc::mcp::{Tool, ToolOutcome};
use crate::rpc::record::{Recorder, escape};
use crate::sandbox::UserIds;
use args::Args;
use fs::{FsError, RootSource};
use ops::Ops;
use shell::{Output, Runner, Status};

/// The code of a call refused, or a write aborted, because its session is stopping (Q59).
pub const STOPPING: &str = "session-stopping";

/// Every built-in tool, in `tools/list` order.
const ALL: [BuiltinTool; 6] = [
    BuiltinTool::FsList,
    BuiltinTool::FsRead,
    BuiltinTool::FsWrite,
    BuiltinTool::FsDelete,
    BuiltinTool::Shell,
    BuiltinTool::Fetch,
];

/// One mount, as the tools reach it.
#[derive(Debug, Clone)]
pub struct Mount {
    /// Guest root.
    pub guest: String,
    /// Host realpath of the root.
    pub host: PathBuf,
    /// Access mode.
    pub mode: MountMode,
    /// Where its files are reached.
    pub root: RootSource,
}

/// The session's mounts as the tools reach them: `brokered` and `ro` on the host pin, `rw` and
/// `staged` in the workspace through `init_dir` (the container init's `/proc/<pid>`).
#[must_use]
pub fn mounts(v: &ValidatedManifest, init_dir: &Arc<OwnedFd>) -> Vec<Mount> {
    v.mounts()
        .iter()
        .map(|m| {
            let (dev, ino) = m.identity();
            let root = match m.mode {
                MountMode::Ro | MountMode::Brokered => RootSource::Host {
                    path: m.host.clone(),
                    dev,
                    ino,
                },
                MountMode::Rw => RootSource::Bind {
                    proc_dir: Arc::clone(init_dir),
                    guest: m.guest.clone(),
                    dev,
                    ino,
                },
                MountMode::Staged => RootSource::Overlay {
                    proc_dir: Arc::clone(init_dir),
                    guest: m.guest.clone(),
                },
            };
            Mount {
                guest: m.guest.clone(),
                host: m.host.clone(),
                mode: m.mode,
                root,
            }
        })
        .collect()
}

/// What the tools of one session are built from.
pub struct Parts<R> {
    /// `tools.builtin`.
    pub builtin: Vec<BuiltinTool>,
    /// The mounts ([`mounts`]).
    pub mounts: Vec<Mount>,
    /// The session's audit recorder.
    pub record: Recorder,
    /// The session's exec gate (`Running::exec_gate`).
    pub exec_gate: Arc<tokio::sync::Mutex<()>>,
    /// The session's operations, closed and drained by its stop (architect Q59).
    pub ops: Ops,
    /// The session's crash reporter: each run section is a task of its own.
    pub crash: CrashReporter,
    /// The sandbox's identity, the launcher's own `UserIds` (the `--user` of the workspace): every
    /// file object is judged by it (architect ruling Q39). Never read from `getuid` here.
    pub ids: UserIds,
    /// Runs `shell` commands ([`exec::PodmanExec`] in production).
    pub shell: R,
    /// The way out for `fetch`: `None` leaves a granted `fetch` unlisted and `tool_unavailable`
    /// (architect ruling Q8: a session without a proxy, or without trust roots).
    pub fetch: Option<FetchParts>,
}

/// What `fetch` runs through.
#[derive(Clone)]
pub struct FetchParts {
    /// The session proxy's connector (`EgressHandle::connector`).
    pub connector: Arc<dyn Connector>,
    /// `network.max_request_bytes`.
    pub max_request: u64,
    /// `network.max_response_bytes`.
    pub max_response: u64,
}

/// The built-in tools of one session.
pub struct Tools<R> {
    core: Arc<Core<R>>,
    crash: CrashReporter,
}

/// What a run section needs, shared with its task.
struct Core<R> {
    builtin: Vec<BuiltinTool>,
    mounts: Vec<Mount>,
    record: Recorder,
    gate: Arc<tokio::sync::Mutex<()>>,
    ops: Ops,
    ids: UserIds,
    shell: R,
    fetch: Option<FetchParts>,
}

impl<R: Runner> Tools<R> {
    /// The tools of a session.
    #[must_use]
    pub fn new(p: Parts<R>) -> Self {
        Self {
            core: Arc::new(Core {
                builtin: p.builtin,
                mounts: p.mounts,
                record: p.record,
                gate: p.exec_gate,
                ops: p.ops,
                ids: p.ids,
                shell: p.shell,
                fetch: p.fetch,
            }),
            crash: p.crash,
        }
    }
}

fn mode_str(m: MountMode) -> &'static str {
    match m {
        MountMode::Ro => "ro",
        MountMode::Rw => "rw",
        MountMode::Brokered => "brokered",
        MountMode::Staged => "staged",
    }
}

/// Runs `f` on the opened root of `src` (objects judged as `ids`), off the runtime.
async fn on_root<T: Send + 'static>(
    src: &RootSource,
    ids: UserIds,
    f: impl FnOnce(&fs::Root) -> Result<T, FsError> + Send + 'static,
) -> Result<T, FsError> {
    let src = src.clone();
    tokio::task::spawn_blocking(move || f(&src.open(ids)?))
        .await
        .unwrap_or(Err(FsError::Io(rustix::io::Errno::IO)))
}

fn add(v: &mut Value, key: &str, value: Value) {
    if let Some(o) = v.as_object_mut() {
        o.insert(key.to_owned(), value);
    }
}

fn sha256(b: &[u8]) -> String {
    hex(&Sha256::digest(b))
}

fn failed(code: &str) -> ToolOutcome {
    ToolOutcome {
        is_error: true,
        text: format!("failed: {code}"),
    }
}

fn reply(v: &Value) -> ToolOutcome {
    ToolOutcome {
        is_error: false,
        text: v.to_string(),
    }
}

impl<R: Runner> Core<R> {
    fn mount_of(&self, guest: &str) -> Option<&Mount> {
        self.mounts.iter().find(|m| m.guest == guest)
    }

    /// The target `path` names, with its mount.
    fn target(&self, path: &str, root_ok: bool) -> Result<(&Mount, Target), &'static str> {
        let guests: Vec<&str> = self.mounts.iter().map(|m| m.guest.as_str()).collect();
        let at = path::locate(&guests, path, root_ok).map_err(path::PathError::code)?;
        let m = self.mounts.get(at.mount).ok_or("path_escapes_mount")?;
        let host = fs::host_path(&m.host, &at.rel);
        Ok((
            m,
            Target {
                mount: m.guest.clone(),
                rel: at.rel,
                host,
            },
        ))
    }

    /// A write or delete target: not under `.git`, and on a mount that takes writes (on `ro`
    /// the policy refuses it, with its own entry, so no file is looked at).
    async fn effect_target(
        &self,
        path: &str,
        check: fn(&fs::Root, &str, bool) -> Result<(), FsError>,
    ) -> Result<Target, &'static str> {
        let (m, t) = self.target(path, false)?;
        if path::protected(&t.rel) {
            return Err("protected-path");
        }
        if m.mode != MountMode::Ro {
            let (rel, brokered) = (t.rel.clone(), m.mode == MountMode::Brokered);
            on_root(&m.root, self.ids, move |r| check(r, &rel, brokered))
                .await
                .map_err(FsError::code)?;
        }
        Ok(t)
    }

    async fn record(&self, actor: Actor, event: &str, decision: Option<&str>, args: Value) -> bool {
        let e = self.record.entry(actor, event, decision).args(args);
        self.record.append(e).await
    }

    async fn run_read(
        &self,
        b: &Bound,
        m: &Mount,
        t: &Target,
        offset: u64,
        len: u64,
    ) -> Option<ToolOutcome> {
        let rel = t.rel.clone();
        let res = on_root(&m.root, self.ids, move |r| fs::read(r, &rel, offset, len)).await;
        let mut f = fields(b);
        add(&mut f, "mode", Value::from(mode_str(m.mode)));
        add(&mut f, "offset", Value::from(offset));
        add(&mut f, "len", Value::from(len));
        let out = match res {
            Ok(r) => {
                add(&mut f, "size", Value::from(r.size));
                add(&mut f, "bytes", Value::from(r.bytes.len()));
                add(&mut f, "sha256", Value::from(sha256(&r.bytes)));
                let (encoding, content) = match String::from_utf8(r.bytes) {
                    Ok(s) => ("utf-8", s),
                    Err(e) => (
                        "base64",
                        base64::engine::general_purpose::STANDARD.encode(e.into_bytes()),
                    ),
                };
                reply(&json!({
                    "path": t.guest(), "size": r.size, "offset": offset,
                    "encoding": encoding, "content": content,
                }))
            }
            Err(e) => {
                add(&mut f, "code", Value::from(e.code()));
                failed(e.code())
            }
        };
        self.record(Actor::Harness, "tool.read", Some("allow"), f)
            .await
            .then_some(out)
    }

    async fn run_list(&self, b: &Bound, m: &Mount, t: &Target) -> Option<ToolOutcome> {
        let rel = t.rel.clone();
        let res = on_root(&m.root, self.ids, move |r| fs::list(r, &rel)).await;
        let mut f = fields(b);
        add(&mut f, "mode", Value::from(mode_str(m.mode)));
        let out = match res {
            Ok(l) => {
                let entries: Vec<Value> = l
                    .entries
                    .iter()
                    .map(|e| json!({"name": e.name, "kind": e.kind, "size": e.size}))
                    .collect();
                let body = json!({
                    "path": t.guest(), "entries": entries,
                    "truncated": l.truncated, "unlisted": l.unlisted,
                });
                add(&mut f, "entries", Value::from(l.entries.len()));
                add(&mut f, "truncated", Value::from(l.truncated));
                add(
                    &mut f,
                    "sha256",
                    Value::from(sha256(body.to_string().as_bytes())),
                );
                reply(&body)
            }
            Err(e) => {
                add(&mut f, "code", Value::from(e.code()));
                failed(e.code())
            }
        };
        self.record(Actor::Harness, "tool.read", Some("allow"), f)
            .await
            .then_some(out)
    }

    /// `fs_write` (`content: Some`) or `fs_delete`: `tool.run`, the effect, `tool.result`.
    async fn run_file(
        &self,
        ticket: &Ticket,
        m: &Mount,
        t: &Target,
        content: Option<&Payload>,
    ) -> Option<ToolOutcome> {
        let b = ticket.bound();
        let mut f = fields(b);
        add(
            &mut f,
            "approval",
            ticket.approval().map_or(Value::Null, Value::from),
        );
        add(&mut f, "mode", Value::from(mode_str(m.mode)));
        if let Some(c) = content {
            add(&mut f, "bytes", Value::from(c.len()));
            add(&mut f, "sha256", Value::from(c.sha256()));
        }
        if !self
            .record(Actor::Harness, "tool.run", Some("allow"), f)
            .await
        {
            return None;
        }
        let brokered = m.mode == MountMode::Brokered;
        // In the workspace's view the watchdog may be walking the same tree: hold the gate. The
        // guard moves into the blocking work, so a dropped call cannot release it while the
        // write still runs (rust review M5). A stop while it waits aborts it (Q59 (b)).
        let held = if brokered {
            None
        } else {
            tokio::select! {
                biased;
                () = self.ops.stopped() => return self.aborted(b).await,
                g = Arc::clone(&self.gate).lock_owned() => Some(g),
            }
        };
        // The last point before the effect: once it begins it runs to its end.
        if self.ops.is_closed() {
            return self.aborted(b).await;
        }
        let rel = t.rel.clone();
        let res = match content {
            Some(c) => {
                let bytes = c.bytes().to_vec();
                on_root(&m.root, self.ids, move |r| {
                    let _held = held;
                    fs::write(r, &rel, &bytes, brokered)
                })
                .await
            }
            None => {
                on_root(&m.root, self.ids, move |r| {
                    let _held = held;
                    fs::delete(r, &rel)
                })
                .await
            }
        };
        let mut r = json!({"call": b.call, "tool": b.action.tool(), "action_sha256": b.digest()});
        let out = match res {
            Ok(()) => {
                add(&mut r, "outcome", Value::from("ok"));
                let mut body = json!({"path": t.guest()});
                match content {
                    Some(c) => add(&mut body, "bytes", Value::from(c.len())),
                    None => add(&mut body, "deleted", Value::from(true)),
                }
                reply(&body)
            }
            Err(e) => {
                add(&mut r, "outcome", Value::from("failed"));
                add(&mut r, "code", Value::from(e.code()));
                failed(e.code())
            }
        };
        self.record(Actor::Sallyd, "tool.result", None, r)
            .await
            .then_some(out)
    }

    /// The `tool.result` of a write or delete the session's stop kept from beginning.
    async fn aborted(&self, b: &Bound) -> Option<ToolOutcome> {
        let r = json!({
            "call": b.call, "tool": b.action.tool(), "action_sha256": b.digest(),
            "outcome": "aborted", "reason": ops::SESSION_STOP,
        });
        self.record(Actor::Sallyd, "tool.result", None, r)
            .await
            .then(|| failed(STOPPING))
    }

    /// The `tool.deny` of a call that arrived once the session's operations were closed.
    async fn stopping(&self, b: &Bound) -> Option<ToolOutcome> {
        let args = json!({"call": b.call, "tool": b.action.tool(), "code": STOPPING});
        self.record(Actor::Sallyd, "tool.deny", Some("deny"), args)
            .await
            .then(|| ToolOutcome {
                is_error: true,
                text: format!("denied: {STOPPING}"),
            })
    }

    async fn run_shell(&self, ticket: &Ticket, argv: &[String], cwd: &str) -> Option<ToolOutcome> {
        let b = ticket.bound();
        let mut f = fields(b);
        add(
            &mut f,
            "approval",
            ticket.approval().map_or(Value::Null, Value::from),
        );
        if !self
            .record(Actor::Harness, "tool.run", Some("allow"), f)
            .await
        {
            return None;
        }
        let o = self.shell.run(argv, cwd).await;
        let mut r = json!({"call": b.call, "tool": "shell", "action_sha256": b.digest()});
        for (name, c) in [("stdout", &o.stdout), ("stderr", &o.stderr)] {
            add(
                &mut r,
                name,
                json!({"bytes": c.total, "kept": c.kept.len(), "sha256": sha256(&c.kept), "cut": c.cut()}),
            );
        }
        let (exit, killed) = match &o.status {
            Status::Exited(c) => (Value::from(*c), Value::Null),
            Status::Killed(why) => (Value::Null, Value::from(*why)),
            Status::Failed(e) => {
                add(&mut r, "error", Value::from(escape(e.as_bytes())));
                (Value::Null, Value::Null)
            }
        };
        add(&mut r, "exit", exit.clone());
        add(&mut r, "killed", killed.clone());
        if !self.record(Actor::Sallyd, "tool.result", None, r).await {
            return None;
        }
        Some(shell_reply(&o, exit, killed))
    }

    /// `fetch` at prepare: the URL first (its host names the grants), then the checks of
    /// `fetch.rs`; the action binds the canonical URL (architect ruling Q4) and, for a grant host,
    /// the note names the credentials the proxy adds, never a value (Q3).
    fn prepare_fetch(
        &self,
        url: &str,
        method: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) -> Result<Prepared, &'static str> {
        let f = self.fetch.as_ref().ok_or("tool_unavailable")?;
        let host = fetch_url::parse(url)
            .map_err(fetch_url::UrlError::code)?
            .host;
        let g = f.connector.grants(&host);
        let len = u64::try_from(body.len()).unwrap_or(u64::MAX);
        let u = fetch::check(url, &method, &headers, len, f.max_request, &g.headers)?;
        let note = (!g.names.is_empty())
            .then(|| format!("the proxy adds {} for {host}", g.names.join(", ")));
        Ok(Prepared {
            action: Action::Fetch {
                method,
                url: u.canonical(),
                headers,
                body: Payload::new(body),
            },
            note,
            destructive: None,
        })
    }

    /// `fetch` at run: `tool.run` before the `CONNECT`, the exchange through the proxy (whose
    /// own entries carry this call as their origin), `tool.result` before the reply (Q7).
    async fn run_fetch(&self, ticket: &Ticket) -> Option<ToolOutcome> {
        let b = ticket.bound();
        let Action::Fetch {
            method,
            url,
            headers,
            body,
        } = &b.action
        else {
            return Some(failed("unsupported"));
        };
        let (Some(f), Ok(u)) = (self.fetch.as_ref(), fetch_url::parse(url)) else {
            return Some(failed("tool_unavailable"));
        };
        let mut e = fields(b);
        add(
            &mut e,
            "approval",
            ticket.approval().map_or(Value::Null, Value::from),
        );
        add(&mut e, "host", Value::from(u.host.clone()));
        add(&mut e, "port", Value::from(u.port));
        add(&mut e, "bytes", Value::from(body.len()));
        add(&mut e, "sha256", Value::from(body.sha256()));
        if !self
            .record(Actor::Harness, "tool.run", Some("allow"), e)
            .await
        {
            return None;
        }
        let origin = json!({"tool": "fetch", "call": b.call});
        let cap = fetch::response_cap(f.max_response);
        let got = fetch_client::send(
            f.connector.as_ref(),
            origin,
            &u,
            method,
            headers,
            body.bytes(),
            cap,
        )
        .await;
        let mut r = json!({"call": b.call, "tool": "fetch", "action_sha256": b.digest()});
        let out = match got {
            Ok(x) => {
                let kept = fetch::reply_headers(&x.headers);
                add(&mut r, "outcome", Value::from("ok"));
                add(&mut r, "status", Value::from(x.status));
                add(&mut r, "headers", Value::from(kept.len()));
                add(&mut r, "kept", Value::from(x.body.len()));
                add(&mut r, "sha256", Value::from(sha256(&x.body)));
                add(&mut r, "truncated", Value::from(x.truncated));
                reply(&fetch::reply(x.status, &kept, x.body, x.truncated))
            }
            Err(code) => {
                add(&mut r, "outcome", Value::from("failed"));
                add(&mut r, "code", Value::from(code));
                failed(code)
            }
        };
        self.record(Actor::Sallyd, "tool.result", None, r)
            .await
            .then_some(out)
    }
}

fn shell_reply(o: &Output, exit: Value, killed: Value) -> ToolOutcome {
    if matches!(o.status, Status::Failed(_)) {
        // The broker could not run podman: the detail is in the audit, not passed to the harness.
        return failed("exec-failed");
    }
    let text = |c: &shell::Captured| String::from_utf8_lossy(&c.kept).into_owned();
    ToolOutcome {
        is_error: !matches!(o.status, Status::Exited(0)),
        text: json!({
            "exit": exit, "killed": killed,
            "stdout": text(&o.stdout), "stdout_cut": o.stdout.cut(),
            "stderr": text(&o.stderr), "stderr_cut": o.stderr.cut(),
        })
        .to_string(),
    }
}

impl<R: Runner> Executor for Tools<R> {
    fn tools(&self) -> Vec<Tool> {
        ALL.iter()
            .filter(|t| self.core.builtin.contains(t))
            .filter(|t| **t != BuiltinTool::Fetch || self.core.fetch.is_some())
            .map(|t| describe(*t))
            .collect()
    }

    async fn prepare(
        &self,
        name: &str,
        arguments: &Map<String, Value>,
    ) -> Result<Prepared, &'static str> {
        self.core.prepare(name, arguments).await
    }

    /// Q59: the call enters the session's operations or is denied `session-stopping`; its run
    /// section, from `tool.run`/`tool.read` to `tool.result`, is a task of its own holding the
    /// operation, so a caller dropped meanwhile loses no effect and no entry, and the session's
    /// stop waits for it.
    async fn run(&self, ticket: Ticket) -> Option<ToolOutcome> {
        let Some(op) = self.core.ops.enter() else {
            return self.core.stopping(ticket.bound()).await;
        };
        let core = Arc::clone(&self.core);
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.crash.spawn("tool", async move {
            let out = core.run(ticket).await;
            drop(op);
            let _ = tx.send(out);
        });
        rx.await.ok().flatten()
    }
}

impl<R: Runner> Core<R> {
    async fn prepare(
        &self,
        name: &str,
        arguments: &Map<String, Value>,
    ) -> Result<Prepared, &'static str> {
        let tool = ALL
            .iter()
            .copied()
            .find(|t| t.as_str() == name)
            .ok_or("unknown-tool")?;
        if !self.builtin.contains(&tool) {
            return Err("tool_not_granted");
        }
        if tool == BuiltinTool::Fetch && self.fetch.is_none() {
            return Err("tool_unavailable");
        }
        let action = match args::parse(name, arguments)? {
            Args::Fetch {
                url,
                method,
                headers,
                body,
            } => return self.prepare_fetch(&url, method, headers, body),
            Args::Read { path, offset, len } => {
                let (m, target) = self.target(&path, false)?;
                let rel = target.rel.clone();
                on_root(&m.root, self.ids, move |r| fs::check_read(r, &rel))
                    .await
                    .map_err(FsError::code)?;
                Action::FsRead {
                    target,
                    offset,
                    len,
                }
            }
            Args::List { path } => {
                let (m, target) = self.target(&path, true)?;
                let rel = target.rel.clone();
                on_root(&m.root, self.ids, move |r| fs::check_list(r, &rel))
                    .await
                    .map_err(FsError::code)?;
                Action::FsList { target }
            }
            Args::Write { path, content } => Action::FsWrite {
                target: self.effect_target(&path, fs::check_write).await?,
                content: Payload::new(content),
            },
            Args::Delete { path } => Action::FsDelete {
                target: self
                    .effect_target(&path, |r, rel, _| fs::check_delete(r, rel))
                    .await?,
            },
            Args::Shell { cmd, cwd } => {
                let cwd = cwd.unwrap_or_else(|| {
                    self.mounts
                        .first()
                        .map_or_else(|| "/".to_owned(), |m| m.guest.clone())
                });
                let destructive = tag::destructive(&cmd);
                return Ok(Prepared {
                    action: Action::Shell { argv: cmd, cwd },
                    note: None,
                    destructive: Some(destructive),
                });
            }
        };
        Ok(Prepared {
            action,
            note: None,
            destructive: None,
        })
    }

    async fn run(&self, ticket: Ticket) -> Option<ToolOutcome> {
        let b = ticket.bound();
        let target = match &b.action {
            Action::Shell { argv, cwd } => return self.run_shell(&ticket, argv, cwd).await,
            Action::Fetch { .. } => return self.run_fetch(&ticket).await,
            // Never prepared by these tools (MCP: M4).
            Action::Mcp { .. } => return Some(failed("unsupported")),
            Action::FsRead { target, .. }
            | Action::FsList { target }
            | Action::FsWrite { target, .. }
            | Action::FsDelete { target } => target,
        };
        // Prepared from these mounts, so always found.
        let Some(m) = self.mount_of(&target.mount) else {
            return Some(failed("unknown-mount"));
        };
        match &b.action {
            Action::FsRead { offset, len, .. } => self.run_read(b, m, target, *offset, *len).await,
            Action::FsList { .. } => self.run_list(b, m, target).await,
            Action::FsWrite { content, .. } => {
                self.run_file(&ticket, m, target, Some(content)).await
            }
            Action::FsDelete { .. } => self.run_file(&ticket, m, target, None).await,
            // Answered above; never a delete by default (rust review H2).
            Action::Shell { .. } | Action::Fetch { .. } | Action::Mcp { .. } => {
                Some(failed("unsupported"))
            }
        }
    }
}

/// The static `tools/list` entry of a tool.
fn describe(t: BuiltinTool) -> Tool {
    let path = json!({"type": "string", "description": "Absolute guest path under a mount"});
    let (name, description, schema) = match t {
        BuiltinTool::FsList => (
            "fs_list",
            "List a directory on a mount.",
            json!({"type": "object", "properties": {"path": path},
                   "required": ["path"], "additionalProperties": false}),
        ),
        BuiltinTool::FsRead => (
            "fs_read",
            "Read a file on a mount (at most 1 MiB per call).",
            json!({"type": "object", "properties": {
                "path": path,
                "offset": {"type": "integer", "minimum": 0},
                "len": {"type": "integer", "minimum": 0, "maximum": args::READ_CAP}},
                "required": ["path"], "additionalProperties": false}),
        ),
        BuiltinTool::FsWrite => (
            "fs_write",
            "Create or replace a file on a mount.",
            json!({"type": "object", "properties": {
                "path": path,
                "content_b64": {"type": "string", "contentEncoding": "base64"}},
                "required": ["path", "content_b64"], "additionalProperties": false}),
        ),
        BuiltinTool::FsDelete => (
            "fs_delete",
            "Delete a file or an empty directory on a mount.",
            json!({"type": "object", "properties": {"path": path},
                   "required": ["path"], "additionalProperties": false}),
        ),
        BuiltinTool::Shell => (
            "shell",
            "Run a command in the workspace (no terminal, time and output limits).",
            json!({"type": "object", "properties": {
                "cmd": {"type": "array", "items": {"type": "string"},
                        "minItems": 1, "maxItems": args::MAX_ARGV},
                "cwd": {"type": "string"}},
                "required": ["cmd"], "additionalProperties": false}),
        ),
        BuiltinTool::Fetch => (
            "fetch",
            "Send one HTTPS request through the session's egress policy. Redirects are returned, \
             not followed; the response body is capped.",
            json!({"type": "object", "properties": {
                "url": {"type": "string", "maxLength": fetch_url::MAX_URL},
                "method": {"type": "string", "pattern": "^[A-Z]{1,16}$"},
                "headers": {"type": "array", "maxItems": fetch::MAX_HEADERS,
                            "items": {"type": "array", "items": {"type": "string"},
                                      "minItems": 2, "maxItems": 2}},
                "body_b64": {"type": "string", "contentEncoding": "base64"}},
                "required": ["url"], "additionalProperties": false}),
        ),
    };
    Tool {
        name,
        description,
        input_schema: schema,
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
