//! RT-AG-11 and RT-AG-12 (#149) with a real harness-role container beside its session's
//! workspace: the harness has no hands, and the workspace cannot reach the harness's sockets.
//! Every absence clause asserts its control first.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use sally_core::manifest::ValidatedManifest;
use sallyd::sandbox::{HarnessRequest, ImageRef, RoleRunning};

use super::common::{climb, inside};
use super::*;

/// RT-AG-11 and RT-AG-12's session: a registry session (no model) in proxy mode allowing
/// mock.test, with one rw mount at `~/code/hands` holding `canary.txt`, granting `fs_write`,
/// `fs_delete` and `shell` (allow, so no call prompts), and its harness launched by the
/// launcher on the net image (which carries the shim).
struct Hands {
    reg: Arc<Registry>,
    info: SessionInfo,
    v: ValidatedManifest,
    harness: RoleRunning,
    /// The mount's host directory.
    host: PathBuf,
    canary: String,
}

async fn hands(x: &Lx) -> Hands {
    let host = x.f.root.join("home/code/hands");
    std::fs::create_dir_all(&host).unwrap();
    let canary = format!("CANARY_HANDS_{:x}", std::process::id());
    std::fs::write(host.join("canary.txt"), &canary).unwrap();
    let validated = x.f.validated(&format!(
        "{}network:\n  mode: proxy\n  allow:\n    - host: mock.test\n\
         tools:\n  builtin: [fs_write, fs_delete, shell]\n  shell: allow\n  \
         acknowledge_unapproved: [shell]\n",
        mounts(&[mount("~/code/hands", "/workspace/p", "rw")])
    ));
    let v = validated.manifest.clone();
    let reg = x.registry(x.events.clone(), Some(test_image()));
    let info = reg.start(Arc::new(validated)).await.unwrap();
    let req = HarnessRequest {
        paths: x.session_paths(&info.id),
        manifest: Arc::new(v.clone()),
        default_image: Some(net_image()),
    };
    let harness = x.launcher.launch_harness(req).await.unwrap();
    Hands {
        reg,
        info,
        v,
        harness,
        host,
        canary,
    }
}

impl Hands {
    /// The harness first, then the session.
    async fn stop(self, x: &Lx) {
        x.launcher.stop_role(self.harness).await.unwrap();
        assert_eq!(
            self.reg.stop(&self.info.id, StopReason::Request).await,
            Some(StopOutcome::Stopped)
        );
    }
}

/// A harness container for session `tag` from the product argv for `v` on the test image, with
/// `leave_out`.
async fn harness_control(
    x: &Lx,
    v: &ValidatedManifest,
    tag: &str,
    leave_out: LeaveOut<'_>,
) -> String {
    harness_control_on(x, v, tag, leave_out, &test_image()).await
}

/// [`harness_control`] on `image` (a bind control needs the test image: the fixture inserts its
/// binds before it).
async fn harness_control_on(
    x: &Lx,
    v: &ValidatedManifest,
    tag: &str,
    leave_out: LeaveOut<'_>,
    image: &ImageRef,
) -> String {
    let paths = x.paths(tag);
    let dirs = SessionDirs::create(&paths, &x.xdg, &[], 0).unwrap();
    let argv = harness_argv(&x.common_args(&dirs), &paths, v, image).unwrap();
    x.control(argv, leave_out).await
}

/// The mount set's defence left out at `/run/sallyport`: its source becomes `host`.
fn source_of(host: &Path) -> LeaveOut<'_> {
    LeaveOut::Source {
        guest: "/run/sallyport",
        host,
    }
}

/// RT-NET-01's control form (analogue): a listener on the container's own loopback `port`,
/// then the probe's `connect` to it, printed as `probe => <result>`.
fn loopback_listener_reached(port: u16) -> String {
    format!(
        "nc -l -p {port} >/dev/null 2>&1 & sleep 1; \
         echo \"probe => $({PROBE} connect 2 1 0 127.0.0.1 {port})\""
    )
}

/// Waits for the net image's own shim (`127.0.0.1:3128`) to log its readiness line in
/// `container`; panics after 10 s. The log so far.
async fn proxy_shim_ready(container: &str) -> String {
    for _ in 0..100 {
        let (_, log) = sh(container, &format!("cat {SHIM_LOG} 2>/dev/null")).await;
        if log.contains("sally-shim: listening on 127.0.0.1:3128") {
            return log;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("{container}: the 3128 shim never became ready");
}

/// A proxy request through `127.0.0.1:3128`, printing whatever comes back.
const PROXY_PROBE: &str = "printf 'CONNECT mock.test:443 HTTP/1.1\\r\\nHost: mock.test:443\\r\\n\\r\\n' \
                           | nc -w 3 127.0.0.1 3128 2>/dev/null";

/// `ls -d` of `/run/sallyport`, then of each of `paths`, in `container`: for each path, `found`
/// or the error. `/run/sallyport` must be found, so the probe tells present from absent.
async fn ls_each(container: &str, paths: &[String]) -> Vec<String> {
    let script: String = std::iter::once("/run/sallyport")
        .chain(paths.iter().map(String::as_str))
        .map(|p| format!("r=$(ls -d -- '{p}' 2>&1 >/dev/null) && echo 'found' || echo \"$r\"; "))
        .collect();
    let (code, out) = sh(container, &script).await;
    assert_eq!(code, 0, "{container}: {out}");
    let lines: Vec<String> = out.lines().map(str::to_owned).collect();
    assert_eq!(lines.len(), paths.len() + 1, "{container}: {out}");
    assert_eq!(lines[0], "found", "{container}: /run/sallyport");
    lines[1..].to_vec()
}

/// The fixture home's files and directories by path relative to `home`: a directory's value is
/// `None`, a file's is its bytes. Exactly one path is left out, by exact match: Sallyport's own
/// state directory. The broker and podman write it on every call (session records, container
/// state; in production the audit log itself), so it is the audit side of RT-AG-11's equation,
/// not a host-side change made for the harness. No tool call can reach it: no mount may contain
/// it (the built-in denylist), file tools resolve beneath the mount root (RT-FS-04), broker
/// state is absent from every role (RT-FS-10), and this session has no staged mount. If the
/// fixture's state directory ever moves, the literal leaves nothing out and the test fails on
/// bookkeeping.
fn snapshot(home: &Path) -> BTreeMap<String, Option<Vec<u8>>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![home.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).unwrap().flatten() {
            let p = e.path();
            let rel = p.strip_prefix(home).unwrap().display().to_string();
            if rel == ".local/share/sallyport" {
                continue;
            }
            if e.file_type().unwrap().is_dir() {
                out.insert(rel, None);
                stack.push(p);
            } else {
                out.insert(rel, Some(std::fs::read(&p).unwrap()));
            }
        }
    }
    out
}

/// One operation's predicted effect on the snapshot: the path relative to the fixture home and
/// its new value (`None` removed, `Some(None)` a directory, `Some(Some(bytes))` a file).
type Change = (String, Option<Option<Vec<u8>>>);

/// `Ok` when `after` is `before` with `change` (if any) applied; else the paths that differ.
fn compare(
    before: &BTreeMap<String, Option<Vec<u8>>>,
    change: Option<&Change>,
    after: &BTreeMap<String, Option<Vec<u8>>>,
) -> Result<(), String> {
    let mut want = before.clone();
    match change {
        Some((path, None)) => {
            want.remove(path);
        }
        Some((path, Some(v))) => {
            want.insert(path.clone(), v.clone());
        }
        None => {}
    }
    let differ: Vec<&String> = want
        .keys()
        .chain(after.keys())
        .filter(|k| want.get(*k) != after.get(*k))
        .collect();
    if differ.is_empty() {
        Ok(())
    } else {
        Err(format!("differs from the prediction at {differ:?}"))
    }
}

/// A small deterministic generator (xorshift64*); the seed is printed in every message.
struct Seeded(u64);

impl Seeded {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % n as u64).unwrap()
    }
}

/// One of RT-AG-11's mutating operations: the tool, its arguments, the guest path it targets
/// and its predicted change.
fn operation(
    i: usize,
    rng: &mut Seeded,
    files: &mut Vec<String>,
) -> (&'static str, Value, String, Change) {
    let at = |name: &str| (format!("/workspace/p/{name}"), format!("code/hands/{name}"));
    let body = format!("op{i}");
    let b64 = base64::engine::general_purpose::STANDARD.encode(&body);
    // The first five operations are each kind once (so every kind runs on every seed), the
    // rest are drawn.
    let drawn = if i < 5 { i } else { rng.below(5) };
    let kind = match drawn {
        1 | 2 if files.is_empty() => 0,
        k => k,
    };
    match kind {
        0 | 1 => {
            let name = if kind == 0 {
                files.push(format!("w{i}"));
                format!("w{i}")
            } else {
                files[rng.below(files.len())].clone()
            };
            let (guest, rel) = at(&name);
            let args = json!({"path": guest, "content_b64": b64});
            (
                "fs_write",
                args,
                guest,
                (rel, Some(Some(body.into_bytes()))),
            )
        }
        2 => {
            let name = files.remove(rng.below(files.len()));
            let (guest, rel) = at(&name);
            ("fs_delete", json!({"path": guest}), guest, (rel, None))
        }
        3 => {
            files.push(format!("t{i}"));
            let (guest, rel) = at(&format!("t{i}"));
            let args = json!({"cmd": ["touch", guest], "cwd": "/workspace/p"});
            ("shell", args, guest, (rel, Some(Some(Vec::new()))))
        }
        _ => {
            let (guest, rel) = at(&format!("d{i}"));
            let args = json!({"cmd": ["mkdir", guest], "cwd": "/workspace/p"});
            ("shell", args, guest, (rel, Some(None)))
        }
    }
}

/// The `tool.run` entries so far: tool and action.
fn tool_runs(x: &Lx) -> Vec<(String, String)> {
    x.events
        .all()
        .into_iter()
        .filter(|(e, _)| e == "tool.run")
        .map(|(_, a)| {
            let field = |k: &str| a[k].as_str().unwrap_or_default().to_owned();
            (field("tool"), field("action"))
        })
        .collect()
}

/// RT-AG-11: the harness has no hands (#149). In a registry session with a mount, a proxy and
/// a live harness, from inside the harness:
/// 1. no mount: `/workspace`, the mount's guest path, its canary and its host path are all
///    absent;
/// 2. no egress socket: `/run/sallyport` holds exactly `agent.sock`, and a proxy request
///    through `127.0.0.1:3128` gets no answer while the shim reports that `net.sock` is not
///    there (the net image's own shim listens on 3128 in every role, so a bare connect
///    succeeds; the mount set is the defence);
/// 3. no route: only `lo`, and the probe's public connect fails `ENETUNREACH` (the probe prints
///    the errno, which tells unreachable from refused and from a time-out);
/// 4. host-side changes equal audit entries: 20 mutating operations (each kind once, then drawn
///    from a per-run seed printed up front and in every message) go through the shim in stdio mode on `agent.sock`, one exchange
///    each. After each, the fixture home (names and content, except Sallyport's own state
///    directory: see [`snapshot`]) differs by exactly the predicted change, and exactly one new
///    `tool.run` names that tool and target. At the end there are 20 `tool.run`, nothing
///    outside the mount changed, and no entry names another session.
///
/// Each control is asserted first: (1) the product harness argv with the mount bound back in
/// at its guest and its host path: the same probe finds all four paths, and the canary reads; (2) with the workspace socket directory as the source of `/run/sallyport`
/// it lists `net.sock`, and on the net image the same proxy request gets an HTTP answer;
/// (3) (analogue) the same probe connect reaches a listener on the harness's own loopback (a
/// defence-off control would need a `--network` other than `none`); (4) two out-of-band host
/// writes, one in the mount and one beside the left-out directory, are each reported as a
/// mismatch by the same comparison, then removed.
#[test]
fn rt_ag_11_the_harness_has_no_hands() {
    rt().block_on(async {
        let x = Lx::new();
        let h = hands(&x).await;
        let c = h.harness.name().to_owned();
        let home = x.f.root.join("home");

        // (1)
        let host = h.host.display().to_string();
        let tried: Vec<String> = vec![
            "/workspace".into(),
            "/workspace/p".into(),
            "/workspace/p/canary.txt".into(),
            host.clone(),
        ];
        // The mount bound back in, at its guest path and at its host path: the same probe finds
        // all four paths, and the canary reads.
        let binds = [
            (h.host.as_path(), "/workspace/p"),
            (h.host.as_path(), host.as_str()),
        ];
        let ctl = harness_control(&x, &h.v, "ag11m", LeaveOut::Binds(&binds)).await;
        for (p, line) in tried.iter().zip(ls_each(&ctl, &tried).await) {
            assert_eq!(line, "found", "control: {p}");
        }
        let (_, got) = sh(&ctl, "cat /workspace/p/canary.txt").await;
        assert_eq!(got, h.canary, "control: the mount bound back in");
        for (p, line) in tried.iter().zip(ls_each(&c, &tried).await) {
            assert!(line.ends_with("No such file or directory"), "{p}: {line}");
        }

        // (2)
        let ws = x.session_paths(&h.info.id).workspace_sockets();
        let ctl = harness_control(&x, &h.v, "ag11s", source_of(&ws)).await;
        let (_, ls) = sh(&ctl, "ls -A /run/sallyport").await;
        assert!(ls.lines().any(|l| l == "net.sock"), "control: {ls}");
        let (_, ls) = sh(&c, "ls -A /run/sallyport").await;
        assert_eq!(ls.lines().collect::<Vec<_>>(), ["agent.sock"]);
        let ctl = harness_control_on(&x, &h.v, "ag11p", source_of(&ws), &net_image()).await;
        proxy_shim_ready(&ctl).await;
        let (_, reply) = sh(&ctl, PROXY_PROBE).await;
        assert!(
            reply.starts_with("HTTP/1.1 "),
            "control: the proxy answers: {reply}"
        );
        let log = proxy_shim_ready(&c).await;
        assert!(!log.contains("relay failed"), "before the request: {log}");
        let (_, reply) = sh(&c, PROXY_PROBE).await;
        assert_eq!(reply, "", "the harness reached a proxy");
        let (_, log) = sh(&c, &format!("cat {SHIM_LOG}")).await;
        assert!(
            log.contains("relay failed: No such file or directory"),
            "the request's relay found net.sock: {log}"
        );

        // (3)
        let (_, out) = sh(&c, &loopback_listener_reached(4001)).await;
        assert!(out.contains("probe => ok"), "control: {out}");
        let (_, nets) = sh(&c, "ls /sys/class/net").await;
        assert_eq!(nets.split_whitespace().collect::<Vec<_>>(), ["lo"]);
        let (_, out) = sh(&c, &format!("{PROBE} connect 2 1 0 1.1.1.1 443")).await;
        assert_eq!(out.trim(), "errno=101", "ENETUNREACH");

        // (4)
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
            | 1;
        let start = snapshot(&home);
        // One write in the mount and one beside the left-out state directory: the walk sees both.
        let beside = home.join(".local/share/stray");
        for (stray, rel) in [
            (h.host.join("stray"), "code/hands/stray"),
            (beside, ".local/share/stray"),
        ] {
            std::fs::write(&stray, b"out of band").unwrap();
            let err = compare(&start, None, &snapshot(&home)).unwrap_err();
            assert!(err.contains(rel), "seed {seed}: control: {err}");
            std::fs::remove_file(&stray).unwrap();
            assert_eq!(
                compare(&start, None, &snapshot(&home)),
                Ok(()),
                "seed {seed}"
            );
        }
        // Printed once up front too, so a panic inside a helper still leaves the seed.
        eprintln!("rt_ag_11 seed {seed}");
        let mut rng = Seeded(seed);
        let mut files = vec!["canary.txt".to_owned()];
        let mut before = start.clone();
        for i in 0..20 {
            let (tool, args, guest, change) = operation(i, &mut rng, &mut files);
            let runs = tool_runs(&x).len();
            let reply = agent_exchange(
                &c,
                &[json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                         "params": {"_meta": meta(), "name": tool, "arguments": args}})],
            )
            .await;
            assert_eq!(
                reply[0]["result"]["isError"],
                json!(false),
                "seed {seed}, op {i} {tool} {guest}: {reply:?}"
            );
            let after = snapshot(&home);
            if let Err(e) = compare(&before, Some(&change), &after) {
                panic!("seed {seed}, op {i} {tool} {guest}: {e}");
            }
            let now = tool_runs(&x);
            assert_eq!(now.len(), runs + 1, "seed {seed}, op {i}: {now:?}");
            let (t, action) = &now[runs];
            assert!(
                t == tool && action.contains(&guest),
                "seed {seed}, op {i} {tool} {guest}: {t} {action}"
            );
            before = after;
        }
        assert_eq!(tool_runs(&x).len(), 20, "seed {seed}");
        let outside = |m: &BTreeMap<String, Option<Vec<u8>>>| {
            m.iter()
                .filter(|(k, _)| !k.starts_with("code/hands/"))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<Vec<_>>()
        };
        assert_eq!(outside(&start), outside(&before), "seed {seed}");
        let own = format!("session: Some({:?})", h.info.id);
        let debug = x.events.debug();
        let named = debug.iter().filter(|d| d.contains(&own)).count();
        assert!(
            named >= 20,
            "control: the session form must match this session's own 20 tool.run entries, \
             found {named}: {debug:#?}"
        );
        assert!(
            debug
                .iter()
                .all(|d| !d.contains("session: Some(") || d.contains(&own)),
            "seed {seed}: {debug:#?}"
        );
        h.stop(&x).await;
    });
}

/// RT-AG-12: the workspace cannot reach the harness sockets (#149). Beside a live harness that
/// serves `agent.sock` (the registry's) and `llm.sock` (bound by this test), with its shim on
/// `127.0.0.1:8080`, from inside the session's workspace:
/// 1. `agent.sock` and `llm.sock` under `/run/sallyport`, under the harness socket directory's
///    host path and under the climb from the workspace's socket directory are all absent, while
///    `/run/sallyport` itself is present;
/// 2. a connect to `127.0.0.1:8080` fails `ECONNREFUSED`, and the busybox HTTP client fails on
///    `/v1/models`.
///
/// Controls, asserted first: (1) the product workspace argv with the harness socket directory
/// as the source of `/run/sallyport` finds both sockets there; with that directory bound at its
/// host path and at the climb's landing path it finds them there; (2) (analogue) the same two
/// probes succeed inside the harness, and the same connect reaches a listener on the
/// workspace's own loopback.
#[test]
fn rt_ag_12_the_workspace_cannot_reach_the_harness_sockets() {
    rt().block_on(async {
        let x = Lx::new();
        let h = hands(&x).await;
        let paths = x.session_paths(&h.info.id);
        let hs = paths.harness_sockets();
        let record = Recorder::new(
            x.events.clone() as Arc<dyn AuditSink>,
            h.info.id.clone(),
            AuditLevel::Full,
        );
        let (crash, _) = sallyd::daemon::crash::CrashReporter::channel();
        let (llm, _) = serve_llm(&hs, record, "hello.jsonl", crash);
        let hc = h.harness.name().to_owned();
        start_llm_shim(&hc).await;
        let ws = format!("sp-ws-{}", h.info.id);
        let up = climb(&paths.workspace_sockets(), &hs);
        let socks = ["agent.sock", "llm.sock"];

        // (1)
        let under: Vec<String> = socks
            .iter()
            .map(|s| format!("/run/sallyport/{s}"))
            .collect();
        let ctl = x.control_workspace(&h.v, "ag12s", source_of(&hs)).await;
        for (p, line) in under.iter().zip(ls_each(&ctl, &under).await) {
            assert_eq!(line, "found", "control: {p}");
        }
        let landing = inside(&up);
        let elsewhere: Vec<String> = socks
            .iter()
            .flat_map(|s| {
                [
                    format!("{}/{s}", hs.display()),
                    format!("/run/sallyport/{up}/{s}"),
                ]
            })
            .collect();
        let host = hs.display().to_string();
        let binds = [
            (hs.as_path(), host.as_str()),
            (hs.as_path(), landing.as_str()),
        ];
        let ctl = x
            .control_workspace(&h.v, "ag12b", LeaveOut::Binds(&binds))
            .await;
        for (p, line) in elsewhere.iter().zip(ls_each(&ctl, &elsewhere).await) {
            assert_eq!(line, "found", "control: {p}");
        }
        let tried: Vec<String> = under.into_iter().chain(elsewhere).collect();
        for (p, line) in tried.iter().zip(ls_each(&ws, &tried).await) {
            assert!(line.ends_with("No such file or directory"), "{p}: {line}");
        }

        // (2)
        let connect = format!("{PROBE} connect 2 1 0 127.0.0.1 {LLM_PORT}");
        let models = format!("wget -q -O - http://127.0.0.1:{LLM_PORT}/v1/models");
        let (_, out) = sh(&hc, &connect).await;
        assert_eq!(out.trim(), "ok", "control: the harness connects");
        let (code, out) = sh(&hc, &models).await;
        assert_eq!(code, 0, "control: the harness lists models: {out}");
        let (_, out) = sh(&ws, &loopback_listener_reached(4002)).await;
        assert!(out.contains("probe => ok"), "control: own loopback: {out}");
        let (_, out) = sh(&ws, &connect).await;
        assert_eq!(out.trim(), "errno=111", "ECONNREFUSED");
        let (code, out) = sh(&ws, &models).await;
        assert_ne!(code, 0, "{out}");
        llm.shutdown().await;
        h.stop(&x).await;
    });
}
