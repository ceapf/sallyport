//! Driven sessions with real containers (architect Q117–Q122 on R3). Red-team rows: a driven
//! session serves no `agent.sock` or `llm.sock`; a driven call meets the same gate; no driven
//! entry is the agent's; nothing of a drive follows `session.stop`.

use sally_proto::{ModelKind, TurnKind};
use sallyd::approvals::{Client, Decision, Seen};
use sallyd::llm::scripted::Script;
use sallyd::rpc::drive::Stepped;

use super::*;

fn script(text: &str) -> Script {
    Script::parse(text).unwrap()
}

const SHELL_TOUCH: &str = "{\"tool_calls\":[{\"name\":\"shell\",\"arguments\":\
    {\"cmd\":[\"touch\",\"/workspace/p/ran\"],\"cwd\":\"/workspace/p\"}}]}\n";

/// A manifest with one rw mount at `~/code/<dir>` and the shell under `mode`.
fn manifest(
    r: &Rx,
    dir: &str,
    mode: &str,
) -> (Arc<sally_core::manifest::ValidatedManifest>, PathBuf) {
    let at = r.x.f.root.join("home/code").join(dir);
    std::fs::create_dir_all(&at).unwrap();
    let text = format!(
        "{}tools:\n  builtin: [shell]\n  shell: {mode}\n",
        mounts(&[mount(&format!("~/code/{dir}"), "/workspace/p", "rw")])
    );
    (Arc::new(r.x.f.load(&text)), at)
}

/// The `Debug` text of every entry of session `id` written so far. TODO(#129): a typed actor
/// accessor on the sink instead of matching the `Debug` text.
fn entries_of(r: &Rx, id: &str) -> Vec<String> {
    let needle = format!("session: Some(\"{id}\")");
    r.sink
        .debug
        .lock()
        .unwrap()
        .iter()
        .filter(|d| d.contains(&needle))
        .cloned()
        .collect()
}

#[test]
fn rt_drv_01_a_driven_session_serves_no_socket_and_says_what_model_it_has() {
    rt().block_on(async {
        let r = registry();
        let v = Arc::new(r.x.f.load(""));
        let s = r
            .reg
            .start_with(Arc::clone(&v), Some(script("{\"fail\":true}\n")))
            .await
            .unwrap();
        assert_eq!(s.model.kind, ModelKind::Scripted);
        assert!(s.model.driven);
        assert_eq!(s.model.turns, Some(1));
        let harness = r.x.session_paths(&s.id).harness_sockets();
        let socks: Vec<_> = std::fs::read_dir(&harness)
            .map(|d| d.flatten().map(|e| e.file_name()).collect())
            .unwrap_or_default();
        assert!(socks.is_empty(), "a driven session binds: {socks:?}");
        assert!(agent_socks(&r.x.xdg.join("sallyport/sessions")).is_empty());
        assert!(r.reg.driver(&s.id).is_some());
        let start =
            r.x.events
                .all()
                .into_iter()
                .find(|(e, _)| e == "session.start")
                .unwrap()
                .1;
        assert_eq!(start["model"]["kind"], "scripted");
        assert_eq!(start["model"]["driven"], true);
        assert_eq!(start["model"]["sha256"].as_str().unwrap().len(), 64);
        // An ordinary session has no drive handle and its model is none.
        let plain = r.reg.start(v).await.unwrap();
        assert!(r.reg.driver(&plain.id).is_none());
        assert_eq!(plain.model.kind, ModelKind::None);
        assert!(!agent_socks(&r.x.xdg.join("sallyport/sessions")).is_empty());
        assert_eq!(
            r.reg.stop(&s.id, StopReason::Request).await,
            Some(StopOutcome::Stopped)
        );
        r.reg.stop(&plain.id, StopReason::Request).await;
    });
}

/// With nobody attached an approve-mode shell is denied `no-approver` and nothing runs; the
/// session's entries are the driver's, never the harness's.
#[test]
fn rt_drv_02_a_driven_call_meets_the_gate_and_no_entry_is_the_agents() {
    rt().block_on(async {
        let r = registry();
        let (v, at) = manifest(&r, "drv02", "approve");
        let s = r
            .reg
            .start_with(v, Some(script(SHELL_TOUCH)))
            .await
            .unwrap();
        let seat = r.reg.driver(&s.id).unwrap().claim().unwrap();
        let Stepped::Step(step) = seat.step().await else {
            panic!("no step")
        };
        assert_eq!(step.kind, TurnKind::ToolCalls);
        assert!(step.calls[0].result.contains("denied"), "{step:?}");
        assert!(!at.join("ran").exists(), "the denied command ran");
        r.reg.stop(&s.id, StopReason::Request).await;
        let own = entries_of(&r, &s.id);
        assert!(
            !own.iter().any(|d| d.contains("actor: Harness")),
            "{own:#?}"
        );
        let drivers = |event: &str| {
            own.iter()
                .any(|d| d.contains("actor: Driver") && d.contains(&format!("event: \"{event}\"")))
        };
        assert!(drivers("drive.turn") && drivers("rpc.request"), "{own:#?}");
        let all = r.x.events.all();
        let deny = all.iter().find(|(e, _)| e == "approval.deny").unwrap();
        assert_eq!(deny.1["reason"], "no-approver");
    });
}

/// Approved from another connection's desk, the command runs once.
#[test]
fn rt_drv_02_an_approved_driven_call_runs_once() {
    rt().block_on(async {
        let hub = Arc::new(Hub::default());
        let r = registry_hub(Some(test_image()), Arc::clone(&hub));
        let mut watch = hub.watch();
        let (v, at) = manifest(&r, "drv02b", "approve");
        let s = r
            .reg
            .start_with(v, Some(script(SHELL_TOUCH)))
            .await
            .unwrap();
        let driver = r.reg.driver(&s.id).unwrap();
        let step = tokio::spawn(async move {
            let seat = driver.claim().unwrap();
            seat.step().await
        });
        let note = tokio::time::timeout(Duration::from_secs(30), watch.rx.recv())
            .await
            .expect("no prompt")
            .expect("the hub dropped the watcher");
        let Note::Requested(prompt) = note else {
            panic!("{note:?}")
        };
        assert!(!at.join("ran").exists(), "it ran before the answer");
        let who = Client { uid: 1, pid: 1 };
        let seen = Seen {
            digest: &prompt.digest,
            full_shown: false,
        };
        r.reg
            .desk(&s.id)
            .unwrap()
            .decide(&prompt.id, Decision::Approve, who, seen)
            .await
            .unwrap();
        let Stepped::Step(done) = step.await.unwrap() else {
            panic!("no step")
        };
        assert!(!done.calls[0].result.contains("denied"), "{done:?}");
        assert!(at.join("ran").exists(), "the approved command did not run");
        r.reg.stop(&s.id, StopReason::Request).await;
        let runs =
            r.x.events
                .all()
                .iter()
                .filter(|(e, a)| e == "tool.run" && a["tool"] == "shell")
                .count();
        assert_eq!(runs, 1);
    });
}

/// `sessions.drive {id}` over a control socket on `r`'s registry; the reply's refusal reason.
async fn drive_over_control(r: &Rx, id: &str) -> Value {
    use sallyd::rpc::control::{Control, ControlParts};
    let state = r.x.f.root.join("home/.local/share/sallyport");
    let control = Arc::new(Control::new(ControlParts {
        record: sallyd::rpc::record::Recorder::new(
            r.sink.clone() as Arc<dyn AuditSink>,
            String::new(),
            AuditLevel::default(),
        ),
        sessions: Arc::clone(&r.reg),
        hub: Arc::new(Hub::default()),
        sessions_dir: Arc::new(sallyd::sandbox::open_sessions(&state).unwrap()),
        env: Arc::new(r.x.f.env.clone()),
        catalog: Arc::new(std::collections::BTreeSet::<String>::new()),
    }));
    let (client, server) = tokio::io::duplex(1 << 20);
    let peer = sallyd::rpc::listen::Peer { uid: 1000, pid: 7 };
    tokio::spawn(control.serve_stream(server, peer));
    let (rd, mut wr) = tokio::io::split(client);
    let req = json!({"jsonrpc": "2.0", "id": 1, "method": "sessions.drive", "params": {"id": id}});
    wr.write_all(format!("{req}\n").as_bytes()).await.unwrap();
    let mut line = String::new();
    BufReader::new(rd).read_line(&mut line).await.unwrap();
    let reply: Value = serde_json::from_str(&line).unwrap();
    reply["error"]["data"]["reason"].clone()
}

/// One scripted `fs_write` of `/workspace/p/early.txt`: the control's turn.
const EARLY_WRITE: &str = "{\"tool_calls\":[{\"name\":\"fs_write\",\"arguments\":\
    {\"path\":\"/workspace/p/early.txt\",\"content_b64\":\"bGF0ZQ==\"}}]}\n";

/// One scripted `fs_write` of `/workspace/p/late.txt`.
const LATE_WRITE: &str = "{\"tool_calls\":[{\"name\":\"fs_write\",\"arguments\":\
    {\"path\":\"/workspace/p/late.txt\",\"content_b64\":\"bGF0ZQ==\"}}]}\n";

/// RT-DRV-03, the seal (#122, architect Q176): a driven `fs_write` whose `tool.run` append is
/// still running past the drain keeps one operation in flight. The step began before the stop,
/// so `Seat::step`'s check cannot refuse it: only the seal holds it. The stop answers failed,
/// `session.stop {in_flight: 1}` follows that `tool.run`, the file is untouched, and no entry of
/// the session follows `session.stop`. The write's `tool.result` either lands before it, aborted,
/// or is refused by the seal with an oplog line naming it (the order is a race once the append is
/// released, as in RT-AG-15). Control (architect Q181): the script's first turn, stepped on the
/// same seat before anything is held, writes `early.txt` and the host sees it.
#[test]
fn rt_drv_03_a_driven_call_past_the_drain_writes_nothing_after_the_stop() {
    rt().block_on(async {
        let r = registry();
        let at = r.x.f.root.join("home/code/drv03b");
        std::fs::create_dir_all(&at).unwrap();
        let v = Arc::new(r.x.f.load(&format!(
            "{}tools:\n  builtin: [fs_write]\n",
            mounts(&[mount("~/code/drv03b", "/workspace/p", "rw")])
        )));
        let two = format!("{EARLY_WRITE}{LATE_WRITE}");
        let s = r.reg.start_with(v, Some(script(&two))).await.unwrap();
        // The host's view of the mount: the probe of "the write touched the file".
        let written = |name: &str| at.join(name).exists();
        let seat = r.reg.driver(&s.id).unwrap().claim().unwrap();
        // Control (#122): before anything is held, the first turn's write on the same seat runs
        // and the host sees its file.
        let Stepped::Step(first) = seat.step().await else {
            panic!("control: the first turn did not step")
        };
        assert_eq!(
            (first.turn, first.calls.len()),
            (1, 1),
            "control: {first:?}"
        );
        assert!(
            !first.calls[0].result.starts_with("denied"),
            "control: {first:?}"
        );
        assert!(
            written("early.txt"),
            "control: the first turn's file is not on the host"
        );
        r.x.events.hold(&["tool.run"]);
        let step = tokio::spawn(async move { seat.step().await });
        r.x.events.until_parked("tool.run", 1).await;
        let stopping = {
            let reg = Arc::clone(&r.reg);
            let id = s.id.clone();
            tokio::spawn(async move { reg.stop(&id, StopReason::Request).await })
        };
        // Past the drain (5 s): the operation is still in flight, its entry still being written.
        tokio::time::sleep(Duration::from_secs(6)).await;
        assert!(!r.x.events.list().contains(&"session.stop".to_owned()));
        r.x.events.hold(&[]);
        let outcome = stopping.await.unwrap();
        assert!(
            matches!(outcome, Some(StopOutcome::Failed(ref w)) if w.contains("1 operations")),
            "{outcome:?}"
        );
        let stepped = step.await.unwrap();
        assert_eq!(stepped, Stepped::Refused("session-stopping"), "{stepped:?}");
        let (stop_at, after) = after_stop(&r.x);
        assert!(after.is_empty(), "after session.stop: {after:?}");
        let all = r.x.events.all();
        assert_eq!(all[stop_at].1["in_flight"], 1, "{all:#?}");
        // The control's entries come first: the late write's are those after its `tool.result`.
        let control_result = all
            .iter()
            .position(|(e, _)| e == "tool.result")
            .expect("the control's tool.result");
        let runs = all.iter().filter(|(e, _)| e == "tool.run").count();
        assert_eq!(
            runs, 2,
            "the control's tool.run and the late write's: {all:#?}"
        );
        let later = |event: &str| {
            all[control_result + 1..]
                .iter()
                .position(|(e, _)| e == event)
                .map(|i| control_result + 1 + i)
        };
        let run = later("tool.run").expect("the late write's tool.run");
        assert!(run < stop_at, "{all:#?}");
        assert!(!written("late.txt"), "the write touched the file");
        match later("tool.result") {
            Some(i) => {
                assert!(i < stop_at, "{all:#?}");
                assert_eq!(all[i].1["outcome"], "aborted", "{all:#?}");
            }
            None => {
                r.until_logged("entry refused after session.stop").await;
                let text = String::from_utf8_lossy(&r.log.0.lock().unwrap()).into_owned();
                assert!(
                    text.lines()
                        .any(|l| l.contains("entry refused after session.stop")
                            && l.contains("tool.result")),
                    "{text}"
                );
            }
        }
    });
}

/// A stop while a step waits on a prompt: the prompt is withdrawn, the step is answered
/// `denied: withdrawn`, `session.stop` is the last entry of the session's audit handle (only
/// teardown's `sandbox.*`, written by the launcher, may follow; ARCHITECTURE §5.4), a step on the
/// same seat afterwards is refused and writes nothing, and a drive over the control socket finds
/// no session.
#[test]
fn rt_drv_03_nothing_of_a_drive_follows_the_stop() {
    rt().block_on(async {
        let hub = Arc::new(Hub::default());
        let r = registry_hub(Some(test_image()), Arc::clone(&hub));
        let mut watch = hub.watch();
        let (v, at) = manifest(&r, "drv03", "approve");
        let three = format!("{SHELL_TOUCH}{SHELL_TOUCH}{{\"content\":\"bye\"}}\n");
        let s = r.reg.start_with(v, Some(script(&three))).await.unwrap();
        let driver = r.reg.driver(&s.id).unwrap();
        let seat = Arc::new(driver.claim().unwrap());
        let step = tokio::spawn({
            let seat = Arc::clone(&seat);
            async move { seat.step().await }
        });
        let note = tokio::time::timeout(Duration::from_secs(30), watch.rx.recv())
            .await
            .expect("no prompt")
            .expect("the hub dropped the watcher");
        let Note::Requested(prompt) = note else {
            panic!("{note:?}")
        };
        assert_eq!(
            r.reg.stop(&s.id, StopReason::Request).await,
            Some(StopOutcome::Stopped)
        );
        // The withdrawn prompt is the tool's own denial: a result, as a model would see it.
        let Stepped::Step(first) = step.await.unwrap() else {
            panic!("the waiting step was not answered")
        };
        assert_eq!((first.turn, first.calls.len()), (1, 1), "{first:?}");
        assert_eq!(first.calls[0].result, "denied: withdrawn");
        let own = entries_of(&r, &s.id);
        let last = own.last().unwrap();
        assert!(last.contains("event: \"session.stop\""), "{own:#?}");
        // The seat is still held here, outside the task: its next step is refused.
        assert_eq!(seat.step().await, Stepped::Refused("session-stopping"));
        assert_eq!(entries_of(&r, &s.id), own, "an entry followed the stop");
        assert_eq!(drive_over_control(&r, &s.id).await, "unknown-session");
        assert_eq!(entries_of(&r, &s.id), own, "an entry followed the stop");
        let all = r.x.events.all();
        let withdraw = all
            .iter()
            .position(|(e, a)| e == "approval.withdraw" && a["id"] == json!(prompt.id))
            .expect("approval.withdraw");
        let stop = all.iter().position(|(e, _)| e == "session.stop").unwrap();
        assert!(withdraw < stop);
        assert!(!at.join("ran").exists(), "the withdrawn command ran");
        assert!(r.reg.driver(&s.id).is_none(), "the session is gone");
        assert!(driver.claim().is_err(), "the seat was taken once");
    });
}
