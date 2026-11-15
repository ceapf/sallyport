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

/// The `Debug` text of every entry of session `id` written so far.
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

/// A stop while a step waits on a prompt: the prompt is withdrawn, `session.stop` is the last
/// entry of the session, and a later drive finds no session.
#[test]
fn rt_drv_03_nothing_of_a_drive_follows_the_stop() {
    rt().block_on(async {
        let hub = Arc::new(Hub::default());
        let r = registry_hub(Some(test_image()), Arc::clone(&hub));
        let mut watch = hub.watch();
        let (v, at) = manifest(&r, "drv03", "approve");
        let s = r
            .reg
            .start_with(v, Some(script(SHELL_TOUCH)))
            .await
            .unwrap();
        let driver = r.reg.driver(&s.id).unwrap();
        let seat = driver.claim().unwrap();
        let step = tokio::spawn(async move { seat.step().await });
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
        let _ = step.await;
        let own = entries_of(&r, &s.id);
        let last = own.last().unwrap();
        assert!(last.contains("event: \"session.stop\""), "{own:#?}");
        let all = r.x.events.all();
        let withdraw = all
            .iter()
            .position(|(e, a)| e == "approval.withdraw" && a["id"] == json!(prompt.id))
            .expect("approval.withdraw");
        let stop = all.iter().position(|(e, _)| e == "session.stop").unwrap();
        assert!(withdraw < stop);
        assert!(!at.join("ran").exists(), "the withdrawn command ran");
        assert!(r.reg.driver(&s.id).is_none(), "the session is gone");
        // A step on the seat taken earlier is refused: the operations are closed.
        let late = driver.claim();
        assert!(late.is_err(), "the seat was taken once");
    });
}
