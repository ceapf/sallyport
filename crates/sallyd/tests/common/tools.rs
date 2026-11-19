//! A session's built-in tools behind the real gate, on a launched workspace (`tests/tools.rs`,
//! `tests/disk.rs`): the tools and their mounts are built as the session registry builds them.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use sally_core::manifest::{AuditLevel, ValidatedManifest};
use sallyd::approvals::Gated;
use sallyd::approvals::policy::Policy;
use sallyd::approvals::queue::{self, Approver, Desk, Limits, Seen};
use sallyd::approvals::render::Prompt;
use sallyd::daemon::crash::CrashReporter;
use sallyd::rpc::agent::ToolHandler;
use sallyd::rpc::mcp::ToolOutcome;
use sallyd::rpc::record::Recorder;
use sallyd::sandbox::Running;
use sallyd::tools::exec::{PodmanExec, session_mounts};
use sallyd::tools::ops::Ops;
use sallyd::tools::{Parts, Tools};
use serde_json::Value;

use super::container::{Lx, ids};

#[derive(Default)]
pub struct Shown(pub Mutex<Vec<Prompt>>);

impl Approver for Shown {
    fn attached(&self) -> bool {
        true
    }
    fn requested(&self, p: &Prompt) {
        self.0.lock().unwrap().push(p.clone());
    }
    fn flood(&self, _: &str) {}
    fn closed(&self, _: &str) {}
}

/// What a client shown `p` sends with its answer (these prompts are never cut).
pub fn seen(p: &Prompt) -> Seen<'_> {
    Seen {
        digest: &p.digest,
        full_shown: false,
    }
}

pub struct Session {
    pub gated: Gated<Tools<PodmanExec>>,
    pub desk: Desk,
    pub shown: Arc<Shown>,
}

impl Session {
    pub async fn call(&self, name: &str, args: Value) -> ToolOutcome {
        let n = self.gated.begin();
        self.gated
            .call(n, name.to_owned(), args.as_object().unwrap().clone())
            .await
            .expect("every entry was written")
    }

    pub async fn shown(&self, n: usize) -> Prompt {
        for _ in 0..5000 {
            if let Some(p) = self.shown.0.lock().unwrap().get(n - 1) {
                return p.clone();
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        panic!("no prompt");
    }
}

/// The session's tools behind the real gate, as the session registry wires them: the mounts and
/// their free-space floor come from the launch, through the registry's own function
/// (`session_mounts`).
pub fn session(x: &Lx, v: &ValidatedManifest, r: &Running, timeout: Duration) -> Session {
    let rec = Recorder::new(
        x.events.clone(),
        r.paths().id().as_str().to_owned(),
        AuditLevel::Full,
    );
    let shown = Arc::new(Shown::default());
    let (gate, desk) = queue::new(
        r.paths().id().as_str().to_owned(),
        Policy::from_manifest(v),
        Limits {
            timeout,
            max_pending: 4,
        },
        rec.clone(),
        Some(Arc::clone(&shown) as Arc<dyn Approver>),
    );
    let ops = Ops::new();
    let tools = Tools::new(Parts {
        builtin: v.manifest().tools.builtin.clone(),
        mounts: session_mounts(v, r),
        record: rec,
        exec_gate: r.exec_gate(),
        ops: ops.clone(),
        crash: CrashReporter::channel().0,
        // The launcher's ids: the workspace's `--user`.
        ids: ids(),
        shell: PodmanExec::new(x.podman.clone(), r, ops),
        // The container tests do not reach the network; fetch has its own tests (#75).
        fetch: None,
    });
    Session {
        gated: Gated::new(gate, tools),
        desk,
        shown,
    }
}
