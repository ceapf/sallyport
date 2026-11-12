//! The production `agent.sock` tool handler: every call goes through the approvals [`Gate`]
//! before an [`Executor`] runs it (Task 10; architect ruling Q18).
//!
//! The executor is a constructor argument, with no test hook: Task 11 supplies the built-in
//! tools (`shell`, `fs_*`, `fetch`), M4 the MCP relay. It turns a call's arguments into the
//! [`Action`] that will run (resolving paths, building argv) and later runs exactly the
//! [`Ticket`] it is given, which it takes by value.

use std::future::Future;

use serde_json::{Map, Value};

use super::action::{Action, Bound};
use super::queue::{Gate, Refusal, Ticket, Withdraw};
use crate::rpc::agent::ToolHandler;
use crate::rpc::mcp::{Tool, ToolOutcome};

/// A call made ready to run: the action, the agent's note and the shell tagger's verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prepared {
    /// The action, as it will run.
    pub action: Action,
    /// Model text shown apart from the action (a reason or description), if any.
    pub note: Option<String>,
    /// For `shell`: whether the tagger marked the command destructive (`None`: no tagger).
    pub destructive: Option<bool>,
}

/// The tools behind the gate.
pub trait Executor: Send + Sync + 'static {
    /// The session's tools, as `tools/list` returns them.
    fn tools(&self) -> Vec<Tool>;
    /// Builds the action `name` with `arguments` would run, or refuses the call with a code
    /// (unknown tool, bad arguments, a path outside every mount, a protected path).
    ///
    /// # Errors
    /// The `denied: <code>` code.
    fn prepare(
        &self,
        name: &str,
        arguments: &Map<String, Value>,
    ) -> impl Future<Output = Result<Prepared, &'static str>> + Send;
    /// Runs the ticket's action and writes its effect entry first (#62). `None`: an entry could
    /// not be written and nothing ran.
    fn run(&self, ticket: Ticket) -> impl Future<Output = Option<ToolOutcome>> + Send;
}

/// The tool handler of one session.
pub struct Gated<E> {
    session: String,
    gate: Gate,
    exec: E,
}

impl<E: Executor> Gated<E> {
    /// The handler for `session`, asking `gate` and running through `exec`.
    #[must_use]
    pub fn new(session: String, gate: Gate, exec: E) -> Self {
        Self {
            session,
            gate,
            exec,
        }
    }
}

impl<E: Executor> ToolHandler for Gated<E> {
    fn tools(&self) -> Vec<Tool> {
        self.exec.tools()
    }

    async fn call(
        &self,
        call: u64,
        name: String,
        arguments: Map<String, Value>,
    ) -> Option<ToolOutcome> {
        let refusal = match self.exec.prepare(&name, &arguments).await {
            Err(code) => self.gate.refuse_call(call, &name, code).await,
            Ok(p) => {
                let bound = Bound {
                    session: self.session.clone(),
                    call,
                    action: p.action,
                };
                match self
                    .gate
                    .admit(bound, p.note.as_deref(), p.destructive)
                    .await
                {
                    Ok(ticket) => return self.exec.run(ticket).await,
                    Err(r) => r,
                }
            }
        };
        match refusal {
            Refusal::Denied(code) => Some(ToolOutcome {
                is_error: true,
                text: format!("denied: {code}"),
            }),
            Refusal::Unrecorded => None,
        }
    }

    async fn withdraw(&self, call: u64, why: Withdraw) {
        self.gate.withdraw(call, why).await;
    }
}
