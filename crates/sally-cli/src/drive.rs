//! `sally session drive <id>`: runs a driven session's script to its end, one `sessions.drive`
//! request per scripted turn (architect Q117, Q121). The command opens one connection and sends
//! nothing but `sessions.drive` with the session id: the script lives in `sallyd`, and what a
//! turn does is decided there. Every line printed passed the clean-check, as everywhere.

use sally_proto::{Step, TurnKind, method};
use serde_json::json;

use crate::EXIT_FAILED;
use crate::client::Client;
use crate::commands::{Out, Printer, call, failed};

/// Steps asked for at most: a script holds up to [`sally_proto::MAX_TURNS`] turns, and the end
/// is one more answer. A daemon that keeps going past it is not speaking the protocol.
pub const MAX_STEPS: usize = sally_proto::MAX_TURNS + 1;

/// Drives session `id` until a step says it is done.
pub fn session_drive(c: &mut Client, id: &str, o: &mut Out<'_>) -> u8 {
    let mut p = Printer::new(o);
    for _ in 0..MAX_STEPS {
        match call::<Step>(c, method::SESSIONS_DRIVE, json!({"id": id})) {
            Ok(step) => {
                show(&mut p, &step);
                if step.done {
                    return p.code();
                }
            }
            Err(e) => return failed(&e, p.o.err).max(p.code()),
        }
    }
    let _ = writeln!(
        p.o.err,
        "sally: the daemon sent more steps than a script holds"
    );
    EXIT_FAILED.max(p.code())
}

/// One step's lines. The texts arrive escaped by `sallyd`; the printer checks them again.
fn show(p: &mut Printer<'_, '_>, s: &Step) {
    let turn = s.turn.to_string();
    match s.kind {
        TurnKind::Content => {
            let text = s.content.as_deref().unwrap_or_default();
            p.line(&["turn ", &turn, ": model says: ", text]);
        }
        TurnKind::ToolCalls if s.calls.is_empty() => p.line(&["turn ", &turn, ": no calls"]),
        TurnKind::ToolCalls => {
            for c in &s.calls {
                p.line(&["turn ", &turn, ": call ", &c.name, " -> ", &c.result]);
            }
        }
        TurnKind::Fail => p.line(&["turn ", &turn, ": the model failed"]),
        TurnKind::End => p.line(&["end of script"]),
    }
}

#[cfg(test)]
#[path = "drive_tests.rs"]
mod tests;
