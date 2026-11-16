//! Line mode's pure decisions (architect Q101, Q144–Q152): what a control connection may ask
//! while it is attached, whether an input is taken, how much of a pipe is read at once, and
//! what an attached command's end is told and audited. The serve loop that holds the attach is
//! in `control.rs`; the runner is `tools/exec.rs`.
//!
//! A control connection is in one state at a time ([`ConnState`]): plain, watching (it called
//! `approvals.watch`), driving (it holds a live drive seat) or attached. While attached it is
//! served `sessions.input` only; any other admitted method is refused `attached` and the attach
//! goes on. `sessions.attach` is refused on a watching connection (`attach-watching`) and on a
//! driving one (`driver-seat`); `sessions.input` on a connection that is not attached, or for
//! another session, is `not-attached`.

use sally_proto::{AttachParams, Attached, InputParams, KillReason, MAX_INPUT_BYTES};
use serde_json::{Value, json};

use super::control_methods::NotAdmitted;
use crate::approvals::Client;
use crate::approvals::queue::who;
use crate::sandbox::SessionId;
use crate::tools::args::argv_shaped;
use crate::tools::shell::{Ran, Status};

/// Output chunks queued for one attached connection at most; a pipe reader waits for room, so
/// nothing is dropped and nothing grows without bound (architect Q152).
pub const OUTPUT_QUEUE: usize = 8;

/// An admitted `sessions.attach`.
#[derive(Debug)]
pub struct AttachCall {
    /// The session.
    pub id: SessionId,
    /// The command.
    pub argv: Vec<String>,
    /// The asked guest directory, checked later as the shell tool checks its own.
    pub cwd: Option<String>,
}

impl AttachCall {
    /// `p` admitted: its id canonical, its argv as the shell tool's `cmd` (1 to
    /// [`MAX_ARGV`](crate::tools::args::MAX_ARGV) strings, the first not empty, none with a NUL;
    /// architect Q101).
    ///
    /// # Errors
    /// [`NotAdmitted::InvalidParams`].
    pub fn admit(p: AttachParams) -> Result<Self, NotAdmitted> {
        if !argv_shaped(&p.argv) {
            return Err(NotAdmitted::InvalidParams);
        }
        Ok(Self {
            id: SessionId::parse(&p.id).map_err(|_| NotAdmitted::InvalidParams)?,
            argv: p.argv,
            cwd: p.cwd,
        })
    }
}

/// An admitted `sessions.input`.
#[derive(Debug)]
pub struct InputCall {
    /// The session.
    pub id: SessionId,
    /// The bytes.
    pub data: String,
    /// The input ends after them.
    pub eof: bool,
}

impl InputCall {
    /// `p` admitted: its id canonical, its data at most [`MAX_INPUT_BYTES`].
    ///
    /// # Errors
    /// [`NotAdmitted::InvalidParams`].
    pub fn admit(p: InputParams) -> Result<Self, NotAdmitted> {
        if p.data.len() > MAX_INPUT_BYTES {
            return Err(NotAdmitted::InvalidParams);
        }
        Ok(Self {
            id: SessionId::parse(&p.id).map_err(|_| NotAdmitted::InvalidParams)?,
            data: p.data,
            eof: p.eof,
        })
    }
}

/// What a control connection is now (architect Q144).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnState {
    /// None of the others.
    Plain,
    /// It called `approvals.watch`.
    Watching,
    /// It holds a live drive seat.
    Driving,
    /// A command it attached runs.
    Attached,
}

impl ConnState {
    /// The state of a connection with these marks. The serve loop never lets two hold at once;
    /// if they did, the most restrictive is the one that counts.
    #[must_use]
    pub fn of(watching: bool, driving: bool, attached: bool) -> Self {
        if attached {
            Self::Attached
        } else if driving {
            Self::Driving
        } else if watching {
            Self::Watching
        } else {
            Self::Plain
        }
    }
}

/// An admitted method, as the state gate sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Asked {
    /// `sessions.input`.
    Input,
    /// `sessions.attach`.
    Attach,
    /// Any other method.
    Other,
}

/// Whether a connection in `state` is served `asked`; the refusal reason if not.
///
/// # Errors
/// `attached`, `not-attached`, `attach-watching` or `driver-seat`.
pub fn gate(state: ConnState, asked: Asked) -> Result<(), &'static str> {
    match (state, asked) {
        (ConnState::Attached, Asked::Input) => Ok(()),
        (ConnState::Attached, Asked::Attach | Asked::Other) => Err("attached"),
        (ConnState::Plain | ConnState::Watching | ConnState::Driving, Asked::Input) => {
            Err("not-attached")
        }
        (ConnState::Watching, Asked::Attach) => Err("attach-watching"),
        (ConnState::Driving, Asked::Attach) => Err("driver-seat"),
        (ConnState::Plain, Asked::Attach)
        | (ConnState::Watching | ConnState::Driving | ConnState::Plain, Asked::Other) => Ok(()),
    }
}

/// The attached command's standard input, as an input request finds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InputState {
    /// An input is taken and not yet written.
    pub pending: bool,
    /// An input with `eof` was taken, or a write to the pipe failed.
    pub closed: bool,
}

/// Whether an input for session `asked` is taken on a connection attached to `attached`.
///
/// # Errors
/// `not-attached` (another session), `input-closed`, `input-pending`.
pub fn admit_input(attached: &str, asked: &str, s: InputState) -> Result<(), &'static str> {
    if attached != asked {
        Err("not-attached")
    } else if s.closed {
        Err("input-closed")
    } else if s.pending {
        Err("input-pending")
    } else {
        Ok(())
    }
}

/// How an attach ends for its client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ended {
    /// The reply.
    Reply(Attached),
    /// `podman exec` could not be run: refused `exec-failed` (architect Q147).
    Failed,
}

/// The end of an attached command that ended with `status`. A kill this runner cannot give an
/// attached command (`timeout`: it runs without a time limit) is a failure, never a code.
#[must_use]
pub fn ended(status: &Status) -> Ended {
    match status {
        Status::Exited(exit_code) => Ended::Reply(Attached::Exited {
            exit_code: *exit_code,
        }),
        Status::Killed(why) => match kill_reason(why) {
            Some(killed) => Ended::Reply(Attached::Killed { killed }),
            None => Ended::Failed,
        },
        Status::Failed(_) => Ended::Failed,
    }
}

fn kill_reason(why: &str) -> Option<KillReason> {
    match why {
        "session-stop" => Some(KillReason::SessionStop),
        "disconnect" => Some(KillReason::Disconnect),
        "start-timeout" => Some(KillReason::StartTimeout),
        _ => None,
    }
}

/// `sandbox.exec`'s args (architect Q101): the session's `exec` number, the argv (the audit
/// writer redacts it and hashes it past 4 KiB), the guest directory and the client.
#[must_use]
pub fn exec_args(exec: u64, argv: &[String], cwd: &str, client: Client) -> Value {
    json!({"exec": exec, "argv": argv, "cwd": cwd, "client": who(client)})
}

/// `sandbox.exec_result`'s args: how it ended and the bytes moved, never their content.
#[must_use]
pub fn result_args(exec: u64, ran: &Ran) -> Value {
    let mut v = json!({
        "exec": exec,
        "stdin_bytes": ran.stdin,
        "stdout_bytes": ran.stdout,
        "stderr_bytes": ran.stderr,
    });
    if let Some(m) = v.as_object_mut() {
        match ended(&ran.status) {
            Ended::Reply(Attached::Exited { exit_code }) => {
                m.insert("exit_code".into(), Value::from(exit_code));
            }
            Ended::Reply(Attached::Killed { killed }) => {
                m.insert("killed".into(), json!(killed));
            }
            Ended::Failed => {
                m.insert("failed".into(), Value::from(true));
            }
        }
    }
    v
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use sally_core::text::StreamEscaper;
    use sally_proto::{MAX_FRAME, MAX_INPUT_BYTES, MAX_OUTPUT_CHUNK, Output, Stream, notification};

    use super::*;

    const STATES: [ConnState; 4] = [
        ConnState::Plain,
        ConnState::Watching,
        ConnState::Driving,
        ConnState::Attached,
    ];

    #[test]
    fn the_state_is_the_most_restrictive_mark() {
        assert_eq!(ConnState::of(false, false, false), ConnState::Plain);
        assert_eq!(ConnState::of(true, false, false), ConnState::Watching);
        assert_eq!(ConnState::of(false, true, false), ConnState::Driving);
        assert_eq!(ConnState::of(false, false, true), ConnState::Attached);
        assert_eq!(ConnState::of(true, true, false), ConnState::Driving);
        assert_eq!(ConnState::of(true, true, true), ConnState::Attached);
        assert_eq!(ConnState::of(true, false, true), ConnState::Attached);
    }

    /// Architect Q144: each state against each kind of method, allow and deny.
    #[test]
    fn the_gate_for_every_state_and_method() {
        for s in STATES {
            let input = gate(s, Asked::Input);
            let attach = gate(s, Asked::Attach);
            let other = gate(s, Asked::Other);
            match s {
                ConnState::Plain => {
                    assert_eq!(
                        (input, attach, other),
                        (Err("not-attached"), Ok(()), Ok(()))
                    );
                }
                ConnState::Watching => assert_eq!(
                    (input, attach, other),
                    (Err("not-attached"), Err("attach-watching"), Ok(()))
                ),
                ConnState::Driving => assert_eq!(
                    (input, attach, other),
                    (Err("not-attached"), Err("driver-seat"), Ok(()))
                ),
                ConnState::Attached => assert_eq!(
                    (input, attach, other),
                    (Ok(()), Err("attached"), Err("attached"))
                ),
            }
        }
    }

    /// Architect Q101, Q147: an input is taken only for the attached session, one at a time,
    /// and never after the input ended.
    #[test]
    fn an_input_is_taken_once_at_a_time_for_the_attached_session() {
        let open = InputState::default();
        assert_eq!(admit_input("a", "a", open), Ok(()));
        assert_eq!(admit_input("a", "b", open), Err("not-attached"));
        let pending = InputState {
            pending: true,
            closed: false,
        };
        assert_eq!(admit_input("a", "a", pending), Err("input-pending"));
        let closed = InputState {
            pending: false,
            closed: true,
        };
        assert_eq!(admit_input("a", "a", closed), Err("input-closed"));
        let both = InputState {
            pending: true,
            closed: true,
        };
        assert_eq!(admit_input("a", "a", both), Err("input-closed"));
        assert_eq!(admit_input("a", "b", both), Err("not-attached"));
    }

    #[test]
    fn the_queue_is_the_ruled_number() {
        assert_eq!(OUTPUT_QUEUE, 8);
    }

    #[test]
    fn each_end_has_its_reply() {
        assert_eq!(
            ended(&Status::Exited(130)),
            Ended::Reply(Attached::Exited { exit_code: 130 })
        );
        for (why, r) in [
            ("session-stop", KillReason::SessionStop),
            ("disconnect", KillReason::Disconnect),
            ("start-timeout", KillReason::StartTimeout),
        ] {
            assert_eq!(
                ended(&Status::Killed(why)),
                Ended::Reply(Attached::Killed { killed: r })
            );
        }
        assert_eq!(ended(&Status::Killed("timeout")), Ended::Failed);
        assert_eq!(ended(&Status::Failed("x".into())), Ended::Failed);
    }

    #[test]
    fn the_entries_carry_counts_and_the_end_never_content() {
        let client = Client { uid: 1000, pid: 7 };
        assert_eq!(
            exec_args(2, &["sh".into()], "/w", client),
            json!({"exec": 2, "argv": ["sh"], "cwd": "/w", "client": {"uid": 1000, "pid": 7}})
        );
        let ran = |status| Ran {
            status,
            stdin: 1,
            stdout: 2,
            stderr: 3,
        };
        let base = |extra: Value| {
            let mut v = json!({"exec": 4, "stdin_bytes": 1, "stdout_bytes": 2, "stderr_bytes": 3});
            v.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            v
        };
        assert_eq!(
            result_args(4, &ran(Status::Exited(0))),
            base(json!({"exit_code": 0}))
        );
        assert_eq!(
            result_args(4, &ran(Status::Killed("disconnect"))),
            base(json!({"killed": "disconnect"}))
        );
        assert_eq!(
            result_args(4, &ran(Status::Failed("podman exec: x".into()))),
            base(json!({"failed": true}))
        );
    }

    /// Architect Q152: the largest output notification, a full chunk of bytes that each escape
    /// to `\xNN` and then to JSON, fits the client's frame cap.
    #[test]
    fn the_worst_output_frame_fits_a_frame() {
        let mut e = StreamEscaper::default();
        let text = e.push(&vec![0x1b; MAX_OUTPUT_CHUNK]);
        let note = json!({"jsonrpc": "2.0", "method": notification::SESSION_OUTPUT,
            "params": Output { id: "f".repeat(64), stream: Stream::Stderr, text }});
        let len = serde_json::to_vec(&note).unwrap().len() + 1;
        assert!(len > 5 * MAX_OUTPUT_CHUNK && len < MAX_FRAME, "{len}");
        // A full chunk of the longest characters escapes shorter.
        let wide = "\u{10ffff}".repeat(MAX_OUTPUT_CHUNK / 4);
        let text = StreamEscaper::default().push(wide.as_bytes());
        assert!(serde_json::to_vec(&text).unwrap().len() < len);
    }

    /// Architect Q148: the largest input request, every byte a control that JSON writes as
    /// `\u00NN`, fits the daemon's frame cap.
    #[test]
    fn the_worst_input_frame_fits_a_frame() {
        let data = "\u{1}".repeat(MAX_INPUT_BYTES);
        let req = json!({"jsonrpc": "2.0", "id": i64::MAX, "method": "sessions.input",
            "params": {"id": "f".repeat(64), "data": data, "eof": true}});
        let len = serde_json::to_vec(&req).unwrap().len() + 1;
        assert!(len > 6 * MAX_INPUT_BYTES && len < MAX_FRAME, "{len}");
    }
}
