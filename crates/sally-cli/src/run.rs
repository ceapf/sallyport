//! `sally sandbox run --manifest <file> -- <cmd>…`: runs a command in a session's workspace,
//! in line mode (architect Q49, Q100–Q102, Q144–Q152).
//!
//! The command starts a session bound to its connection (`lifetime: "connection"`), attaches
//! the command, and then only relays: the command's output, which `sallyd` escaped to printable
//! ASCII and newline, goes to stdout and stderr after the clean-check; this terminal's stdin
//! goes to the command as UTF-8 text, one `sessions.input` at a time, each sent after the last
//! was written. When the command ends, the session is stopped and `sally` exits with the
//! command's code (137 if `sallyd` killed it), or 1 if any output failed the clean-check (it is
//! shown escaped); a refused stop makes it at least 1. Ctrl-C ends `sally`; its connection's
//! end kills the command and stops the session.
//!
//! Nothing here asks for a decision: approvals are answered in another terminal (`sally
//! approve`). Anything prompt-like in the run terminal is the command's output; the exit status
//! and `sally audit tail` are what to trust. `sally` prints nothing of its own between the
//! attach and its reply; its own lines go to stderr, prefixed `sally: `.
//!
//! A reader that stops reading for over 10 s (output piped into a paused pager) gets the
//! command killed: `sallyd` drops a connection whose write blocks that long (architect Q152).
//! TODO(#139): binary stdin; invalid UTF-8 on stdin ends the run (`disconnect`), never with an
//! end of input. TODO(#138): `--tty`, raw terminal passthrough, before M1 exit.

use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};

use sally_proto::{Attached, KillReason, MAX_INPUT_BYTES, Output, Session, Stream, method};
use serde_json::{Value, json};

use crate::client::{Client, Decoded, Error, Writer};
use crate::commands::{Out, call, failed, read_manifest};
use crate::{EXIT_FAILED, EXIT_REFUSED, clean};

/// The exit code of a command `sallyd` killed (as a shell reports a `SIGKILL`).
pub const EXIT_KILLED: u8 = 137;

/// Request ids of the stdin thread start here, so its replies are told apart from the run's
/// own.
pub const INPUT_IDS: i64 = 1 << 40;

/// Stdin cut into UTF-8 text: a character split across two reads is carried, at most 3 bytes.
#[derive(Debug, Default)]
pub struct Utf8Cut {
    carry: Vec<u8>,
}

/// Stdin is not UTF-8 text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotUtf8;

impl Utf8Cut {
    /// How many bytes to read next, so the text sent, carry included, is at most
    /// [`MAX_INPUT_BYTES`].
    #[must_use]
    pub fn read_len(&self) -> usize {
        MAX_INPUT_BYTES.saturating_sub(self.carry.len())
    }

    /// The whole characters of what was carried and `read`; an incomplete one at the end is
    /// carried.
    ///
    /// # Errors
    /// [`NotUtf8`] for a byte sequence that is not UTF-8.
    pub fn take(&mut self, read: &[u8]) -> Result<String, NotUtf8> {
        let mut bytes = std::mem::take(&mut self.carry);
        bytes.extend_from_slice(read);
        match String::from_utf8(bytes) {
            Ok(s) => Ok(s),
            Err(e) => {
                let err = e.utf8_error();
                if err.error_len().is_some() {
                    return Err(NotUtf8);
                }
                let mut bytes = e.into_bytes();
                self.carry = bytes.split_off(err.valid_up_to());
                String::from_utf8(bytes).map_err(|_| NotUtf8)
            }
        }
    }

    /// The end of stdin.
    ///
    /// # Errors
    /// [`NotUtf8`] when a character was cut short by the end.
    pub fn finish(self) -> Result<(), NotUtf8> {
        if self.carry.is_empty() {
            Ok(())
        } else {
            Err(NotUtf8)
        }
    }
}

/// The exit code for how the command ended; `Err` with the code `sallyd` sent when it is no
/// exit status.
///
/// # Errors
/// The code, when it is outside 0–255.
pub fn exit_of(a: &Attached) -> Result<u8, i32> {
    match a {
        Attached::Exited { exit_code } => u8::try_from(*exit_code).map_err(|_| *exit_code),
        Attached::Killed { .. } => Ok(EXIT_KILLED),
    }
}

fn kill_name(k: KillReason) -> &'static str {
    match k {
        KillReason::SessionStop => "the session stopped",
        KillReason::Disconnect => "the connection closed",
        KillReason::StartTimeout => "it did not start in time",
    }
}

/// Runs `argv` in a session of `manifest`, its stdin `stdin`.
pub fn sandbox_run(
    c: &mut Client,
    manifest: &Path,
    argv: &[String],
    stdin: impl Read + Send + 'static,
    o: &mut Out<'_>,
) -> u8 {
    let text = match read_manifest(manifest) {
        Ok(t) => t,
        Err(msg) => {
            let shown = clean::line(&manifest.display().to_string()).text;
            let _ = writeln!(o.err, "sally: {shown}: {msg}");
            return EXIT_FAILED;
        }
    };
    let params = json!({"manifest": text, "lifetime": "connection"});
    let session = match call::<Session>(c, method::SESSIONS_CREATE, params) {
        Ok(s) => s,
        Err(e) => return failed(&e, o.err),
    };
    // A run that failed leaves the session to its connection's end: `sally` exits, and the
    // bound session stops (`disconnect`).
    let (code, dirty) = match attach(c, &session.id, argv, stdin, o) {
        Ok(ended) => ended,
        Err(code) => return code,
    };
    let code = if stop(c, &session.id, o.err) {
        code
    } else {
        code.max(EXIT_REFUSED)
    };
    if dirty {
        // Q149: dirty is EXIT_REFUSED, whatever the command's code: a run that showed
        // something escaped is refused, never mistaken for the command's own result.
        let _ = writeln!(
            o.err,
            "sally: some output was not clean; it is shown escaped"
        );
        return EXIT_REFUSED;
    }
    code
}

/// Attaches `argv` and relays until its reply: `Ok` with the command's exit code and whether any
/// output failed the clean-check; `Err` with the exit code of a failed run.
fn attach(
    c: &mut Client,
    id: &str,
    argv: &[String],
    stdin: impl Read + Send + 'static,
    o: &mut Out<'_>,
) -> Result<(u8, bool), u8> {
    let attach = c
        .send(method::SESSIONS_ATTACH, json!({"id": id, "argv": argv}))
        .map_err(|e| failed(&e, o.err))?;
    let writer = c.writer(INPUT_IDS).map_err(|e| failed(&e, o.err))?;
    let (permits, granted) = mpsc::sync_channel(1);
    let _ = permits.try_send(());
    let invalid = Arc::new(AtomicBool::new(false));
    let pump = Pump {
        id: id.to_owned(),
        w: writer,
        granted,
        invalid: Arc::clone(&invalid),
    };
    std::thread::spawn(move || pump.run(stdin));
    let mut shown = Shown::default();
    let end = relay(c, attach, &invalid, permits, &mut shown, o);
    // `sally`'s own lines start a line of their own, never the end of the command's.
    if shown.open {
        let _ = writeln!(o.err);
    }
    match end {
        Relayed::Reply(result) => ended(result, o).map(|code| (code, shown.dirty)),
        Relayed::Failed(e) => Err(failed(&e, o.err)),
        Relayed::NotUtf8 => {
            let _ = writeln!(
                o.err,
                "sally: stdin is not UTF-8 text; the command was ended"
            );
            Err(EXIT_FAILED)
        }
    }
}

/// What the command's output did to the terminal so far.
#[derive(Debug, Default)]
struct Shown {
    /// Some output failed the clean-check.
    dirty: bool,
    /// The last output did not end its line.
    open: bool,
}

/// How a relay ended; nothing of `sally`'s own is printed until then.
enum Relayed {
    /// The attach's reply.
    Reply(Result<Value, Error>),
    /// The run failed.
    Failed(Error),
    /// Stdin was not UTF-8 text.
    NotUtf8,
}

/// Prints the command's output and passes its stdin on, until the attach's reply.
fn relay(
    c: &mut Client,
    attach: i64,
    invalid: &AtomicBool,
    permits: SyncSender<()>,
    shown: &mut Shown,
    o: &mut Out<'_>,
) -> Relayed {
    let mut permits = Some(permits);
    loop {
        let frame = match c.recv() {
            Ok(f) => f,
            Err(_) if invalid.load(Ordering::SeqCst) => return Relayed::NotUtf8,
            Err(e) => return Relayed::Failed(e),
        };
        match frame {
            Decoded::Note(n) => {
                if let Err(e) = show(&n, shown, o) {
                    return Relayed::Failed(e);
                }
            }
            Decoded::Reply { id: got, result } if got == json!(attach) => {
                return Relayed::Reply(result);
            }
            Decoded::Reply { id: got, result } if is_input(&got) => match result {
                Ok(_) => {
                    if let Some(p) = &permits {
                        let _ = p.try_send(());
                    }
                }
                // The command no longer takes input: stop sending it.
                Err(Error::Refused(d)) if d.reason == "input-closed" => permits = None,
                Err(e) => return Relayed::Failed(e),
            },
            Decoded::Reply { .. } => return Relayed::Failed(Error::Unexpected),
        }
    }
}

/// Whether a reply's id is one of the stdin thread's.
fn is_input(id: &Value) -> bool {
    id.as_i64().is_some_and(|i| i >= INPUT_IDS)
}

/// The attach's reply as an exit code.
fn ended(result: Result<Value, Error>, o: &mut Out<'_>) -> Result<u8, u8> {
    let v = result.map_err(|e| failed(&e, o.err))?;
    let a: Attached = serde_json::from_value(v).map_err(|_| failed(&Error::Unexpected, o.err))?;
    if let Attached::Killed { killed } = &a {
        let why = kill_name(*killed);
        let _ = writeln!(o.err, "sally: the command was killed: {why}");
    }
    match exit_of(&a) {
        Ok(code) => Ok(code),
        Err(n) => {
            let _ = writeln!(o.err, "sally: sallyd sent an exit code out of range ({n})");
            Err(EXIT_FAILED)
        }
    }
}

/// Prints one `session.output`, noting in `shown` whether it was clean and ended its line.
fn show(note: &Value, shown: &mut Shown, o: &mut Out<'_>) -> Result<(), Error> {
    if note.get("method") != Some(&json!(sally_proto::notification::SESSION_OUTPUT)) {
        return Err(Error::Unexpected);
    }
    let out: Output = note
        .get("params")
        .cloned()
        .and_then(|p| serde_json::from_value(p).ok())
        .ok_or(Error::Unexpected)?;
    let checked = clean::text(&out.text);
    let w = match out.stream {
        Stream::Stdout => &mut *o.out,
        Stream::Stderr => &mut *o.err,
    };
    // TODO(#143): a closed stdout (EPIPE) should end the run.
    let _ = write!(w, "{}", checked.text);
    let _ = w.flush();
    shown.dirty |= !checked.clean;
    if let Some(last) = checked.text.chars().last() {
        shown.open = last != '\n';
    }
    Ok(())
}

/// Stops session `id`; whether it stopped. Replies to the stdin thread's late inputs are passed
/// over; a refusal is printed.
fn stop(c: &mut Client, id: &str, err: &mut dyn std::io::Write) -> bool {
    let sent = match c.send(method::SESSIONS_STOP, json!({"id": id})) {
        Ok(s) => s,
        Err(e) => {
            failed(&e, err);
            return false;
        }
    };
    loop {
        match c.recv() {
            Ok(Decoded::Reply { id: got, result }) if got == json!(sent) => {
                return match result {
                    Ok(_) => true,
                    Err(e) => {
                        failed(&e, err);
                        false
                    }
                };
            }
            Ok(Decoded::Reply { id: got, .. }) if is_input(&got) => {}
            Ok(_) => {
                failed(&Error::Unexpected, err);
                return false;
            }
            Err(e) => {
                failed(&e, err);
                return false;
            }
        }
    }
}

/// The stdin thread: reads stdin, cuts it into UTF-8 text and sends it, one input per permit.
struct Pump {
    id: String,
    w: Writer,
    granted: Receiver<()>,
    invalid: Arc<AtomicBool>,
}

impl Pump {
    fn run(mut self, mut stdin: impl Read) {
        let mut cut = Utf8Cut::default();
        let mut buf = vec![0u8; MAX_INPUT_BYTES];
        loop {
            let want = cut.read_len();
            let Some(space) = buf.get_mut(..want) else {
                return;
            };
            let n = match stdin.read(space) {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                // Any other read error is the end of stdin.
                Err(_) => 0,
            };
            if n == 0 {
                if cut.finish().is_err() {
                    self.not_utf8();
                } else {
                    self.send("", true);
                }
                return;
            }
            match cut.take(buf.get(..n).unwrap_or_default()) {
                Ok(text) if text.is_empty() => {}
                Ok(text) => {
                    if !self.send(&text, false) {
                        return;
                    }
                }
                Err(NotUtf8) => {
                    self.not_utf8();
                    return;
                }
            }
        }
    }

    /// Sends one input once the last was written; `false` once inputs are no longer taken.
    fn send(&mut self, data: &str, eof: bool) -> bool {
        if self.granted.recv().is_err() {
            return false;
        }
        let params = json!({"id": self.id, "data": data, "eof": eof});
        self.w.send(method::SESSIONS_INPUT, params).is_ok()
    }

    /// Ends the run without an end of input: the connection closes, which kills the command.
    fn not_utf8(&self) {
        self.invalid.store(true, Ordering::SeqCst);
        self.w.close();
    }
}

#[cfg(test)]
#[path = "run_tests.rs"]
mod tests;
