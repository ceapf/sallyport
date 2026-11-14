//! `sally approve` (architect Q80): watches for prompts and asks a human, one at a time, on the
//! terminal (`/dev/tty`, never stdin or stdout, so nothing piped in can answer).
//!
//! - Answers are whole words: `approve`, `deny`, `deny-all`; anything else asks again.
//! - Typed-ahead input is discarded before each question (`flush`, tcflush in the binary).
//! - An answer is bound to the prompt on screen when the read began (its id and digest); if
//!   that prompt closed meanwhile, the line is discarded, never applied to the next one.
//! - A cut prompt shows its full text before the question; one whose full text could not be
//!   sent, or whose text failed the clean-check, can only be denied.
//! - The terminal closing (end of input) or failing denies the prompt on screen, and `sally`
//!   exits non-zero.
//! - The connection ending (sallyd stopped, or dropped this approver for falling behind; architect
//!   Q91) is told in one line, and `sally` exits non-zero: the prompts still pending are denied.

use std::collections::{HashSet, VecDeque};
use std::io::{BufRead, Write};

use sally_proto::{Closed, Flood, Prompt, Prompts, method, notification};
use serde_json::{Value, json};

use crate::client::{Client, Error};
use crate::commands::failed;
use crate::{EXIT_FAILED, EXIT_REFUSED, clean};

/// The terminal: where prompts are shown and answers read.
pub struct Tty<'a> {
    /// Answers.
    pub input: &'a mut dyn BufRead,
    /// Prompts and questions.
    pub output: &'a mut dyn Write,
    /// Discards typed-ahead input; called before each read.
    pub flush: &'a mut dyn FnMut(),
}

/// A human's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// `approve`.
    Approve,
    /// `deny`.
    Deny,
    /// `deny-all`: this prompt and the rest of its session.
    DenyAll,
}

impl Answer {
    fn wire(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Deny => "deny",
            Self::DenyAll => "deny_all_session",
        }
    }
}

/// `line` as an answer, when it is one of the words offered.
#[must_use]
pub fn parse_answer(line: &str, deny_only: bool) -> Option<Answer> {
    match line.trim() {
        "approve" if !deny_only => Some(Answer::Approve),
        "deny" => Some(Answer::Deny),
        "deny-all" => Some(Answer::DenyAll),
        _ => None,
    }
}

/// The prompts still to ask about, de-duplicated by id (architect Q73.4). It holds only live
/// prompts: a closed one leaves `seen` too (sallyd removes a prompt before it tells the close
/// and never reuses an id, so no later list or notification carries it again).
#[derive(Default)]
struct Queue {
    waiting: VecDeque<Prompt>,
    seen: HashSet<String>,
    /// The prompt on screen, and whether it closed while it was asked about.
    on_screen: Option<String>,
    on_screen_closed: bool,
    /// The last list was cut: list again once the queue is empty (architect Q84) ...
    cut: bool,
    /// ... and something was answered or closed since, so a new list can differ.
    progress: bool,
}

impl Queue {
    fn add(&mut self, p: Prompt) {
        if self.seen.insert(p.id.clone()) {
            self.waiting.push_back(p);
        }
    }

    fn listed(&mut self, all: Prompts) {
        self.cut = !all.complete;
        self.progress = false;
        for p in all.prompts {
            self.add(p);
        }
    }

    fn closed(&mut self, id: &str) {
        self.seen.remove(id);
        self.waiting.retain(|p| p.id != id);
        self.on_screen_closed |= self.on_screen.as_deref() == Some(id);
        self.progress = true;
    }

    /// Takes in one notification; a flood is told on `out`.
    fn note(&mut self, n: &Value, out: &mut dyn Write) {
        let params = n.get("params").cloned().unwrap_or(Value::Null);
        match n.get("method").and_then(Value::as_str) {
            Some(notification::APPROVAL_REQUESTED) => {
                if let Ok(p) = serde_json::from_value::<Prompt>(params) {
                    self.add(p);
                }
            }
            Some(notification::APPROVAL_CLOSED) => {
                if let Ok(c) = serde_json::from_value::<Closed>(params) {
                    self.closed(&c.id);
                }
            }
            Some(notification::APPROVAL_FLOOD) => {
                let s = serde_json::from_value::<Flood>(params)
                    .map_or_else(|_| String::new(), |f| f.session);
                let s = clean::line(&s).text;
                let _ = writeln!(
                    out,
                    "session {s} is asking too often: its prompts are denied for now"
                );
            }
            _ => {}
        }
    }
}

/// Runs the approver until the terminal closes or the connection ends.
pub fn approve(c: &mut Client, tty: &mut Tty<'_>, err: &mut dyn Write) -> u8 {
    match run(c, tty) {
        Ok(code) => code,
        Err(Error::Closed | Error::Behind) => {
            let _ = writeln!(
                err,
                "sally: lost sallyd (it stopped, or this approver fell behind); \
                 prompts still pending are denied"
            );
            EXIT_FAILED
        }
        Err(e) => failed(&e, err),
    }
}

fn run(c: &mut Client, tty: &mut Tty<'_>) -> Result<u8, Error> {
    let mut q = Queue::default();
    q.listed(prompts(c.call(method::APPROVALS_WATCH, json!({}))?)?);
    loop {
        while let Some(n) = c.try_note()? {
            q.note(&n, tty.output);
        }
        let Some(p) = q.waiting.pop_front() else {
            if q.cut && q.progress {
                q.listed(prompts(c.call(method::APPROVALS_LIST, json!({}))?)?);
            } else {
                let n = c.next_note()?;
                q.note(&n, tty.output);
            }
            continue;
        };
        q.on_screen = Some(p.id.clone());
        q.on_screen_closed = false;
        let asked = ask(c, tty, &mut q, &p);
        q.on_screen = None;
        q.progress = true;
        if let Some(code) = asked? {
            return Ok(code);
        }
    }
}

fn prompts(v: Value) -> Result<Prompts, Error> {
    serde_json::from_value(v).map_err(|_| Error::Unexpected)
}

/// Shows `p` and asks until it is answered or closed; `Some(code)` when `sally` must exit.
fn ask(c: &mut Client, tty: &mut Tty<'_>, q: &mut Queue, p: &Prompt) -> Result<Option<u8>, Error> {
    let shown = clean::text(&p.text);
    let mut deny_only = !shown.clean;
    let _ = write!(tty.output, "\n{}", shown.text);
    let mut full_shown = false;
    if p.truncated {
        match &p.full {
            Some(full) if !p.full_unavailable => {
                let full = clean::text(full);
                deny_only |= !full.clean;
                full_shown = full.clean;
                let _ = writeln!(tty.output, "  full action:\n{}", full.text);
            }
            _ => {
                deny_only = true;
                let _ = writeln!(tty.output, "  (the full action is too long to show)");
            }
        }
    }
    loop {
        let question = if deny_only {
            "deny or deny-all? "
        } else {
            "approve, deny or deny-all? "
        };
        let _ = write!(tty.output, "{question}");
        let _ = tty.output.flush();
        (tty.flush)();
        let mut line = String::new();
        let read = tty.input.read_line(&mut line);
        if !matches!(read, Ok(n) if n > 0) {
            // The terminal is gone: the prompt on screen is denied.
            let _ = decide(c, p, Answer::Deny, false);
            let _ = writeln!(
                tty.output,
                "\nno terminal input: denied {}",
                clean::line(&p.id).text
            );
            return Ok(Some(EXIT_REFUSED));
        }
        while let Some(n) = c.try_note()? {
            q.note(&n, tty.output);
        }
        if q.on_screen_closed {
            let _ = writeln!(
                tty.output,
                "that prompt closed meanwhile; the answer was not used"
            );
            return Ok(None);
        }
        let Some(answer) = parse_answer(&line, deny_only) else {
            continue;
        };
        match decide(c, p, answer, full_shown) {
            Ok(()) => {
                let _ = writeln!(tty.output, "{}: {}", answer.wire(), clean::line(&p.id).text);
            }
            Err(Error::Refused(d)) => {
                let reason = clean::line(&d.reason).text;
                let _ = writeln!(tty.output, "not taken: {reason}");
            }
            // Sent, perhaps, but no reply: sallyd may have applied it.
            Err(e) => {
                let id = clean::line(&p.id).text;
                let _ = writeln!(
                    tty.output,
                    "the {} for {id} may have been taken (see the audit log)",
                    answer.wire()
                );
                return Err(e);
            }
        }
        return Ok(None);
    }
}

fn decide(c: &mut Client, p: &Prompt, a: Answer, full_shown: bool) -> Result<(), Error> {
    let params = json!({
        "id": p.id, "decision": a.wire(), "digest": p.digest,
        "full_shown": full_shown && a == Answer::Approve,
    });
    c.call(method::APPROVALS_DECIDE, params).map(drop)
}

#[cfg(test)]
#[path = "approve_tests.rs"]
mod tests;
