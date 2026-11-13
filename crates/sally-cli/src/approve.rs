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

use std::collections::{HashSet, VecDeque};
use std::io::{BufRead, Write};

use sally_proto::{Prompt, Prompts, method, notification};
use serde_json::{Value, json};

use crate::client::{Client, Error};
use crate::commands::failed;
use crate::{EXIT_REFUSED, clean};

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

/// The prompts still to ask about, de-duplicated by id (architect Q73.4).
#[derive(Default)]
struct Queue {
    waiting: VecDeque<Prompt>,
    seen: HashSet<String>,
    closed: HashSet<String>,
    /// The last list was cut: list again once the queue is empty (architect Q84).
    cut: bool,
}

impl Queue {
    fn add(&mut self, p: Prompt) {
        if !self.closed.contains(&p.id) && self.seen.insert(p.id.clone()) {
            self.waiting.push_back(p);
        }
    }

    fn listed(&mut self, all: Prompts) {
        self.cut = !all.complete;
        for p in all.prompts {
            self.add(p);
        }
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
                if let Some(id) = params.get("id").and_then(Value::as_str) {
                    self.closed.insert(id.to_owned());
                    self.waiting.retain(|p| p.id != id);
                }
            }
            Some(notification::APPROVAL_FLOOD) => {
                let s = params.get("session").and_then(Value::as_str).unwrap_or("");
                let s = clean::line(s).text;
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
            if q.cut {
                q.listed(prompts(c.call(method::APPROVALS_LIST, json!({}))?)?);
            } else {
                let n = c.next_note()?;
                q.note(&n, tty.output);
            }
            continue;
        };
        if let Some(code) = ask(c, tty, &mut q, &p)? {
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
        if q.closed.contains(&p.id) {
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
            Err(e) => return Err(e),
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
