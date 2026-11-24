//! `sally approve` (architect Q80): watches for prompts and asks a human, one at a time, on the
//! terminal (`/dev/tty`, never stdin or stdout, so nothing piped in can answer).
//!
//! - Answers are whole words: `approve`, `deny`, `deny-all`; anything else asks again.
//! - Typed-ahead input is discarded before each question (`flush`, tcflush in the binary).
//! - An answer is bound to the prompt on screen when the read began (its id and digest); if
//!   that prompt closed meanwhile, the line is discarded, never applied to the next one.
//! - A prompt is laid out here ([`layout`], RT-AG-04): the CLI's lines at the left edge, every
//!   row of request text behind [`GUTTER`], wrapped to the terminal's width. A cut prompt shows
//!   its full text before the question; one whose full text could not be sent, or whose text
//!   failed the clean-check, can only be denied.
//! - When the prompt is taller than the screen, and above every question asked again, the start
//!   of the action is printed again ([`again`]), so it is in the last screen before the
//!   question; when fewer than [`MIN_HEAD_ROWS`] rows of it fit, or the terminal's size is not
//!   known or under [`MIN_COLUMNS`] columns, the prompt can only be denied.
//! - The terminal closing (end of input) or failing, its typed-ahead input included when it
//!   cannot be discarded, denies the prompt on screen, and `sally` exits non-zero.
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
    /// Discards typed-ahead input; called before each read. When it fails, nothing is read:
    /// the input could be an answer typed before the question.
    pub flush: &'a mut dyn FnMut() -> std::io::Result<()>,
    /// The terminal's size, read each time a prompt or its again-block is laid out.
    pub size: &'a mut dyn FnMut() -> Size,
}

/// A terminal's size; 0 for either means it is not known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Size {
    /// Columns.
    pub columns: u16,
    /// Rows.
    pub rows: u16,
}

/// What every row of request text is printed behind (RT-AG-04): no row of it starts at the left
/// edge, where the CLI's own lines start, and none of those lines starts with it.
pub const GUTTER: &str = "  | ";
/// Below this many columns a prompt can only be denied: a guttered row must hold
/// [`sally_core::text::LONGEST_UNIT`].
pub(crate) const MIN_COLUMNS: usize = 40;
/// Below this many rows of the action's start above the question, a prompt can only be denied.
pub(crate) const MIN_HEAD_ROWS: usize = 4;
/// The screen a prompt is laid out on when the terminal's size is not known, or narrower than
/// [`MIN_COLUMNS`]; such a prompt can only be denied.
const FALLBACK: (usize, usize) = (80, 24);

/// The columns and rows a prompt is laid out on, and the reason it can only be denied when the
/// size cannot be used: unknown (either is 0), or fewer than [`MIN_COLUMNS`] columns.
fn screen(size: Size) -> ((usize, usize), Option<&'static str>) {
    let (columns, rows) = (usize::from(size.columns), usize::from(size.rows));
    if columns == 0 || rows == 0 {
        return (FALLBACK, Some("the terminal's size is not known"));
    }
    if columns < MIN_COLUMNS {
        return (FALLBACK, Some("the terminal is narrower than 40 columns"));
    }
    ((columns, rows), None)
}

/// A prompt laid out for one terminal ([`layout`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    /// Everything printed before the first question, each line ending in `\n`.
    pub shown: String,
    /// Only deny can be answered.
    pub deny_only: bool,
    /// A cut prompt's full text is in `shown`.
    pub full_shown: bool,
    /// A field failed the clean-check (shown escaped).
    pub dirty: bool,
}

/// Lines being laid out: the CLI's own at the left edge, request text in guttered rows of at
/// most `columns - 1` characters, and the rows they take on the screen.
struct Lines {
    text: String,
    rows: usize,
    /// Guttered rows break at this many characters; `None` leaves them whole.
    width: Option<usize>,
    /// Characters a screen row is counted to hold: one fewer than its columns, as a terminal
    /// that wraps eagerly moves to the next row on the last column.
    usable: usize,
    /// A field failed the clean-check.
    dirty: bool,
}

impl Lines {
    /// Lines for a screen of `columns` (`None`: not a terminal, rows left whole). Not named `new`:
    /// it holds logic, and cargo-mutants skips functions named `new` (CLAUDE.md).
    fn on(columns: Option<usize>) -> Self {
        let usable = columns.map(|c| c.saturating_sub(1).max(1));
        Self {
            text: String::new(),
            rows: 0,
            width: usable.map(|u| u.saturating_sub(GUTTER.len())),
            usable: usable.unwrap_or(usize::MAX),
            dirty: false,
        }
    }

    /// The screen rows `len` characters take, at least one.
    fn rows_for(&self, len: usize) -> usize {
        len.div_ceil(self.usable).max(1)
    }

    /// One of the CLI's lines, at the left edge; its sallyd-sent parts are checked by the
    /// caller.
    fn own(&mut self, line: &str) {
        self.text.push_str(line);
        self.text.push('\n');
        self.rows = self.rows.saturating_add(self.rows_for(line.len()));
    }

    /// `field` from sallyd, checked: its escaped form when it fails the check.
    fn checked(&mut self, field: &str) -> String {
        let c = clean::line(field);
        self.dirty |= !c.clean;
        c.text
    }

    /// Request text, checked, in guttered rows. Every unit sallyd writes, and every run mark
    /// whatever text it is in, is at most `LONGEST_UNIT`, so at a usable width no row is wider
    /// than the width; each row is still counted as the screen rows it takes.
    fn guttered(&mut self, field: &str) {
        let text = self.checked(field);
        for row in self.rows_of(&text) {
            let rows = self.rows_for(GUTTER.len().saturating_add(row.len()));
            self.text.push_str(GUTTER);
            self.text.push_str(row);
            self.text.push('\n');
            self.rows = self.rows.saturating_add(rows);
        }
    }

    fn rows_of<'t>(&self, text: &'t str) -> Vec<&'t str> {
        let rows = self
            .width
            .map_or_else(|| vec![text], |w| sally_core::text::escaped_rows(text, w));
        if rows.is_empty() { vec![""] } else { rows }
    }
}

/// `p` laid out on a terminal of `size` (`None`: not a terminal, rows left whole), for
/// everything up to its first question (RT-AG-04): the CLI's lines at the left edge; the note,
/// the action and a cut prompt's full text each under a label, every row of them behind
/// [`GUTTER`]; the note before the action. When the prompt is taller than the screen,
/// [`again`]'s block follows, so the action's start is on the last screen.
#[must_use]
pub fn layout(p: &Prompt, size: Option<Size>) -> Layout {
    let (screen, refusal) = size.map_or(((usize::MAX, usize::MAX), None), screen);
    let mut l = Lines::on(size.map(|_| screen.0));
    l.own("");
    header(&mut l, p, "");
    if let Some(why) = refusal {
        l.own(&format!("  ({why}: this prompt can only be denied)"));
    }
    if let Some(n) = &p.note {
        l.own("  from the agent (untrusted, not the action):");
        l.guttered(n);
    }
    l.own("  action:");
    l.guttered(&p.action);
    if p.truncated {
        l.own("  (cut: the full action must be shown before it can be approved)");
    }
    footer(&mut l, p);
    let mut full_shown = false;
    let mut deny_only = refusal.is_some();
    if p.truncated {
        match &p.full {
            Some(full) if !p.full_unavailable => {
                l.own("  full action:");
                l.guttered(full);
                full_shown = true;
            }
            _ => {
                deny_only = true;
                l.own("  (the full action is too long to show)");
            }
        }
    }
    // The question takes one more row.
    if size.is_some() && l.rows.saturating_add(1) > screen.1 {
        let a = again_on(p, screen);
        l.text.push_str(&a.shown);
        deny_only |= a.deny_only;
    }
    Layout {
        full_shown: full_shown && !l.dirty,
        deny_only: deny_only || l.dirty,
        dirty: l.dirty,
        shown: l.text,
    }
}

/// The block printed directly above a question asked again, and above the first one when the
/// prompt is taller than the screen: the approval, the first rows of the cut action that fit,
/// how many rows of it are left out, the risk and the digest. Deny-only when fewer than
/// [`MIN_HEAD_ROWS`] rows of the action fit (or all of a shorter one), or the size cannot be used.
#[must_use]
pub(crate) fn again(p: &Prompt, size: Size) -> Layout {
    let (screen, refusal) = screen(size);
    let mut a = again_on(p, screen);
    if let Some(why) = refusal {
        a.shown
            .insert_str(0, &format!("  ({why}: this prompt can only be denied)\n"));
        a.deny_only = true;
    }
    a
}

fn again_on(p: &Prompt, (columns, rows): (usize, usize)) -> Layout {
    let cut = cut_line(p, columns);
    let mut fixed = Lines::on(Some(columns));
    header(&mut fixed, p, ": the start of its action again");
    tail(&mut fixed, p, cut.as_deref());
    let mut action = Lines::on(Some(columns));
    action.guttered(&p.action);
    // The question's row, and the line naming what is left out when not all of it fits.
    let room = rows.saturating_sub(fixed.rows).saturating_sub(1);
    let (head, left) = if action.rows <= room {
        (action.rows, 0)
    } else {
        let head = room.saturating_sub(1);
        (head, action.rows.saturating_sub(head))
    };
    let mut l = Lines::on(Some(columns));
    header(&mut l, p, ": the start of its action again");
    for row in action.text.lines().take(head) {
        l.text.push_str(row);
        l.text.push('\n');
    }
    if left > 0 {
        l.own(&format!("  ({left} more rows of the action, shown above)"));
    }
    tail(&mut l, p, cut.as_deref());
    Layout {
        shown: l.text,
        deny_only: head < action.rows.min(MIN_HEAD_ROWS) || l.dirty || action.dirty,
        full_shown: false,
        dirty: l.dirty || action.dirty,
    }
}

/// For a cut prompt, the again-block's line saying where its full text is, and how long it is:
/// the start shown again is of the cut action, and what the cut left out may matter most.
fn cut_line(p: &Prompt, columns: usize) -> Option<String> {
    if !p.truncated {
        return None;
    }
    Some(match &p.full {
        Some(full) if !p.full_unavailable => {
            let mut f = Lines::on(Some(columns));
            f.guttered(full);
            format!("  (cut: the full action, {} rows, is shown above)", f.rows)
        }
        _ => "  (cut: the full action is too long to show)".to_owned(),
    })
}

/// The again-block's lines after the action's rows: the cut line, if any, then [`footer`].
fn tail(l: &mut Lines, p: &Prompt, cut: Option<&str>) {
    if let Some(c) = cut {
        l.own(c);
    }
    footer(l, p);
}

/// The approval's own line: its id, session and call, then `tail`.
fn header(l: &mut Lines, p: &Prompt, tail: &str) {
    let (id, session) = (l.checked(&p.id), l.checked(&p.session));
    l.own(&format!(
        "approval {id} (session {session}, call {}){tail}",
        p.call
    ));
}

/// The risk line, when there is one, then the digest.
fn footer(l: &mut Lines, p: &Prompt) {
    if !p.risk_tags.is_empty() {
        let tags = l.checked(&p.risk_tags.join(", "));
        l.own(&format!("  risk: {tags}"));
    }
    let digest = l.checked(&p.digest);
    l.own(&format!("  digest: {digest}"));
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
    let first = layout(p, Some((tty.size)()));
    let mut deny_only = first.deny_only;
    let full_shown = first.full_shown;
    let _ = write!(tty.output, "{}", first.shown);
    let mut asked = false;
    loop {
        // A question asked again has the action's start directly above it (RT-AG-04).
        if asked {
            let a = again(p, (tty.size)());
            deny_only |= a.deny_only;
            let _ = write!(tty.output, "{}", a.shown);
        }
        asked = true;
        let question = if deny_only {
            "deny or deny-all? "
        } else {
            "approve, deny or deny-all? "
        };
        let _ = write!(tty.output, "{question}");
        let _ = tty.output.flush();
        let mut line = String::new();
        let read = (tty.flush)().and_then(|()| tty.input.read_line(&mut line));
        if !matches!(read, Ok(n) if n > 0) {
            // The terminal is gone, or what it holds may have been typed before the question:
            // the prompt on screen is denied.
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

#[cfg(test)]
#[path = "approve_layout_tests.rs"]
mod layout_tests;
