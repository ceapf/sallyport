//! The daemon's operational log on stderr (architect Q43, #61): diagnostics only, never a
//! substitute for the audit log. An audit entry is written first; this line follows it.
//!
//! A line is `ts level component msg k="v" …`. Every value (and the message) is redacted with
//! the current redactor, then escaped with [`sally_core::text`] (so no line break, terminal
//! escape or quote from untrusted text survives), then capped at [`MAX_VALUE`] bytes; the whole
//! line is capped at [`MAX_LINE`] bytes by dropping whole fields. What goes in: startup facts,
//! a refusal to start, shutdown, session start and stop by id, accept errors, podman failures,
//! panics and failed audit appends. What never goes in: manifests, tool argv, bodies, model
//! output, environment.
//!
//! Logging never blocks: lines go through a bounded queue to a writer thread; a full queue drops
//! the line and the writer reports the count later. Write errors are ignored.

use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sally_core::audit::Redactor;
use sally_core::text::escape_capped;

/// Largest value (and message) after escaping.
pub const MAX_VALUE: usize = 4096;
/// Largest line, newline excluded.
pub const MAX_LINE: usize = 16 * 1024;
/// Lines waiting for the writer; past this a line is dropped.
pub const QUEUE: usize = 1024;
/// How often [`Oplog::flush`] looks at the queue.
const FLUSH_POLL: Duration = Duration::from_millis(5);

/// A line's severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// Normal operation.
    Info,
    /// Something failed and was handled.
    Warn,
    /// Something failed that ends a session or the daemon.
    Error,
}

impl Level {
    fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

/// The operational log. Cheap to clone; every clone feeds the same writer.
#[derive(Clone)]
pub struct Oplog {
    tx: SyncSender<String>,
    shared: Arc<Shared>,
}

struct Shared {
    redactor: RwLock<Arc<Redactor>>,
    dropped: AtomicU64,
    /// Lines queued and not yet written.
    pending: AtomicU64,
}

impl std::fmt::Debug for Oplog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Oplog").finish_non_exhaustive()
    }
}

impl Oplog {
    /// A log on this process's stderr.
    #[must_use]
    pub fn stderr() -> Self {
        Self::new(std::io::stderr())
    }

    /// A log written to `out` by a writer thread of its own.
    #[must_use]
    pub fn new(out: impl Write + Send + 'static) -> Self {
        let (tx, rx) = sync_channel(QUEUE);
        let shared = Arc::new(Shared {
            redactor: RwLock::new(Arc::new(Redactor::default())),
            dropped: AtomicU64::new(0),
            pending: AtomicU64::new(0),
        });
        let s = Arc::clone(&shared);
        // A thread that cannot start leaves a log that drops every line (counted, never blocks).
        let _ = std::thread::Builder::new()
            .name("oplog".into())
            .spawn(move || drain(&rx, out, &s));
        Self { tx, shared }
    }

    /// Replaces the redactor applied to every later line.
    pub fn set_redactor(&self, r: Arc<Redactor>) {
        *self
            .shared
            .redactor
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = r;
    }

    /// Logs one line; never blocks.
    pub fn log(&self, level: Level, component: &str, msg: &str, fields: &[(&str, &str)]) {
        let redactor = Arc::clone(
            &self
                .shared
                .redactor
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        let line = format_line(&now(), level, component, msg, fields, &redactor);
        self.shared.pending.fetch_add(1, Ordering::SeqCst);
        match self.tx.try_send(line) {
            Ok(()) => {}
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.shared.pending.fetch_sub(1, Ordering::SeqCst);
                self.shared.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Waits, at most `limit`, until every queued line is written: before the process exits.
    /// Whether the queue drained.
    pub fn flush(&self, limit: Duration) -> bool {
        let end = Instant::now() + limit;
        loop {
            if self.shared.pending.load(Ordering::SeqCst) == 0 {
                return true;
            }
            if Instant::now() >= end {
                return false;
            }
            std::thread::sleep(FLUSH_POLL);
        }
    }

    /// [`Level::Info`].
    pub fn info(&self, component: &str, msg: &str, fields: &[(&str, &str)]) {
        self.log(Level::Info, component, msg, fields);
    }

    /// [`Level::Warn`].
    pub fn warn(&self, component: &str, msg: &str, fields: &[(&str, &str)]) {
        self.log(Level::Warn, component, msg, fields);
    }

    /// [`Level::Error`].
    pub fn error(&self, component: &str, msg: &str, fields: &[(&str, &str)]) {
        self.log(Level::Error, component, msg, fields);
    }

    /// Lines dropped so far and not yet reported by the writer.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.shared.dropped.load(Ordering::Relaxed)
    }
}

fn drain(rx: &Receiver<String>, mut out: impl Write, s: &Shared) {
    while let Ok(line) = rx.recv() {
        let _ = out.write_all(line.as_bytes());
        let lost = s.dropped.swap(0, Ordering::Relaxed);
        if lost > 0 {
            let note = format!("{} warn oplog \"lines dropped\" count=\"{lost}\"\n", now());
            let _ = out.write_all(note.as_bytes());
        }
        let _ = out.flush();
        s.pending.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Seconds since the epoch with milliseconds.
fn now() -> String {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}.{:03}", d.as_secs(), d.subsec_millis())
}

/// One neutralized text: redacted, escaped, capped, with `"` escaped too (values are quoted).
fn clean(raw: &str, redactor: &Redactor) -> String {
    let redacted = redactor.redact_str(raw);
    escape_capped(redacted.as_bytes(), MAX_VALUE).replace('"', "\\x22")
}

/// The line for one event, newline included. `component` and the field keys are the caller's
/// constants; they are escaped anyway.
#[must_use]
pub fn format_line(
    ts: &str,
    level: Level,
    component: &str,
    msg: &str,
    fields: &[(&str, &str)],
    redactor: &Redactor,
) -> String {
    let head = format!(
        "{ts} {} {} \"{}\"",
        level.as_str(),
        clean(component, redactor).replace(' ', "_"),
        clean(msg, redactor)
    );
    let mut line = escape_capped(head.as_bytes(), MAX_LINE);
    for (i, (k, v)) in fields.iter().enumerate() {
        let key = clean(k, redactor).replace(' ', "_");
        let field = format!(" {key}=\"{}\"", clean(v, redactor));
        if line.len().saturating_add(field.len()) > MAX_LINE {
            let rest = fields.len().saturating_sub(i);
            line.push_str(&format!(" ...(+{rest} fields)"));
            break;
        }
        line.push_str(&field);
    }
    line.push('\n');
    line
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::Duration;

    fn none() -> Redactor {
        Redactor::default()
    }

    #[test]
    fn a_line_has_time_level_component_message_and_quoted_fields() {
        let l = format_line(
            "1.000",
            Level::Info,
            "session",
            "started",
            &[("id", "s-1"), ("mounts", "2")],
            &none(),
        );
        assert_eq!(
            l,
            "1.000 info session \"started\" id=\"s-1\" mounts=\"2\"\n"
        );
        let w = format_line("2.5", Level::Warn, "x", "m", &[], &none());
        assert_eq!(w, "2.5 warn x \"m\"\n");
        let e = format_line("3", Level::Error, "x", "m", &[], &none());
        assert!(e.starts_with("3 error x "));
    }

    #[test]
    fn untrusted_text_cannot_forge_a_line_a_field_or_a_terminal_escape() {
        let evil = "a\"\nb 0.0 error forged \"x\" k=\"\x1b[2J";
        let l = format_line("1", Level::Info, "c d", evil, &[("k", evil)], &none());
        assert_eq!(l.matches('\n').count(), 1);
        assert!(l.ends_with('\n'));
        assert!(!l.contains('\x1b'));
        // Only the delimiters the format itself writes are quotes.
        assert_eq!(l.matches('"').count(), 4, "{l}");
        assert!(l.contains("\\x22") && l.contains("\\x0a") && l.contains("\\x1b"));
        assert!(l.starts_with("1 info c_d "), "{l}");
        let body = l.trim_end_matches('\n');
        assert!(body.bytes().all(|b| (b' '..=b'~').contains(&b)), "{l}");
    }

    #[test]
    fn secrets_are_redacted_before_they_are_escaped() {
        // A secret with a backslash and a non-ASCII character: escaping first would hide it.
        let secret = "s3cr\\et-é-value";
        let r = Redactor::new([("TOKEN", secret)]);
        let l = format_line(
            "1",
            Level::Info,
            "c",
            secret,
            &[("v", &format!("x{secret}y"))],
            &r,
        );
        assert!(l.contains("[REDACTED:TOKEN]"), "{l}");
        assert!(!l.contains("s3cr"), "{l}");
        assert_eq!(l.matches("[REDACTED:TOKEN]").count(), 2);
    }

    #[test]
    fn values_and_the_line_are_capped() {
        let big = "a".repeat(MAX_VALUE * 2);
        let l = format_line("1", Level::Info, "c", "m", &[("v", &big)], &none());
        assert!(
            l.contains(&format!("...(+{} bytes)", MAX_VALUE)),
            "value cut"
        );
        let v = "b".repeat(MAX_VALUE);
        let fields: Vec<(&str, &str)> = (0..10).map(|_| ("k", v.as_str())).collect();
        let l = format_line("1", Level::Info, "c", "m", &fields, &none());
        assert!(l.len() <= MAX_LINE + 1, "{}", l.len());
        assert!(l.trim_end().ends_with("fields)"), "fields dropped whole");
        // Exactly at the cap nothing is dropped; one byte more drops the last field.
        let head = format_line("1", Level::Info, "c", "m", &[], &none());
        let wrap = " k=\"\"".len();
        let mut room = MAX_LINE - (head.len() - 1);
        let mut values = Vec::new();
        while room > 0 {
            let v = if room > 4000 + 2 * wrap {
                4000
            } else {
                room - wrap
            };
            values.push("c".repeat(v));
            room -= v + wrap;
        }
        let fields: Vec<(&str, &str)> = values.iter().map(|v| ("k", v.as_str())).collect();
        let l = format_line("1", Level::Info, "c", "m", &fields, &none());
        assert!(!l.contains("...(+"), "{}", l.len());
        assert_eq!(l.len(), MAX_LINE + 1);
        values.last_mut().unwrap().push('c');
        let fields: Vec<(&str, &str)> = values.iter().map(|v| ("k", v.as_str())).collect();
        let l = format_line("1", Level::Info, "c", "m", &fields, &none());
        assert!(l.trim_end().ends_with("...(+1 fields)"), "{}", l.len());
    }

    /// A writer that records lines, optionally blocking until released.
    #[derive(Clone, Default)]
    struct Sink {
        lines: Arc<Mutex<Vec<u8>>>,
        gate: Arc<Mutex<()>>,
        fail: bool,
    }

    impl Write for Sink {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            let _held = self.gate.lock().unwrap();
            if self.fail {
                return Err(std::io::ErrorKind::BrokenPipe.into());
            }
            self.lines.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn wait_for(sink: &Sink, needle: &str) -> String {
        for _ in 0..500 {
            let text = String::from_utf8(sink.lines.lock().unwrap().clone()).unwrap();
            if text.contains(needle) {
                return text;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("{needle:?} never written");
    }

    #[test]
    fn lines_reach_the_writer_and_the_redactor_can_be_swapped() {
        let sink = Sink::default();
        let log = Oplog::new(sink.clone());
        assert!(format!("{log:?}").starts_with("Oplog"));
        log.info("daemon", "ready", &[("v", "canary-123456789")]);
        let first = wait_for(&sink, "canary-123456789");
        // `<secs>.<millis>` since the epoch, and no drop note when nothing was dropped.
        let ts = first.split(' ').next().unwrap();
        let (secs, millis) = ts.split_once('.').unwrap();
        assert!(secs.parse::<u64>().unwrap() > 1_700_000_000, "{ts}");
        assert!(millis.len() == 3 && millis.parse::<u16>().is_ok(), "{ts}");
        assert!(!first.contains("lines dropped"), "{first}");
        log.set_redactor(Arc::new(Redactor::new([("C", "canary-123456789")])));
        log.warn("daemon", "again", &[("v", "canary-123456789")]);
        let text = wait_for(&sink, "[REDACTED:C]");
        assert_eq!(text.matches("canary-123456789").count(), 1, "{text}");
        log.error("daemon", "x", &[]);
        wait_for(&sink, " error daemon ");
    }

    #[test]
    fn a_stuck_writer_never_blocks_the_caller_and_drops_are_reported() {
        let sink = Sink::default();
        let held = sink.gate.lock().unwrap();
        let log = Oplog::new(sink.clone());
        let start = std::time::Instant::now();
        for i in 0..(QUEUE + 50) {
            log.info("t", "line", &[("i", &i.to_string())]);
        }
        assert!(start.elapsed() < Duration::from_secs(5));
        assert!(log.dropped() >= 49, "{}", log.dropped());
        drop(held);
        log.info("t", "after", &[]);
        let text = wait_for(&sink, "lines dropped");
        // The note counts what was lost, once.
        assert_eq!(text.matches("lines dropped").count(), 1, "{text}");
        assert!(!text.contains("count=\"0\""), "{text}");
    }

    /// `flush` returns once every queued line is written, and gives up at its limit on a stuck
    /// writer; a dropped line is not waited for.
    #[test]
    fn flush_waits_for_queued_lines_within_its_limit() {
        let sink = Sink::default();
        let held = sink.gate.lock().unwrap();
        let log = Oplog::new(sink.clone());
        for i in 0..(QUEUE + 10) {
            log.info("t", "line", &[("i", &i.to_string())]);
        }
        let start = Instant::now();
        assert!(!log.flush(Duration::from_millis(100)));
        assert!(start.elapsed() >= Duration::from_millis(100));
        drop(held);
        assert!(log.flush(Duration::from_secs(10)));
        let text = String::from_utf8(sink.lines.lock().unwrap().clone()).unwrap();
        // Every queued line is there: the writer holds one and the queue the rest.
        assert!(text.matches(" info t ").count() > QUEUE, "{}", text.len());
        log.info("t", "last", &[]);
        assert!(log.flush(Duration::from_secs(10)));
        let text = String::from_utf8(sink.lines.lock().unwrap().clone()).unwrap();
        assert!(text.contains("\"last\""), "{text}");
    }

    #[test]
    fn write_errors_are_ignored() {
        let sink = Sink {
            fail: true,
            ..Sink::default()
        };
        let log = Oplog::new(sink);
        for _ in 0..10 {
            log.info("t", "line", &[]);
        }
        assert_eq!(log.dropped(), 0);
    }
}
