//! Audit entries of the broker sockets (SI-4; architect ruling Q9). Every entry is appended off
//! the runtime before the reply it covers; a failed append means no effect and no reply. Strings
//! the peer chose (a method, a path, a field name, an id) are escaped and cut before they are
//! written.

use std::sync::Arc;

use sally_core::audit::{Actor, NewEntry};
use sally_core::manifest::AuditLevel;

use crate::sandbox::AuditSink;

/// Bytes of a peer-chosen string kept in an entry.
pub const LOGGED_BYTES: usize = 64;

/// Where one session's socket entries go.
#[derive(Clone)]
pub struct Recorder {
    audit: Arc<dyn AuditSink>,
    session: String,
    level: AuditLevel,
}

impl std::fmt::Debug for Recorder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Recorder")
            .field("session", &self.session)
            .field("level", &self.level)
            .finish_non_exhaustive()
    }
}

impl Recorder {
    /// A recorder for `session` at `level`.
    #[must_use]
    pub fn new(audit: Arc<dyn AuditSink>, session: String, level: AuditLevel) -> Self {
        Self {
            audit,
            session,
            level,
        }
    }

    /// A new entry of this session (none for an empty session id: the control socket's).
    #[must_use]
    pub fn entry(&self, actor: Actor, event: &str, decision: Option<&str>) -> NewEntry {
        let e = NewEntry::new(actor, event);
        let e = if self.session.is_empty() {
            e
        } else {
            e.session(self.session.clone())
        };
        match decision {
            Some(d) => e.decision(d),
            None => e,
        }
    }

    /// Appends off the runtime; whether the entry was written.
    pub async fn append(&self, entry: NewEntry) -> bool {
        let (sink, level) = (Arc::clone(&self.audit), self.level);
        matches!(
            tokio::task::spawn_blocking(move || sink.append(entry, level)).await,
            Ok(Ok(()))
        )
    }
}

/// `raw` for an audit entry: printable ASCII other than `\` and `"` as is, every other byte as
/// `\xNN`; at most [`LOGGED_BYTES`] input bytes, then `…(+N)` with the number left out.
#[must_use]
pub fn escape(raw: &[u8]) -> String {
    let shown = raw.get(..LOGGED_BYTES).unwrap_or(raw);
    let mut out = String::with_capacity(shown.len());
    for &b in shown {
        if (0x20..0x7f).contains(&b) && b != b'\\' && b != b'"' {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("\\x{b:02x}"));
        }
    }
    if raw.len() > shown.len() {
        out.push_str(&format!("…(+{})", raw.len() - shown.len()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_names_the_session_and_level_only() {
        let (_, rec) = crate::rpc::testkit::recorder("sess-a");
        assert_eq!(
            format!("{rec:?}"),
            r#"Recorder { session: "sess-a", level: Full, .. }"#
        );
    }

    #[test]
    fn printable_text_is_kept() {
        assert_eq!(escape(b"tools/list"), "tools/list");
        assert_eq!(escape(b""), "");
    }

    #[test]
    fn controls_quotes_backslashes_and_high_bytes_are_escaped() {
        assert_eq!(
            escape(b"a\x1b[2J\r\n\"\\\x7f\xe2\x80\xae"),
            "a\\x1b[2J\\x0d\\x0a\\x22\\x5c\\x7f\\xe2\\x80\\xae"
        );
    }

    #[test]
    fn long_input_is_cut_with_a_count() {
        let exact = vec![b'a'; LOGGED_BYTES];
        assert_eq!(escape(&exact), "a".repeat(LOGGED_BYTES));
        let long = vec![b'a'; LOGGED_BYTES + 3];
        assert_eq!(escape(&long), format!("{}…(+3)", "a".repeat(LOGGED_BYTES)));
    }
}
