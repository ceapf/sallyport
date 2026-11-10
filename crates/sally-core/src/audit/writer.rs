//! The audit writer: single-writer, fsynced before it returns (SI-4), hash-chained, monthly
//! files, a head file for tail-deletion detection, redaction before anything touches disk.
//!
//! **Fail closed:** if [`AuditWriter::append`] returns an error the caller must not perform the
//! action the entry describes. An entry is durable before `append` returns, and an entry for an
//! action that then does not happen is harmless.

use std::fs::{DirBuilder, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use jiff::Timestamp;
use rustix::fs::{FlockOperation, Mode, OFlags};
use serde_json::{Value, json};

use super::entry::{
    Actor, Entry, GENESIS_HASH, MAX_ARGS_BYTES, MAX_LINE_BYTES, VerifyErrorKind, is_decision,
    is_event, is_session, parse_line, sha256_hex, truncation_marker,
};
use super::layout::{HEAD_FILE, HEAD_TMP, Head, LOCK_FILE, list_log_files, log_file_name};
use super::redact::Redactor;
use crate::fsutil::{FsIssue, check_private_dir};
use crate::manifest::AuditLevel;

/// Source of time. Tests inject a fixed one.
pub trait Clock: Send {
    /// The current instant.
    fn now(&self) -> Timestamp;
}

/// The system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        Timestamp::now()
    }
}

/// Whether an entry is a decision record (always kept) or per-request detail (kept only at
/// `audit.level: full`). Levels control detail, never coverage (SI-4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Detail {
    /// A decision, launch, approval, import: written at every level.
    #[default]
    Decision,
    /// Per-request lines, `fs_read`, inference metadata: dropped at `actions`.
    Full,
}

/// An entry to append; the writer adds `seq`, `ts`, hashes and redaction.
#[derive(Debug, Clone)]
pub struct NewEntry {
    actor: Actor,
    event: String,
    session: Option<String>,
    decision: Option<String>,
    args: Value,
    detail: Detail,
}

impl NewEntry {
    /// A decision-level entry with no session, decision or args.
    pub fn new(actor: Actor, event: impl Into<String>) -> Self {
        Self {
            actor,
            event: event.into(),
            session: None,
            decision: None,
            args: Value::Null,
            detail: Detail::Decision,
        }
    }

    /// Sets the session id.
    #[must_use]
    pub fn session(mut self, session: impl Into<String>) -> Self {
        self.session = Some(session.into());
        self
    }

    /// Sets the decision (`allow`, `deny`, …).
    #[must_use]
    pub fn decision(mut self, decision: impl Into<String>) -> Self {
        self.decision = Some(decision.into());
        self
    }

    /// Sets the arguments. They are redacted and size-limited before being written.
    #[must_use]
    pub fn args(mut self, args: Value) -> Self {
        self.args = args;
        self
    }

    /// Marks the entry as decision-level or detail.
    #[must_use]
    pub const fn detail(mut self, detail: Detail) -> Self {
        self.detail = detail;
        self
    }

    fn validate(&self) -> Result<(), AuditError> {
        let bad = |m| Err(AuditError::InvalidEntry(m));
        if !is_event(&self.event) {
            return bad("event must be lowercase noun.verb, at most 64 bytes");
        }
        if self.session.as_deref().is_some_and(|s| !is_session(s)) {
            return bad("session must be 1-64 characters of A-Z a-z 0-9 _ . : -");
        }
        if self.decision.as_deref().is_some_and(|d| !is_decision(d)) {
            return bad("decision must be lowercase, at most 32 bytes");
        }
        Ok(())
    }
}

/// What [`AuditWriter::append`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Appended {
    /// Written and fsynced.
    Written {
        /// The entry's sequence number.
        seq: u64,
    },
    /// A detail entry dropped by `audit.level: actions`.
    Filtered,
}

impl Appended {
    /// The sequence number, if an entry was written.
    #[must_use]
    pub const fn seq(self) -> Option<u64> {
        match self {
            Self::Written { seq } => Some(seq),
            Self::Filtered => None,
        }
    }
}

/// Why the audit log could not be opened or written. Messages never include entry contents.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuditError {
    /// Another writer holds the log.
    #[error("{path}: the audit log is in use by another writer")]
    Locked {
        /// The lock file.
        path: String,
    },
    /// The directory or a file is not private enough.
    #[error("{path}: {msg}")]
    Permissions {
        /// Host path.
        path: String,
        /// What is wrong.
        msg: String,
    },
    /// An I/O error.
    #[error("{path}: {source}")]
    Io {
        /// Host path.
        path: String,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// The entry is not acceptable. Nothing was written.
    #[error("invalid audit entry: {0}")]
    InvalidEntry(&'static str),
    /// The log is shorter than its head file records: the newest entries were removed.
    #[error(
        "the audit log is missing entries that audit.head records (truncated or deleted); \
         run `sally audit verify`, and to start a new log move the audit directory aside"
    )]
    TailMissing,
    /// The log has entries but no head file.
    #[error(
        "audit.head is missing from a log with several entries; move the audit directory aside to start a new log"
    )]
    HeadMissing,
    /// The log or head file is damaged.
    #[error("{path}: {msg}")]
    Corrupt {
        /// Host path.
        path: String,
        /// What is wrong.
        msg: &'static str,
    },
    /// An earlier write failed and could not be rolled back; the writer refuses further use.
    #[error("the audit writer failed earlier and cannot be trusted; restart")]
    Poisoned,
}

impl From<FsIssue> for AuditError {
    fn from(issue: FsIssue) -> Self {
        match issue {
            FsIssue::Permissions { path, msg } => Self::Permissions { path, msg },
            FsIssue::Io { path, source } => Self::Io { path, source },
        }
    }
}

fn io_at(path: &Path) -> impl Fn(std::io::Error) -> AuditError + '_ {
    move |source| AuditError::Io {
        path: path.display().to_string(),
        source,
    }
}

struct Current {
    file: File,
    month: String,
    len: u64,
}

/// The single writer of an audit directory.
pub struct AuditWriter {
    dir: PathBuf,
    clock: Box<dyn Clock>,
    redactor: Redactor,
    _lock: File,
    current: Option<Current>,
    tip_seq: u64,
    tip_hash: String,
    poisoned: bool,
}

impl std::fmt::Debug for AuditWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditWriter")
            .field("dir", &self.dir)
            .field("tip_seq", &self.tip_seq)
            .finish_non_exhaustive()
    }
}

struct Loaded {
    tip: Option<Entry>,
    current: Option<Current>,
    dropped: u64,
}

impl AuditWriter {
    /// Opens (creating if needed, mode 0700) the audit directory, takes the writer lock, finds
    /// the end of the chain, drops a torn final line left by a crash (recording
    /// `audit.recovered`), and reconciles the head file.
    ///
    /// # Errors
    /// [`AuditError`]: another writer, a directory that is not private, damage, or a missing
    /// tail ([`AuditError::TailMissing`]: the log is shorter than its head records).
    pub fn open(dir: &Path, clock: Box<dyn Clock>) -> Result<Self, AuditError> {
        if !dir.exists() {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .map_err(io_at(dir))?;
        }
        check_private_dir(dir)?;
        let lock = take_lock(dir)?;
        let files = list_log_files(dir).map_err(io_at(dir))?;
        let loaded = load_tip(&files)?;
        reconcile_head(dir, loaded.tip.as_ref())?;
        let (tip_seq, tip_hash) = loaded
            .tip
            .as_ref()
            .map_or((0, GENESIS_HASH.to_owned()), |e| (e.seq, e.hash.clone()));
        let mut writer = Self {
            dir: dir.to_owned(),
            clock,
            redactor: Redactor::default(),
            _lock: lock,
            current: loaded.current,
            tip_seq,
            tip_hash,
            poisoned: false,
        };
        if loaded.dropped > 0 {
            let note = NewEntry::new(Actor::Sallyd, "audit.recovered")
                .args(json!({ "dropped_bytes": loaded.dropped }));
            writer.commit(&note)?;
        }
        Ok(writer)
    }

    /// Replaces the set of secrets redacted from every following entry. `sallyd` passes the
    /// union of the secrets of all live sessions.
    pub fn set_redactor(&mut self, redactor: Redactor) {
        self.redactor = redactor;
    }

    /// `(seq, hash)` of the newest entry; `(0, GENESIS_HASH)` for an empty log.
    #[must_use]
    pub fn tip(&self) -> (u64, &str) {
        (self.tip_seq, &self.tip_hash)
    }

    /// Appends an entry unless `level` filters it. Durable (fsynced) when it returns `Written`.
    ///
    /// # Errors
    /// [`AuditError::InvalidEntry`] (nothing written) or an I/O error. **On any error the
    /// caller must not perform the action** (SI-4).
    pub fn append(&mut self, entry: NewEntry, level: AuditLevel) -> Result<Appended, AuditError> {
        entry.validate()?;
        if entry.detail == Detail::Full && level == AuditLevel::Actions {
            return Ok(Appended::Filtered);
        }
        self.commit(&entry).map(|seq| Appended::Written { seq })
    }

    fn commit(&mut self, new: &NewEntry) -> Result<u64, AuditError> {
        if self.poisoned {
            return Err(AuditError::Poisoned);
        }
        let redacted = self.redactor.redact_value(&new.args);
        let full = serde_json::to_string(&redacted).unwrap_or_default();
        let args_sha256 = sha256_hex(full.as_bytes());
        let args = if full.len() > MAX_ARGS_BYTES {
            truncation_marker(full.len())
        } else {
            redacted
        };
        let now = self.clock.now();
        let month = now.strftime("%Y%m").to_string();
        self.ensure_file(&month)?;
        let mut entry = Entry {
            seq: self.tip_seq.saturating_add(1),
            ts: now.strftime("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            session: new.session.clone(),
            actor: new.actor,
            event: new.event.clone(),
            decision: new.decision.clone(),
            args,
            args_sha256,
            prev_hash: self.tip_hash.clone(),
            hash: String::new(),
        };
        entry.hash = entry.compute_hash();
        let mut line = entry.to_line();
        if line.len() > MAX_LINE_BYTES {
            return Err(AuditError::InvalidEntry("entry is too large"));
        }
        line.push('\n');
        let path = self.dir.join(log_file_name(&month));
        let Some(cur) = self.current.as_mut() else {
            return Err(AuditError::Poisoned);
        };
        if let Err(e) = cur
            .file
            .write_all(line.as_bytes())
            .and_then(|()| cur.file.sync_data())
        {
            // Roll back a partial line so the next append does not land after garbage.
            if cur.file.set_len(cur.len).is_err() {
                self.poisoned = true;
            }
            return Err(io_at(&path)(e));
        }
        cur.len = cur
            .len
            .saturating_add(u64::try_from(line.len()).unwrap_or(u64::MAX));
        self.tip_seq = entry.seq;
        self.tip_hash = entry.hash.clone();
        write_head(
            &self.dir,
            &Head {
                seq: entry.seq,
                hash: entry.hash,
            },
        )?;
        Ok(self.tip_seq)
    }

    /// Makes sure the current file is the one for `month`, or a later one if the clock stepped
    /// back: files only ever rotate forward.
    fn ensure_file(&mut self, month: &str) -> Result<(), AuditError> {
        if self
            .current
            .as_ref()
            .is_some_and(|c| c.month.as_str() >= month)
        {
            return Ok(());
        }
        let path = self.dir.join(log_file_name(month));
        let file = OpenOptions::new()
            .append(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(io_at(&path))?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(io_at(&path))?;
        File::open(&self.dir)
            .and_then(|d| d.sync_all())
            .map_err(io_at(&self.dir))?;
        self.current = Some(Current {
            file,
            month: month.to_owned(),
            len: 0,
        });
        Ok(())
    }
}

fn take_lock(dir: &Path) -> Result<File, AuditError> {
    let path = dir.join(LOCK_FILE);
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&path)
        .map_err(io_at(&path))?;
    match rustix::fs::flock(&file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(file),
        Err(rustix::io::Errno::WOULDBLOCK) => Err(AuditError::Locked {
            path: path.display().to_string(),
        }),
        Err(e) => Err(io_at(&path)(e.into())),
    }
}

fn open_log_rw(path: &Path) -> Result<File, AuditError> {
    let corrupt = |msg| AuditError::Corrupt {
        path: path.display().to_string(),
        msg,
    };
    let fd = rustix::fs::open(
        path,
        OFlags::RDWR | OFlags::APPEND | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| io_at(path)(e.into()))?;
    let file = File::from(fd);
    let meta = file.metadata().map_err(io_at(path))?;
    if !meta.is_file() {
        return Err(corrupt("is not a regular file"));
    }
    if meta.uid() != rustix::process::geteuid().as_raw() || meta.permissions().mode() & 0o077 != 0 {
        return Err(AuditError::Permissions {
            path: path.display().to_string(),
            msg: "must be owned by the current user and not accessible to group or others (chmod 600)".to_owned(),
        });
    }
    Ok(file)
}

/// Finds the end of the chain: the last entry of the newest non-empty file, dropping a torn
/// final line of the newest file.
fn load_tip(files: &[(String, PathBuf)]) -> Result<Loaded, AuditError> {
    let mut loaded = Loaded {
        tip: None,
        current: None,
        dropped: 0,
    };
    for (i, (month, path)) in files.iter().enumerate().rev() {
        let newest = i + 1 == files.len();
        let file = open_log_rw(path)?;
        let (entry, len, dropped) = last_entry(&file, path, newest)?;
        if newest {
            loaded.dropped = dropped;
            loaded.current = Some(Current {
                file,
                month: month.clone(),
                len,
            });
        }
        if entry.is_some() {
            loaded.tip = entry;
            break;
        }
    }
    Ok(loaded)
}

/// The last complete entry of `file`, the file's good length, and how many torn bytes were cut.
fn last_entry(
    file: &File,
    path: &Path,
    may_repair: bool,
) -> Result<(Option<Entry>, u64, u64), AuditError> {
    let corrupt = |msg| AuditError::Corrupt {
        path: path.display().to_string(),
        msg,
    };
    let chunk_max = u64::try_from(2 * MAX_LINE_BYTES + 2).unwrap_or(u64::MAX);
    let mut dropped = 0u64;
    let mut len = file.metadata().map_err(io_at(path))?.len();
    loop {
        if len == 0 {
            return Ok((None, 0, dropped));
        }
        let n = len.min(chunk_max);
        let mut buf = vec![0u8; usize::try_from(n).map_err(|_| corrupt("is too large"))?];
        file.read_exact_at(&mut buf, len - n).map_err(io_at(path))?;
        if buf.last() == Some(&b'\n') {
            let body = buf.get(..buf.len() - 1).unwrap_or_default();
            let start = body.iter().rposition(|b| *b == b'\n').map_or(0, |p| p + 1);
            if start == 0 && n < len {
                return Err(corrupt("has a line longer than the limit"));
            }
            let line = body.get(start..).unwrap_or_default();
            let entry = parse_line(line)
                .map_err(|_| corrupt("its last entry is damaged; run `sally audit verify`"))?;
            return Ok((Some(entry), len, dropped));
        }
        // No trailing newline: a torn write (only the newest file may have one).
        if !may_repair {
            return Err(corrupt("does not end with a complete entry"));
        }
        let cut = match buf.iter().rposition(|b| *b == b'\n') {
            Some(p) => u64::try_from(p + 1).unwrap_or(0),
            None if n == len => 0,
            None => return Err(corrupt("has a torn line longer than the limit")),
        };
        let keep = len - n + cut;
        file.set_len(keep)
            .and_then(|()| file.sync_all())
            .map_err(io_at(path))?;
        dropped = dropped.saturating_add(len - keep);
        len = keep;
    }
}

fn reconcile_head(dir: &Path, tip: Option<&Entry>) -> Result<(), AuditError> {
    let head_path = dir.join(HEAD_FILE);
    let head = Head::read(dir).map_err(|_| AuditError::Corrupt {
        path: head_path.display().to_string(),
        msg: "is unreadable or malformed",
    })?;
    match (tip, head) {
        (None, None) => Ok(()),
        (None, Some(_)) => Err(AuditError::TailMissing),
        (Some(t), None) if t.seq == 1 && t.prev_hash == GENESIS_HASH => write_head(
            dir,
            &Head {
                seq: t.seq,
                hash: t.hash.clone(),
            },
        ),
        (Some(_), None) => Err(AuditError::HeadMissing),
        (Some(t), Some(h)) if h.seq == t.seq && h.hash == t.hash => Ok(()),
        (Some(t), Some(h)) if h.seq.saturating_add(1) == t.seq && h.hash == t.prev_hash => {
            // Crash between the entry write and the head update: the entry is valid.
            write_head(
                dir,
                &Head {
                    seq: t.seq,
                    hash: t.hash.clone(),
                },
            )
        }
        (Some(t), Some(h)) if h.seq > t.seq => Err(AuditError::TailMissing),
        (Some(_), Some(_)) => Err(AuditError::Corrupt {
            path: head_path.display().to_string(),
            msg: "does not match the log",
        }),
    }
}

fn write_head(dir: &Path, head: &Head) -> Result<(), AuditError> {
    let tmp = dir.join(HEAD_TMP);
    let target = dir.join(HEAD_FILE);
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(io_at(&tmp))?;
    f.write_all(head.line().as_bytes())
        .and_then(|()| f.sync_data())
        .map_err(io_at(&tmp))?;
    std::fs::rename(&tmp, &target).map_err(io_at(&target))
}

impl From<VerifyErrorKind> for AuditError {
    fn from(_: VerifyErrorKind) -> Self {
        Self::Corrupt {
            path: String::new(),
            msg: "audit data is damaged",
        }
    }
}
