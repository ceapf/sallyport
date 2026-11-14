//! `sally audit verify`: walk every log file in order and check each entry's canonical form,
//! hash, link to its predecessor and sequence number, then compare the chain with `audit.head`.
//! Reports the first bad `seq`. Memory is bounded by the line limit.
//!
//! Safe to run beside a live writer: the head is read **first**, and the log may run past it
//! (the writer appends an entry and then updates the head), while a log that ends before the
//! head is tail deletion. An unterminated final line is treated as an append in flight (or a
//! crash-torn tail), not as damage; the head comparison still catches a removed entry.

use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

use super::entry::{GENESIS_HASH, MAX_LINE_BYTES, VerifyErrorKind, parse_line};
use super::layout::{HEAD_FILE, Head, list_log_files};

/// A failed verification: the first bad entry and why.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("audit verification failed at seq {seq} ({location}{}): {kind}", line_suffix(*.line))]
pub struct VerifyError {
    /// The sequence number the first bad entry should have had (0 when the problem is the head
    /// file alone and no entry is involved).
    pub seq: u64,
    /// What is wrong.
    pub kind: VerifyErrorKind,
    /// File name (or `audit.head`).
    pub location: String,
    /// 1-based line within the file, when the problem is on a line.
    pub line: Option<u64>,
}

fn line_suffix(line: Option<u64>) -> String {
    line.map_or_else(String::new, |n| format!(" line {n}"))
}

/// How the head file relates to the end of the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadStatus {
    /// `audit.head` names the newest entry.
    Current,
    /// The log runs past the head: a writer is mid-append, or crashed between the entry and the
    /// head update. Harmless; the writer repairs a one-entry lag on open.
    LogAhead,
    /// No head and at most one entry (nothing written yet, or a crash during the very first
    /// write).
    Absent,
}

/// A successful verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    /// Entries checked.
    pub entries: u64,
    /// Log files read.
    pub files: usize,
    /// `seq` of the newest entry (0 if none).
    pub last_seq: u64,
    /// Hash of the newest entry ([`GENESIS_HASH`] if none).
    pub last_hash: String,
    /// State of the head file.
    pub head: HeadStatus,
    /// The newest file ends with an unterminated line (an append in flight or a crash-torn
    /// tail); it was ignored.
    pub torn_tail: bool,
}

fn fail(seq: u64, kind: VerifyErrorKind, location: &str, line: Option<u64>) -> VerifyError {
    VerifyError {
        seq,
        kind,
        location: location.to_owned(),
        line,
    }
}

/// Where the walk currently is.
struct Chain {
    next_seq: u64,
    prev_hash: String,
    torn: bool,
}

/// Verifies the audit directory `dir`.
///
/// # Errors
/// [`VerifyError`] naming the first bad `seq`; never includes log text.
pub fn verify(dir: &Path) -> Result<VerifyReport, VerifyError> {
    let head = Head::read(dir).map_err(|k| fail(0, k, HEAD_FILE, None))?;
    let files = list_log_files(dir).map_err(|_| {
        fail(
            1,
            VerifyErrorKind::Unreadable,
            &dir.display().to_string(),
            None,
        )
    })?;
    let mut chain = Chain {
        next_seq: 1,
        prev_hash: GENESIS_HASH.to_owned(),
        torn: false,
    };
    for (i, (_, path)) in files.iter().enumerate() {
        let name = path
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
        let last_file = i + 1 == files.len();
        walk_file(path, &name, last_file, head.as_ref(), &mut chain)?;
    }
    let last_seq = chain.next_seq.saturating_sub(1);
    let status = check_head(head.as_ref(), last_seq)?;
    Ok(VerifyReport {
        entries: last_seq,
        files: files.len(),
        last_seq,
        last_hash: chain.prev_hash,
        head: status,
        torn_tail: chain.torn,
    })
}

fn walk_file(
    path: &Path,
    name: &str,
    last_file: bool,
    head: Option<&Head>,
    chain: &mut Chain,
) -> Result<(), VerifyError> {
    let is_file = std::fs::symlink_metadata(path).is_ok_and(|m| m.is_file());
    let Some(file) = is_file.then(|| File::open(path).ok()).flatten() else {
        return Err(fail(
            chain.next_seq,
            VerifyErrorKind::Unreadable,
            name,
            None,
        ));
    };
    let mut reader = BufReader::new(file);
    let mut buf = Vec::new();
    let mut line_no = 0u64;
    loop {
        line_no += 1;
        let at = |kind| fail(chain.next_seq, kind, name, Some(line_no));
        match read_line(&mut reader, &mut buf).map_err(|_| at(VerifyErrorKind::Unreadable))? {
            Line::Eof => return Ok(()),
            Line::TooLong { .. } => return Err(at(VerifyErrorKind::LineTooLong)),
            Line::Unterminated if last_file => {
                chain.torn = true;
                return Ok(());
            }
            Line::Unterminated => return Err(at(VerifyErrorKind::Malformed)),
            Line::Complete => {}
        }
        let entry = parse_line(&buf).map_err(at)?;
        if entry.seq != chain.next_seq {
            return Err(at(VerifyErrorKind::SeqGap));
        }
        if entry.prev_hash != chain.prev_hash {
            return Err(at(VerifyErrorKind::ChainBroken));
        }
        if head.is_some_and(|h| h.seq == entry.seq && h.hash != entry.hash) {
            return Err(fail(
                entry.seq,
                VerifyErrorKind::HeadMismatch,
                HEAD_FILE,
                None,
            ));
        }
        chain.prev_hash = entry.hash;
        chain.next_seq = chain.next_seq.saturating_add(1);
    }
}

/// Compares the head with the end of the verified chain. A head naming an entry that exists
/// with the same hash was already confirmed during the walk.
fn check_head(head: Option<&Head>, last_seq: u64) -> Result<HeadStatus, VerifyError> {
    let Some(head) = head else {
        return if last_seq <= 1 {
            Ok(HeadStatus::Absent)
        } else {
            Err(fail(
                last_seq,
                VerifyErrorKind::HeadMissing,
                HEAD_FILE,
                None,
            ))
        };
    };
    match head.seq.cmp(&last_seq) {
        std::cmp::Ordering::Greater => Err(fail(
            last_seq.saturating_add(1),
            VerifyErrorKind::TailMissing,
            HEAD_FILE,
            None,
        )),
        std::cmp::Ordering::Equal => Ok(HeadStatus::Current),
        std::cmp::Ordering::Less => Ok(HeadStatus::LogAhead),
    }
}

pub(super) enum Line {
    Complete,
    Unterminated,
    /// Over `MAX_LINE_BYTES`; `ended` when its newline was read too (else the rest is unread).
    TooLong {
        ended: bool,
    },
    Eof,
}

/// Reads one line into `buf` (newline stripped), never buffering more than the limit.
pub(super) fn read_line(r: &mut impl BufRead, buf: &mut Vec<u8>) -> std::io::Result<Line> {
    buf.clear();
    let limit = u64::try_from(MAX_LINE_BYTES + 2).unwrap_or(u64::MAX);
    let n = r.by_ref().take(limit).read_until(b'\n', buf)?;
    if n == 0 {
        return Ok(Line::Eof);
    }
    if buf.last() == Some(&b'\n') {
        buf.pop();
        return Ok(if buf.len() > MAX_LINE_BYTES {
            Line::TooLong { ended: true }
        } else {
            Line::Complete
        });
    }
    Ok(if u64::try_from(n).unwrap_or(u64::MAX) >= limit {
        Line::TooLong { ended: false }
    } else {
        Line::Unterminated
    })
}
