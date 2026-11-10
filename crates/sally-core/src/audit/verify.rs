//! `sally audit verify`: walk every log file in order and check each entry's canonical form,
//! hash, link to its predecessor and sequence number, then compare the end of the chain with
//! `audit.head`. Reports the first bad `seq`. Memory is bounded by the line limit.

use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

use super::entry::{GENESIS_HASH, MAX_LINE_BYTES, VerifyErrorKind, parse_line};
use super::layout::{HEAD_FILE, Head, list_log_files};

/// A failed verification: the first bad entry and why.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("audit verification failed at seq {seq} ({location}{}): {kind}", line_suffix(*.line))]
pub struct VerifyError {
    /// The sequence number the first bad entry should have had.
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
    /// The log is one entry ahead of the head (a crash between the two writes); harmless, the
    /// writer repairs it on open.
    Behind,
    /// No head and a single first entry (a crash during the very first write), or an empty log.
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
}

/// Verifies the audit directory `dir`.
///
/// # Errors
/// [`VerifyError`] naming the first bad `seq`; never includes log text.
pub fn verify(dir: &Path) -> Result<VerifyReport, VerifyError> {
    let files = list_log_files(dir).map_err(|_| {
        fail(
            1,
            VerifyErrorKind::Unreadable,
            dir.display().to_string(),
            None,
        )
    })?;
    let mut next_seq = 1u64;
    let mut prev_hash = GENESIS_HASH.to_owned();
    let mut last_prev = GENESIS_HASH.to_owned();
    let mut buf = Vec::new();
    for (_, path) in &files {
        let name = path
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
        let is_file = std::fs::symlink_metadata(path).is_ok_and(|m| m.is_file());
        let file = if is_file { File::open(path).ok() } else { None };
        let Some(file) = file else {
            return Err(fail(next_seq, VerifyErrorKind::Unreadable, name, None));
        };
        let mut reader = BufReader::new(file);
        let mut line_no = 0u64;
        loop {
            line_no += 1;
            let at = |kind| fail(next_seq, kind, name.clone(), Some(line_no));
            match read_line(&mut reader, &mut buf).map_err(|_| at(VerifyErrorKind::Unreadable))? {
                Line::Eof => break,
                Line::TooLong => return Err(at(VerifyErrorKind::LineTooLong)),
                Line::Unterminated => return Err(at(VerifyErrorKind::Malformed)),
                Line::Complete => {}
            }
            let entry = parse_line(&buf).map_err(at)?;
            if entry.seq != next_seq {
                return Err(at(VerifyErrorKind::SeqGap));
            }
            if entry.prev_hash != prev_hash {
                return Err(at(VerifyErrorKind::ChainBroken));
            }
            last_prev = entry.prev_hash;
            prev_hash = entry.hash;
            next_seq += 1;
        }
    }
    let last_seq = next_seq - 1;
    let head = check_head(dir, last_seq, &prev_hash, &last_prev)?;
    Ok(VerifyReport {
        entries: last_seq,
        files: files.len(),
        last_seq,
        last_hash: prev_hash,
        head,
    })
}

fn fail(seq: u64, kind: VerifyErrorKind, location: String, line: Option<u64>) -> VerifyError {
    VerifyError {
        seq,
        kind,
        location,
        line,
    }
}

fn check_head(
    dir: &Path,
    last_seq: u64,
    last_hash: &str,
    last_prev: &str,
) -> Result<HeadStatus, VerifyError> {
    let at = |seq, kind| fail(seq, kind, HEAD_FILE.to_owned(), None);
    let head = Head::read(dir).map_err(|k| at(last_seq + 1, k))?;
    let Some(head) = head else {
        return match last_seq {
            0 | 1 => Ok(HeadStatus::Absent),
            _ => Err(at(last_seq, VerifyErrorKind::HeadMissing)),
        };
    };
    if head.seq == last_seq && head.hash == last_hash {
        return Ok(HeadStatus::Current);
    }
    if head.seq > last_seq {
        return Err(at(last_seq + 1, VerifyErrorKind::TailMissing));
    }
    // The head may only lag by one entry, and only if it is that entry's predecessor.
    if head.seq + 1 == last_seq && head.hash == last_prev {
        return Ok(HeadStatus::Behind);
    }
    Err(at(last_seq, VerifyErrorKind::HeadMismatch))
}

enum Line {
    Complete,
    Unterminated,
    TooLong,
    Eof,
}

/// Reads one line into `buf` (newline stripped), never buffering more than the limit.
fn read_line(r: &mut impl BufRead, buf: &mut Vec<u8>) -> std::io::Result<Line> {
    buf.clear();
    let limit = u64::try_from(MAX_LINE_BYTES + 2).unwrap_or(u64::MAX);
    let n = r.by_ref().take(limit).read_until(b'\n', buf)?;
    if n == 0 {
        return Ok(Line::Eof);
    }
    if buf.last() == Some(&b'\n') {
        buf.pop();
        return Ok(if buf.len() > MAX_LINE_BYTES {
            Line::TooLong
        } else {
            Line::Complete
        });
    }
    Ok(if u64::try_from(n).unwrap_or(u64::MAX) >= limit {
        Line::TooLong
    } else {
        Line::Unterminated
    })
}
