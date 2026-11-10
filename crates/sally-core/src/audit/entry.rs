//! The entry format and its strict line parser (SI-4). Everything that reads a log line goes
//! through [`parse_line`]: bounds first, then a strict parse, then a byte-for-byte canonical
//! check, then the hash. Nothing here echoes any text from the line.
#![deny(clippy::indexing_slicing)]

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// `prev_hash` of the first entry ever written.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
/// Largest serialized `args` kept in an entry; larger ones become a marker plus a hash.
pub const MAX_ARGS_BYTES: usize = 4 * 1024;
/// Longest accepted log line, newline excluded. Readers refuse longer lines without buffering
/// them.
pub const MAX_LINE_BYTES: usize = 8 * 1024;

const MAX_EVENT_BYTES: usize = 64;
const MAX_SESSION_BYTES: usize = 64;
const MAX_DECISION_BYTES: usize = 32;
/// `YYYY-MM-DDTHH:MM:SS.mmmZ`.
const TS_LEN: usize = 24;

/// Who caused the entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Actor {
    /// A human, through the CLI or UI.
    User,
    /// The sandboxed harness, through a tool call.
    Harness,
    /// The broker itself.
    Sallyd,
}

/// One audit line. Field order is the canonical serialization order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    /// 1-based position in the whole log, across files.
    pub seq: u64,
    /// UTC time, `YYYY-MM-DDTHH:MM:SS.mmmZ`.
    pub ts: String,
    /// Session id, if the entry belongs to one.
    pub session: Option<String>,
    /// Who caused it.
    pub actor: Actor,
    /// `noun.verb`.
    pub event: String,
    /// `allow`, `deny`, … when the entry records a decision.
    pub decision: Option<String>,
    /// Redacted arguments, at most [`MAX_ARGS_BYTES`] serialized, or a truncation marker.
    pub args: Value,
    /// SHA-256 (hex) of the serialized **redacted** full arguments.
    pub args_sha256: String,
    /// `hash` of the previous entry, or [`GENESIS_HASH`].
    pub prev_hash: String,
    /// `sha256(prev_hash ‖ canonical_json(entry without hash))`, hex.
    pub hash: String,
}

/// The entry without its hash, in canonical field order.
#[derive(Serialize)]
struct Body<'a> {
    seq: u64,
    ts: &'a str,
    session: Option<&'a str>,
    actor: Actor,
    event: &'a str,
    decision: Option<&'a str>,
    args: &'a Value,
    args_sha256: &'a str,
    prev_hash: &'a str,
}

impl Entry {
    /// Canonical JSON of the entry without `hash`: compact, fixed field order, object keys
    /// sorted (serde_json maps are ordered).
    #[must_use]
    pub fn canonical_body(&self) -> String {
        let body = Body {
            seq: self.seq,
            ts: &self.ts,
            session: self.session.as_deref(),
            actor: self.actor,
            event: &self.event,
            decision: self.decision.as_deref(),
            args: &self.args,
            args_sha256: &self.args_sha256,
            prev_hash: &self.prev_hash,
        };
        // Serializing plain data into a String cannot fail.
        serde_json::to_string(&body).unwrap_or_default()
    }

    /// The hash this entry must carry.
    #[must_use]
    pub fn compute_hash(&self) -> String {
        let mut h = Sha256::new();
        h.update(self.prev_hash.as_bytes());
        h.update(self.canonical_body().as_bytes());
        hex(&h.finalize())
    }

    /// The exact line (without newline) written to the log.
    #[must_use]
    pub fn to_line(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

/// Why a log line or the log as a whole failed verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum VerifyErrorKind {
    /// Not a valid entry: bad JSON, unknown or missing field, wrong type, bad token or format.
    #[error("not a valid audit entry")]
    Malformed,
    /// Valid JSON but not the exact bytes the writer would have produced.
    #[error("entry is not in canonical form")]
    NonCanonical,
    /// `hash` does not match the entry's contents.
    #[error("hash does not match the entry")]
    HashMismatch,
    /// `args_sha256` does not match the stored `args`.
    #[error("args_sha256 does not match the stored args")]
    ArgsHashMismatch,
    /// `prev_hash` is not the previous entry's hash.
    #[error("prev_hash does not link to the previous entry")]
    ChainBroken,
    /// `seq` is not the previous one plus one.
    #[error("sequence number is out of order or has a gap")]
    SeqGap,
    /// A line is longer than the limit.
    #[error("line is longer than the limit")]
    LineTooLong,
    /// The newest entries are gone: `audit.head` records more than the log holds.
    #[error("log ends before the head records (entries were removed)")]
    TailMissing,
    /// There is more than one entry but no `audit.head`.
    #[error("audit.head is missing")]
    HeadMissing,
    /// `audit.head` is unreadable or malformed.
    #[error("audit.head is invalid")]
    HeadInvalid,
    /// `audit.head` and the log disagree.
    #[error("audit.head does not match the log")]
    HeadMismatch,
    /// A log file is not a regular file, or could not be read.
    #[error("log file cannot be read")]
    Unreadable,
}

/// Parses and checks one log line (no trailing newline).
///
/// Checks, in order: length, strict JSON shape (unknown fields refused), token and format
/// rules, `args_sha256` (when the args were not truncated), byte-for-byte canonical form, and
/// `hash`. It does **not** check the link to neighbours (`seq`, `prev_hash`); the verifier does.
///
/// # Errors
/// A [`VerifyErrorKind`]; never carries any of the line's text.
pub fn parse_line(line: &[u8]) -> Result<Entry, VerifyErrorKind> {
    if line.len() > MAX_LINE_BYTES {
        return Err(VerifyErrorKind::LineTooLong);
    }
    let entry: Entry = serde_json::from_slice(line).map_err(|_| VerifyErrorKind::Malformed)?;
    check_fields(&entry)?;
    if entry.to_line().as_bytes() != line {
        return Err(VerifyErrorKind::NonCanonical);
    }
    if !is_truncation_marker(&entry.args) {
        let full = serde_json::to_string(&entry.args).unwrap_or_default();
        if sha256_hex(full.as_bytes()) != entry.args_sha256 {
            return Err(VerifyErrorKind::ArgsHashMismatch);
        }
    }
    if entry.compute_hash() != entry.hash {
        return Err(VerifyErrorKind::HashMismatch);
    }
    Ok(entry)
}

fn check_fields(e: &Entry) -> Result<(), VerifyErrorKind> {
    let ok = e.seq >= 1
        && is_timestamp(&e.ts)
        && e.session.as_deref().is_none_or(is_session)
        && is_event(&e.event)
        && e.decision.as_deref().is_none_or(is_decision)
        && is_hex64(&e.args_sha256)
        && is_hex64(&e.prev_hash)
        && is_hex64(&e.hash);
    if ok {
        Ok(())
    } else {
        Err(VerifyErrorKind::Malformed)
    }
}

/// `{"truncated":true,"bytes":N}`: what the writer stores for oversized args.
fn is_truncation_marker(args: &Value) -> bool {
    args.as_object().is_some_and(|o| {
        o.len() == 2
            && o.get("truncated") == Some(&Value::Bool(true))
            && o.get("bytes").is_some_and(Value::is_u64)
    })
}

pub(crate) fn truncation_marker(bytes: usize) -> Value {
    serde_json::json!({ "truncated": true, "bytes": bytes })
}

pub(crate) fn is_hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_timestamp(s: &str) -> bool {
    s.len() == TS_LEN
        && s.bytes().enumerate().all(|(i, b)| match i {
            4 | 7 => b == b'-',
            10 => b == b'T',
            13 | 16 => b == b':',
            19 => b == b'.',
            23 => b == b'Z',
            _ => b.is_ascii_digit(),
        })
}

/// `noun.verb` style: lowercase start, then `[a-z0-9_.:-]`, at most 64 bytes.
pub(crate) fn is_event(s: &str) -> bool {
    token(
        s,
        MAX_EVENT_BYTES,
        |b| b.is_ascii_lowercase(),
        |b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_.:-".contains(&b),
    )
}

/// Alphanumeric start, then `[A-Za-z0-9_.:-]`, at most 64 bytes.
pub(crate) fn is_session(s: &str) -> bool {
    token(
        s,
        MAX_SESSION_BYTES,
        |b| b.is_ascii_alphanumeric(),
        |b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b),
    )
}

/// Lowercase start, then `[a-z0-9_.-]`, at most 32 bytes.
pub(crate) fn is_decision(s: &str) -> bool {
    token(
        s,
        MAX_DECISION_BYTES,
        |b| b.is_ascii_lowercase(),
        |b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_.-".contains(&b),
    )
}

fn token(s: &str, max: usize, first: fn(u8) -> bool, rest: impl Fn(u8) -> bool) -> bool {
    let mut b = s.bytes();
    s.len() <= max && b.next().is_some_and(first) && b.all(rest)
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

pub(crate) fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}
