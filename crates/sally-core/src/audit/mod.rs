//! The tamper-evident audit log (SI-4): hash-chained NDJSON, monthly files, redaction of secret
//! values, a head file that makes deleting the newest entries detectable, and a verifier.
//!
//! **Entry:** `{seq, ts, session, actor, event, decision, args, args_sha256, prev_hash, hash}`,
//! with `hash = sha256(prev_hash ‖ canonical_json(entry without hash))`. `args` is redacted and
//! at most [`MAX_ARGS_BYTES`]; larger ones are stored as `{"truncated":true,"bytes":N}`.
//! `args_sha256` hashes the **redacted** full args, never the raw ones: a hash of the raw value
//! would let someone brute-force a short secret.
//!
//! **Files:** `audit-YYYYMM.jsonl` (UTC month), `audit.head` (`{seq, hash}` of the newest entry,
//! written after every entry), `audit.lock` (single writer). The chain continues across files
//! through the first entry's `prev_hash`; files only ever rotate forward.
//!
//! **Tail deletion:** a prefix of a valid hash chain is itself a valid chain, so removing the
//! newest entries is caught only through `audit.head`. A crash can leave the log one entry ahead
//! of the head; that is accepted and repaired. A crash can also leave a torn final line; the
//! writer drops it on open (SI-4 writes before the effect, so the action never happened) and
//! records `audit.recovered`.
//!
//! **Verification beside a writer:** `verify` reads the head first and accepts a log that runs
//! past it; a log that ends before the head is tail deletion.
//!
//! **Residual:** whoever can rewrite the whole directory, head included, can rewrite the whole
//! chain (THREAT_MODEL, "whole audit chain can be rewritten by the user"). The directory is never
//! mounted into a sandbox.

mod entry;
mod layout;
mod redact;
mod tail;
mod verify;
mod writer;

pub use entry::{
    Actor, Entry, GENESIS_HASH, MAX_ARGS_BYTES, MAX_LINE_BYTES, VerifyErrorKind, parse_line,
};
pub use redact::{MIN_BASE64_PATTERN, Redactor, SessionForms, basic_credential, secret_forms};
/// Strict parse of the bytes of an `audit.head` file: `(seq, hash)`. Bounded and canonical-only;
/// the fuzz entry point for the head parser.
///
/// # Errors
/// [`VerifyErrorKind::HeadInvalid`].
pub fn parse_head(bytes: &[u8]) -> Result<(u64, String), VerifyErrorKind> {
    layout::Head::parse(bytes).map(|h| (h.seq, h.hash))
}

pub use tail::{MAX_TAIL, Tail, tail};
pub use verify::{HeadStatus, VerifyError, VerifyReport, verify};
pub use writer::{Appended, AuditError, AuditWriter, Clock, Detail, NewEntry, SystemClock};
