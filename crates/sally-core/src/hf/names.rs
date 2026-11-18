//! The names a Hub request is built from, each validated before it reaches a URL: a repository
//! id, a revision, a commit, and a file path. Every one is percent-encoded by [`encode`], the one
//! encoder, so no character the caller or the Hub chose can change the request's shape.
#![deny(clippy::indexing_slicing)]

use std::ffi::OsStr;
use std::fmt;

use super::HfError;
use super::{MAX_PATH_BYTES, MAX_REPO_PART_BYTES, MAX_REVISION_BYTES, MAX_SEGMENT_BYTES};
use crate::library::SourceName;
use crate::model::detect;

/// The commit hash length in hex digits.
const COMMIT_HEX: usize = 40;
/// The default revision.
const MAIN: &str = "main";

/// A repository id, `namespace/name`, each part `[A-Za-z0-9][A-Za-z0-9._-]` and at most 96
/// bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoId(String);

impl RepoId {
    /// `id`, if it is a valid repository id.
    ///
    /// # Errors
    /// [`HfError::RepoInvalid`].
    pub fn parse(id: &str) -> Result<Self, HfError> {
        let mut parts = id.split('/');
        let ok = matches!(
            (parts.next(), parts.next(), parts.next()),
            (Some(ns), Some(name), None) if repo_part_ok(ns) && repo_part_ok(name)
        );
        if ok {
            Ok(Self(id.to_owned()))
        } else {
            Err(HfError::RepoInvalid)
        }
    }

    /// The id as given.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The id for a URL path: each part encoded, joined by `/`.
    #[must_use]
    pub fn encoded(&self) -> String {
        encode_path(&self.0)
    }
}

impl fmt::Display for RepoId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One part of a repository id.
pub(super) fn repo_part_ok(part: &str) -> bool {
    let b = part.as_bytes();
    match b.first() {
        Some(first) if first.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    b.len() <= MAX_REPO_PART_BYTES
        && b.iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

/// A revision: a branch, tag or commit name of `[A-Za-z0-9._/-]`, 1 to 128 bytes. In a URL it
/// is one encoded segment (`/` becomes `%2F`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revision(String);

impl Revision {
    /// `rev`, if it is a valid revision.
    ///
    /// # Errors
    /// [`HfError::RevisionInvalid`].
    pub fn parse(rev: &str) -> Result<Self, HfError> {
        if revision_ok(rev) {
            Ok(Self(rev.to_owned()))
        } else {
            Err(HfError::RevisionInvalid)
        }
    }

    /// The default branch, `main`.
    #[must_use]
    pub fn main() -> Self {
        Self(MAIN.to_owned())
    }

    /// The revision as given.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The revision as one encoded URL segment.
    #[must_use]
    pub fn encoded(&self) -> String {
        encode(&self.0)
    }
}

/// The revision rule.
pub(super) fn revision_ok(rev: &str) -> bool {
    (1..=MAX_REVISION_BYTES).contains(&rev.len())
        && rev
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'/' | b'-'))
}

/// A commit hash: 40 lowercase hex digits. Files are downloaded at the commit the list names,
/// never at a branch, so the bytes are the ones the list's hashes describe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit(String);

impl Commit {
    /// `sha`, if it is 40 lowercase hex digits.
    ///
    /// # Errors
    /// [`HfError::CommitInvalid`].
    pub fn parse(sha: &str) -> Result<Self, HfError> {
        if sha.len() == COMMIT_HEX && sha.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            Ok(Self(sha.to_owned()))
        } else {
            Err(HfError::CommitInvalid)
        }
    }

    /// The 40 hex digits.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A file's path in a repository: segments split on `/`, each 1 to 255 bytes of
/// `[A-Za-z0-9._+~-]` and never `.` or `..`, at most 1024 bytes in all; the last segment passes
/// the model allowlist and the library's name check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoPath(String);

impl RepoPath {
    /// `path`, if Sallyport downloads it.
    ///
    /// # Errors
    /// [`HfError::PathInvalid`].
    pub fn parse(path: &str) -> Result<Self, HfError> {
        if path_ok(path) {
            Ok(Self(path.to_owned()))
        } else {
            Err(HfError::PathInvalid)
        }
    }

    /// The path as listed.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The last segment: the name the model is stored under.
    #[must_use]
    pub fn file_name(&self) -> &str {
        self.0.rsplit('/').next().unwrap_or(&self.0)
    }

    /// The path for a URL: each segment encoded, joined by `/`.
    #[must_use]
    pub fn encoded(&self) -> String {
        encode_path(&self.0)
    }
}

/// The path rule.
pub(super) fn path_ok(path: &str) -> bool {
    if path.is_empty() || path.len() > MAX_PATH_BYTES {
        return false;
    }
    let segments_ok = path.split('/').all(|s| {
        (1..=MAX_SEGMENT_BYTES).contains(&s.len())
            && s != "."
            && s != ".."
            && s.bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'+' | b'~' | b'-'))
    });
    let last = path.rsplit('/').next().unwrap_or(path);
    segments_ok && detect::by_name(OsStr::new(last)).is_ok() && SourceName::checked(last).is_some()
}

/// Percent-encodes every byte but the unreserved ones (`A-Z a-z 0-9 - . _ ~`), `/` included.
#[must_use]
pub fn encode(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for b in raw.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push(hex_digit(b >> 4));
            out.push(hex_digit(b & 0x0f));
        }
    }
    out
}

/// Each `/`-separated segment encoded, joined by `/`.
fn encode_path(raw: &str) -> String {
    raw.split('/').map(encode).collect::<Vec<_>>().join("/")
}

/// One uppercase hex digit of a nibble.
fn hex_digit(n: u8) -> char {
    char::from(
        b"0123456789ABCDEF"
            .get(usize::from(n & 0x0f))
            .copied()
            .unwrap_or(b'0'),
    )
}

#[cfg(test)]
#[path = "names_tests.rs"]
mod tests;
