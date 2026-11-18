//! The repository's file list: the answer to `GET /api/models/{repo}/revision/{rev}?blobs=true`.
//!
//! Bounds first: a body over [`MAX_LIST_BYTES`] is refused before it is parsed, and the
//! `siblings` array is counted as it is read and refused at the first entry past
//! [`MAX_SIBLINGS`], so the vector never grows past the bound. A duplicate key at any level is
//! refused (serde's duplicate-field error); unknown keys are ignored. A refusal names the JSON
//! position only, never a value.
//!
//! Each sibling is checked on its own. One Sallyport cannot pull (a path it does not download,
//! no LFS SHA-256, a missing or out-of-bound size, two sizes that disagree) carries its reason
//! and does not fail the list.
#![deny(clippy::indexing_slicing)]

use std::fmt;

use serde::Deserialize;
use serde::de::{self, Deserializer, SeqAccess, Visitor};

use super::names::{Commit, RepoPath};
use super::{HfError, MAX_FILE_SIZE, MAX_LIST_BYTES, MAX_SIBLINGS, SHOWN_NAME_BYTES};
use crate::model::hash::Digest;
use crate::text;

/// The parsed list: the commit it describes and every file in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileList {
    commit: Commit,
    files: Vec<Listed>,
}

impl FileList {
    /// The commit the list describes; files are downloaded at this commit.
    #[must_use]
    pub const fn commit(&self) -> &Commit {
        &self.commit
    }

    /// Every file, in the Hub's order.
    #[must_use]
    pub fn files(&self) -> &[Listed] {
        &self.files
    }

    /// The listed file at `path`, if Sallyport can pull it. The first entry with that path
    /// decides.
    ///
    /// # Errors
    /// [`HfError::FileNotListed`], or the reason the listed file cannot be pulled.
    pub fn wanted(&self, path: &RepoPath) -> Result<&Wanted, HfError> {
        let listed = self
            .files
            .iter()
            .find(|f| f.raw == path.as_str())
            .ok_or_else(|| HfError::FileNotListed(path.as_str().to_owned()))?;
        listed.pull.as_ref().map_err(Clone::clone)
    }
}

/// One file of the list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    raw: String,
    shown: String,
    size: Option<u64>,
    pull: Result<Wanted, HfError>,
}

impl Listed {
    /// The file's path as the Hub lists it, escaped to printable ASCII and capped.
    #[must_use]
    pub fn shown(&self) -> &str {
        &self.shown
    }

    /// The size the Hub lists, if any.
    #[must_use]
    pub const fn size(&self) -> Option<u64> {
        self.size
    }

    /// What a pull of it would fetch, or why it cannot be pulled.
    ///
    /// # Errors
    /// The reason it cannot be pulled.
    pub const fn pull(&self) -> Result<&Wanted, &HfError> {
        self.pull.as_ref()
    }
}

/// A file Sallyport can pull: a valid path, its size and its publisher's SHA-256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wanted {
    path: RepoPath,
    size: u64,
    sha256: Digest,
}

impl Wanted {
    /// The path in the repository.
    #[must_use]
    pub const fn path(&self) -> &RepoPath {
        &self.path
    }

    /// The size the Hub lists, 1 byte to [`MAX_FILE_SIZE`].
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// The SHA-256 the Hub lists (`lfs.sha256`).
    #[must_use]
    pub const fn sha256(&self) -> &Digest {
        &self.sha256
    }
}

#[derive(Deserialize)]
struct RawList {
    sha: String,
    #[serde(deserialize_with = "bounded_siblings")]
    siblings: Vec<RawSibling>,
}

#[derive(Deserialize)]
struct RawSibling {
    rfilename: String,
    #[serde(default)]
    size: Option<u64>,
    #[serde(default)]
    lfs: Option<RawLfs>,
}

#[derive(Deserialize)]
struct RawLfs {
    #[serde(default)]
    sha256: Option<String>,
    #[serde(default)]
    size: Option<u64>,
}

/// Parses the list.
///
/// # Errors
/// [`HfError::ListTooLarge`], [`HfError::ListMalformed`], [`HfError::CommitInvalid`].
pub fn parse_list(body: &[u8]) -> Result<FileList, HfError> {
    if body.len() > MAX_LIST_BYTES {
        return Err(HfError::ListTooLarge);
    }
    let raw: RawList = serde_json::from_slice(body).map_err(|e| HfError::ListMalformed {
        line: e.line(),
        column: e.column(),
    })?;
    let commit = Commit::parse(&raw.sha)?;
    let files = raw.siblings.into_iter().map(listed).collect();
    Ok(FileList { commit, files })
}

/// One sibling, checked.
fn listed(s: RawSibling) -> Listed {
    let lfs_size = s.lfs.as_ref().and_then(|l| l.size);
    let size = lfs_size.or(s.size);
    let pull = pullable(&s, lfs_size);
    Listed {
        shown: text::escape_capped(s.rfilename.as_bytes(), SHOWN_NAME_BYTES),
        raw: s.rfilename,
        size,
        pull,
    }
}

/// Whether a sibling can be pulled, in this order: its path, its hash, its size.
fn pullable(s: &RawSibling, lfs_size: Option<u64>) -> Result<Wanted, HfError> {
    let path = RepoPath::parse(&s.rfilename)?;
    let sha256 = s
        .lfs
        .as_ref()
        .and_then(|l| l.sha256.as_deref())
        .and_then(|h| Digest::parse(h).ok())
        .ok_or(HfError::NoPublisherHash)?;
    let size = listed_size(s.size, lfs_size)?;
    Ok(Wanted { path, size, sha256 })
}

/// The size, when the two the Hub may list agree and it is 1 byte to [`MAX_FILE_SIZE`].
pub(super) fn listed_size(size: Option<u64>, lfs_size: Option<u64>) -> Result<u64, HfError> {
    let size = match (size, lfs_size) {
        (Some(a), Some(b)) if a != b => return Err(HfError::SizeDisagrees),
        (_, Some(s)) | (Some(s), None) => s,
        (None, None) => return Err(HfError::SizeInvalid),
    };
    if (1..=MAX_FILE_SIZE).contains(&size) {
        Ok(size)
    } else {
        Err(HfError::SizeInvalid)
    }
}

/// `siblings`, refused past [`MAX_SIBLINGS`] entries before the next one is read.
fn bounded_siblings<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<RawSibling>, D::Error> {
    struct Bounded;
    impl<'de> Visitor<'de> for Bounded {
        type Value = Vec<RawSibling>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("an array of files")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut out = Vec::new();
            while let Some(s) = seq.next_element()? {
                if out.len() == MAX_SIBLINGS {
                    return Err(de::Error::custom("too many files"));
                }
                out.push(s);
            }
            Ok(out)
        }
    }
    d.deserialize_seq(Bounded)
}

#[cfg(test)]
#[path = "list_tests.rs"]
mod tests;
