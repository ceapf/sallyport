//! The Hugging Face Hub client's decisions: everything that decides, and nothing that opens a
//! socket (the HTTPS transport is `sallyd::hf`).
//!
//! - [`names`]: the repository id, revision, commit and file path, validated before they reach
//!   a URL and percent-encoded by one encoder.
//! - [`list`]: the bounded parse of a repository's file list, giving each file's path, size and
//!   LFS SHA-256 at one commit.
//! - [`plan`]: the request for each hop. The first goes to `huggingface.co`; a redirect is
//!   followed only to https on the default port, to `huggingface.co` or `hf.co` or a subdomain
//!   of either; only a hop to `huggingface.co` itself carries the token; files are fetched at
//!   the listed commit, never at a branch.
//! - [`head`]: the decision on each response head (redirect, bounded wait, body, refusal), and
//!   the resume rules for a partial download.
//!
//! The bytes themselves go to a [`crate::library::Download`], and
//! [`crate::library::Library::promote`] checks the listed SHA-256 before anything else reads
//! them. The token's value never reaches this module.
//!
//! The bounds below are constants with their values pinned by tests.

// TODO(#214): the range fetch of a GGUF header, for the fit estimate, lands with the estimator.

pub mod error;
pub mod head;
pub mod list;
pub mod names;
pub mod plan;

pub use error::HfError;

/// Largest file-list body read (8 MiB); the reader takes one byte more to see it is over.
pub const MAX_LIST_BYTES: usize = 8_388_608;
/// Most files in one list.
pub const MAX_SIBLINGS: usize = 10_000;
/// Longest file path in bytes.
pub const MAX_PATH_BYTES: usize = 1024;
/// Longest path segment in bytes.
pub const MAX_SEGMENT_BYTES: usize = 255;
/// Longest repository id part (namespace or name) in bytes.
pub const MAX_REPO_PART_BYTES: usize = 96;
/// Longest revision in bytes.
pub const MAX_REVISION_BYTES: usize = 128;
/// Largest file pulled (1 TiB).
pub const MAX_FILE_SIZE: u64 = 1_099_511_627_776;
/// Most redirects followed per request.
pub const MAX_REDIRECTS: u32 = 3;
/// Most rate-limit retries per request.
pub const MAX_RETRIES: u32 = 3;
/// Longest wait for one retry, in seconds.
pub const MAX_RETRY_WAIT_SECS: u64 = 60;
/// The wait when Retry-After is absent or not delta-seconds, in seconds.
pub const DEFAULT_RETRY_WAIT_SECS: u64 = 5;
/// Longest Location followed, in bytes.
pub const MAX_LOCATION_BYTES: usize = 4096;
/// Longest escaped file name shown from a list, in bytes (before the cut marker).
pub const SHOWN_NAME_BYTES: usize = 128;

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
