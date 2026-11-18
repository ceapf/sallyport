//! Why a Hub request was refused. Each variant has a stable [`HfError::code`]; every code starts
//! `hf_`, so none collides with a detect, GGUF or library code.
//!
//! No variant holds text the Hub chose: a status is a number, a size is a number, a header or a
//! JSON value is never echoed (serde's messages can quote a value, so only its position is
//! kept). The one name shown is the file path the caller asked for, already validated: at most
//! 1024 bytes of `[A-Za-z0-9._+~-]` and `/`.

/// Why a Hub request was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HfError {
    /// The repository id is not `namespace/name` with each part `[A-Za-z0-9][A-Za-z0-9._-]`,
    /// at most 96 bytes.
    #[error("a repository id is namespace/name, each starting with a letter or digit")]
    RepoInvalid,
    /// The revision is empty, too long, or holds a character outside `[A-Za-z0-9._/-]`.
    #[error("a revision is a branch, tag or commit name of letters, digits, '.', '_', '/', '-'")]
    RevisionInvalid,
    /// The file path is not one Sallyport downloads (characters, segment or total length, or
    /// a final name the model allowlist refuses).
    #[error("the file path is not one Sallyport downloads")]
    PathInvalid,
    /// The file list is larger than its bound.
    #[error("the Hub's file list is too large")]
    ListTooLarge,
    /// The file list is not the JSON expected (a key it reads given twice, a wrong type, too
    /// many files).
    #[error("the Hub's file list is malformed (line {line}, column {column})")]
    ListMalformed {
        /// Line of the first error.
        line: usize,
        /// Column of the first error.
        column: usize,
    },
    /// The file list's commit is not 40 lowercase hex digits.
    #[error("the Hub's file list names no valid commit")]
    CommitInvalid,
    /// The file asked for is not in the list.
    #[error("{0} is not in the repository's file list")]
    FileNotListed(String),
    /// The listed file has no LFS SHA-256, so its bytes cannot be checked.
    #[error("the Hub lists no SHA-256 for this file, so it cannot be verified")]
    NoPublisherHash,
    /// The listed size is missing, zero, or over the bound.
    #[error("the Hub lists no usable size for this file")]
    SizeInvalid,
    /// The listed size and the LFS size disagree.
    #[error("the Hub lists two different sizes for this file")]
    SizeDisagrees,
    /// A redirect target is not https on the default port to a Hub host, or its Location is
    /// malformed.
    #[error("the Hub redirected to a location Sallyport does not follow")]
    RedirectRefused,
    /// More redirects than the bound.
    #[error("the Hub redirected too many times")]
    TooManyRedirects,
    /// Still rate-limited after the bounded retries.
    #[error("the Hub is rate-limiting requests; try again later")]
    RateLimited,
    /// 404.
    #[error("the Hub has no such repository, revision or file")]
    NotFound,
    /// 401 or 403: the repository is gated or private.
    #[error("the Hub refused access (a gated or private repository needs a token)")]
    Unauthorized,
    /// Any other status.
    #[error("the Hub answered status {0}")]
    UpstreamStatus(u16),
    /// The response length is missing or is not the listed size (or the rest of it).
    #[error("the Hub's response length does not match the listed size")]
    LengthMismatch,
    /// A 206 whose Content-Range is not exactly the range asked for, or a 206 not asked for.
    #[error("the Hub answered a range other than the one asked for")]
    RangeMismatch,
    /// 416: the partial is not a prefix of the file.
    #[error("the Hub refused the resume range")]
    RangeNotSatisfiable,
    /// The file body came with a Content-Encoding.
    #[error("the Hub sent the file encoded; Sallyport takes it only as stored")]
    ContentEncoding,
}

impl HfError {
    /// The stable reason code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::RepoInvalid => "hf_repo_invalid",
            Self::RevisionInvalid => "hf_revision_invalid",
            Self::PathInvalid => "hf_path_invalid",
            Self::ListTooLarge => "hf_list_too_large",
            Self::ListMalformed { .. } => "hf_list_malformed",
            Self::CommitInvalid => "hf_commit_invalid",
            Self::FileNotListed(_) => "hf_file_not_listed",
            Self::NoPublisherHash => "hf_no_publisher_hash",
            Self::SizeInvalid => "hf_size_invalid",
            Self::SizeDisagrees => "hf_size_disagrees",
            Self::RedirectRefused => "hf_redirect_refused",
            Self::TooManyRedirects => "hf_too_many_redirects",
            Self::RateLimited => "hf_rate_limited",
            Self::NotFound => "hf_not_found",
            Self::Unauthorized => "hf_unauthorized",
            Self::UpstreamStatus(_) => "hf_upstream_status",
            Self::LengthMismatch => "hf_length_mismatch",
            Self::RangeMismatch => "hf_range_mismatch",
            Self::RangeNotSatisfiable => "hf_range_refused",
            Self::ContentEncoding => "hf_content_encoding",
        }
    }

    /// Whether this refusal deletes the partial download: the bytes on disk can no longer be
    /// trusted to be a prefix of the file. Every other refusal keeps it for a resume.
    #[must_use]
    pub const fn discards_partial(&self) -> bool {
        matches!(
            self,
            Self::RangeMismatch | Self::RangeNotSatisfiable | Self::ContentEncoding
        )
    }
}

#[cfg(test)]
#[path = "error_tests.rs"]
mod tests;
