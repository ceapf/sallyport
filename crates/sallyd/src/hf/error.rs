//! Why a Hub list or pull failed. Each variant has a stable [`PullError::code`]: the core's and
//! the library's codes pass through, and the transport's own start `hf_`. No variant holds text
//! the Hub or the network chose, and none can hold the token.

use sally_core::hf::HfError;
use sally_core::library::LibraryError;

/// Why a Hub list or pull failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PullError {
    /// The decision layer refused.
    #[error(transparent)]
    Hf(#[from] HfError),
    /// The library refused or failed.
    #[error(transparent)]
    Library(#[from] LibraryError),
    /// The host name did not resolve, or answered nothing usable in time.
    #[error("{0} did not resolve")]
    ResolveFailed(String),
    /// The host resolved to an address Sallyport never connects to (loopback, private,
    /// link-local, this host's own).
    #[error("{0} resolved to an address Sallyport does not connect to")]
    AddressDenied(String),
    /// No connection to any pinned address.
    #[error("could not connect to {0}")]
    ConnectFailed(String),
    /// The TLS handshake or the certificate check failed.
    #[error("the TLS connection to {0} failed")]
    TlsFailed(String),
    /// A step did not finish in its time.
    #[error("the Hub did not answer in time ({0})")]
    Timeout(&'static str),
    /// The HTTP exchange failed (a malformed response, a connection that ended mid-head).
    #[error("the HTTP exchange with the Hub failed")]
    Protocol,
    /// A header the decision needs was sent twice, or is not visible ASCII.
    #[error("the Hub sent a malformed {0} header")]
    HeaderInvalid(&'static str),
    /// The body ended before its length, or failed; what arrived is kept for a resume.
    #[error("the download stopped before the end of the file; pull again to resume")]
    BodyFailed,
    /// The token holds a byte an HTTP header cannot carry; it is never sent or shown.
    #[error("the Hub token holds characters an HTTP header cannot carry")]
    TokenUnusable,
    /// A blocking library task failed.
    #[error("a library task failed")]
    Task,
}

impl PullError {
    /// The stable reason code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Hf(e) => e.code(),
            Self::Library(e) => e.code(),
            Self::ResolveFailed(_) => "hf_resolve_failed",
            Self::AddressDenied(_) => "hf_address_denied",
            Self::ConnectFailed(_) => "hf_connect_failed",
            Self::TlsFailed(_) => "hf_tls_failed",
            Self::Timeout(_) => "hf_timeout",
            Self::Protocol => "hf_protocol",
            Self::HeaderInvalid(_) => "hf_header_invalid",
            Self::BodyFailed => "hf_body_failed",
            Self::TokenUnusable => "hf_token_unusable",
            Self::Task => "hf_task_failed",
        }
    }
}
