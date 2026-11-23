//! The request for each hop: which host, which path, whether it asks for a range, whether it
//! carries the token. `sallyd` sends exactly what this plans and nothing it chose itself.
//!
//! The first hop of every request goes to [`API_HOST`]. A redirect is followed only to https
//! on the default port, with no userinfo, to [`API_HOST`] or `hf.co` or a subdomain of either on
//! a label boundary ([`REDIRECT_DOMAINS`]). Every hop's host and path are planned again from the
//! Location alone. The token goes only to a hop whose host is exactly [`API_HOST`], and only
//! while the chain has never left it: once one hop has gone to another host, no later hop of
//! that chain carries the token, a return to [`API_HOST`] included (it is followed without it).
#![deny(clippy::indexing_slicing)]

use super::HfError;
use super::MAX_LOCATION_BYTES;
use super::names::{Commit, RepoId, RepoPath, Revision};

/// The Hub's API and file host; the only host a token is sent to.
pub const API_HOST: &str = "huggingface.co";
/// The domains a redirect may go to, the domain itself or a subdomain on a label boundary.
pub const REDIRECT_DOMAINS: [&str; 2] = ["huggingface.co", "hf.co"];
/// Longest host name (RFC 1035).
const MAX_HOST_BYTES: usize = 253;
/// Longest label.
const MAX_LABEL_BYTES: usize = 63;
/// The only scheme followed.
const HTTPS: &str = "https://";

/// One hop: an https GET on port 443.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    host: String,
    path: String,
    range_from: Option<u64>,
    auth: bool,
}

impl Request {
    /// The host to resolve, check and connect to (and to verify the certificate for).
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The request target: path and query, starting with `/`.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// `Some(n)`: send `Range: bytes=n-`.
    #[must_use]
    pub const fn range_from(&self) -> Option<u64> {
        self.range_from
    }

    /// Whether this hop carries the token: only when its host is exactly [`API_HOST`] and no
    /// earlier hop of its chain went to another host.
    #[must_use]
    pub const fn carries_auth(&self) -> bool {
        self.auth
    }
}

/// The file list of `repo` at `rev`.
#[must_use]
pub fn list_request(repo: &RepoId, rev: &Revision) -> Request {
    Request {
        host: API_HOST.to_owned(),
        path: format!(
            "/api/models/{}/revision/{}?blobs=true",
            repo.encoded(),
            rev.encoded()
        ),
        range_from: None,
        auth: true,
    }
}

/// The file at `path` of `repo` at `commit`, from byte `from` (no range when 0).
#[must_use]
pub fn file_request(repo: &RepoId, commit: &Commit, path: &RepoPath, from: u64) -> Request {
    Request {
        host: API_HOST.to_owned(),
        path: format!(
            "/{}/resolve/{}/{}",
            repo.encoded(),
            commit.as_str(),
            path.encoded()
        ),
        range_from: (from > 0).then_some(from),
        auth: true,
    }
}

/// Where a download goes on from, or `None` when every byte is on disk (go to verify).
#[must_use]
pub const fn next_fetch(written: u64, size: u64) -> Option<u64> {
    if written >= size { None } else { Some(written) }
}

/// The next hop after a redirect from `current` to `location`: an absolute `https://host/…`
/// or a path on the current host. The range is kept. The next hop carries the token only if
/// `current` carried it and the next host is exactly [`API_HOST`]: a chain that has left the API
/// host never carries it again.
///
/// # Errors
/// [`HfError::RedirectRefused`].
pub fn redirect(current: &Request, location: &str) -> Result<Request, HfError> {
    if location.len() > MAX_LOCATION_BYTES || !location.bytes().all(location_byte) {
        return Err(HfError::RedirectRefused);
    }
    let (host, path) = if let Some(rest) = location.strip_prefix(HTTPS) {
        let split = rest.find('/').unwrap_or(rest.len());
        let (authority, path) = rest.split_at(split);
        let host = authority.to_ascii_lowercase();
        if !redirect_host_ok(&host) {
            return Err(HfError::RedirectRefused);
        }
        let path = if path.is_empty() { "/" } else { path };
        (host, path.to_owned())
    } else if location.starts_with('/') && !location.starts_with("//") {
        (current.host.clone(), location.to_owned())
    } else {
        return Err(HfError::RedirectRefused);
    };
    Ok(Request {
        auth: current.auth && host == API_HOST,
        host,
        path,
        range_from: current.range_from,
    })
}

/// A byte a followed Location may hold: printable ASCII from RFC 3986's sets, no fragment.
fn location_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'-' | b'.'
                | b'_'
                | b'~'
                | b':'
                | b'/'
                | b'?'
                | b'['
                | b']'
                | b'@'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b'%'
        )
}

/// Whether `host` (lowercase) is a Hub domain or a subdomain of one on a label boundary: LDH
/// labels of 1 to 63 bytes, no label starting or ending with `-`, at most 253 bytes. A port, a
/// userinfo or an IP literal never passes (`:`, `@`, `[` are not LDH; an all-digit name is no
/// Hub domain).
#[must_use]
pub fn redirect_host_ok(host: &str) -> bool {
    let labels_ok = host.len() <= MAX_HOST_BYTES
        && host.split('.').all(|l| {
            let b = l.as_bytes();
            (1..=MAX_LABEL_BYTES).contains(&b.len())
                && b.iter()
                    .all(|c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'-'))
                && b.first() != Some(&b'-')
                && b.last() != Some(&b'-')
        });
    labels_ok
        && REDIRECT_DOMAINS.iter().any(|d| {
            host == *d
                || host
                    .strip_suffix(d)
                    .is_some_and(|prefix| prefix.ends_with('.'))
        })
}

#[cfg(test)]
#[path = "plan_tests.rs"]
mod tests;
