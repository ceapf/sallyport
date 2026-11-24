//! The decision on each response head: follow a redirect, wait and retry, read the body (and
//! how), or refuse. Pure over the status and the few headers that matter; `sallyd` reads the
//! head and does what this returns.
//!
//! A file body is taken only as stored (no Content-Encoding) and only at the length listed:
//! a 200 must declare the whole size and starts the file again; a 206 must answer exactly
//! the range asked for (`bytes n-(size-1)/size`) and is appended. Anything that makes the bytes
//! on disk untrustworthy as a prefix (another range, a 416, an encoding) refuses and deletes
//! the partial ([`HfError::discards_partial`]).
//!
//! The file list, which carries the publisher's hashes, is read from the API host only: a
//! redirect of the list call to any other host is refused (RT-MDL-11).
#![deny(clippy::indexing_slicing)]

use super::plan::{API_HOST, Request, redirect};
use super::{
    DEFAULT_RETRY_WAIT_SECS, HfError, MAX_LIST_BYTES, MAX_REDIRECTS, MAX_RETRIES,
    MAX_RETRY_WAIT_SECS,
};

/// Most digits read from a Retry-After value.
const MAX_RETRY_DIGITS: usize = 10;
/// Most digits of a length or a range bound (`u64::MAX` has 20).
const MAX_NUMBER_DIGITS: usize = 20;

/// What a response head said, as far as the decision needs. Each header is its single value,
/// or `None` when absent; a header sent twice is the transport's refusal, never one of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Head<'a> {
    /// The status code.
    pub status: u16,
    /// `Content-Length`.
    pub content_length: Option<&'a str>,
    /// `Content-Range`.
    pub content_range: Option<&'a str>,
    /// `Location`.
    pub location: Option<&'a str>,
    /// `Retry-After`.
    pub retry_after: Option<&'a str>,
    /// Whether a `Content-Encoding` header is present, whatever its value.
    pub content_encoding: bool,
}

/// Redirects and retries taken so far for one request.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Tries {
    redirects: u32,
    retries: u32,
}

/// What to do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Send this hop next.
    Redirect(Request),
    /// Wait this many seconds, then send the same hop again.
    Wait(u64),
    /// Read the body.
    Body(Body),
}

/// How to take the body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Body {
    /// The file list: read at most [`MAX_LIST_BYTES`] + 1 bytes.
    List,
    /// File bytes that go on from what is on disk.
    Append,
    /// The whole file again: empty the partial first.
    FromStart,
}

/// The decision on the head of a file-list request. The list carries the publisher's hashes, so
/// it is read from the API host only: a list request to any other host, and a redirect of the
/// list call to any other host, are refused.
///
/// # Errors
/// The refusal.
pub fn decide_list(head: &Head<'_>, req: &Request, tries: &mut Tries) -> Result<Step, HfError> {
    if req.host() != API_HOST {
        return Err(HfError::RedirectRefused);
    }
    match common(head, req, tries)? {
        Some(Step::Redirect(next)) if next.host() != API_HOST => {
            return Err(HfError::RedirectRefused);
        }
        Some(step) => return Ok(step),
        None => {}
    }
    if head.status != 200 {
        return Err(HfError::UpstreamStatus(head.status));
    }
    if head.content_encoding {
        return Err(HfError::ContentEncoding);
    }
    if let Some(cl) = head.content_length {
        let len = parse_u64(cl).ok_or(HfError::LengthMismatch)?;
        if usize::try_from(len).map_or(true, |len| len > MAX_LIST_BYTES) {
            return Err(HfError::ListTooLarge);
        }
    }
    Ok(Step::Body(Body::List))
}

/// The decision on the head of a file request sent with `written` bytes on disk, for a file
/// listed at `size` bytes.
///
/// # Errors
/// The refusal; [`HfError::discards_partial`] says whether the partial goes too.
pub fn decide_file(
    head: &Head<'_>,
    req: &Request,
    tries: &mut Tries,
    written: u64,
    size: u64,
) -> Result<Step, HfError> {
    if let Some(step) = common(head, req, tries)? {
        return Ok(step);
    }
    if head.status == 416 {
        return Err(HfError::RangeNotSatisfiable);
    }
    if !matches!(head.status, 200 | 206) {
        return Err(HfError::UpstreamStatus(head.status));
    }
    if head.content_encoding {
        return Err(HfError::ContentEncoding);
    }
    if head.status == 200 {
        return match head.content_length.and_then(parse_u64) {
            Some(len) if len == size && written == 0 => Ok(Step::Body(Body::Append)),
            Some(len) if len == size => Ok(Step::Body(Body::FromStart)),
            _ => Err(HfError::LengthMismatch),
        };
    }
    let asked = req.range_from().ok_or(HfError::RangeMismatch)?;
    let last = size.checked_sub(1).ok_or(HfError::RangeMismatch)?;
    let range = head.content_range.and_then(parse_content_range);
    if asked != written || range != Some((written, last, size)) {
        return Err(HfError::RangeMismatch);
    }
    if let Some(cl) = head.content_length
        && parse_u64(cl) != size.checked_sub(written)
    {
        return Err(HfError::RangeMismatch);
    }
    Ok(Step::Body(Body::Append))
}

/// Redirects, rate limits and the statuses every request refuses alike; `None` for the rest.
fn common(head: &Head<'_>, req: &Request, tries: &mut Tries) -> Result<Option<Step>, HfError> {
    match head.status {
        301 | 302 | 303 | 307 | 308 => {
            tries.redirects = tries.redirects.saturating_add(1);
            if tries.redirects > MAX_REDIRECTS {
                return Err(HfError::TooManyRedirects);
            }
            let location = head.location.ok_or(HfError::RedirectRefused)?;
            redirect(req, location).map(|next| Some(Step::Redirect(next)))
        }
        429 => wait(head, tries),
        503 if head.retry_after.is_some() => wait(head, tries),
        401 | 403 => Err(HfError::Unauthorized),
        404 => Err(HfError::NotFound),
        _ => Ok(None),
    }
}

/// One more retry, or the refusal once the bound is used.
fn wait(head: &Head<'_>, tries: &mut Tries) -> Result<Option<Step>, HfError> {
    tries.retries = tries.retries.saturating_add(1);
    if tries.retries > MAX_RETRIES {
        return Err(HfError::RateLimited);
    }
    Ok(Some(Step::Wait(retry_wait(head.retry_after))))
}

/// Seconds to wait: a delta-seconds Retry-After of at most ten digits, capped at
/// [`MAX_RETRY_WAIT_SECS`]; the date form, garbage or none wait [`DEFAULT_RETRY_WAIT_SECS`].
#[must_use]
pub fn retry_wait(value: Option<&str>) -> u64 {
    value
        .filter(|v| v.len() <= MAX_RETRY_DIGITS)
        .and_then(parse_u64)
        .map_or(DEFAULT_RETRY_WAIT_SECS, |s| s.min(MAX_RETRY_WAIT_SECS))
}

/// A canonical decimal of 1 to 20 ASCII digits that fits in a `u64`: no sign, no space, no
/// leading zero (except `0` itself).
#[must_use]
pub fn parse_u64(s: &str) -> Option<u64> {
    canonical_digits(s).then(|| s.parse().ok()).flatten()
}

/// The shape [`parse_u64`] checks before it parses: 1 to 20 ASCII digits, no leading zero
/// (except `0` itself). Bounds first: no longer string reaches the parser.
pub(super) fn canonical_digits(s: &str) -> bool {
    (1..=MAX_NUMBER_DIGITS).contains(&s.len())
        && s.bytes().all(|b| b.is_ascii_digit())
        && !(s.len() > 1 && s.starts_with('0'))
}

/// `bytes first-last/total` with `first <= last < total`, exactly; nothing else.
#[must_use]
pub fn parse_content_range(s: &str) -> Option<(u64, u64, u64)> {
    let rest = s.strip_prefix("bytes ")?;
    let (range, total) = rest.split_once('/')?;
    let (first, last) = range.split_once('-')?;
    let (first, last, total) = (parse_u64(first)?, parse_u64(last)?, parse_u64(total)?);
    (first <= last && last < total).then_some((first, last, total))
}

#[cfg(test)]
#[path = "head_tests.rs"]
mod tests;
