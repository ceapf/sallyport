//! The `fetch` tool's URL (#75; architect ruling Q4). Pure and hand-written: `https` only, no
//! userinfo, no fragment, the host through the egress copy of host normalization
//! ([`authority::parse`]: lower-case, one trailing dot stripped, IP literals refused in every
//! spelling), the port 1–65535 (443 when absent), and a path and query of RFC 3986 characters and
//! `%XX` escapes only, never decoded, with no literal `.` or `..` path segment.
//!
//! The approval ticket binds and shows the canonical form ([`FetchUrl::canonical`]):
//! `https://host[:port]/path[?query]`, the port written only when it is not 443. The request
//! target sent upstream is exactly its path-and-query part, so what the human approves is what
//! goes on the wire (SI-5). The canonical form parses to itself.
#![deny(clippy::indexing_slicing)]

use crate::egress::authority::{self, AuthorityError};

/// Longest URL accepted, in bytes. The request head limit (`fetch.rs`) is the binding bound.
pub const MAX_URL: usize = 4096;

/// The only scheme.
const HTTPS: &str = "https://";
/// The port a canonical URL leaves out.
const DEFAULT_PORT: u16 = 443;

/// A checked `fetch` URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchUrl {
    /// Lower-case hostname without a trailing dot.
    pub host: String,
    /// The port, 443 when the URL names none.
    pub port: u16,
    /// The origin-form request target: the path (at least `/`) and the query, as given.
    pub target: String,
}

/// Why a URL is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlError {
    /// Another scheme (`http`, `ftp`, …).
    NotHttps,
    /// The host is an IP address.
    IpLiteral,
    /// Longer than [`MAX_URL`].
    TooLong,
    /// Anything else: userinfo, a fragment, a bad host or port, a character outside RFC 3986, a
    /// broken `%` escape, a `.` or `..` path segment.
    Malformed,
}

impl UrlError {
    /// The `denied: <code>` text.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::NotHttps => "url-not-https",
            Self::IpLiteral => "ip-literal",
            Self::TooLong => "url-too-long",
            Self::Malformed => "bad-url",
        }
    }
}

impl FetchUrl {
    /// `https://host[:port]/path[?query]`, the port only when it is not 443.
    #[must_use]
    pub fn canonical(&self) -> String {
        if self.port == DEFAULT_PORT {
            format!("{HTTPS}{}{}", self.host, self.target)
        } else {
            format!("{HTTPS}{}:{}{}", self.host, self.port, self.target)
        }
    }
}

/// Parses a `fetch` URL.
///
/// # Errors
/// [`UrlError`].
pub fn parse(url: &str) -> Result<FetchUrl, UrlError> {
    if url.len() > MAX_URL {
        return Err(UrlError::TooLong);
    }
    let rest = after_scheme(url)?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (auth, tail) = rest.split_at_checked(end).ok_or(UrlError::Malformed)?;
    if auth.contains('@') {
        return Err(UrlError::Malformed);
    }
    // A bracketed IPv6 literal without a port still reaches the parser, which names it.
    let with_port = if auth.ends_with(']') || !auth.contains(':') {
        format!("{auth}:{DEFAULT_PORT}")
    } else {
        auth.to_owned()
    };
    let a = authority::parse(&with_port).map_err(|e| match e {
        AuthorityError::IpLiteral => UrlError::IpLiteral,
        AuthorityError::Malformed => UrlError::Malformed,
    })?;
    let target = if tail.starts_with('/') {
        tail.to_owned()
    } else {
        format!("/{tail}")
    };
    check_target(&target)?;
    Ok(FetchUrl {
        host: a.host,
        port: a.port,
        target,
    })
}

/// What follows `https://` (any case); another RFC 3986 scheme is [`UrlError::NotHttps`].
fn after_scheme(url: &str) -> Result<&str, UrlError> {
    if let Some(head) = url.get(..HTTPS.len())
        && head.eq_ignore_ascii_case(HTTPS)
    {
        return url.get(HTTPS.len()..).ok_or(UrlError::Malformed);
    }
    let scheme = url.split_once(':').map_or("", |(s, _)| s);
    let mut chars = scheme.chars();
    let named = chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    Err(if named {
        UrlError::NotHttps
    } else {
        UrlError::Malformed
    })
}

/// RFC 3986 path and query characters and `%XX` only (so no fragment, space or control byte),
/// and no `.` or `..` path segment.
fn check_target(target: &str) -> Result<(), UrlError> {
    // No index arithmetic: each step takes its bytes off the front (rust review L3).
    let mut rest = target.as_bytes();
    while let Some((&c, tail)) = rest.split_first() {
        rest = match (c, tail) {
            (b'%', [h, l, more @ ..]) if h.is_ascii_hexdigit() && l.is_ascii_hexdigit() => more,
            (b'%', _) => return Err(UrlError::Malformed),
            _ if c.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@/?".contains(&c) => tail,
            _ => return Err(UrlError::Malformed),
        };
    }
    let path = target.split_once('?').map_or(target, |(p, _)| p);
    if path.split('/').any(|s| s == "." || s == "..") {
        return Err(UrlError::Malformed);
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn ok(url: &str) -> (String, u16, String, String) {
        let u = parse(url).unwrap_or_else(|e| panic!("{url}: {e:?}"));
        let c = u.canonical();
        (u.host, u.port, u.target, c)
    }

    #[test]
    fn https_urls_parse_to_host_port_target_and_their_canonical_form() {
        assert_eq!(
            ok("https://api.mock.test/v1/x?y=1&z=%2F"),
            (
                "api.mock.test".into(),
                443,
                "/v1/x?y=1&z=%2F".into(),
                "https://api.mock.test/v1/x?y=1&z=%2F".into()
            )
        );
        assert_eq!(
            ok("HTTPS://API.Mock.Test.:8443"),
            (
                "api.mock.test".into(),
                8443,
                "/".into(),
                "https://api.mock.test:8443/".into()
            )
        );
        assert_eq!(ok("https://a.mock.test:443?q").3, "https://a.mock.test/?q");
        assert_eq!(ok("https://a.mock.test:0443/").3, "https://a.mock.test/");
        assert_eq!(ok("https://a.mock.test/").2, "/");
        // Every RFC 3986 path and query character, and escapes kept as given (never decoded).
        let all = "/a-._~!$&'()*+,;=:@/%2e%2E%00?/?:@-._~!$&'()*+,;=%ff";
        assert_eq!(ok(&format!("https://a.mock.test{all}")).2, all);
        // Dots inside a segment, and in the query, are not dot segments.
        assert_eq!(
            ok("https://a.mock.test/a..b/.c/d.?x=/../.").2,
            "/a..b/.c/d.?x=/../."
        );
    }

    #[test]
    fn the_canonical_form_parses_to_itself() {
        for url in [
            "https://a.mock.test",
            "HTTPS://A.mock.test.:443/x",
            "https://a.mock.test:8443?q=1",
            "https://a.mock.test/%41/b?c#",
        ] {
            let Ok(u) = parse(url) else { continue };
            let c = u.canonical();
            assert_eq!(parse(&c), Ok(u), "{url}");
            assert_eq!(parse(&c).unwrap().canonical(), c, "{url}");
        }
    }

    #[test]
    fn other_schemes_are_not_https() {
        for url in [
            "http://a.mock.test/",
            "ftp://a.mock.test/",
            "httpss://a.mock.test/",
            "https:a.mock.test/",
            "https:/a.mock.test/",
            "file:///etc/passwd",
            "x+y-z.1:opaque",
        ] {
            assert_eq!(parse(url), Err(UrlError::NotHttps), "{url}");
        }
    }

    #[test]
    fn ip_literals_are_refused_in_every_spelling() {
        for url in [
            "https://127.0.0.1/",
            "https://10.0.0.1:443/",
            "https://2130706433/",
            "https://0x7f000001/",
            "https://[::1]/",
            "https://[::1]:443/",
            "https://[fe80::1]:8443/x",
        ] {
            assert_eq!(parse(url), Err(UrlError::IpLiteral), "{url}");
        }
    }

    #[test]
    fn everything_else_unusable_is_malformed() {
        for url in [
            "",
            "https://",
            "https:///x",
            "https://:443/",
            "https://a.mock.test:/",
            "https://a.mock.test:0/",
            "https://a.mock.test:65536/",
            "https://a.mock.test:+443/",
            "https://a.mock.test:44a/",
            "https://user@a.mock.test/",
            "https://user:pw@a.mock.test/",
            "https://a.mock.test/x#frag",
            "https://a.mock.test#",
            "https://a.mock.test/a b",
            "https://a.mock.test/a\tb",
            "https://a.mock.test/a\r\nX: y",
            "https://a.mock.test/a\"b",
            "https://a.mock.test/a<b>",
            "https://a.mock.test/a\\b",
            "https://a.mock.test/a^b",
            "https://a.mock.test/a`b",
            "https://a.mock.test/a{b}",
            "https://a.mock.test/a|b",
            "https://a.mock.test/é",
            "https://a.mock.test/%",
            "https://a.mock.test/%4",
            "https://a.mock.test/%4g",
            "https://a.mock.test/?%zz",
            "https://a.mock.test/.",
            "https://a.mock.test/./x",
            "https://a.mock.test/x/..",
            "https://a.mock.test/x/../y?q",
            "https://localhost/",
            "https://a..mock.test/",
            "https://a_b.mock.test/",
            "https://a.mock.test\\x/",
        ] {
            assert_eq!(parse(url), Err(UrlError::Malformed), "{url:?}");
        }
    }

    #[test]
    fn the_length_bound_is_exact() {
        let base = "https://a.mock.test/";
        let at = format!("{base}{}", "a".repeat(MAX_URL - base.len()));
        assert_eq!(at.len(), MAX_URL);
        assert!(parse(&at).is_ok());
        assert_eq!(parse(&format!("{at}a")), Err(UrlError::TooLong));
    }

    #[test]
    fn errors_have_their_codes() {
        assert_eq!(UrlError::NotHttps.code(), "url-not-https");
        assert_eq!(UrlError::IpLiteral.code(), "ip-literal");
        assert_eq!(UrlError::TooLong.code(), "url-too-long");
        assert_eq!(UrlError::Malformed.code(), "bad-url");
    }
}
