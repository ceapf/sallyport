//! Hostname rules (MANIFEST_SPEC §1 HostRule, SI-9).
//!
//! Manifests must spell hosts canonically (lowercase ASCII, no trailing dot) so the text the
//! user reviewed is exactly what the egress policy matches. IP literals in any spelling are
//! refused here; the egress proxy refuses them again on every request.
#![deny(clippy::indexing_slicing)]

use std::fmt;

/// A validated egress host pattern.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HostPattern {
    /// `"*"`: any hostname (still subject to the IP-range filter).
    Any,
    /// `"*.example.com"`: strict subdomains of the stored base (`example.com`).
    Suffix(String),
    /// An exact hostname.
    Exact(String),
}

impl HostPattern {
    /// Whether `host` (already normalized: lowercase, no trailing dot) matches.
    #[must_use]
    pub fn matches(&self, host: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(h) => host == h,
            Self::Suffix(base) => host
                .strip_suffix(base.as_str())
                .and_then(|rest| rest.strip_suffix('.'))
                .is_some_and(|label_part| !label_part.is_empty()),
        }
    }
}

/// Suffixes under which anyone can register a subdomain (hosting, tunnels, object storage).
/// `*.<one of these>` reaches attacker-controlled hosts, so it counts as unrestricted egress.
/// Deliberately a short curated list, not the full Public Suffix List: it covers the services an
/// exfiltrating agent would reach for; anything else still needs an explicit rule. This is the
/// one maintained constant for shared hosting (AMENDMENTS-01).
/// TODO(v2): derive from the Public Suffix List's private section.
const SHARED_SUFFIXES: &[&str] = &[
    "amazonaws.com",
    "s3.amazonaws.com",
    "cloudfront.net",
    "appspot.com",
    "web.app",
    "firebaseapp.com",
    "azurewebsites.net",
    "blob.core.windows.net",
    "github.io",
    "githubusercontent.com",
    "gitlab.io",
    "pages.dev",
    "workers.dev",
    "r2.dev",
    "trycloudflare.com",
    "herokuapp.com",
    "vercel.app",
    "netlify.app",
    "fly.dev",
    "onrender.com",
    "glitch.me",
    "ngrok.io",
    "ngrok.app",
    "ngrok-free.app",
    "loca.lt",
    "serveo.net",
    "replit.dev",
    "repl.co",
    "deno.dev",
    "surge.sh",
    "co.uk",
    "com.au",
    "co.jp",
];

impl HostPattern {
    /// `*`, or a wildcard over a suffix where anyone can register hosts (see `SHARED_SUFFIXES`).
    #[must_use]
    pub fn is_effectively_unrestricted(&self) -> bool {
        match self {
            Self::Any => true,
            Self::Suffix(base) => SHARED_SUFFIXES.contains(&base.as_str()),
            Self::Exact(_) => false,
        }
    }
}

impl fmt::Display for HostPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => f.write_str("*"),
            Self::Suffix(b) => write!(f, "*.{b}"),
            Self::Exact(h) => f.write_str(h),
        }
    }
}

/// Why a host string was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HostError {
    /// Looks like an IP address (dotted, integer, hex, octal, or IPv6).
    #[error("IP literals are not allowed; use a hostname")]
    IpLiteral,
    /// A wildcard where an exact hostname is required.
    #[error("host must be exact (no wildcards)")]
    Wildcard,
    /// Malformed or too broad; the string explains.
    #[error("{0}")]
    Invalid(&'static str),
}

const MAX_HOST_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

/// Parses an exact hostname. Wildcards are refused with [`HostError::Wildcard`].
///
/// # Errors
/// See [`HostError`].
pub fn parse_hostname(s: &str) -> Result<String, HostError> {
    if s.contains('*') {
        return Err(HostError::Wildcard);
    }
    check_hostname(s)?;
    Ok(s.to_owned())
}

/// Parses an allow-rule host: exact, `*.base` (base needs at least two labels), or `*`.
///
/// # Errors
/// See [`HostError`].
pub fn parse_host_pattern(s: &str) -> Result<HostPattern, HostError> {
    if s == "*" {
        return Ok(HostPattern::Any);
    }
    if let Some(base) = s.strip_prefix("*.") {
        if base.contains('*') {
            return Err(HostError::Invalid("only one leading \"*.\" is allowed"));
        }
        check_hostname(base)?;
        if !base.contains('.') {
            return Err(HostError::Invalid(
                "wildcard base must have at least two labels (\"*.com\" is too broad)",
            ));
        }
        return Ok(HostPattern::Suffix(base.to_owned()));
    }
    if s.contains('*') {
        return Err(HostError::Invalid(
            "\"*\" is only allowed alone or as a leading \"*.\"",
        ));
    }
    check_hostname(s)?;
    Ok(HostPattern::Exact(s.to_owned()))
}

fn check_hostname(s: &str) -> Result<(), HostError> {
    if s.is_empty() {
        return Err(HostError::Invalid("empty hostname"));
    }
    if s.contains(':') || s.starts_with('[') {
        return Err(HostError::IpLiteral);
    }
    if s.len() > MAX_HOST_LEN {
        return Err(HostError::Invalid("hostname longer than 253 characters"));
    }
    if s.ends_with('.') {
        return Err(HostError::Invalid("remove the trailing dot"));
    }
    if s.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(HostError::Invalid("hostnames must be lowercase"));
    }
    let labels: Vec<&str> = s.split('.').collect();
    // A numeric last label makes this an inet_aton-style IP spelling (`127.1`, `2130706433`,
    // `0x7f.0.0.1`, `0177.0.0.1`); an all-numeric name has a numeric last label too. Checked
    // before label syntax so the error says "IP literal" rather than something vaguer.
    if labels.last().is_some_and(|l| is_numeric_label(l)) {
        return Err(HostError::IpLiteral);
    }
    for label in labels {
        check_label(label)?;
    }
    Ok(())
}

fn is_numeric_label(l: &str) -> bool {
    let hex = l.strip_prefix("0x").or_else(|| l.strip_prefix("0X"));
    match hex {
        Some(h) => !h.is_empty() && h.bytes().all(|b| b.is_ascii_hexdigit()),
        None => !l.is_empty() && l.bytes().all(|b| b.is_ascii_digit()),
    }
}

fn check_label(l: &str) -> Result<(), HostError> {
    if l.is_empty() {
        return Err(HostError::Invalid("empty label (\"..\")"));
    }
    if l.len() > MAX_LABEL_LEN {
        return Err(HostError::Invalid("label longer than 63 characters"));
    }
    if !l
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(HostError::Invalid(
            "only a-z, 0-9, '-' and '.' are allowed (use punycode for IDNs)",
        ));
    }
    if l.starts_with('-') || l.ends_with('-') {
        return Err(HostError::Invalid("labels cannot start or end with '-'"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_and_suffix_patterns() {
        assert_eq!(
            parse_host_pattern("api.github.com"),
            Ok(HostPattern::Exact("api.github.com".into()))
        );
        assert_eq!(
            parse_host_pattern("*.pypi.org"),
            Ok(HostPattern::Suffix("pypi.org".into()))
        );
        assert_eq!(parse_host_pattern("*"), Ok(HostPattern::Any));
    }

    #[test]
    fn suffix_matching_follows_spec() {
        let p = HostPattern::Suffix("example.com".into());
        assert!(p.matches("a.example.com"));
        assert!(p.matches("a.b.example.com"));
        assert!(!p.matches("example.com"));
        assert!(!p.matches("example.com.evil.net"));
        assert!(!p.matches("evilexample.com"));
        assert!(!p.matches(".example.com"));
    }

    #[test]
    fn exact_matching() {
        let p = HostPattern::Exact("api.github.com".into());
        assert!(p.matches("api.github.com"));
        assert!(!p.matches("x.api.github.com"));
    }

    #[test]
    fn ip_literals_refused_in_every_spelling() {
        for ip in [
            "127.0.0.1",
            "127.1",
            "2130706433",
            "0x7f000001",
            "0x7f.0.0.1",
            "0177.0.0.1",
            "::1",
            "[::1]",
            "fe80::1",
            "10.0.0.1",
            "*.1.2.3",
            "169.254.169.254",
        ] {
            assert_eq!(parse_host_pattern(ip), Err(HostError::IpLiteral), "{ip}");
        }
    }

    #[test]
    fn malformed_hosts_refused() {
        for bad in [
            "",
            "API.github.com",
            "github.com.",
            "a..b",
            "-a.com",
            "a-.com",
            "a_b.com",
            "*.com",
            "a.*.com",
            "*example.com",
            "**",
            "*.*.com",
            "ex ample.com",
            "exämple.com",
            &"a".repeat(64),
            &format!("{}.com", "a.".repeat(130)),
        ] {
            assert!(
                matches!(parse_host_pattern(bad), Err(HostError::Invalid(_))),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn shared_suffix_wildcards_are_unrestricted() {
        for p in [
            "*",
            "*.github.io",
            "*.s3.amazonaws.com",
            "*.workers.dev",
            "*.co.uk",
        ] {
            assert!(
                parse_host_pattern(p).is_ok_and(|h| h.is_effectively_unrestricted()),
                "{p}"
            );
        }
        for p in [
            "*.pypi.org",
            "*.myorg.github.io",
            "api.github.io",
            "github.io",
        ] {
            assert!(
                parse_host_pattern(p).is_ok_and(|h| !h.is_effectively_unrestricted()),
                "{p}"
            );
        }
    }

    #[test]
    fn exact_hostname_refuses_wildcards() {
        assert_eq!(parse_hostname("*"), Err(HostError::Wildcard));
        assert_eq!(parse_hostname("*.github.com"), Err(HostError::Wildcard));
        assert_eq!(
            parse_hostname("api.github.com"),
            Ok("api.github.com".into())
        );
    }

    #[test]
    fn numeric_non_final_labels_are_fine() {
        assert!(parse_hostname("1password.com").is_ok());
        assert!(parse_hostname("s3.us-east-1.amazonaws.com").is_ok());
    }
}
