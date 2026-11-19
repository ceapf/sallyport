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
/// exfiltrating agent would reach for; anything else still needs an explicit rule. With
/// [`SHARED_TREES`] this is the one maintained list for shared hosting (AMENDMENTS-01). No entry
/// of either list lies under another (a test holds it), so every entry is one testable case.
/// Some entries (`gradio.live`, `glitch.me`, `loca.lt`, `serveo.net`) are not in the Public
/// Suffix List; a list derived from it must keep them.
/// TODO(#235): derive from the Public Suffix List's private section.
const SHARED_SUFFIXES: &[&str] = &[
    "cloudfront.net",
    "web.app",
    "firebaseapp.com",
    "cloudfunctions.net",
    "amplifyapp.com",
    "gradio.live",
    "github.io",
    "githubusercontent.com",
    "gitlab.io",
    "pages.dev",
    "workers.dev",
    "r2.dev",
    "trycloudflare.com",
    "vercel.app",
    "netlify.app",
    "fly.dev",
    "onrender.com",
    "glitch.me",
    "ngrok.app",
    "ngrok-free.app",
    "ngrok.dev",
    "ngrok-free.dev",
    "ngrok.pizza",
    "ngrok.pro",
    "loca.lt",
    "serveo.net",
    "repl.run",
    "deno.dev",
    "surge.sh",
    "co.uk",
    "com.au",
    "co.jp",
];

/// Shared trees: providers whose registrable hosts sit at any depth below the entry (regional
/// and per-service endpoints such as `<bucket>.s3.<region>.amazonaws.com`,
/// `<app>.<region>-01.azurewebsites.net` or `<service>.a.run.app`), so a wildcard over any base
/// under one counts too. An entry is a tree when the Public Suffix List's private section lists
/// `*.<entry>`, or `<x>.<entry>` beside the entry, or only names two or more labels below it
/// (read at publicsuffix/list commit f7796455091118a5617cc7588523b083a8223301).
/// Two exceptions. `windows.net` is unlisted but is the parent of the listed Azure service
/// suffixes (`servicebus.windows.net`, `blob.core.windows.net`, …), chosen to cover them all.
/// `storage.googleapis.com` is not in the list; it is a tree because a verified domain owner
/// may name a bucket with dots (`example.com.storage.googleapis.com`), from a security review
/// and not yet confirmed from the provider's naming documentation (#235).
const SHARED_TREES: &[&str] = &[
    "amazonaws.com",
    "on.aws",
    "elasticbeanstalk.com",
    "awsapprunner.com",
    "windows.net",
    "azurewebsites.net",
    "storage.googleapis.com",
    "run.app",
    "appspot.com",
    "herokuapp.com",
    "hf.space",
    "ngrok.io",
    "replit.dev",
    "replit.app",
    "repl.co",
];

impl HostPattern {
    /// `*`, or a wildcard that reaches hosts anyone can register: its base is a listed entry
    /// (an entry of [`SHARED_SUFFIXES`] or a tree of [`SHARED_TREES`]), a parent of one
    /// (`*.googleapis.com` covers `*.storage.googleapis.com`), or lies under a listed shared
    /// tree (`*.s3.us-east-1.amazonaws.com`, `*.web.core.windows.net`).
    #[must_use]
    pub fn is_effectively_unrestricted(&self) -> bool {
        match self {
            Self::Any => true,
            Self::Suffix(base) => covers_shared_hosting(base),
            Self::Exact(_) => false,
        }
    }
}

/// Whether `*.<base>` matches hosts under a shared-hosting entry (see
/// [`HostPattern::is_effectively_unrestricted`]).
fn covers_shared_hosting(base: &str) -> bool {
    let under_tree = SHARED_TREES.iter().any(|tree| is_below(base, tree));
    under_tree
        || SHARED_SUFFIXES
            .iter()
            .chain(SHARED_TREES)
            .any(|entry| *entry == base || is_below(entry, base))
}

/// Whether `host` lies strictly below `parent` at a label boundary (`a.b.c` below `b.c`; not
/// `ab.c`). Both are validated hostnames, so no label is empty.
fn is_below(host: &str, parent: &str) -> bool {
    host.strip_suffix(parent)
        .is_some_and(|rest| rest.ends_with('.'))
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
/// Why a host of one label is refused: the egress proxy refuses it as malformed and looks names
/// up absolute, so no rule naming one could ever be reached (issue #46).
const ONE_LABEL: &str =
    "a host of one label (\"localhost\", \"intranet\") is never reachable through the proxy";
const MAX_LABEL_LEN: usize = 63;

/// Parses an exact hostname. Wildcards are refused with [`HostError::Wildcard`].
///
/// # Errors
/// See [`HostError`].
pub fn parse_hostname(s: &str) -> Result<String, HostError> {
    if s.contains('*') {
        return Err(HostError::Wildcard);
    }
    check_exact(s)?;
    Ok(s.to_owned())
}

/// A full hostname of at least two labels.
fn check_exact(s: &str) -> Result<(), HostError> {
    check_hostname(s)?;
    if !s.contains('.') {
        return Err(HostError::Invalid(ONE_LABEL));
    }
    Ok(())
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
    check_exact(s)?;
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
            // Hosting a stranger can register under, by an exact entry.
            "*.gradio.live",
            "*.amplifyapp.com",
            "*.cloudfunctions.net",
            "*.ngrok.dev",
            "*.ngrok-free.dev",
            "*.ngrok.pizza",
            "*.ngrok.pro",
            "*.repl.run",
            // A parent of an entry: its wildcard matches the entry's hosts too.
            "*.googleapis.com",
            // A tree itself, and anywhere under one: regional and service endpoints.
            "*.amazonaws.com",
            "*.s3.us-east-1.amazonaws.com",
            "*.execute-api.eu-west-1.amazonaws.com",
            "*.windows.net",
            "*.core.windows.net",
            "*.notcore.windows.net",
            "*.web.core.windows.net",
            "*.z13.web.core.windows.net",
            "*.servicebus.windows.net",
            "*.storage.googleapis.com",
            "*.com.storage.googleapis.com",
            "*.run.app",
            "*.a.run.app",
            "*.appspot.com",
            "*.r.appspot.com",
            "*.azurewebsites.net",
            "*.eastus-01.azurewebsites.net",
            "*.hf.space",
            "*.static.hf.space",
            "*.myorg.hf.space",
            "*.ngrok.io",
            "*.eu.ngrok.io",
            "*.replit.dev",
            "*.picard.replit.dev",
            "*.replit.app",
            "*.id.replit.app",
            "*.repl.co",
            "*.id.repl.co",
            "*.herokuapp.com",
            "*.compute.herokuapp.com",
            "*.on.aws",
            "*.lambda-url.us-east-1.on.aws",
            "*.elasticbeanstalk.com",
            "*.us-east-1.elasticbeanstalk.com",
            "*.awsapprunner.com",
            "*.us-east-1.awsapprunner.com",
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
            // Label boundaries: a shared name inside a label is not that name.
            "*.xamazonaws.com",
            "*.ows.net",
            "*.notstorage.googleapis.com",
            "*.leapis.com",
            // Exact hosts are never unrestricted, even under a tree.
            "x.s3.us-east-1.amazonaws.com",
        ] {
            assert!(
                parse_host_pattern(p).is_ok_and(|h| !h.is_effectively_unrestricted()),
                "{p}"
            );
        }
    }

    /// Every entry is a wildcard base a manifest can write, appears once, and lies under no
    /// other entry: a redundant entry would be a case no test can tell apart.
    #[test]
    fn shared_hosting_lists_are_distinct_valid_bases() {
        let all: Vec<&str> = SHARED_SUFFIXES
            .iter()
            .chain(SHARED_TREES)
            .copied()
            .collect();
        for (i, e) in all.iter().enumerate() {
            assert_eq!(
                parse_host_pattern(&format!("*.{e}")),
                Ok(HostPattern::Suffix((*e).to_owned())),
                "{e}"
            );
            for (j, other) in all.iter().enumerate() {
                if i != j {
                    assert_ne!(e, other, "duplicate {e}");
                    assert!(!is_below(e, other), "{e} lies under {other}");
                }
            }
        }
    }

    #[test]
    fn is_below_needs_a_label_boundary() {
        assert!(is_below("a.b.c", "b.c"));
        assert!(!is_below("ab.c", "b.c"));
        assert!(!is_below("b.c", "b.c"));
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
    fn a_host_of_one_label_is_refused() {
        let want: Result<(), _> = Err(HostError::Invalid(ONE_LABEL));
        for h in ["localhost", "intranet", "a", "x-1"] {
            assert_eq!(parse_hostname(h).map(|_| ()), want, "{h}");
            assert_eq!(parse_host_pattern(h).map(|_| ()), want, "{h}");
        }
        assert!(parse_hostname("a.b").is_ok());
        assert!(parse_host_pattern("a.b").is_ok());
        // `*.com` keeps its own, more specific message.
        assert_ne!(parse_host_pattern("*.com").map(|_| ()), want);
    }

    #[test]
    fn numeric_non_final_labels_are_fine() {
        assert!(parse_hostname("1password.com").is_ok());
        assert!(parse_hostname("s3.us-east-1.amazonaws.com").is_ok());
    }
}
