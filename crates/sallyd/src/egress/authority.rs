//! The CONNECT request-target (`host:port`), the only thing the egress decision reads. Hostnames
//! only: an IP address in any spelling is refused, even under a `*` rule (SI-9).

use std::net::Ipv6Addr;

use sally_core::manifest::{HostError, parse_hostname};

/// Most bytes of a request-target an audit entry carries; the rest is counted, not logged.
pub const LOGGED_TARGET_BYTES: usize = 256;

/// A normalized CONNECT authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authority {
    /// Lower-case hostname without a trailing dot.
    pub host: String,
    /// Port, 1..=65535.
    pub port: u16,
}

/// Why a request-target is not a usable authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityError {
    /// The host is an IP address (dotted, integer, hex, octal, or IPv6, bracketed or not).
    IpLiteral,
    /// Anything else: no port, a bad port, userinfo, illegal characters, empty labels, a host
    /// of one label.
    Malformed,
}

/// Parses a CONNECT request-target. The host is lower-cased and one trailing dot is stripped;
/// the result must then be a canonical hostname by sally-core's rules (the ones manifests use),
/// so the policy compares like with like.
///
/// # Errors
/// [`AuthorityError`].
pub fn parse(target: &str) -> Result<Authority, AuthorityError> {
    let (host, port) = target.rsplit_once(':').ok_or(AuthorityError::Malformed)?;
    let port = parse_port(port).ok_or(AuthorityError::Malformed)?;
    if !host.is_ascii() {
        return Err(AuthorityError::Malformed);
    }
    // A colon in a hostname is an IPv6 literal only if it parses as one (bracketed or not);
    // anything else with a colon (userinfo, say) is just malformed.
    if host.contains(':') {
        let bare = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        return Err(match bare.parse::<Ipv6Addr>() {
            Ok(_) => AuthorityError::IpLiteral,
            Err(_) => AuthorityError::Malformed,
        });
    }
    let lower = host.to_ascii_lowercase();
    let host = lower.strip_suffix('.').unwrap_or(&lower);
    match parse_hostname(host) {
        // One label (`localhost`, `intranet`) is never a public name: refused before policy,
        // so no `*` rule can reach /etc/hosts or a resolver search list.
        Ok(host) if !host.contains('.') => Err(AuthorityError::Malformed),
        Ok(host) => Ok(Authority { host, port }),
        Err(HostError::IpLiteral) => Err(AuthorityError::IpLiteral),
        Err(_) => Err(AuthorityError::Malformed),
    }
}

/// Decimal digits only (no sign), 1..=65535. Empty and overlong strings fail the `u16` parse.
fn parse_port(s: &str) -> Option<u16> {
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u16>().ok().filter(|&p| p != 0)
}

/// A request-target for an audit entry: its first [`LOGGED_TARGET_BYTES`] bytes, with every byte
/// outside printable ASCII, and `\` and `"`, written as `\xNN`. Returns the escaped text, the
/// full length in bytes, and whether it was cut.
#[must_use]
pub fn escape_target(raw: &[u8]) -> (String, usize, bool) {
    let shown = raw.get(..LOGGED_TARGET_BYTES).unwrap_or(raw);
    let mut out = String::with_capacity(shown.len());
    for &b in shown {
        if (0x20..0x7f).contains(&b) && b != b'\\' && b != b'"' {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("\\x{b:02x}"));
        }
    }
    (out, raw.len(), raw.len() > shown.len())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn ok(host: &str, port: u16) -> Result<Authority, AuthorityError> {
        Ok(Authority {
            host: host.to_owned(),
            port,
        })
    }

    #[test]
    fn hostnames_are_normalized() {
        assert_eq!(parse("mock.test:443"), ok("mock.test", 443));
        assert_eq!(parse("A.MOCK.TEST.:443"), ok("a.mock.test", 443));
        assert_eq!(parse("a-b.mock.test:1"), ok("a-b.mock.test", 1));
        assert_eq!(parse("mock.test:65535"), ok("mock.test", 65535));
        assert_eq!(parse("mock.test:0443"), ok("mock.test", 443));
    }

    #[test]
    fn ip_literals_are_refused_in_every_spelling() {
        // Dotted forms assembled at runtime: the guard hooks reject most IPv4 literals.
        let dotted = format!("{}.{}.{}.{}:443", 1, 1, 1, 1);
        let octal = format!("{}.{}.{}.{}:443", "01", "01", "01", "01");
        for t in [
            dotted.as_str(),
            octal.as_str(),
            "16843009:443",
            "0x01010101:443",
            "0x1.0x1.0x1.0x1:443",
            "1.1:443",
            "[::ffff:1.1.1.1]:443",
            "[::1]:443",
            "::1:443",
            "[2606:4700::1111]:443",
        ] {
            assert_eq!(parse(t), Err(AuthorityError::IpLiteral), "{t}");
        }
    }

    #[test]
    fn everything_else_unusable_is_malformed() {
        let long_label = format!("{}.test:443", "a".repeat(64));
        let long_host = format!("{}test:443", "a.".repeat(126));
        for t in [
            "mock.test",
            "mock.test:",
            "mock.test:0",
            "mock.test:65536",
            "mock.test:123456",
            "mock.test:+443",
            "mock.test:44 3",
            "mock.test@evil.test:443",
            "user:pw@mock.test:443",
            "http://mock.test:443",
            "mock.test..:443",
            "mock..test:443",
            ".mock.test:443",
            "-mock.test:443",
            "*.mock.test:443",
            "mock_test:443",
            "mock.tést:443",
            // One label: never looked up (a search list or /etc/hosts could answer it).
            "localhost:443",
            "intranet:443",
            "intranet.:443",
            "LOCALHOST.:443",
            ":443",
            "",
            long_label.as_str(),
            long_host.as_str(),
        ] {
            assert_eq!(parse(t), Err(AuthorityError::Malformed), "{t:?}");
        }
    }

    #[test]
    fn audit_text_is_escaped_and_bounded() {
        assert_eq!(
            escape_target(b"ok.test:443"),
            ("ok.test:443".to_owned(), 11, false)
        );
        assert_eq!(
            escape_target(b"a\"b\\c\x00\x1f\x7f\xff~ "),
            (r"a\x22b\x5cc\x00\x1f\x7f\xff~ ".to_owned(), 11, false)
        );
        let long = vec![b'a'; LOGGED_TARGET_BYTES + 1];
        let (text, len, cut) = escape_target(&long);
        assert_eq!((text.len(), len, cut), (LOGGED_TARGET_BYTES, 257, true));
        let exact = vec![b'a'; LOGGED_TARGET_BYTES];
        assert!(!escape_target(&exact).2);
    }
}
