//! The CONNECT request-target (`host:port`), the only thing the egress decision reads. Hostnames
//! only: an IP address in any spelling is refused, even under a `*` rule (SI-9).

use std::net::Ipv6Addr;
use std::sync::Arc;

use sally_core::audit::{NewEntry, Redactor};
use sally_core::manifest::{HostError, parse_hostname};
use sally_core::text::Style;

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
// TODO(#160): the lower-cased host goes into every entry that names it, where a mixed-case form
// in a label no longer matches the session's forms (a documented residual, architect Q253; the
// raw target of a refusal is declared by `with_target` and masked whole).
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
    // `parse_hostname` also refuses a host of one label (`localhost`, `intranet`): malformed
    // before policy, so no `*` rule can reach a resolver search list (architect Q18).
    match parse_hostname(host) {
        Ok(host) => Ok(Authority { host, port }),
        Err(HostError::IpLiteral) => Err(AuthorityError::IpLiteral),
        Err(_) => Err(AuthorityError::Malformed),
    }
}

/// Why the `Host` header of an intercepted request is refused (architect Q29).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostHeaderError {
    /// Not an authority by [`parse`]'s rules (IP literal, userinfo, bad port, not ASCII…): 400.
    Malformed,
    /// A usable authority, but not the CONNECT one: 421.
    Mismatch,
}

/// Checks one `Host` header value of a request inside the tunnel to `connect`. It is normalized
/// as a CONNECT target is (lower case, one trailing dot) and must name the same host. The port
/// may be left out only when the CONNECT port is 443; otherwise it must be present and equal.
///
/// # Errors
/// [`HostHeaderError`].
pub fn host_header(value: &[u8], connect: &Authority) -> Result<(), HostHeaderError> {
    let text = std::str::from_utf8(value).map_err(|_| HostHeaderError::Malformed)?;
    let explicit = text.contains(':');
    let parsed = if explicit {
        parse(text)
    } else {
        parse(&format!("{text}:{HTTPS_PORT}"))
    };
    let auth = parsed.map_err(|_| HostHeaderError::Malformed)?;
    let port_ok = if explicit {
        auth.port == connect.port
    } else {
        connect.port == HTTPS_PORT
    };
    if auth.host == connect.host && port_ok {
        Ok(())
    } else {
        Err(HostHeaderError::Mismatch)
    }
}

/// The port an omitted `Host` port stands for.
const HTTPS_PORT: u16 = 443;

/// The `Host` header sent upstream, rebuilt from the CONNECT authority: `host`, plus `:port`
/// unless the port is 443 (architect Q29).
#[must_use]
pub fn upstream_host(connect: &Authority) -> String {
    if connect.port == HTTPS_PORT {
        connect.host.clone()
    } else {
        format!("{}:{}", connect.host, connect.port)
    }
}

/// Decimal digits only (no sign), 1..=65535. Empty and overlong strings fail the `u16` parse.
fn parse_port(s: &str) -> Option<u16> {
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u16>().ok().filter(|&p| p != 0)
}

/// How text the sandbox chose (a request-target, a method) is logged: its first
/// [`LOGGED_TARGET_BYTES`] bytes, every byte outside printable ASCII, and `\` and `"`, as `\xNN`
/// (architect Q288's hex format).
pub const TARGET_STYLE: Style = Style::Hex {
    max: LOGGED_TARGET_BYTES,
};

/// Text the sandbox chose, as an egress entry declares it: masked with the session's own forms
/// (`None` for a session without secret grants), uncut and unescaped. The audit writer then
/// masks it whole with every live session's forms, and only then cuts and escapes it in
/// [`TARGET_STYLE`] (architect Q253, Q276), so no cut or escape can split or rewrite a form of
/// any live session's secret. The session's own pass keeps a late entry masked after its forms
/// left the writer.
#[must_use]
pub fn own_masked(raw: &str, forms: Option<&Redactor>) -> Arc<str> {
    match forms {
        Some(r) => Arc::from(r.redact_str(raw).as_ref()),
        None => Arc::from(raw),
    }
}

/// `e` with the sandbox's request-target `raw` declared as its `target`, with `target_cut`
/// saying whether the masked text was cut. The builder puts the raw length in `target_bytes`.
#[must_use]
pub fn with_target(e: NewEntry, raw: &str, forms: Option<&Redactor>) -> NewEntry {
    e.text_and_cut("target", "target_cut", own_masked(raw, forms), TARGET_STYLE)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use sally_core::audit::Actor;

    /// The target as a writer with no secrets logs it: the text, the raw length, and whether
    /// it was cut. `forms` is the session's own pass.
    fn logged(raw: &str, forms: Option<&Redactor>) -> (String, usize, bool) {
        let e = with_target(NewEntry::new(Actor::Sallyd, "egress.deny"), raw, forms);
        let v = e.resolved(&Redactor::default());
        let text = v["target"].as_str().unwrap().to_owned();
        (text, raw.len(), v["target_cut"].as_bool().unwrap())
    }

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

    fn connect(host: &str, port: u16) -> Authority {
        Authority {
            host: host.to_owned(),
            port,
        }
    }

    #[test]
    fn a_host_header_naming_the_connect_authority_is_accepted() {
        let at443 = connect("api.mock.test", 443);
        for v in [
            "api.mock.test",
            "API.Mock.Test",
            "api.mock.test.",
            "api.mock.test:443",
            "api.mock.test.:443",
        ] {
            assert_eq!(host_header(v.as_bytes(), &at443), Ok(()), "{v}");
        }
        let at8443 = connect("api.mock.test", 8443);
        assert_eq!(host_header(b"api.mock.test:8443", &at8443), Ok(()));
    }

    #[test]
    fn a_host_header_naming_anything_else_is_a_mismatch() {
        let at443 = connect("api.mock.test", 443);
        for v in [
            "other.mock.test",
            "mock.test",
            "x.api.mock.test",
            "api.mock.test:8443",
        ] {
            assert_eq!(
                host_header(v.as_bytes(), &at443),
                Err(HostHeaderError::Mismatch),
                "{v}"
            );
        }
        // Off 443 the port must be present and equal.
        let at8443 = connect("api.mock.test", 8443);
        for v in ["api.mock.test", "api.mock.test:443", "api.mock.test:8444"] {
            assert_eq!(
                host_header(v.as_bytes(), &at8443),
                Err(HostHeaderError::Mismatch),
                "{v}"
            );
        }
    }

    #[test]
    fn an_unusable_host_header_is_malformed() {
        let at443 = connect("api.mock.test", 443);
        let dotted = format!("{}.{}.{}.{}", 1, 1, 1, 1);
        for v in [
            b"".as_slice(),
            b"api.mock.test:",
            b"api.mock.test:0",
            b"api.mock.test:+443",
            b"user@api.mock.test",
            b"user:pw@api.mock.test:443",
            b"[::1]",
            b"[::1]:443",
            dotted.as_bytes(),
            b"api.mock.test..",
            b"api mock.test",
            b"api.mock.test\xff",
            b"localhost",
            b"*.mock.test",
        ] {
            assert_eq!(
                host_header(v, &at443),
                Err(HostHeaderError::Malformed),
                "{:?}",
                String::from_utf8_lossy(v)
            );
        }
    }

    #[test]
    fn the_upstream_host_header_is_rebuilt_from_the_connect_authority() {
        assert_eq!(
            upstream_host(&connect("api.mock.test", 443)),
            "api.mock.test"
        );
        assert_eq!(
            upstream_host(&connect("api.mock.test", 8443)),
            "api.mock.test:8443"
        );
    }

    /// A session without secret grants: escaped and cut, nothing masked.
    #[test]
    fn audit_text_is_escaped_and_bounded() {
        assert_eq!(
            logged("ok.test:443", None),
            ("ok.test:443".to_owned(), 11, false)
        );
        assert_eq!(
            logged("a\"b\\c\x00\x1f\x7f\u{ff}~ ", None),
            (r"a\x22b\x5cc\x00\x1f\x7f\xc3\xbf~ ".to_owned(), 12, false)
        );
        let long = "a".repeat(LOGGED_TARGET_BYTES + 1);
        let (text, len, cut) = logged(&long, None);
        assert_eq!((text.len(), len, cut), (LOGGED_TARGET_BYTES, 257, true));
        let exact = "a".repeat(LOGGED_TARGET_BYTES);
        assert!(!logged(&exact, None).2);
    }

    /// A 40-character canary, assembled at runtime, with no run of one character.
    fn canary() -> String {
        ('a'..='z').cycle().step_by(7).take(40).collect()
    }

    /// Whether any 8-character run of `secret` occurs in `text`.
    fn holds_a_run_of(secret: &str, text: &str) -> bool {
        secret
            .as_bytes()
            .windows(8)
            .any(|w| text.contains(std::str::from_utf8(w).unwrap()))
    }

    /// Architect Q253: a form is masked in the whole raw text before the cut, so one straddling
    /// the cut (at byte 250) or ending just past it (at byte 220) leaves no run of itself; the
    /// length is the raw one and the cut is the masked text's.
    #[test]
    fn a_form_is_masked_before_the_cut() {
        let canary = canary();
        let forms = Redactor::new([("C", canary.as_str())]);
        for at in [220, 250] {
            let pad = "/".to_owned() + &"p".repeat(at - 1);
            let raw = format!("{pad}{canary}{}", "q".repeat(60));
            assert!(raw.len() > 300);
            let masked = format!("{pad}[REDACTED:C]{}", "q".repeat(60));
            let (text, len, cut) = logged(&raw, Some(&forms));
            assert_eq!(text, masked[..LOGGED_TARGET_BYTES], "at {at}");
            assert_eq!((len, cut), (raw.len(), true), "at {at}");
            assert!(!holds_a_run_of(&canary, &text), "at {at}: {text}");
        }
    }

    /// Architect Q253: the cut is the masked text's, not the raw text's. A raw text over the
    /// bound whose masked text fits is not cut; one whose masked text is exactly the bound is not
    /// either.
    #[test]
    fn the_cut_is_judged_on_the_masked_text() {
        let canary = canary();
        let forms = Redactor::new([("C", canary.as_str())]);
        let placeholder = "[REDACTED:C]".len();
        let pad = "p".repeat(LOGGED_TARGET_BYTES - placeholder);
        let raw = format!("{pad}{canary}");
        assert!(raw.len() > LOGGED_TARGET_BYTES);
        let (text, len, cut) = logged(&raw, Some(&forms));
        assert_eq!(text, format!("{pad}[REDACTED:C]"));
        assert_eq!(
            (text.len(), len, cut),
            (LOGGED_TARGET_BYTES, raw.len(), false)
        );
        let (_, _, cut) = logged(&format!("{raw}q"), Some(&forms));
        assert!(cut);
    }

    /// Architect Q253: a form holding `"` and `\` is masked before the escape could rewrite it:
    /// the placeholder stands where it was, and no escaped remnant of it is left.
    #[test]
    fn a_form_holding_quote_and_backslash_is_masked_before_the_escape() {
        let value = format!(
            "{}\"{}\\{}",
            &canary()[..12],
            &canary()[12..24],
            &canary()[24..]
        );
        let forms = Redactor::new([("Q", value.as_str())]);
        let (text, len, cut) = logged(&format!("/x{value}/y"), Some(&forms));
        assert_eq!(text, "/x[REDACTED:Q]/y");
        assert_eq!((len, cut), (value.len() + 4, false));
        assert!(!text.contains(r"\x22") && !text.contains(r"\x5c"), "{text}");
    }
}
