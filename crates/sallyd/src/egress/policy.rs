//! The session's egress policy and the reasons a request is refused. Pure: the decision reads
//! only the normalized authority, never a header (SI-9).
//!
//! Order (maintainer's Task 8 decision 3, architect ruling Q1): host rule, then port, then the
//! secret-grant check; resolution and the address filter come after, so a denied name is never
//! resolved.

use sally_core::manifest::{HostPattern, ValidatedManifest, parse_hostname};

use super::authority::Authority;

/// Why the proxy refused or ended a request. The wire form ([`Reason::as_str`]) is kebab-case and
/// appears in the audit entry and the reply body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// No allow rule matches the host.
    HostNotAllowed,
    /// A rule matches the host, but none of the matching rules lists the port.
    PortNotAllowed,
    /// The target host is an IP address.
    IpLiteral,
    /// A resolved address is not global unicast, or belongs to this host.
    IpRangeDenied,
    /// The name did not resolve (or not in time).
    ResolveFailed,
    /// Every pinned address refused the connection or did not answer in time.
    ConnectFailed,
    /// Not a CONNECT request (v1 has no plain-HTTP forwarding).
    PlainHttpUnsupported,
    /// The host has a secret grant, but the proxy holds no session CA leaf for it, so it can be
    /// neither intercepted nor (ever) spliced (architect Q39: fail closed).
    GrantHostUnavailable,
    /// The session's `network.max_connections` is reached.
    TooManyConnections,
    /// The request head is over 8 KiB or has too many header lines.
    HeadTooLarge,
    /// The request head did not arrive in time.
    HeadTimeout,
    /// Not a usable request.
    Malformed,
    /// In an intercepted tunnel: the `Host` header names another authority (architect Q29).
    HostMismatch,
    /// In an intercepted tunnel: the request asks for a protocol upgrade (decision 5).
    UpgradeRefused,
    /// In an intercepted tunnel: the method is `TRACE`, which would echo the request back
    /// (architect ruling R6, 9a-2 review).
    MethodRefused,
    /// In an intercepted tunnel: the request body is over `network.max_request_bytes`.
    RequestTooLarge,
    /// In an intercepted tunnel: the response body is over `network.max_response_bytes`, or its
    /// head over 64 KiB or 100 headers.
    ResponseTooLarge,
    /// In an intercepted tunnel: the response is compressed, framed other than plain chunked, or
    /// an upgrade (architect Q30).
    UpstreamEncoded,
    /// The upstream TLS handshake or its certificate verification failed (architect Q28).
    UpstreamTlsFailed,
    /// The upstream closed before it sent a response head (architect Q43).
    UpstreamClosed,
    /// The upstream's response head is not HTTP/1.x (architect Q45).
    UpstreamMalformed,
    /// A form of a session secret reaches into a response header's name, or its redacted value
    /// is no header value (Task 9a-3, architect D5): nothing is forwarded.
    UpstreamEchoedSecret,
}

impl Reason {
    /// Every reason, in declaration order.
    pub const ALL: [Self; 22] = [
        Self::HostNotAllowed,
        Self::PortNotAllowed,
        Self::IpLiteral,
        Self::IpRangeDenied,
        Self::ResolveFailed,
        Self::ConnectFailed,
        Self::PlainHttpUnsupported,
        Self::GrantHostUnavailable,
        Self::TooManyConnections,
        Self::HeadTooLarge,
        Self::HeadTimeout,
        Self::Malformed,
        Self::HostMismatch,
        Self::UpgradeRefused,
        Self::MethodRefused,
        Self::RequestTooLarge,
        Self::ResponseTooLarge,
        Self::UpstreamEncoded,
        Self::UpstreamTlsFailed,
        Self::UpstreamClosed,
        Self::UpstreamMalformed,
        Self::UpstreamEchoedSecret,
    ];

    /// The reason whose [`Self::as_str`] form is `code`, if any (the `fetch` tool reads the
    /// proxy's refusal back with it; architect ruling Q5).
    #[must_use]
    pub fn from_code(code: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.as_str() == code)
    }

    /// The audit and reply form.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HostNotAllowed => "host-not-allowed",
            Self::PortNotAllowed => "port-not-allowed",
            Self::IpLiteral => "ip-literal",
            Self::IpRangeDenied => "ip-range-denied",
            Self::ResolveFailed => "resolve-failed",
            Self::ConnectFailed => "connect-failed",
            Self::PlainHttpUnsupported => "plain-http-unsupported",
            Self::GrantHostUnavailable => "grant-host-unavailable",
            Self::TooManyConnections => "too-many-connections",
            Self::HeadTooLarge => "head-too-large",
            Self::HeadTimeout => "head-timeout",
            Self::Malformed => "malformed",
            Self::HostMismatch => "host-mismatch",
            Self::UpgradeRefused => "upgrade-refused",
            Self::MethodRefused => "method-refused",
            Self::RequestTooLarge => "request-too-large",
            Self::ResponseTooLarge => "response-too-large",
            Self::UpstreamEncoded => "upstream-encoded",
            Self::UpstreamTlsFailed => "upstream-tls-failed",
            Self::UpstreamClosed => "upstream-closed",
            Self::UpstreamMalformed => "upstream-malformed",
            Self::UpstreamEchoedSecret => "upstream-echoed-secret",
        }
    }

    /// The HTTP status the client gets. `head-timeout` closes without a reply, so its status is
    /// never sent; 408 is what it would be.
    #[must_use]
    pub fn status(self) -> u16 {
        match self {
            Self::HostNotAllowed
            | Self::PortNotAllowed
            | Self::IpLiteral
            | Self::IpRangeDenied
            | Self::GrantHostUnavailable
            | Self::UpgradeRefused => 403,
            Self::ResolveFailed
            | Self::ConnectFailed
            | Self::ResponseTooLarge
            | Self::UpstreamEncoded
            | Self::UpstreamTlsFailed
            | Self::UpstreamClosed
            | Self::UpstreamMalformed
            | Self::UpstreamEchoedSecret => 502,
            Self::PlainHttpUnsupported | Self::MethodRefused => 405,
            Self::TooManyConnections => 429,
            Self::HeadTooLarge => 431,
            Self::HeadTimeout => 408,
            Self::Malformed => 400,
            Self::HostMismatch => 421,
            Self::RequestTooLarge => 413,
        }
    }

    /// Whether this is a resource limit (`egress.limit`) rather than a policy denial
    /// (`egress.deny`).
    #[must_use]
    pub fn is_limit(self) -> bool {
        matches!(
            self,
            Self::TooManyConnections
                | Self::HeadTooLarge
                | Self::HeadTimeout
                | Self::RequestTooLarge
                | Self::ResponseTooLarge
        )
    }
}

/// Where an allowed request goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// A host without a secret grant: the tunnel is spliced untouched (Task 8).
    Splice,
    /// A grant host: TLS is terminated with the session CA's leaf (Task 9a-2).
    Intercept,
}

/// One secret grant as the proxy sees it: the host and the header name, never the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// The normalized injection host.
    pub host: String,
    /// The header the secret is injected into, as the manifest spells it.
    pub header: String,
}

/// One allow rule: a host pattern and its ports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// Host pattern (sally-core's matcher).
    pub host: HostPattern,
    /// Allowed ports.
    pub ports: Vec<u16>,
}

/// One session's egress policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    rules: Vec<Rule>,
    grants: Vec<Grant>,
}

impl Policy {
    /// A policy from the session's allow rules and its secret grants (hosts and header names).
    #[must_use]
    pub fn new(rules: Vec<Rule>, grants: Vec<Grant>) -> Self {
        Self { rules, grants }
    }

    /// The policy of a validated manifest: its `network.allow` rules and the injection host and
    /// header of every secret grant. The validator already checked both; an injection host that
    /// is not a hostname cannot match a normalized authority and is left out.
    #[must_use]
    pub fn from_manifest(v: &ValidatedManifest) -> Self {
        let rules = v
            .egress()
            .iter()
            .map(|r| Rule {
                host: r.host.clone(),
                ports: r.ports.clone(),
            })
            .collect();
        let grants = v
            .manifest()
            .secrets
            .iter()
            .filter_map(|s| {
                parse_hostname(&s.inject.host).ok().map(|host| Grant {
                    host,
                    header: s.inject.header.clone(),
                })
            })
            .collect();
        Self::new(rules, grants)
    }

    /// The injection hosts of the session's secret grants, normalized, in manifest order (a host
    /// may repeat).
    #[must_use]
    pub fn grant_hosts(&self) -> Vec<String> {
        self.grants.iter().map(|g| g.host.clone()).collect()
    }

    /// The header names of every grant of `host`, lower-cased, each once, in manifest order:
    /// every client copy of them is dropped inside the tunnel (architect Q40).
    #[must_use]
    pub fn grant_headers(&self, host: &str) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for g in self.grants.iter().filter(|g| g.host == host) {
            let name = g.header.to_ascii_lowercase();
            if !out.contains(&name) {
                out.push(name);
            }
        }
        out
    }

    /// Decides on `a` before anything is resolved: refused, or the route it takes. A grant host
    /// is intercepted on every allowed port, whichever rule matched, and never spliced.
    ///
    /// # Errors
    /// [`Reason::HostNotAllowed`] or [`Reason::PortNotAllowed`].
    pub fn decide(&self, a: &Authority) -> Result<Route, Reason> {
        let mut matching = self
            .rules
            .iter()
            .filter(|r| r.host.matches(&a.host))
            .peekable();
        if matching.peek().is_none() {
            return Err(Reason::HostNotAllowed);
        }
        if !matching.any(|r| r.ports.contains(&a.port)) {
            return Err(Reason::PortNotAllowed);
        }
        if self.grants.iter().any(|g| g.host == a.host) {
            return Ok(Route::Intercept);
        }
        Ok(Route::Splice)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use sally_core::manifest::parse_host_pattern;

    fn rule(host: &str, ports: &[u16]) -> Rule {
        Rule {
            host: parse_host_pattern(host).unwrap(),
            ports: ports.to_vec(),
        }
    }

    fn at(host: &str, port: u16) -> Authority {
        Authority {
            host: host.to_owned(),
            port,
        }
    }

    #[test]
    fn wildcard_rules_match_on_label_boundaries_only() {
        let p = Policy::new(vec![rule("*.mock.test", &[443])], vec![]);
        assert_eq!(p.decide(&at("a.mock.test", 443)), Ok(Route::Splice));
        assert_eq!(p.decide(&at("b.a.mock.test", 443)), Ok(Route::Splice));
        for denied in ["mock.test", "mock.test.evil.test", "xmock.test"] {
            assert_eq!(
                p.decide(&at(denied, 443)),
                Err(Reason::HostNotAllowed),
                "{denied}"
            );
        }
    }

    #[test]
    fn the_port_is_checked_against_every_rule_that_matches_the_host() {
        let p = Policy::new(
            vec![rule("a.mock.test", &[443]), rule("*.mock.test", &[8443])],
            vec![],
        );
        assert_eq!(p.decide(&at("a.mock.test", 443)), Ok(Route::Splice));
        assert_eq!(p.decide(&at("a.mock.test", 8443)), Ok(Route::Splice));
        assert_eq!(
            p.decide(&at("a.mock.test", 22)),
            Err(Reason::PortNotAllowed)
        );
        assert_eq!(
            p.decide(&at("b.mock.test", 443)),
            Err(Reason::PortNotAllowed)
        );
        assert_eq!(
            p.decide(&at("evil.example", 443)),
            Err(Reason::HostNotAllowed)
        );
    }

    fn grant(host: &str, header: &str) -> Grant {
        Grant {
            host: host.to_owned(),
            header: header.to_owned(),
        }
    }

    #[test]
    fn grant_hosts_are_intercepted_after_host_and_port_whichever_rule_matched() {
        let grants = vec![grant("api.mock.test", "authorization")];
        let exact = Policy::new(vec![rule("api.mock.test", &[443, 8443])], grants.clone());
        assert_eq!(
            exact.decide(&at("api.mock.test", 443)),
            Ok(Route::Intercept)
        );
        assert_eq!(
            exact.decide(&at("api.mock.test", 8443)),
            Ok(Route::Intercept)
        );
        assert_eq!(
            exact.decide(&at("api.mock.test", 22)),
            Err(Reason::PortNotAllowed)
        );
        let any = Policy::new(vec![rule("*", &[443])], grants);
        assert_eq!(any.decide(&at("api.mock.test", 443)), Ok(Route::Intercept));
        assert_eq!(any.decide(&at("www.mock.test", 443)), Ok(Route::Splice));
        assert_eq!(any.decide(&at("x.api.mock.test", 443)), Ok(Route::Splice));
    }

    #[test]
    fn the_headers_to_drop_are_every_grant_header_of_that_host_lower_cased() {
        let p = Policy::new(
            vec![rule("*", &[443])],
            vec![
                grant("api.mock.test", "Authorization"),
                grant("api.mock.test", "X-Api-Key"),
                grant("api.mock.test", "authorization"),
                grant("other.mock.test", "X-Other"),
            ],
        );
        assert_eq!(
            p.grant_headers("api.mock.test"),
            ["authorization", "x-api-key"]
        );
        assert_eq!(p.grant_headers("other.mock.test"), ["x-other"]);
        assert!(p.grant_headers("www.mock.test").is_empty());
        assert_eq!(
            p.grant_hosts(),
            [
                "api.mock.test",
                "api.mock.test",
                "api.mock.test",
                "other.mock.test"
            ]
        );
    }

    #[test]
    fn a_manifest_gives_its_rules_and_grant_hosts() {
        use sally_core::manifest::{HostEnv, load};
        let env = HostEnv {
            home: "/nonexistent/home".into(),
            other_homes: Vec::new(),
            xdg_config_home: None,
            xdg_data_home: None,
            xdg_runtime_dir: None,
            podman_storage: Vec::new(),
            nproc: 8,
            mem_bytes: 16 << 30,
        };
        let body = "apiVersion: sallyport/v1\nkind: Manifest\nname: t\nmodel:\n  ref: any\n\
                    network:\n  mode: proxy\n  allow:\n    - host: api.mock.test\n    \
                    - host: \"*.mock.test\"\n      ports: [443, 8443]\n\
                    secrets:\n  - name: GITHUB_TOKEN\n    inject:\n      host: api.mock.test\n      \
                    header: Authorization\n      format: \"Bearer {value}\"\n";
        let names: std::collections::BTreeSet<String> =
            ["GITHUB_TOKEN".to_owned()].into_iter().collect();
        let v = load(body, &env, &names).unwrap().manifest;
        let p = Policy::from_manifest(&v);
        assert_eq!(
            p,
            Policy::new(
                vec![
                    rule("api.mock.test", &[443]),
                    rule("*.mock.test", &[443, 8443])
                ],
                vec![grant("api.mock.test", "Authorization")],
            )
        );
    }

    #[test]
    fn an_empty_policy_allows_nothing() {
        let p = Policy::new(vec![], vec![]);
        assert_eq!(p.decide(&at("mock.test", 443)), Err(Reason::HostNotAllowed));
    }

    #[test]
    fn hosts_without_a_grant_are_spliced() {
        let p = Policy::new(vec![rule("*.mock.test", &[443])], vec![]);
        assert_eq!(p.decide(&at("a.mock.test", 443)), Ok(Route::Splice));
    }

    #[test]
    fn every_reason_is_listed_once_and_read_back_from_its_code() {
        for (i, r) in Reason::ALL.into_iter().enumerate() {
            assert_eq!(Reason::from_code(r.as_str()), Some(r));
            assert!(!Reason::ALL[..i].contains(&r), "{r:?} listed twice");
        }
        for other in ["", "Host-Not-Allowed", "host-not-allowed\n", "ok"] {
            assert_eq!(Reason::from_code(other), None, "{other:?}");
        }
    }

    #[test]
    fn reasons_have_their_wire_form_status_and_event() {
        use Reason::*;
        let table = [
            (HostNotAllowed, "host-not-allowed", 403, false),
            (PortNotAllowed, "port-not-allowed", 403, false),
            (IpLiteral, "ip-literal", 403, false),
            (IpRangeDenied, "ip-range-denied", 403, false),
            (ResolveFailed, "resolve-failed", 502, false),
            (ConnectFailed, "connect-failed", 502, false),
            (PlainHttpUnsupported, "plain-http-unsupported", 405, false),
            (GrantHostUnavailable, "grant-host-unavailable", 403, false),
            (TooManyConnections, "too-many-connections", 429, true),
            (HeadTooLarge, "head-too-large", 431, true),
            (HeadTimeout, "head-timeout", 408, true),
            (Malformed, "malformed", 400, false),
            (HostMismatch, "host-mismatch", 421, false),
            (UpgradeRefused, "upgrade-refused", 403, false),
            (MethodRefused, "method-refused", 405, false),
            (RequestTooLarge, "request-too-large", 413, true),
            (ResponseTooLarge, "response-too-large", 502, true),
            (UpstreamEncoded, "upstream-encoded", 502, false),
            (UpstreamTlsFailed, "upstream-tls-failed", 502, false),
            (UpstreamClosed, "upstream-closed", 502, false),
            (UpstreamMalformed, "upstream-malformed", 502, false),
            (UpstreamEchoedSecret, "upstream-echoed-secret", 502, false),
        ];
        for (r, s, status, limit) in table {
            assert_eq!((r.as_str(), r.status(), r.is_limit()), (s, status, limit));
        }
    }
}
