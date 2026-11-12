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
    /// The host has a secret grant; served only once the token proxy exists (Task 9a).
    GrantHostUnavailable,
    /// The session's `network.max_connections` is reached.
    TooManyConnections,
    /// The request head is over 8 KiB or has too many header lines.
    HeadTooLarge,
    /// The request head did not arrive in time.
    HeadTimeout,
    /// Not a usable request.
    Malformed,
}

impl Reason {
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
            | Self::GrantHostUnavailable => 403,
            Self::ResolveFailed | Self::ConnectFailed => 502,
            Self::PlainHttpUnsupported => 405,
            Self::TooManyConnections => 429,
            Self::HeadTooLarge => 431,
            Self::HeadTimeout => 408,
            Self::Malformed => 400,
        }
    }

    /// Whether this is a resource limit (`egress.limit`) rather than a policy denial
    /// (`egress.deny`).
    #[must_use]
    pub fn is_limit(self) -> bool {
        matches!(
            self,
            Self::TooManyConnections | Self::HeadTooLarge | Self::HeadTimeout
        )
    }
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
    grant_hosts: Vec<String>,
}

impl Policy {
    /// A policy from the session's allow rules and the hosts its secrets are injected into.
    #[must_use]
    pub fn new(rules: Vec<Rule>, grant_hosts: Vec<String>) -> Self {
        Self { rules, grant_hosts }
    }

    /// The policy of a validated manifest: its `network.allow` rules and the injection host of
    /// every secret grant. The validator already checked both; an injection host that is not a
    /// hostname cannot match a normalized authority and is left out.
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
        let grant_hosts = v
            .manifest()
            .secrets
            .iter()
            .filter_map(|s| parse_hostname(&s.inject.host).ok())
            .collect();
        Self::new(rules, grant_hosts)
    }

    /// The injection hosts of the session's secret grants, normalized, in manifest order (a host
    /// may repeat).
    #[must_use]
    pub fn grant_hosts(&self) -> &[String] {
        &self.grant_hosts
    }

    /// Decides on `a` before anything is resolved.
    ///
    /// # Errors
    /// [`Reason::HostNotAllowed`], [`Reason::PortNotAllowed`] or
    /// [`Reason::GrantHostUnavailable`].
    pub fn decide(&self, a: &Authority) -> Result<(), Reason> {
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
        // TODO(#45): Task 9a serves grant hosts through the token proxy. Until then they are
        // refused, whichever rule matched, and never spliced.
        if self.grant_hosts.contains(&a.host) {
            return Err(Reason::GrantHostUnavailable);
        }
        Ok(())
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
        assert_eq!(p.decide(&at("a.mock.test", 443)), Ok(()));
        assert_eq!(p.decide(&at("b.a.mock.test", 443)), Ok(()));
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
        assert_eq!(p.decide(&at("a.mock.test", 443)), Ok(()));
        assert_eq!(p.decide(&at("a.mock.test", 8443)), Ok(()));
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

    #[test]
    fn grant_hosts_are_refused_after_host_and_port_whichever_rule_matched() {
        let grants = vec!["api.mock.test".to_owned()];
        let exact = Policy::new(vec![rule("api.mock.test", &[443])], grants.clone());
        assert_eq!(
            exact.decide(&at("api.mock.test", 443)),
            Err(Reason::GrantHostUnavailable)
        );
        assert_eq!(
            exact.decide(&at("api.mock.test", 22)),
            Err(Reason::PortNotAllowed)
        );
        let any = Policy::new(vec![rule("*", &[443])], grants);
        assert_eq!(
            any.decide(&at("api.mock.test", 443)),
            Err(Reason::GrantHostUnavailable)
        );
        assert_eq!(any.decide(&at("www.mock.test", 443)), Ok(()));
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
                vec!["api.mock.test".to_owned()],
            )
        );
    }

    #[test]
    fn an_empty_policy_allows_nothing() {
        let p = Policy::new(vec![], vec![]);
        assert_eq!(p.decide(&at("mock.test", 443)), Err(Reason::HostNotAllowed));
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
        ];
        for (r, s, status, limit) in table {
            assert_eq!((r.as_str(), r.status(), r.is_limit()), (s, status, limit));
        }
    }
}
