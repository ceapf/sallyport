//! `network.*` checks.

use std::collections::HashSet;

use super::super::diag::{Code, Diags};
use super::super::host::{HostError, HostPattern, parse_host_pattern};
use super::super::types::{HostRule, Network, NetworkMode};
use super::super::units::ByteSize;
use super::EgressRule;
use super::rest::in_range;

const MAX_RULES: usize = 256;
const MAX_CONNECTIONS: u32 = 1024;

pub(super) fn host_error(d: &mut Diags, path: String, raw: &str, e: HostError) {
    match e {
        HostError::IpLiteral => d.error(
            path,
            Code::IpLiteral,
            format!("{raw:?} is an IP literal; only hostnames are allowed"),
        ),
        HostError::Wildcard => d.error(
            path,
            Code::NotExactHost,
            format!("{raw:?}: host must be exact (no wildcards)"),
        ),
        HostError::Invalid(why) => d.error(path, Code::BadHost, format!("{raw:?}: {why}")),
    }
}

/// Returns parsed rules (even with `mode: none`, so secrets can be checked against them).
pub(super) fn check_network(n: &Network, d: &mut Diags) -> Vec<EgressRule> {
    if n.allow.len() > MAX_RULES {
        d.error(
            "network.allow",
            Code::OutOfRange,
            format!("at most {MAX_RULES} rules"),
        );
        return Vec::new();
    }
    let mut rules: Vec<EgressRule> = Vec::new();
    // Indices of rules that reach any attacker-registrable host: "*" or a shared suffix.
    let mut unrestricted: Vec<usize> = Vec::new();
    for (i, rule) in n.allow.iter().enumerate() {
        let Some(host) = check_rule(rule, i, &rules, d) else {
            continue;
        };
        if host.is_effectively_unrestricted() {
            unrestricted.push(i);
        }
        rules.push(EgressRule {
            host,
            ports: rule.ports.clone(),
        });
    }
    check_acknowledgement(n, &unrestricted, d);
    if n.mode == NetworkMode::None && !n.allow.is_empty() {
        d.warn(
            "network.allow",
            Code::Inconsistent,
            "ignored because network.mode is none",
        );
    }
    check_limits(n, d);
    rules
}

fn check_rule(
    rule: &HostRule,
    i: usize,
    earlier: &[EgressRule],
    d: &mut Diags,
) -> Option<HostPattern> {
    let path = format!("network.allow[{i}].host");
    let host = match parse_host_pattern(&rule.host) {
        Ok(h) => h,
        Err(e) => {
            host_error(d, path, &rule.host, e);
            return None;
        }
    };
    if earlier.iter().any(|r| r.host == host) {
        d.error(
            path,
            Code::Duplicate,
            format!("{:?} is listed twice", rule.host),
        );
    }
    check_ports(&rule.ports, i, d);
    Some(host)
}

fn check_acknowledgement(n: &Network, unrestricted: &[usize], d: &mut Diags) {
    match (unrestricted, n.acknowledge_unrestricted_egress) {
        ([], false) => {}
        ([], true) => d.warn(
            "network.acknowledge_unrestricted_egress",
            Code::Inconsistent,
            "set but no rule is unrestricted",
        ),
        (indices, false) => {
            for &i in indices {
                let host = n.allow.get(i).map_or("", |r| r.host.as_str());
                let what = if host == "*" {
                    "\"*\"".to_owned()
                } else {
                    format!("{host:?} covers hosts anyone can register, so it")
                };
                d.error(
                    format!("network.allow[{i}].host"),
                    Code::UnacknowledgedWildcard,
                    format!("{what} requires network.acknowledge_unrestricted_egress: true"),
                );
            }
        }
        (_, true) => d.warn(
            "network.allow",
            Code::Risky,
            "unrestricted egress: the agent can send anything it reads to any public host",
        ),
    }
}

fn check_limits(n: &Network, d: &mut Diags) {
    let bytes = |x| ByteSize::from_bytes(x).to_string();
    let req = n.max_request_bytes.bytes();
    in_range(
        d,
        "network.max_request_bytes",
        req,
        ByteSize::KIB,
        ByteSize::GIB,
        bytes,
    );
    let resp = n.max_response_bytes.bytes();
    in_range(
        d,
        "network.max_response_bytes",
        resp,
        ByteSize::KIB,
        16 * ByteSize::GIB,
        bytes,
    );
    let conns = n.max_connections;
    in_range(
        d,
        "network.max_connections",
        conns,
        1,
        MAX_CONNECTIONS,
        |x| x.to_string(),
    );
}

fn check_ports(ports: &[u16], i: usize, d: &mut Diags) {
    let path = format!("network.allow[{i}].ports");
    if ports.is_empty() {
        d.error(path, Code::InvalidValue, "at least one port is required");
        return;
    }
    let mut seen = HashSet::new();
    for (j, p) in ports.iter().enumerate() {
        if *p == 0 {
            d.error(
                format!("{path}[{j}]"),
                Code::OutOfRange,
                "port 0 is not a port",
            );
        } else if !seen.insert(p) {
            d.error(
                format!("{path}[{j}]"),
                Code::Duplicate,
                format!("port {p} is listed twice"),
            );
        }
    }
}
