//! The `[data-can-leave]` finding (AMENDMENTS-01 §5, Agents Rule of Two).
//!
//! The model and everything it reads are untrusted input. When a manifest grants both private
//! data (any mount or secret) and an outward channel (any allow rule), whatever the agent reads
//! can be sent to any allowed host. The finding names both sides in plain words. It is a warning,
//! not an error, and has no acknowledge flag: it is the normal shape of a useful agent, so the
//! point is that the user sees it, every time.

use std::collections::{BTreeMap, BTreeSet};

use super::super::host::HostPattern;
use super::super::types::{Manifest, NetworkMode};
use super::{EgressRule, ResolvedMount};

/// The finding's sentence, or `None` when private data and an outward channel do not coexist.
/// `egress` must already be empty when `network.mode` is `none`.
pub(crate) fn data_can_leave(
    m: &Manifest,
    mounts: &[ResolvedMount],
    egress: &[EgressRule],
) -> Option<String> {
    if m.network.mode == NetworkMode::None || egress.is_empty() {
        return None;
    }
    let readable = readable(m, mounts);
    if readable.is_empty() {
        return None;
    }
    let grant_hosts: BTreeSet<&str> = m.secrets.iter().map(|s| s.inject.host.as_str()).collect();
    let destinations: Vec<String> = egress
        .iter()
        .map(|r| destination(&r.host, &grant_hosts))
        .collect();
    Some(format!(
        "Anything this agent reads — {} — can be sent to {}.",
        join(&readable),
        join(&destinations)
    ))
}

/// Mount realpaths, then what each secret unlocks (one entry per secret, all its hosts).
fn readable(m: &Manifest, mounts: &[ResolvedMount]) -> Vec<String> {
    let mut out: Vec<String> = mounts
        .iter()
        .map(|mt| mt.host.display().to_string())
        .collect();
    let mut by_secret: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for s in &m.secrets {
        by_secret
            .entry(s.name.as_str())
            .or_default()
            .insert(s.inject.host.as_str());
    }
    out.extend(by_secret.into_iter().map(|(name, hosts)| {
        let hosts: Vec<&str> = hosts.into_iter().collect();
        format!("whatever your {name} unlocks on {}", hosts.join(" or "))
    }));
    out
}

fn destination(host: &HostPattern, grant_hosts: &BTreeSet<&str>) -> String {
    match host {
        HostPattern::Any => "any public hostname".to_owned(),
        h if h.is_effectively_unrestricted() => format!("{h} (anyone can register these)"),
        HostPattern::Exact(name) if grant_hosts.contains(name.as_str()) => {
            format!("{name} (acting as you)")
        }
        h => h.to_string(),
    }
}

/// `a`, `a and b`, `a, b and c`.
fn join(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    }
}

#[cfg(test)]
mod tests {
    use super::join;

    #[test]
    fn join_reads_like_english() {
        let v = |xs: &[&str]| xs.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert_eq!(join(&v(&[])), "");
        assert_eq!(join(&v(&["a"])), "a");
        assert_eq!(join(&v(&["a", "b"])), "a and b");
        assert_eq!(join(&v(&["a", "b", "c"])), "a, b and c");
    }
}
