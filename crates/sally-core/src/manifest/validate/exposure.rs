//! The `[data-can-leave]` finding (AMENDMENTS-01 §5, Agents Rule of Two).
//!
//! The model and everything it reads are untrusted input. When a manifest grants both private
//! data (any mount or secret) and an outward channel (any allow rule), whatever the agent reads
//! can be sent to any allowed host. The finding names both sides in plain words. It is a warning,
//! not an error, and has no acknowledge flag: it is the normal shape of a useful agent, so the
//! point is that the user sees it, every time.

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::ffi::OsStrExt as _;

use super::super::host::{HostPattern, parse_hostname};
use super::super::types::{BuiltinTool, Manifest, NetworkMode};
use super::{EgressRule, ResolvedMount};
use crate::secrets::is_secret_name;
use crate::text;

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
    let fetch = if m.tools.builtin.contains(&BuiltinTool::Fetch) {
        FETCH_GET
    } else {
        ""
    };
    Some(format!(
        "Anything this agent reads ({}) can be sent to {}.{fetch}",
        join(&readable),
        join(&destinations)
    ))
}

/// What the finding adds when `fetch` is granted: GET and HEAD never prompt, whatever
/// `tools.fetch_writes` says, so a URL is an unprompted way out (maintainer, #75 part 2).
const FETCH_GET: &str =
    " The fetch tool's GET requests are not prompted and can carry data out in the URL.";

/// Mount realpaths, then what each secret unlocks (one entry per secret, all its hosts), then
/// one unnamed entry per grant that cannot be named, in manifest order.
///
/// Each realpath is quoted from its bytes ([`text::quoted_path`]), the same form as the
/// summary's mount lines, so the finding is printable ASCII and the summary's first line, its
/// mount lines and this warning name a folder alike (RT-MAN-05).
///
/// A grant is named only when its secret name and its host both passed their own checks
/// (architect Q376): on a rejected manifest either may hold a pasted credential with a quote,
/// backslash, space or slash, which the diagnostic mask does not cover.
fn readable(m: &Manifest, mounts: &[ResolvedMount]) -> Vec<String> {
    let mut out: Vec<String> = mounts
        .iter()
        .map(|mt| text::quoted_path(mt.host.as_os_str().as_bytes()))
        .collect();
    let mut by_secret: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    let mut unnamed = Vec::new();
    for (i, s) in m.secrets.iter().enumerate() {
        if is_secret_name(&s.name) && parse_hostname(&s.inject.host).is_ok() {
            by_secret
                .entry(s.name.as_str())
                .or_default()
                .insert(s.inject.host.as_str());
        } else {
            unnamed.push(format!("whatever the secret at secrets[{i}] unlocks"));
        }
    }
    // TODO(#195): the hosts are joined bare, here and in destination(); a host label shaped
    // like a token is not masked.
    out.extend(by_secret.into_iter().map(|(name, hosts)| {
        let hosts: Vec<&str> = hosts.into_iter().collect();
        format!("whatever your {name:?} unlocks on {}", hosts.join(" or "))
    }));
    out.extend(unnamed);
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
    use std::ffi::OsStr;
    use std::path::PathBuf;

    use super::super::super::paths::DirId;
    use super::super::super::types::{ApproveGlobs, MountMode};
    use super::*;

    fn mount(host: &[u8]) -> ResolvedMount {
        ResolvedMount {
            host: PathBuf::from(OsStr::from_bytes(host)),
            guest: "/workspace/p".to_owned(),
            mode: MountMode::Ro,
            approve: ApproveGlobs::not_applicable(),
            id: DirId { dev: 0, ino: 0 },
        }
    }

    /// RT-MAN-05: the finding quotes each realpath from its bytes, so it is printable ASCII for a
    /// letter outside ASCII, a quote, a backslash and a byte that is not UTF-8, and names each
    /// as the summary's mount line does.
    #[test]
    fn the_finding_quotes_each_realpath_from_its_bytes() {
        #[allow(clippy::unwrap_used)]
        let m = super::super::super::parse::parse(
            "apiVersion: sallyport/v1\nkind: Manifest\nname: t\nmodel:\n  ref: any\n\
             network:\n  mode: proxy\n  allow:\n    - host: api.github.com\n",
        )
        .unwrap();
        let hosts: [&[u8]; 3] = [b"/h/caf\xc3\xa9", b"/h/a \"b\\c", b"/h/x\xffy"];
        let mounts: Vec<ResolvedMount> = hosts.iter().map(|h| mount(h)).collect();
        let egress = [EgressRule {
            host: HostPattern::Exact("api.github.com".to_owned()),
            ports: vec![443],
        }];
        let finding = data_can_leave(&m, &mounts, &egress).unwrap_or_default();
        assert!(
            finding.bytes().all(|b| (b' '..=b'~').contains(&b)),
            "{finding:?}"
        );
        assert_eq!(
            finding,
            "Anything this agent reads (\"/h/caf\\u{e9}\", \"/h/a \\\"b\\\\c\" and \
             \"/h/x\\xffy\") can be sent to api.github.com."
        );
    }

    #[test]
    fn join_reads_like_english() {
        let v = |xs: &[&str]| xs.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert_eq!(join(&v(&[])), "");
        assert_eq!(join(&v(&["a"])), "a");
        assert_eq!(join(&v(&["a", "b"])), "a and b");
        assert_eq!(join(&v(&["a", "b", "c"])), "a, b and c");
    }
}
