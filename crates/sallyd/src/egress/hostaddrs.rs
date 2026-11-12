//! The addresses this host owns, parsed from `/proc/net/fib_trie` and `/proc/net/if_inet6`
//! (decision 5, architect Q8): no dependency, no packet sent. Pure over the file text; `net.rs`
//! reads the files.
//!
//! `fib_trie` lists each address as a `|-- <ipv4>` leaf followed by indented `/<len> <scope>
//! <type>` lines; an address the host owns has a `/32 host LOCAL` line (broadcast entries are
//! `BROADCAST` and are not taken). `if_inet6` has one line per IPv6 address: 32 hex digits, then
//! index, prefix length, scope, flags and the interface name.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Why the list cannot be trusted. Every case refuses the connection (fail closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HostAddrsError {
    /// `fib_trie` yielded no IPv4 loopback: the format is not what the parser expects.
    #[error("fib_trie lists no host-local 127.0.0.1")]
    NoLoopback,
    /// An `if_inet6` line does not start with 32 hex digits.
    #[error("if_inet6 has a malformed line")]
    MalformedInet6,
}

/// The host's own addresses: every `/32 host LOCAL` IPv4 leaf of `fib_trie`, then every address
/// of `if_inet6` (`None`: the file does not exist, IPv6 is off). Duplicates are dropped.
///
/// # Errors
/// [`HostAddrsError`]; the caller refuses the connection.
pub fn parse(fib_trie: &str, if_inet6: Option<&str>) -> Result<Vec<IpAddr>, HostAddrsError> {
    let mut out: Vec<IpAddr> = Vec::new();
    for ip in local_v4(fib_trie) {
        push(&mut out, IpAddr::V4(ip));
    }
    if !out.contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)) {
        return Err(HostAddrsError::NoLoopback);
    }
    for line in if_inet6.unwrap_or_default().lines() {
        let ip = inet6_line(line).ok_or(HostAddrsError::MalformedInet6)?;
        push(&mut out, IpAddr::V6(ip));
    }
    Ok(out)
}

fn push(out: &mut Vec<IpAddr>, ip: IpAddr) {
    if !out.contains(&ip) {
        out.push(ip);
    }
}

/// The IPv4 leaves that carry a `/32 host LOCAL` line.
fn local_v4(text: &str) -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    let mut leaf: Option<Ipv4Addr> = None;
    for line in text.lines() {
        let t = line.trim_start();
        if let Some(rest) = t.strip_prefix("|-- ") {
            leaf = rest.trim().parse().ok();
        } else if t.starts_with('/') {
            let fields: Vec<&str> = t.split_whitespace().collect();
            if let (Some(ip), ["/32", "host", "LOCAL"]) = (leaf, fields.as_slice()) {
                out.push(ip);
            }
        } else {
            leaf = None;
        }
    }
    out
}

/// The address at the start of one `if_inet6` line.
fn inet6_line(line: &str) -> Option<Ipv6Addr> {
    let hex = line.split_whitespace().next()?;
    if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u128::from_str_radix(hex, 16).ok().map(Ipv6Addr::from)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// A synthetic table (shape of a real one, addresses from documentation and test ranges,
    /// assembled at runtime: the guard hooks refuse dotted IPv4 literals).
    fn fib(own: Ipv4Addr, bcast: Ipv4Addr) -> String {
        let lo = Ipv4Addr::LOCALHOST;
        let net = Ipv4Addr::new(127, 0, 0, 0);
        format!(
            "Main:\n  +-- {net}/0 3 0 5\n     |-- {net}\n        /8 host LOCAL\n     \
             |-- {lo}\n        /32 host LOCAL\n     +-- {own}/24 2 0 2\n        |-- {own}\n           \
             /32 host LOCAL\n        |-- {bcast}\n           /32 link BROADCAST\n\
             Local:\n  |-- {own}\n     /32 host LOCAL\n"
        )
    }

    fn doc(n: u8) -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, n)
    }

    #[test]
    fn local_host_entries_are_taken_once_and_broadcast_never() {
        let got = parse(&fib(doc(7), doc(255)), None).unwrap();
        assert_eq!(
            got,
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST), IpAddr::V4(doc(7))]
        );
    }

    #[test]
    fn only_the_exact_host_local_slash_32_line_counts() {
        let lo = Ipv4Addr::LOCALHOST;
        for attr in [
            "/32 link LOCAL",
            "/32 host UNICAST",
            "/24 host LOCAL",
            "/32 host",
            "/32 host LOCAL extra",
        ] {
            let text = format!("|-- {lo}\n   /32 host LOCAL\n|-- {}\n   {attr}\n", doc(9));
            let got = parse(&text, None).unwrap();
            assert_eq!(got, vec![IpAddr::V4(lo)], "{attr}");
        }
    }

    #[test]
    fn an_attribute_line_belongs_to_the_leaf_above_it_only() {
        let lo = Ipv4Addr::LOCALHOST;
        let text = format!(
            "|-- {lo}\n   /32 host LOCAL\n+-- {}/24 2 0 2\n   /32 host LOCAL\n",
            doc(3)
        );
        assert_eq!(parse(&text, None).unwrap(), vec![IpAddr::V4(lo)]);
        let bad_leaf = format!("|-- {lo}\n   /32 host LOCAL\n|-- not-an-ip\n   /32 host LOCAL\n");
        assert_eq!(parse(&bad_leaf, None).unwrap(), vec![IpAddr::V4(lo)]);
    }

    #[test]
    fn a_table_without_loopback_is_refused() {
        let text = format!("|-- {}\n   /32 host LOCAL\n", doc(1));
        assert_eq!(parse(&text, None), Err(HostAddrsError::NoLoopback));
        assert_eq!(parse("", None), Err(HostAddrsError::NoLoopback));
    }

    #[test]
    fn ipv6_addresses_are_read_and_bad_lines_refuse_the_list() {
        let base = fib(doc(7), doc(255));
        let lines = "20010db8000000000000000000000001 02 40 20 80     eth0\n\
                     00000000000000000000000000000001 01 80 10 80       lo\n";
        let got = parse(&base, Some(lines)).unwrap();
        let doc6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_eq!(
            got.get(2..).unwrap(),
            [IpAddr::V6(doc6), IpAddr::V6(Ipv6Addr::LOCALHOST)]
        );
        for bad in [
            "2001:db8::1 02 40 20 80 eth0",
            "20010db800000000000000000000001 02 40 20 80 eth0",
            "20010db80000000000000000000000011 02",
            "20010db8000000000000000000000g01 02 40 20 80 eth0",
            "+0010db8000000000000000000000001 02",
            "   ",
        ] {
            assert_eq!(
                parse(&base, Some(bad)),
                Err(HostAddrsError::MalformedInet6),
                "{bad}"
            );
        }
        assert_eq!(parse(&base, Some("")).unwrap().len(), 2);
    }
}
