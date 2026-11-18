//! The addresses this host owns and the networks it is directly connected to, parsed from
//! `/proc/net/fib_trie`, `/proc/net/if_inet6` and `/proc/net/ipv6_route` (decision 5, architect
//! Q8): no dependency, no packet sent. Pure over the file text; `net.rs` reads the files.
//!
//! Every `fib_trie` line has one of four shapes: a table header (`Main:`, `Local:`, `Id <n>:`),
//! a node (`+-- <ipv4>/<len> <n> <n> <n>`), a leaf (`|-- <ipv4>`), or a route line under a leaf
//! (`/<len> <scope> <type>`, then an optional `tos=<n>`; the kernel prints an unknown scope as
//! `scope=<n>` and an unknown type as `type <n>`, which has one token too many and refuses). A
//! `/32 host LOCAL` line is an address the host owns. Any other route line is a network the host
//! reaches with no gateway, except one of length 0, a route that only drops traffic
//! (`BLACKHOLE`, `UNREACHABLE`, `PROHIBIT`), and a `universe` route: the scope the kernel gives a
//! route through a gateway (a device route given that scope by hand is therefore not counted).
//!
//! `if_inet6` has one line per IPv6 address: 32 hex digits, the interface index (2 to 8 hex
//! digits), prefix length, scope and flags (2 each), the interface name. The address is owned,
//! and its prefix names a network. `ipv6_route` has one line per route: destination, its length,
//! source, its length, next hop, metric, reference count, use count, flags, and the interface
//! (absent for some routes). A route counts unless it has length 0, the gateway flag, or the
//! reject flag (set on every route that only drops traffic).
//!
//! A line the parser does not understand, a prefix longer than the address, or a network written
//! with bits set below its length refuses the whole list (fail closed).

#![deny(clippy::indexing_slicing)]

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::addr::{HostNets, Net};

/// IPv4 route types that only drop traffic.
const DROP_V4: [&str; 3] = ["BLACKHOLE", "UNREACHABLE", "PROHIBIT"];
/// `RTF_GATEWAY` in `ipv6_route`'s flags.
const RTF_GATEWAY: u128 = 0x2;
/// `RTF_REJECT` in `ipv6_route`'s flags: blackhole, unreachable, prohibit and throw routes.
const RTF_REJECT: u128 = 0x200;
/// The magnitude of `i32::MIN`, the most negative table id `%d` prints.
const I32_MAGNITUDE: u32 = 2_147_483_648;

/// One of the three tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Table {
    /// `/proc/net/fib_trie`.
    FibTrie,
    /// `/proc/net/if_inet6`.
    IfInet6,
    /// `/proc/net/ipv6_route`.
    Ipv6Route,
}

impl std::fmt::Display for Table {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::FibTrie => "fib_trie",
            Self::IfInet6 => "if_inet6",
            Self::Ipv6Route => "ipv6_route",
        })
    }
}

/// Why the tables cannot be trusted. Every case refuses the connection (fail closed). The text
/// is a closed set (a table name, fixed words, a line number), never a line's content or a path:
/// it is written to the audit log as the refusal's `cause`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HostAddrsError {
    /// `fib_trie` yielded no IPv4 loopback: the format is not what the parser expects.
    #[error("fib_trie lists no host-local 127.0.0.1")]
    NoLoopback,
    /// A line (1-based) is not in its table's form.
    #[error("{table} line {line} is malformed")]
    Malformed {
        /// The table.
        table: Table,
        /// The line, counted from 1.
        line: usize,
    },
    /// One of `if_inet6` and `ipv6_route` exists and the other does not.
    #[error("only one of if_inet6 and ipv6_route exists")]
    Ipv6Half,
    /// A table could not be read (`fib_trie` missing included).
    #[error("{table} could not be read: {kind}")]
    Unreadable {
        /// The table.
        table: Table,
        /// How the read failed.
        kind: io::ErrorKind,
    },
    /// A table is longer than the size bound.
    #[error("{table} is over the size bound")]
    TooLarge {
        /// The table.
        table: Table,
    },
    /// The task reading the tables did not return.
    #[error("the table reader failed")]
    ReaderFailed,
}

/// The text of `if_inet6` and `ipv6_route` (`None`: the file does not exist).
#[derive(Debug, Clone, Copy, Default)]
pub struct Ipv6Tables<'a> {
    /// `/proc/net/if_inet6`.
    pub addrs: Option<&'a str>,
    /// `/proc/net/ipv6_route`.
    pub routes: Option<&'a str>,
}

/// The host's own addresses and connected networks, each list sorted and without duplicates.
/// Both IPv6 files missing means IPv6 is off.
///
/// # Errors
/// [`HostAddrsError`]; the caller refuses the connection.
pub fn parse(fib_trie: &str, v6: Ipv6Tables<'_>) -> Result<HostNets, HostAddrsError> {
    let mut host = HostNets::default();
    for line in fib_lines(fib_trie)? {
        match line {
            Fib::Own(ip) => host.own.push(IpAddr::V4(ip)),
            Fib::Connected(net) => host.connected.push(net),
        }
    }
    if !host.own.contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)) {
        return Err(HostAddrsError::NoLoopback);
    }
    let (addrs, routes) = match (v6.addrs, v6.routes) {
        (None, None) => return Ok(sorted(host)),
        (Some(a), Some(r)) => (a, r),
        _ => return Err(HostAddrsError::Ipv6Half),
    };
    for (i, line) in addrs.lines().enumerate() {
        let (ip, len) = inet6_line(line).ok_or_else(|| malformed(Table::IfInet6, i))?;
        host.own.push(IpAddr::V6(ip));
        // Length 0 is no network (`Net::prefix` refuses it); 128 is the address itself.
        if let Some(n) = Net::prefix(IpAddr::V6(ip), len) {
            host.connected.push(n);
        }
    }
    for (i, line) in routes.lines().enumerate() {
        let net = route6_line(line).map_err(|Bad| malformed(Table::Ipv6Route, i))?;
        host.connected.extend(net);
    }
    Ok(sorted(host))
}

/// Line `i` (from 0) of `table` is malformed.
fn malformed(table: Table, i: usize) -> HostAddrsError {
    HostAddrsError::Malformed {
        table,
        line: i.saturating_add(1),
    }
}

/// Both lists sorted, duplicates dropped (the kernel prints the merged table twice).
fn sorted(mut host: HostNets) -> HostNets {
    host.own.sort_unstable();
    host.own.dedup();
    host.connected.sort_unstable();
    host.connected.dedup();
    host
}

/// Digits only (no sign), as a number (an empty string fails to parse).
fn decimal<T: std::str::FromStr>(s: &str) -> Option<T> {
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// What one `fib_trie` route line says about its leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fib {
    Own(Ipv4Addr),
    Connected(Net),
}

/// Every route line of `fib_trie` that names an own address or a connected network, in order.
fn fib_lines(text: &str) -> Result<Vec<Fib>, HostAddrsError> {
    let mut out = Vec::new();
    let mut leaf: Option<Ipv4Addr> = None;
    for (i, line) in text.lines().enumerate() {
        let bad = || malformed(Table::FibTrie, i);
        let t = line.trim_start();
        if let Some(rest) = t.strip_prefix("|-- ") {
            leaf = Some(rest.parse().map_err(|_| bad())?);
        } else if t.starts_with('/') {
            let ip = leaf.ok_or_else(bad)?;
            let fields: Vec<&str> = t.split_whitespace().collect();
            let route = route_v4(&fields).ok_or_else(bad)?;
            out.extend(route.judge(ip).map_err(|Bad| bad())?);
        } else if is_header(t) || is_node(t) {
            leaf = None;
        } else {
            return Err(bad());
        }
    }
    Ok(out)
}

/// `Main:`, `Local:` or `Id <n>:` (the kernel prints a table id with `%d`, so one past
/// `i32::MAX` is negative): `n` is an `i32` as `%d` writes it, never `-0`.
fn is_header(t: &str) -> bool {
    let id = |n: &str| match n.strip_prefix('-') {
        Some(m) => decimal::<u32>(m).is_some_and(|v| (1..=I32_MAGNITUDE).contains(&v)),
        None => decimal::<i32>(n).is_some(),
    };
    t == "Main:"
        || t == "Local:"
        || t.strip_prefix("Id ")
            .and_then(|r| r.strip_suffix(':'))
            .is_some_and(id)
}

/// `+-- <ipv4>/<len> <n> <n> <n>`.
fn is_node(t: &str) -> bool {
    let Some(rest) = t.strip_prefix("+-- ") else {
        return false;
    };
    let fields: Vec<&str> = rest.split_whitespace().collect();
    let [key, a, b, c] = fields.as_slice() else {
        return false;
    };
    let key_ok = key.split_once('/').is_some_and(|(ip, len)| {
        ip.parse::<Ipv4Addr>().is_ok() && decimal::<u32>(len).is_some_and(|l| l <= 32)
    });
    key_ok && [a, b, c].iter().all(|n| decimal::<u32>(n).is_some())
}

/// A line that is not in its table's form.
struct Bad;

/// One `fib_trie` route line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RouteV4<'a> {
    len: u32,
    scope: &'a str,
    kind: &'a str,
}

impl RouteV4<'_> {
    /// What the line says about `ip`, its leaf: nothing for a route of length 0, one that only
    /// drops, or one through a gateway (`universe`). A leaf with bits set below the line's
    /// length is not a network the kernel writes: it refuses the list.
    fn judge(&self, ip: Ipv4Addr) -> Result<Option<Fib>, Bad> {
        if self.len == 0 {
            return if ip.is_unspecified() {
                Ok(None)
            } else {
                Err(Bad)
            };
        }
        let net = Net::prefix(IpAddr::V4(ip), self.len)
            .filter(|n| n.addr() == IpAddr::V4(ip))
            .ok_or(Bad)?;
        if (self.len, self.scope, self.kind) == (32, "host", "LOCAL") {
            return Ok(Some(Fib::Own(ip)));
        }
        if DROP_V4.contains(&self.kind) || self.scope == "universe" {
            return Ok(None);
        }
        Ok(Some(Fib::Connected(net)))
    }
}

/// `/<len> <scope> <type>`, then an optional `tos=<n>`.
fn route_v4<'a>(fields: &[&'a str]) -> Option<RouteV4<'a>> {
    let [len, scope, kind, rest @ ..] = fields else {
        return None;
    };
    let len: u32 = decimal(len.strip_prefix('/')?).filter(|l| *l <= 32)?;
    let tos_ok = match rest {
        [] => true,
        [tos] => tos
            .strip_prefix("tos=")
            .is_some_and(|n| decimal::<u8>(n).is_some()),
        _ => false,
    };
    tos_ok.then_some(RouteV4 { len, scope, kind })
}

/// Hex digits only, `min..=max` of them, as a number.
fn hex(field: &str, min: usize, max: usize) -> Option<u128> {
    if !(min..=max).contains(&field.len()) || !field.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u128::from_str_radix(field, 16).ok()
}

/// Exactly `n` hex digits, as a number.
fn hex_exact(field: &str, n: usize) -> Option<u128> {
    hex(field, n, n)
}

/// A prefix length: two hex digits, at most 128.
fn prefix_len(field: &str) -> Option<u32> {
    hex_exact(field, 2)
        .and_then(|l| u32::try_from(l).ok())
        .filter(|l| *l <= 128)
}

/// The address and prefix length of one `if_inet6` line.
fn inet6_line(line: &str) -> Option<(Ipv6Addr, u32)> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    let [addr, index, len, scope, flags, _name] = fields.as_slice() else {
        return None;
    };
    let ip = Ipv6Addr::from(hex_exact(addr, 32)?);
    hex(index, 2, 8)?;
    hex_exact(scope, 2)?;
    hex_exact(flags, 2)?;
    Some((ip, prefix_len(len)?))
}

/// The network of one `ipv6_route` line: `None` when the route does not count (length 0, a
/// gateway, or a reject route).
fn route6_line(line: &str) -> Result<Option<Net>, Bad> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    let (dest, len, src, src_len, next, metric, refs, uses, flags) = match fields.as_slice() {
        [d, l, s, sl, n, m, r, u, f] | [d, l, s, sl, n, m, r, u, f, _] => {
            (*d, *l, *s, *sl, *n, *m, *r, *u, *f)
        }
        _ => return Err(Bad),
    };
    let dest = IpAddr::V6(Ipv6Addr::from(hex_exact(dest, 32).ok_or(Bad)?));
    let len = prefix_len(len).ok_or(Bad)?;
    // The other fields are checked for form only.
    prefix_len(src_len).ok_or(Bad)?;
    for (f, n) in [(src, 32), (next, 32), (metric, 8), (refs, 8), (uses, 8)] {
        hex_exact(f, n).ok_or(Bad)?;
    }
    let flags = hex_exact(flags, 8).ok_or(Bad)?;
    let net = match Net::prefix(dest, len) {
        Some(n) if n.addr() == dest => Some(n),
        None if dest.is_unspecified() => None,
        _ => return Err(Bad),
    };
    // Two tests, not one mask of both flags: they share no bit.
    if flags & RTF_GATEWAY != 0 || flags & RTF_REJECT != 0 {
        return Ok(None);
    }
    Ok(net)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[path = "hostaddrs_tests.rs"]
mod tests;
