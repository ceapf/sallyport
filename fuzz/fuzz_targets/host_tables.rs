//! Fuzz target: arbitrary bytes → the parser of the host's own tables (`/proc/net/fib_trie`,
//! `if_inet6`, `ipv6_route`) that the egress address filter reads on every connection. The
//! kernel writes the format, but the values come partly from the network (advertised prefixes
//! and routes), and the parser gates SI-9; CLAUDE.md: every such parser has a fuzz target.
//!
//! Input: one byte saying which IPv6 files exist (bit 0: `if_inet6`, bit 1: `ipv6_route`), then
//! the three texts separated by `#` (no table holds one). Non-UTF-8 input returns (production
//! reads with `read_to_string`, which refuses it).
//!
//! Invariants: never panics; an accepted table owns 127.0.0.1, holds only networks equal to
//! `Net::prefix` of their own address and length, and keeps both lists sorted and unique; an
//! accepted `fib_trie` with a line that is no shape appended is refused at that table; a
//! malformed-line error names a line inside its table's text.
#![no_main]
#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr};

use libfuzzer_sys::fuzz_target;
use sallyd::egress::addr::Net;
use sallyd::egress::hostaddrs::{HostAddrsError, Ipv6Tables, Table, parse};

fuzz_target!(|data: &[u8]| {
    let Some((&which, rest)) = data.split_first() else {
        return;
    };
    let Ok(text) = std::str::from_utf8(rest) else {
        return;
    };
    let mut parts = text.splitn(3, '#');
    let fib = parts.next().unwrap_or_default();
    let addrs = parts.next().unwrap_or_default();
    let routes = parts.next().unwrap_or_default();
    let v6 = Ipv6Tables {
        addrs: (which & 1 != 0).then_some(addrs),
        routes: (which & 2 != 0).then_some(routes),
    };
    match parse(fib, v6) {
        Ok(host) => {
            assert!(host.own.contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)), "no loopback");
            for n in &host.connected {
                assert_eq!(Net::prefix(n.addr(), n.bits()), Some(*n), "not a network");
            }
            let own_ok = host.own.windows(2).all(|w| matches!(w, [a, b] if a < b));
            assert!(own_ok, "own not sorted unique");
            let nets_ok = host.connected.windows(2).all(|w| matches!(w, [a, b] if a < b));
            assert!(nets_ok, "nets not sorted unique");
            let garbage = format!("{fib}\n|- \n");
            assert!(
                matches!(
                    parse(&garbage, v6),
                    Err(HostAddrsError::Malformed {
                        table: Table::FibTrie,
                        ..
                    })
                ),
                "a line of no shape was accepted"
            );
        }
        Err(HostAddrsError::Malformed { table, line }) => {
            let of = match table {
                Table::FibTrie => fib,
                Table::IfInet6 => addrs,
                Table::Ipv6Route => routes,
            };
            assert!((1..=of.lines().count()).contains(&line), "line {line} outside");
        }
        Err(_) => {}
    }
});
