//! Tests of the host-table parser. Addresses are assembled at runtime: the guard hooks refuse
//! dotted IPv4 literals.
use super::super::addr::{Rule, denied_by};
use super::*;

/// A synthetic table (the shape of a real one; documentation and test ranges).
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

fn v4(ip: Ipv4Addr) -> IpAddr {
    IpAddr::V4(ip)
}

fn v6(s: &str) -> IpAddr {
    IpAddr::V6(s.parse().unwrap())
}

fn net(ip: IpAddr, len: u32) -> Net {
    Net::prefix(ip, len).unwrap()
}

/// `fib_trie` text with only loopback and one leaf carrying `line`.
fn one(leaf: Ipv4Addr, line: &str) -> String {
    let lo = Ipv4Addr::LOCALHOST;
    format!("|-- {lo}\n   /32 host LOCAL\n|-- {leaf}\n   {line}\n")
}

fn v4_only(text: &str) -> Result<HostNets, HostAddrsError> {
    parse(text, Ipv6Tables::default())
}

/// The refusal for line `line` (from 1) of `table`.
fn at(table: Table, line: usize) -> Result<HostNets, HostAddrsError> {
    Err(HostAddrsError::Malformed { table, line })
}

#[test]
fn local_host_entries_are_owned_once_and_every_other_line_is_a_network() {
    let got = v4_only(&fib(doc(7), doc(255))).unwrap();
    assert_eq!(got.own, [v4(Ipv4Addr::LOCALHOST), v4(doc(7))]);
    assert_eq!(
        got.connected,
        [
            net(v4(Ipv4Addr::new(127, 0, 0, 0)), 8),
            net(v4(doc(255)), 32)
        ]
    );
}

/// Was: every line but `/32 host LOCAL` ignored, and the last two cases ignored too. Now every
/// other route line names a network and a line not in the route-line shape refuses the list.
#[test]
fn only_a_slash_32_host_local_line_is_an_own_address() {
    for (leaf, line, len) in [
        (doc(9), "/32 link LOCAL", 32),
        (doc(9), "/32 host UNICAST", 32),
        (doc(0), "/24 host LOCAL", 24),
        (doc(8), "/31 host LOCAL", 31),
    ] {
        let got = v4_only(&one(leaf, line)).unwrap();
        assert_eq!(got.own, [v4(Ipv4Addr::LOCALHOST)], "{line}");
        assert_eq!(got.connected, [net(v4(leaf), len)], "{line}");
    }
    for line in ["/32 host", "/32 host LOCAL extra"] {
        assert_eq!(v4_only(&one(doc(9), line)), at(Table::FibTrie, 4), "{line}");
    }
}

/// Was: a `universe` route was taken as one through a gateway and not counted, a `/1` route
/// counted, and a `THROW` line counted. Now the scope is not read, lengths 0 to 7 are ignored as
/// default-like, and `THROW` is ignored with the drop types.
#[test]
fn routes_count_whatever_their_scope_but_drop_throw_and_default_like_routes_do_not() {
    let lan = Ipv4Addr::new(93, 184, 216, 0);
    let half = Ipv4Addr::new(128, 0, 0, 0);
    let any = Ipv4Addr::UNSPECIFIED;
    for (leaf, line, counts) in [
        (lan, "/24 link UNICAST", Some(24)),
        (lan, "/24 universe UNICAST", Some(24)),
        (half, "/1 link UNICAST", None),
        (lan, "/24 site UNICAST", Some(24)),
        (lan, "/24 nowhere UNICAST", Some(24)),
        (lan, "/24 scope=253 UNICAST", Some(24)),
        (lan, "/24 link ANYCAST", Some(24)),
        (lan, "/24 link MULTICAST", Some(24)),
        (lan, "/24 link type", Some(24)),
        (lan, "/24 link UNICAST tos=8", Some(24)),
        (lan, "/24 link UNICAST tos=255", Some(24)),
        (lan, "/24 link THROW", None),
        (any, "/0 link UNICAST", None),
        (any, "/0 host LOCAL", None),
        (any, "/0 universe UNICAST", None),
        (lan, "/24 link BLACKHOLE", None),
        (lan, "/24 link UNREACHABLE", None),
        (lan, "/24 link PROHIBIT", None),
        (lan, "/24 host BLACKHOLE", None),
    ] {
        let got = v4_only(&one(leaf, line)).unwrap();
        let want: Vec<Net> = counts.map(|l| net(v4(leaf), l)).into_iter().collect();
        assert_eq!(got.connected, want, "{line}");
        assert_eq!(got.own, [v4(Ipv4Addr::LOCALHOST)], "{line}");
    }
}

/// The rule `ip` meets under a table whose one route line is `line`, on leaf `leaf`.
fn rule_under(leaf: Ipv4Addr, line: &str, ip: Ipv4Addr) -> Option<Rule> {
    denied_by(v4(ip), &v4_only(&one(leaf, line)).unwrap())
}

/// One leg per row of the `fib_trie` probe table in `docs/dev/PROBE_NOTES.md`, on a global
/// prefix. A counted row refuses an address inside its prefix as a connected network; its
/// control, an address just past the prefix, passes. An ignored row lets the address inside
/// pass; its control, the same leaf under a plain device route, refuses it.
#[test]
fn every_probe_table_row_counts_but_throw_and_default_like_routes() {
    let net24 = Ipv4Addr::new(93, 184, 216, 0);
    let (inside24, past24) = (
        Ipv4Addr::new(93, 184, 216, 9),
        Ipv4Addr::new(93, 184, 217, 9),
    );
    let net25 = Ipv4Addr::new(93, 184, 216, 128);
    let (inside25, past25) = (
        Ipv4Addr::new(93, 184, 216, 200),
        Ipv4Addr::new(93, 184, 216, 9),
    );
    let counted = [
        (
            "from the address",
            net24,
            "/24 link UNICAST",
            inside24,
            past24,
        ),
        (
            "plain device route",
            net24,
            "/24 link UNICAST",
            inside24,
            past24,
        ),
        (
            "device route, scope global",
            net24,
            "/24 universe UNICAST",
            inside24,
            past24,
        ),
        (
            "nexthop object, device only",
            net24,
            "/24 universe UNICAST",
            inside24,
            past24,
        ),
        (
            "multipath, device legs",
            net25,
            "/25 universe UNICAST",
            inside25,
            past25,
        ),
        (
            "through a gateway",
            net25,
            "/25 universe UNICAST",
            inside25,
            past25,
        ),
    ];
    for (row, leaf, line, inside, past) in counted {
        assert_eq!(
            rule_under(leaf, line, inside),
            Some(Rule::ConnectedNetwork),
            "{row}"
        );
        assert_eq!(rule_under(leaf, line, past), None, "{row}: control");
    }
    let (low, high) = (Ipv4Addr::UNSPECIFIED, Ipv4Addr::new(128, 0, 0, 0));
    let (net8_low, net8_high) = (Ipv4Addr::new(93, 0, 0, 0), Ipv4Addr::new(151, 0, 0, 0));
    let inside_high = Ipv4Addr::new(151, 101, 1, 9);
    let ignored = [
        ("throw", net24, "/24 universe THROW", inside24, net24),
        (
            "throw, link scope",
            net24,
            "/24 link THROW",
            inside24,
            net24,
        ),
        (
            "half-space, low",
            low,
            "/1 universe UNICAST",
            inside24,
            net8_low,
        ),
        (
            "half-space, high",
            high,
            "/1 universe UNICAST",
            inside_high,
            net8_high,
        ),
    ];
    for (row, leaf, line, inside, control_leaf) in ignored {
        assert_eq!(rule_under(leaf, line, inside), None, "{row}");
        let control_line = if control_leaf == net24 {
            "/24 link UNICAST"
        } else {
            "/8 link UNICAST"
        };
        assert_eq!(
            rule_under(control_leaf, control_line, inside),
            Some(Rule::ConnectedNetwork),
            "{row}: control"
        );
    }
}

/// Lengths 0 to 7 are default-like and ignored, whatever the scope; 8 is the shortest route
/// that counts. Control: the same address under a `/8` route is refused.
#[test]
fn routes_shorter_than_eight_are_default_like() {
    let ip = Ipv4Addr::new(1, 2, 3, 4);
    for len in 1..=7 {
        let line = format!("/{len} link UNICAST");
        assert_eq!(rule_under(Ipv4Addr::UNSPECIFIED, &line, ip), None, "{line}");
    }
    let net8 = Ipv4Addr::new(1, 0, 0, 0);
    for line in ["/8 link UNICAST", "/8 universe UNICAST"] {
        assert_eq!(
            rule_under(net8, line, ip),
            Some(Rule::ConnectedNetwork),
            "{line}"
        );
        let past = Ipv4Addr::new(2, 2, 3, 4);
        assert_eq!(rule_under(net8, line, past), None, "{line}: control");
    }
}

#[test]
fn a_route_line_the_parser_does_not_understand_refuses_the_list() {
    for line in [
        "/33 link UNICAST",
        "/x link UNICAST",
        "/-1 link UNICAST",
        "24 link UNICAST",
        "/24",
        "/24 link",
        "/24 link UNICAST extra",
        "/24 link UNICAST tos=x",
        "/24 link UNICAST tos=256",
        "/24 link UNICAST tos 8",
        "/24 link UNICAST tos=8 extra",
        "/24 link type 13",
        "/24 link type x",
    ] {
        let leaf = Ipv4Addr::new(93, 184, 216, 0);
        assert_eq!(v4_only(&one(leaf, line)), at(Table::FibTrie, 4), "{line}");
    }
}

#[test]
fn a_leaf_with_bits_below_its_route_length_refuses_the_list() {
    for (leaf, line) in [
        (Ipv4Addr::new(93, 184, 216, 1), "/24 link UNICAST"),
        (Ipv4Addr::new(93, 184, 216, 1), "/31 link UNICAST"),
        (Ipv4Addr::new(93, 184, 216, 0), "/1 link UNICAST"),
        (Ipv4Addr::new(0, 0, 0, 1), "/0 universe UNICAST"),
        (Ipv4Addr::new(128, 0, 0, 0), "/0 link UNICAST"),
    ] {
        assert_eq!(
            v4_only(&one(leaf, line)),
            at(Table::FibTrie, 4),
            "{leaf} {line}"
        );
    }
}

/// Was: a route line under a node, and a leaf that is not an address, were ignored. Now every
/// line is a header, a node, a leaf or a route line under a leaf, or the list is refused.
#[test]
fn every_fib_line_has_one_of_four_shapes() {
    let lo = Ipv4Addr::LOCALHOST;
    let base = format!("|-- {lo}\n   /32 host LOCAL\n");
    let d = doc(0);
    let ok = format!(
        "Main:\n{base}Local:\nId 255:\nId -1:\nId 2147483647:\nId -2147483648:\n  \
         +-- {d}/24 2 0 2\n  \
         +-- {d}/32 0 0 0\n|-- {d}\n   /24 link UNICAST\n   /32 link BROADCAST\n"
    );
    let got = v4_only(&ok).unwrap();
    assert_eq!(got.own, [v4(lo)]);
    assert_eq!(got.connected, [net(v4(d), 24), net(v4(d), 32)]);
    // Each bad text with the line (from 1) that refuses it.
    for (bad, line) in [
        (format!("{base}+-- {d}/24 2 0 2\n   /24 link UNICAST\n"), 4),
        (format!("/24 link UNICAST\n{base}"), 1),
        (format!("{base}Main:\n   /24 link UNICAST\n"), 4),
        (format!("{base}|-- not-an-ip\n   /32 host LOCAL\n"), 3),
        (format!("{base}|-- {d} \n"), 3),
        (format!("{base}\n"), 3),
        (format!("{base}garbage\n"), 3),
        (format!("{base}Id x:\n"), 3),
        (format!("{base}Id 5\n"), 3),
        (format!("{base}Id +5:\n"), 3),
        (format!("{base}Id --5:\n"), 3),
        // `%d` prints neither `-0` nor anything outside `i32`.
        (format!("{base}Id -0:\n"), 3),
        (format!("{base}Id 2147483648:\n"), 3),
        (format!("{base}Id 4294967295:\n"), 3),
        (format!("{base}Id -2147483649:\n"), 3),
        (format!("{base}Id :\n"), 3),
        (format!("{base}Other:\n"), 3),
        (format!("{base}+-- x/24 2 0 2\n"), 3),
        (format!("{base}+-- {d}/33 2 0 2\n"), 3),
        (format!("{base}+-- {d}/x 2 0 2\n"), 3),
        (format!("{base}+-- {d}/+24 2 0 2\n"), 3),
        (format!("{base}+-- {d}/24 2 0\n"), 3),
        (format!("{base}+-- {d}/24 2 0 2 2\n"), 3),
        (format!("{base}+-- {d} 2 0 2\n"), 3),
        (format!("{base}+-- {d}/24 2 0 x\n"), 3),
        (format!("{base}+-- {d}/24 x 0 2\n"), 3),
        (format!("{base}+-- {d}/24 2 +0 2\n"), 3),
        (format!("|-- {d}\n   /+24 link UNICAST\n{base}"), 2),
        (format!("|-- {d}\n   /24 link UNICAST tos=+8\n{base}"), 2),
    ] {
        assert_eq!(v4_only(&bad), at(Table::FibTrie, line), "{bad:?}");
    }
}

/// The kernel prints the merged table under both headers: each address and network is kept
/// once, the lists sorted.
#[test]
fn a_table_printed_twice_gives_each_entry_once_in_order() {
    let lo = Ipv4Addr::LOCALHOST;
    let (a, b) = (doc(0), Ipv4Addr::new(93, 184, 216, 0));
    let half = format!(
        "|-- {b}\n   /24 link UNICAST\n   /32 host LOCAL\n|-- {lo}\n   /32 host LOCAL\n\
         |-- {a}\n   /24 link UNICAST\n   /32 host LOCAL\n"
    );
    let got = v4_only(&format!("Main:\n{half}Local:\n{half}")).unwrap();
    assert_eq!(got.own, [v4(b), v4(lo), v4(a)]);
    assert_eq!(got.connected, [net(v4(b), 24), net(v4(a), 24)]);
}

#[test]
fn a_table_without_loopback_is_refused() {
    let text = format!("|-- {}\n   /32 host LOCAL\n", doc(1));
    assert_eq!(v4_only(&text), Err(HostAddrsError::NoLoopback));
    assert_eq!(v4_only(""), Err(HostAddrsError::NoLoopback));
}

fn with_v6(addrs: &str, routes: &str) -> Result<HostNets, HostAddrsError> {
    let v6 = Ipv6Tables {
        addrs: Some(addrs),
        routes: Some(routes),
    };
    parse(&fib(doc(7), doc(255)), v6)
}

#[test]
fn ipv6_addresses_are_owned_and_name_their_networks() {
    let lines = "20010db8000000000000000000000001 02 40 20 80     eth0\n\
                 20010db8000000000000000000000002 1ff 40 20 80     veth9\n\
                 20010db9000000000000000000000001 0a 00 00 80     tun0\n\
                 00000000000000000000000000000001 01 80 10 80       lo\n";
    let got = with_v6(lines, "").unwrap();
    assert_eq!(
        got.own.get(2..).unwrap(),
        [
            v6("::1"),
            v6("2001:db8::1"),
            v6("2001:db8::2"),
            v6("2001:db9::1")
        ]
    );
    // One /64 for both addresses on it; a prefix of 0 names none; ::1 names only itself.
    assert_eq!(
        got.connected.get(2..).unwrap(),
        [net(v6("::1"), 128), net(v6("2001:db8::"), 64)]
    );
}

#[test]
fn a_malformed_line_is_named_by_its_table_and_number() {
    let good6 = "20010db8000000000000000000000001 02 40 20 80 eth0\n";
    let good_route = route6(LAN6, "40", "00000001");
    assert_eq!(
        with_v6(&format!("{good6}{good6}bad\n"), ""),
        at(Table::IfInet6, 3)
    );
    assert_eq!(
        with_v6("", &format!("{good_route}\n{good_route}\nbad\n")),
        at(Table::Ipv6Route, 3)
    );
    let text = format!("{}garbage\n", fib(doc(7), doc(255)));
    let lines = text.lines().count();
    assert_eq!(v4_only(&text), at(Table::FibTrie, lines));
    // The text is a closed set: table, fixed words, number.
    let e = HostAddrsError::Malformed {
        table: Table::Ipv6Route,
        line: 12,
    };
    assert_eq!(e.to_string(), "ipv6_route line 12 is malformed");
    let names = [Table::FibTrie, Table::IfInet6, Table::Ipv6Route].map(|t| t.to_string());
    assert_eq!(names, ["fib_trie", "if_inet6", "ipv6_route"]);
    for (e, text) in [
        (
            HostAddrsError::NoLoopback,
            "fib_trie lists no host-local 127.0.0.1",
        ),
        (
            HostAddrsError::Ipv6Half,
            "only one of if_inet6 and ipv6_route exists",
        ),
        (
            HostAddrsError::TooLarge {
                table: Table::IfInet6,
            },
            "if_inet6 is over the size bound",
        ),
        (HostAddrsError::ReaderFailed, "the table reader failed"),
    ] {
        assert_eq!(e.to_string(), text);
    }
    let e = HostAddrsError::Unreadable {
        table: Table::FibTrie,
        kind: std::io::ErrorKind::NotFound,
    };
    // The kind's text is the standard library's fixed description, never an OS message or a
    // path; pinned whole so a change in it shows here, not first in an audit reader.
    let kind = std::io::ErrorKind::NotFound;
    assert_eq!(e.to_string(), format!("fib_trie could not be read: {kind}"));
    assert_eq!(kind.to_string(), "entity not found");
}

/// The bound on a negative table id is `i32::MIN`'s magnitude.
#[test]
fn the_negative_id_bound_is_i32_min() {
    assert_eq!(I32_MAGNITUDE, i32::MIN.unsigned_abs());
}

#[test]
fn a_malformed_if_inet6_line_refuses_the_list() {
    for bad in [
        "2001:db8::1 02 40 20 80 eth0",
        "20010db800000000000000000000001 02 40 20 80 eth0",
        "20010db80000000000000000000000011 02 40 20 80 eth0",
        "20010db8000000000000000000000g01 02 40 20 80 eth0",
        "+0010db8000000000000000000000001 02 40 20 80 eth0",
        "20010db8000000000000000000000001 02 81 20 80 eth0",
        "20010db8000000000000000000000001 02 4 20 80 eth0",
        "20010db8000000000000000000000001 02 040 20 80 eth0",
        "20010db8000000000000000000000001 0x 40 20 80 eth0",
        "20010db8000000000000000000000001 2 40 20 80 eth0",
        "20010db8000000000000000000000001 123456789 40 20 80 eth0",
        "20010db8000000000000000000000001 02 40 2g 80 eth0",
        "20010db8000000000000000000000001 02 40 020 80 eth0",
        "20010db8000000000000000000000001 02 40 20 8z eth0",
        "20010db8000000000000000000000001 02 40 20 800 eth0",
        "20010db8000000000000000000000001 02 40 20 80",
        "20010db8000000000000000000000001 02 40 20 80 eth0 extra",
        "20010db8000000000000000000000001 02",
        "   ",
    ] {
        assert_eq!(with_v6(bad, ""), at(Table::IfInet6, 1), "{bad}");
    }
    let widest = "20010db8000000000000000000000001 12345678 40 20 80 eth0";
    assert!(with_v6(widest, "").is_ok());
}

/// One `ipv6_route` line for `dest/len` with `flags` and a zero next hop.
fn route6(dest: &str, len: &str, flags: &str) -> String {
    let zero = "0".repeat(32);
    format!("{dest} {len} {zero} 00 {zero} 00000100 00000001 00000000 {flags}     eth0")
}

const LAN6: &str = "26064700001000000000000000000000";

#[test]
fn ipv6_routes_count_unless_through_a_gateway_rejecting_or_default() {
    let lan = net(v6("2606:4700:10::"), 64);
    for (flags, counts) in [
        ("00000001", true),
        ("00000000", true),
        ("80200001", true),
        ("00040001", true),
        ("00000003", false),
        ("00000002", false),
        ("80200003", false),
        ("00000201", false),
        ("00200200", false),
        ("ffffffff", false),
    ] {
        let got = with_v6("", &route6(LAN6, "40", flags)).unwrap();
        assert_eq!(got.connected.contains(&lan), counts, "{flags}");
        assert_eq!(got.connected.len(), 2 + usize::from(counts), "{flags}");
    }
    // A next hop without the gateway flag still counts.
    let hop = route6(LAN6, "40", "00000001").replacen(&"0".repeat(32), &"f".repeat(32), 2);
    assert!(with_v6("", &hop).unwrap().connected.contains(&lan));
    // A default route with no gateway names no network, and the list stands.
    let zero = "0".repeat(32);
    let default = route6(&zero, "00", "00000001");
    assert_eq!(with_v6("", &default).unwrap().connected.len(), 2);
    // No device field.
    let bare = route6(LAN6, "40", "00000001").replace("     eth0", "");
    assert!(with_v6("", &bare).unwrap().connected.contains(&lan));
}

#[test]
fn a_malformed_ipv6_route_line_refuses_the_list() {
    let good = route6(LAN6, "40", "00000001");
    let mut bad: Vec<String> = vec![
        route6(LAN6, "81", "00000001"),
        route6(LAN6, "4", "00000001"),
        route6(LAN6, "40", "0000001"),
        route6(LAN6, "40", "0000000g"),
        route6("2606470000100000000000000000000", "40", "00000001"),
        route6("26064700001000000000000000000001", "40", "00000001"),
        route6("26064700001000000000000000000001", "7f", "00000001"),
        route6(LAN6, "00", "00000001"),
        route6(LAN6, "00", "00000003"),
        format!("{good} extra"),
        "   ".to_owned(),
    ];
    // Each other field, one at a time: a character that is not hex, or a wrong width.
    let fields: Vec<&str> = good.split_whitespace().collect();
    for i in [2, 3, 4, 5, 6, 7] {
        for wrong in ["g", "00000000000000000000000000000000000"] {
            let mut f = fields.clone();
            *f.get_mut(i).unwrap() = wrong;
            bad.push(f.join(" "));
        }
    }
    bad.push(fields.get(..8).unwrap().join(" "));
    let mut src_len = fields.clone();
    *src_len.get_mut(3).unwrap() = "81";
    bad.push(src_len.join(" "));
    for text in &bad {
        assert_eq!(with_v6("", text), at(Table::Ipv6Route, 1), "{text}");
    }
    assert!(with_v6("", &good).is_ok());
}

#[test]
fn ipv6_is_off_only_when_both_files_are_missing() {
    let base = fib(doc(7), doc(255));
    assert_eq!(parse(&base, Ipv6Tables::default()).unwrap().own.len(), 2);
    let half = [
        Ipv6Tables {
            addrs: Some(""),
            routes: None,
        },
        Ipv6Tables {
            addrs: None,
            routes: Some(""),
        },
    ];
    for v6 in half {
        assert_eq!(parse(&base, v6), Err(HostAddrsError::Ipv6Half), "{v6:?}");
    }
    assert_eq!(with_v6("", "").unwrap().own.len(), 2);
}
