//! The egress address filter (SI-9): a resolved address passes only if it is global unicast, not
//! one the host itself owns, and not inside a network the host is directly connected to. IPv6
//! forms that carry an IPv4 address (v4-mapped, NAT64 `64:ff9b::/96`, 6to4 `2002::/16`) are
//! judged by that IPv4 address as well.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Which rule of the filter refused an address, in the order they are checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// Not global unicast (a reserved, private, loopback, link-local or documentation range).
    ReservedRange,
    /// An address this host owns.
    OwnAddress,
    /// Inside a network in the host's route tables: an IPv4 route of length 8 or more, gateway
    /// or not; an IPv6 route without the gateway or reject flag; an own IPv6 address's prefix.
    ConnectedNetwork,
}

impl Rule {
    /// The name the `egress.deny` entry records.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReservedRange => "reserved-range",
            Self::OwnAddress => "own-address",
            Self::ConnectedNetwork => "connected-network",
        }
    }
}

/// A network: an address and a prefix length of at least 1 (a prefix of length 0 is never a
/// network here: it would be every address).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Net {
    addr: IpAddr,
    len: u32,
}

impl Net {
    /// The network of length `len` that holds `addr` (its bits below `len` cleared), or `None`
    /// when `len` is 0 or longer than the address.
    #[must_use]
    pub fn prefix(addr: IpAddr, len: u32) -> Option<Self> {
        let masked = match addr {
            IpAddr::V4(a) if (1..=32).contains(&len) => {
                IpAddr::V4(Ipv4Addr::from(u32::from(a) & v4_mask(len)))
            }
            IpAddr::V6(a) if (1..=128).contains(&len) => {
                IpAddr::V6(Ipv6Addr::from(u128::from(a) & v6_mask(len)))
            }
            _ => return None,
        };
        Some(Self { addr: masked, len })
    }

    /// The network's first address (no bit set below its length).
    #[must_use]
    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    /// The prefix length, in bits.
    #[must_use]
    pub fn bits(&self) -> u32 {
        self.len
    }

    /// Whether `ip` (of the same family) is inside this network.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => u32::from(a) & v4_mask(self.len) == u32::from(n),
            (IpAddr::V6(n), IpAddr::V6(a)) => u128::from(a) & v6_mask(self.len) == u128::from(n),
            _ => false,
        }
    }
}

/// What the host's own tables say: the addresses it owns and the networks it is directly
/// connected to (sorted and without duplicates when the tables are parsed).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostNets {
    /// Addresses this host owns.
    pub own: Vec<IpAddr>,
    /// Networks this host is directly connected to.
    pub connected: Vec<Net>,
}

/// IPv4 networks that are not global unicast, as (network, prefix length).
const DENIED_V4: &[(u32, u32)] = &[
    (0x0000_0000, 8),  // 0/8, "this network"
    (0x0A00_0000, 8),  // 10/8, private
    (0x6440_0000, 10), // 100.64/10, carrier-grade NAT
    (0x7F00_0000, 8),  // 127/8, loopback
    (0xA9FE_0000, 16), // 169.254/16, link-local
    (0xAC10_0000, 12), // 172.16/12, private
    (0xC000_0000, 24), // 192.0.0/24, IETF protocol assignments
    (0xC000_0200, 24), // 192.0.2/24, documentation
    (0xC058_6300, 24), // 192.88.99/24, 6to4 relay anycast (deprecated)
    (0xC0A8_0000, 16), // 192.168/16, private
    (0xC612_0000, 15), // 198.18/15, benchmarking
    (0xC633_6400, 24), // 198.51.100/24, documentation
    (0xCB00_7100, 24), // 203.0.113/24, documentation
    (0xE000_0000, 4),  // 224/4, multicast
    (0xF000_0000, 4),  // 240/4, reserved, including the limited broadcast address
];

/// IPv6 global unicast, `2000::/3`: everything outside it is denied.
const GLOBAL_V6: (u128, u32) = (0x2000 << 112, 3);

/// Networks inside `2000::/3` that are still not global unicast.
const DENIED_V6: &[(u128, u32)] = &[
    (0x2001_0000 << 96, 23), // 2001::/23, IETF assignments: Teredo, benchmarking, ORCHID
    (0x2001_0db8 << 96, 32), // 2001:db8::/32, documentation
    (0x3fff_0000 << 96, 20), // 3fff::/20, documentation
];

/// The mask of a `len`-bit IPv4 prefix (`len` in 1..=32).
fn v4_mask(len: u32) -> u32 {
    u32::MAX.checked_shl(32 - len).unwrap_or(0)
}

/// The mask of a `len`-bit IPv6 prefix (`len` in 1..=128).
fn v6_mask(len: u32) -> u128 {
    u128::MAX.checked_shl(128 - len).unwrap_or(0)
}

/// Whether `addr` is inside `net/len` (`len` in 1..=32).
fn in_v4(addr: u32, (net, len): (u32, u32)) -> bool {
    addr & v4_mask(len) == net
}

/// Whether `addr` is inside `net/len` (`len` in 1..=128).
fn in_v6(addr: u128, (net, len): (u128, u32)) -> bool {
    addr & v6_mask(len) == net
}

fn v4_denied(a: Ipv4Addr) -> bool {
    let x = u32::from(a);
    DENIED_V4.iter().any(|&net| in_v4(x, net))
}

/// The IPv4 address an IPv6 address carries: v4-mapped (`::ffff:a.b.c.d`), NAT64 well-known
/// prefix (`64:ff9b::a.b.c.d`) or 6to4 (`2002:aabb:ccdd::/48`).
fn embedded_v4(a: Ipv6Addr) -> Option<Ipv4Addr> {
    let [o0, o1, o2, o3, o4, o5, _, _, _, _, _, _, o12, o13, o14, o15] = a.octets();
    let low = Ipv4Addr::new(o12, o13, o14, o15);
    let x = u128::from(a);
    if in_v6(x, (0xffff << 32, 96)) || in_v6(x, (0x0064_ff9b << 96, 96)) {
        return Some(low);
    }
    if [o0, o1] == [0x20, 0x02] {
        return Some(Ipv4Addr::new(o2, o3, o4, o5));
    }
    None
}

fn v6_denied(a: Ipv6Addr) -> bool {
    if let Some(v4) = embedded_v4(a) {
        return v4_denied(v4);
    }
    let x = u128::from(a);
    !in_v6(x, GLOBAL_V6) || DENIED_V6.iter().any(|&net| in_v6(x, net))
}

/// The rule under which the proxy must refuse to connect to `ip`, or `None` when it may. Checked
/// in [`Rule`]'s order: not global unicast; owned by this host; inside a network this host is
/// directly connected to. The host's tables are compared with `ip` as given and with the IPv4
/// address an IPv6 form carries.
#[must_use]
pub fn denied_by(ip: IpAddr, host: &HostNets) -> Option<Rule> {
    let reserved = match ip {
        IpAddr::V4(a) => v4_denied(a),
        IpAddr::V6(a) => v6_denied(a),
    };
    if reserved {
        return Some(Rule::ReservedRange);
    }
    let carried = match ip {
        IpAddr::V6(a) => embedded_v4(a).map(IpAddr::V4),
        IpAddr::V4(_) => None,
    };
    let forms = || std::iter::once(ip).chain(carried);
    if forms().any(|f| host.own.contains(&f)) {
        return Some(Rule::OwnAddress);
    }
    if forms().any(|f| host.connected.iter().any(|n| n.contains(f))) {
        return Some(Rule::ConnectedNetwork);
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn v4(x: u32) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(x))
    }

    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse().unwrap())
    }

    /// The filter with `own` as the host's addresses and no connected network.
    fn is_denied(ip: IpAddr, own: &[IpAddr]) -> bool {
        let host = HostNets {
            own: own.to_vec(),
            connected: Vec::new(),
        };
        denied_by(ip, &host).is_some()
    }

    fn net(ip: IpAddr, len: u32) -> Net {
        Net::prefix(ip, len).unwrap()
    }

    #[test]
    fn every_denied_v4_network_is_denied_at_both_ends_and_its_neighbours_pass() {
        for &(net, len) in DENIED_V4 {
            let last = net | (u32::MAX >> len);
            assert!(is_denied(v4(net), &[]), "{net:#x}/{len} first");
            assert!(is_denied(v4(last), &[]), "{net:#x}/{len} last");
            for outside in [net.checked_sub(1), last.checked_add(1)]
                .into_iter()
                .flatten()
            {
                let listed = DENIED_V4.iter().any(|&n| in_v4(outside, n));
                assert_eq!(is_denied(v4(outside), &[]), listed, "{outside:#x}");
            }
        }
    }

    #[test]
    fn global_unicast_v4_passes() {
        // Public resolvers, a public web host, and the last address below 224/4.
        for x in [0x0101_0101, 0x0808_0808, 0x5DB8_D822, 0xDFFF_FFFF] {
            assert!(!is_denied(v4(x), &[]), "{x:#x}");
        }
    }

    #[test]
    fn non_global_v6_is_denied() {
        for s in [
            "::",
            "::1",
            "fc00::1",
            "fdff:ffff::1",
            "fe80::1",
            "febf::1",
            "ff02::1",
            "2001::1",
            "2001:0:4136:e378::1",
            "2001:1ff::1",
            "2001:db8::1",
            "3fff::1",
            "3fff:fff::1",
            "64:ff9b:1::1",
            "::a01:203",
            "1fff:ffff::1",
            "4000::1",
        ] {
            assert!(is_denied(v6(s), &[]), "{s}");
        }
    }

    #[test]
    fn global_unicast_v6_passes() {
        for s in [
            "2000::1",
            "2001:200::1",
            "2001:4860:4860::8888",
            "2606:4700::1111",
            "3ffe::1",
            "3fff:1000::1",
            "3fff:ffff::1",
        ] {
            assert!(!is_denied(v6(s), &[]), "{s}");
        }
    }

    #[test]
    fn ipv6_forms_carrying_ipv4_are_judged_by_the_ipv4_address() {
        for (denied, s) in [
            (true, "::ffff:7f00:1"),
            (true, "::ffff:a00:5"),
            (false, "::ffff:101:101"),
            (true, "64:ff9b::a9fe:a9fe"),
            (false, "64:ff9b::808:808"),
            (true, "2002:7f00:1::1"),
            (true, "2002:c0a8:101::1"),
            (false, "2002:808:808::1"),
        ] {
            assert_eq!(is_denied(v6(s), &[]), denied, "{s}");
        }
    }

    #[test]
    fn addresses_the_host_owns_are_denied_in_every_spelling() {
        let own = [v4(0x5DB8_D822), v6("2606:4700::1111")];
        assert!(is_denied(v4(0x5DB8_D822), &own));
        assert!(is_denied(v6("::ffff:5db8:d822"), &own));
        assert!(is_denied(v6("64:ff9b::5db8:d822"), &own));
        assert!(is_denied(v6("2002:5db8:d822::1"), &own));
        assert!(is_denied(v6("2606:4700::1111"), &own));
        assert!(!is_denied(v4(0x0808_0808), &own));
    }

    #[test]
    fn a_prefix_is_one_to_the_address_length_long_and_clears_the_bits_below() {
        for (ip, max) in [(v4(0x5DB8_D801), 32), (v6("2606:4700::1"), 128)] {
            assert_eq!(Net::prefix(ip, 0), None, "{ip}/0");
            assert_eq!(Net::prefix(ip, max), Some(Net { addr: ip, len: max }));
            assert_eq!(Net::prefix(ip, max + 1), None, "{ip}/{}", max + 1);
        }
        // Every bit below the length is cleared, every bit above kept.
        let n = net(v4(0xFFFF_FFFF), 1);
        assert_eq!((n.addr(), n.bits()), (v4(0x8000_0000), 1));
        assert_eq!(net(v6("2606:4700::"), 48).bits(), 48);
        assert_eq!(net(v4(0x5DB8_D8FF), 24).addr(), v4(0x5DB8_D800));
        assert_eq!(net(v4(0x5DB8_D8FF), 31).addr(), v4(0x5DB8_D8FE));
        let n = net(v6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), 1);
        assert_eq!((n.addr(), n.len), (v6("8000::"), 1));
        assert_eq!(net(v6("2606:4700:10::1"), 64).addr(), v6("2606:4700:10::"));
        assert_eq!(net(v6("2606:4700:10::1"), 127).addr(), v6("2606:4700:10::"));
        // Two addresses on one network give the same network.
        assert_eq!(net(v4(0x5DB8_D801), 24), net(v4(0x5DB8_D807), 24));
    }

    #[test]
    fn a_network_holds_exactly_its_prefix_whatever_its_host_bits() {
        // A /24 written with host bits set, as a table gives an own address's prefix.
        let n = net(v4(0x5DB8_D801), 24);
        for (x, inside) in [
            (0x5DB8_D800, true),
            (0x5DB8_D8FF, true),
            (0x5DB8_D7FF, false),
            (0x5DB8_D900, false),
        ] {
            assert_eq!(n.contains(v4(x)), inside, "{x:#x}");
        }
        let n = net(v6("2606:4700:10::1"), 64);
        for (s, inside) in [
            ("2606:4700:10::", true),
            ("2606:4700:10:0:ffff:ffff:ffff:ffff", true),
            ("2606:4700:f:ffff:ffff:ffff:ffff:ffff", false),
            ("2606:4700:10:1::", false),
        ] {
            assert_eq!(n.contains(v6(s)), inside, "{s}");
        }
        assert!(net(v4(0x5DB8_D800), 32).contains(v4(0x5DB8_D800)));
        assert!(!net(v4(0x5DB8_D800), 32).contains(v4(0x5DB8_D801)));
        assert!(net(v6("2606:4700::"), 1).contains(v6("7fff::1")));
        assert!(!net(v6("2606:4700::"), 1).contains(v6("8000::1")));
        // A network never holds an address of the other family.
        assert!(!net(v4(0x5DB8_D800), 24).contains(v6("::ffff:5db8:d801")));
        assert!(!net(v6("::"), 1).contains(v4(0x5DB8_D801)));
    }

    #[test]
    fn each_rule_is_named_and_checked_in_order() {
        let peer = v4(0x5DB8_D807);
        let host = HostNets {
            own: vec![v4(0x5DB8_D801), v4(0x0A00_0001)],
            connected: vec![net(v4(0x5DB8_D800), 24), net(v4(0x0A00_0000), 8)],
        };
        // A private address that is also owned and connected: the first rule names it.
        assert_eq!(denied_by(v4(0x0A00_0001), &host), Some(Rule::ReservedRange));
        // A public address that is owned and connected.
        assert_eq!(denied_by(v4(0x5DB8_D801), &host), Some(Rule::OwnAddress));
        assert_eq!(denied_by(peer, &host), Some(Rule::ConnectedNetwork));
        assert_eq!(denied_by(v4(0x5DB8_D907), &host), None);
        assert_eq!(denied_by(peer, &HostNets::default()), None);
        let names = [
            Rule::ReservedRange,
            Rule::OwnAddress,
            Rule::ConnectedNetwork,
        ]
        .map(Rule::as_str);
        assert_eq!(
            names,
            ["reserved-range", "own-address", "connected-network"]
        );
    }

    #[test]
    fn a_connected_network_refuses_every_spelling_that_carries_its_address() {
        let host = HostNets {
            own: Vec::new(),
            connected: vec![net(v4(0x5DB8_D800), 24), net(v6("2606:4700:10::"), 64)],
        };
        for s in [
            "::ffff:5db8:d807",
            "64:ff9b::5db8:d807",
            "2002:5db8:d807::1",
            "2606:4700:10::7",
        ] {
            assert_eq!(denied_by(v6(s), &host), Some(Rule::ConnectedNetwork), "{s}");
        }
        for s in ["::ffff:5db8:d907", "64:ff9b::5db8:d907", "2606:4700:11::7"] {
            assert_eq!(denied_by(v6(s), &host), None, "{s}");
        }
    }
}
