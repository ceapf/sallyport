//! The egress address filter (SI-9): a resolved address passes only if it is global unicast and
//! not one the host itself owns. IPv6 forms that carry an IPv4 address (v4-mapped, NAT64
//! `64:ff9b::/96`, 6to4 `2002::/16`) are judged by that IPv4 address.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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

/// Whether `addr` is inside `net/len` (`len` in 1..=32).
fn in_v4(addr: u32, (net, len): (u32, u32)) -> bool {
    let mask = u32::MAX.checked_shl(32 - len).unwrap_or(0);
    addr & mask == net
}

/// Whether `addr` is inside `net/len` (`len` in 1..=128).
fn in_v6(addr: u128, (net, len): (u128, u32)) -> bool {
    let mask = u128::MAX.checked_shl(128 - len).unwrap_or(0);
    addr & mask == net
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

/// Whether the proxy must refuse to connect to `ip`: not global unicast, or owned by this host
/// (`own`, compared both as given and by the IPv4 address an IPv6 form carries).
#[must_use]
pub fn is_denied(ip: IpAddr, own: &[IpAddr]) -> bool {
    let carried = match ip {
        IpAddr::V6(a) => embedded_v4(a).map(IpAddr::V4),
        IpAddr::V4(_) => None,
    };
    if own.contains(&ip) || carried.is_some_and(|c| own.contains(&c)) {
        return true;
    }
    match ip {
        IpAddr::V4(a) => v4_denied(a),
        IpAddr::V6(a) => v6_denied(a),
    }
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
}
