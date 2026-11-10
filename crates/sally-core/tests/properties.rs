//! Property tests (AMENDMENTS-01 §15): the egress wildcard matcher and manifest round-trips.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use proptest::prelude::*;
use sally_core::manifest::{HostPattern, parse_host_pattern};

// Labels from 1 to 63 characters; length extremes are covered by tests/limits.rs.
const LABEL: &str = "[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?";

fn hostname(max_labels: usize) -> impl Strategy<Value = String> {
    prop::collection::vec(LABEL, 1..=max_labels).prop_map(|l| l.join("."))
}

proptest! {
    /// `*.base` matches strict subdomains and nothing else: not the base itself, not a
    /// host that merely ends with the base's text, not the base with more labels after it.
    #[test]
    fn suffix_wildcard_matches_exactly_strict_subdomains(
        sub in hostname(3),
        base in hostname(2).prop_map(|b| format!("{b}.example")),
        junk in LABEL,
    ) {
        let p = parse_host_pattern(&format!("*.{base}")).unwrap();
        let subdomain = format!("{sub}.{base}");
        let longer = format!("{base}.{junk}");
        let glued = format!("{junk}{base}");
        let empty_label = format!(".{base}");
        prop_assert!(matches!(p, HostPattern::Suffix(_)));
        prop_assert!(p.matches(&subdomain));
        prop_assert!(!p.matches(&base));
        prop_assert!(!p.matches(&longer));
        prop_assert!(!p.matches(&glued));
        prop_assert!(!p.matches(&empty_label));
    }

    /// An exact rule matches only its own name.
    #[test]
    fn exact_rule_matches_only_itself(a in hostname(3), b in hostname(3)) {
        let a = format!("{a}.example");
        let b = format!("{b}.example");
        let p = parse_host_pattern(&a).unwrap();
        prop_assert!(p.matches(&a));
        prop_assert_eq!(p.matches(&b), a == b);
    }

    /// Parsing never panics on arbitrary input (including controls, NUL and bidi/zero-width
    /// characters), and anything accepted round-trips through `Display` to the same pattern.
    #[test]
    fn host_pattern_parse_is_total_and_round_trips(
        s in prop_oneof![
            any::<String>(),
            "[a-z0-9.*-]{0,80}",
            hostname(4).prop_map(|h| format!("*.{h}")),
            hostname(4).prop_map(|h| format!("{h}.example")),
        ]
    ) {
        if let Ok(p) = parse_host_pattern(&s) {
            prop_assert_eq!(parse_host_pattern(&p.to_string()).unwrap(), p);
        }
    }

    /// A name whose last label is numeric is an IP spelling, never a hostname rule.
    #[test]
    fn numeric_last_label_is_an_ip_literal(h in hostname(3), n in "[0-9]{1,5}|0x[0-9a-f]{1,4}") {
        let name = format!("{h}.{n}");
        prop_assert!(parse_host_pattern(&name).is_err());
    }
}
