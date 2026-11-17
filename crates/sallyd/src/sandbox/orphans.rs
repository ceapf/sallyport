//! Which listed containers an orphan sweep removes (architect Q61, Q64): pure, so its every
//! branch is tested without a container.
//!
//! A container is an orphan only when all of these hold:
//! - it carries [`INSTALLATION_LABEL`] equal to this installation's id. A container with no
//!   label, or another installation's (another daemon, a test run), is never removed. The listing
//!   is pre-filtered by podman on the label, and the value is compared again here;
//! - its name is a session container's (`sp-ws-<id>`, `sp-h-<id>`) with a plain id inside the
//!   sweep's scope;
//! - no live session owns that id.
//!
//! The listing is one line per container, `<full ID> <name> <installation label>`, each a JSON
//! string ([`ps_args`]; podman prints `""` for a missing label), so a label value holding a
//! newline cannot forge a line (PROBE_NOTES). Only that one label is asked for, never the whole
//! set: a container's labels include its image's, so a line would otherwise be as long as an
//! image author likes (architect Q307). A line is daemon-bounded (ID, name and UUID, at most
//! 179 bytes), so about 360 containers fit under the launcher's 64 KiB stdout cap; a longer
//! listing is refused there (#173). The live sessions are bounded so their worst listing fits
//! with room to spare ([`super::budget::MAX_LIVE_SESSIONS`], checked when a launch reserves its
//! id; the relation is tested below). Inference instances and outside-made containers are not
//! counted, which leaves a residual (TODO(#134)). A line that does not parse fails the whole sweep, never
//! skips silently. An orphan is removed by its full ID, never its name, which a new container
//! could have taken since the listing.

use std::ffi::OsString;

use serde_json::Value;

use super::types::{INSTALLATION_LABEL, Installation};

/// The name prefixes of session containers. An inference instance (`sp-infer-<id>`) is not a
/// session: its liveness is not in `Sessions`, so it is not swept here. TODO(#134): sweep
/// instances against their own liveness set before any RPC reaches the inference launch.
pub const SESSION_PREFIXES: [&str; 2] = ["sp-ws-", "sp-h-"];

/// `podman ps` arguments listing this installation's containers, one per line.
#[must_use]
pub fn ps_args(installation: &Installation) -> Vec<OsString> {
    [
        "ps".to_owned(),
        "--all".to_owned(),
        "--no-trunc".to_owned(),
        "--filter".to_owned(),
        format!("label={INSTALLATION_LABEL}={}", installation.as_str()),
        "--format".to_owned(),
        format!(
            "{{{{json .ID}}}} {{{{json .Names}}}} {{{{json (index .Labels \"{INSTALLATION_LABEL}\")}}}}"
        ),
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}

/// A container to remove: its full ID (what `podman rm` is given), its name, and the session id
/// in the name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Orphan {
    /// The full container ID: 64 lowercase hex digits.
    pub container: String,
    /// The container name.
    pub name: String,
    /// The session id the name carries.
    pub id: String,
}

/// One parsed listing line. Named fields, so the ID and the name cannot be swapped.
struct Listed {
    /// The full container ID.
    container: String,
    /// The container name.
    name: String,
    /// Its [`INSTALLATION_LABEL`] value; podman prints `""` for a container without it.
    label: String,
}

/// The orphans in `listing` (the output of [`ps_args`]).
///
/// # Errors
/// A line that is not exactly three JSON strings (a full container ID, a name and the
/// installation label), naming the line number. Any other label value or a fourth value is one.
pub fn orphans(
    listing: &str,
    installation: &Installation,
    scope: &str,
    is_live: impl Fn(&str) -> bool,
) -> Result<Vec<Orphan>, String> {
    let mut out = Vec::new();
    for (n, line) in listing.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let Listed {
            container,
            name,
            label,
        } = parse_line(line).ok_or_else(|| format!("ps line {}: malformed", n + 1))?;
        if label != installation.as_str() {
            continue;
        }
        let Some(id) = SESSION_PREFIXES
            .iter()
            .find_map(|p| name.strip_prefix(p))
            .filter(|id| plain_name(id) && in_scope(id, scope))
        else {
            continue;
        };
        if is_live(id) {
            continue;
        }
        out.push(Orphan {
            id: id.to_owned(),
            container,
            name,
        });
    }
    Ok(out)
}

/// `<string: full ID> <string: name> <string: label>` and nothing else.
fn parse_line(line: &str) -> Option<Listed> {
    let mut values = serde_json::Deserializer::from_str(line).into_iter::<Value>();
    let mut string = || match values.next()?.ok()? {
        Value::String(s) => Some(s),
        _ => None,
    };
    let container = string().filter(|c| full_id(c))?;
    let name = string()?;
    let label = string()?;
    values.next().is_none().then_some(Listed {
        container,
        name,
        label,
    })
}

/// 64 lowercase hex digits, as `podman ps --no-trunc` prints an ID.
fn full_id(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `id` is inside `scope` (empty: everything), which ends at a dash.
fn in_scope(id: &str, scope: &str) -> bool {
    scope.is_empty() || id == scope || id.strip_prefix(scope).is_some_and(|r| r.starts_with('-'))
}

/// `[a-z0-9-]`, as session ids are.
fn plain_name(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::sandbox::budget::MAX_LIVE_SESSIONS;
    use crate::sandbox::commands::OUTPUT_CAP;
    use crate::sandbox::launch::stdout_text;
    use crate::sandbox::types::SessionId;

    const OWN: &str = "0123abcd-ef01-4234-8567-89abcdef0123";
    const OTHER: &str = "fedcba98-7654-4321-8fed-cba987654321";

    fn own() -> Installation {
        Installation::parse(OWN).unwrap()
    }

    /// A container ID derived from its name, so each test container has its own.
    fn cid(name: &str) -> String {
        let mut h = [0u8; 32];
        for (i, b) in name.bytes().enumerate() {
            let at = i % 32;
            h[at] = h[at].wrapping_mul(31).wrapping_add(b);
        }
        h.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// A listing line as podman prints it: a missing label is `""` (PROBE_NOTES, Q307).
    fn line(name: &str, label: Option<&str>) -> String {
        format!(
            "\"{}\" {} {}",
            cid(name),
            Value::String(name.to_owned()),
            Value::String(label.unwrap_or_default().to_owned())
        )
    }

    fn names(listing: &str, scope: &str, live: &[&str]) -> Vec<String> {
        orphans(listing, &own(), scope, |id| live.contains(&id))
            .unwrap()
            .into_iter()
            .map(|o| o.name)
            .collect()
    }

    #[test]
    fn the_listing_asks_podman_for_this_installations_label() {
        let args: Vec<String> = ps_args(&own())
            .into_iter()
            .map(|a| a.into_string().unwrap())
            .collect();
        assert_eq!(
            args,
            [
                "ps",
                "--all",
                "--no-trunc",
                "--filter",
                &format!("label=sallyport.installation={OWN}"),
                "--format",
                "{{json .ID}} {{json .Names}} {{json (index .Labels \"sallyport.installation\")}}",
            ]
        );
    }

    /// The removal names the listed container by its full ID (security review PS-L5): a name
    /// re-used between the listing and the removal is another container, and not equal.
    #[test]
    fn an_orphan_carries_its_full_container_id() {
        let listing = line("sp-ws-a-1", Some(OWN));
        let o = orphans(&listing, &own(), "", |_| false).unwrap();
        assert_eq!(o.len(), 1);
        assert_eq!(o[0].container, cid("sp-ws-a-1"));
        assert_eq!(o[0].container.len(), 64);
        let reused = listing.replacen(&cid("sp-ws-a-1"), &cid("sp-ws-a-1x"), 1);
        let again = orphans(&reused, &own(), "", |_| false).unwrap();
        assert_eq!(again[0].name, o[0].name);
        assert_ne!(again, o);
        // Every hex digit, `a` to `f` and `0` to `9`, is one.
        for id in ["0123456789abcdef".repeat(4), "f9".repeat(32)] {
            let l = format!("\"{id}\" \"sp-ws-a-1\" \"{OWN}\"");
            let o = orphans(&l, &own(), "", |_| false).unwrap();
            assert_eq!(o[0].container, id);
        }
    }

    #[test]
    fn only_this_installations_unowned_session_containers_are_orphans() {
        let listing = [
            line("sp-ws-a-1", Some(OWN)),
            line("sp-h-a-2", Some(OWN)),
            line("sp-ws-a-3", None),         // no label: a foreign container
            line("sp-ws-a-4", Some(OTHER)),  // another installation
            line("other-a-5", Some(OWN)),    // label without the prefix
            line("sp-infer-a-6", Some(OWN)), // not a session container
            line("sp-ws-a-7", Some(&format!("{OWN}x"))), // a longer value
            line("sp-ws-a-8", Some(&OWN.to_uppercase())),
            line("sp-ws-a-9", Some(OWN)),  // live
            line("sp-ws-A-10", Some(OWN)), // not a plain id
            line("sp-ws-", Some(OWN)),     // no id
        ]
        .join("\n");
        assert_eq!(names(&listing, "", &["a-9"]), ["sp-ws-a-1", "sp-h-a-2"]);
        let o = orphans(&listing, &own(), "", |_| false).unwrap();
        assert_eq!(o[0].id, "a-1");
        assert_eq!(o[1].id, "a-2");
    }

    /// Architect Q307: podman prints the label as a JSON string (`""` when missing), so any other
    /// value is not podman's format and fails the sweep. This includes the old labels-object
    /// form, which once carried every image label.
    #[test]
    fn a_label_that_is_not_a_string_fails_the_sweep() {
        let a = cid("a");
        for bad in [
            "7".to_owned(),
            "null".to_owned(),
            "true".to_owned(),
            format!("[\"{OWN}\"]"),
            format!("{{\"{INSTALLATION_LABEL}\": \"{OWN}\"}}"),
            "{}".to_owned(),
        ] {
            let listing = format!("\"{a}\" \"sp-ws-a-1\" {bad}");
            let e = orphans(&listing, &own(), "", |_| false).unwrap_err();
            assert_eq!(e, "ps line 1: malformed", "{bad:?}");
        }
    }

    #[test]
    fn a_scope_keeps_the_sweep_inside_it() {
        let listing = [
            line("sp-ws-t1-1-a", Some(OWN)),
            line("sp-ws-t1-10-a", Some(OWN)),
            line("sp-ws-t1-1", Some(OWN)),
        ]
        .join("\n");
        assert_eq!(names(&listing, "t1-1", &[]), ["sp-ws-t1-1-a", "sp-ws-t1-1"]);
    }

    #[test]
    fn a_newline_in_a_label_cannot_forge_a_line() {
        let victim = format!("\"{}\" \"sp-ws-victim\" \"{OWN}\"", cid("victim"));
        // On a line of its own the payload is an orphan, so only the escape keeps it out.
        assert_eq!(names(&victim, "", &[]), ["sp-ws-victim"]);
        let listing = line("sp-ws-a-1", Some(&format!("{OWN}\n{victim}")));
        assert_eq!(listing.lines().count(), 1);
        assert!(names(&listing, "", &[]).is_empty());
    }

    #[test]
    fn a_malformed_line_fails_the_sweep() {
        let id = "0fab".repeat(16);
        let short = &id[..12];
        let upper = id.to_uppercase();
        // Each line below is well-formed but for one fault, so that fault alone refuses it.
        assert_eq!(
            names(&format!("\"{id}\" \"sp-ws-a-1\" \"{OWN}\""), "", &[]),
            ["sp-ws-a-1"]
        );
        for bad in [
            "sp-ws-a-1".to_owned(),
            format!("\"{id}\" \"sp-ws-a-1\""),
            format!("\"{id}\" \"sp-ws-a-1\" {{"),
            format!("\"{id}\" \"sp-ws-a-1\" [] "),
            format!("\"{id}\" \"sp-ws-a-1\" \"{OWN}\" \"{OWN}\""),
            format!("\"{id}\" \"sp-ws-a-1\" \"{OWN}\" null"),
            format!("\"{id}\" 7 \"{OWN}\""),
            // The name where the ID belongs (the old two-field form).
            format!("\"sp-ws-a-1\" \"{OWN}\""),
            // An ID that is not 64 lowercase hex digits: truncated, uppercase, too long, a name.
            format!("\"{short}\" \"sp-ws-a-1\" \"{OWN}\""),
            format!("\"{upper}\" \"sp-ws-a-1\" \"{OWN}\""),
            format!("\"{id}0\" \"sp-ws-a-1\" \"{OWN}\""),
            format!("\"{}g\" \"sp-ws-a-1\" \"{OWN}\"", &id[..63]),
            format!("\"{}`\" \"sp-ws-a-1\" \"{OWN}\"", &id[..63]),
            format!("\"{}/\" \"sp-ws-a-1\" \"{OWN}\"", &id[..63]),
            format!("\"sp-ws-a-1\" \"sp-ws-a-1\" \"{OWN}\""),
            format!("7 \"sp-ws-a-1\" \"{OWN}\""),
            // A line cut inside the label.
            format!("\"{id}\" \"sp-ws-a-1\" \"0123"),
        ] {
            let listing = format!("{}\n{bad}", line("sp-ws-a-0", Some(OWN)));
            let e = orphans(&listing, &own(), "", |_| false).unwrap_err();
            assert_eq!(e, "ps line 2: malformed", "{bad:?}");
        }
        assert!(orphans("\n  \n", &own(), "", |_| false).unwrap().is_empty());
    }

    #[test]
    fn orphan_scope_ends_at_a_dash() {
        assert!(in_scope("t1-1-a", "t1-1"));
        assert!(in_scope("t1-1", "t1-1"));
        assert!(in_scope("anything", ""));
        assert!(!in_scope("t1-10-a", "t1-1"));
        assert!(!in_scope("t1-1a", "t1-1"));
    }

    #[test]
    fn orphan_names_are_plain() {
        assert!(plain_name("t1-0-a"));
        for bad in ["", "A", "a b", "a/b", "a;b", "a_b"] {
            assert!(!plain_name(bad), "{bad:?}");
        }
    }

    /// The longest listing line a session container can have, newline included: a full ID, the
    /// longer session prefix with a 64-character id, and an installation UUID, each a JSON
    /// string ([`ps_args`]).
    const MAX_PS_LINE: usize = 179;

    /// Listing lines counted per live session: twice its two containers ([`SESSION_PREFIXES`]),
    /// the factor of two being margin.
    const LINES_PER_SESSION: usize = 4;

    /// Listing room no live session accounts for: inference instances, which the sweep lists but
    /// `Sessions` does not count (TODO(#134)), and leftovers of killed predecessors or
    /// containers made outside this daemon under its label.
    const HEADROOM: usize = 16 * 1024;

    /// The longest line `name` can have as podman prints it, newline included.
    fn listed(name: &str) -> String {
        format!("{}\n", line(name, Some(OWN)))
    }

    #[test]
    fn max_ps_line_is_the_longest_line_a_session_container_has() {
        let id = "a".repeat(64);
        assert!(SessionId::parse(&id).is_ok(), "64 characters is an id");
        assert!(SessionId::parse(&format!("{id}a")).is_err(), "65 is not");
        let longest = SESSION_PREFIXES
            .iter()
            .map(|p| listed(&format!("{p}{id}")).len())
            .max()
            .unwrap();
        assert_eq!(longest, MAX_PS_LINE);
    }

    #[test]
    fn the_listing_of_the_most_live_sessions_leaves_the_headroom_under_the_cap() {
        let worst = LINES_PER_SESSION * MAX_LIVE_SESSIONS * MAX_PS_LINE;
        assert!(
            worst + HEADROOM <= OUTPUT_CAP,
            "{worst} + {HEADROOM} > {OUTPUT_CAP}"
        );
    }

    /// The worst listing of [`MAX_LIVE_SESSIONS`] sessions, every line as long as a line gets,
    /// goes through the launcher's stdout check and parses; the cap refuses the listing one
    /// session's block past what fits, so the limit is what keeps the sweep working.
    #[test]
    fn the_session_limit_keeps_the_worst_listing_under_the_cap() {
        let block = |n: usize| -> String {
            (0..LINES_PER_SESSION)
                .map(|k| {
                    let l = listed(&format!("sp-ws-{:a<64}", format!("{n}-{k}")));
                    assert_eq!(l.len(), MAX_PS_LINE, "{l}");
                    l
                })
                .collect()
        };
        let listing = |sessions: usize| -> String { (0..sessions).map(block).collect() };

        let worst = listing(MAX_LIVE_SESSIONS);
        let text = stdout_text("ps", worst.as_bytes(), OUTPUT_CAP).unwrap();
        let found = orphans(&text, &own(), "", |_| false).unwrap();
        assert_eq!(found.len(), LINES_PER_SESSION * MAX_LIVE_SESSIONS);

        let fits = OUTPUT_CAP / (LINES_PER_SESSION * MAX_PS_LINE);
        assert!(MAX_LIVE_SESSIONS < fits, "{MAX_LIVE_SESSIONS} >= {fits}");
        assert!(stdout_text("ps", listing(fits).as_bytes(), OUTPUT_CAP).is_ok());
        assert!(stdout_text("ps", listing(fits + 1).as_bytes(), OUTPUT_CAP).is_err());
    }
}
