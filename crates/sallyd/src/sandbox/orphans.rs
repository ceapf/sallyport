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
//! The listing is one line per container, `<name as JSON> <labels as JSON object or null>`
//! ([`ps_args`]), so a label value holding a newline cannot forge a line (PROBE_NOTES). A line
//! that does not parse fails the whole sweep, never skips silently.

use std::ffi::OsString;

use serde_json::Value;

use super::types::{INSTALLATION_LABEL, Installation};

/// The name prefixes of session containers.
pub const SESSION_PREFIXES: [&str; 2] = ["sp-ws-", "sp-h-"];

/// `podman ps` arguments listing this installation's containers, one per line.
#[must_use]
pub fn ps_args(installation: &Installation) -> Vec<OsString> {
    [
        "ps".to_owned(),
        "--all".to_owned(),
        "--filter".to_owned(),
        format!("label={INSTALLATION_LABEL}={}", installation.as_str()),
        "--format".to_owned(),
        "{{json .Names}} {{json .Labels}}".to_owned(),
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}

/// A container to remove: its name, and the session id in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Orphan {
    /// The container name.
    pub name: String,
    /// The session id the name carries.
    pub id: String,
}

/// The orphans in `listing` (the output of [`ps_args`]).
///
/// # Errors
/// A line that is not a JSON string followed by a JSON object or `null`, naming the line number.
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
        let (name, labels) =
            parse_line(line).ok_or_else(|| format!("ps line {}: malformed", n + 1))?;
        let ours = labels
            .as_ref()
            .and_then(|l| l.get(INSTALLATION_LABEL))
            .and_then(Value::as_str)
            .is_some_and(|v| v == installation.as_str());
        if !ours {
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
            name,
        });
    }
    Ok(out)
}

/// `<string> <object|null>` and nothing else.
fn parse_line(line: &str) -> Option<(String, Option<serde_json::Map<String, Value>>)> {
    let mut values = serde_json::Deserializer::from_str(line).into_iter::<Value>();
    let name = match values.next()?.ok()? {
        Value::String(s) => s,
        _ => return None,
    };
    let labels = match values.next()?.ok()? {
        Value::Object(m) => Some(m),
        Value::Null => None,
        _ => return None,
    };
    values.next().is_none().then_some((name, labels))
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

    const OWN: &str = "0123abcd-ef01-4234-8567-89abcdef0123";
    const OTHER: &str = "fedcba98-7654-4321-8fed-cba987654321";

    fn own() -> Installation {
        Installation::parse(OWN).unwrap()
    }

    fn line(name: &str, label: Option<&str>) -> String {
        let labels = label.map_or(
            Value::Null,
            |v| serde_json::json!({ INSTALLATION_LABEL: v, "other": "x" }),
        );
        format!("{} {labels}", Value::String(name.to_owned()))
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
                "--filter",
                &format!("label=sallyport.installation={OWN}"),
                "--format",
                "{{json .Names}} {{json .Labels}}",
            ]
        );
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

    #[test]
    fn a_label_that_is_not_a_string_is_not_this_installations() {
        let listing = format!(
            "\"sp-ws-a-1\" {{\"{INSTALLATION_LABEL}\": 7}}\n\"sp-ws-a-2\" {{\"other\": \"{OWN}\"}}"
        );
        assert!(names(&listing, "", &[]).is_empty());
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
        let forged = format!("{OWN}\n\"sp-ws-victim\" {{\"{INSTALLATION_LABEL}\": \"{OWN}\"}}");
        let listing = line("sp-ws-a-1", Some(&forged));
        assert_eq!(listing.lines().count(), 1);
        assert!(names(&listing, "", &[]).is_empty());
    }

    #[test]
    fn a_malformed_line_fails_the_sweep() {
        for bad in [
            "sp-ws-a-1",
            "\"sp-ws-a-1\"",
            "\"sp-ws-a-1\" {",
            "\"sp-ws-a-1\" [] ",
            "\"sp-ws-a-1\" null null",
            "7 null",
            // A listing cut at the output cap.
            "\"sp-ws-a-1\" {\"sallyport.installation\":\"0123",
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
}
