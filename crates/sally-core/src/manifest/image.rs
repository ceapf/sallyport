//! The one grammar for container image references (SI-11), shared by the manifest validator and
//! the `sallyd` argv builder so the two can never drift.
//!
//! Accepted: `[<registry>/]<path>[:<tag>]@sha256:<64 lowercase hex>` where
//! - `<registry>` is `localhost` or a dotted hostname, optionally with `:<port>`, and is only
//!   recognised in front of at least one more path segment;
//! - `<path>` is one or more `/`-separated components of lowercase letters, digits and `._-`,
//!   each starting and ending with a letter or digit;
//! - `<tag>` is only allowed when the reference has a `/` (a single-segment `name:tag` reads as a
//!   transport such as `oci:<dir>` to Podman).
//!
//! The point of the strictness is that Podman treats `<transport>:<rest>` (`dir:`, `oci:`,
//! `docker-archive:`, `docker-daemon:`, `containers-storage:`, `docker://` …) as an instruction
//! to load an image from a host path or another daemon even with `--pull=never`. No transport
//! name contains a `.` and none is `localhost`, so a reference this grammar accepts never starts
//! with one.

/// Longest accepted reference name (the part before `@sha256:`).
const MAX_NAME: usize = 255;
/// Longest accepted tag (OCI distribution spec).
const MAX_TAG: usize = 128;
/// Length of a hex SHA-256 digest.
const DIGEST_HEX: usize = 64;

/// Whether `s` is a digest-pinned image reference in the grammar above.
#[must_use]
pub fn is_pinned_image_ref(s: &str) -> bool {
    let Some((name, digest)) = s.split_once("@sha256:") else {
        return false;
    };
    digest_ok(digest) && name_ok(name)
}

fn digest_ok(d: &str) -> bool {
    d.len() == DIGEST_HEX
        && d.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn name_ok(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_NAME {
        return false;
    }
    let mut segs: Vec<&str> = name.split('/').collect();
    let has_slash = segs.len() > 1;
    if has_slash
        && segs
            .first()
            .is_some_and(|s| s.contains(['.', ':']) || *s == "localhost")
    {
        if !segs.first().is_some_and(|s| registry_ok(s)) {
            return false;
        }
        segs.remove(0);
    }
    let Some((last, path)) = segs.split_last() else {
        return false;
    };
    let last = match last.split_once(':') {
        Some((comp, tag)) if has_slash && tag_ok(tag) => comp,
        Some(_) => return false,
        None => last,
    };
    path.iter().chain([&last]).all(|c| component_ok(c))
}

/// `localhost` or a dotted hostname, optionally `:<port>`.
fn registry_ok(s: &str) -> bool {
    let (host, port) = match s.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (s, None),
    };
    let port_ok =
        port.is_none_or(|p| (1..=5).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit()));
    let host_ok = host == "localhost"
        || (host.contains('.')
            && host.split('.').all(|label| {
                !label.is_empty()
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            }));
    port_ok && host_ok
}

fn component_ok(c: &str) -> bool {
    let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    c.bytes().next().is_some_and(alnum)
        && c.bytes().last().is_some_and(alnum)
        && c.bytes()
            .all(|b| alnum(b) || matches!(b, b'.' | b'_' | b'-'))
}

fn tag_ok(t: &str) -> bool {
    t.len() <= MAX_TAG
        && t.bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_')
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::is_pinned_image_ref;

    fn d() -> String {
        "0123456789abcdef".repeat(4)
    }

    #[test]
    fn accepts_registry_short_and_tagged_references() {
        for name in [
            "ghcr.io/a/b",
            "sallyport/workspace",
            "workspace",
            "localhost/sandbox-base:1",
            "localhost:5000/x",
            "registry.example.com:443/team/img:v1.2",
            "a/b_c.d-e",
            // One segment is a name, never a registry, even when it reads like one.
            "localhost",
            "a.b",
            "reg-1.example.com/x",
        ] {
            assert!(
                is_pinned_image_ref(&format!("{name}@sha256:{}", d())),
                "{name}"
            );
        }
        // The name bound is inclusive: exactly 255 bytes pass.
        let longest = format!("{}/x", "a".repeat(253));
        assert_eq!(longest.len(), 255);
        assert!(is_pinned_image_ref(&format!("{longest}@sha256:{}", d())));
    }

    #[test]
    fn a_registry_port_is_one_to_five_digits() {
        for (name, ok) in [
            ("reg.io:1/x", true),
            ("reg.io:65535/x", true),
            ("reg.io:12a/x", false),
            ("reg.io:/x", false),
            ("reg.io:123456/x", false),
        ] {
            assert_eq!(
                is_pinned_image_ref(&format!("{name}@sha256:{}", d())),
                ok,
                "{name}"
            );
        }
    }

    #[test]
    fn refuses_transports_and_malformed_references() {
        for name in [
            "dir:/any/dir",
            "dir:5000/rel",
            "dir:rel",
            "oci:/x",
            "oci:foo",
            "oci-archive:/x.tar",
            "docker-archive:/x.tar",
            "docker-daemon:x",
            "containers-storage:x",
            "docker://ghcr.io/a",
            "sif:/x.sif",
            "ostree:x",
            "tarball:/x",
            "workspace:tag",
            "Ghcr.io/a",
            "ghcr.io/A",
            "-ghcr.io/a",
            ".a/b",
            "a/_b",
            "a//b",
            "a/b/",
            "/a/b",
            "ghcr.io:x/a",
            "ghcr.io:123456/a",
            "ghcr..io/a",
            "ghcr.-io/a",
            "a/b:",
            "a/b:-x",
            "a/b:c:d",
            "a b",
            "",
        ] {
            assert!(
                !is_pinned_image_ref(&format!("{name}@sha256:{}", d())),
                "{name:?}"
            );
        }
        let long = format!("{}/x", "a".repeat(254));
        assert!(!is_pinned_image_ref(&format!("{long}@sha256:{}", d())));
        assert!(!is_pinned_image_ref(&format!(
            "a/b:{}@sha256:{}",
            "t".repeat(129),
            d()
        )));
    }

    #[test]
    fn refuses_bad_digests() {
        let d = d();
        for s in [
            "a/b".to_owned(),
            format!("a/b@sha256:{}", &d[1..]),
            format!("a/b@sha256:{d}0"),
            format!("a/b@sha256:{}", d.to_uppercase()),
            format!("a/b@sha512:{d}"),
        ] {
            assert!(!is_pinned_image_ref(&s), "{s}");
        }
    }
}
