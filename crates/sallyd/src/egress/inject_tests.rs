//! Credentials (Task 9a-3): rendering, the per-host injection, the refusals, and the redaction
//! built with them. Allow and deny for `secrets[].name`, `inject.host` and `header/format`
//! (MANIFEST_SPEC §3).
#![allow(clippy::unwrap_used)]

use hyper::http::header;

use super::*;

/// A value assembled at runtime: no credential-shaped literal in the tree.
fn value(tag: &str) -> String {
    format!("{tag}-{}", "v".repeat(20))
}

fn spec(name: &str, host: &str, header: &str, format: &str) -> Spec {
    Spec {
        name: name.into(),
        host: host.into(),
        header: header.into(),
        format: format.into(),
        basic_user: None,
    }
}

fn basic(name: &str, host: &str, user: &str) -> Spec {
    Spec {
        basic_user: Some(user.into()),
        ..spec(name, host, "Authorization", "Basic {basic}")
    }
}

/// RFC 7617's blob, computed here by hand (standard alphabet, padded), not by sally-core.
fn blob(user: &str, secret: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let data = format!("{user}:{secret}").into_bytes();
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = |i: usize| u32::from(chunk.get(i).copied().unwrap_or(0));
        let n = (b(0) << 16) | (b(1) << 8) | b(2);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn values(names: &[&str]) -> Vec<(String, Secret<String>)> {
    names
        .iter()
        .map(|n| ((*n).to_owned(), Secret::new(value(n))))
        .collect()
}

fn bearer(name: &str, host: &str) -> Spec {
    spec(name, host, "Authorization", "Bearer {value}")
}

#[test]
fn a_grant_host_gets_its_rendered_header_replacing_any_client_copy() {
    let c = Credentials::new(&[bearer("GH", "a.mock.test")], values(&["GH"])).unwrap();
    let mut h = HeaderMap::new();
    h.append(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer attacker"),
    );
    h.append(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer two"),
    );
    h.insert(header::ACCEPT, HeaderValue::from_static("*/*"));
    // Architect Q2: this test alone tells `insert` from `append` (RT-SEC-04 guards the pair).
    assert_eq!(set(&c, "a.mock.test", &mut h), ["secret:GH"]);
    let all: Vec<_> = h.get_all(header::AUTHORIZATION).iter().collect();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0], format!("Bearer {}", value("GH")).as_str());
    assert!(all[0].is_sensitive());
    assert_eq!(h.get(header::ACCEPT).unwrap(), "*/*");
}

/// Prepares `host`'s grant headers, applies them to `h`, and returns the names it reported.
fn set(c: &Credentials, host: &str, h: &mut HeaderMap) -> Vec<String> {
    let p = c.prepare(host);
    let names = p.names().to_vec();
    p.apply(h);
    names
}

#[test]
fn another_grants_credential_is_never_set_on_this_host() {
    let specs = [bearer("GH", "a.mock.test"), bearer("OTHER", "b.mock.test")];
    let c = Credentials::new(&specs, values(&["GH", "OTHER"])).unwrap();
    let mut h = HeaderMap::new();
    assert_eq!(set(&c, "b.mock.test", &mut h), ["secret:OTHER"]);
    assert_eq!(
        h.get(header::AUTHORIZATION).unwrap(),
        format!("Bearer {}", value("OTHER")).as_str()
    );
    let mut none = HeaderMap::new();
    assert!(set(&c, "c.mock.test", &mut none).is_empty());
    assert!(none.is_empty());
}

/// Architect ruling Q4: the names `egress.request` reports are exactly the headers set, in order;
/// a prepared set shows its names and never a value.
#[test]
fn a_host_with_two_grants_gets_both_headers_and_reports_them_in_order() {
    let specs = [
        bearer("GH", "a.mock.test"),
        spec("KEY", "a.mock.test", "X-Api-Key", "{value}"),
    ];
    let c = Credentials::new(&specs, values(&["GH", "KEY"])).unwrap();
    let p = c.prepare("a.mock.test");
    let shown = format!("{p:?}");
    assert!(
        shown.contains("secret:GH") && shown.contains("secret:KEY"),
        "{shown}"
    );
    assert!(!shown.contains(&value("GH")) && !shown.contains(&value("KEY")));
    let mut h = HeaderMap::new();
    let names = p.names().to_vec();
    p.apply(&mut h);
    let set_order: Vec<&str> = h.keys().map(|k| k.as_str()).collect();
    assert_eq!(set_order, ["authorization", "x-api-key"]);
    assert_eq!(names, ["secret:GH", "secret:KEY"]);
    assert_eq!(h.get("x-api-key").unwrap(), value("KEY").as_str());
    assert!(h.get("x-api-key").unwrap().is_sensitive());
    assert_eq!(c.hosts(), ["a.mock.test"]);
}

#[test]
fn hosts_are_listed_once_in_grant_order() {
    let specs = [
        bearer("A", "b.mock.test"),
        bearer("B", "a.mock.test"),
        spec("A", "b.mock.test", "X-Key", "{value}"),
    ];
    let c = Credentials::new(&specs, values(&["A", "B"])).unwrap();
    assert_eq!(c.hosts(), ["b.mock.test", "a.mock.test"]);
}

#[test]
fn a_grant_whose_secret_is_missing_is_refused_by_name() {
    let specs = [bearer("GH", "a.mock.test"), bearer("GONE", "b.mock.test")];
    let err = Credentials::new(&specs, values(&["GH"])).unwrap_err();
    assert_eq!(err, CredentialsError::Missing("GONE".into()));
    assert!(!err.to_string().contains(&value("GH")));
}

/// Task 9b (#80): a `{basic}` grant gets `base64(basic_user:secret)` at its placeholder, for
/// every user length (1, 2, 3 bytes put the secret at all three base64 alignments).
#[test]
fn a_basic_grant_gets_the_padded_base64_of_user_colon_secret() {
    for user in ["x", "ab", "git", "x-access-token"] {
        let c = Credentials::new(&[basic("GH", "a.mock.test", user)], values(&["GH"])).unwrap();
        let mut h = HeaderMap::new();
        assert_eq!(set(&c, "a.mock.test", &mut h), ["secret:GH"]);
        let want = format!("Basic {}", blob(user, &value("GH")));
        assert_eq!(
            h.get(header::AUTHORIZATION).unwrap(),
            want.as_str(),
            "{user}"
        );
        assert!(h.get(header::AUTHORIZATION).unwrap().is_sensitive());
    }
    // The placeholder anywhere in the format, text kept on both sides.
    let s = Spec {
        basic_user: Some("u".into()),
        ..spec("GH", "a.mock.test", "X-Git", "a {basic} b")
    };
    let c = Credentials::new(&[s], values(&["GH"])).unwrap();
    let mut h = HeaderMap::new();
    let _ = set(&c, "a.mock.test", &mut h);
    let want = format!("a {} b", blob("u", &value("GH")));
    assert_eq!(h.get("x-git").unwrap(), want.as_str());
}

/// Architect ruling A2 condition 1: `render` is a full second guard behind the validator.
/// Exactly one placeholder in all, `basic_user` exactly with `{basic}`, and a user that is
/// neither empty nor holds `:`.
#[test]
fn a_format_and_user_that_do_not_pair_are_refused() {
    let with_user = |format: &str, user: Option<&str>| Spec {
        basic_user: user.map(str::to_owned),
        ..spec("GH", "a.mock.test", "Authorization", format)
    };
    for s in [
        with_user("{value} {basic}", Some("u")),
        with_user("{value} {basic}", None),
        with_user("{basic} {basic}", Some("u")),
        with_user("Basic {basic}", None),
        with_user("Bearer {value}", Some("u")),
        with_user("Basic {basic}", Some("")),
        with_user("Basic {basic}", Some("a:b")),
        with_user("Basic {basic}", Some(":")),
        with_user("Basic", Some("u")),
    ] {
        assert_eq!(
            Credentials::new(std::slice::from_ref(&s), values(&["GH"])).unwrap_err(),
            CredentialsError::Format("GH".into()),
            "{s:?}"
        );
    }
}

#[test]
fn a_format_without_exactly_one_value_placeholder_is_refused() {
    for f in ["Bearer", "{value} {value}", "{valu}", "{basic}", ""] {
        let s = spec("GH", "a.mock.test", "Authorization", f);
        assert_eq!(
            Credentials::new(&[s], values(&["GH"])).unwrap_err(),
            CredentialsError::Format("GH".into()),
            "{f}"
        );
    }
    for f in ["{value}", "token {value}", "{value};", "a{value}b"] {
        let s = spec("GH", "a.mock.test", "Authorization", f);
        let c = Credentials::new(&[s], values(&["GH"])).unwrap();
        let mut h = HeaderMap::new();
        let _ = set(&c, "a.mock.test", &mut h);
        let want = f.replace("{value}", &value("GH"));
        assert_eq!(h.get(header::AUTHORIZATION).unwrap(), want.as_str(), "{f}");
    }
}

#[test]
fn the_same_header_twice_on_one_host_is_refused_whatever_its_case() {
    let specs = [
        bearer("A", "a.mock.test"),
        spec("B", "a.mock.test", "AUTHORIZATION", "{value}"),
    ];
    assert_eq!(
        Credentials::new(&specs, values(&["A", "B"])).unwrap_err(),
        CredentialsError::Duplicate {
            host: "a.mock.test".into(),
            header: "authorization".into(),
        }
    );
    let other_host = [bearer("A", "a.mock.test"), bearer("B", "b.mock.test")];
    assert!(Credentials::new(&other_host, values(&["A", "B"])).is_ok());
}

#[test]
fn a_header_name_or_rendered_value_that_cannot_be_sent_is_refused() {
    let bad_name = spec("GH", "a.mock.test", "Bad Header", "{value}");
    let bad_value = spec(
        "GH",
        "a.mock.test",
        "Authorization",
        "Bearer {value}\r\nX: y",
    );
    for s in [bad_name, bad_value] {
        assert_eq!(
            Credentials::new(&[s], values(&["GH"])).unwrap_err(),
            CredentialsError::Header("GH".into())
        );
    }
}

#[test]
fn a_rendered_value_too_long_to_redact_is_refused() {
    let format = format!("{}{{value}}", "x".repeat(super::super::redact::MAX_FORM));
    let s = spec("GH", "a.mock.test", "Authorization", &format);
    assert!(matches!(
        Credentials::new(&[s], values(&["GH"])),
        Err(CredentialsError::TooLong(_))
    ));
}

/// Allow (Rust review H1): the largest value the store accepts, made of a character every
/// percent-encoder escapes (three bytes each), still builds.
#[test]
fn the_largest_store_value_builds() {
    use sally_core::secrets::MAX_VALUE_BYTES;
    let s = spec("GH", "a.mock.test", "Authorization", "Bearer {value}");
    let v = vec![("GH".to_owned(), Secret::new("!".repeat(MAX_VALUE_BYTES)))];
    assert!(Credentials::new(&[s], v).is_ok());
}

/// The bound covers the longest form of the largest store value (its percent-encoding, three
/// bytes per byte) plus the longest format the manifest accepts (1024 bytes). Checked when the
/// tests compile, so a smaller bound does not build.
const _: () =
    assert!(3 * sally_core::secrets::MAX_VALUE_BYTES + 1024 <= super::super::redact::MAX_FORM);

#[test]
fn the_redaction_covers_every_secret_its_forms_and_each_rendered_value() {
    let specs = [
        bearer("GH", "a.mock.test"),
        spec("KEY", "b.mock.test", "X-Api-Key", "k={value}"),
        spec("GH", "c.mock.test", "X-Token", "tok {value} end"),
    ];
    let c = Credentials::new(&specs, values(&["GH", "KEY", "UNUSED"])).unwrap();
    let r = c.redaction();
    let gh = value("GH");
    // Architect D4: a response from a.mock.test echoing b.mock.test's secret is redacted too.
    for echo in [
        gh.clone(),
        value("KEY"),
        format!("Bearer {gh}"),
        format!("tok {gh} end"),
        format!("k={}", value("KEY")),
    ] {
        let s = r.scan(echo.as_bytes());
        assert_eq!(s.first, Some(0), "{echo}");
        assert_eq!(s.bytes.len(), echo.len());
        assert!(!String::from_utf8_lossy(&s.bytes).contains(&gh));
    }
    // A value no grant names is not kept, so it is not redacted.
    assert_eq!(r.scan(value("UNUSED").as_bytes()).first, None);
    // The longest form: the 24-byte KEY value's base64 at alignment 0 (32 characters), longer
    // than "tok " + GH's value + " end" (31).
    assert_eq!((value("KEY").len(), gh.len() + 8), (24, 31));
    assert_eq!(r.longest(), 32);
}

/// AMENDMENTS-02 B1 (architect ruling A2): a `{basic}` grant's redaction covers the rendered
/// value, the whole blob with its padding, and the blob with the padding stripped. Each check
/// covers bytes the secret's own forms cannot: the `Basic ` prefix, and the blob's first
/// characters (the user's) and its last.
#[test]
fn a_basic_grants_redaction_covers_its_rendered_value_and_blob_with_and_without_padding() {
    let fill = |n: usize| "*".repeat(n);
    // 25, 26 and 27 bytes of `user:secret`: two, one and no padding characters.
    for user in ["x", "ab", "git"] {
        let b = blob(user, &value("GH"));
        let c = Credentials::new(&[basic("GH", "a.mock.test", user)], values(&["GH"])).unwrap();
        let r = c.redaction();
        assert_eq!(r.filler(), b'*');
        let rendered = format!("Basic {b}");
        assert_eq!(
            r.bytes(rendered.as_bytes()),
            fill(rendered.len()).as_bytes()
        );
        assert_eq!(r.bytes(b.as_bytes()), fill(b.len()).as_bytes(), "{user}");
        let bare = b.trim_end_matches('=');
        let echo = format!("\"{bare}\"");
        let want = format!("\"{}\"", fill(bare.len()));
        assert_eq!(r.bytes(echo.as_bytes()), want.as_bytes(), "{user}");
    }
}

/// Allow (architect ruling A2 condition 4): the longest user the manifest accepts with the
/// largest store value still builds.
#[test]
fn the_longest_basic_user_with_the_largest_store_value_builds() {
    use sally_core::secrets::MAX_VALUE_BYTES;
    let s = basic("GH", "a.mock.test", &"u".repeat(MAX_BASIC_USER));
    let v = vec![("GH".to_owned(), Secret::new("!".repeat(MAX_VALUE_BYTES)))];
    assert!(Credentials::new(&[s], v).is_ok());
}

/// `secrets[].inject.basic_user`'s limit (MANIFEST_SPEC §3; the validator's own constant is
/// private).
const MAX_BASIC_USER: usize = 256;

/// The `{basic}` bound: the padded base64 of the longest user, `:` and the largest store value,
/// plus the longest format, fits a form.
const _: () = assert!(
    4 * (MAX_BASIC_USER + 1 + sally_core::secrets::MAX_VALUE_BYTES).div_ceil(3) + 1024
        <= super::super::redact::MAX_FORM
);

/// Decision 5 (architect D7): the store file gives the named values that exist and nothing else;
/// a store it refuses is an error that carries no value.
#[test]
fn the_store_file_gives_only_the_named_values() {
    use std::os::unix::fs::PermissionsExt;
    let dir = crate::egress::scratch::scratch("inject-unit", "store");
    std::fs::set_permissions(&*dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.join("secrets.toml");
    let mut s = SecretStore::empty(path.clone());
    for n in ["A", "B", "C"] {
        s.set(n, value(n)).unwrap();
    }
    s.save().unwrap();
    let src = StoreFile { path: path.clone() };
    let got = src.load(&["C".into(), "A".into(), "GONE".into()]).unwrap();
    let got: Vec<(&str, &str)> = got
        .iter()
        .map(|(n, v)| (n.as_str(), v.expose().as_str()))
        .collect();
    assert_eq!(
        got,
        [("C", value("C").as_str()), ("A", value("A").as_str())]
    );
    assert!(src.load(&[]).unwrap().is_empty());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
    let err = src.load(&["A".into()]).unwrap_err();
    assert!(!err.to_string().contains(&value("A")), "{err}");
}

#[test]
fn debug_names_grants_but_never_a_value() {
    let c = Credentials::new(&[bearer("GH", "a.mock.test")], values(&["GH"])).unwrap();
    let d = format!("{c:?}");
    assert!(d.contains("a.mock.test") && d.contains("authorization") && d.contains("GH"));
    assert!(!d.contains(&value("GH")));
}
