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
    }
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

#[test]
fn a_basic_format_is_refused_until_task_9b() {
    let s = spec("GH", "a.mock.test", "Authorization", "Basic {basic}");
    assert!(s.is_basic());
    assert!(!bearer("GH", "a.mock.test").is_basic());
    assert_eq!(
        Credentials::new(&[s], values(&["GH"])).unwrap_err(),
        CredentialsError::Basic("GH".into())
    );
}

#[test]
fn a_format_without_exactly_one_value_placeholder_is_refused() {
    for f in ["Bearer", "{value} {value}", "{valu}", ""] {
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
/// bytes per byte) plus the longest format the manifest accepts (1024 bytes).
#[test]
fn max_form_covers_the_longest_form_and_format() {
    use sally_core::secrets::MAX_VALUE_BYTES;
    assert!(3 * MAX_VALUE_BYTES + 1024 <= super::super::redact::MAX_FORM);
}

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
        let (out, first) = r.scan(echo.as_bytes());
        assert_eq!(first, Some(0), "{echo}");
        assert_eq!(out.len(), echo.len());
        assert!(!String::from_utf8_lossy(&out).contains(&gh));
    }
    // A value no grant names is not kept, so it is not redacted.
    assert_eq!(r.scan(value("UNUSED").as_bytes()).1, None);
    // The longest form: the 24-byte KEY value's base64 at alignment 0 (32 characters), longer
    // than "tok " + GH's value + " end" (31).
    assert_eq!((value("KEY").len(), gh.len() + 8), (24, 31));
    assert_eq!(r.longest(), 32);
}

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
