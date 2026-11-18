#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use hyper::http::HeaderValue;
use sally_core::hf::names::{Commit, RepoId, RepoPath};
use sally_core::hf::plan::{file_request, redirect};

use super::*;

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

fn file(from: u64) -> Request {
    file_request(
        &RepoId::parse("a/b").unwrap(),
        &Commit::parse(SHA).unwrap(),
        &RepoPath::parse("m.gguf").unwrap(),
        from,
    )
}

/// A token assembled at run time, so no credential-shaped literal is in the source.
pub(super) fn token() -> Secret<String> {
    Secret::new(["h", "f_", &"t".repeat(34)].concat())
}

/// A hop to huggingface.co carries Host, identity encoding, the agent, the range and the token
/// (marked sensitive); nothing else.
#[test]
fn the_api_hop_carries_the_token_and_the_range() {
    let t = token();
    let r = build(&file(7), Some(&t)).unwrap();
    assert_eq!(r.method(), Method::GET);
    assert_eq!(r.uri().to_string(), format!("/a/b/resolve/{SHA}/m.gguf"));
    let h = r.headers();
    assert_eq!(h[HOST], "huggingface.co");
    assert_eq!(h[ACCEPT_ENCODING], "identity");
    assert_eq!(h[USER_AGENT], "sallyport");
    assert_eq!(h[RANGE], "bytes=7-");
    let auth = &h[AUTHORIZATION];
    assert!(auth.is_sensitive());
    assert_eq!(auth.to_str().unwrap(), format!("Bearer {}", t.expose()));
    assert_eq!(h.len(), 5);
}

/// A hop to another host carries no token even when one is set, and no Range at offset 0.
#[test]
fn other_hops_carry_no_token() {
    let t = token();
    let cdn = redirect(&file(0), "https://cdn-lfs.hf.co/x?y=1").unwrap();
    let r = build(&cdn, Some(&t)).unwrap();
    assert_eq!(r.uri(), "/x?y=1");
    assert_eq!(r.headers()[HOST], "cdn-lfs.hf.co");
    assert!(r.headers().get(AUTHORIZATION).is_none());
    assert!(r.headers().get(RANGE).is_none());
    let no_token = build(&file(0), None).unwrap();
    assert!(no_token.headers().get(AUTHORIZATION).is_none());
}

/// A token an HTTP header cannot carry is refused, and the refusal does not show it.
#[test]
fn an_unusable_token_is_refused_unshown() {
    let bad = Secret::new("abc\ndef".to_owned());
    let err = build(&file(0), Some(&bad)).unwrap_err();
    assert_eq!(err.code(), "hf_token_unusable");
    assert!(!err.to_string().contains("abc"));
}

fn headers(pairs: &[(&'static str, &[u8])]) -> HeaderMap {
    let mut h = HeaderMap::new();
    for (k, v) in pairs {
        h.append(*k, HeaderValue::from_bytes(v).unwrap());
    }
    h
}

/// The head's values are taken once each; Content-Encoding is a presence.
#[test]
fn head_values_are_read_once_each() {
    let h = headers(&[
        ("content-length", b"10"),
        ("content-range", b"bytes 0-9/10"),
        ("location", b"/x"),
        ("retry-after", b"3"),
        ("content-encoding", b"identity"),
        ("x-other", b"a"),
        ("x-other", b"b"),
    ]);
    let v = HeadValues::of(206, &h).unwrap();
    let head = v.head();
    assert_eq!(head.status, 206);
    assert_eq!(head.content_length, Some("10"));
    assert_eq!(head.content_range, Some("bytes 0-9/10"));
    assert_eq!(head.location, Some("/x"));
    assert_eq!(head.retry_after, Some("3"));
    assert!(head.content_encoding);
    let none = HeadValues::of(200, &HeaderMap::new()).unwrap();
    assert_eq!(none.head().content_length, None);
    assert!(!none.head().content_encoding);
}

/// A needed header sent twice, or holding a byte outside visible ASCII, is refused by name.
#[test]
fn a_repeated_or_non_ascii_header_is_refused() {
    for (name, label) in [
        ("content-length", "Content-Length"),
        ("content-range", "Content-Range"),
        ("location", "Location"),
        ("retry-after", "Retry-After"),
    ] {
        let twice = headers(&[(name, b"1"), (name, b"1")]);
        let err = HeadValues::of(200, &twice).unwrap_err();
        assert_eq!(err.code(), "hf_header_invalid");
        assert!(err.to_string().contains(label), "{err}");
        let odd = headers(&[(name, b"\xff")]);
        assert_eq!(
            HeadValues::of(200, &odd).unwrap_err().code(),
            "hf_header_invalid"
        );
    }
}
