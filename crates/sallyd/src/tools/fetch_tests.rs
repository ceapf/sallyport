//! The `fetch` tool's decisions: allow and deny for each rule (architect rulings Q3–Q5, Q13).

#![allow(clippy::unwrap_used)]

use hyper::http::HeaderValue;

use super::*;

const URL: &str = "https://a.mock.test/x";
const MAX: u64 = 1000;

fn h(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
        .collect()
}

fn c(method: &str, headers: &[(&str, &str)]) -> Result<FetchUrl, &'static str> {
    check(URL, method, &h(headers), 0, MAX, &["x-key".to_owned()])
}

#[test]
fn a_plain_get_passes_and_the_url_refusals_keep_their_codes() {
    let u = c("GET", &[]).unwrap();
    assert_eq!(u.canonical(), URL);
    for (url, code) in [
        ("http://a.mock.test/", "url-not-https"),
        ("https://127.0.0.1/", "ip-literal"),
        ("https://a.mock.test/#f", "bad-url"),
    ] {
        assert_eq!(check(url, "GET", &[], 0, MAX, &[]), Err(code), "{url}");
    }
}

#[test]
fn methods_are_one_to_sixteen_upper_case_letters_never_connect_or_trace() {
    for m in [
        "GET",
        "HEAD",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
        "A",
        "ABCDEFGHIJKLMNOP",
    ] {
        assert!(c(m, &[]).is_ok(), "{m}");
    }
    for m in [
        "",
        "get",
        "Get",
        "GET ",
        "G-T",
        "G1",
        "ABCDEFGHIJKLMNOPQ",
        "CONNECT",
        "TRACE",
    ] {
        assert_eq!(c(m, &[]), Err(BAD), "{m:?}");
    }
}

#[test]
fn header_names_are_tokens_and_values_visible_text() {
    assert!(
        c(
            "GET",
            &[("Accept", "text/*; q=0.5\tx"), ("X-A!#$%&'*+-.^_`|~1", "")]
        )
        .is_ok()
    );
    for (n, v) in [
        ("", "x"),
        ("X A", "x"),
        ("X:A", "x"),
        ("X\"A", "x"),
        ("X(A)", "x"),
        ("Ä", "x"),
        ("X-A", "a\r\nb: c"),
        ("X-A", "a\nb"),
        ("X-A", "a\0b"),
        ("X-A", "\u{7f}"),
        ("X-A", "é"),
        ("X-A", " x"),
        ("X-A", "x "),
        ("X-A", "\tx"),
        ("X-A", "x\t"),
    ] {
        assert_eq!(c("GET", &[(n, v)]), Err(BAD), "{n:?}: {v:?}");
    }
}

#[test]
fn every_header_the_proxy_drops_and_the_grant_headers_are_refused_in_any_case() {
    for n in [
        "Host",
        "Content-Length",
        "Transfer-Encoding",
        "Connection",
        "Keep-Alive",
        "Upgrade",
        "TE",
        "Trailer",
        "Expect",
        "Accept-Encoding",
        "Range",
        "If-Range",
        "Request-Range",
        "Proxy-Authorization",
        "proxy-anything",
        "HTTP2-Settings",
        "X-Key",
        "x-key",
    ] {
        assert_eq!(c("GET", &[(n, "1")]), Err(BAD), "{n}");
    }
    // A name given twice, in any case, is refused; distinct names pass.
    assert_eq!(
        c("GET", &[("X-A", "1"), ("X-B", "2"), ("x-a", "3")]),
        Err(BAD)
    );
    assert_eq!(c("GET", &[("X-A", "1"), ("X-A", "1")]), Err(BAD));
    assert!(c("GET", &[("X-A", "1"), ("X-B", "1"), ("X-AB", "1")]).is_ok());
    // Another host's grant header passes.
    assert!(check(URL, "GET", &h(&[("X-Key", "1")]), 0, MAX, &[]).is_ok());
}

#[test]
fn the_header_count_and_body_size_bounds_are_exact() {
    let names: Vec<String> = (0..=MAX_HEADERS).map(|i| format!("x-{i}")).collect();
    let at: Vec<(String, String)> = names[..MAX_HEADERS]
        .iter()
        .map(|n| (n.clone(), String::new()))
        .collect();
    assert!(check(URL, "GET", &at, 0, MAX, &[]).is_ok());
    let over: Vec<(String, String)> = names.iter().map(|n| (n.clone(), String::new())).collect();
    assert_eq!(check(URL, "GET", &over, 0, MAX, &[]), Err(BAD));
    assert!(check(URL, "POST", &[], MAX, MAX, &[]).is_ok());
    assert_eq!(
        check(URL, "POST", &[], MAX + 1, MAX, &[]),
        Err("request-too-large")
    );
}

#[test]
fn the_head_must_fit_the_proxys_request_head_limit_as_sent() {
    let u = fetch_url::parse(URL).unwrap();
    let base = head_len("GET", &u, &h(&[("x-a", "")]), 0);
    // "GET /x HTTP/1.1\r\n" + "host: a.mock.test\r\n" + "x-a: \r\n" + "content-length: 0\r\n" + "\r\n"
    assert_eq!(base, 17 + 19 + 7 + 19 + 2);
    assert_eq!(
        head_len("GET", &u, &[], 12345) - head_len("GET", &u, &[], 0),
        4
    );
    let fill = MAX_REQUEST_HEAD - base;
    let fits = h(&[("x-a", &"v".repeat(fill))]);
    assert_eq!(head_len("GET", &u, &fits, 0), MAX_REQUEST_HEAD);
    assert!(check(URL, "GET", &fits, 0, MAX, &[]).is_ok());
    let over = h(&[("x-a", &"v".repeat(fill + 1))]);
    assert_eq!(check(URL, "GET", &over, 0, MAX, &[]), Err("head-too-large"));
    let other_port = fetch_url::parse("https://a.mock.test:8443/x").unwrap();
    assert_eq!(host_header(&other_port), "a.mock.test:8443");
    assert_eq!(host_header(&u), "a.mock.test");
    assert_eq!(
        head_len("GET", &other_port, &[], 0),
        head_len("GET", &u, &[], 0) + 5
    );
}

#[test]
fn the_response_cap_is_the_lower_of_the_tools_and_the_manifests() {
    assert_eq!(response_cap(u64::MAX), BODY_CAP);
    assert_eq!(response_cap(BODY_CAP), BODY_CAP);
    assert_eq!(response_cap(10), 10);
}

#[test]
fn only_listed_text_headers_within_the_bounds_are_returned_in_order() {
    let mut m = HeaderMap::new();
    m.append("location", HeaderValue::from_static("https://b.mock.test/"));
    m.append("set-cookie", HeaderValue::from_static("s=1"));
    m.append("content-type", HeaderValue::from_static("text/plain"));
    m.append("etag", HeaderValue::from_bytes(b"\"\xff\"").unwrap());
    m.append(
        "date",
        HeaderValue::from_str(&"d".repeat(MAX_REPLY_VALUE)).unwrap(),
    );
    m.append(
        "expires",
        HeaderValue::from_str(&"e".repeat(MAX_REPLY_VALUE + 1)).unwrap(),
    );
    let got = reply_headers(&m);
    let names: Vec<&str> = got.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, ["location", "content-type", "date"]);
    assert_eq!(got[0].1, "https://b.mock.test/");
    let mut many = HeaderMap::new();
    for i in 0..=MAX_REPLY_HEADERS {
        many.append("etag", HeaderValue::from_str(&i.to_string()).unwrap());
    }
    assert_eq!(reply_headers(&many).len(), MAX_REPLY_HEADERS);
}

#[test]
fn the_reply_carries_text_bodies_as_text_and_others_as_base64() {
    let r = reply(
        302,
        &h(&[("location", "https://b.mock.test/")]),
        b"hi".to_vec(),
        false,
    );
    assert_eq!(
        r,
        json!({"status": 302, "headers": [["location", "https://b.mock.test/"]],
               "encoding": "utf-8", "body": "hi", "bytes": 2, "truncated": false})
    );
    let r = reply(200, &[], vec![0xff, 0], true);
    assert_eq!(r["encoding"], "base64");
    assert_eq!(r["body"], "/wA=");
    assert_eq!(r["bytes"], 2);
    assert_eq!(r["truncated"], true);
}
