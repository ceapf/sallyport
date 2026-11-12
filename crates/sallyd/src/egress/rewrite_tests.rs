#![allow(clippy::unwrap_used)]

use super::*;

fn at(host: &str, port: u16) -> Authority {
    Authority {
        host: host.to_owned(),
        port,
    }
}

fn heads(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut h = HeaderMap::new();
    for (n, v) in pairs {
        h.append(
            HeaderName::from_bytes(n.as_bytes()).unwrap(),
            HeaderValue::from_str(v).unwrap(),
        );
    }
    h
}

fn uri(s: &str) -> Uri {
    s.parse().unwrap()
}

fn req(pairs: &[(&str, &str)]) -> Result<Request, Reason> {
    req_with(&Method::GET, pairs)
}

fn req_with(method: &Method, pairs: &[(&str, &str)]) -> Result<Request, Reason> {
    request(
        method,
        Version::HTTP_11,
        &uri("/x?y=1"),
        &heads(pairs),
        &at("api.mock.test", 443),
        &["authorization".to_owned(), "x-api-key".to_owned()],
    )
}

fn names(h: &HeaderMap) -> Vec<&str> {
    h.keys().map(HeaderName::as_str).collect()
}

#[test]
fn ordinary_headers_pass_and_host_is_rebuilt() {
    let out = req(&[
        ("host", "API.mock.test."),
        ("user-agent", "git/2"),
        ("accept", "a"),
        ("accept", "b"),
    ])
    .unwrap();
    assert_eq!(out.headers.get("host").unwrap(), "api.mock.test");
    assert_eq!(out.headers.get("user-agent").unwrap(), "git/2");
    assert_eq!(out.headers.get_all("accept").iter().count(), 2);
    assert_eq!(out.length, None);
    let at8443 = request(
        &Method::GET,
        Version::HTTP_11,
        &uri("/"),
        &heads(&[("host", "api.mock.test:8443")]),
        &at("api.mock.test", 8443),
        &[],
    )
    .unwrap();
    assert_eq!(at8443.headers.get("host").unwrap(), "api.mock.test:8443");
}

#[test]
fn every_client_copy_of_a_grant_header_is_dropped_in_any_case() {
    let out = req(&[
        ("host", "api.mock.test"),
        ("Authorization", "Bearer attacker"),
        ("authorization", "Bearer second"),
        ("X-API-KEY", "k"),
        ("x-other", "kept"),
    ])
    .unwrap();
    assert_eq!(names(&out.headers), ["x-other", "host"]);
}

#[test]
fn hop_by_hop_proxy_and_encoding_headers_are_dropped() {
    let out = req(&[
        ("host", "api.mock.test"),
        ("connection", "keep-alive, X-Named"),
        ("x-named", "1"),
        ("keep-alive", "timeout=5"),
        ("proxy-authorization", "Basic x"),
        ("proxy-connection", "keep-alive"),
        ("proxy-anything", "x"),
        ("te", "trailers"),
        ("trailer", "x-t"),
        ("expect", "100-continue"),
        ("accept-encoding", "gzip"),
        ("content-length", "3"),
        ("range", "bytes=0-3"),
        ("if-range", "\"etag\""),
        ("x-kept", "1"),
    ])
    .unwrap();
    assert_eq!(names(&out.headers), ["x-kept", "host"]);
    assert_eq!(out.length, Some(3));
    let chunked = req(&[("host", "api.mock.test"), ("transfer-encoding", "chunked")]).unwrap();
    assert_eq!(names(&chunked.headers), ["host"]);
}

#[test]
fn a_connection_token_never_removes_host() {
    let out = req(&[("host", "api.mock.test"), ("connection", "host")]).unwrap();
    assert_eq!(out.headers.get("host").unwrap(), "api.mock.test");
}

#[test]
fn only_origin_form_http_1_1_is_accepted() {
    let h = heads(&[("host", "api.mock.test")]);
    let a = at("api.mock.test", 443);
    for target in ["http://api.mock.test/x", "api.mock.test:443", "*"] {
        assert_eq!(
            request(&Method::GET, Version::HTTP_11, &uri(target), &h, &a, &[]),
            Err(Reason::Malformed),
            "{target}"
        );
    }
    for v in [Version::HTTP_10, Version::HTTP_09, Version::HTTP_2] {
        assert_eq!(
            request(&Method::GET, v, &uri("/"), &h, &a, &[]),
            Err(Reason::Malformed),
            "{v:?}"
        );
    }
}

#[test]
fn host_must_be_present_once_and_name_the_connect_authority() {
    assert_eq!(req(&[]), Err(Reason::Malformed));
    assert_eq!(
        req(&[("host", "api.mock.test"), ("host", "api.mock.test")]),
        Err(Reason::Malformed)
    );
    assert_eq!(
        req(&[("host", "user@api.mock.test")]),
        Err(Reason::Malformed)
    );
    assert_eq!(
        req(&[("host", "other.mock.test")]),
        Err(Reason::HostMismatch)
    );
}

#[test]
fn upgrades_are_refused() {
    for extra in [
        ("upgrade", "websocket"),
        ("connection", "Upgrade"),
        ("connection", "keep-alive, upgrade"),
        ("http2-settings", "AAMAAABkAAQAAP__"),
    ] {
        assert_eq!(
            req(&[("host", "api.mock.test"), extra]),
            Err(Reason::UpgradeRefused),
            "{extra:?}"
        );
    }
}

#[test]
fn framing_is_one_chunked_or_one_decimal_length() {
    for ok in ["chunked", "Chunked", "CHUNKED"] {
        assert!(
            req(&[("host", "api.mock.test"), ("transfer-encoding", ok)]).is_ok(),
            "{ok}"
        );
    }
    let bad: [&[(&str, &str)]; 9] = [
        &[("transfer-encoding", "gzip")],
        &[("transfer-encoding", "gzip, chunked")],
        &[("transfer-encoding", "chunked, chunked")],
        &[
            ("transfer-encoding", "chunked"),
            ("transfer-encoding", "chunked"),
        ],
        &[("transfer-encoding", "chunked"), ("content-length", "3")],
        &[("content-length", "3"), ("content-length", "3")],
        &[("content-length", "+3")],
        &[("content-length", "3, 3")],
        &[("content-length", "")],
    ];
    for extra in bad {
        let mut all = vec![("host", "api.mock.test")];
        all.extend_from_slice(extra);
        assert_eq!(req(&all), Err(Reason::Malformed), "{extra:?}");
    }
    assert_eq!(
        req(&[("host", "api.mock.test"), ("content-length", "0")])
            .unwrap()
            .length,
        Some(0)
    );
}

#[test]
fn expect_is_absent_or_one_100_continue() {
    assert!(req(&[("host", "api.mock.test"), ("expect", "100-Continue")]).is_ok());
    for bad in [
        &[("expect", "200-ok")][..],
        &[("expect", "100-continue"), ("expect", "100-continue")][..],
    ] {
        let mut all = vec![("host", "api.mock.test")];
        all.extend_from_slice(bad);
        assert_eq!(req(&all), Err(Reason::Malformed), "{bad:?}");
    }
}

/// Architect ruling R6 (9a-2 review): ordinary methods pass; `TRACE` would echo the request
/// (and, from 9a-3, an injected credential) back into the sandbox; `CONNECT` inside a tunnel is
/// not a request this proxy forwards. Matched ASCII case-insensitively, since an upstream may be.
#[test]
fn trace_is_refused_and_connect_is_malformed() {
    let host = [("host", "api.mock.test")];
    for ok in [
        "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "PROPFIND",
    ] {
        let m = Method::from_bytes(ok.as_bytes()).unwrap();
        assert!(req_with(&m, &host).is_ok(), "{ok}");
    }
    for trace in ["TRACE", "trace", "Trace"] {
        let m = Method::from_bytes(trace.as_bytes()).unwrap();
        assert_eq!(req_with(&m, &host), Err(Reason::MethodRefused), "{trace}");
    }
    for connect in ["CONNECT", "connect"] {
        let m = Method::from_bytes(connect.as_bytes()).unwrap();
        assert_eq!(req_with(&m, &host), Err(Reason::Malformed), "{connect}");
    }
}

#[test]
fn checks_run_in_order_malformed_before_mismatch_before_method_before_upgrade() {
    assert_eq!(
        req_with(&Method::CONNECT, &[("host", "other.mock.test")]),
        Err(Reason::Malformed)
    );
    assert_eq!(
        req_with(&Method::TRACE, &[("host", "other.mock.test")]),
        Err(Reason::HostMismatch)
    );
    assert_eq!(
        req_with(
            &Method::TRACE,
            &[("host", "api.mock.test"), ("upgrade", "h2c")]
        ),
        Err(Reason::MethodRefused)
    );
    assert_eq!(
        req(&[("host", "other.mock.test"), ("upgrade", "h2c")]),
        Err(Reason::HostMismatch)
    );
    assert_eq!(
        req(&[
            ("host", "api.mock.test"),
            ("upgrade", "h2c"),
            ("content-length", "x")
        ]),
        Err(Reason::UpgradeRefused)
    );
}

/// The hop-by-hop headers every response loses (9a-2 review R4: this fixture used to carry both
/// `Content-Length` and `Transfer-Encoding`, the ambiguous framing that is now refused).
const HOP_BY_HOP: [(&str, &str); 7] = [
    ("connection", "close, x-named"),
    ("x-named", "1"),
    ("keep-alive", "timeout=5"),
    ("proxy-authenticate", "Basic"),
    ("trailer", "x-t"),
    ("te", "trailers"),
    ("location", "https://other.mock.test/"),
];

#[test]
fn identity_responses_pass_without_hop_by_hop_headers() {
    let mut by_length = vec![("content-type", "text/plain"), ("content-length", "5")];
    by_length.extend_from_slice(&HOP_BY_HOP);
    let out = response(StatusCode::FOUND, &heads(&by_length)).unwrap();
    assert_eq!(names(&out), ["content-type", "content-length", "location"]);
    let mut chunked = vec![
        ("content-type", "text/plain"),
        ("transfer-encoding", "chunked"),
    ];
    chunked.extend_from_slice(&HOP_BY_HOP);
    let out = response(StatusCode::FOUND, &heads(&chunked)).unwrap();
    assert_eq!(names(&out), ["content-type", "location"]);
}

/// Architect ruling R4 (9a-2 review): a response framed two ways, or with two lengths, is
/// `upstream-malformed`; an encoding refusal comes first.
#[test]
fn ambiguous_response_framing_is_upstream_malformed() {
    let bad: [&[(&str, &str)]; 6] = [
        &[("transfer-encoding", "chunked"), ("content-length", "5")],
        &[("content-length", "5"), ("content-length", "5")],
        &[("content-length", "5"), ("content-length", "6")],
        &[("content-length", "5, 5")],
        &[("content-length", "+5")],
        &[("content-length", "")],
    ];
    for h in bad {
        assert_eq!(
            response(StatusCode::OK, &heads(h)),
            Err(Reason::UpstreamMalformed),
            "{h:?}"
        );
    }
    assert_eq!(
        response(
            StatusCode::OK,
            &heads(&[("transfer-encoding", "gzip"), ("content-length", "5")])
        ),
        Err(Reason::UpstreamEncoded)
    );
}

#[test]
fn encoded_or_upgraded_responses_are_refused() {
    assert_eq!(
        response(StatusCode::SWITCHING_PROTOCOLS, &HeaderMap::new()),
        Err(Reason::UpstreamEncoded)
    );
    // Task 9a-3 (decision 1, architect D6): any Content-Encoding at all, even `identity`.
    let bad: [&[(&str, &str)]; 9] = [
        &[("content-encoding", "gzip")],
        &[("content-encoding", "identity")],
        &[("content-encoding", "Identity")],
        &[("content-encoding", "")],
        &[("content-encoding", "identity, gzip")],
        &[
            ("content-encoding", "identity"),
            ("content-encoding", "identity"),
        ],
        &[("transfer-encoding", "gzip, chunked")],
        &[
            ("transfer-encoding", "chunked"),
            ("transfer-encoding", "chunked"),
        ],
        &[("upgrade", "websocket")],
    ];
    for h in bad {
        assert_eq!(
            response(StatusCode::OK, &heads(h)),
            Err(Reason::UpstreamEncoded),
            "{h:?}"
        );
    }
}

#[test]
fn a_declared_length_is_within_the_cap_up_to_and_at_it() {
    assert_eq!(
        declared_length(&heads(&[("content-length", "10")])),
        Some(10)
    );
    assert_eq!(declared_length(&HeaderMap::new()), None);
    assert_eq!(
        declared_length(&heads(&[("content-length", "1"), ("content-length", "1")])),
        None
    );
    assert_eq!(
        declared_length(&heads(&[("content-length", "99999999999999999999")])),
        None
    );
    assert!(within(Some(10), 10));
    assert!(!within(Some(11), 10));
    assert!(within(None, 0));
}
