//! Fuzz target: arbitrary bytes, parsed as an HTTP/1.x head, through the intercepted tunnel's
//! request and response rewriting (Task 9a-2, architect Q36/Q41/Q51/Q52) and its `Host` check.
//!
//! Invariants: never panics. An accepted request head carries exactly one `Host`, equal to the
//! one rebuilt from the CONNECT authority; no dropped header survives (hop-by-hop, `Proxy-*`,
//! `Accept-Encoding`, `Expect`, the grant header, anything `Connection` names); never both
//! framing headers (in fact neither: the proxy's client frames the body). An accepted response
//! head has no hop-by-hop header, no `Proxy-*` and no framing header but `Content-Length`.
#![no_main]
#![forbid(unsafe_code)]

use hyper::http::header::{HeaderMap, HeaderName, HeaderValue};
use hyper::http::{StatusCode, Uri, Version};
use libfuzzer_sys::fuzz_target;
use sallyd::egress::authority::{self, Authority};
use sallyd::egress::rewrite;

const GRANT: &str = "authorization";

fn headers(parsed: &[httparse::Header<'_>]) -> Option<HeaderMap> {
    let mut map = HeaderMap::new();
    for h in parsed {
        let name = HeaderName::from_bytes(h.name.as_bytes()).ok()?;
        let value = HeaderValue::from_bytes(h.value).ok()?;
        map.append(name, value);
    }
    Some(map)
}

fn connection_names(h: &HeaderMap) -> Vec<String> {
    h.get_all("connection")
        .iter()
        .flat_map(|v| v.as_bytes().split(|&b| b == b','))
        .map(|t| String::from_utf8_lossy(t.trim_ascii()).to_ascii_lowercase())
        .filter(|t| !t.is_empty() && t != "host")
        .collect()
}

fn check_request(data: &[u8], connect: &Authority) {
    let mut slots = [httparse::EMPTY_HEADER; 100];
    let mut req = httparse::Request::new(&mut slots);
    let Ok(httparse::Status::Complete(_)) = req.parse(data) else {
        return;
    };
    let (Some(path), Some(minor)) = (req.path, req.version) else {
        return;
    };
    let Ok(uri) = path.parse::<Uri>() else {
        return;
    };
    let Some(input) = headers(req.headers) else {
        return;
    };
    let version = if minor == 1 { Version::HTTP_11 } else { Version::HTTP_10 };
    let Ok(out) = rewrite::request(version, &uri, &input, connect, &[GRANT.to_owned()]) else {
        return;
    };
    let hosts: Vec<_> = out.headers.get_all("host").iter().collect();
    assert_eq!(hosts.len(), 1, "not exactly one Host");
    assert_eq!(hosts[0].as_bytes(), authority::upstream_host(connect).as_bytes());
    for name in out.headers.keys() {
        let n = name.as_str();
        assert!(
            ![
                "connection", "keep-alive", "te", "trailer", "expect", "accept-encoding",
                "upgrade", "transfer-encoding", "content-length", "http2-settings", GRANT,
            ]
            .contains(&n),
            "{n} survived"
        );
        assert!(!n.starts_with("proxy-"), "{n} survived");
    }
    for named in connection_names(&input) {
        assert!(!out.headers.contains_key(named.as_str()), "{named} (named by Connection) survived");
    }
}

fn check_response(data: &[u8]) {
    let mut slots = [httparse::EMPTY_HEADER; 100];
    let mut resp = httparse::Response::new(&mut slots);
    let Ok(httparse::Status::Complete(_)) = resp.parse(data) else {
        return;
    };
    let Some(Ok(status)) = resp.code.map(StatusCode::from_u16) else {
        return;
    };
    let Some(input) = headers(resp.headers) else {
        return;
    };
    let Ok(out) = rewrite::response(status, &input) else {
        return;
    };
    assert_ne!(status, StatusCode::SWITCHING_PROTOCOLS);
    for name in out.keys() {
        let n = name.as_str();
        assert!(
            !["connection", "keep-alive", "te", "trailer", "transfer-encoding", "upgrade"].contains(&n),
            "{n} survived"
        );
        assert!(!n.starts_with("proxy-"), "{n} survived");
    }
    for named in connection_names(&input) {
        assert!(!out.contains_key(named.as_str()), "{named} (named by Connection) survived");
    }
}

fuzz_target!(|data: &[u8]| {
    let connect = Authority {
        host: "api.mock.test".to_owned(),
        port: if data.first().is_some_and(|b| b & 1 == 1) { 8443 } else { 443 },
    };
    check_request(data, &connect);
    check_response(data);
    // The Host check on its own: never panics; an accepted value names the authority.
    if authority::host_header(data, &connect).is_ok() {
        let text = String::from_utf8_lossy(data).to_ascii_lowercase();
        assert!(text.starts_with(&connect.host), "accepted Host names another host");
    }
});
