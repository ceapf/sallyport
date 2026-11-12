//! Intercepted tunnels without containers (Task 9a-2), on the rig in `intercept_rig.rs`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{IpAddr, Ipv4Addr};

use rustls::RootCertStore;
use tokio::io::{AsyncReadExt, duplex};

use super::super::Limits;
use super::*;
use crate::egress::ca::Validity;

#[path = "intercept_rig.rs"]
mod rig;
use rig::*;

#[tokio::test]
async fn a_grant_host_is_intercepted_rewritten_forwarded_and_audited_in_order() {
    let r = rig(Opts::default());
    let out = r
        .talk(&get(
            "/echo",
            "Authorization: Bearer attacker\r\nauthorization: Bearer two\r\n\
             Accept-Encoding: gzip\r\nProxy-Authorization: Basic eA==\r\n\
             Connection: keep-alive, X-Hop\r\nX-Hop: 1\r\nX-Kept: yes\r\n",
        ))
        .await;
    assert!(out.starts_with("HTTP/1.1 200 OK\r\n"), "{out}");
    assert!(out.ends_with("ok"), "{out}");
    let seen = r.seen();
    assert_eq!(seen.len(), 1);
    let up = seen[0].to_ascii_lowercase();
    assert!(up.starts_with("get /echo http/1.1\r\n"), "{up}");
    assert!(up.contains("host: a.mock.test\r\n"), "{up}");
    assert!(up.contains("x-kept: yes\r\n"), "{up}");
    for gone in [
        "authorization",
        "accept-encoding",
        "proxy-",
        "x-hop",
        "connection: keep",
    ] {
        assert!(!up.contains(gone), "{gone} reached the upstream: {up}");
    }
    assert_eq!(
        r.sink.events(),
        ["egress.allow", "egress.request", "egress.close"]
    );
    assert_eq!(r.sink.args("egress.allow")["intercept"], json!(true));
    assert_eq!(
        r.sink.args("egress.request"),
        json!({"host": HOST, "port": 443, "method": "GET", "target": "/echo",
               "target_bytes": 5, "target_cut": false, "injected": []})
    );
    let close = r.sink.args("egress.close");
    assert_eq!(close["intercept"], json!(true));
    assert_eq!(close["requests"], json!(1));
    assert_eq!(close["statuses"], json!({"2xx": 1}));
    assert_eq!(close["end"], json!("closed"));
    assert_eq!(close["connected"], json!(true));
    assert!(close["bytes_up"].as_u64().unwrap() > 0);
    assert!(close["bytes_down"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn keep_alive_requests_share_one_upstream_connection() {
    let r = rig(Opts::default());
    let out = r.talk(&(get("/echo", "") + &get("/redirect", ""))).await;
    assert_eq!(out.matches("HTTP/1.1 ").count(), 2, "{out}");
    assert_eq!(*r.dials.lock().unwrap(), 1);
    assert_eq!(r.seen().len(), 2);
    let close = r.sink.args("egress.close");
    assert_eq!(close["requests"], json!(2));
    assert_eq!(close["statuses"], json!({"2xx": 1, "3xx": 1}));
}

#[tokio::test]
async fn a_redirect_is_returned_unfollowed() {
    let r = rig(Opts::default());
    let out = r.talk(&get("/redirect", "")).await;
    assert!(out.starts_with("HTTP/1.1 302 Found\r\n"), "{out}");
    assert!(out.contains("location: https://b.mock.test/"), "{out}");
    assert_eq!(r.seen().len(), 1);
    assert_eq!(*r.dials.lock().unwrap(), 1);
}

/// One refusal inside the tunnel: status, the audited event and reason, nothing upstream.
async fn refused_inside(raw: &str, status: &str, event: &str, reason: &str) -> Rig {
    let r = rig(Opts::default());
    let out = r.talk(raw).await;
    assert!(
        out.starts_with(&format!("HTTP/1.1 {status} ")),
        "{raw:?}: {out}"
    );
    assert!(out.contains("connection: close\r\n"), "{out}");
    assert!(out.ends_with(&format!("{reason}\n")), "{out}");
    assert!(r.seen().is_empty(), "{raw:?} reached the upstream");
    let args = r.sink.args(event);
    assert_eq!(args["reason"], json!(reason), "{raw:?}");
    assert_eq!(
        (args["host"].clone(), args["port"].clone()),
        (json!(HOST), json!(443))
    );
    let events = r.sink.events();
    assert_eq!(events.last().map(String::as_str), Some("egress.close"));
    assert!(!events.contains(&"egress.request".to_owned()), "{events:?}");
    r
}

#[tokio::test]
async fn a_host_header_naming_another_authority_is_421() {
    let raw = "GET /echo HTTP/1.1\r\nHost: b.mock.test\r\n\r\n";
    let r = refused_inside(raw, "421", "egress.deny", "host-mismatch").await;
    assert_eq!(r.sink.args("egress.deny")["target"], json!("/echo"));
    assert_eq!(r.sink.args("egress.close")["end"], json!("refused"));
}

#[tokio::test]
async fn heads_the_proxy_cannot_forward_as_they_are_are_400() {
    for raw in [
        "GET http://a.mock.test/x HTTP/1.1\r\nHost: a.mock.test\r\n\r\n",
        "GET /x HTTP/1.1\r\nHost: a.mock.test\r\nHost: a.mock.test\r\n\r\n",
        "GET /x HTTP/1.1\r\n\r\n",
        "GET /x HTTP/1.0\r\nHost: a.mock.test\r\n\r\n",
        "OPTIONS * HTTP/1.1\r\nHost: a.mock.test\r\n\r\n",
        "POST /x HTTP/1.1\r\nHost: a.mock.test\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n",
        "GET /x HTTP/1.1\r\nHost: a.mock.test\r\nExpect: nothing\r\n\r\n",
    ] {
        let r = rig(Opts::default());
        let out = r.talk(raw).await;
        assert!(out.contains(" 400 "), "{raw:?}: {out}");
        assert!(r.seen().is_empty(), "{raw:?}");
        assert_eq!(
            r.sink.args("egress.deny")["reason"],
            json!("malformed"),
            "{raw:?}"
        );
    }
}

#[tokio::test]
async fn upgrades_are_refused_403() {
    let raw = get("/ws", "Connection: Upgrade\r\nUpgrade: websocket\r\n");
    refused_inside(&raw, "403", "egress.deny", "upgrade-refused").await;
}

/// Architect ruling R6: `TRACE` is refused 405, `CONNECT` inside a tunnel is malformed; neither
/// reaches the upstream.
#[tokio::test]
async fn trace_and_connect_never_reach_the_upstream() {
    let trace = format!("TRACE /echo HTTP/1.1\r\nHost: {HOST}\r\n\r\n");
    refused_inside(&trace, "405", "egress.deny", "method-refused").await;
    for target in [format!("{HOST}:443"), "/".to_owned()] {
        let connect = format!("CONNECT {target} HTTP/1.1\r\nHost: {HOST}\r\n\r\n");
        refused_inside(&connect, "400", "egress.deny", "malformed").await;
    }
}

/// Architect ruling R4: a response framed two ways, or with two `Content-Length` lines, is 502
/// `upstream-malformed` and none of its body reaches the client. Pins what hyper's client does
/// with duplicate lengths: equal ones (two lines, or one `6, 6` list) reach `rewrite::response`
/// and are refused there; differing ones fail hyper's own parse (the Q45 path).
#[tokio::test]
async fn an_ambiguously_framed_response_is_502_and_never_forwarded() {
    for path in ["/te-cl", "/cl-twice", "/cl-differ", "/cl-list"] {
        let r = rig(Opts::default());
        let out = r.talk(&get(path, "")).await;
        assert!(out.starts_with("HTTP/1.1 502 "), "{path}: {out}");
        assert!(out.ends_with("upstream-malformed\n"), "{path}: {out}");
        assert!(!out.contains("SMUGGL"), "{path}: {out}");
        assert_eq!(
            r.sink.args("egress.deny")["reason"],
            json!("upstream-malformed"),
            "{path}"
        );
    }
}

#[tokio::test]
async fn an_encoded_or_switching_response_is_502_and_never_forwarded() {
    for path in ["/gzip", "/switch"] {
        let r = rig(Opts::default());
        let out = r.talk(&get(path, "")).await;
        assert!(out.starts_with("HTTP/1.1 502 "), "{path}: {out}");
        assert!(out.ends_with("upstream-encoded\n"), "{out}");
        assert!(!out.contains("GZBODY"), "{out}");
        assert_eq!(
            r.sink.args("egress.deny")["reason"],
            json!("upstream-encoded")
        );
        assert_eq!(r.sink.args("egress.close")["end"], json!("refused"));
    }
}

#[tokio::test]
async fn response_bodies_pass_at_the_cap_and_are_refused_one_over() {
    let r = rig(Opts::default());
    let out = r.talk(&get("/len/16", "")).await;
    assert!(out.ends_with(&"b".repeat(16)), "{out}");
    let r = rig(Opts::default());
    let out = r.talk(&get("/len/17", "")).await;
    assert!(out.starts_with("HTTP/1.1 502 "), "{out}");
    assert!(!out.contains("bbbb"), "{out}");
    let limit = r.sink.args("egress.limit");
    assert_eq!(limit["reason"], json!("response-too-large"));
    assert_eq!(limit["part"], json!("body"));
}

/// Architect ruling R5: the cap pre-check uses the length hyper decoded, so a HEAD answer or a
/// 304, whose `Content-Length` describes a body that never comes, is not a false 502. A HEAD
/// answer keeps its length; hyper's server never writes one on a 204 or 304
/// (`can_have_content_length`), so the 304 reaches the client without it.
#[tokio::test]
async fn a_length_without_a_body_is_not_held_to_the_cap() {
    for (raw, status, length) in [
        (
            format!("HEAD /head-only HTTP/1.1\r\nHost: {HOST}\r\n\r\n"),
            "200",
            true,
        ),
        (get("/not-modified", ""), "304", false),
    ] {
        let r = rig(Opts::default());
        let out = r.talk(&raw).await;
        assert!(
            out.starts_with(&format!("HTTP/1.1 {status} ")),
            "{raw:?}: {out}"
        );
        assert_eq!(
            out.contains("content-length: 100\r\n"),
            length,
            "{raw:?}: {out}"
        );
        assert!(out.ends_with("\r\n\r\n"), "{raw:?}: {out}");
        assert!(!r.sink.events().contains(&"egress.limit".to_owned()));
        assert_eq!(r.sink.args("egress.close")["requests"], json!(1));
    }
}

#[tokio::test]
async fn a_streamed_response_one_over_the_cap_is_cut_after_its_audit_entry() {
    let r = rig(Opts::default());
    let out = r.talk(&get("/chunks/16", "")).await;
    assert!(out.ends_with("0\r\n\r\n"), "{out}");
    let r = rig(Opts::default());
    let out = r.talk(&get("/chunks/17", "")).await;
    // When the over-cap chunk is already there as hyper writes the head, hyper drops the
    // unflushed head with the cut: the client sees the head or nothing, never the body.
    assert!(
        out.is_empty() || out.starts_with("HTTP/1.1 200 OK\r\n"),
        "{out}"
    );
    assert!(!out.contains(&"c".repeat(17)), "{out}");
    assert!(
        !out.ends_with("0\r\n\r\n"),
        "a cut sends no last chunk: {out}"
    );
    assert_eq!(
        r.sink.args("egress.limit")["reason"],
        json!("response-too-large")
    );
    let events = r.sink.events();
    assert_eq!(
        events,
        [
            "egress.allow",
            "egress.request",
            "egress.limit",
            "egress.close"
        ]
    );
    assert_eq!(r.sink.args("egress.close")["end"], json!("limit"));
}

#[tokio::test]
async fn response_trailers_are_never_forwarded() {
    let r = rig(Opts::default());
    let out = r.talk(&get("/trailer", "")).await;
    assert!(out.contains("ok"), "{out}");
    assert!(!out.to_ascii_lowercase().contains("x-late"), "{out}");
    assert!(!out.contains("trailer-value"), "{out}");
}

#[tokio::test]
async fn request_bodies_pass_at_the_cap_and_are_refused_one_over() {
    let body = "q".repeat(16);
    let r = rig(Opts::default());
    let out = r
        .talk(&format!(
            "POST /echo HTTP/1.1\r\nHost: {HOST}\r\nContent-Length: 16\r\n\r\n{body}"
        ))
        .await;
    assert!(out.starts_with("HTTP/1.1 200 "), "{out}");
    assert!(r.seen()[0].ends_with(&body));
    let raw = format!("POST /echo HTTP/1.1\r\nHost: {HOST}\r\nContent-Length: 17\r\n\r\n{body}q");
    refused_inside(&raw, "413", "egress.limit", "request-too-large").await;
}

#[tokio::test]
async fn a_chunked_request_crossing_the_cap_is_413() {
    let r = rig(Opts::default());
    let raw = format!(
        "POST /echo HTTP/1.1\r\nHost: {HOST}\r\nTransfer-Encoding: chunked\r\n\r\n\
         10\r\n{}\r\n1\r\nq\r\n0\r\n\r\n",
        "q".repeat(16)
    );
    let out = r.talk(&raw).await;
    assert!(out.starts_with("HTTP/1.1 413 "), "{out}");
    assert_one_request_limit(&r);
}

/// Exactly one `egress.limit request-too-large`, without `part`, and the tunnel ends `limit`
/// (architect ruling R2).
fn assert_one_request_limit(r: &Rig) {
    let events = r.sink.events();
    let limits = events.iter().filter(|e| *e == "egress.limit").count();
    assert_eq!(limits, 1, "{events:?}");
    let limit = r.sink.args("egress.limit");
    assert_eq!(
        (
            limit["reason"].clone(),
            limit["host"].clone(),
            limit["port"].clone()
        ),
        (json!("request-too-large"), json!(HOST), json!(443))
    );
    assert!(
        limit["target"].as_str().is_some_and(|t| t.starts_with('/')),
        "{limit}"
    );
    assert!(
        limit["target_bytes"].is_u64() && limit["target_cut"].is_boolean(),
        "{limit}"
    );
    assert!(limit.get("part").is_none(), "{limit}");
    assert_eq!(
        r.sink.args("egress.close")["end"],
        json!("limit"),
        "{events:?}"
    );
}

/// Architect ruling R2: the upstream answers before the body ends (here a 401 after the head),
/// and the body then crosses the cap. The response head is already forwarded, so there is no
/// 413; the crossing is still audited, once, and the tunnel ends `limit`.
#[tokio::test]
async fn a_request_body_crossing_the_cap_after_an_early_response_is_audited_once() {
    let r = rig(Opts::default());
    let (_, tls, task) = r.open(443).await;
    let mut tls = tls.unwrap();
    let head =
        format!("POST /early HTTP/1.1\r\nHost: {HOST}\r\nTransfer-Encoding: chunked\r\n\r\n");
    tls.write_all(head.as_bytes()).await.unwrap();
    bounded("the early 401", async {
        let mut got = Vec::new();
        let mut b = [0u8; 1];
        while !got.ends_with(b"\r\n\r\n") {
            tls.read_exact(&mut b).await.unwrap();
            got.push(b[0]);
        }
        assert!(
            got.starts_with(b"HTTP/1.1 401 "),
            "{}",
            String::from_utf8_lossy(&got)
        );
    })
    .await;
    let body = format!("20\r\n{}\r\n0\r\n\r\n", "q".repeat(32));
    let _ = tls.write_all(body.as_bytes()).await;
    let _ = tls.shutdown().await;
    let rest = drain(&mut tls).await;
    join(task).await;
    assert!(!rest.contains("413"), "{rest}");
    assert_one_request_limit(&r);
}

/// Architect ruling R3, and hyper's incomplete-message mapping: a client that breaks off its own
/// request body, or its head, ends the tunnel `closed`: no refusal entry, no reply, no 502.
#[tokio::test]
async fn a_client_that_breaks_off_its_request_ends_closed() {
    let body_cut = format!(
        "POST /echo HTTP/1.1\r\nHost: {HOST}\r\nContent-Length: 16\r\n\r\n{}",
        "q".repeat(8)
    );
    for (raw, requests) in [(body_cut.as_str(), 1), ("GET /echo HT", 0)] {
        let r = rig(Opts::default());
        let out = r.talk(raw).await;
        assert!(out.is_empty(), "{raw:?}: {out}");
        let events = r.sink.events();
        let expected: &[&str] = if requests == 1 {
            &["egress.allow", "egress.request", "egress.close"]
        } else {
            &["egress.allow", "egress.close"]
        };
        assert_eq!(events, expected, "{raw:?}");
        let close = r.sink.args("egress.close");
        assert_eq!(close["end"], json!("closed"), "{raw:?}");
        assert_eq!(close["requests"], json!(requests), "{raw:?}");
        assert!(r.seen().is_empty(), "{raw:?}");
    }
}

#[tokio::test]
async fn request_trailers_and_client_framing_never_reach_the_upstream() {
    let r = rig(Opts::default());
    let raw = format!(
        "POST /echo HTTP/1.1\r\nHost: {HOST}\r\nTransfer-Encoding: chunked\r\n\r\n\
         3\r\nabc\r\n0\r\nAuthorization: Bearer late\r\n\r\n"
    );
    let out = r.talk(&raw).await;
    assert!(out.starts_with("HTTP/1.1 200 "), "{out}");
    let up = r.seen()[0].to_ascii_lowercase();
    assert!(!up.contains("authorization"), "{up}");
    assert!(up.contains("abc"), "{up}");
}

/// Architect Q51: framing hyper resolves itself before the proxy sees the head. The upstream
/// gets exactly one framing header, set by the proxy's own client, and the decoded body; or
/// nothing at all when hyper answered 400 itself.
#[tokio::test]
async fn ambiguous_client_framing_never_reaches_the_upstream() {
    let te_cl = format!(
        "POST /echo HTTP/1.1\r\nHost: {HOST}\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n\
         3\r\nabc\r\n0\r\n\r\n"
    );
    let dup = format!(
        "POST /echo HTTP/1.1\r\nHost: {HOST}\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc"
    );
    for raw in [te_cl, dup] {
        let r = rig(Opts::default());
        let out = r.talk(&raw).await;
        assert!(out.starts_with("HTTP/1.1 200 "), "{raw:?}: {out}");
        let up = r.seen()[0].to_ascii_lowercase();
        let framing =
            up.matches("content-length:").count() + up.matches("transfer-encoding:").count();
        assert_eq!(framing, 1, "{up}");
        assert!(up.contains("abc"), "{up}");
    }
    for cl in ["Content-Length: 3, 3", "Content-Length: +3"] {
        refused_framing(cl).await;
    }
}

/// Architect ruling (9a-2 part 2): re-framing after a full parse is safe only while the upstream
/// sees one unambiguous framing, so differing duplicate lengths are refused, never resolved.
#[tokio::test]
async fn differing_duplicate_content_lengths_are_refused() {
    for cl in [
        "Content-Length: 3\r\nContent-Length: 4",
        "Content-Length: 4\r\nContent-Length: 3",
        "Content-Length: 3, 4",
        "Content-Length: 3\r\nContent-Length: 3x",
    ] {
        refused_framing(cl).await;
    }
}

/// A POST with `cl` as its length headers is answered 400 `malformed` and never forwarded.
async fn refused_framing(cl: &str) {
    let r = rig(Opts::default());
    let out = r
        .talk(&format!(
            "POST /echo HTTP/1.1\r\nHost: {HOST}\r\n{cl}\r\n\r\nabcd"
        ))
        .await;
    assert!(out.starts_with("HTTP/1.1 400 "), "{cl}: {out}");
    assert!(r.seen().is_empty(), "{cl}");
    assert_eq!(r.sink.args("egress.deny")["reason"], json!("malformed"));
    assert_eq!(r.sink.args("egress.close")["end"], json!("refused"));
}

#[tokio::test]
async fn an_oversized_request_head_is_a_limit() {
    let r = rig(Opts::default());
    let out = r
        .talk(&get("/x", &format!("X-Big: {}\r\n", "a".repeat(9000))))
        .await;
    assert!(out.starts_with("HTTP/1.1 431 "), "{out}");
    assert_eq!(
        r.sink.args("egress.limit")["reason"],
        json!("head-too-large")
    );
    assert_eq!(r.sink.args("egress.close")["end"], json!("limit"));
}

#[tokio::test]
async fn a_request_head_under_its_guaranteed_size_passes() {
    let r = rig(Opts::default());
    let filler = format!("X-Big: {}\r\n", "a".repeat(MAX_HEAD - REQUEST_READ - 200));
    let out = r.talk(&get("/x", &filler)).await;
    assert!(
        out.starts_with("HTTP/1.1 200 "),
        "{}",
        &out[..out.len().min(80)]
    );
}

/// The request head cut (ARCHITECTURE §7, architect 9a-2 part 2): exact at `MAX_HEAD -
/// REQUEST_READ` (7168 bytes, request line and blank line included), whole or split, up to and
/// past the 8 KiB buffer backstop. A refusal is hyper's own 431 (Q45): audited, nothing
/// forwarded, the tunnel ended.
#[tokio::test]
async fn request_heads_pass_up_to_7168_bytes_and_are_refused_from_7169() {
    let start = format!("GET /x HTTP/1.1\r\nHost: {HOST}\r\n");
    let cut = MAX_HEAD - REQUEST_READ;
    for total in [cut - 1, cut] {
        for at in [total, split_at(total)] {
            let r = rig(Opts::default());
            let out = r.talk_split(&sized_head(&start, total), at).await;
            assert!(out.starts_with("HTTP/1.1 200 "), "{total} at {at}");
        }
    }
    for total in [
        cut + 1,
        cut + 100,
        MAX_HEAD,
        MAX_HEAD + 1,
        MAX_HEAD + REQUEST_READ,
    ] {
        for at in [total, split_at(total)] {
            let r = rig(Opts::default());
            let out = r.talk_split(&sized_head(&start, total), at).await;
            assert!(out.starts_with("HTTP/1.1 431 "), "{total} at {at}: {out}");
            assert!(r.seen().is_empty(), "{total} at {at}");
            assert_eq!(
                r.sink.args("egress.limit")["reason"],
                json!("head-too-large")
            );
            assert_eq!(r.sink.args("egress.close")["end"], json!("limit"));
        }
    }
}

/// The response head cut: exact at `MAX_RESPONSE_HEAD - RESPONSE_READ` (61440 bytes), whole or
/// split, up to and past the 64 KiB buffer backstop.
#[tokio::test]
async fn response_heads_pass_up_to_61440_bytes_and_are_refused_from_61441() {
    let cut = MAX_RESPONSE_HEAD - RESPONSE_READ;
    for total in [cut - 1, cut] {
        for path in ["/head", "/splithead"] {
            let r = rig(Opts::default());
            let out = r.talk(&get(&format!("{path}/{total}"), "")).await;
            assert!(out.starts_with("HTTP/1.1 200 "), "{path} {total}");
        }
    }
    let over = [
        cut + 1,
        cut + 100,
        MAX_RESPONSE_HEAD,
        MAX_RESPONSE_HEAD + 1,
        MAX_RESPONSE_HEAD + RESPONSE_READ,
    ];
    for total in over {
        for path in ["/head", "/splithead"] {
            let r = rig(Opts::default());
            let out = r.talk(&get(&format!("{path}/{total}"), "")).await;
            assert!(out.starts_with("HTTP/1.1 502 "), "{path} {total}: {out}");
            let limit = r.sink.args("egress.limit");
            assert_eq!(
                (limit["reason"].clone(), limit["part"].clone()),
                (json!("response-too-large"), json!("head")),
                "{path} {total}"
            );
        }
    }
}

#[tokio::test]
async fn upstream_heads_too_large_or_unparsable_are_502() {
    let r = rig(Opts::default());
    let out = r.talk(&get("/okhead", "")).await;
    assert!(
        out.starts_with("HTTP/1.1 200 "),
        "{}",
        &out[..out.len().min(80)]
    );
    let r = rig(Opts::default());
    let out = r.talk(&get("/bighead", "")).await;
    assert!(out.starts_with("HTTP/1.1 502 "), "{out}");
    let limit = r.sink.args("egress.limit");
    assert_eq!(
        (limit["reason"].clone(), limit["part"].clone()),
        (json!("response-too-large"), json!("head"))
    );
    let r = rig(Opts::default());
    let out = r.talk(&get("/garbage", "")).await;
    assert!(out.starts_with("HTTP/1.1 502 "), "{out}");
    assert_eq!(
        r.sink.args("egress.deny")["reason"],
        json!("upstream-malformed")
    );
}

/// Architect Q43: the close entry first, then the 502; the request is never replayed.
#[tokio::test]
async fn an_upstream_that_closes_before_answering_gets_close_first_then_502() {
    let r = rig(Opts::default());
    let out = r.talk(&get("/close", "")).await;
    assert!(out.starts_with("HTTP/1.1 502 "), "{out}");
    assert!(out.ends_with("upstream-closed\n"), "{out}");
    assert_eq!(r.seen().len(), 1, "never replayed");
    assert_eq!(*r.dials.lock().unwrap(), 1);
    assert_eq!(
        r.sink.events(),
        ["egress.allow", "egress.request", "egress.close"]
    );
    let close = r.sink.args("egress.close");
    assert_eq!(close["end"], json!("upstream-closed"));
    assert_eq!(close["connected"], json!(true));
}

/// A rig whose head timer is long, so only the upstream's close can end a quiet tunnel soon.
fn slow_head_rig() -> Rig {
    rig(Opts {
        limits: Limits {
            head: Duration::from_secs(30),
            max_request: 16,
            max_response: 16,
            ..Limits::new(8)
        },
        ..Opts::default()
    })
}

/// Architect ruling R1 (a) and (c): the upstream ends its connection with a response. The
/// response, even one still streaming when the upstream connection ends, reaches the client
/// whole; then the tunnel closes (`closed`) at once, not when the client's head timer runs out.
/// The client keeps its sending side open throughout.
#[tokio::test]
async fn an_upstream_that_ends_with_its_response_closes_the_tunnel_after_it() {
    for (path, body) in [("/close-after", "ok"), ("/close-slow", "okok")] {
        let r = slow_head_rig();
        let started = Instant::now();
        let (_, tls, task) = r.open(443).await;
        let mut tls = tls.unwrap();
        tls.write_all(get(path, "").as_bytes()).await.unwrap();
        let out = drain(&mut tls).await;
        join(task).await;
        assert!(started.elapsed() < Duration::from_secs(2), "{path}");
        assert!(out.starts_with("HTTP/1.1 200 "), "{path}: {out}");
        assert!(out.ends_with(&format!("\r\n\r\n{body}")), "{path}: {out}");
        let close = r.sink.args("egress.close");
        assert_eq!(
            (close["end"].clone(), close["requests"].clone()),
            (json!("closed"), json!(1)),
            "{path}"
        );
    }
}

/// Architect ruling R1 (b): a request that arrives after the upstream closed is never forwarded
/// or counted. Pipelined behind a response that ends the upstream connection, the second request
/// either finds the tunnel closing (no reply) or is read first and refused 502 `upstream-closed`
/// after the close entry; which one depends on task timing, and both keep the rule.
#[tokio::test]
async fn a_request_after_the_upstream_closed_is_never_forwarded_or_counted() {
    let r = slow_head_rig();
    let two = format!("{}{}", get("/close-after", ""), get("/echo", ""));
    let out = r.talk(&two).await;
    assert!(out.starts_with("HTTP/1.1 200 "), "{out}");
    assert_eq!(r.seen().len(), 1, "{out}");
    let events = r.sink.events();
    let requests = events.iter().filter(|e| *e == "egress.request").count();
    assert_eq!(requests, 1, "{events:?}");
    assert_eq!(events.last().map(String::as_str), Some("egress.close"));
    let close = r.sink.args("egress.close");
    assert_eq!(close["requests"], json!(1));
    let end = if out.contains("upstream-closed\n") {
        "upstream-closed"
    } else {
        "closed"
    };
    assert_eq!(close["end"], json!(end), "{out}");
}

/// Architect ruling R1 (b) as wired (rust re-review H1): the upstream answers keep-alive, then
/// closes, with a second request pipelined behind the first. Either the tunnel closes after the
/// first response (seen in every local run: hyper's server disables keep-alive) or the second
/// request gets the upstream-closed 502 after the close entry; never a hang, never a request
/// entry the count misses. The H1 window itself (a request read, `ready()` pending, the
/// connection ending cleanly while kept) cannot be forced here; the fix (the ended connection
/// future is dropped, which fails `ready()`) rests on the reviewer's hyper probe.
#[tokio::test]
async fn a_request_racing_the_upstreams_close_never_hangs_or_miscounts() {
    let r = slow_head_rig();
    let two = format!("{}{}", get("/then-eof", ""), get("/echo", ""));
    let out = r.talk(&two).await;
    assert!(out.starts_with("HTTP/1.1 200 "), "{out}");
    assert_eq!(r.seen().len(), 1, "{out}");
    let close = r.sink.args("egress.close");
    let end = if out.ends_with("upstream-closed\n") {
        "upstream-closed"
    } else {
        "closed"
    };
    assert_eq!(close["end"], json!(end), "{out}");
    let events = r.sink.events();
    let entries = events.iter().filter(|e| *e == "egress.request").count();
    assert_eq!(close["requests"], json!(entries), "{events:?}");
    assert_eq!(events.last().map(String::as_str), Some("egress.close"));
}

/// Architect ruling R1 (b), the branch the pipelined test cannot reach on demand: an upstream
/// connection that is gone before a request is audited gets the close entry and the 502, and
/// the request is neither audited nor counted.
#[tokio::test]
async fn a_request_for_a_closed_upstream_connection_is_not_audited_or_counted() {
    let r = rig(Opts::default());
    let (near, _far) = duplex(1 << 10);
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake::<_, Capped<Incoming>>(TokioIo::new(near))
            .await
            .unwrap();
    drop(conn);
    let auth = Authority {
        host: HOST.to_owned(),
        port: 443,
    };
    let used = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 215, 9)), 443);
    let st = State::new(auth, used, Vec::new(), Arc::new(Activity::new()));
    let reply = r.proxy.upstream_ready(&st, &mut sender).await;
    let resp = reply.expect("a closed connection is not ready").unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(r.sink.events(), ["egress.close"]);
    let close = r.sink.args("egress.close");
    assert_eq!(
        (close["end"].clone(), close["requests"].clone()),
        (json!("upstream-closed"), json!(0))
    );
}

/// Architect ruling RQ1 (R1 amended): the upstream hangs up while the tunnel's first head is
/// still arriving. hyper's graceful shutdown drops a partial head only after a finished exchange
/// (`KA::Idle`), or when nothing is in its read buffer yet; a first head it holds part of is read
/// to its end, and a head hyper refuses is still audited. `first` is sent and buffered, the
/// upstream hangs up, then `rest` (if any) follows.
async fn head_after_upstream_hangup(
    head: Duration,
    first: &str,
    rest: Option<&str>,
) -> (Rig, String) {
    let hangup = Arc::new(tokio::sync::Notify::new());
    let r = rig(Opts {
        hangup: Some(Arc::clone(&hangup)),
        limits: Limits {
            head,
            max_request: 16,
            max_response: 16,
            ..Limits::new(8)
        },
        ..Opts::default()
    });
    let (_, tls, task) = r.open(443).await;
    let mut tls = tls.unwrap();
    tls.write_all(first.as_bytes()).await.unwrap();
    tls.flush().await.unwrap();
    // Lets hyper buffer `first`: with an empty read buffer the hangup closes the tunnel unread.
    tokio::time::sleep(Duration::from_millis(100)).await;
    hangup.notify_one();
    until("the upstream hangs up", || *r.ended.lock().unwrap() > 0).await;
    // Lets the tunnel's select loop see the upstream connection end before the head does.
    tokio::time::sleep(Duration::from_millis(100)).await;
    if let Some(rest) = rest {
        let _ = tls.write_all(rest.as_bytes()).await;
        let _ = tls.shutdown().await;
    }
    let out = drain(&mut tls).await;
    join(task).await;
    assert!(r.seen().is_empty());
    assert!(!r.sink.events().iter().any(|e| e == "egress.request"));
    (r, out)
}

#[tokio::test]
async fn an_oversized_head_after_the_upstream_hung_up_is_still_a_limit() {
    let first = format!("GET /x HTTP/1.1\r\nHost: {HOST}\r\n");
    let rest = format!("X-Big: {}\r\n\r\n", "a".repeat(9000));
    let (r, _) = head_after_upstream_hangup(Duration::from_secs(30), &first, Some(&rest)).await;
    assert_eq!(
        r.sink.args("egress.limit")["reason"],
        json!("head-too-large")
    );
    assert_eq!(r.sink.args("egress.close")["end"], json!("limit"));
}

#[tokio::test]
async fn a_garbled_head_after_the_upstream_hung_up_is_still_refused() {
    let first = format!("GET /x HTTP/1.1\r\nHost: {HOST}\r\n");
    let (r, out) =
        head_after_upstream_hangup(Duration::from_secs(30), &first, Some("no colon\r\n\r\n")).await;
    let why = format!(
        "{:?} {} {out:?}",
        r.sink.events(),
        r.sink.args("egress.close")
    );
    assert_eq!(
        r.sink.args("egress.deny")["reason"],
        json!("malformed"),
        "{why}"
    );
    assert_eq!(r.sink.args("egress.close")["end"], json!("refused"));
}

#[tokio::test]
async fn a_head_stalled_after_the_upstream_hung_up_is_still_a_limit() {
    let (r, _) = head_after_upstream_hangup(Duration::from_secs(1), "GET /echo HT", None).await;
    assert_eq!(r.sink.args("egress.limit")["reason"], json!("head-timeout"));
    assert_eq!(r.sink.args("egress.close")["end"], json!("limit"));
}

/// A stop during the upstream TLS handshake ends the tunnel `session-stopped` at once, with no
/// `200` and no reply (9a-2 review: the handshake was not raced against the stop).
#[tokio::test]
async fn stopping_the_session_during_the_upstream_handshake_ends_session_stopped() {
    let r = rig(Opts {
        stall: true,
        limits: Limits {
            connect: Duration::from_secs(30),
            ..Limits::new(8)
        },
        ..Opts::default()
    });
    let (mut c, s) = duplex(1 << 16);
    let proxy = Arc::clone(&r.proxy);
    let task = tokio::spawn(async move { proxy.serve(s).await });
    c.write_all(format!("CONNECT {HOST}:443 HTTP/1.1\r\nHost: {HOST}:443\r\n\r\n").as_bytes())
        .await
        .unwrap();
    until("the upstream is dialled", || *r.dials.lock().unwrap() > 0).await;
    r.proxy.stop();
    let out = drain(&mut c).await;
    join(task).await;
    assert!(out.is_empty(), "{out}");
    assert_eq!(r.sink.events(), ["egress.allow", "egress.close"]);
    let close = r.sink.args("egress.close");
    assert_eq!(
        (close["end"].clone(), close["connected"].clone()),
        (json!("session-stopped"), json!(true))
    );
}

/// Architect Q28: upstream verification before the `200`; failure is audited, then 502.
#[tokio::test]
async fn an_upstream_that_fails_verification_gets_no_200() {
    let r = rig(Opts {
        upstream_name: "wrong.mock.test",
        ..Opts::default()
    });
    let (reply, tls, task) = r.open(443).await;
    join(task).await;
    assert!(tls.is_none());
    assert!(reply.starts_with("HTTP/1.1 502 "), "{reply}");
    assert!(reply.ends_with("upstream-tls-failed\n"), "{reply}");
    assert_eq!(r.sink.events(), ["egress.allow", "egress.close"]);
    let close = r.sink.args("egress.close");
    assert_eq!(
        (
            close["end"].clone(),
            close["connected"].clone(),
            close["intercept"].clone()
        ),
        (json!("upstream-tls-failed"), json!(true), json!(true))
    );
}

#[tokio::test]
async fn a_client_that_does_not_speak_tls_ends_client_tls_failed() {
    let r = rig(Opts::default());
    let (mut c, s) = duplex(1 << 16);
    let proxy = Arc::clone(&r.proxy);
    let task = tokio::spawn(async move { proxy.serve(s).await });
    let connect =
        format!("CONNECT {HOST}:443 HTTP/1.1\r\nHost: {HOST}:443\r\n\r\nGET / HTTP/1.1\r\n\r\n");
    c.write_all(connect.as_bytes()).await.unwrap();
    let out = drain(&mut c).await;
    join(task).await;
    assert!(out.starts_with("HTTP/1.1 200 "), "{out}");
    assert_eq!(
        r.sink.args("egress.close")["end"],
        json!("client-tls-failed")
    );
    assert!(r.seen().is_empty());
}

/// Architect Q53: silence after the handshake or after a response is an idle close, a started
/// head that stalls is a limit.
#[tokio::test]
async fn head_timeouts_are_limits_only_once_a_head_started() {
    let r = rig(Opts::default());
    let (_, tls, task) = r.open(443).await;
    let mut tls = tls.unwrap();
    let _ = drain(&mut tls).await;
    join(task).await;
    assert_eq!(r.sink.args("egress.close")["end"], json!("idle-timeout"));
    assert!(!r.sink.events().contains(&"egress.limit".to_owned()));

    let r = rig(Opts::default());
    let (_, tls, task) = r.open(443).await;
    let mut tls = tls.unwrap();
    tls.write_all(b"GET /echo HT").await.unwrap();
    tls.flush().await.unwrap();
    let _ = drain(&mut tls).await;
    join(task).await;
    assert_eq!(r.sink.args("egress.limit")["reason"], json!("head-timeout"));
    assert_eq!(r.sink.args("egress.close")["end"], json!("limit"));

    let r = rig(Opts::default());
    let (_, tls, task) = r.open(443).await;
    let mut tls = tls.unwrap();
    tls.write_all(get("/echo", "").as_bytes()).await.unwrap();
    let out = drain(&mut tls).await;
    join(task).await;
    assert!(out.starts_with("HTTP/1.1 200 "), "{out}");
    assert_eq!(r.sink.args("egress.close")["end"], json!("idle-timeout"));
    assert!(!r.sink.events().contains(&"egress.limit".to_owned()));
}

#[tokio::test]
async fn an_exchange_idle_past_the_limit_ends_idle_timeout() {
    // Five of the ten promised bytes, then nothing: the response body stalls.
    let hang: Handler =
        Arc::new(|_| Some("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort".into()));
    let r = rig(Opts {
        handler: hang,
        limits: Limits {
            head: Duration::from_secs(5),
            idle: Duration::from_millis(300),
            max_request: 16,
            max_response: 16,
            ..Limits::new(8)
        },
        ..Opts::default()
    });
    let started = Instant::now();
    // Nothing else ends this tunnel (no head is awaited mid-exchange), so a missing idle limit
    // would hang: bound the wait.
    let out = tokio::time::timeout(Duration::from_secs(5), r.talk(&get("/echo", "")))
        .await
        .expect("the idle limit ends a stalled exchange");
    assert!(out.contains("short"), "{out}");
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(r.sink.args("egress.close")["end"], json!("idle-timeout"));
    // The upstream connection goes with the tunnel, though its response never finished.
    upstream_ends(&r).await;
}

#[test]
fn the_idle_watch_fires_only_in_flight_and_never_spins() {
    let last = Instant::now();
    let idle = Duration::from_secs(300);
    let before = last + Duration::from_secs(1);
    let at = last + idle;
    let after = at + Duration::from_secs(7);
    for busy in [true, false] {
        assert_eq!(idle_wake(before, last, idle, busy), Some(at));
    }
    assert_eq!(idle_wake(at, last, idle, true), None);
    assert_eq!(idle_wake(after, last, idle, true), None);
    assert_eq!(idle_wake(at, last, idle, false), Some(at + idle));
    assert_eq!(idle_wake(after, last, idle, false), Some(after + idle));
}

#[test]
fn a_refusal_body_ends_once_its_text_is_taken() {
    assert!(Out::Reply(None).is_end_stream());
    assert!(!Out::Reply(Some(Bytes::from_static(b"x"))).is_end_stream());
}

/// Architect Q53: between exchanges only the head timer runs; the idle limit (shorter here)
/// does not end a keep-alive tunnel.
#[tokio::test]
async fn the_idle_limit_does_not_run_between_exchanges() {
    let r = rig(Opts {
        limits: Limits {
            head: Duration::from_secs(2),
            idle: Duration::from_millis(100),
            max_request: 16,
            max_response: 16,
            ..Limits::new(8)
        },
        ..Opts::default()
    });
    let (_, tls, task) = r.open(443).await;
    let mut tls = tls.unwrap();
    for _ in 0..2 {
        tls.write_all(get("/echo", "").as_bytes()).await.unwrap();
        bounded("a response", async {
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                assert_eq!(tls.read(&mut byte).await.unwrap(), 1, "tunnel ended early");
                head.push(byte[0]);
            }
            let mut body = [0u8; 2];
            tls.read_exact(&mut body).await.unwrap();
        })
        .await;
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    let _ = tls.shutdown().await;
    let _ = drain(&mut tls).await;
    join(task).await;
    assert_eq!(r.sink.args("egress.close")["requests"], json!(2));
}

#[tokio::test]
async fn a_failed_request_entry_closes_without_a_reply_or_an_upstream_request() {
    let r = rig(Opts {
        fail_on: Some("egress.request"),
        ..Opts::default()
    });
    let out = r.talk(&get("/echo", "")).await;
    assert!(out.is_empty(), "{out}");
    assert!(r.seen().is_empty());
    assert_eq!(r.sink.args("egress.close")["end"], json!("error"));
}

/// Architect ruling RQ2: a body-cap `egress.limit` that could not be written ends the tunnel
/// `error` with no reply. The request side would otherwise answer 413 and end `limit` with no
/// entry behind either.
#[tokio::test]
async fn a_failed_request_limit_entry_ends_error_without_a_413() {
    let r = rig(Opts {
        fail_on: Some("egress.limit"),
        ..Opts::default()
    });
    let raw = format!(
        "POST /echo HTTP/1.1\r\nHost: {HOST}\r\nTransfer-Encoding: chunked\r\n\r\n\
         10\r\n{}\r\n1\r\nq\r\n0\r\n\r\n",
        "q".repeat(16)
    );
    let out = r.talk(&raw).await;
    assert!(!out.contains("413"), "{out}");
    assert!(!r.sink.events().iter().any(|e| e == "egress.limit"));
    assert_eq!(r.sink.args("egress.close")["end"], json!("error"));
}

/// Architect ruling RQ2, response side: the cut still happens, and the tunnel ends `error`.
#[tokio::test]
async fn a_failed_response_limit_entry_still_cuts_and_ends_error() {
    let r = rig(Opts {
        fail_on: Some("egress.limit"),
        ..Opts::default()
    });
    let out = r.talk(&get("/chunks/17", "")).await;
    assert!(!out.contains(&"c".repeat(17)), "{out}");
    assert!(
        !out.ends_with("0\r\n\r\n"),
        "a cut sends no last chunk: {out}"
    );
    assert!(!r.sink.events().iter().any(|e| e == "egress.limit"));
    assert_eq!(r.sink.args("egress.close")["end"], json!("error"));
}

/// Waits (bounded) until the mock upstream saw its connection end.
async fn upstream_ends(r: &Rig) {
    until("the upstream connection closes with the tunnel", || {
        *r.ended.lock().unwrap() > 0
    })
    .await;
}

/// A stop ends the tunnel `session-stopped`, and the upstream connection goes with it (it is
/// driven inside the tunnel's future, never spawned): while a request waits for a head the
/// upstream never sends, and between exchanges on an idle keep-alive connection.
#[tokio::test]
async fn stopping_the_session_ends_an_intercepted_tunnel() {
    for in_flight in [true, false] {
        let r = rig(Opts {
            limits: Limits {
                head: Duration::from_secs(30),
                max_request: 16,
                max_response: 16,
                ..Limits::new(8)
            },
            ..Opts::default()
        });
        let (_, tls, task) = r.open(443).await;
        let mut tls = tls.unwrap();
        if in_flight {
            tls.write_all(get("/hang", "").as_bytes()).await.unwrap();
            until("the upstream sees the request", || !r.seen().is_empty()).await;
        } else {
            tls.write_all(get("/echo", "").as_bytes()).await.unwrap();
            bounded("the first response", async {
                let mut got = Vec::new();
                let mut b = [0u8; 1];
                while !got.ends_with(b"\r\n\r\nok") {
                    tls.read_exact(&mut b).await.unwrap();
                    got.push(b[0]);
                }
            })
            .await;
        }
        r.proxy.stop();
        let _ = drain(&mut tls).await;
        join(task).await;
        let close = r.sink.args("egress.close");
        assert_eq!(close["end"], json!("session-stopped"), "{in_flight}");
        upstream_ends(&r).await;
    }
}

#[tokio::test]
async fn an_intercepted_tunnel_on_another_allowed_port_names_it_in_host() {
    let r = rig(Opts::default());
    let (_, tls, task) = r.open(8443).await;
    let mut tls = tls.unwrap();
    tls.write_all(format!("GET /echo HTTP/1.1\r\nHost: {HOST}:8443\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let _ = tls.shutdown().await;
    let out = drain(&mut tls).await;
    join(task).await;
    assert!(out.starts_with("HTTP/1.1 200 "), "{out}");
    assert!(
        r.seen()[0]
            .to_ascii_lowercase()
            .contains("host: a.mock.test:8443\r\n")
    );
}

/// Architect ruling R7: each leaf's signer is built from its key in place, and a key that does
/// not belong to its certificate is refused (as `with_single_cert` refused it before).
#[test]
fn a_leaf_whose_key_is_not_its_certificates_is_refused() {
    let v = Validity::for_session(std::time::SystemTime::now(), Duration::from_secs(600)).unwrap();
    let hosts = [HOST.to_owned(), "b.mock.test".to_owned()];
    let roots = || crate::egress::roots::Roots {
        store: Arc::new(RootCertStore::empty()),
        pem: String::new(),
        skipped: 0,
        path: "/test-roots.pem".into(),
    };
    assert!(Interception::new(SessionTls::mint(&hosts, v).unwrap(), roots()).is_ok());
    let mut swapped = SessionTls::mint(&hosts, v).unwrap();
    let (a, b) = swapped.leaves.split_at_mut(1);
    std::mem::swap(&mut a[0].key, &mut b[0].key);
    assert!(matches!(
        Interception::new(swapped, roots()),
        Err(CaError::Generate(_))
    ));
}

#[test]
fn summaries_list_non_zero_status_classes_only() {
    let s = Summary {
        requests: 3,
        statuses: [0, 2, 0, 1, 0],
    };
    assert_eq!(s.statuses_json(), json!({"2xx": 2, "4xx": 1}));
    assert_eq!(Summary::default().statuses_json(), json!({}));
}
