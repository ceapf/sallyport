//! Probe (architect ruling Q9): what hyper itself writes when it refuses a request head. These
//! pin the behaviour that makes `llm.sock` read the head itself and gate hyper's writes.
#![allow(clippy::unwrap_used)]

use std::convert::Infallible;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::head::{Head, Parsed, parse};
use super::server::agrees;

async fn hyper_reply(input: &[u8]) -> (String, bool) {
    let (mut client, server) = tokio::io::duplex(1 << 20);
    let called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let seen = std::sync::Arc::clone(&called);
    let task = tokio::spawn(async move {
        let svc = service_fn(move |_req| {
            seen.store(true, std::sync::atomic::Ordering::SeqCst);
            async {
                Ok::<_, Infallible>(hyper::Response::new(Full::new(Bytes::from_static(b"ok"))))
            }
        });
        let _ = http1::Builder::new()
            .keep_alive(false)
            .serve_connection(TokioIo::new(server), svc)
            .await;
    });
    client.write_all(input).await.unwrap();
    client.shutdown().await.unwrap();
    let mut out = Vec::new();
    client.read_to_end(&mut out).await.unwrap();
    task.await.unwrap();
    (
        String::from_utf8_lossy(&out).into_owned(),
        called.load(std::sync::atomic::Ordering::SeqCst),
    )
}

#[tokio::test]
async fn hyper_answers_a_malformed_head_without_calling_the_service() {
    for input in [
        &b"GARBAGE\r\n\r\n"[..],
        b"POST /v1/chat/completions HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
        b"GET / HTTP/1.1\r\nbad header\r\n\r\n",
    ] {
        let (reply, called) = hyper_reply(input).await;
        assert!(!called, "{input:?}");
        assert!(reply.starts_with("HTTP/1.1 400"), "{input:?}: {reply:?}");
    }
}

#[tokio::test]
async fn hyper_answers_an_oversize_head_without_calling_the_service() {
    let mut big = b"GET / HTTP/1.1\r\n".to_vec();
    for i in 0..200 {
        big.extend_from_slice(format!("X-{i}: {}\r\n", "a".repeat(1000)).as_bytes());
    }
    big.extend_from_slice(b"\r\n");
    let (reply, called) = hyper_reply(&big).await;
    assert!(!called);
    assert!(reply.starts_with("HTTP/1.1 431"), "{reply:?}");
}

/// What hyper made of `input`: `None` when it refused it (the service never ran), otherwise
/// whether it read the request `checked` describes.
async fn hyper_view(input: &[u8], checked: Option<Head>) -> Option<bool> {
    let (mut client, server) = tokio::io::duplex(1 << 20);
    let seen = std::sync::Arc::new(std::sync::Mutex::new(None));
    let out = std::sync::Arc::clone(&seen);
    let task = tokio::spawn(async move {
        let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
            let agree = checked.as_ref().is_some_and(|h| agrees(h, &req));
            *out.lock().unwrap() = Some(agree);
            async {
                Ok::<_, Infallible>(hyper::Response::new(Full::new(Bytes::from_static(b"ok"))))
            }
        });
        let _ = http1::Builder::new()
            .keep_alive(false)
            .serve_connection(TokioIo::new(server), svc)
            .await;
    });
    // No half-close here: this builder keeps hyper's default (`half_close` off), under which a
    // peer that has shut its write side gets no reply, which would hide what it made of the head.
    client.write_all(input).await.unwrap();
    let mut sink = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        client.read_to_end(&mut sink),
    )
    .await
    .unwrap()
    .unwrap();
    task.await.unwrap();
    *seen.lock().unwrap()
}

/// hyper (`half_close` off) calls the service for a complete request whose peer has already
/// shut its write side, then drops the reply: the peer gets nothing (the broker records the
/// close as `http-error` unless the request entry was already written).
#[tokio::test]
async fn hyper_never_answers_a_half_closed_peer() {
    let (reply, called) = hyper_reply(b"GET /v1/models HTTP/1.1\r\n\r\n").await;
    assert!(called);
    assert_eq!(reply, "");
}

/// A half-closed peer's request through a builder with `half_close` as given, served by a
/// service that answers after a short wait: (reply, whether the service ran to its end).
async fn half_closed(half_close: bool) -> (String, bool) {
    let (mut client, server) = tokio::io::duplex(1 << 20);
    let finished = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let done = std::sync::Arc::clone(&finished);
    let task = tokio::spawn(async move {
        let svc = service_fn(move |_req| {
            let done = std::sync::Arc::clone(&done);
            async move {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                done.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok::<_, Infallible>(hyper::Response::new(Full::new(Bytes::from_static(b"ok"))))
            }
        });
        let _ = http1::Builder::new()
            .keep_alive(false)
            .half_close(half_close)
            .serve_connection(TokioIo::new(server), svc)
            .await;
    });
    client
        .write_all(b"GET /v1/models HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    client.shutdown().await.unwrap();
    let mut out = Vec::new();
    client.read_to_end(&mut out).await.unwrap();
    task.await.unwrap();
    // Long enough for a service that was not dropped to finish.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    (
        String::from_utf8_lossy(&out).into_owned(),
        finished.load(std::sync::atomic::Ordering::SeqCst),
    )
}

/// With `half_close` off (hyper's default), the read EOF drops the service future mid-way: a
/// half-closed peer gets nothing and the service never finishes. With it on (what `llm.sock`
/// sets, architect ruling Q14), the service runs to its end and the peer gets the reply.
#[tokio::test]
async fn half_close_decides_whether_a_half_closed_peer_is_served() {
    let (reply, finished) = half_closed(false).await;
    assert_eq!((reply.as_str(), finished), ("", false));
    let (reply, finished) = half_closed(true).await;
    assert!(reply.starts_with("HTTP/1.1 200"), "{reply:?}");
    assert!(reply.ends_with("ok"), "{reply:?}");
    assert!(finished);
}

/// The architect's condition on the head pre-read: the broker decides on its one parse, and hyper
/// never reads a head the broker accepted as some other request. Heads two parsers could read
/// differently: the broker either refuses each, or accepts it exactly as hyper reads it.
#[tokio::test]
async fn hyper_never_reads_an_accepted_head_differently() {
    use Parsed::{Complete, Refused};
    const CHAT: &str = "POST /v1/chat/completions HTTP/1.1";
    const MODELS: &str = "GET /v1/models HTTP/1.1";
    // (input, what the broker makes of it, whether hyper accepts it)
    let cases = [
        // Duplicate Content-Length: hyper takes equal values; the broker refuses every form.
        (
            format!("{CHAT}\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{{}}"),
            "content-length",
            true,
        ),
        (
            format!("{CHAT}\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n{{}}x"),
            "content-length",
            false,
        ),
        (
            format!("{CHAT}\r\nContent-Length: 2, 2\r\n\r\n{{}}"),
            "content-length",
            false,
        ),
        // Content-Length with Transfer-Encoding, in both orders: hyper reads the chunked body.
        (
            format!("{CHAT}\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"),
            "transfer-encoding",
            true,
        ),
        (
            format!("{CHAT}\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n0\r\n\r\n"),
            "transfer-encoding",
            true,
        ),
        (
            format!("{CHAT}\r\nTransfer-Encoding: identity\r\nContent-Length: 2\r\n\r\n{{}}"),
            "transfer-encoding",
            false,
        ),
        // Folded (obs-fold) headers.
        (
            format!("{MODELS}\r\nX-A: a\r\n b\r\n\r\n"),
            "malformed",
            false,
        ),
        (
            format!("{CHAT}\r\nContent-Length:\r\n 2\r\n\r\n{{}}"),
            "malformed",
            false,
        ),
        (
            format!("{CHAT}\r\nX-A: a\r\n\tContent-Length: 9\r\nContent-Length: 2\r\n\r\n{{}}"),
            "malformed",
            false,
        ),
        // Whitespace before the colon.
        (
            format!("{CHAT}\r\nContent-Length : 2\r\n\r\n{{}}"),
            "malformed",
            false,
        ),
        // Bare line feeds, alone and mixed with CRLF.
        (format!("{CHAT}\nContent-Length: 2\n\n{{}}"), "ok", true),
        (
            format!("{MODELS}\r\nX-A: a\nContent-Length: 0\r\n\n"),
            "ok",
            true,
        ),
        // A bare carriage return.
        (
            format!("{MODELS}\rContent-Length: 0\r\n\r\n"),
            "malformed",
            false,
        ),
        // A leading empty line, and padding around the length value.
        (format!("\r\n{MODELS}\r\n\r\n"), "ok", true),
        (
            format!("{CHAT}\r\nContent-Length:   2  \r\n\r\n{{}}"),
            "ok",
            true,
        ),
        // A signed Content-Length.
        (
            format!("{CHAT}\r\nContent-Length: +2\r\n\r\n{{}}"),
            "content-length",
            false,
        ),
    ];
    for (input, broker, hyper_accepts) in &cases {
        let (input, broker, hyper_accepts) = (input.as_bytes(), *broker, *hyper_accepts);
        let shown = String::from_utf8_lossy(input);
        let ours = parse(input);
        let checked = match &ours {
            Complete(h) => {
                assert_eq!(broker, "ok", "{shown:?}");
                Some(h.clone())
            }
            Refused(r) => {
                assert_eq!(broker, *r, "{shown:?}");
                None
            }
            other => panic!("{shown:?}: {other:?}"),
        };
        let view = hyper_view(input, checked).await;
        // Where the broker is stricter than hyper, the row records it.
        assert_eq!(view.is_some(), hyper_accepts, "{shown:?}");
        // The condition itself: every head the broker accepts, hyper reads the same way.
        if matches!(ours, Complete(_)) {
            assert_eq!(view, Some(true), "{shown:?}");
        }
    }
}
