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
