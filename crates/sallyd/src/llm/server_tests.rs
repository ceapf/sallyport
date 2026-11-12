#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::rpc::testkit::{Sink, recorder};

const CONTEXT: u64 = 4096;

/// A backend that answers at once and remembers what it was given.
#[derive(Default)]
struct Fake {
    calls: AtomicUsize,
    seen: Mutex<Vec<Chat>>,
    fail: bool,
}

impl Backend for Arc<Fake> {
    async fn complete(&self, chat: Chat) -> Result<Reply, BackendError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let stream = chat.stream;
        self.seen.lock().unwrap().push(chat);
        if self.fail {
            return Err(BackendError);
        }
        if !stream {
            return Ok(Reply::Whole(
                json!({"object": "chat.completion", "choices": [
                    {"index": 0, "message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}
                ]}),
            ));
        }
        let (tx, rx) = mpsc::channel(4);
        tokio::spawn(async move {
            for t in ["a", "b"] {
                let _ = tx
                    .send(json!({"choices": [{"delta": {"content": t}}]}))
                    .await;
            }
        });
        Ok(Reply::Stream(rx))
    }
}

fn setup_with(fake: Fake) -> (Arc<Llm<Arc<Fake>>>, Arc<Fake>, Arc<Sink>) {
    let fake = Arc::new(fake);
    let (sink, rec) = recorder("sess-a");
    let settings = Settings {
        model: "local-model".into(),
        context: CONTEXT,
    };
    (
        Arc::new(Llm::new(Arc::clone(&fake), rec, settings)),
        fake,
        sink,
    )
}

fn setup() -> (Arc<Llm<Arc<Fake>>>, Arc<Fake>, Arc<Sink>) {
    setup_with(Fake::default())
}

/// Sends `raw`, half-closes, and returns everything the server wrote.
async fn exchange(llm: &Arc<Llm<Arc<Fake>>>, raw: &[u8]) -> String {
    let (mut client, server) = tokio::io::duplex(1 << 20);
    let task = tokio::spawn(Arc::clone(llm).serve_stream(server));
    client.write_all(raw).await.unwrap();
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), client.read_to_end(&mut out))
        .await
        .expect("no end of reply")
        .unwrap();
    task.await.unwrap();
    String::from_utf8_lossy(&out).into_owned()
}

fn post(body: &str) -> Vec<u8> {
    format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn chat(extra: Value) -> String {
    let mut b = json!({"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]});
    for (k, v) in extra.as_object().unwrap() {
        b[k] = v.clone();
    }
    b.to_string()
}

fn status(reply: &str) -> u16 {
    reply.get(9..12).and_then(|s| s.parse().ok()).unwrap_or(0)
}

fn body(reply: &str) -> Value {
    let start = reply.find("\r\n\r\n").unwrap() + 4;
    serde_json::from_str(&reply[start..]).unwrap()
}

fn denies(sink: &Sink) -> Vec<(String, Value)> {
    sink.rows()
        .into_iter()
        .filter(|r| r.event == "llm.deny")
        .map(|r| {
            (
                r.args["reason"].as_str().unwrap().to_owned(),
                r.args["status"].clone(),
            )
        })
        .collect()
}

#[tokio::test]
async fn models_names_the_sessions_model() {
    let (llm, fake, sink) = setup();
    let r = exchange(&llm, b"GET /v1/models HTTP/1.1\r\nHost: x\r\n\r\n").await;
    assert_eq!(status(&r), 200);
    assert_eq!(body(&r)["data"][0]["id"], json!("local-model"));
    assert_eq!(sink.events(), ["llm.request"]);
    assert_eq!(sink.last("llm.request"), json!({"path": "/v1/models"}));
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_chat_request_is_checked_recorded_then_answered() {
    let (llm, fake, sink) = setup();
    let b = chat(json!({}));
    let r = exchange(&llm, &post(&b)).await;
    assert_eq!(status(&r), 200, "{r}");
    assert_eq!(body(&r)["choices"][0]["message"]["content"], json!("hi"));
    assert_eq!(sink.events(), ["llm.request", "llm.response"]);
    let req = sink.last("llm.request");
    assert_eq!(req["messages"], json!(1));
    assert_eq!(req["stream"], json!(false));
    assert_eq!(req["bytes"], json!(b.len()));
    assert_eq!(req["sha256"].as_str().unwrap().len(), 64);
    // No limit asked for: the backend gets the context as its bound (ruling Q2).
    assert_eq!(req["max_tokens"], json!(CONTEXT));
    let seen = fake.seen.lock().unwrap();
    assert_eq!(seen[0].max_tokens, CONTEXT);
    // The model the harness named never reaches the backend (Task 7 decision 1).
    assert!(!seen[0].body.contains_key("model"));
    let resp = sink.rows()[1].clone();
    assert!(resp.debug.contains("detail: Full"));
    assert_eq!(resp.args["status"], json!(200));
}

#[tokio::test]
async fn a_streamed_reply_is_server_sent_events_then_done() {
    let (llm, _, sink) = setup();
    let r = exchange(&llm, &post(&chat(json!({"stream": true})))).await;
    assert_eq!(status(&r), 200);
    assert!(r.contains("text/event-stream"), "{r}");
    let a = r
        .find(r#"data: {"choices":[{"delta":{"content":"a"}}]}"#)
        .unwrap();
    let b = r
        .find(r#"data: {"choices":[{"delta":{"content":"b"}}]}"#)
        .unwrap();
    let done = r.find("data: [DONE]").unwrap();
    assert!(a < b && b < done);
    // The response entry follows the stream.
    tokio::time::timeout(Duration::from_secs(5), async {
        while sink.events().len() < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let resp = sink.last("llm.response");
    assert_eq!(
        (resp["events"].clone(), resp["cut"].clone()),
        (json!(2), json!(false))
    );
}

/// RT-INF-05 (llm.sock half): endpoints other than the two served are 404 and recorded; image
/// parts and `n: 5` are 400; the backend sees none of them.
#[tokio::test]
async fn rt_inf_05_other_endpoints_and_parts_never_reach_the_backend() {
    let (llm, fake, sink) = setup();
    for target in [
        "POST /v1/completions",
        "POST /models/load",
        "GET /props",
        "GET /slots",
        "POST /tokenize",
        "POST /v1/embeddings",
        "GET /v1/chat/completions",
        "POST /v1/models",
        "POST /v1/chat/completions/",
        "POST /v1/chat/completions?x=1",
        "OPTIONS *",
        "GET /health",
    ] {
        let r = exchange(
            &llm,
            format!("{target} HTTP/1.1\r\nContent-Length: 2\r\n\r\n{{}}").as_bytes(),
        )
        .await;
        assert_eq!(status(&r), 404, "{target}: {r}");
    }
    let image = json!({"messages": [{"role": "user", "content": [
        {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}}
    ]}]});
    let r = exchange(&llm, &post(&image.to_string())).await;
    assert_eq!(
        (status(&r), body(&r)["error"]["code"].clone()),
        (400, json!("non-text-part"))
    );
    assert_eq!(
        body(&r)["error"]["param"],
        json!("messages[0].content[0].type")
    );
    let r = exchange(&llm, &post(&chat(json!({"n": 5})))).await;
    assert_eq!(
        (status(&r), body(&r)["error"]["code"].clone()),
        (400, json!("n-must-be-1"))
    );
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
    let d = denies(&sink);
    assert_eq!(d.len(), 14);
    assert!(
        d[..12]
            .iter()
            .all(|(r, s)| r == "not-found" && *s == json!(404))
    );
    let first = sink.rows()[0].args.clone();
    assert_eq!(first["path"], json!("/v1/completions"));
    assert_eq!(first["method"], json!("POST"));
    assert_eq!(sink.rows()[13].args["field"], json!("n"));
}

/// RT-INF-03 on llm.sock (ruling Q4): unknown fields, a huge token limit, a 10 MiB body, `n:
/// 100`, `logit_bias`; and a path-like `model`, which is dropped (Task 7 decision 1) so the
/// backend never sees it.
#[tokio::test]
async fn rt_inf_03_request_validation_on_llm_sock() {
    let (llm, fake, sink) = setup();
    for (extra, code) in [
        (json!({"logit_bias": {"1": 100}}), "unknown-field"),
        (json!({"logprobs": true}), "unknown-field"),
        (json!({"max_tokens": 1_000_000_000u64}), "token-limit"),
        (json!({"max_tokens": CONTEXT + 1}), "token-limit"),
        (json!({"n": 100}), "n-must-be-1"),
    ] {
        let r = exchange(&llm, &post(&chat(extra.clone()))).await;
        assert_eq!(
            (status(&r), body(&r)["error"]["code"].clone()),
            (400, json!(code)),
            "{extra}"
        );
    }
    // 10 MiB: refused from its Content-Length, before a byte of it is read.
    let big = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
        10 * 1024 * 1024
    );
    let r = exchange(&llm, big.as_bytes()).await;
    assert_eq!(status(&r), 413);
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        denies(&sink).last().unwrap(),
        &("body-too-large".to_owned(), json!(413))
    );
    let r = exchange(
        &llm,
        &post(&chat(json!({"model": "../../models/other.gguf"}))),
    )
    .await;
    assert_eq!(status(&r), 200);
    let seen = fake.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert!(!seen[0].body.contains_key("model"));
}

#[tokio::test]
async fn a_body_over_the_cap_is_refused_while_read() {
    // A Content-Length at the cap passes the head check; the body reader enforces it too.
    let (llm, fake, _) = setup();
    let mut b = chat(json!({}));
    b.push_str(&" ".repeat(body::MAX_BODY - b.len()));
    let r = exchange(&llm, &post(&b)).await;
    assert_eq!(status(&r), 200);
    let over = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
        body::MAX_BODY + 1
    );
    let r = exchange(&llm, over.as_bytes()).await;
    assert_eq!(status(&r), 413);
    assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn heads_the_broker_refuses_are_answered_by_it() {
    let (llm, fake, sink) = setup();
    for (raw, code, reason) in [
        (&b"GARBAGE\r\n\r\n"[..], 400, "malformed"),
        (b"GET /v1/models HTTP/1.0\r\n\r\n", 400, "http-version"),
        (
            b"POST /v1/chat/completions HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
            400,
            "transfer-encoding",
        ),
        (
            b"POST /v1/chat/completions HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
            400,
            "content-length",
        ),
        (
            b"POST /v1/chat/completions HTTP/1.1\r\n\r\n",
            411,
            "length-required",
        ),
        (
            b"GET /v1/models HTTP/1.1\r\nContent-Length: 1\r\n\r\nx",
            400,
            "unexpected-body",
        ),
    ] {
        let r = exchange(&llm, raw).await;
        assert_eq!(status(&r), code, "{r}");
        assert_eq!(body(&r)["error"]["code"], json!(reason));
        assert!(r.contains("Connection: close"));
    }
    let mut big = b"GET /v1/models HTTP/1.1\r\n".to_vec();
    big.extend_from_slice(format!("X: {}\r\n\r\n", "a".repeat(head::MAX_HEAD)).as_bytes());
    let r = exchange(&llm, &big).await;
    assert_eq!(status(&r), 431);
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
    assert_eq!(denies(&sink).len(), 7);
}

/// Heads two parsers could read differently, end to end: the broker refuses each with its own
/// entry, or serves exactly the request it checked (architect ruling on the head pre-read).
#[tokio::test]
async fn ambiguous_heads_are_refused_or_served_as_checked() {
    let (llm, fake, sink) = setup();
    let chat_line = "POST /v1/chat/completions HTTP/1.1";
    let b = chat(json!({}));
    let n = b.len();
    for (raw, code, reason) in [
        (
            format!("{chat_line}\r\nContent-Length: {n}\r\nContent-Length: {n}\r\n\r\n{b}"),
            400,
            "content-length",
        ),
        (
            format!("{chat_line}\r\nTransfer-Encoding: chunked\r\nContent-Length: {n}\r\n\r\n{b}"),
            400,
            "transfer-encoding",
        ),
        (
            format!("{chat_line}\r\nX-A: a\r\n Content-Length: {n}\r\n\r\n{b}"),
            400,
            "malformed",
        ),
        (
            format!("{chat_line}\r\nContent-Length:\r\n {n}\r\n\r\n{b}"),
            400,
            "malformed",
        ),
    ] {
        let r = exchange(&llm, raw.as_bytes()).await;
        assert_eq!(
            (status(&r), body(&r)["error"]["code"].clone()),
            (code, json!(reason)),
            "{raw:?}"
        );
    }
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
    assert_eq!(denies(&sink).len(), 4);
    // Bare line feeds: both parsers read the same request, so it is served.
    let r = exchange(
        &llm,
        format!("{chat_line}\nContent-Length: {n}\n\n{b}").as_bytes(),
    )
    .await;
    assert_eq!(status(&r), 200, "{r}");
    assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
    assert_eq!(sink.last("llm.request")["bytes"], json!(n));
}

#[tokio::test(start_paused = true)]
async fn a_slow_head_is_closed_unanswered_and_recorded() {
    let (llm, _, sink) = setup();
    let (mut client, server) = tokio::io::duplex(1024);
    let task = tokio::spawn(Arc::clone(&llm).serve_stream(server));
    client.write_all(b"GET /v1/mod").await.unwrap();
    let mut out = Vec::new();
    client.read_to_end(&mut out).await.unwrap();
    task.await.unwrap();
    assert!(out.is_empty());
    assert_eq!(denies(&sink), [("head-timeout".to_owned(), Value::Null)]);
}

#[tokio::test]
async fn an_empty_connection_leaves_no_entry_and_a_cut_head_does() {
    let (llm, _, sink) = setup();
    assert_eq!(exchange_closed(&llm, b"").await, "");
    assert!(sink.rows().is_empty());
    assert_eq!(exchange_closed(&llm, b"GET /v1/mo").await, "");
    assert_eq!(denies(&sink), [("incomplete-head".to_owned(), Value::Null)]);
}

async fn exchange_closed(llm: &Arc<Llm<Arc<Fake>>>, raw: &[u8]) -> String {
    let (mut client, server) = tokio::io::duplex(1024);
    let task = tokio::spawn(Arc::clone(llm).serve_stream(server));
    client.write_all(raw).await.unwrap();
    client.shutdown().await.unwrap();
    let mut out = Vec::new();
    client.read_to_end(&mut out).await.unwrap();
    task.await.unwrap();
    String::from_utf8_lossy(&out).into_owned()
}

/// Architect ruling Q14: a client that sends its whole request and then shuts its write side
/// (the shim passes that on) gets the full reply, with its entries in order, on both routes.
#[tokio::test]
async fn a_half_closed_client_is_answered() {
    let (llm, fake, sink) = setup();
    let r = exchange_closed(&llm, b"GET /v1/models HTTP/1.1\r\n\r\n").await;
    assert_eq!(status(&r), 200, "{r}");
    assert_eq!(body(&r)["data"][0]["id"], json!("local-model"));
    assert_eq!(sink.events(), ["llm.request"]);
    let r = exchange_closed(&llm, &post(&chat(json!({})))).await;
    assert_eq!(status(&r), 200, "{r}");
    assert_eq!(body(&r)["choices"][0]["message"]["content"], json!("hi"));
    assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        sink.events(),
        ["llm.request", "llm.request", "llm.response"]
    );
    let r = exchange_closed(&llm, &post(&chat(json!({"stream": true})))).await;
    assert!(r.contains("data: [DONE]\n\n"), "{r}");
}

/// A half-closed client whose body is cut short is refused `400 body-error` after its entry;
/// no reply ever goes out without one.
#[tokio::test]
async fn a_half_closed_client_with_a_short_body_is_refused() {
    let (llm, fake, sink) = setup();
    let r = exchange_closed(
        &llm,
        b"POST /v1/chat/completions HTTP/1.1\r\nContent-Length: 100\r\n\r\n{\"messages\"",
    )
    .await;
    assert_eq!(
        (status(&r), body(&r)["error"]["code"].clone()),
        (400, json!("body-error"))
    );
    assert_eq!(denies(&sink), [("body-error".to_owned(), json!(400))]);
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
}

/// A peer that closes both directions right after its request still ends the connection (its
/// task returns, so its slot is free) and leaves its entry.
#[tokio::test]
async fn a_peer_gone_after_its_request_ends_the_connection() {
    let (llm, _, sink) = setup();
    let (mut client, server) = tokio::io::duplex(1024);
    let task = tokio::spawn(Arc::clone(&llm).serve_stream(server));
    client.write_all(&post(&chat(json!({})))).await.unwrap();
    drop(client);
    tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .expect("the connection outlived its peer")
        .unwrap();
    assert_eq!(
        sink.events().first().map(String::as_str),
        Some("llm.request")
    );
}

#[tokio::test(start_paused = true)]
async fn a_slow_body_is_refused_after_its_timeout() {
    let (llm, fake, sink) = setup();
    let (mut client, server) = tokio::io::duplex(1 << 16);
    let task = tokio::spawn(Arc::clone(&llm).serve_stream(server));
    client
        .write_all(
            b"POST /v1/chat/completions HTTP/1.1\r\nContent-Length: 100\r\n\r\n{\"messages\"",
        )
        .await
        .unwrap();
    let mut out = Vec::new();
    client.read_to_end(&mut out).await.unwrap();
    task.await.unwrap();
    assert_eq!(status(&String::from_utf8_lossy(&out)), 408);
    assert_eq!(denies(&sink), [("body-timeout".to_owned(), json!(408))]);
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_backend_failure_is_a_recorded_502() {
    let (llm, _, sink) = setup_with(Fake {
        fail: true,
        ..Fake::default()
    });
    let r = exchange(&llm, &post(&chat(json!({})))).await;
    assert_eq!(status(&r), 502);
    assert_eq!(body(&r)["error"]["type"], json!("server_error"));
    assert_eq!(sink.events(), ["llm.request", "llm.response"]);
    assert_eq!(sink.last("llm.response")["status"], json!(502));
}

#[tokio::test]
async fn a_failed_request_entry_means_no_backend_call_and_no_reply() {
    let (llm, fake, sink) = setup();
    sink.fail_next.store(1, Ordering::SeqCst);
    let r = exchange(&llm, &post(&chat(json!({})))).await;
    assert_eq!(r, "", "a reply went out without its entry");
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
    // hyper's own answer was held back by the gate; the close is recorded afterwards.
    assert_eq!(denies(&sink), [("http-error".to_owned(), Value::Null)]);
    sink.set_failing(true);
    for raw in [
        &post(&chat(json!({"n": 2})))[..],
        b"GET /nope HTTP/1.1\r\n\r\n",
        b"GET /v1/models HTTP/1.1\r\n\r\n",
    ] {
        assert_eq!(exchange(&llm, raw).await, "");
    }
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn requests_are_read_at_the_session_rate() {
    let (llm, _, sink) = setup();
    let started = tokio::time::Instant::now();
    let n = 20u32;
    for _ in 0..n {
        exchange(&llm, b"GET /v1/models HTTP/1.1\r\n\r\n").await;
    }
    // BURST at once, then RATE per second: (20 − 10) / 5 = 2 s.
    let took = started.elapsed();
    let expect = Duration::from_secs(u64::from((n - BURST) / RATE));
    assert!(
        took >= expect && took < expect + Duration::from_millis(100),
        "{took:?}"
    );
    assert_eq!(sink.rows().len(), n as usize);
}

#[tokio::test]
async fn a_peer_with_another_uid_is_refused_and_recorded() {
    let dir = std::env::temp_dir().join(format!("sp-llm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("llm.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let (llm, _, sink) = setup();
    let me = rustix::process::getuid().as_raw();
    let h = Arc::clone(&llm).listen(listener, me.wrapping_add(1));
    let mut s = UnixStream::connect(&path).await.unwrap();
    let _ = s.write_all(b"GET /v1/models HTTP/1.1\r\n\r\n").await;
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out)).await;
    assert!(out.is_empty());
    assert_eq!(
        sink.last("llm.deny"),
        json!({"reason": "peer-uid", "uid": me})
    );
    h.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn hashes_are_lowercase_hex() {
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(hex(&[0, 255, 16]), "00ff10");
}

fn checked(method: &str, path: &str, content_length: Option<u64>) -> Head {
    Head {
        method: method.into(),
        path: path.into(),
        content_length,
        len: 0,
    }
}

fn hyper_req(
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &'static str,
) -> hyper::Request<http_body_util::Full<Bytes>> {
    let mut b = hyper::Request::builder()
        .method(method)
        .uri(path)
        .version(hyper::Version::HTTP_11);
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    b.body(http_body_util::Full::new(Bytes::from_static(
        body.as_bytes(),
    )))
    .unwrap()
}

#[test]
fn hyper_must_read_the_request_the_broker_checked() {
    let chat = checked("POST", "/v1/chat/completions", Some(2));
    let same = || {
        hyper_req(
            "POST",
            "/v1/chat/completions",
            &[("content-length", "2")],
            "{}",
        )
    };
    assert!(agrees(&chat, &same()));
    // Each field read differently is a mismatch.
    let other_method = hyper_req(
        "PUT",
        "/v1/chat/completions",
        &[("content-length", "2")],
        "{}",
    );
    assert!(!agrees(&chat, &other_method));
    let other_path = hyper_req("POST", "/v1/models", &[("content-length", "2")], "{}");
    assert!(!agrees(&chat, &other_path));
    let mut http10 = same();
    *http10.version_mut() = hyper::Version::HTTP_10;
    assert!(!agrees(&chat, &http10));
    let te = hyper_req(
        "POST",
        "/v1/chat/completions",
        &[("content-length", "2"), ("transfer-encoding", "chunked")],
        "{}",
    );
    assert!(!agrees(&chat, &te));
    let other_length = hyper_req(
        "POST",
        "/v1/chat/completions",
        &[("content-length", "3")],
        "{}x",
    );
    assert!(!agrees(&chat, &other_length));
    let two_lengths = hyper_req(
        "POST",
        "/v1/chat/completions",
        &[("content-length", "2"), ("content-length", "2")],
        "{}",
    );
    assert!(!agrees(&chat, &two_lengths));
    // A body length hyper frames differently from the header the broker read.
    let unframed = hyper_req(
        "POST",
        "/v1/chat/completions",
        &[("content-length", "2")],
        "{}x",
    );
    assert!(!agrees(&chat, &unframed));
    // No Content-Length: hyper must see none, and an empty body.
    let models = checked("GET", "/v1/models", None);
    assert!(agrees(&models, &hyper_req("GET", "/v1/models", &[], "")));
    let zero = hyper_req("GET", "/v1/models", &[("content-length", "0")], "");
    assert!(!agrees(&models, &zero));
    assert!(agrees(&checked("GET", "/v1/models", Some(0)), &zero));
    assert!(!agrees(&models, &hyper_req("GET", "/v1/models", &[], "x")));
    // The request-target compares as sent: no query, no absolute form, no case folding.
    assert!(!agrees(&models, &hyper_req("GET", "/v1/models?x", &[], "")));
    assert!(!agrees(&models, &hyper_req("GET", "/V1/models", &[], "")));
    let absolute = checked("GET", "http://x/v1/models", None);
    assert!(!agrees(
        &absolute,
        &hyper_req("GET", "http://x/v1/models", &[], "")
    ));
    let authority = checked("GET", "x:80", None);
    assert!(!agrees(&authority, &hyper_req("GET", "x:80", &[], "")));
}

#[tokio::test]
async fn a_request_hyper_reads_differently_is_closed_unanswered_and_recorded() {
    // Force a disagreement: the broker checked one head, the replayed bytes hold another.
    let (llm, fake, sink) = setup();
    let (mut client, server) = tokio::io::duplex(1 << 16);
    let checked_head = checked("GET", "/v1/models", None);
    let replay = b"GET /v1/models?x HTTP/1.1\r\n\r\n".to_vec();
    let task =
        tokio::spawn(Arc::clone(&llm).hand_to_hyper(server, replay, Route::Models, checked_head));
    // The client keeps its write side open: the mismatch alone must close the connection.
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), client.read_to_end(&mut out))
        .await
        .expect("the connection stayed open")
        .unwrap();
    task.await.unwrap();
    assert!(out.is_empty(), "{}", String::from_utf8_lossy(&out));
    assert_eq!(denies(&sink), [("head-mismatch".to_owned(), Value::Null)]);
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
    assert!(!sink.events().contains(&"llm.request".to_owned()));
}

#[test]
fn the_reply_cap_is_16_mib_and_a_close_names_itself() {
    assert_eq!(MAX_RESPONSE, 16_777_216);
    assert_eq!(Closed.to_string(), "closed");
}

#[tokio::test]
async fn models_takes_an_empty_body_with_its_length_stated() {
    let (llm, _, _) = setup();
    let r = exchange(
        &llm,
        b"GET /v1/models HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
    )
    .await;
    assert_eq!(status(&r), 200, "{r}");
}

#[tokio::test]
async fn the_server_stop_ends_a_live_connection() {
    let (llm, _, sink) = setup();
    let (_client, server) = tokio::io::duplex(1024);
    let task = tokio::spawn(Arc::clone(&llm).serve_stream(server));
    tokio::task::yield_now().await;
    Server::stop(&*llm);
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("stop left the connection open")
        .unwrap();
    assert!(sink.rows().is_empty());
}

/// Streams events of the given encoded sizes through [`pump`]; the `llm.response` arguments and
/// what reached the peer.
async fn pumped(sizes: &[usize]) -> (Value, Vec<Bytes>) {
    let (sink, rec) = recorder("sess-a");
    let (events_tx, events_rx) = mpsc::channel(sizes.len());
    for &n in sizes {
        let v = json!("x".repeat(n - 10));
        assert_eq!(reply::event(&v).len(), n);
        events_tx.send(v).await.unwrap();
    }
    drop(events_tx);
    let (tx, mut rx) = mpsc::channel(4);
    let task = tokio::spawn(pump(events_rx, tx, rec));
    let mut out = Vec::new();
    while let Some(b) = rx.recv().await {
        out.push(b);
    }
    task.await.unwrap();
    (sink.last("llm.response"), out)
}

#[tokio::test]
async fn a_stream_of_exactly_the_cap_is_whole_and_one_byte_more_is_cut() {
    let (resp, out) = pumped(&[MAX_RESPONSE]).await;
    assert_eq!(
        (resp["cut"].clone(), resp["events"].clone()),
        (json!(false), json!(1))
    );
    assert_eq!(out.len(), 2);
    assert_eq!(&out[1][..], reply::DONE);
    let (resp, out) = pumped(&[MAX_RESPONSE - 20, 20]).await;
    assert_eq!(
        (resp["cut"].clone(), resp["bytes"].clone()),
        (json!(false), json!(MAX_RESPONSE))
    );
    assert_eq!(out.len(), 3);
    let (resp, out) = pumped(&[MAX_RESPONSE + 1]).await;
    assert_eq!(
        (resp["cut"].clone(), resp["events"].clone()),
        (json!(true), json!(0))
    );
    assert!(out.is_empty(), "a cut stream ends without [DONE]");
    let (resp, out) = pumped(&[MAX_RESPONSE - 20, 21]).await;
    assert_eq!(
        (resp["cut"].clone(), resp["bytes"].clone()),
        (json!(true), json!(MAX_RESPONSE - 20))
    );
    assert_eq!(out.len(), 1);
}
