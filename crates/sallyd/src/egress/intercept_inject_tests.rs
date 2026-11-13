//! Injection and response redaction in intercepted tunnels (Task 9a-3), on the rig in
//! `intercept_rig.rs`. The rig's grant is `T0` on `a.mock.test`: `Authorization: Bearer
//! <value(0)>`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

/// Limits large enough for an echoed head and value.
fn roomy() -> Limits {
    Limits {
        head: Duration::from_millis(500),
        idle: Duration::from_secs(2),
        max_request: 4096,
        max_response: 4096,
        ..Limits::new(8)
    }
}

fn echoing(handler: Handler) -> Rig {
    rig(Opts {
        handler,
        limits: roomy(),
        ..Opts::default()
    })
}

/// The `authorization` line of a request the mock received, as sent.
fn auth_line(req: &str) -> String {
    req.lines()
        .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
        .unwrap_or_default()
        .to_owned()
}

/// The bearer token of a request the mock received, or `""`.
fn token(req: &str) -> String {
    auth_line(req)
        .split_once("Bearer ")
        .map_or(String::new(), |(_, t)| t.to_owned())
}

/// Echoes the request's credential in a header and in a body split into three writes, one
/// boundary inside the value (decision 3). Content-Length framed.
fn echo_split(req: &str) -> Option<String> {
    let line = auth_line(req);
    let token = token(req);
    let (a, b) = token.split_at(token.len() / 2);
    let body = format!("{{\"seen\":\"{token}\"}}");
    Some(format!(
        "HTTP/1.1 200 OK\r\nX-Echo: {line}\r\nContent-Length: {}\r\n\r\n{{\"seen\":\"{a}{PAUSE}{b}\"}}{PAUSE}",
        body.len()
    ))
}

/// RT-SEC-03/06 building block: the upstream receives the real credential, the client's copy is
/// gone, and every echo of it reaches the client redacted at the same length.
#[tokio::test]
async fn an_echoed_credential_is_redacted_in_headers_and_across_body_writes() {
    let r = echoing(Arc::new(echo_split));
    let out = r
        .talk(&get("/echo", "Authorization: Bearer attacker\r\n"))
        .await;
    let secret = value(0);
    // Positive control: the mock received the real value (and echoed it).
    let up = &r.seen()[0];
    assert!(up.contains(&format!("Bearer {secret}")), "{up}");
    assert!(!up.contains("attacker"), "{up}");
    // The client sees no form of it, filler at its offset and length instead, and the length
    // the upstream sent.
    assert!(!out.contains(&secret), "{out}");
    let fill = |n: usize| "*".repeat(n);
    // The rendered header value (`Bearer <value>`) is a form of its own, so it goes whole.
    let rendered = "Bearer ".len() + secret.len();
    assert!(
        out.contains(&format!("x-echo: authorization: {}\r\n", fill(rendered))),
        "{out}"
    );
    let body = format!("{{\"seen\":\"{}\"}}", fill(secret.len()));
    assert!(out.ends_with(&body), "{out}");
    assert!(
        out.contains(&format!("content-length: {}\r\n", body.len())),
        "{out}"
    );
    // Architect Q13: the response's entry names the secret and the bytes, header and body.
    let entry = r.sink.args("egress.response");
    let bytes = (rendered + secret.len()) as u64;
    assert_eq!(
        entry["redacted"],
        json!([{"secret": "secret:T0", "bytes": bytes}])
    );
    assert_eq!(entry["redacted_bytes"], json!(bytes));
    assert_eq!(entry["end"], json!("complete"));
}

/// The same over a chunked response whose chunks split the value.
#[tokio::test]
async fn a_chunked_echo_split_inside_the_value_is_redacted() {
    let r = echoing(Arc::new(|req: &str| {
        let token = token(req);
        let (a, b) = token.split_at(5);
        Some(format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
             {:x}\r\nx{a}\r\n{PAUSE}{:x}\r\n{b}y\r\n{PAUSE}0\r\n\r\n",
            a.len() + 1,
            b.len() + 1
        ))
    }));
    let out = r.talk(&get("/echo", "")).await;
    let secret = value(0);
    assert!(!out.contains(&secret), "{out}");
    assert!(!out.contains(&secret[5..]), "{out}");
    let mut body = String::new();
    // De-chunk the client's view.
    let mut rest = out.split_once("\r\n\r\n").unwrap().1;
    while let Some((size, tail)) = rest.split_once("\r\n") {
        let n = usize::from_str_radix(size, 16).unwrap();
        if n == 0 {
            break;
        }
        body.push_str(&tail[..n]);
        rest = &tail[n + 2..];
    }
    assert_eq!(body, format!("x{}y", "*".repeat(secret.len())));
}

/// Architect D5: a form reaching into a header name is refused before anything is forwarded.
#[tokio::test]
async fn a_credential_in_a_response_header_name_is_refused_unforwarded() {
    let r = echoing(Arc::new(|req: &str| {
        let token = token(req);
        Some(format!(
            "HTTP/1.1 200 OK\r\nX-{token}: 1\r\nContent-Length: 4\r\n\r\nbody"
        ))
    }));
    let out = r.talk(&get("/echo", "")).await;
    assert!(out.starts_with("HTTP/1.1 502 "), "{out}");
    assert!(out.ends_with("upstream-echoed-secret\n"), "{out}");
    assert!(!out.contains("body"), "{out}");
    assert_eq!(
        r.sink.events(),
        [
            "egress.allow",
            "egress.request",
            "egress.deny",
            "egress.close"
        ]
    );
    let deny = r.sink.args("egress.deny");
    assert_eq!(deny["reason"], json!("upstream-echoed-secret"));
    assert_eq!(r.sink.args("egress.close")["end"], json!("refused"));
    assert!(!deny.to_string().contains(&value(0)));
}

/// Architect D5: the upstream's reason phrase never reaches the client.
#[tokio::test]
async fn the_upstream_reason_phrase_is_replaced_by_the_canonical_one() {
    let r = echoing(Arc::new(|req: &str| {
        let token = token(req);
        Some(format!(
            "HTTP/1.1 200 {token}\r\nContent-Length: 2\r\n\r\nok"
        ))
    }));
    let out = r.talk(&get("/echo", "")).await;
    assert!(out.starts_with("HTTP/1.1 200 OK\r\n"), "{out}");
    assert!(!out.contains(&value(0)), "{out}");
}

/// Architect D9/D13: no entry of an injected exchange holds the value or any form of it, and
/// `egress.request` names the grant.
#[tokio::test]
async fn no_audit_entry_of_an_injected_exchange_holds_a_form_of_the_value() {
    let r = echoing(Arc::new(echo_split));
    let _ = r.talk(&get("/echo", "")).await;
    assert_eq!(
        r.sink.args("egress.request")["injected"],
        json!(["secret:T0"])
    );
    let forms = sally_core::audit::secret_forms(&value(0));
    for event in r.sink.events() {
        let args = r.sink.args(&event).to_string();
        for f in &forms {
            assert!(!args.contains(f.expose().as_str()), "{event}: {args}");
        }
    }
}

/// A request whose `egress.request` cannot be written is never sent, so the credential leaves on
/// nothing. This proves the refusal, not architect D13's order (header set after the entry):
/// that order is held by `forward`'s structure and the `Prepared` type (ruling Q4).
#[tokio::test]
async fn a_failed_request_entry_sends_nothing_with_the_credential() {
    let r = rig(Opts {
        fail_on: Some("egress.request"),
        ..Opts::default()
    });
    let out = r.talk(&get("/echo", "")).await;
    assert!(!out.contains("200"), "{out}");
    assert!(r.seen().is_empty());
}

/// Decision 4: `Range` and `If-Range` never reach the upstream.
#[tokio::test]
async fn range_requests_reach_the_upstream_whole() {
    let r = rig(Opts::default());
    let _ = r
        .talk(&get("/echo", "Range: bytes=0-3\r\nIf-Range: \"e\"\r\n"))
        .await;
    let up = r.seen()[0].to_ascii_lowercase();
    assert!(!up.contains("range"), "{up}");
}

/// The upstream answers with `Content-Encoding: <encoding>` and a 4-byte body.
fn encoded(encoding: &'static str) -> Rig {
    rig(Opts {
        handler: Arc::new(move |_| {
            Some(format!(
                "HTTP/1.1 200 OK\r\nContent-Encoding: {encoding}\r\nContent-Length: 4\r\n\r\nbody"
            ))
        }),
        ..Opts::default()
    })
}

/// Decision 1 as relaxed by R1 (architect Q10): an encoded response is refused, nothing
/// forwarded; one `identity` passes, unchanged.
#[tokio::test]
async fn an_encoded_response_is_refused_unforwarded_and_identity_passes() {
    let out = encoded("gzip").talk(&get("/echo", "")).await;
    assert!(out.starts_with("HTTP/1.1 502 "), "{out}");
    assert!(out.ends_with("upstream-encoded\n"), "{out}");
    assert!(!out.contains("body"), "{out}");
    let out = encoded("Identity").talk(&get("/echo", "")).await;
    assert!(out.starts_with("HTTP/1.1 200 "), "{out}");
    assert!(out.contains("content-encoding: Identity\r\n"), "{out}");
    assert!(out.ends_with("\r\n\r\nbody"), "{out}");
}

/// Architect Q13 (b2): the response's entry is written before its end reaches the client; when
/// it cannot be, the end never does and the tunnel ends `error`.
#[tokio::test]
async fn a_response_whose_entry_fails_never_completes() {
    let r = rig(Opts {
        handler: Arc::new(echo_split),
        limits: roomy(),
        fail_on: Some("egress.response"),
        ..Opts::default()
    });
    let out = r.talk(&get("/echo", "")).await;
    let fill = "*".repeat(value(0).len());
    assert!(out.starts_with("HTTP/1.1 200 "), "{out}");
    assert!(!out.ends_with(&format!("{fill}\"}}")), "{out}");
    assert!(!out.contains(&value(0)), "{out}");
    assert_eq!(r.sink.args("egress.close")["end"], json!("error"));
}

/// Architect Q13 (b3): a client that reads the redacted bytes and goes away cannot suppress the
/// entry; it says the body was dropped and counts what was redacted so far.
#[tokio::test]
async fn a_client_that_drops_a_redacted_body_still_gets_it_recorded() {
    let r = echoing(Arc::new(|req: &str| {
        let token = token(req);
        let pad = "z".repeat(80);
        let pauses = PAUSE.repeat(30);
        Some(format!(
            "HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n{token}{pad}{pauses}rest"
        ))
    }));
    let (head, tls, task) = r.open(443).await;
    let mut tls = tls.unwrap_or_else(|| panic!("not opened: {head}"));
    tls.write_all(get("/echo", "").as_bytes()).await.unwrap();
    let want = "*".repeat(value(0).len());
    let mut got = Vec::new();
    bounded("reading the redacted part", async {
        let mut buf = [0u8; 512];
        while !String::from_utf8_lossy(&got).contains(&want) {
            let n = tls.read(&mut buf).await.unwrap();
            assert!(n > 0, "closed early");
            got.extend_from_slice(&buf[..n]);
        }
    })
    .await;
    drop(tls);
    join(task).await;
    bounded("the dropped body's entry", async {
        while !r.sink.events().iter().any(|e| e == "egress.response") {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    let entry = r.sink.args("egress.response");
    assert_eq!(entry["end"], json!("dropped"));
    let n = value(0).len() as u64;
    assert_eq!(
        entry["redacted"],
        json!([{"secret": "secret:T0", "bytes": n}])
    );
}

/// Architect Q13 (b1): a body known empty at its head (here a 304) gets its entry before the
/// head goes out; if it cannot be written, no head goes out.
#[tokio::test]
async fn an_empty_response_is_recorded_before_its_head() {
    let not_modified: Handler =
        Arc::new(|_| Some("HTTP/1.1 304 Not Modified\r\nContent-Length: 10\r\n\r\n".into()));
    let r = echoing(Arc::clone(&not_modified));
    let out = r.talk(&get("/echo", "")).await;
    assert!(out.starts_with("HTTP/1.1 304 "), "{out}");
    let entry = r.sink.args("egress.response");
    assert_eq!(
        (&entry["status"], &entry["end"]),
        (&json!(304), &json!("complete"))
    );
    let failing = rig(Opts {
        handler: not_modified,
        limits: roomy(),
        fail_on: Some("egress.response"),
        ..Opts::default()
    });
    let out = failing.talk(&get("/echo", "")).await;
    assert!(!out.contains("304"), "{out}");
}

/// Architect Q13: one `egress.response` per response the tunnel forwarded, as many as
/// `egress.close` counts in `statuses`.
#[tokio::test]
async fn each_forwarded_response_has_its_entry() {
    let r = echoing(Arc::new(echo_split));
    let two = format!("{}{}", get("/echo", ""), get("/echo", ""));
    let _ = r.talk(&two).await;
    let responses = r
        .sink
        .events()
        .iter()
        .filter(|e| *e == "egress.response")
        .count();
    assert_eq!(responses, 2);
    assert_eq!(r.sink.args("egress.close")["statuses"], json!({"2xx": 2}));
}
