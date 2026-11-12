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

/// Echoes the request's credential in a header and in a body split into three writes, one
/// boundary inside the value (decision 3). Content-Length framed.
fn echo_split(req: &str) -> Option<String> {
    let line = auth_line(req);
    let token = line.split_once("Bearer ").map_or("", |(_, t)| t).to_owned();
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
    // The client sees no form of it, the label instead, and the length the upstream sent.
    assert!(!out.contains(&secret), "{out}");
    let label = "[REDACTED:T0]";
    let fill = |n: usize| format!("{label}{}", "*".repeat(n - label.len()));
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
}

/// The same over a chunked response whose chunks split the value.
#[tokio::test]
async fn a_chunked_echo_split_inside_the_value_is_redacted() {
    let r = echoing(Arc::new(|req: &str| {
        let token = auth_line(req)
            .split_once("Bearer ")
            .map_or(String::new(), |(_, t)| t.to_owned());
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
    assert_eq!(body.len(), secret.len() + 2);
    assert!(
        body.starts_with("x[REDACTED:T0]*") && body.ends_with("*y"),
        "{body}"
    );
}

/// Architect D5: a form reaching into a header name is refused before anything is forwarded.
#[tokio::test]
async fn a_credential_in_a_response_header_name_is_refused_unforwarded() {
    let r = echoing(Arc::new(|req: &str| {
        let token = auth_line(req)
            .split_once("Bearer ")
            .map_or(String::new(), |(_, t)| t.to_owned());
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
        let token = auth_line(req)
            .split_once("Bearer ")
            .map_or(String::new(), |(_, t)| t.to_owned());
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

/// Architect D13: a request whose `egress.request` cannot be written is never sent, so the
/// credential is never set on anything that leaves.
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

/// Decision 1 (architect D6): even `Content-Encoding: identity` is refused, nothing forwarded.
#[tokio::test]
async fn any_content_encoding_is_refused_unforwarded() {
    let r = rig(Opts {
        handler: Arc::new(|_| {
            Some(
                "HTTP/1.1 200 OK\r\nContent-Encoding: identity\r\nContent-Length: 4\r\n\r\nbody"
                    .into(),
            )
        }),
        ..Opts::default()
    });
    let out = r.talk(&get("/echo", "")).await;
    assert!(out.starts_with("HTTP/1.1 502 "), "{out}");
    assert!(out.ends_with("upstream-encoded\n"), "{out}");
    assert!(!out.contains("body"), "{out}");
}
