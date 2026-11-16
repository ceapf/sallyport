//! The text the sandbox chose in intercepted tunnels' audit entries (architect Q253), on the rig
//! in `intercept_rig.rs`: a form of the grant (`T0`, [`value`]`(0)`) in a request-target or as
//! the method is masked in the whole text before the 256-byte cut and the escape, in every entry
//! that carries it. The rig's sink has no redactor of its own, so what it records is what the
//! arguments hold.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::egress::authority::LOGGED_TARGET_BYTES;

/// A target of more than 300 bytes holding the grant's value across the 256-byte cut.
fn straddling() -> String {
    let at = LOGGED_TARGET_BYTES - value(0).len() / 2;
    format!("/{}{}/{}", "p".repeat(at - 1), value(0), "q".repeat(60))
}

/// [`straddling`] as the entries must carry it: masked, then cut.
fn masked() -> String {
    let t = straddling().replace(&value(0), "[REDACTED:T0]");
    t[..LOGGED_TARGET_BYTES].to_owned()
}

/// Whether any 8-character run of the grant's value occurs in `text`.
fn holds_a_run(text: &str) -> bool {
    let v = value(0);
    v.as_bytes()
        .windows(8)
        .any(|w| text.contains(std::str::from_utf8(w).unwrap()))
}

/// `event`'s target is [`masked`], its length the raw one, and it was cut.
fn assert_masked(r: &Rig, event: &str) {
    let args = r.sink.args(event);
    let raw = straddling();
    assert!(raw.len() > 300);
    assert_eq!(args["target"], json!(masked()), "{event}: {args}");
    assert_eq!(args["target_bytes"], json!(raw.len()), "{event}");
    assert_eq!(args["target_cut"], json!(true), "{event}");
    assert!(!holds_a_run(&args.to_string()), "{event}: {args}");
}

fn ok_rig() -> Rig {
    rig(Opts {
        handler: Arc::new(|_| Some("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".into())),
        limits: Limits {
            max_request: 4096,
            max_response: 4096,
            ..Opts::default().limits
        },
        ..Opts::default()
    })
}

#[tokio::test]
async fn a_form_across_the_cut_is_masked_in_the_request_and_response_entries() {
    let r = ok_rig();
    let out = r.talk(&get(&straddling(), "")).await;
    assert!(out.starts_with("HTTP/1.1 200 "), "{out}");
    assert_masked(&r, "egress.request");
    assert_masked(&r, "egress.response");
    assert_eq!(r.sink.args("egress.response")["end"], json!("complete"));
}

#[tokio::test]
async fn a_form_across_the_cut_is_masked_in_a_deny_inside_the_tunnel() {
    let r = ok_rig();
    let raw = get(
        &straddling(),
        "Connection: Upgrade\r\nUpgrade: websocket\r\n",
    );
    let out = r.talk(&raw).await;
    assert!(out.starts_with("HTTP/1.1 403 "), "{out}");
    assert_eq!(
        r.sink.args("egress.deny")["reason"],
        json!("upgrade-refused")
    );
    assert_masked(&r, "egress.deny");
}

#[tokio::test]
async fn a_form_across_the_cut_is_masked_in_a_limit_inside_the_tunnel() {
    let r = rig(Opts::default());
    let raw = format!(
        "POST {} HTTP/1.1\r\nHost: {HOST}\r\nContent-Length: 17\r\n\r\n{}",
        straddling(),
        "q".repeat(17)
    );
    let out = r.talk(&raw).await;
    assert!(out.starts_with("HTTP/1.1 413 "), "{out}");
    assert_eq!(
        r.sink.args("egress.limit")["reason"],
        json!("request-too-large")
    );
    assert_masked(&r, "egress.limit");
}

/// A path check (architect Q257): the entry of a body the client dropped, written from a
/// detached task, carries the same masked target. Its control is `with_target`'s call in
/// `intercept_report.rs`, the one builder it shares with the complete case.
#[tokio::test]
async fn a_form_across_the_cut_is_masked_in_a_dropped_responses_entry() {
    let r = rig(Opts {
        // The redacting stream holds back one byte less than the longest form: the padding
        // lets `first` out before the pauses.
        handler: Arc::new(|_| {
            let (pad, pauses) = ("z".repeat(80), PAUSE.repeat(30));
            Some(format!(
                "HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\nfirst{pad}{pauses}rest"
            ))
        }),
        limits: Limits {
            max_request: 4096,
            max_response: 4096,
            ..Opts::default().limits
        },
        ..Opts::default()
    });
    let (head, tls, task) = r.open(443).await;
    let mut tls = tls.unwrap_or_else(|| panic!("not opened: {head}"));
    tls.write_all(get(&straddling(), "").as_bytes())
        .await
        .unwrap();
    let mut got = Vec::new();
    bounded("reading the first part", async {
        let mut buf = [0u8; 512];
        while !String::from_utf8_lossy(&got).contains("first") {
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
    assert_eq!(r.sink.args("egress.response")["end"], json!("dropped"));
    assert_masked(&r, "egress.response");
}

/// An extension method is the sandbox's text too: one across the cut is masked before it is
/// cut (architect Q256). Token characters only, as a method must be.
#[tokio::test]
async fn a_form_across_the_cut_of_an_extension_method_is_masked() {
    let r = ok_rig();
    let pad = "M".repeat(LOGGED_TARGET_BYTES - value(0).len() / 2);
    let method = format!("{pad}{}{}", value(0), "N".repeat(60));
    assert!(method.len() > 300);
    let raw = format!("{method} /m HTTP/1.1\r\nHost: {HOST}\r\n\r\n");
    let out = r.talk(&raw).await;
    assert!(out.starts_with("HTTP/1.1 200 "), "{out}");
    let args = r.sink.args("egress.request");
    let masked = method.replace(&value(0), "[REDACTED:T0]");
    assert_eq!(
        args["method"],
        json!(masked[..LOGGED_TARGET_BYTES]),
        "{args}"
    );
    assert!(!holds_a_run(&args.to_string()), "{args}");
}

/// A method shorter than the cut is masked whole.
#[tokio::test]
async fn a_form_as_the_method_is_masked() {
    let r = ok_rig();
    let raw = format!("{} /m HTTP/1.1\r\nHost: {HOST}\r\n\r\n", value(0));
    let out = r.talk(&raw).await;
    assert!(out.starts_with("HTTP/1.1 200 "), "{out}");
    let args = r.sink.args("egress.request");
    assert_eq!(args["method"], json!("[REDACTED:T0]"), "{args}");
    assert_eq!(args["target"], json!("/m"));
    assert!(!holds_a_run(&args.to_string()), "{args}");
}
