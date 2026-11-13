//! The `fetch` tool's client through a real proxy (#75; architect rulings Q1, Q5–Q7), on the rig
//! in `intercept_rig.rs`: injection and redaction on the grant host, verification against the
//! upstream roots on a spliced host, the TLS choice both ways, refusals read back as reason
//! codes, redirects returned, the body cap, `HEAD`, the timeout, and the origin on every entry.

use std::io;

use serde_json::json;
use tokio::io::DuplexStream;

use super::*;
use crate::egress::local::{ClientTls, Connector, HostGrants, ORIGIN};
use crate::tools::fetch_client::{Fetched, send};
use crate::tools::fetch_url::{self, FetchUrl};

/// Serves each stream on the rig's proxy inside its origin's scope (the accept loop's part, tested
/// in `net.rs`); with `swap`, chooses the wrong client TLS configuration on purpose.
struct RigConnector {
    proxy: Arc<Proxy<Public, Upstream, NoOwn>>,
    tls: ClientTls,
    swap: bool,
}

impl Connector for RigConnector {
    fn open(&self, origin: Value) -> io::Result<DuplexStream> {
        let (ours, theirs) = duplex(1 << 16);
        let p = Arc::clone(&self.proxy);
        tokio::spawn(ORIGIN.scope(origin, async move { p.serve(theirs).await }));
        Ok(ours)
    }

    fn client_tls(&self, host: &str) -> Arc<rustls::ClientConfig> {
        let other = if host == HOST {
            "spliced.mock.test"
        } else {
            HOST
        };
        self.tls.choose(if self.swap { other } else { host })
    }

    fn grants(&self, _: &str) -> HostGrants {
        HostGrants::default()
    }
}

fn connector(r: &Rig, swap: bool) -> RigConnector {
    RigConnector {
        proxy: Arc::clone(&r.proxy),
        tls: ClientTls::of(r.proxy.interception(), None)
            .unwrap()
            .unwrap(),
        swap,
    }
}

fn wide() -> Limits {
    Limits {
        head: Duration::from_secs(5),
        idle: Duration::from_secs(600),
        ..Limits::new(8)
    }
}

fn echo(req: &str) -> Option<String> {
    let path = req.split(' ').nth(1).unwrap_or("/");
    Some(match path {
        "/echo" => format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{req}",
            req.len()
        ),
        "/hang" => String::new(),
        _ => return canned(req),
    })
}

fn url(s: &str) -> FetchUrl {
    fetch_url::parse(s).unwrap()
}

async fn get(c: &RigConnector, u: &str, cap: u64) -> Result<Fetched, &'static str> {
    let origin = json!({"tool": "fetch", "call": 7});
    bounded("fetch", send(c, origin, &url(u), "GET", &[], &[], cap)).await
}

fn origin_on_every_egress_entry(r: &Rig) {
    let rows = r.sink.rows();
    assert!(!rows.is_empty());
    for (event, args) in rows.iter() {
        assert!(event.starts_with("egress."), "{event}");
        assert_eq!(
            args["origin"],
            json!({"tool": "fetch", "call": 7}),
            "{event}"
        );
    }
}

#[tokio::test]
async fn a_grant_host_gets_the_credential_and_a_redacted_response_with_every_entry_tagged() {
    let r = rig(Opts {
        handler: Arc::new(echo),
        limits: wide(),
        ..Opts::default()
    });
    let c = connector(&r, false);
    let got = get(&c, &format!("https://{HOST}/echo"), 1 << 20)
        .await
        .unwrap();
    assert_eq!(got.status, 200);
    let seen = r.seen().join("");
    assert!(
        seen.contains(&format!("authorization: Bearer {}", value(0))),
        "the upstream got the credential: {seen}"
    );
    let body = String::from_utf8(got.body).unwrap();
    assert!(body.starts_with("GET /echo HTTP/1.1"), "{body}");
    assert!(
        !body.contains(&value(0)),
        "the echoed credential is redacted"
    );
    assert!(!got.truncated);
    // The proxy writes its close entry once its side of the connection ends, after the call.
    until("egress.close", || r.sink.events().len() == 4).await;
    assert_eq!(
        r.sink.events(),
        [
            "egress.allow",
            "egress.request",
            "egress.response",
            "egress.close"
        ]
    );
    assert_eq!(r.sink.args("egress.allow")["intercept"], true);
    origin_on_every_egress_entry(&r);
}

#[tokio::test]
async fn a_grant_host_on_another_allowed_port_is_intercepted_too() {
    let r = rig(Opts {
        handler: Arc::new(echo),
        limits: wide(),
        ..Opts::default()
    });
    let got = get(
        &connector(&r, false),
        &format!("https://{HOST}:8443/echo"),
        1 << 20,
    )
    .await
    .unwrap();
    assert_eq!(got.status, 200);
    assert!(
        r.seen()
            .join("")
            .contains(&format!("authorization: Bearer {}", value(0)))
    );
    assert!(!String::from_utf8(got.body).unwrap().contains(&value(0)));
    assert_eq!(r.sink.args("egress.allow")["port"], 8443);
}

#[tokio::test]
async fn a_spliced_host_is_verified_against_the_upstream_roots_and_gets_no_credential() {
    let spliced = "spliced.mock.test";
    let r = rig(Opts {
        handler: Arc::new(echo),
        limits: wide(),
        upstream_name: "spliced.mock.test",
        ..Opts::default()
    });
    let got = get(
        &connector(&r, false),
        &format!("https://{spliced}/echo"),
        1 << 20,
    )
    .await
    .unwrap();
    assert_eq!(got.status, 200);
    let body = String::from_utf8(got.body).unwrap();
    assert!(body.contains(&format!("host: {spliced}")), "{body}");
    assert!(
        !body.to_ascii_lowercase().contains("authorization"),
        "{body}"
    );
    until("egress.close", || r.sink.events().len() == 2).await;
    assert_eq!(r.sink.events(), ["egress.allow", "egress.close"]);
    assert_eq!(r.sink.args("egress.allow")["intercept"], false);
    origin_on_every_egress_entry(&r);
}

#[tokio::test]
async fn the_wrong_tls_choice_fails_the_handshake_both_ways() {
    let r = rig(Opts {
        limits: wide(),
        ..Opts::default()
    });
    let c = connector(&r, true);
    assert_eq!(
        get(&c, &format!("https://{HOST}/"), 100).await.unwrap_err(),
        "tls-failed",
        "the upstream roots do not verify the session CA's leaf"
    );
    let r = rig(Opts {
        limits: wide(),
        upstream_name: "spliced.mock.test",
        ..Opts::default()
    });
    let c = connector(&r, true);
    assert_eq!(
        get(&c, "https://spliced.mock.test/", 100)
            .await
            .unwrap_err(),
        "tls-failed",
        "the session CA does not verify the real upstream"
    );
    assert!(r.seen().is_empty());
}

#[tokio::test]
async fn a_refused_connect_answers_the_proxys_reason_and_dials_nothing() {
    let r = rig(Opts {
        limits: wide(),
        ..Opts::default()
    });
    let c = connector(&r, false);
    assert_eq!(
        get(&c, "https://evil.test/", 100).await.unwrap_err(),
        "host-not-allowed"
    );
    assert_eq!(
        get(&c, &format!("https://{HOST}:9443/"), 100)
            .await
            .unwrap_err(),
        "port-not-allowed"
    );
    assert_eq!(*r.dials.lock().unwrap(), 0);
    assert_eq!(r.sink.events(), ["egress.deny", "egress.deny"]);
    origin_on_every_egress_entry(&r);
}

#[tokio::test]
async fn a_redirect_is_returned_never_followed_and_head_has_no_body() {
    let r = rig(Opts {
        limits: wide(),
        ..Opts::default()
    });
    let c = connector(&r, false);
    let got = get(&c, &format!("https://{HOST}/redirect"), 100)
        .await
        .unwrap();
    assert!((300..400).contains(&got.status), "{}", got.status);
    assert!(got.headers.contains_key("location"));
    assert_eq!(r.seen().len(), 1, "one request, nothing followed");
    let head = bounded(
        "head",
        send(
            &c,
            json!({"tool": "fetch", "call": 7}),
            &url(&format!("https://{HOST}/head-only")),
            "HEAD",
            &[],
            &[],
            100,
        ),
    )
    .await
    .unwrap();
    assert_eq!(head.status, 200);
    assert!(head.body.is_empty() && !head.truncated);
}

#[tokio::test]
async fn the_body_is_cut_at_the_cap_and_kept_whole_up_to_it() {
    let r = rig(Opts {
        limits: wide(),
        ..Opts::default()
    });
    let c = connector(&r, false);
    let cut = get(&c, &format!("https://{HOST}/len/100"), 10)
        .await
        .unwrap();
    assert_eq!((cut.body.len(), cut.truncated), (10, true));
    let whole = get(&c, &format!("https://{HOST}/len/100"), 100)
        .await
        .unwrap();
    assert_eq!((whole.body.len(), whole.truncated), (100, false));
}

/// The real gate and tools (`tools/tests.rs`) with `fetch` going out through the rig's proxy.
fn gated(r: &Rig, approval_timeout: Duration) -> Arc<crate::tools::tests::Fx> {
    let mut o = crate::tools::tests::opts_without_mounts();
    o.fetch = Some(crate::tools::FetchParts {
        connector: Arc::new(connector(r, false)),
        max_request: 1 << 20,
        max_response: 1 << 20,
    });
    o.approval_timeout = approval_timeout;
    Arc::new(crate::tools::tests::fx("fetch-rt", o))
}

/// Calls `fetch` with `args` on a task; the handle answers the call's reply text.
fn call(f: &Arc<crate::tools::tests::Fx>, args: Value) -> tokio::task::JoinHandle<String> {
    let f = Arc::clone(f);
    tokio::spawn(async move { f.text("fetch", args).await })
}

/// RT-AG-14, fetch on the wire (architect ruling Q9): a `POST` with `fetch_writes: approve`
/// stays pending with nothing dialled or sent upstream, is denied on timeout and on a human
/// deny with nothing sent, reaches the upstream exactly once when approved, and its approval
/// cannot be used again; a `GET` runs without a prompt. Fails without the approvals gate in
/// front of `Tools::run` (the POST would reach the upstream before any decision).
#[tokio::test]
async fn rt_ag_14_fetch_a_write_reaches_the_upstream_only_once_approved() {
    use crate::approvals::queue::Decision;
    use crate::tools::tests::ME;
    let r = rig(Opts {
        handler: Arc::new(echo),
        limits: wide(),
        ..Opts::default()
    });
    let f = gated(&r, Duration::from_millis(400));
    let post = json!({"url": format!("https://{HOST}/echo"), "method": "POST",
                      "body_b64": "c2VjcmV0IG5vdGVz"});
    let nothing_sent = |when: &str| {
        assert_eq!(*r.dials.lock().unwrap(), 0, "{when}: dialled");
        assert!(r.seen().is_empty(), "{when}: sent upstream");
        assert!(r.sink.events().is_empty(), "{when}: an egress entry");
    };
    // Timeout.
    let h = call(&f, post.clone());
    f.until_shown(1).await;
    nothing_sent("pending");
    assert_eq!(bounded("timeout", h).await.unwrap(), "denied: timeout");
    nothing_sent("after the timeout");
    // Deny.
    let h = call(&f, post.clone());
    let p = f.until_shown(2).await;
    assert!(
        p.action
            .starts_with(&format!("fetch \"POST\" \"https://{HOST}/echo\""))
    );
    nothing_sent("pending again");
    f.desk.decide(&p.id, Decision::Deny, ME).await.unwrap();
    assert_eq!(bounded("deny", h).await.unwrap(), "denied: denied");
    nothing_sent("after the deny");
    // Approve: exactly one request.
    let h = call(&f, post.clone());
    let p = f.until_shown(3).await;
    nothing_sent("pending a third time");
    f.desk.decide(&p.id, Decision::Approve, ME).await.unwrap();
    let out: Value = serde_json::from_str(&bounded("approve", h).await.unwrap()).unwrap();
    assert_eq!(out["status"], 200);
    assert!(
        out["body"]
            .as_str()
            .unwrap()
            .starts_with("POST /echo HTTP/1.1")
    );
    assert_eq!(r.seen().len(), 1);
    assert!(r.seen()[0].ends_with("secret notes"));
    // The approval is single-use.
    assert!(f.desk.decide(&p.id, Decision::Approve, ME).await.is_err());
    assert_eq!(r.seen().len(), 1, "a reused approval sends nothing");
    // A read runs without a prompt.
    let got = bounded(
        "get",
        f.text("fetch", json!({"url": format!("https://{HOST}/")})),
    )
    .await;
    assert!(got.starts_with("{\"body\":\"ok\""), "{got}");
    assert_eq!(f.prompts().len(), 3);
    assert_eq!(r.seen().len(), 2);
}

/// Architect ruling Q7: `tool.run` before anything goes out, at the lowest audit level too, and
/// `tool.result` before the reply; the proxy's entries carry the call as their origin.
#[tokio::test]
async fn a_fetch_is_audited_before_it_goes_out_and_before_its_reply() {
    let r = rig(Opts {
        handler: Arc::new(echo),
        limits: wide(),
        ..Opts::default()
    });
    let f = gated(&r, Duration::from_secs(30));
    let got = bounded(
        "get",
        f.text("fetch", json!({"url": format!("https://{HOST}/redirect")})),
    )
    .await;
    let v: Value = serde_json::from_str(&got).unwrap();
    assert!((300..400).contains(&v["status"].as_u64().unwrap()));
    assert_eq!(v["headers"][0][0], "location");
    let tool = f.sink.events();
    assert_eq!(tool, ["tool.run", "tool.result"]);
    let run = f.sink.last("tool.run");
    assert_eq!(
        (run["host"].clone(), run["port"].clone()),
        (json!(HOST), json!(443))
    );
    let result = f.sink.last("tool.result");
    assert_eq!(result["outcome"], "ok");
    assert_eq!(result["status"], v["status"]);
    let call = run["call"].clone();
    assert_eq!(r.sink.args("egress.allow")["origin"]["call"], call);
    // Refused at prepare: no entry of the proxy, a deny of the tools.
    let bad = f
        .text("fetch", json!({"url": "http://plain.mock.test/"}))
        .await;
    assert_eq!(bad, "denied: url-not-https");
}

#[tokio::test(start_paused = true)]
async fn a_response_that_never_comes_fails_at_the_timeout() {
    let r = rig(Opts {
        handler: Arc::new(echo),
        limits: wide(),
        ..Opts::default()
    });
    let c = connector(&r, false);
    let origin = json!({"tool": "fetch", "call": 7});
    let got = send(
        &c,
        origin,
        &url(&format!("https://{HOST}/hang")),
        "GET",
        &[],
        &[],
        10,
    )
    .await;
    assert_eq!(got.unwrap_err(), "timeout");
}
