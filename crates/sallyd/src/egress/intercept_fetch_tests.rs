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
