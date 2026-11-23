//! Red-team rows RT-SEC-09 and RT-SEC-13 (Task 9a-2; RT-SEC-10 is in `session_ca.rs`),
//! RT-SEC-03, 04, 05, 06, 06b, 07 and 11 (Task 9a-3: injection and response redaction), and
//! RT-SEC-12 with RT-SEC-07 over every form (Task 9b: `{basic}` grants and encoded echoes).
//!
//! Each test launches a real workspace session with secret grants on `mock.test` and
//! `mock3.test` (launcher, session CA, CA files, and the credentials from the production
//! secrets store file over a temporary 0600 store: architect D12; the canaries are built at
//! runtime by `common::egress::canary`). TLS legs run host-side over the session's `net.sock`, the socket the
//! shim relays to (architect Q47: the test image has no TLS client); the route decision and leaf
//! selection under test sit in `sallyd`, identical from either end of the socket. The upstream is
//! the in-process TLS mock of `common/egress.rs`, verified against a test CA. The rig the rows
//! share (TLS over `net.sock`, response parsing, the canaries) is `common/intercept.rs`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::container::{Lx, SHIM_LOG, exec, net_image, rt};
use common::egress::tls_upstream;
use common::forms::{
    ALPHABETS, PCTS, b64, basic_blob, basic_forms, core_range, forms_of, json_str, pct,
};
use common::intercept::{
    allow_routes, body_and_length, check_echo_forms, connect, credential_in, filled, get_req, gh,
    git, header_values, mock3, over, rendered, responses, session_ca, test_ca, tls, upstream_reply,
};
use sallyd::sandbox::{Running, WorkspaceRequest};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// `mock.test` and `mock3.test` (grant hosts, a secret each) and `mock2.test` (allowed, no
/// grant) on 443.
const MANIFEST: &str = "network:\n  mode: proxy\n  allow:\n    - host: mock.test\n    \
                        - host: mock2.test\n    - host: mock3.test\n\
                        secrets:\n  - name: GITHUB_TOKEN\n    inject: {host: mock.test, \
                        header: Authorization, format: \"Bearer {value}\"}\n  \
                        - name: MOCK3_TOKEN\n    inject: {host: mock3.test, \
                        header: X-Api-Key, format: \"{value}\"}\n";

/// [`MANIFEST`] plus `GIT_TOKEN` granted three times as `Authorization: Basic {basic}`, on
/// `b1`, `b2` and `b3.mock.test` with the users of [`BASIC_HOSTS`] (RT-SEC-12, RT-SEC-07).
const FORMS_MANIFEST: &str = "network:\n  mode: proxy\n  allow:\n    - host: mock.test\n    \
                              - host: mock2.test\n    - host: mock3.test\n    \
                              - host: b1.mock.test\n    - host: b2.mock.test\n    \
                              - host: b3.mock.test\n\
                              secrets:\n  - name: GITHUB_TOKEN\n    inject: {host: mock.test, \
                              header: Authorization, format: \"Bearer {value}\"}\n  \
                              - name: MOCK3_TOKEN\n    inject: {host: mock3.test, \
                              header: X-Api-Key, format: \"{value}\"}\n  \
                              - name: GIT_TOKEN\n    inject: {host: b1.mock.test, \
                              header: Authorization, format: \"Basic {basic}\", basic_user: x}\n  \
                              - name: GIT_TOKEN\n    inject: {host: b2.mock.test, \
                              header: Authorization, format: \"Basic {basic}\", basic_user: ab}\n  \
                              - name: GIT_TOKEN\n    inject: {host: b3.mock.test, \
                              header: Authorization, format: \"Basic {basic}\", basic_user: git}\n";

/// The `{basic}` grant hosts of [`FORMS_MANIFEST`] and their users: one, two and three bytes,
/// so the secret sits at all three base64 alignments inside the blob (RT-SEC-12).
const BASIC_HOSTS: [(&str, &str); 3] = [
    ("b1.mock.test", "x"),
    ("b2.mock.test", "ab"),
    ("b3.mock.test", "git"),
];

/// Every host the test manifests allow; each resolves to the TLS mock.
const HOSTS: [&str; 6] = [
    "mock.test",
    "mock2.test",
    "mock3.test",
    "b1.mock.test",
    "b2.mock.test",
    "b3.mock.test",
];

async fn session(lx: &Lx, tag: &str) -> Running {
    session_of(lx, tag, MANIFEST).await
}

async fn session_of(lx: &Lx, tag: &str, manifest: &str) -> Running {
    let req = WorkspaceRequest {
        paths: lx.paths(tag),
        manifest: Arc::new(lx.f.load(manifest)),
        default_image: Some(net_image()),
        crash: sallyd::daemon::crash::CrashReporter::channel().0,
    };
    let r = lx.launcher.launch_workspace(req).await.expect("launch");
    for _ in 0..100 {
        let (_, log) = exec(&r, &format!("cat {SHIM_LOG} 2>/dev/null")).await;
        if log.contains("sally-shim: listening on 127.0.0.1:3128") {
            for host in HOSTS {
                lx.egress.resolver.set(host, vec![vec![tls_upstream()]]);
            }
            return r;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the shim never became ready");
}

/// RT-SEC-09. Controls: the route decision (`policy::decide` → `Route::Intercept` only for grant
/// hosts) and the leaf selection (`Interception::server`, by the CONNECT host). Splicing a grant
/// host fails the session-CA handshake; intercepting the other host fails the byte-equal leaf
/// assertion; presenting one grant host's leaf for the other (say, the first leaf for every
/// host) fails that host's own-name handshake.
#[test]
fn rt_sec_09_a_grant_host_gets_a_session_ca_leaf_and_any_other_host_its_own_chain() {
    rt().block_on(async {
        let lx = Lx::new();
        let r = session(&lx, "sec09").await;
        let sock = lx.paths("sec09").workspace_sockets().join("net.sock");
        let ca = session_ca(&lx, "sec09");

        for (grant, other_grant) in [("mock.test", "mock3.test"), ("mock3.test", "mock.test")] {
            let t = tls(connect(&sock, grant).await, grant, &ca)
                .await
                .unwrap_or_else(|e| panic!("{grant}: its leaf must verify: {e}"));
            let chain = t.get_ref().1.peer_certificates().unwrap().to_vec();
            assert_ne!(
                chain[0], lx.egress.dialer.pki.leaf,
                "{grant}: the upstream's own leaf"
            );
            for name in [other_grant, "other.mock.test"] {
                let wrong = tls(connect(&sock, grant).await, name, &ca).await;
                assert!(
                    wrong.is_err(),
                    "{grant}: its session-CA leaf verified for {name}"
                );
            }
        }

        let t = tls(
            connect(&sock, "mock2.test").await,
            "mock2.test",
            &test_ca(&lx),
        )
        .await
        .expect("non-grant host: the upstream's own chain");
        let chain = t.get_ref().1.peer_certificates().unwrap().to_vec();
        assert_eq!(
            chain[0], lx.egress.dialer.pki.leaf,
            "not the upstream's leaf"
        );
        assert!(
            chain.iter().all(|c| *c != ca),
            "the session CA is in the chain"
        );
        let by_session = tls(connect(&sock, "mock2.test").await, "mock2.test", &ca).await;
        assert!(
            by_session.is_err(),
            "a non-grant leaf verified against the session CA"
        );

        let routes = allow_routes(&lx);
        for (host, intercept) in [
            ("mock.test", true),
            ("mock3.test", true),
            ("mock2.test", false),
        ] {
            assert!(routes.contains(&(host.to_owned(), intercept)), "{routes:?}");
        }
        assert!(
            routes
                .iter()
                .all(|(h, i)| *i == (h == "mock.test" || h == "mock3.test")),
            "{routes:?}"
        );
        lx.stop(r).await;
    });
}

/// RT-SEC-13, rewritten with `inject-requires-tls` deleted (#59): plaintext never reaches a grant
/// host, either way a client tries it.
/// - Proxy-form `GET http://…`. Control: the 405 before policy in `Proxy::clear`. Without it the
///   request would reach policy, a lookup and a dial.
/// - `CONNECT` to the grant host, then plaintext where the TLS handshake belongs. Control: the
///   client handshake in `intercept::exchanges`, before hyper serves anything. Without it the
///   plaintext request would be parsed and forwarded (`egress.request`, the upstream sees it).
///
/// No credential can be attached on either path: nothing is forwarded at all.
///
/// In-test control (asserted first): one TLS `GET` to the same grant host on the same session
/// is looked up, dialled, seen by the upstream and audited as `egress.request`, once each. Every
/// later count is an exact equality with the control's, so an unwired resolver, dialer, mock log
/// or audit sink fails the test instead of passing it.
#[test]
fn rt_sec_13_plain_http_to_a_grant_host_is_never_forwarded() {
    rt().block_on(async {
        let lx = Lx::new();
        let r = session(&lx, "sec13").await;
        let count = |name: &str| lx.events.list().iter().filter(|e| *e == name).count();
        let closes = |lx: &Lx| {
            lx.events
                .all()
                .into_iter()
                .filter(|(e, _)| e == "egress.close")
                .map(|(_, a)| a)
                .collect::<Vec<_>>()
        };
        async fn close_number(lx: &Lx, n: usize, closes: impl Fn(&Lx) -> Vec<serde_json::Value>) {
            for _ in 0..100 {
                if closes(lx).len() >= n {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }

        let back = over(
            &lx,
            "sec13",
            "mock.test",
            &get_req("mock.test", "/echo-headers", ""),
        )
        .await;
        assert!(back.starts_with("HTTP/1.1 200 "), "control: {back}");
        let lookups = vec!["mock.test".to_owned()];
        assert_eq!(lx.egress.resolver.lookups(), lookups, "control: lookups");
        assert_eq!(lx.egress.dialer.dials().len(), 1, "control: dials");
        assert_eq!(lx.egress.dialer.seen().len(), 1, "control: upstream log");
        assert_eq!(count("egress.request"), 1, "control: egress.request");
        close_number(&lx, 1, closes).await;
        assert_eq!(closes(&lx).len(), 1, "control: egress.close");

        let req = "GET http://mock.test/echo-headers HTTP/1.1\\r\\nHost: mock.test\\r\\n\\r\\n";
        let (_, out) = exec(&r, &format!("printf '{req}' | nc -w 3 127.0.0.1 3128")).await;
        assert!(out.starts_with("HTTP/1.1 405 "), "{out}");
        assert!(out.contains("plain-http-unsupported"), "{out}");
        assert_eq!(lx.egress.resolver.lookups(), lookups, "looked up");
        assert_eq!(lx.egress.dialer.dials().len(), 1, "dialled");
        assert_eq!(
            lx.egress.dialer.seen().len(),
            1,
            "the upstream saw a request"
        );
        let deny: Vec<_> = lx
            .events
            .all()
            .into_iter()
            .filter(|(e, _)| e == "egress.deny")
            .map(|(_, a)| a)
            .collect();
        assert_eq!(deny.len(), 1, "{deny:?}");
        assert_eq!(deny[0]["reason"], json!("plain-http-unsupported"));
        assert_eq!(deny[0]["target"], json!("http://mock.test/echo-headers"));

        let sock = lx.paths("sec13").workspace_sockets().join("net.sock");
        let mut s = connect(&sock, "mock.test").await;
        s.write_all(b"GET /echo-headers HTTP/1.1\r\nHost: mock.test\r\n\r\n")
            .await
            .unwrap();
        let mut back = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(15), s.read_to_end(&mut back)).await;
        assert!(matches!(read, Ok(Ok(_))), "the tunnel stayed open");
        assert!(
            !String::from_utf8_lossy(&back).contains("HTTP/"),
            "an HTTP answer to plaintext: {back:?}"
        );
        assert_eq!(
            lx.egress.dialer.seen().len(),
            1,
            "the upstream saw a request"
        );
        // The failed handshake drops the client before the close entry is written. The control's
        // close is the first; the proxy-form deny writes none (no tunnel), so the tunnel's is the
        // second.
        close_number(&lx, 2, closes).await;
        let all = closes(&lx);
        assert_eq!(all.len(), 2, "egress.close: {all:?}");
        let close = all.last().expect("egress.close").clone();
        assert_eq!(count("egress.request"), 1, "{:?}", lx.events.list());
        assert_eq!(close["end"], json!("client-tls-failed"), "{close}");
        assert_eq!(close["requests"], json!(0), "{close}");
        lx.stop(r).await;
    });
}

/// Every independently computed form of every canary of [`FORMS_MANIFEST`]: the forms of each
/// value, each rendered `Bearer` value, and each `{basic}` grant's rendered value and blobs.
fn every_form() -> Vec<String> {
    let mut all: Vec<String> = [gh(), mock3(), git()]
        .iter()
        .flat_map(|c| forms_of(c))
        .collect();
    all.push(rendered());
    for (_, user) in BASIC_HOSTS {
        all.extend(basic_forms(user, &git()));
    }
    all
}

/// The encoders RT-SEC-12 and RT-SEC-07 compute their forms with, against published vectors:
/// RFC 4648 §10 (base64), RFC 7617 §2 (Basic), and the URL-safe alphabet's two characters; the
/// percent encoder against hand-built vectors for each flag; the JSON-string encoder against
/// `serde_json` (a third-party encoder, not the code under test) for every ASCII character and
/// two others.
#[test]
fn the_test_encoders_match_published_vectors() {
    assert_eq!(b64(b"foobar", ALPHABETS[0]), "Zm9vYmFy");
    assert_eq!(b64(b"fooba", ALPHABETS[0]), "Zm9vYmE=");
    assert_eq!(b64(b"foob", ALPHABETS[0]), "Zm9vYg==");
    assert_eq!(
        basic_blob("Aladdin", "open sesame"),
        "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
    );
    assert_eq!(b64(&[0xfb, 0xff], ALPHABETS[0]), "+/8=");
    assert_eq!(b64(&[0xfb, 0xff], ALPHABETS[1]), "-_8=");
    assert_eq!(pct("a/b c", PCTS[0]), "a%2Fb%20c");
    assert_eq!(pct("a/b c", PCTS[1]), "a%2fb%20c");
    assert_eq!(pct("a/b c", PCTS[2]), "a%2Fb+c");
    assert_eq!(pct("a/b c", PCTS[3]), "a/b%20c");
    assert_eq!(pct("a/b c?", PCTS[7]), "a/b+c%3f");
    assert_eq!(pct("a/b c!", PCTS[11]), "a%2fb+c!");
    assert_eq!(pct("(x)'*", PCTS[8]), "(x)'*");
    assert_eq!(json_str("a\"b\\c\n\u{1}"), "a\\\"b\\\\c\\n\\u0001");
    assert_eq!(
        json_str("\u{8}\u{c}\r\t\u{1f}/\u{7f}é"),
        "\\b\\f\\r\\t\\u001f/\u{7f}é"
    );
    for c in (0u8..=0x7f).map(char::from).chain(['é', '\u{2028}']) {
        let one = c.to_string();
        let quoted = serde_json::to_string(&one).unwrap();
        assert_eq!(json_str(&one), quoted[1..quoted.len() - 1], "{c:?}");
    }
    // The secret's core of base64("A" ‖ "foo" ‖ …): bits 8..32 give characters 2..5.
    assert_eq!(core_range(1, 3), 2..5);
    // Each percent spelling of GIT_TOKEN's canary, and its JSON-string spelling, differs from
    // the raw value and from the others.
    let mut spellings: Vec<String> = PCTS.iter().map(|p| pct(&git(), *p)).collect();
    spellings.push(json_str(&git()));
    spellings.push(git());
    spellings.sort();
    spellings.dedup();
    assert_eq!(spellings.len(), PCTS.len() + 2);
}

/// RT-SEC-03: injection scope. Controls: `Credentials::prepare`, called with the tunnel's own host
/// (`intercept::forward`); the route decision (`Route::Splice` for `mock2.test`); the redaction
/// of the response (`redact::Redacted`). Setting every grant on every host fails the mock2/mock3
/// assertions; skipping the redaction fails the filler assertion; intercepting `mock2.test`
/// gives it an `egress.response`.
#[test]
fn rt_sec_03_a_credential_reaches_only_its_own_grant_host() {
    rt().block_on(async {
        let lx = Lx::new();
        let r = session(&lx, "sec03").await;
        let out = over(
            &lx,
            "sec03",
            "mock.test",
            &get_req("mock.test", "/echo-headers", ""),
        )
        .await;
        let _ = over(
            &lx,
            "sec03",
            "mock2.test",
            &get_req("mock2.test", "/echo-headers", ""),
        )
        .await;
        let _ = over(
            &lx,
            "sec03",
            "mock3.test",
            &get_req("mock3.test", "/echo-headers", ""),
        )
        .await;
        let seen = lx.egress.dialer.seen();
        assert_eq!(seen.len(), 3, "{seen:?}");
        // Positive control: the grant host's upstream got the real credential, once.
        assert_eq!(
            header_values(&seen[0], "authorization"),
            [format!("Bearer {}", gh())]
        );
        assert!(!seen[0].contains(&mock3()), "{}", seen[0]);
        // The allowed host without a grant got none.
        assert!(
            header_values(&seen[1], "authorization").is_empty(),
            "{}",
            seen[1]
        );
        assert!(!seen[1].contains(&gh()) && !seen[1].contains(&mock3()));
        // The other grant host got its own credential only.
        assert_eq!(header_values(&seen[2], "x-api-key"), [mock3()]);
        assert!(!seen[2].contains(&gh()), "{}", seen[2]);
        // The sandbox's view of the echo: redacted, same length as the upstream sent.
        assert!(out.starts_with("HTTP/1.1 200 OK"), "{out}");
        assert!(!out.contains(&gh()), "{out}");
        let (body, n) = body_and_length(&out);
        assert_eq!(body, filled(&seen[0]));
        assert_eq!(n, seen[0].len());
        lx.stop(r).await;
        // Each intercepted response has its entry; the spliced one has none (architect Q13).
        assert_eq!(responses(&lx, "mock.test").len(), 1);
        assert_eq!(responses(&lx, "mock3.test").len(), 1);
        assert!(responses(&lx, "mock2.test").is_empty());
    });
}

/// RT-SEC-04: a client-supplied copy of the grant header. Controls, a pair: the grant-header drop
/// in `rewrite::request` (architect Q40) and `Prepared::apply`'s `insert` (one value). Each
/// alone keeps the client's copy away, so this test fails only when both are removed (the drop
/// gone and `insert` turned into `append`: two `Authorization` lines reach the upstream); each
/// control has its own unit test (architect Q2): `rewrite_tests::
/// every_client_copy_of_a_grant_header_is_dropped_in_any_case` and `inject_tests::
/// a_grant_host_gets_its_rendered_header_replacing_any_client_copy`.
#[test]
fn rt_sec_04_a_client_copy_of_the_grant_header_never_reaches_the_grant_host() {
    rt().block_on(async {
        let lx = Lx::new();
        let r = session(&lx, "sec04").await;
        let attack = "Authorization: Bearer attacker\r\nauthorization: Bearer second\r\n\
                      X-Api-Key: attacker\r\nX-Kept: 1\r\n";
        let _ = over(
            &lx,
            "sec04",
            "mock.test",
            &get_req("mock.test", "/echo-headers", attack),
        )
        .await;
        let _ = over(
            &lx,
            "sec04",
            "mock3.test",
            &get_req("mock3.test", "/echo-headers", attack),
        )
        .await;
        let spliced = "Authorization: Bearer attacker\r\nAccept-Encoding: gzip\r\n";
        let out = over(
            &lx,
            "sec04",
            "mock2.test",
            &get_req("mock2.test", "/echo-headers", spliced),
        )
        .await;
        let seen = lx.egress.dialer.seen();
        assert_eq!(seen.len(), 3, "{seen:?}");
        assert_eq!(
            header_values(&seen[0], "authorization"),
            [format!("Bearer {}", gh())]
        );
        assert_eq!(header_values(&seen[0], "x-kept"), ["1"]);
        assert_eq!(header_values(&seen[1], "x-api-key"), [mock3()]);
        // mock3's grant is X-Api-Key: the client's Authorization is not its header, so it passes.
        assert_eq!(header_values(&seen[1], "authorization").len(), 2);
        // The spliced host receives the client's headers unchanged.
        assert!(out.starts_with("HTTP/1.1 200 OK"), "{out}");
        assert!(
            seen[2].contains("Authorization: Bearer attacker\r\n"),
            "{}",
            seen[2]
        );
        assert!(seen[2].contains("Accept-Encoding: gzip\r\n"), "{}", seen[2]);
        lx.stop(r).await;
    });
}

/// RT-SEC-05: a redirect is returned, never followed, and the client's own follow-up to the
/// non-grant host carries no credential. Control: the proxy never dials a `Location` (one
/// upstream connection per tunnel, Q28). The follow-up's tunnel is spliced, so no injection
/// code runs on it at all.
#[test]
fn rt_sec_05_a_redirect_is_returned_unfollowed_and_its_target_gets_no_credential() {
    rt().block_on(async {
        let lx = Lx::new();
        let r = session(&lx, "sec05").await;
        let out = over(
            &lx,
            "sec05",
            "mock.test",
            &get_req("mock.test", "/redirect", ""),
        )
        .await;
        assert!(out.starts_with("HTTP/1.1 302 Found"), "{out}");
        assert_eq!(
            header_values(&out, "location"),
            ["https://mock2.test/echo-headers"]
        );
        assert_eq!(lx.egress.dialer.dials().len(), 1, "a redirect was followed");
        // Positive control: the redirecting request itself carried the credential.
        let seen = lx.egress.dialer.seen();
        assert_eq!(seen.len(), 1, "{seen:?}");
        assert!(seen[0].contains(&gh()), "{}", seen[0]);
        let _ = over(
            &lx,
            "sec05",
            "mock2.test",
            &get_req("mock2.test", "/echo-headers", ""),
        )
        .await;
        let seen = lx.egress.dialer.seen();
        assert_eq!(seen.len(), 2, "{seen:?}");
        assert!(!seen[1].contains(&gh()), "{}", seen[1]);
        assert!(header_values(&seen[1], "authorization").is_empty());
        lx.stop(r).await;
    });
}

/// RT-SEC-06: the upstream echoes the credential in its body and in a response header; both
/// reach the sandbox as a run of the session's filler at the echo's offset and length, and the
/// response's `egress.response` names the secret and those bytes. Controls: `redact::headers`
/// (the header), `redact::Redacted` (the body), with the forms built by `Credentials::new`; the
/// per-secret count in `redact::Stream` and the append in `intercept_report` (the entry).
#[test]
fn rt_sec_06_an_echo_in_body_and_header_is_redacted_at_the_same_length() {
    rt().block_on(async {
        let lx = Lx::new();
        let r = session(&lx, "sec06").await;
        let out = over(
            &lx,
            "sec06",
            "mock.test",
            &get_req("mock.test", "/echo-headers", ""),
        )
        .await;
        let seen = lx.egress.dialer.seen();
        // Positive control: the mock received the credential, so its echo held it.
        assert!(seen[0].contains(&gh()), "{}", seen[0]);
        assert!(!out.contains(&gh()), "{out}");
        let echoed = header_values(&out, "x-echo-authorization");
        assert_eq!(echoed, [filled(&rendered())], "{out}");
        let (body, n) = body_and_length(&out);
        assert_eq!(body, filled(&seen[0]));
        assert_eq!(n, seen[0].len());
        lx.stop(r).await;
        let entries = responses(&lx, "mock.test");
        assert_eq!(entries.len(), 1, "{entries:?}");
        let bytes = 2 * rendered().len() as u64;
        assert_eq!(
            entries[0]["redacted"],
            json!([{"secret": "secret:GITHUB_TOKEN", "bytes": bytes}])
        );
        assert_eq!(entries[0]["redacted_bytes"], json!(bytes));
        assert_eq!(entries[0]["end"], json!("complete"));
    });
}

/// RT-SEC-06, a name: the upstream puts the credential it received into a response header's
/// name, where no filler of the same length can stand. The response is refused with 502
/// `upstream-echoed-secret` and nothing of it is forwarded; one `egress.deny` names the
/// reason, without the value. Controls: both header-name checks of `redact::headers` (the
/// any-case search of the name and separator, and the first covered byte's place in
/// `redacted_value`; each stands alone, so only both removed let the name through). In-test
/// control: the mock, asked around the proxy with the same credential, does send that header
/// and the body the 502 must not carry.
#[test]
fn rt_sec_06_a_credential_in_a_response_header_name_is_refused_unforwarded() {
    rt().block_on(async {
        let lx = Lx::new();
        let r = session(&lx, "sec06n").await;
        let out = over(
            &lx,
            "sec06n",
            "mock.test",
            &get_req("mock.test", "/echo-name", ""),
        )
        .await;
        let seen = lx.egress.dialer.seen();
        assert_eq!(seen.len(), 1, "{seen:?}");
        assert!(seen[0].contains(&gh()), "{}", seen[0]);
        assert!(out.starts_with("HTTP/1.1 502 "), "{out}");
        assert!(out.contains("upstream-echoed-secret"), "{out}");
        assert!(!out.contains("NAMED"), "{out}");
        assert!(!out.contains(&gh()), "{out}");
        // The control of the lines above: asked around the proxy, the mock sends both.
        let auth = format!("Authorization: {}\r\n", rendered());
        let direct =
            upstream_reply(&lx, "mock.test", &get_req("mock.test", "/echo-name", &auth)).await;
        assert!(direct.starts_with("HTTP/1.1 200 OK"), "{direct}");
        assert_eq!(header_values(&direct, &format!("x-{}", gh())), ["1"]);
        assert!(direct.ends_with("NAMED"), "{direct}");
        lx.stop(r).await;
        let denies: Vec<_> = lx
            .events
            .all()
            .into_iter()
            .filter(|(e, _)| e == "egress.deny")
            .map(|(_, a)| a)
            .collect();
        assert_eq!(denies.len(), 1, "{denies:?}");
        assert_eq!(denies[0]["reason"], json!("upstream-echoed-secret"));
        assert_eq!(denies[0]["host"], json!("mock.test"));
        assert!(!denies[0].to_string().contains(&gh()), "{}", denies[0]);
    });
}

/// RT-SEC-06b: compressed echoes. `Accept-Encoding` never reaches the grant host, so its echo
/// comes back uncompressed and redacted; a response encoded anyway is refused with 502
/// `upstream-encoded` and never forwarded (decision 1). Controls: `Accept-Encoding` in
/// `rewrite::REQUEST_DROPPED`; the `Content-Encoding` check in `rewrite::response`. In-test
/// control: the mock, asked directly, does send the encoded marker the 502 must not carry.
#[test]
fn rt_sec_06b_compression_is_stripped_and_an_encoded_echo_is_refused() {
    rt().block_on(async {
        let lx = Lx::new();
        let r = session(&lx, "sec06b").await;
        let gzip = "Accept-Encoding: gzip\r\n";
        let plain = over(
            &lx,
            "sec06b",
            "mock.test",
            &get_req("mock.test", "/echo-headers", gzip),
        )
        .await;
        let encoded = over(
            &lx,
            "sec06b",
            "mock.test",
            &get_req("mock.test", "/echo-gzip", gzip),
        )
        .await;
        let seen = lx.egress.dialer.seen();
        assert_eq!(seen.len(), 2, "{seen:?}");
        for s in &seen {
            assert!(header_values(s, "accept-encoding").is_empty(), "{s}");
            assert!(s.contains(&gh()), "{s}");
        }
        assert!(plain.starts_with("HTTP/1.1 200 OK"), "{plain}");
        assert!(header_values(&plain, "content-encoding").is_empty());
        assert!(plain.contains("GET /echo-headers HTTP/1.1"), "{plain}");
        assert!(!plain.contains(&gh()), "{plain}");
        let (body, _) = body_and_length(&plain);
        assert_eq!(body, filled(&seen[0]));
        assert!(encoded.starts_with("HTTP/1.1 502 "), "{encoded}");
        assert!(encoded.contains("upstream-encoded"), "{encoded}");
        assert!(!encoded.contains("GZIPPED"), "{encoded}");
        // The control of the line above: asked around the proxy, the mock sends the marker.
        let direct =
            upstream_reply(&lx, "mock.test", &get_req("mock.test", "/echo-gzip", gzip)).await;
        assert!(direct.starts_with("HTTP/1.1 200 OK"), "{direct}");
        assert_eq!(header_values(&direct, "content-encoding"), ["gzip"]);
        assert_eq!(body_and_length(&direct), ("GZIPPED", 7), "{direct}");
        lx.stop(r).await;
    });
}

/// RT-SEC-06b, ranges: `Range`, `If-Range` and `Request-Range` never reach a grant host, so an
/// echo cannot be fetched in pieces the redaction sees only one at a time. Controls: the three
/// entries of `rewrite::REQUEST_DROPPED` (each removed on its own lets its header through). In-test
/// controls: an `X-Kept` header on the same request reaches the grant host, and the same request
/// to `mock2.test` (spliced, never rewritten) arrives with all three.
#[test]
fn rt_sec_06b_range_headers_never_reach_a_grant_host() {
    const RANGED: [&str; 3] = ["range", "if-range", "request-range"];
    rt().block_on(async {
        let lx = Lx::new();
        let r = session(&lx, "sec06r").await;
        let extra = "Range: bytes=0-3\r\nIf-Range: \"v1\"\r\nRequest-Range: bytes=0-3\r\n\
                     X-Kept: yes\r\n";
        let granted = over(
            &lx,
            "sec06r",
            "mock.test",
            &get_req("mock.test", "/echo-headers", extra),
        )
        .await;
        let spliced = over(
            &lx,
            "sec06r",
            "mock2.test",
            &get_req("mock2.test", "/echo-headers", extra),
        )
        .await;
        let seen = lx.egress.dialer.seen();
        assert_eq!(seen.len(), 2, "{seen:?}");
        assert!(granted.starts_with("HTTP/1.1 200 OK"), "{granted}");
        assert!(spliced.starts_with("HTTP/1.1 200 OK"), "{spliced}");
        assert!(seen[0].contains(&gh()), "{}", seen[0]);
        for name in RANGED {
            assert!(
                header_values(&seen[0], name).is_empty(),
                "{name}: {}",
                seen[0]
            );
            assert_eq!(
                header_values(&seen[1], name).len(),
                1,
                "{name}: {}",
                seen[1]
            );
        }
        assert_eq!(header_values(&seen[0], "x-kept"), ["yes"], "{}", seen[0]);
        assert_eq!(header_values(&seen[1], "x-kept"), ["yes"], "{}", seen[1]);
        lx.stop(r).await;
    });
}

/// `mock.test` with a `GITHUB_TOKEN` grant (so intercepted) and both body caps at the smallest
/// value the validator takes, 1 KiB (RT-NET-09).
const CAP_MANIFEST: &str = "network:\n  mode: proxy\n  allow:\n    - host: mock.test\n  \
                            max_request_bytes: 1KiB\n  max_response_bytes: 1KiB\n\
                            secrets:\n  - name: GITHUB_TOKEN\n    inject: {host: mock.test, \
                            header: Authorization, format: \"Bearer {value}\"}\n";

/// RT-NET-09, body caps: inside an intercepted tunnel of a real session, the manifest's
/// `max_request_bytes` and `max_response_bytes` hold. A request body one byte over is 413
/// `request-too-large` and never reaches the upstream; a response body one byte over is 502
/// `response-too-large` and none of it is forwarded; each refusal has its `egress.limit` entry.
/// Controls: the session's `body_caps`, taken from the manifest's `network` in `egress::net` and
/// handed to `Limits::of_session`; either one left unwired lets its one-over body through.
/// In-test controls: a body exactly at each cap passes, on the same session.
#[test]
fn rt_net_09_body_caps_hold_inside_an_intercepted_tunnel() {
    const CAP: usize = 1024;
    rt().block_on(async {
        let lx = Lx::new();
        let r = session_of(&lx, "net09b", CAP_MANIFEST).await;
        let post = |n: usize| {
            format!(
                "POST /sink HTTP/1.1\r\nHost: mock.test\r\nContent-Length: {n}\r\n\r\n{}",
                "q".repeat(n)
            )
        };
        let at = over(&lx, "net09b", "mock.test", &post(CAP)).await;
        assert!(at.starts_with("HTTP/1.1 200 OK"), "{at}");
        let over_req = over(&lx, "net09b", "mock.test", &post(CAP + 1)).await;
        assert!(over_req.starts_with("HTTP/1.1 413 "), "{over_req}");
        assert!(over_req.contains("request-too-large"), "{over_req}");
        let seen = lx.egress.dialer.seen();
        assert_eq!(seen.len(), 1, "the body over the cap reached the upstream");
        assert!(seen[0].ends_with(&"q".repeat(CAP)), "{}", seen[0]);
        let len = |n: usize| get_req("mock.test", &format!("/len/{n}"), "");
        let at = over(&lx, "net09b", "mock.test", &len(CAP)).await;
        assert!(at.starts_with("HTTP/1.1 200 OK"), "{at}");
        assert!(at.ends_with(&"b".repeat(CAP)), "{at}");
        let over_resp = over(&lx, "net09b", "mock.test", &len(CAP + 1)).await;
        assert!(over_resp.starts_with("HTTP/1.1 502 "), "{over_resp}");
        assert!(over_resp.contains("response-too-large"), "{over_resp}");
        assert!(!over_resp.contains("bbbb"), "{over_resp}");
        lx.stop(r).await;
        let limits: Vec<_> = lx
            .events
            .all()
            .into_iter()
            .filter(|(e, _)| e == "egress.limit")
            .map(|(_, a)| (a["reason"].clone(), a["host"].clone()))
            .collect();
        assert_eq!(
            limits,
            [
                (json!("request-too-large"), json!("mock.test")),
                (json!("response-too-large"), json!("mock.test")),
            ]
        );
    });
}

/// `mock.test` (a `GITHUB_TOKEN` grant), `mock3.test` (a `HOST_TOKEN` grant) and any host
/// under `*.mock.test` (allowed, no grant, so spliced: a grant host must be exact; architect
/// Q279).
const HOST_MANIFEST: &str = "network:\n  mode: proxy\n  allow:\n    - host: mock.test\n    \
                             - host: mock3.test\n    - host: \"*.mock.test\"\n\
                             secrets:\n  - name: GITHUB_TOKEN\n    inject: {host: mock.test, \
                             header: Authorization, format: \"Bearer {value}\"}\n  \
                             - name: HOST_TOKEN\n    inject: {host: mock3.test, \
                             header: X-Api-Key, format: \"{value}\"}\n";

/// RT-SEC-07, after the release (#94, architect Q249, Q266, Q279): a sandbox that knows a
/// granted value (here it is simply given it) opens a tunnel to `<value>.mock.test`, a host the
/// wildcard rule allows, so the value stands in the CONNECT host, which `sallyd` logs as the
/// sandbox sent it, lower-cased, and does not mask before the sink (#160). The session stops
/// with the tunnel open; its `egress.close` append is held until the stop is done,
/// `session.closed` is written and the session's forms have left the logs' redactors. When it
/// lands, after `session.closed`, its `host` is `[REDACTED:HOST_TOKEN].mock.test`, and the
/// value is nowhere in it, because the session's egress sink redacts with the session's own
/// forms. Only the raw form can stand in a host (a lower-case DNS label); this test proves
/// nothing about the other forms. The test sink never redacts, so the per-session redaction is
/// the only one it shows; `egress.allow`, written while the session is live, is checked too,
/// as an extra. Control (hand-checked once, uncommitted): the launcher passing the session's
/// unwrapped sink to its egress fails it, the raw value in the host.
#[test]
fn rt_sec_07_an_entry_written_after_the_release_holds_no_credential_in_its_host() {
    rt().block_on(async {
        let lx = Lx::new();
        let r = session_of(&lx, "sec07h", HOST_MANIFEST).await;
        let id = lx.paths("sec07h").id().as_str().to_owned();
        assert_eq!(lx.redactors.sessions(), std::slice::from_ref(&id));
        let value = common::egress::canary("HOST_TOKEN");
        let host = format!("{value}.mock.test");
        lx.egress.resolver.set(&host, vec![vec![tls_upstream()]]);
        let sock = lx.paths("sec07h").workspace_sockets().join("net.sock");
        // Held before the tunnel exists, so it cannot close unheld in between.
        let unhold = lx.events.held(&["egress.close"]);
        let tunnel = connect(&sock, &host).await;
        // Bounded, so a stop that waited for the held append fails instead of hanging.
        let bound = Duration::from_secs(60);
        let done = tokio::time::timeout(bound, lx.launcher.stop(r))
            .await
            .expect("the stop waited for the held append")
            .unwrap();
        lx.events.until_parked("egress.close", 1).await;
        tokio::time::timeout(
            bound,
            lx.launcher
                .close(done, sallyd::session::StopReason::Request),
        )
        .await
        .expect("session.closed waited for the held append");
        assert!(lx.redactors.sessions().is_empty(), "the forms stayed");
        drop(unhold);
        let mut close = None;
        for _ in 0..200 {
            let all = lx.events.all();
            let closed = all.iter().position(|(e, _)| e == "session.closed");
            let late = all.iter().position(|(e, _)| e == "egress.close");
            if let (Some(c), Some(q)) = (closed, late) {
                assert!(c < q, "control: the close landed before the release");
                close = Some(all[q].1.clone());
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let close = close.expect("the held egress.close landed");
        let allow = lx
            .events
            .all()
            .into_iter()
            .find(|(e, a)| e == "egress.allow" && a["intercept"] == json!(false))
            .expect("the tunnel's egress.allow")
            .1;
        for (event, entry) in [("egress.close", &close), ("egress.allow", &allow)] {
            assert_eq!(
                entry["host"],
                json!("[REDACTED:HOST_TOKEN].mock.test"),
                "{event}: {entry}"
            );
            assert!(!entry.to_string().contains(&value), "{event}: {entry}");
            let found = credential_in(event, entry, &forms_of(&value));
            assert!(found.is_none(), "{found:?}");
        }
        drop(tunnel);
    });
}

/// RT-SEC-07: after injected and echoed exchanges on every grant host (`Bearer`, a bare value,
/// three `{basic}` grants, the encoded echoes of `/echo-forms`), no audit entry holds any form
/// of any canary (each independently computed: raw, percent, JSON-string, base64 cores,
/// rendered values, blobs; searched in every decoded string, key and number, so JSON escaping cannot hide one),
/// and each `egress.request` names its grant. Control: `request_args` builds `injected` from
/// grant names (`Prepared::names`), and no entry is built from a header map or a body. In-test
/// control of the search (#122): [`credential_in`] finds every form planted in an entry.
#[test]
fn rt_sec_07_no_audit_entry_holds_a_credential() {
    rt().block_on(async {
        let lx = Lx::new();
        let r = session_of(&lx, "sec07", FORMS_MANIFEST).await;
        let _ = over(
            &lx,
            "sec07",
            "mock.test",
            &get_req("mock.test", "/echo-headers", ""),
        )
        .await;
        let _ = over(
            &lx,
            "sec07",
            "mock3.test",
            &get_req("mock3.test", "/echo-headers", ""),
        )
        .await;
        let _ = over(
            &lx,
            "sec07",
            "mock2.test",
            &get_req("mock2.test", "/echo-headers", ""),
        )
        .await;
        let _ = over(
            &lx,
            "sec07",
            "mock.test",
            &get_req("mock.test", "/echo-gzip", ""),
        )
        .await;
        for (host, _) in BASIC_HOSTS {
            for path in ["/echo-headers", "/echo-forms"] {
                let _ = over(&lx, "sec07", host, &get_req(host, path, "")).await;
            }
        }
        // Positive control: every credential was sent.
        let seen = lx.egress.dialer.seen().concat();
        assert!(seen.contains(&gh()) && seen.contains(&mock3()));
        for (_, user) in BASIC_HOSTS {
            assert!(seen.contains(&basic_blob(user, &git())), "{user}");
        }
        lx.stop(r).await;
        let forms = every_form();
        // Control (#122): the same search finds each form planted in an entry, as a string
        // value that JSON escapes, deep in an array, and as a key.
        for f in &forms {
            for planted in [
                json!({"note": format!("\"{f}\"")}),
                json!({"a": [{"b": [format!("x{f}y")]}]}),
                json!({ f.as_str(): 1 }),
            ] {
                assert!(
                    credential_in("planted", &planted, &forms).is_some(),
                    "control: {f} not found in {planted}"
                );
            }
        }
        let all = lx.events.all();
        for (event, args) in &all {
            let found = credential_in(event, args, &forms);
            assert!(found.is_none(), "{found:?}");
        }
        let injected: Vec<(String, serde_json::Value)> = all
            .iter()
            .filter(|(e, _)| e == "egress.request")
            .map(|(_, a)| {
                (
                    a["host"].as_str().unwrap().to_owned(),
                    a["injected"].clone(),
                )
            })
            .collect();
        let mut want = vec![
            ("mock.test".to_owned(), json!(["secret:GITHUB_TOKEN"])),
            ("mock3.test".to_owned(), json!(["secret:MOCK3_TOKEN"])),
            ("mock.test".to_owned(), json!(["secret:GITHUB_TOKEN"])),
        ];
        for (host, _) in BASIC_HOSTS {
            for _ in 0..2 {
                want.push((host.to_owned(), json!(["secret:GIT_TOKEN"])));
            }
        }
        assert_eq!(injected, want);
    });
}

/// RT-SEC-11: `expose_env` gives the workspace the public placeholder only; the grant host's
/// upstream gets the real credential in its place, the non-grant host at most the placeholder.
/// Controls: the placeholder in `argv::PLACEHOLDER` (the only value `--env` can carry), and on
/// the grant host the pair of RT-SEC-04 (the grant-header drop and `Prepared::apply`'s
/// `insert`): the replace half fails only when both of that pair are removed (architect Q2).
#[test]
fn rt_sec_11_the_workspace_holds_only_the_placeholder() {
    rt().block_on(async {
        let lx = Lx::new();
        let manifest = MANIFEST.replace(
            "format: \"Bearer {value}\"}\n",
            "format: \"Bearer {value}\"}\n    expose_env: GH_TOKEN\n",
        );
        let r = session_of(&lx, "sec11", &manifest).await;
        let (_, env) = exec(&r, "env").await;
        let (_, procs) = exec(
            &r,
            "for f in /proc/[0-9]*/environ; do tr '\\0' '\\n' < $f; done 2>/dev/null",
        )
        .await;
        // Control (#122): each dump is shown to read the environment: both carry the placeholder,
        // and the `/proc` one from PID 1 and from the shell that reads it.
        let copies = |dump: &str| dump.matches("GH_TOKEN=sallyport-placeholder").count();
        assert!(copies(&env) >= 1, "control: the env dump misses it: {env}");
        assert!(
            copies(&procs) >= 2,
            "control: the /proc dump misses it: {procs}"
        );
        for dump in [&env, &procs] {
            assert!(!dump.contains(&gh()) && !dump.contains("CANARY"), "{dump}");
        }
        let placeholder = "Authorization: Bearer sallyport-placeholder\r\n";
        let _ = over(
            &lx,
            "sec11",
            "mock.test",
            &get_req("mock.test", "/echo-headers", placeholder),
        )
        .await;
        let _ = over(
            &lx,
            "sec11",
            "mock2.test",
            &get_req("mock2.test", "/echo-headers", placeholder),
        )
        .await;
        let seen = lx.egress.dialer.seen();
        assert_eq!(
            header_values(&seen[0], "authorization"),
            [format!("Bearer {}", gh())]
        );
        assert!(!seen[0].contains("sallyport-placeholder"), "{}", seen[0]);
        assert!(!seen[1].contains(&gh()), "{}", seen[1]);
        assert_eq!(
            header_values(&seen[1], "authorization"),
            ["Bearer sallyport-placeholder"]
        );
        lx.stop(r).await;
    });
}

/// RT-SEC-12: encoded echoes split across chunks. Each `{basic}` grant host answers
/// `/echo-forms` with `GIT_TOKEN`'s raw value, every percent spelling (three keep-sets, with and
/// without `+` for a space, both hex cases), its JSON-string spelling, base64 of
/// prefix‖secret‖suffix at all three alignments in both alphabets, the padded and the unpadded
/// blob, and the request it got, in 5-byte HTTP chunks; and `/echo-headers` with the rendered
/// value in a header. The three users put the secret at all three alignments inside the blob.
/// Controls: the held-back overlap of `redact::Stream` (without it, a form split across chunks
/// passes); the forms `Credentials::new` builds: the secret's own (raw, percent with each
/// keep-set, JSON-string, base64 cores),
/// and the grant's rendered value and blobs (`render`; without them the `Basic ` prefix and
/// the blob's edge characters pass); `redact::headers` for the header echo.
#[test]
fn rt_sec_12_every_encoded_echo_split_across_chunks_is_redacted() {
    rt().block_on(async {
        let lx = Lx::new();
        let r = session_of(&lx, "sec12", FORMS_MANIFEST).await;
        let mut outs = Vec::new();
        for (host, _) in BASIC_HOSTS {
            let forms = over(&lx, "sec12", host, &get_req(host, "/echo-forms", "")).await;
            let headers = over(&lx, "sec12", host, &get_req(host, "/echo-headers", "")).await;
            outs.push((forms, headers));
        }
        let seen = lx.egress.dialer.seen();
        assert_eq!(seen.len(), 2 * BASIC_HOSTS.len(), "{seen:?}");
        lx.stop(r).await;
        for (i, ((host, user), (forms, headers))) in BASIC_HOSTS.iter().zip(&outs).enumerate() {
            let body = check_echo_forms(host, user, &seen[2 * i], forms);
            let rendered = format!("Basic {}", basic_blob(user, &git()));
            assert_eq!(
                header_values(headers, "x-echo-authorization"),
                ["*".repeat(rendered.len())],
                "{headers}"
            );
            let bare = rendered["Basic ".len()..].trim_end_matches('=');
            assert!(!headers.contains(bare), "{headers}");
            let entries = responses(&lx, host);
            assert_eq!(entries.len(), 2, "{entries:?}");
            let n = body.bytes().filter(|b| *b == b'*').count() as u64;
            assert_eq!(
                entries[0]["redacted"],
                json!([{"secret": "secret:GIT_TOKEN", "bytes": n}]),
                "{host}"
            );
            assert_eq!(entries[0]["redacted_bytes"], json!(n));
            assert_eq!(entries[0]["end"], json!("complete"));
        }
    });
}
