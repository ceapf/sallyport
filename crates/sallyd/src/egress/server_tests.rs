#![allow(clippy::unwrap_used)]
//! Unit tests of the handler: fake resolver, dialer, host addresses and audit sink. Addresses are
//! built with `Ipv4Addr::new` (the repository's guard hooks refuse dotted IPv4 literals).

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;

use sally_core::audit::AuditError;
use sally_core::manifest::parse_host_pattern;
use tokio::io::{DuplexStream, duplex};

use super::*;
use crate::egress::policy::Rule;

/// A public address (documentation-free, globally routed).
fn public(n: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(93, 184, 215, n))
}

fn sock(ip: IpAddr, port: u16) -> SocketAddr {
    SocketAddr::new(ip, port)
}

/// Answers per name, one list per call (the last repeats); counts every lookup.
#[derive(Default)]
struct FakeResolver {
    answers: HashMap<String, Vec<io::Result<Vec<IpAddr>>>>,
    hang: bool,
    calls: Arc<Mutex<Vec<String>>>,
}

impl FakeResolver {
    fn with(mut self, host: &str, answers: Vec<Vec<IpAddr>>) -> Self {
        self.answers
            .insert(host.to_owned(), answers.into_iter().map(Ok).collect());
        self
    }
}

impl Resolver for FakeResolver {
    async fn resolve(&self, host: &str, _port: u16) -> io::Result<Vec<SocketAddr>> {
        let n = {
            let mut calls = self.calls.lock().unwrap();
            calls.push(host.to_owned());
            calls.iter().filter(|h| *h == host).count()
        };
        if self.hang {
            std::future::pending::<()>().await;
        }
        let Some(list) = self.answers.get(host) else {
            return Err(io::ErrorKind::NotFound.into());
        };
        let pick = list.get(n - 1).or(list.last()).unwrap();
        match pick {
            Ok(ips) => Ok(ips.iter().map(|ip| sock(*ip, 1)).collect()),
            Err(e) => Err(io::Error::new(e.kind(), "fake")),
        }
    }
}

/// Connects to an in-memory echo server unless the address refuses or hangs; records attempts.
#[derive(Default)]
struct FakeDialer {
    refuse: Vec<IpAddr>,
    hang: Vec<IpAddr>,
    dials: Arc<Mutex<Vec<SocketAddr>>>,
}

impl Dialer for FakeDialer {
    type Stream = DuplexStream;
    async fn dial(&self, to: SocketAddr) -> io::Result<DuplexStream> {
        self.dials.lock().unwrap().push(to);
        if self.hang.contains(&to.ip()) {
            std::future::pending::<()>().await;
        }
        if self.refuse.contains(&to.ip()) {
            return Err(io::ErrorKind::ConnectionRefused.into());
        }
        let (near, mut far) = duplex(64 * 1024);
        tokio::spawn(async move {
            let (mut r, mut w) = tokio::io::split(&mut far);
            let _ = tokio::io::copy(&mut r, &mut w).await;
            let _ = w.shutdown().await;
        });
        Ok(near)
    }
}

struct FakeHost(Option<Vec<IpAddr>>);

impl HostAddrs for FakeHost {
    async fn own(&self) -> io::Result<Vec<IpAddr>> {
        self.0.clone().ok_or_else(|| io::ErrorKind::NotFound.into())
    }
}

/// Records (event, decision, arguments); `fail` refuses every append.
#[derive(Default)]
struct Sink {
    entries: Mutex<Vec<(String, Option<String>, Value)>>,
    fail: bool,
}

impl AuditSink for Sink {
    fn append(&self, e: NewEntry, _: AuditLevel) -> Result<(), AuditError> {
        if self.fail {
            return Err(AuditError::InvalidEntry("fake failure"));
        }
        let row = (
            e.event().to_owned(),
            e.decision_value().map(str::to_owned),
            e.arguments().clone(),
        );
        self.entries.lock().unwrap().push(row);
        Ok(())
    }
}

impl Sink {
    fn events(&self) -> Vec<String> {
        let rows = self.entries.lock().unwrap();
        rows.iter().map(|(e, _, _)| e.clone()).collect()
    }
    fn decisions(&self) -> Vec<Option<String>> {
        let rows = self.entries.lock().unwrap();
        rows.iter().map(|(_, d, _)| d.clone()).collect()
    }
    fn args(&self, event: &str) -> Value {
        let rows = self.entries.lock().unwrap();
        let row = rows.iter().find(|(e, _, _)| e == event);
        row.map_or(Value::Null, |(_, _, a)| a.clone())
    }
}

fn rule(host: &str, ports: &[u16]) -> Rule {
    Rule {
        host: parse_host_pattern(host).unwrap(),
        ports: ports.to_vec(),
    }
}

struct Rig {
    proxy: Arc<Proxy<FakeResolver, FakeDialer, FakeHost>>,
    sink: Arc<Sink>,
    lookups: Arc<Mutex<Vec<String>>>,
    dials: Arc<Mutex<Vec<SocketAddr>>>,
}

struct Setup {
    resolver: FakeResolver,
    dialer: FakeDialer,
    host: FakeHost,
    sink: Sink,
    max: usize,
    grants: Vec<String>,
}

impl Default for Setup {
    fn default() -> Self {
        Self {
            resolver: FakeResolver::default()
                .with("a.mock.test", vec![vec![public(1)]])
                .with("mock.test", vec![vec![public(2)]]),
            dialer: FakeDialer::default(),
            host: FakeHost(Some(vec![])),
            sink: Sink::default(),
            max: 8,
            grants: vec![],
        }
    }
}

impl Setup {
    fn rig(self) -> Rig {
        let sink = Arc::new(self.sink);
        let lookups = Arc::clone(&self.resolver.calls);
        let dials = Arc::clone(&self.dialer.dials);
        let policy = Policy::new(
            vec![rule("*.mock.test", &[443]), rule("mock.test", &[443, 8443])],
            self.grants,
        );
        let proxy = Arc::new(Proxy::new(Parts {
            policy,
            resolver: self.resolver,
            dialer: self.dialer,
            host: self.host,
            audit: Arc::clone(&sink) as Arc<dyn AuditSink>,
            session: "s-1".into(),
            level: AuditLevel::default(),
            limits: Limits::new(self.max),
        }));
        Rig {
            proxy,
            sink,
            lookups,
            dials,
        }
    }
}

impl Rig {
    /// Sends `req`, closes the sending half, and returns everything the proxy sent back.
    async fn send(&self, req: &[u8]) -> String {
        let (mut client, server) = duplex(MAX_HEAD * 4);
        let proxy = Arc::clone(&self.proxy);
        let task = tokio::spawn(async move { proxy.serve(server).await });
        client.write_all(req).await.unwrap();
        client.shutdown().await.unwrap();
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        task.await.unwrap();
        String::from_utf8_lossy(&out).into_owned()
    }

    fn lookups(&self) -> usize {
        self.lookups.lock().unwrap().len()
    }

    fn dials(&self) -> Vec<SocketAddr> {
        self.dials.lock().unwrap().clone()
    }
}

fn connect(target: &str) -> Vec<u8> {
    format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").into_bytes()
}

#[tokio::test]
async fn an_allowed_host_is_tunnelled_to_its_pinned_address() {
    let rig = Setup::default().rig();
    let mut req = connect("a.mock.test:443");
    req.extend_from_slice(b"ping");
    let got = rig.send(&req).await;
    assert_eq!(got, "HTTP/1.1 200 Connection Established\r\n\r\nping");
    assert_eq!(rig.dials(), vec![sock(public(1), 443)]);
    assert_eq!(rig.sink.events(), ["egress.allow", "egress.close"]);
    assert_eq!(rig.sink.decisions(), [Some("allow".to_owned()), None]);
    assert_eq!(
        rig.sink.args("egress.allow"),
        json!({"host": "a.mock.test", "port": 443, "addresses": [public(1).to_string()]})
    );
    assert_eq!(
        rig.sink.args("egress.close"),
        json!({
            "host": "a.mock.test", "port": 443, "connected": true,
            "address": public(1).to_string(), "bytes_up": 4, "bytes_down": 4, "end": "closed",
        })
    );
}

#[tokio::test]
async fn refusals_are_audited_then_answered_and_nothing_is_resolved() {
    let ip = Ipv4Addr::new(1, 1, 1, 1).to_string();
    let cases: Vec<(String, Reason)> = vec![
        ("evil.test:443".into(), Reason::HostNotAllowed),
        ("mock.test:22".into(), Reason::PortNotAllowed),
        ("a.mock.test:8443".into(), Reason::PortNotAllowed),
        (format!("{ip}:443"), Reason::IpLiteral),
        ("16843009:443".into(), Reason::IpLiteral),
        ("0x01010101:443".into(), Reason::IpLiteral),
        (format!("[::ffff:{ip}]:443"), Reason::IpLiteral),
        ("[::1]:443".into(), Reason::IpLiteral),
        ("mock.test".into(), Reason::Malformed),
        ("user@mock.test:443".into(), Reason::Malformed),
        ("mock.test:0".into(), Reason::Malformed),
    ];
    for (target, reason) in cases {
        let rig = Setup::default().rig();
        let got = rig.send(&connect(&target)).await;
        assert_eq!(got, reply(reason), "{target}");
        assert_eq!(rig.lookups(), 0, "{target}");
        assert!(rig.dials().is_empty(), "{target}");
        assert_eq!(rig.sink.events(), ["egress.deny"], "{target}");
        assert_eq!(rig.sink.decisions(), [Some("deny".to_owned())]);
        assert_eq!(
            rig.sink.args("egress.deny"),
            json!({
                "reason": reason.as_str(), "target": target,
                "target_bytes": target.len(), "target_cut": false,
            }),
            "{target}"
        );
    }
}

#[tokio::test]
async fn the_decision_uses_the_request_target_never_the_host_header() {
    let rig = Setup::default().rig();
    let got = rig
        .send(b"CONNECT evil.test:443 HTTP/1.1\r\nHost: a.mock.test:443\r\n\r\n")
        .await;
    assert_eq!(got, reply(Reason::HostNotAllowed));
    assert_eq!(rig.lookups(), 0);
    assert_eq!(
        rig.sink.args("egress.deny")["target"],
        json!("evil.test:443")
    );
    let logged = rig.sink.args("egress.deny").to_string();
    assert!(!logged.contains("a.mock.test"), "{logged}");
}

#[tokio::test]
async fn userinfo_in_a_connect_target_is_refused() {
    let rig = Setup::default().rig();
    let got = rig.send(&connect("a.mock.test@evil.test:443")).await;
    assert_eq!(got, reply(Reason::Malformed));
    assert_eq!(rig.lookups(), 0);
}

#[tokio::test]
async fn anything_but_connect_gets_405_whatever_its_target() {
    for req in [
        &b"GET http://evil.test/ HTTP/1.1\r\nHost: a.mock.test\r\n\r\n"[..],
        b"GET http://a.mock.test@evil.test/ HTTP/1.1\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: a.mock.test\r\n\r\n",
        b"POST http://a.mock.test/ HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
    ] {
        let rig = Setup::default().rig();
        let got = rig.send(req).await;
        assert_eq!(got, reply(Reason::PlainHttpUnsupported));
        assert!(got.contains("\r\nAllow: CONNECT\r\n"));
        assert_eq!(rig.lookups(), 0);
        assert_eq!(rig.sink.events(), ["egress.deny"]);
    }
}

#[tokio::test]
async fn a_long_target_is_logged_escaped_and_cut_never_echoed() {
    let rig = Setup::default().rig();
    // No port: a valid request-target, an invalid authority. Escaping itself: authority.rs.
    let target = format!("{}.test", "a".repeat(300));
    let got = rig.send(&connect(&target)).await;
    assert_eq!(got, reply(Reason::Malformed));
    let args = rig.sink.args("egress.deny");
    assert_eq!(args["target"], json!("a".repeat(256)));
    assert_eq!(args["target_bytes"], json!(target.len()));
    assert_eq!(args["target_cut"], json!(true));
}

#[tokio::test]
async fn a_grant_host_is_refused_before_any_lookup() {
    let rig = Setup {
        grants: vec!["a.mock.test".into()],
        ..Setup::default()
    }
    .rig();
    let got = rig.send(&connect("a.mock.test:443")).await;
    assert_eq!(got, reply(Reason::GrantHostUnavailable));
    assert_eq!(rig.lookups(), 0);
}

#[tokio::test]
async fn names_are_normalized_before_the_decision() {
    let rig = Setup::default().rig();
    let got = rig.send(&connect("A.MOCK.TEST.:443")).await;
    assert!(got.starts_with("HTTP/1.1 200 "), "{got}");
    assert_eq!(*rig.lookups.lock().unwrap(), ["a.mock.test"]);
}

#[tokio::test]
async fn one_denied_address_refuses_the_whole_name() {
    let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let private = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
    let metadata = IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254));
    for bad in [loopback, private, metadata, IpAddr::V6(Ipv6Addr::LOCALHOST)] {
        let rig = Setup {
            resolver: FakeResolver::default().with("a.mock.test", vec![vec![public(1), bad]]),
            ..Setup::default()
        }
        .rig();
        let got = rig.send(&connect("a.mock.test:443")).await;
        assert_eq!(got, reply(Reason::IpRangeDenied), "{bad}");
        assert!(rig.dials().is_empty(), "{bad}");
        assert_eq!(rig.sink.events(), ["egress.deny"]);
    }
}

#[tokio::test]
async fn the_hosts_own_addresses_are_refused_and_an_unknown_list_refuses_all() {
    let own = Setup {
        host: FakeHost(Some(vec![public(1)])),
        ..Setup::default()
    }
    .rig();
    assert_eq!(
        own.send(&connect("a.mock.test:443")).await,
        reply(Reason::IpRangeDenied)
    );
    assert!(own.dials().is_empty());
    let unknown = Setup {
        host: FakeHost(None),
        ..Setup::default()
    }
    .rig();
    assert_eq!(
        unknown.send(&connect("a.mock.test:443")).await,
        reply(Reason::IpRangeDenied)
    );
    assert!(unknown.dials().is_empty());
    assert_eq!(unknown.lookups(), 0);
    assert_eq!(
        unknown.sink.args("egress.deny"),
        json!({
            "reason": "ip-range-denied", "target": "a.mock.test:443", "target_bytes": 15,
            "target_cut": false, "filter": "host-addresses-unavailable",
        })
    );
}

#[tokio::test]
async fn every_address_is_filtered_but_only_sixteen_are_kept() {
    let mut ips: Vec<IpAddr> = (1..=20).map(public).collect();
    let rig = Setup {
        resolver: FakeResolver::default().with("a.mock.test", vec![ips.clone()]),
        ..Setup::default()
    }
    .rig();
    let got = rig.send(&connect("a.mock.test:443")).await;
    assert!(got.starts_with("HTTP/1.1 200 "), "{got}");
    let kept: Vec<String> = ips
        .iter()
        .take(MAX_ADDRS)
        .map(ToString::to_string)
        .collect();
    assert_eq!(rig.sink.args("egress.allow")["addresses"], json!(kept));
    ips.push(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let late = Setup {
        resolver: FakeResolver::default().with("a.mock.test", vec![ips]),
        ..Setup::default()
    }
    .rig();
    let got = late.send(&connect("a.mock.test:443")).await;
    assert_eq!(got, reply(Reason::IpRangeDenied));
}

#[tokio::test]
async fn an_answer_over_sixty_four_addresses_fails_before_dedupe_and_filter() {
    let full: Vec<IpAddr> = (1..=64).map(public).collect();
    let mut over_by_loopback = full.clone();
    over_by_loopback.push(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let rig = Setup {
        resolver: FakeResolver::default()
            .with("a.mock.test", vec![full])
            .with("b.mock.test", vec![over_by_loopback])
            .with("c.mock.test", vec![vec![public(1); MAX_ANSWER + 1]]),
        ..Setup::default()
    }
    .rig();
    let got = rig.send(&connect("a.mock.test:443")).await;
    assert!(got.starts_with("HTTP/1.1 200 "), "{got}");
    assert_eq!(rig.dials().len(), 1);
    for target in ["b.mock.test:443", "c.mock.test:443"] {
        let got = rig.send(&connect(target)).await;
        assert_eq!(got, reply(Reason::ResolveFailed), "{target}");
    }
    assert_eq!(rig.dials().len(), 1, "nothing more was dialled");
    let rows = rig.sink.entries.lock().unwrap();
    let reasons: Vec<&Value> = rows.iter().map(|(_, _, a)| &a["reason"]).collect();
    assert_eq!(
        reasons.iter().filter(|r| **r == "resolve-failed").count(),
        2
    );
}

#[tokio::test]
async fn stopping_ends_checks_without_a_reply_and_tunnels_with_session_stopped() {
    let rig = Setup::default().rig();
    let (mut open, server) = duplex(4096);
    let proxy = Arc::clone(&rig.proxy);
    let tunnel = tokio::spawn(async move { proxy.serve(server).await });
    open.write_all(&connect("a.mock.test:443")).await.unwrap();
    let mut ok = vec![0u8; ESTABLISHED.len()];
    open.read_exact(&mut ok).await.unwrap();
    let (mut waiting, server) = duplex(4096);
    let proxy = Arc::clone(&rig.proxy);
    let check = tokio::spawn(async move { proxy.serve(server).await });
    waiting.write_all(b"CONNECT a.mock").await.unwrap();
    rig.proxy.stop();
    tunnel.await.unwrap();
    check.await.unwrap();
    let mut rest = Vec::new();
    waiting.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty());
    assert_eq!(
        rig.sink.args("egress.close")["end"],
        json!("session-stopped")
    );
    assert_eq!(rig.sink.events(), ["egress.allow", "egress.close"]);
    let after = rig.send(&connect("a.mock.test:443")).await;
    assert_eq!(after, "");
}

#[tokio::test(start_paused = true)]
async fn stopping_while_dialling_writes_a_close_without_a_reply() {
    let rig = Setup {
        dialer: FakeDialer {
            hang: vec![public(1)],
            ..FakeDialer::default()
        },
        ..Setup::default()
    }
    .rig();
    let (mut client, server) = duplex(4096);
    let proxy = Arc::clone(&rig.proxy);
    let task = tokio::spawn(async move { proxy.serve(server).await });
    client.write_all(&connect("a.mock.test:443")).await.unwrap();
    while rig.dials().is_empty() {
        tokio::task::yield_now().await;
    }
    rig.proxy.stop();
    task.await.unwrap();
    let mut out = Vec::new();
    client.read_to_end(&mut out).await.unwrap();
    assert!(out.is_empty());
    assert_eq!(
        rig.sink.args("egress.close"),
        json!({
            "host": "a.mock.test", "port": 443, "connected": false,
            "bytes_up": 0, "bytes_down": 0, "end": "session-stopped",
        })
    );
}

#[tokio::test(start_paused = true)]
async fn a_client_that_never_reads_its_reply_is_closed() {
    let rig = Setup::default().rig();
    let (mut client, server) = duplex(16);
    let proxy = Arc::clone(&rig.proxy);
    let task = tokio::spawn(async move { proxy.serve(server).await });
    client.write_all(&connect("evil.test:443")).await.unwrap();
    let t0 = tokio::time::Instant::now();
    task.await.unwrap();
    assert_eq!(t0.elapsed(), REPLY_TIMEOUT);
}

#[tokio::test]
async fn a_rebinding_name_is_looked_up_once_per_connection_and_pinned() {
    let rig = Setup {
        resolver: FakeResolver::default().with(
            "a.mock.test",
            vec![vec![public(1)], vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]],
        ),
        ..Setup::default()
    }
    .rig();
    let first = rig.send(&connect("a.mock.test:443")).await;
    assert!(first.starts_with("HTTP/1.1 200 "), "{first}");
    assert_eq!(rig.lookups(), 1);
    assert_eq!(rig.dials(), vec![sock(public(1), 443)]);
    let second = rig.send(&connect("a.mock.test:443")).await;
    assert_eq!(second, reply(Reason::IpRangeDenied));
    assert_eq!(rig.lookups(), 2);
    assert_eq!(rig.dials(), vec![sock(public(1), 443)]);
}

#[tokio::test]
async fn failed_or_empty_lookups_are_502() {
    let mut empty = FakeResolver::default().with("a.mock.test", vec![vec![]]);
    empty
        .answers
        .insert("mock.test".into(), vec![Err(io::ErrorKind::Other.into())]);
    let rig = Setup {
        resolver: empty,
        ..Setup::default()
    }
    .rig();
    for target in ["a.mock.test:443", "mock.test:443", "b.mock.test:443"] {
        assert_eq!(
            rig.send(&connect(target)).await,
            reply(Reason::ResolveFailed),
            "{target}"
        );
    }
    assert!(rig.dials().is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_lookup_gets_five_seconds() {
    let rig = Setup {
        resolver: FakeResolver {
            hang: true,
            ..FakeResolver::default()
        },
        ..Setup::default()
    }
    .rig();
    let t0 = tokio::time::Instant::now();
    let got = rig.send(&connect("a.mock.test:443")).await;
    assert_eq!(got, reply(Reason::ResolveFailed));
    assert_eq!(t0.elapsed(), RESOLVE_TIMEOUT);
}

#[tokio::test]
async fn the_requested_port_is_dialled_and_duplicates_are_tried_once() {
    let (a, b) = (public(1), public(2));
    let rig = Setup {
        resolver: FakeResolver::default().with("a.mock.test", vec![vec![a, a, b]]),
        dialer: FakeDialer {
            refuse: vec![a],
            ..FakeDialer::default()
        },
        ..Setup::default()
    }
    .rig();
    let got = rig.send(&connect("a.mock.test:443")).await;
    assert!(got.starts_with("HTTP/1.1 200 "), "{got}");
    assert_eq!(rig.dials(), vec![sock(a, 443), sock(b, 443)]);
    assert_eq!(
        rig.sink.args("egress.allow")["addresses"],
        json!([a.to_string(), b.to_string()])
    );
    assert_eq!(
        rig.sink.args("egress.close")["address"],
        json!(b.to_string())
    );
}

#[tokio::test]
async fn at_most_three_addresses_are_tried_then_502_connect_failed() {
    let ips: Vec<IpAddr> = (1..=4).map(public).collect();
    let rig = Setup {
        resolver: FakeResolver::default().with("a.mock.test", vec![ips.clone()]),
        dialer: FakeDialer {
            refuse: ips.clone(),
            ..FakeDialer::default()
        },
        ..Setup::default()
    }
    .rig();
    let got = rig.send(&connect("a.mock.test:443")).await;
    assert_eq!(got, reply(Reason::ConnectFailed));
    let tried: Vec<SocketAddr> = ips.iter().take(3).map(|ip| sock(*ip, 443)).collect();
    assert_eq!(rig.dials(), tried);
    assert_eq!(rig.sink.events(), ["egress.allow", "egress.close"]);
    let all: Vec<String> = ips.iter().map(ToString::to_string).collect();
    assert_eq!(rig.sink.args("egress.allow")["addresses"], json!(all));
    assert_eq!(
        rig.sink.args("egress.close"),
        json!({
            "host": "a.mock.test", "port": 443, "connected": false,
            "bytes_up": 0, "bytes_down": 0, "end": "connect-failed",
        })
    );
    assert_eq!(rig.sink.decisions(), [Some("allow".to_owned()), None]);
}

#[tokio::test(start_paused = true)]
async fn each_connect_attempt_gets_ten_seconds() {
    let (a, b) = (public(1), public(2));
    let rig = Setup {
        resolver: FakeResolver::default().with("a.mock.test", vec![vec![a, b]]),
        dialer: FakeDialer {
            hang: vec![a],
            ..FakeDialer::default()
        },
        ..Setup::default()
    }
    .rig();
    let t0 = tokio::time::Instant::now();
    let got = rig.send(&connect("a.mock.test:443")).await;
    assert!(got.starts_with("HTTP/1.1 200 "), "{got}");
    assert!(t0.elapsed() >= CONNECT_TIMEOUT, "{:?}", t0.elapsed());
    assert!(t0.elapsed() < CONNECT_TIMEOUT * 2, "{:?}", t0.elapsed());
    assert_eq!(rig.dials(), vec![sock(a, 443), sock(b, 443)]);
}

#[tokio::test]
async fn connections_over_the_cap_get_429_without_being_read() {
    let rig = Setup {
        max: 1,
        ..Setup::default()
    }
    .rig();
    let (mut held, server) = duplex(4096);
    let proxy = Arc::clone(&rig.proxy);
    let first = tokio::spawn(async move { proxy.serve(server).await });
    held.write_all(&connect("a.mock.test:443")).await.unwrap();
    let mut ok = vec![0u8; ESTABLISHED.len()];
    held.read_exact(&mut ok).await.unwrap();
    assert_eq!(ok, ESTABLISHED);
    let got = rig.send(&connect("a.mock.test:443")).await;
    assert_eq!(got, reply(Reason::TooManyConnections));
    assert_eq!(
        rig.sink.args("egress.limit"),
        json!({"reason": "too-many-connections"})
    );
    drop(held);
    first.await.unwrap();
    let again = rig.send(&connect("a.mock.test:443")).await;
    assert!(again.starts_with("HTTP/1.1 200 "), "{again}");
}

#[tokio::test]
async fn an_oversized_head_is_431_and_a_limit_entry_with_its_size() {
    let rig = Setup::default().rig();
    let mut req = b"CONNECT a.mock.test:443 HTTP/1.1\r\nX: ".to_vec();
    req.resize(MAX_HEAD + 100, b'a');
    let got = rig.send(&req).await;
    assert_eq!(got, reply(Reason::HeadTooLarge));
    assert_eq!(rig.sink.events(), ["egress.limit"]);
    assert_eq!(
        rig.sink.args("egress.limit")["reason"],
        json!("head-too-large")
    );
    assert_eq!(rig.sink.args("egress.limit")["head_bytes"], json!(MAX_HEAD));
    assert_eq!(rig.lookups(), 0);
}

#[tokio::test(start_paused = true)]
async fn a_slow_head_is_closed_without_a_reply_at_ten_seconds() {
    let rig = Setup::default().rig();
    let (mut client, server) = duplex(4096);
    let proxy = Arc::clone(&rig.proxy);
    let task = tokio::spawn(async move { proxy.serve(server).await });
    client.write_all(b"CONNECT a.mock.te").await.unwrap();
    let t0 = tokio::time::Instant::now();
    let mut out = Vec::new();
    client.read_to_end(&mut out).await.unwrap();
    task.await.unwrap();
    assert!(out.is_empty());
    assert_eq!(t0.elapsed(), HEAD_TIMEOUT);
    assert_eq!(
        rig.sink.args("egress.limit"),
        json!({"reason": "head-timeout", "head_bytes": 17})
    );
}

#[tokio::test]
async fn garbage_is_400_with_its_size_only() {
    let rig = Setup::default().rig();
    let got = rig.send(b"\x16\x03\x01\x02\x00garbage").await;
    assert_eq!(got, reply(Reason::Malformed));
    assert_eq!(
        rig.sink.args("egress.deny"),
        json!({"reason": "malformed", "head_bytes": 12})
    );
}

#[tokio::test]
async fn when_the_audit_log_fails_nothing_is_answered_or_dialled() {
    for req in [connect("a.mock.test:443"), connect("evil.test:443")] {
        let rig = Setup {
            sink: Sink {
                fail: true,
                ..Sink::default()
            },
            ..Setup::default()
        }
        .rig();
        assert_eq!(rig.send(&req).await, "");
        assert!(rig.dials().is_empty());
    }
}

#[test]
fn replies_carry_the_status_phrase_and_reason_only() {
    use Reason::*;
    let table = [
        (HostNotAllowed, "403 Forbidden"),
        (PortNotAllowed, "403 Forbidden"),
        (IpLiteral, "403 Forbidden"),
        (IpRangeDenied, "403 Forbidden"),
        (GrantHostUnavailable, "403 Forbidden"),
        (ResolveFailed, "502 Bad Gateway"),
        (ConnectFailed, "502 Bad Gateway"),
        (PlainHttpUnsupported, "405 Method Not Allowed"),
        (TooManyConnections, "429 Too Many Requests"),
        (HeadTooLarge, "431 Request Header Fields Too Large"),
        (HeadTimeout, "408 Request Timeout"),
        (Malformed, "400 Bad Request"),
    ];
    for (r, status) in table {
        let code = r.as_str();
        let allow = if r == PlainHttpUnsupported {
            "Allow: CONNECT\r\n"
        } else {
            ""
        };
        let want = format!(
            "HTTP/1.1 {status}\r\n{allow}Content-Type: text/plain\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{code}\n",
            code.len() + 1
        );
        assert_eq!(reply(r), want);
    }
    assert_eq!(phrase(500), "Error");
}

#[test]
fn the_limits_are_pinned() {
    assert_eq!(
        Limits::new(7),
        Limits {
            head: Duration::from_secs(10),
            resolve: Duration::from_secs(5),
            connect: Duration::from_secs(10),
            idle: Duration::from_secs(300),
            max_connections: 7,
        }
    );
    assert_eq!(MAX_DIALS, 3);
    assert_eq!((MAX_ADDRS, MAX_ANSWER, ADMISSION_EXTRA), (16, 64, 64));
}

#[test]
fn the_in_flight_bound_is_the_cap_plus_sixty_four_and_never_overflows() {
    assert_eq!(Limits::new(8).in_flight(), 72);
    assert_eq!(Limits::new(0).in_flight(), 64);
    assert_eq!(Limits::new(usize::MAX).in_flight(), Semaphore::MAX_PERMITS);
    assert_eq!(
        Limits::new(Semaphore::MAX_PERMITS - 64).in_flight(),
        Semaphore::MAX_PERMITS
    );
    assert_eq!(
        Limits::new(Semaphore::MAX_PERMITS - 65).in_flight(),
        Semaphore::MAX_PERMITS - 1
    );
}

#[test]
fn a_huge_connection_cap_does_not_panic() {
    let rig = Setup {
        max: usize::MAX,
        ..Setup::default()
    }
    .rig();
    assert_eq!(rig.proxy.limits().max_connections, usize::MAX);
}

// read_head on its own.

const SHORT: Duration = Duration::from_millis(200);

#[tokio::test]
async fn a_head_sent_in_pieces_is_read_with_what_follows_it() {
    let (mut client, mut proxy) = duplex(64);
    let sender = tokio::spawn(async move {
        for part in [
            &b"CONNECT mock.te"[..],
            b"st:443 HTTP/1.1\r\n",
            b"\r\nhello",
        ] {
            client.write_all(part).await.unwrap();
            tokio::task::yield_now().await;
        }
        client
    });
    let mut buf = [0u8; MAX_HEAD];
    let filled = read_head(&mut proxy, &mut buf, HEAD_TIMEOUT).await.unwrap();
    let _client = sender.await.unwrap();
    let head_len = b"CONNECT mock.test:443 HTTP/1.1\r\n\r\n".len();
    assert!(filled >= head_len);
    assert_eq!(&buf[..head_len], b"CONNECT mock.test:443 HTTP/1.1\r\n\r\n");
}

/// A client whose every read returns exactly one of its chunks (or what fits of it), then EOF:
/// each chunk is its own read whatever the scheduler does.
struct Chunks(std::collections::VecDeque<Vec<u8>>);

impl AsyncRead for Chunks {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        if let Some(c) = self.0.pop_front() {
            let n = c.len().min(buf.remaining());
            buf.put_slice(&c[..n]);
            if n < c.len() {
                self.0.push_front(c[n..].to_vec());
            }
        }
        std::task::Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn a_long_line_sent_byte_by_byte_completes() {
    // Bytes without a line end are not re-parsed (Rust review M2), so they do not use up the
    // parse budget: 1 000 one-byte reads, then the line end.
    let mut parts = vec![b"CONNECT mock.test:443 HTTP/1.1\r\nX-Pad: ".to_vec()];
    parts.extend((0..1000).map(|_| b"a".to_vec()));
    parts.push(b"\r\n\r\n".to_vec());
    let mut buf = [0u8; MAX_HEAD];
    let filled = read_head(&mut Chunks(parts.into()), &mut buf, HEAD_TIMEOUT).await;
    assert!(filled.is_ok(), "{filled:?}");
}

#[tokio::test]
async fn more_line_ends_than_a_head_can_have_are_too_large() {
    // Blank lines before the request line are skipped by the parser, so without a budget each
    // one-byte line end would re-parse the whole buffer until the timeout. Parse 1 is of the
    // empty buffer, parse k after k - 1 bytes: parse 129 (over the budget) comes at 128 bytes.
    let parts: Vec<Vec<u8>> = (0..=MAX_PARSES).map(|_| b"\n".to_vec()).collect();
    let mut buf = [0u8; MAX_HEAD];
    let got = read_head(&mut Chunks(parts.into()), &mut buf, HEAD_TIMEOUT).await;
    assert_eq!(got, Err((Reason::HeadTooLarge, MAX_PARSES)));
    assert_eq!(MAX_PARSES, 128);
}

#[tokio::test]
async fn a_full_buffer_without_a_line_end_is_too_large() {
    let mut parts = vec![b"CONNECT mock.test:443 HTTP/1.1\r\nX: ".to_vec()];
    parts.extend((0..MAX_HEAD / 64 + 1).map(|_| vec![b'a'; 64]));
    let mut buf = [0u8; MAX_HEAD];
    let got = read_head(&mut Chunks(parts.into()), &mut buf, HEAD_TIMEOUT).await;
    assert_eq!(got, Err((Reason::HeadTooLarge, MAX_HEAD)));
}

#[tokio::test]
async fn garbage_in_a_large_first_read_is_malformed_at_once() {
    let (mut client, mut proxy) = duplex(MAX_HEAD);
    client.write_all(&[0x16; 512]).await.unwrap();
    let mut buf = [0u8; MAX_HEAD];
    let got = read_head(&mut proxy, &mut buf, SHORT).await;
    assert_eq!(got, Err((Reason::Malformed, 512)));
    drop(client);
}

#[tokio::test]
async fn a_head_over_8_kib_is_too_large() {
    let (mut client, mut proxy) = duplex(MAX_HEAD * 2);
    let mut req = b"CONNECT mock.test:443 HTTP/1.1\r\nX: ".to_vec();
    req.resize(MAX_HEAD + 100, b'a');
    client.write_all(&req).await.unwrap();
    let mut buf = [0u8; MAX_HEAD];
    let got = read_head(&mut proxy, &mut buf, HEAD_TIMEOUT).await;
    assert_eq!(got, Err((Reason::HeadTooLarge, MAX_HEAD)));
}

#[tokio::test]
async fn a_silent_or_slow_client_times_out() {
    let (mut client, mut proxy) = duplex(64);
    client
        .write_all(b"CONNECT mock.test:443 HTTP/1.1\r\n")
        .await
        .unwrap();
    let mut buf = [0u8; MAX_HEAD];
    let got = read_head(&mut proxy, &mut buf, SHORT).await;
    assert_eq!(got, Err((Reason::HeadTimeout, 32)));
    drop(client);
}

#[tokio::test]
async fn closing_before_a_complete_head_is_malformed() {
    let (mut client, mut proxy) = duplex(64);
    client
        .write_all(b"CONNECT mock.test:443 HTTP/1.1\r\n")
        .await
        .unwrap();
    drop(client);
    let mut buf = [0u8; MAX_HEAD];
    let got = read_head(&mut proxy, &mut buf, HEAD_TIMEOUT).await;
    assert_eq!(got, Err((Reason::Malformed, 32)));
}

#[tokio::test]
async fn garbage_is_malformed_at_once() {
    let (mut client, mut proxy) = duplex(64);
    client.write_all(b"\x16\x03\x01\x02\x00").await.unwrap();
    let mut buf = [0u8; MAX_HEAD];
    let got = read_head(&mut proxy, &mut buf, HEAD_TIMEOUT).await;
    assert_eq!(got, Err((Reason::Malformed, 5)));
    drop(client);
}
