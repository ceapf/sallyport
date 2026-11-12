//! Red-team rows RT-NET-02 to 07, 09 and 10 (Task 8): every attack runs inside a real workspace
//! container, through the real shim (`127.0.0.1:3128` → `/run/sallyport/net.sock`) to the
//! session's egress listener, which the launcher started with the fake resolver and dialer of
//! `common/egress.rs` (decision 10: the constructor seam production fills with the system ones).
//! Raw requests come from busybox `nc`. Unit tests of the full matrix: `src/egress/*_tests.rs`.
//!
//! IPv4 addresses are assembled at runtime or written as allowlisted values: the repository's
//! guard hooks refuse other dotted literals.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::container::{Lx, SHIM_LOG, exec, net_image, rt};
use common::egress::public;
use sallyd::sandbox::{Running, WorkspaceRequest};
use serde_json::json;

/// `*.mock.test` on 443, `mock.test` itself on 443 only.
const NET: &str = "network:\n  mode: proxy\n  allow:\n    - host: \"*.mock.test\"\n    \
                   - host: mock.test\n";

/// Launches a proxy-mode session on the net image and waits for the shim's readiness line.
async fn session(lx: &Lx, net: &str, tag: &str) -> Running {
    let v = lx.f.load(net);
    let req = WorkspaceRequest {
        paths: lx.paths(tag),
        manifest: Arc::new(v),
        default_image: net_image(),
    };
    let r = lx.launcher.launch_workspace(req).await.expect("launch");
    for _ in 0..100 {
        let (_, log) = exec(&r, &format!("cat {SHIM_LOG} 2>/dev/null")).await;
        if log.contains("sally-shim: listening on 127.0.0.1:3128") {
            return r;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the shim never became ready");
}

/// Sends `req` (printf escapes: `\r\n`) through the shim; returns everything that came back.
async fn via_shim(r: &Running, req: &str) -> String {
    exec(r, &format!("printf '{req}' | nc -w 3 127.0.0.1 3128"))
        .await
        .1
}

/// As [`via_shim`], but keeps the client open a second so tunnelled bytes can come back.
async fn tunnel(r: &Running, req: &str) -> String {
    exec(
        r,
        &format!("(printf '{req}'; sleep 1) | nc -w 2 127.0.0.1 3128"),
    )
    .await
    .1
}

fn connect(target: &str) -> String {
    format!("CONNECT {target} HTTP/1.1\\r\\nHost: {target}\\r\\n\\r\\n")
}

fn status(reply: &str) -> &str {
    reply.get(9..12).unwrap_or_default()
}

/// The `egress.deny` (or `.limit`) entries, oldest first.
fn refusals(lx: &Lx, event: &str) -> Vec<serde_json::Value> {
    lx.events
        .all()
        .into_iter()
        .filter(|(e, _)| e == event)
        .map(|(_, a)| a)
        .collect()
}

#[test]
fn rt_net_02_a_denied_name_is_never_resolved_inside_or_by_the_host() {
    rt().block_on(async {
        let lx = Lx::new();
        let r = session(&lx, NET, "n02").await;
        let canary = format!("c{:x}.attacker.test", std::process::id());
        for cmd in [
            format!("nslookup {canary}"),
            format!("nslookup {canary} 8.8.8.8"),
            format!("getent hosts {canary}"),
        ] {
            let (code, _) = exec(&r, &format!("timeout 10 {cmd}")).await;
            assert_ne!(code, 0, "{cmd} resolved inside the sandbox");
        }
        let got = via_shim(&r, &connect(&format!("{canary}:443"))).await;
        assert_eq!(status(&got), "403", "{got}");
        assert!(got.ends_with("host-not-allowed\n"), "{got}");
        assert!(
            lx.egress.resolver.lookups().is_empty(),
            "the host looked a denied name up"
        );
        assert_eq!(
            refusals(&lx, "egress.deny")[0]["target"],
            json!(format!("{canary}:443"))
        );
        lx.stop(r).await;
    });
}

#[test]
fn rt_net_03_a_host_off_the_list_is_refused_and_the_upstream_sees_nothing() {
    rt().block_on(async {
        let lx = Lx::new();
        let r = session(&lx, NET, "n03").await;
        let tls = via_shim(&r, &connect("example.org:443")).await;
        assert_eq!(status(&tls), "403", "{tls}");
        let plain = via_shim(
            &r,
            "GET http://example.org/ HTTP/1.1\\r\\nHost: example.org\\r\\n\\r\\n",
        )
        .await;
        assert_eq!(status(&plain), "405", "{plain}");
        assert!(plain.contains("plain-http-unsupported"), "{plain}");
        let denied = refusals(&lx, "egress.deny");
        assert_eq!(denied[0]["reason"], json!("host-not-allowed"));
        assert_eq!(denied[0]["target"], json!("example.org:443"));
        assert_eq!(denied[1]["target"], json!("http://example.org/"));
        assert!(lx.egress.dialer.dials().is_empty());
        assert!(lx.egress.resolver.lookups().is_empty());
        lx.stop(r).await;
    });
}

#[test]
fn rt_net_04_an_allowed_host_on_another_port_is_refused() {
    rt().block_on(async {
        let lx = Lx::new();
        let r = session(&lx, NET, "n04").await;
        for target in ["mock.test:22", "mock.test:8443", "a.mock.test:8443"] {
            let got = via_shim(&r, &connect(target)).await;
            assert_eq!(status(&got), "403", "{target}: {got}");
            assert!(got.ends_with("port-not-allowed\n"), "{target}: {got}");
        }
        assert!(lx.egress.resolver.lookups().is_empty());
        lx.stop(r).await;
    });
}

#[test]
fn rt_net_05_only_the_request_target_decides_and_ip_literals_are_refused() {
    rt().block_on(async {
        let lx = Lx::new();
        let r = session(&lx, NET, "n05").await;
        let one = Ipv4Addr::new(1, 1, 1, 1);
        let cases: Vec<(String, &str, &str)> = vec![
            (
                "GET http://evil.test/ HTTP/1.1\\r\\nHost: mock.test\\r\\n\\r\\n".into(),
                "405",
                "http://evil.test/",
            ),
            (
                "GET http://mock.test@evil.test/ HTTP/1.1\\r\\n\\r\\n".into(),
                "405",
                "http://mock.test@evil.test/",
            ),
            (
                "CONNECT evil.test:443 HTTP/1.1\\r\\nHost: mock.test:443\\r\\n\\r\\n".into(),
                "403",
                "evil.test:443",
            ),
            (
                connect("mock.test@evil.test:443"),
                "400",
                "mock.test@evil.test:443",
            ),
            (connect(&format!("{one}:443")), "403", "1.1.1.1:443"),
            (connect("16843009:443"), "403", "16843009:443"),
            (connect("0x01010101:443"), "403", "0x01010101:443"),
            (
                connect(&format!("[::ffff:{one}]:443")),
                "403",
                "[::ffff:1.1.1.1]:443",
            ),
        ];
        for (req, want, _) in &cases {
            let got = via_shim(&r, req).await;
            assert_eq!(status(&got), *want, "{req}: {got}");
            assert!(!got.contains("evil"), "the reply echoes the target: {got}");
        }
        let logged: Vec<serde_json::Value> = refusals(&lx, "egress.deny")
            .iter()
            .map(|a| a["target"].clone())
            .collect();
        let want: Vec<serde_json::Value> = cases.iter().map(|(_, _, t)| json!(t)).collect();
        assert_eq!(logged, want);
        let ip = refusals(&lx, "egress.deny")[4]["reason"].clone();
        assert_eq!(ip, json!("ip-literal"));
        assert!(lx.egress.resolver.lookups().is_empty());
        assert!(lx.egress.dialer.dials().is_empty());
        lx.stop(r).await;
    });
}

#[test]
fn rt_net_06_wildcards_match_whole_labels_after_normalization() {
    rt().block_on(async {
        let lx = Lx::new();
        let net = "network:\n  mode: proxy\n  allow:\n    - host: \"*.mock.test\"\n";
        let r = session(&lx, net, "n06").await;
        lx.egress.resolver.set("a.mock.test", vec![vec![public(1)]]);
        for (target, want) in [
            ("a.mock.test:443", "200"),
            ("A.MOCK.TEST.:443", "200"),
            ("mock.test:443", "403"),
            ("mock.test.evil.test:443", "403"),
            ("xmock.test:443", "403"),
        ] {
            let got = tunnel(&r, &format!("{}ping", connect(target))).await;
            assert_eq!(status(&got), want, "{target}: {got}");
            if want == "200" {
                assert!(got.ends_with("\r\n\r\nping"), "{target}: {got:?}");
            }
        }
        assert_eq!(lx.egress.resolver.lookups(), ["a.mock.test", "a.mock.test"]);
        lx.stop(r).await;
    });
}

#[test]
fn rt_net_07_names_that_resolve_to_internal_or_own_addresses_are_refused() {
    rt().block_on(async {
        let lx = Lx::new();
        let r = session(&lx, NET, "n07").await;
        let names = &lx.egress.resolver;
        names.set("lo.mock.test", vec![vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]]);
        names.set(
            "ten.mock.test",
            vec![vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))]],
        );
        let metadata = IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254));
        names.set("meta.mock.test", vec![vec![metadata]]);
        names.set("v6.mock.test", vec![vec![IpAddr::V6(Ipv6Addr::LOCALHOST)]]);
        names.set(
            "mix.mock.test",
            vec![vec![public(1), IpAddr::V4(Ipv4Addr::LOCALHOST)]],
        );
        // The host's real non-loopback addresses (whatever they are; never printed), and a
        // public one the fake host-address source claims as the host's own.
        let real = sallyd::egress::net::ProcHostAddrs::default();
        let own_real: Vec<IpAddr> = sallyd::egress::server::HostAddrs::own(&real)
            .await
            .unwrap()
            .into_iter()
            .filter(|ip| !ip.is_loopback())
            .collect();
        assert!(!own_real.is_empty(), "the host has no non-loopback address");
        names.set("lan.mock.test", vec![own_real.clone()]);
        lx.egress.host.set([own_real, vec![public(9)]].concat());
        names.set("own.mock.test", vec![vec![public(9)]]);
        for host in ["lo", "ten", "meta", "v6", "mix", "lan", "own"] {
            let got = via_shim(&r, &connect(&format!("{host}.mock.test:443"))).await;
            assert_eq!(status(&got), "403", "{host}");
            assert!(got.ends_with("ip-range-denied\n"), "{host}");
        }
        assert!(lx.egress.dialer.dials().is_empty());
        // Rebinding: public on the first lookup, loopback on the second.
        names.set(
            "rebind.mock.test",
            vec![vec![public(2)], vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]],
        );
        let first = tunnel(&r, &format!("{}ping", connect("rebind.mock.test:443"))).await;
        assert_eq!(status(&first), "200", "{first}");
        let second = via_shim(&r, &connect("rebind.mock.test:443")).await;
        assert_eq!(status(&second), "403", "{second}");
        assert_eq!(lx.egress.dialer.dials(), [SocketAddr::new(public(2), 443)]);
        lx.stop(r).await;
    });
}

#[test]
fn rt_net_09_oversized_heads_slow_clients_and_too_many_connections_are_limited() {
    rt().block_on(async {
        let lx = Lx::new();
        let net = format!("{NET}  max_connections: 2\n");
        let r = session(&lx, &net, "n09").await;
        lx.egress.resolver.set("a.mock.test", vec![vec![public(1)]]);
        // A 100 KiB request line.
        let line = exec(
            &r,
            "(printf 'CONNECT a.mock.test:443'; head -c 102400 /dev/zero | tr '\\0' a; \
             printf ' HTTP/1.1\\r\\n\\r\\n') | nc -w 3 127.0.0.1 3128",
        )
        .await
        .1;
        assert_eq!(status(&line), "431", "{line:?}");
        // 20 MiB of headers: the proxy stops reading at 8 KiB and closes (the reply may be lost
        // to the reset of a client still sending; the audit entry is not).
        let t0 = Instant::now();
        exec(
            &r,
            "(printf 'CONNECT a.mock.test:443 HTTP/1.1\\r\\n'; head -c 20971520 /dev/zero | \
             tr '\\0' a) | nc -w 3 127.0.0.1 3128",
        )
        .await;
        assert!(t0.elapsed() < Duration::from_secs(30));
        let limits = refusals(&lx, "egress.limit");
        assert_eq!(limits.len(), 2, "{limits:?}");
        for l in &limits {
            assert_eq!(l["reason"], json!("head-too-large"));
            assert!(l["head_bytes"].as_u64().unwrap() <= 8192, "{l}");
        }
        // Slowloris: one byte a second is closed at the 10 s head limit, without a reply.
        let t0 = Instant::now();
        let drip = exec(
            &r,
            "(for c in C O N N E C T ' ' a . m o c k . t e s t; do printf \"$c\"; sleep 1; \
             done) | nc 127.0.0.1 3128",
        )
        .await
        .1;
        let took = t0.elapsed();
        assert!(drip.is_empty(), "{drip:?}");
        assert!(took >= Duration::from_secs(9) && took < Duration::from_secs(14), "{took:?}");
        assert_eq!(refusals(&lx, "egress.limit")[2]["reason"], json!("head-timeout"));
        // Two held tunnels fill max_connections: the third is refused at accept.
        let held = exec(
            &r,
            &format!(
                "for i in 1 2; do (printf '{c}'; sleep 6) | nc 127.0.0.1 3128 > /tmp/held$i & done; \
                 sleep 2; printf '{c}' | nc -w 3 127.0.0.1 3128; wait; cat /tmp/held1 /tmp/held2",
                c = connect("a.mock.test:443")
            ),
        )
        .await
        .1;
        assert!(held.starts_with("HTTP/1.1 429 "), "{held}");
        assert_eq!(held.matches("200 Connection Established").count(), 2, "{held}");
        let last = refusals(&lx, "egress.limit");
        assert_eq!(last[3], json!({"reason": "too-many-connections"}));
        lx.stop(r).await;
    });
}

#[test]
fn rt_net_09_a_thousand_connections_leave_the_proxy_bounded() {
    rt().block_on(async { thousand().await });
}

async fn thousand() {
    use rustix::process::{Resource, getrlimit, setrlimit};
    use sallyd::egress::net::{EgressStarter, SessionEgress};
    use sallyd::egress::policy::Policy;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // 1000 client ends and 1000 proxy ends live in this one process.
    let mut lim = getrlimit(Resource::Nofile);
    let need = 4096;
    assert!(
        lim.maximum.is_none_or(|m| m >= need),
        "raise the nofile hard limit to {need}"
    );
    lim.current = Some(need);
    setrlimit(Resource::Nofile, lim).unwrap();
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("rt-net-09-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("net.sock");
    let egress = common::egress::fake_egress();
    egress.resolver.set("a.mock.test", vec![vec![public(1)]]);
    let events = Arc::new(common::container::Events::default());
    let rule = sallyd::egress::policy::Rule {
        host: sally_core::manifest::parse_host_pattern("*.mock.test").unwrap(),
        ports: vec![443],
    };
    let handle = egress
        .start(
            &sock,
            SessionEgress {
                policy: Policy::new(vec![rule], vec![]),
                max_connections: 32,
                session: "rt-net-09".into(),
                level: sally_core::manifest::AuditLevel::default(),
                audit: events.clone(),
            },
        )
        .unwrap();
    let before = rss_kib();
    let mut clients = Vec::new();
    for _ in 0..1000 {
        let mut c = tokio::net::UnixStream::connect(&sock).await.unwrap();
        // A connection over the cap is answered and closed at accept, maybe before this write.
        let _ = c
            .write_all(b"CONNECT a.mock.test:443 HTTP/1.1\r\n\r\n")
            .await;
        clients.push(c);
    }
    let mut ok = 0;
    let mut limited = 0;
    for c in &mut clients {
        let mut head = [0u8; 12];
        c.read_exact(&mut head).await.unwrap();
        match &head[9..12] {
            b"200" => ok += 1,
            b"429" => limited += 1,
            other => panic!("{}", String::from_utf8_lossy(other)),
        }
    }
    let grew = rss_kib().saturating_sub(before);
    assert_eq!((ok, limited), (32, 968));
    assert!(grew < 50 * 1024, "RSS grew {grew} KiB");
    let limits = events
        .list()
        .iter()
        .filter(|e| *e == "egress.limit")
        .count();
    assert_eq!(limits, 968);
    drop(clients);
    handle.shutdown().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

fn rss_kib() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let line = status.lines().find(|l| l.starts_with("VmRSS:")).unwrap();
    line.split_whitespace().nth(1).unwrap().parse().unwrap()
}

#[test]
fn rt_net_10_replacing_the_shim_gains_nothing() {
    rt().block_on(async {
        let lx = Lx::new();
        let r = session(&lx, NET, "n10").await;
        lx.egress.resolver.set("a.mock.test", vec![vec![public(1)]]);
        // Kill the shim and listen on its port: the sandbox can, but its own proxy has no way out.
        let (code, out) = exec(
            &r,
            "pkill -x sally-shim; sleep 0.5; (nc -l -p 3128 > /dev/null &); sleep 0.5; \
             timeout 5 nc -w 2 1.1.1.1 443 < /dev/null; echo direct=$?",
        )
        .await;
        assert_eq!(code, 0, "{out}");
        assert!(!out.contains("direct=0"), "a direct connection succeeded: {out}");
        // Talk to net.sock directly: the shim binary as the attacker's dumb relay (architect Q14).
        let stdio = |req: &str| {
            format!("printf '{req}' | timeout 10 /usr/local/bin/sally-shim --stdio /run/sallyport/net.sock")
        };
        let garbage = exec(&r, &stdio("\\026\\003\\001garbage\\r\\n\\r\\n")).await.1;
        assert_eq!(status(&garbage), "400", "{garbage:?}");
        let denied = exec(&r, &stdio(&connect("evil.test:443"))).await.1;
        assert_eq!(status(&denied), "403", "{denied}");
        let allowed = exec(&r, &format!("(printf '{}ping'; sleep 1) | timeout 10 /usr/local/bin/sally-shim --stdio /run/sallyport/net.sock", connect("a.mock.test:443"))).await.1;
        assert_eq!(status(&allowed), "200", "{allowed}");
        assert!(allowed.ends_with("ping"), "{allowed:?}");
        lx.stop(r).await;
    });
}

#[test]
fn net_sock_exists_only_in_proxy_mode() {
    rt().block_on(async {
        let lx = Lx::new();
        let none = lx.launch(&lx.f.load(""), "nnone").await.unwrap();
        let (_, ls) = exec(&none, "ls /run/sallyport").await;
        assert!(!ls.contains("net.sock"), "{ls}");
        lx.stop(none).await;
        let proxy = session(&lx, NET, "nproxy").await;
        let (_, ls) = exec(&proxy, "ls -l /run/sallyport/net.sock").await;
        assert!(ls.starts_with("srw-------"), "{ls}");
        lx.stop(proxy).await;
    });
}
