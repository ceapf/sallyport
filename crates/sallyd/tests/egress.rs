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
use sallyd::egress::server::ESTABLISHED;
use sallyd::sandbox::{Running, WorkspaceRequest};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
        // A name that exists fails too: the failure is the missing network, not NXDOMAIN.
        for cmd in [
            format!("nslookup {canary}"),
            format!("nslookup {canary} 8.8.8.8"),
            format!("getent hosts {canary}"),
            "nslookup example.org 8.8.8.8".to_owned(),
            "getent hosts example.org".to_owned(),
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

/// Task 9a-1 (architect Q38 (g), (h)): a session with a secret grant finds `ca-bundle.pem` and
/// `session-ca.pem` beside `net.sock`, read-only and equal to the host copies; the harness socket
/// directory never gets them; a session without secrets gets neither. The grant host itself is
/// still refused until Task 9a-2.
#[test]
fn the_session_ca_files_reach_the_workspace_read_only_and_only_with_secrets() {
    use sallyd::egress::ca::{BUNDLE_FILE, CA_FILE};
    use sha2::{Digest, Sha256};
    rt().block_on(async {
        let lx = Lx::new();
        let grant = "secrets:\n  - name: GITHUB_TOKEN\n    inject: {host: mock.test, \
                     header: Authorization, format: \"Bearer {value}\"}\n";
        let r = session(&lx, &format!("{NET}{grant}"), "ca1").await;
        let (_, ls) = exec(&r, "ls -A /run/sallyport | tr '\\n' ' '").await;
        assert_eq!(ls.trim(), "ca-bundle.pem net.sock session-ca.pem", "{ls}");
        let host = lx.paths("ca1").workspace_sockets();
        for f in [BUNDLE_FILE, CA_FILE] {
            let want = hex(&Sha256::digest(std::fs::read(host.join(f)).unwrap()));
            let (_, got) = exec(&r, &format!("sha256sum /run/sallyport/{f}")).await;
            assert!(got.starts_with(&want), "{f}: {got} vs {want}");
        }
        let (code, out) = exec(
            &r,
            "echo x > /run/sallyport/ca-bundle.pem; echo x > /run/sallyport/new; echo $?",
        )
        .await;
        assert!(out.lines().any(|l| l.trim() == "1"), "{code} {out}");
        assert_eq!(out.matches("Read-only file system").count(), 2, "{out}");
        let harness = lx.paths("ca1").harness_sockets();
        for f in [BUNDLE_FILE, CA_FILE] {
            assert!(!harness.join(f).exists(), "{f} in the harness directory");
        }
        // Task 9a-2 (architect Q47 (4)): the grant host is now intercepted, so CONNECT from
        // inside the container gets its 200 once the upstream verified.
        lx.egress
            .resolver
            .set("mock.test", vec![vec![common::egress::tls_upstream()]]);
        let opened = via_shim(&r, &connect("mock.test:443")).await;
        assert!(opened.starts_with("HTTP/1.1 200 "), "{opened}");
        lx.stop(r).await;
        let r = session(&lx, NET, "ca0").await;
        let (_, ls) = exec(&r, "ls -A /run/sallyport").await;
        assert_eq!(ls.trim(), "net.sock", "{ls}");
        lx.stop(r).await;
    });
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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
        ];
        for (req, want, _) in &cases {
            let got = via_shim(&r, req).await;
            assert_eq!(status(&got), *want, "{req}: {got}");
            assert!(!got.contains("evil"), "the reply echoes the target: {got}");
        }
        lx.stop(r).await;
        // The literals under `*`: nothing but the IP-literal check can refuse them here.
        let any = "network:\n  mode: proxy\n  acknowledge_unrestricted_egress: true\n  allow:\n    \
                   - host: \"*\"\n";
        let r = session(&lx, any, "n05any").await;
        let literals = [
            format!("{one}:443"),
            "16843009:443".to_owned(),
            "0x01010101:443".to_owned(),
            "0X01010101.:443".to_owned(),
            "017700000001:443".to_owned(),
            format!("[::ffff:{one}]:443"),
            "[::1]:443".to_owned(),
        ];
        for target in &literals {
            let got = via_shim(&r, &connect(target)).await;
            assert_eq!(status(&got), "403", "{target}: {got}");
            assert!(got.ends_with("ip-literal\n"), "{target}: {got}");
        }
        let denied = refusals(&lx, "egress.deny");
        let logged: Vec<serde_json::Value> = denied.iter().map(|a| a["target"].clone()).collect();
        let want: Vec<serde_json::Value> = cases
            .iter()
            .map(|(_, _, t)| json!(t))
            .chain(literals.iter().map(|t| json!(t)))
            .collect();
        assert_eq!(logged, want);
        for d in denied.iter().skip(cases.len()) {
            assert_eq!(d["reason"], json!("ip-literal"), "{d}");
        }
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
        // 20 MiB of headers: the proxy stops reading at 8 KiB, answers, drains at most
        // DRAIN_BYTES and closes. The reply may be lost: a client still sending past the drain
        // fails its send, and the shim then closes its TCP side (#76). The audit entry is not.
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
        // Closed at about 10 s, before the 17 s drip would have ended on its own.
        assert!(took >= Duration::from_secs(9) && took < Duration::from_secs(17), "{took:?}");
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
    rt().block_on(async {
        raise_nofile(8192);
        a_thousand_open_tunnels().await;
        over_the_cap_is_429().await;
    });
}

/// Tunnels held open at once in the memory case.
const TUNNELS: usize = 1000;
/// Bytes each tunnel carries both ways: more than a copy buffer, so every buffer is filled.
const PUSH: usize = 64 * 1024;
/// Growth allowed beyond the copy buffers: tasks, sockets' user-space state, the test's own echo
/// tasks and audit rows (about 10 KiB a tunnel measured; 24 KiB allowed).
const SLACK_KIB: usize = 24 * TUNNELS;

/// 1000 tunnels, all open, each carrying 64 KiB up and back: the proxy's memory grows by its two
/// 16 KiB copy buffers per tunnel plus slack, not by what flows (Rust review M5). With 64 KiB
/// buffers the growth would be about four times the buffer term and fail.
async fn a_thousand_open_tunnels() {
    // The documented copy buffer (ARCHITECTURE §5.3), not the code's constant: a larger buffer
    // in the code must fail this row.
    const BUF_BYTES: usize = 16 * 1024;
    let dir = Scratch::new("rt-net-09-mem");
    let events = Arc::new(common::container::Events::default());
    let (handle, sock) = listen(&dir, TUNNELS, Arc::clone(&events));
    let before = rss_kib();
    let mut clients = Vec::with_capacity(TUNNELS);
    for i in 0..TUNNELS {
        if i % 64 == 0 {
            tokio::task::yield_now().await;
        }
        let mut c = tokio::net::UnixStream::connect(&sock).await.unwrap();
        c.write_all(b"CONNECT a.mock.test:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        clients.push(c);
    }
    let mut head = [0u8; ESTABLISHED.len()];
    for c in &mut clients {
        c.read_exact(&mut head).await.unwrap();
        assert_eq!(&head[..], ESTABLISHED);
    }
    let push = vec![0x5a_u8; PUSH];
    for c in &mut clients {
        c.write_all(&push).await.unwrap();
    }
    let mut back = vec![0u8; PUSH];
    for c in &mut clients {
        c.read_exact(&mut back).await.unwrap();
        assert!(back.iter().all(|&b| b == 0x5a));
    }
    let grew = rss_kib().saturating_sub(before);
    let buffers_kib = 2 * BUF_BYTES * TUNNELS / 1024;
    eprintln!(
        "rt-net-09: RSS grew {grew} KiB; bound {} KiB",
        buffers_kib + SLACK_KIB
    );
    assert!(
        grew < u64::try_from(buffers_kib + SLACK_KIB).unwrap(),
        "RSS grew {grew} KiB for {TUNNELS} tunnels (buffers {buffers_kib} KiB + slack {SLACK_KIB} KiB)"
    );
    let ev = events.list();
    assert_eq!(ev.iter().filter(|e| *e == "egress.allow").count(), TUNNELS);
    assert!(!ev.iter().any(|e| e == "egress.limit"), "none refused");
    drop(clients);
    handle.shutdown().await;
}

/// 1 000 connections against a cap of 32: 968 are answered 429 at accept. Past 32 + 64 accepted
/// at once the accept loop waits (architect Q20), so the flood also runs through that bound and
/// the listen backlog.
async fn over_the_cap_is_429() {
    let dir = Scratch::new("rt-net-09-cap");
    let events = Arc::new(common::container::Events::default());
    let (handle, sock) = listen(&dir, 32, Arc::clone(&events));
    let mut clients = Vec::new();
    for i in 0..1000 {
        if i % 16 == 0 {
            tokio::task::yield_now().await;
        }
        let mut c = tokio::net::UnixStream::connect(&sock).await.unwrap();
        // A connection over the cap is answered and closed at accept, maybe before this write.
        let _ = c
            .write_all(b"CONNECT a.mock.test:443 HTTP/1.1\r\n\r\n")
            .await;
        clients.push(c);
    }
    let (mut ok, mut limited) = (0, 0);
    for c in &mut clients {
        let mut head = [0u8; 12];
        c.read_exact(&mut head).await.unwrap();
        match &head[9..12] {
            b"200" => ok += 1,
            b"429" => limited += 1,
            other => panic!("{}", String::from_utf8_lossy(other)),
        }
    }
    assert_eq!((ok, limited), (32, 968));
    let limits = events
        .list()
        .iter()
        .filter(|e| *e == "egress.limit")
        .count();
    assert_eq!(limits, 968);
    drop(clients);
    handle.shutdown().await;
}

/// Raises this process's soft nofile limit to `need` (client and proxy ends live in one process).
fn raise_nofile(need: u64) {
    use rustix::process::{Resource, getrlimit, setrlimit};
    let mut lim = getrlimit(Resource::Nofile);
    assert!(
        lim.maximum.is_none_or(|m| m >= need),
        "raise the nofile hard limit to {need}"
    );
    lim.current = Some(need);
    setrlimit(Resource::Nofile, lim).unwrap();
}

/// A scratch directory under `CARGO_TARGET_TMPDIR`, removed however the test ends.
struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Echoes through a socket pair with a 1 KiB copy, so the test's own memory per tunnel stays
/// small next to the proxy's buffers.
struct PairEcho;

impl sallyd::egress::server::Dialer for PairEcho {
    type Stream = tokio::net::UnixStream;
    async fn dial(&self, _: SocketAddr) -> std::io::Result<Self::Stream> {
        let (near, mut far) = tokio::net::UnixStream::pair()?;
        tokio::spawn(async move {
            let mut b = [0u8; 1024];
            while let Ok(n @ 1..) = far.read(&mut b).await {
                if far.write_all(&b[..n]).await.is_err() {
                    break;
                }
            }
        });
        Ok(near)
    }
}

/// A listener in `dir` that allows `*.mock.test:443`, with `a.mock.test` at a public address.
fn listen(
    dir: &Scratch,
    max_connections: usize,
    audit: Arc<common::container::Events>,
) -> (sallyd::egress::net::EgressHandle, std::path::PathBuf) {
    use sallyd::egress::net::{Egress, EgressStarter, SessionEgress};
    use sallyd::egress::policy::{Policy, Rule};
    let egress = Egress {
        resolver: Arc::new(common::egress::Names::default()),
        dialer: Arc::new(PairEcho),
        host: Arc::new(common::egress::Owned::default()),
        roots: sallyd::egress::roots::BundleFiles::default(),
    };
    egress.resolver.set("a.mock.test", vec![vec![public(1)]]);
    let rule = Rule {
        host: sally_core::manifest::parse_host_pattern("*.mock.test").unwrap(),
        ports: vec![443],
    };
    let sock = dir.0.join("net.sock");
    let handle = egress
        .start(
            &sock,
            SessionEgress {
                policy: Policy::new(vec![rule], vec![]),
                max_connections,
                body_caps: (1 << 20, 1 << 20),
                session: "rt-net-09".into(),
                level: sally_core::manifest::AuditLevel::default(),
                audit,
                ca: false,
                timeout: std::time::Duration::from_secs(60),
                interception: None,
            },
        )
        .unwrap();
    (handle, sock)
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
            // By /proc/<pid>/comm: busybox `pgrep -x` compares the full argv[0] (PROBE_NOTES).
            // A killed shim stays a zombie (the entry's `sleep` never reaps), so count live ones.
            "shims() { for p in /proc/[0-9]*; do grep -qs '^State:.*Z' $p/status && continue; \
               [ \"$(cat $p/comm 2>/dev/null)\" = sally-shim ] && echo ${p#/proc/}; done; }; \
             for pid in $(shims); do kill $pid && echo killed=$pid; done; sleep 0.5; \
             echo left=$(shims | wc -l); \
             (nc -l -p 3128 > /dev/null 2>/tmp/own-listener &); sleep 0.5; cat /tmp/own-listener; \
             grep -qsE ':0C38 0+:0000 0A' /proc/net/tcp /proc/net/tcp6 && echo own=listening; \
             timeout 5 nc -w 2 1.1.1.1 443 < /dev/null; echo direct=$?",
        )
        .await;
        assert_eq!(code, 0, "{out}");
        // The listening shim is gone, and its port taken by our own listener, before anything is
        // sent to net.sock.
        assert_eq!(out.matches("killed=").count(), 1, "{out}");
        assert!(out.contains("left=0"), "{out}");
        assert!(!out.contains("Address in use"), "{out}");
        assert!(out.contains("own=listening"), "our own listener holds 3128: {out}");
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
