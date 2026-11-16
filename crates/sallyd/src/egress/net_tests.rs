//! Tests of the session listener, the resolver, the dialer and the host's own addresses.
use super::*;
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn the_hosts_own_addresses_include_loopback() {
    let own = ProcHostAddrs::default().own().await.unwrap();
    assert!(
        own.contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)),
        "{} addresses",
        own.len()
    );
}

#[tokio::test]
async fn unreadable_or_oversized_proc_files_fail_and_a_missing_inet6_is_none() {
    let dir = scratch("proc");
    let fib = dir.join("fib");
    let lo = Ipv4Addr::LOCALHOST;
    std::fs::write(&fib, format!("|-- {lo}\n   /32 host LOCAL\n")).unwrap();
    let p = |f: &Path, v6: &Path| ProcHostAddrs {
        fib_trie: f.to_owned(),
        if_inet6: v6.to_owned(),
    };
    let missing = dir.join("missing");
    assert_eq!(p(&fib, &missing).read().unwrap(), vec![IpAddr::V4(lo)]);
    assert!(p(&missing, &missing).read().is_err());
    assert!(p(&fib, &dir).read().is_err(), "a directory is not NotFound");
    let big = dir.join("big");
    let mut body = format!("|-- {lo}\n   /32 host LOCAL\n");
    body.push_str(&" ".repeat(usize::try_from(MAX_PROC_BYTES).unwrap()));
    std::fs::write(&big, body).unwrap();
    assert!(p(&big, &missing).read().is_err());
    let exact = dir.join("exact");
    let mut body = format!("|-- {lo}\n   /32 host LOCAL\n");
    let pad = usize::try_from(MAX_PROC_BYTES).unwrap() - body.len();
    body.push_str(&" ".repeat(pad));
    std::fs::write(&exact, body).unwrap();
    assert!(p(&exact, &missing).read().is_ok());
    assert_eq!(MAX_PROC_BYTES, 1 << 20, "the documented 1 MiB");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn the_dialer_connects_to_a_loopback_listener_and_reports_refusal() {
    // Test-only listener on an ephemeral loopback port (architect Q16).
    let l = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let addr = l.local_addr().unwrap();
    let accept = tokio::spawn(async move { l.accept().await.unwrap().0 });
    let mut s = TcpDialer.dial(addr).await.unwrap();
    assert!(s.nodelay().unwrap());
    let mut peer = accept.await.unwrap();
    s.write_all(b"x").await.unwrap();
    let mut b = [0u8; 1];
    peer.read_exact(&mut b).await.unwrap();
    drop((s, peer));
    let closed = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port());
    assert!(TcpDialer.dial(closed).await.is_err());
}

#[test]
fn getaddrinfo_answers_localhost_from_the_hosts_file() {
    // Hermetic: glibc answers the relative name `localhost` from /etc/hosts ("files" comes
    // first). The absolute `localhost.` is not matched there and would go to DNS, so this test
    // never asks for it (docs/dev/PROBE_NOTES.md).
    // Fail loudly rather than send a query where that does not hold.
    let nss = std::fs::read_to_string("/etc/nsswitch.conf").unwrap_or_default();
    let hosts_line = nss.lines().find(|l| l.trim_start().starts_with("hosts:"));
    let first = hosts_line.and_then(|l| l.split_whitespace().nth(1));
    assert_eq!(first, Some("files"), "nsswitch hosts must list files first");
    let hosts = std::fs::read_to_string("/etc/hosts").unwrap();
    assert!(
        hosts.lines().any(|l| {
            let l = l.split('#').next().unwrap_or_default();
            l.split_whitespace().skip(1).any(|n| n == "localhost")
        }),
        "/etc/hosts must name localhost"
    );
    let got = getaddrinfo("localhost", 443).unwrap();
    assert!(!got.is_empty());
    assert!(
        got.iter().all(|a| a.ip().is_loopback() && a.port() == 443),
        "{got:?}"
    );
}

#[test]
fn names_are_looked_up_absolute() {
    assert_eq!(absolute("a.mock.test"), "a.mock.test.");
}

/// Opens its gate on drop.
struct Opener(Arc<Gate>);
impl Drop for Opener {
    fn drop(&mut self) {
        self.0.release();
    }
}

/// A blocking-call seam: counts entries and holds each call until opened.
#[derive(Default)]
struct Gate {
    open: std::sync::Mutex<bool>,
    cv: std::sync::Condvar,
    entered: std::sync::atomic::AtomicUsize,
}

impl Gate {
    fn pass(&self) {
        self.entered
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let open = self.open.lock().unwrap();
        drop(self.cv.wait_while(open, |o| !*o).unwrap());
    }
    fn release(&self) {
        *self.open.lock().unwrap() = true;
        self.cv.notify_all();
    }
    /// A gate that opens when the returned guard drops, so a failing assertion releases the
    /// parked blocking threads instead of hanging the runtime's shutdown (Rust re-review M1).
    fn shut() -> (Arc<Self>, Opener) {
        let g = Arc::new(Self::default());
        (Arc::clone(&g), Opener(g))
    }
    fn entered(&self) -> usize {
        self.entered.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Polls `f` every 10 ms for up to 10 s.
async fn until(what: &str, f: impl Fn() -> bool) {
    for _ in 0..1000 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {what}");
}

fn public(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 215, 1)), port)
}

/// A resolver over a seam that waits at `gate` (if any) and answers [`public`].
fn gated(
    slots: usize,
    gate: Option<Arc<Gate>>,
    names: Arc<std::sync::Mutex<Vec<String>>>,
) -> SystemResolver {
    SystemResolver::new(
        Arc::new(Semaphore::new(slots)),
        Arc::new(move |name: &str, port| {
            names.lock().unwrap().push(format!("{name}:{port}"));
            if let Some(g) = &gate {
                g.pass();
            }
            Ok(vec![public(port)])
        }),
    )
}

#[tokio::test]
async fn the_resolver_looks_up_the_absolute_name_in_a_slot() {
    let names = Arc::default();
    let r = gated(1, None, Arc::clone(&names));
    assert_eq!(r.resolve("a.mock.test", 443).await.unwrap(), [public(443)]);
    assert_eq!(*names.lock().unwrap(), ["a.mock.test.:443"]);
    assert_eq!(r.slots.available_permits(), 1, "the slot is returned");
    assert!(format!("{r:?}").contains("free_slots: 1"));
    assert_eq!(
        SystemResolver::default().slots.available_permits(),
        MAX_LOOKUPS
    );
    assert_eq!(MAX_LOOKUPS, 64);
}

#[tokio::test]
async fn with_no_free_slot_a_lookup_fails_at_once_without_a_call() {
    let names = Arc::default();
    let r = gated(0, None, Arc::clone(&names));
    let got = tokio::time::timeout(Duration::from_secs(1), r.resolve("a.mock.test", 443))
        .await
        .expect("fails at once, never queues");
    assert_eq!(got.unwrap_err().kind(), io::ErrorKind::WouldBlock);
    assert!(names.lock().unwrap().is_empty(), "nothing was spawned");
}

#[tokio::test]
async fn a_slot_stays_taken_until_the_lookup_returns_even_after_a_timeout() {
    let (gate, _open) = Gate::shut();
    let r = gated(2, Some(Arc::clone(&gate)), Arc::default());
    let gave_up =
        tokio::time::timeout(Duration::from_millis(50), r.resolve("a.mock.test", 443)).await;
    assert!(gave_up.is_err(), "the caller timed out");
    until("the lookup to start", || gate.entered() == 1).await;
    assert_eq!(
        r.slots.available_permits(),
        1,
        "still held by the stuck call"
    );
    gate.release();
    until("the slot to come back", || r.slots.available_permits() == 2).await;
}

#[tokio::test]
async fn audit_entries_are_written_while_every_lookup_slot_is_stuck() {
    let (gate, _open) = Gate::shut();
    let resolver = Arc::new(gated(MAX_LOOKUPS, Some(Arc::clone(&gate)), Arc::default()));
    let stuck: Vec<_> = (0..MAX_LOOKUPS)
        .map(|_| {
            let r = Arc::clone(&resolver);
            tokio::spawn(async move { r.resolve("slow.mock.test", 443).await })
        })
        .collect();
    until("every slot to be stuck", || gate.entered() == MAX_LOOKUPS).await;
    let dir = scratch("stuck");
    let sock = dir.join("net.sock");
    let audit = Arc::new(Ends::default());
    let handle = start(Arc::clone(&resolver), Arc::clone(&audit), 4, &sock);
    let got = tokio::time::timeout(Duration::from_secs(5), async {
        (
            exchange(&sock, "a.mock.test:443").await,
            exchange(&sock, "evil.test:443").await,
        )
    })
    .await
    .expect("refusals are audited and answered while lookups hang");
    assert!(got.0.starts_with("HTTP/1.1 502 "), "{}", got.0);
    assert!(got.1.starts_with("HTTP/1.1 403 "), "{}", got.1);
    assert_eq!(
        audit.rows(),
        ["egress.deny resolve-failed", "egress.deny host-not-allowed"]
    );
    assert_eq!(gate.entered(), MAX_LOOKUPS, "no 65th lookup was made");
    gate.release();
    for t in stuck {
        assert_eq!(t.await.unwrap().unwrap(), [public(443)]);
    }
    handle.shutdown().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn past_the_in_flight_bound_nothing_more_is_accepted_until_one_ends() {
    let dir = scratch("inflight");
    let sock = dir.join("net.sock");
    let (gate, _open) = Gate::shut();
    let audit = Arc::new(Ends {
        gate: Some(Arc::clone(&gate)),
        ..Ends::default()
    });
    // Cap 0: every connection is a 429 whose audit append waits at the gate, holding its
    // in-flight slot. The bound is 0 + 64.
    let handle = start(Arc::new(OnePublic), Arc::clone(&audit), 0, &sock);
    let bound = Limits::new(0).in_flight();
    let mut clients = Vec::new();
    for _ in 0..=bound {
        clients.push(UnixStream::connect(&sock).await.unwrap());
    }
    until("the bound to fill", || gate.entered() == bound).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(gate.entered(), bound, "connection bound+1 is not accepted");
    gate.release();
    until("the last one to be served", || {
        audit.rows().len() == bound + 1
    })
    .await;
    assert!(
        audit
            .rows()
            .iter()
            .all(|r| r == "egress.limit too-many-connections")
    );
    handle.shutdown().await;
    drop(clients);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn dropping_the_handle_aborts_every_connection() {
    let dir = scratch("drop");
    let sock = dir.join("net.sock");
    let audit = Arc::new(Ends::default());
    let handle = start(Arc::new(OnePublic), Arc::clone(&audit), 4, &sock);
    let mut open = UnixStream::connect(&sock).await.unwrap();
    open.write_all(b"CONNECT a.mock.test:443 HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    let mut ok = vec![0u8; super::super::server::ESTABLISHED.len()];
    open.read_exact(&mut ok).await.unwrap();
    drop(handle);
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), open.read_to_end(&mut rest))
        .await
        .expect("the tunnel was aborted")
        .unwrap();
    assert!(rest.is_empty());
    until("the listener to go", || {
        std::os::unix::net::UnixStream::connect(&sock).is_err()
    })
    .await;
    // The proxy and every connection task hold the sink: once they are gone, a graceful
    // stop (what a dropped handle without the abort gets) would have written its close.
    until("the proxy to go", || Arc::strong_count(&audit) == 1).await;
    assert_eq!(audit.rows(), ["egress.allow "], "aborted: no close entry");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Architect rulings Q1 and Q7: a connector's connections are served by the session's accept
/// loop like accepted ones, every entry of theirs carries the origin and no other does, and a
/// stop ends them with their close entry; afterwards the connector is refused.
#[tokio::test]
async fn a_connectors_connections_are_served_tagged_and_stop_with_the_session() {
    let dir = scratch("local");
    let sock = dir.join("net.sock");
    assert!(
        start(Arc::new(OnePublic), Arc::default(), 4, &sock)
            .connector()
            .is_none(),
        "no fetch, no connector"
    );
    std::fs::remove_file(&sock).unwrap();
    let audit = Arc::new(Ends::default());
    let roots = super::super::roots::Roots {
        store: Arc::new(rustls::RootCertStore::empty()),
        pem: String::new(),
        skipped: 0,
        path: "/test-roots.pem".into(),
    };
    let handle = start_with(
        Arc::new(OnePublic),
        Arc::clone(&audit),
        4,
        &sock,
        Some(roots),
    );
    let c = handle.connector().unwrap();
    let origin = || serde_json::json!({"tool": "fetch", "call": 1});
    let mut denied = c.open(origin()).unwrap();
    denied
        .write_all(b"CONNECT evil.test:443 HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    let mut out = String::new();
    denied.read_to_string(&mut out).await.unwrap();
    assert!(out.starts_with("HTTP/1.1 403 "), "{out}");
    assert!(
        exchange(&sock, "evil.test:443")
            .await
            .starts_with("HTTP/1.1 403 ")
    );
    let mut open = c.open(origin()).unwrap();
    open.write_all(b"CONNECT a.mock.test:443 HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    let mut ok = vec![0u8; super::super::server::ESTABLISHED.len()];
    open.read_exact(&mut ok).await.unwrap();
    handle.shutdown().await;
    let tag = r#" origin={"call":1,"tool":"fetch"}"#;
    assert_eq!(
        audit.rows(),
        [
            format!("egress.deny host-not-allowed{tag}"),
            "egress.deny host-not-allowed".to_owned(),
            format!("egress.allow {tag}"),
            format!("egress.close session-stopped{tag}"),
        ]
    );
    let refused = c.open(origin()).unwrap_err();
    assert_eq!(refused.kind(), io::ErrorKind::BrokenPipe);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Rust review M2 / security review L2: with one in-flight slot left, a queued
/// broker-originated connection gets it; no slot is held back for an `accept` that waits.
#[tokio::test]
async fn the_last_free_slot_serves_a_queued_connector_connection() {
    let dir = scratch("lastslot");
    let sock = dir.join("net.sock");
    let (gate, _open) = Gate::shut();
    let audit = Arc::new(Ends {
        gate: Some(Arc::clone(&gate)),
        ..Ends::default()
    });
    let roots = super::super::roots::Roots {
        store: Arc::new(rustls::RootCertStore::empty()),
        pem: String::new(),
        skipped: 0,
        path: "/test-roots.pem".into(),
    };
    // Cap 0: each connection is a 429 whose append waits at the gate, holding its slot.
    let handle = start_with(
        Arc::new(OnePublic),
        Arc::clone(&audit),
        0,
        &sock,
        Some(roots),
    );
    let bound = Limits::new(0).in_flight();
    let mut clients = Vec::new();
    for _ in 1..bound {
        clients.push(UnixStream::connect(&sock).await.unwrap());
    }
    until("all but one slot to fill", || gate.entered() == bound - 1).await;
    let local = handle
        .connector()
        .unwrap()
        .open(serde_json::json!({"call": 1}))
        .unwrap();
    until("the connector's connection to be served", || {
        gate.entered() == bound
    })
    .await;
    gate.release();
    until("every entry", || audit.rows().len() == bound).await;
    assert!(audit.rows().iter().any(|r| r.contains("origin=")));
    handle.shutdown().await;
    drop((clients, local));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Security re-review L (#75 part 2): a connector connection still queued for a slot when
/// the handle is dropped (the abort path) is never served: its stream reads its end, it
/// never reaches an entry, and the connector is refused from then on.
#[tokio::test]
async fn dropping_the_handle_ends_a_queued_connector_connection_unserved() {
    let dir = scratch("dropq");
    let sock = dir.join("net.sock");
    let (gate, _open) = Gate::shut();
    let audit = Arc::new(Ends {
        gate: Some(Arc::clone(&gate)),
        ..Ends::default()
    });
    let roots = super::super::roots::Roots {
        store: Arc::new(rustls::RootCertStore::empty()),
        pem: String::new(),
        skipped: 0,
        path: "/test-roots.pem".into(),
    };
    // Cap 0: each connection is a 429 whose append waits at the gate, holding its slot.
    let handle = start_with(
        Arc::new(OnePublic),
        Arc::clone(&audit),
        0,
        &sock,
        Some(roots),
    );
    let bound = Limits::new(0).in_flight();
    let mut clients = Vec::new();
    for _ in 0..bound {
        clients.push(UnixStream::connect(&sock).await.unwrap());
    }
    until("every slot to fill", || gate.entered() == bound).await;
    let c = handle.connector().unwrap();
    let mut queued = c.open(serde_json::json!({"call": 1})).unwrap();
    drop(handle);
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), queued.read_to_end(&mut rest))
        .await
        .expect("the queued connection outlived the handle")
        .unwrap();
    assert!(rest.is_empty(), "{rest:?}");
    assert_eq!(gate.entered(), bound, "the queued connection was served");
    let refused = c.open(serde_json::json!({"call": 2})).unwrap_err();
    assert_eq!(refused.kind(), io::ErrorKind::BrokenPipe);
    gate.release();
    assert!(!audit.rows().iter().any(|r| r.contains("origin=")));
    drop(clients);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Starts a listener at `sock` that allows `a.mock.test:443` only.
fn start<R: Resolver>(
    resolver: Arc<R>,
    audit: Arc<Ends>,
    max_connections: usize,
    sock: &Path,
) -> EgressHandle {
    start_with(resolver, audit, max_connections, sock, None)
}

/// [`start`]; with `roots`, a session that grants `fetch`.
fn start_with<R: Resolver>(
    resolver: Arc<R>,
    audit: Arc<Ends>,
    max_connections: usize,
    sock: &Path,
    roots: Option<super::super::roots::Roots>,
) -> EgressHandle {
    use sally_core::manifest::parse_host_pattern;
    let starter = Egress {
        resolver,
        dialer: Arc::new(Echo),
        host: Arc::new(NoneOwned),
        roots: BundleFiles::default(),
        secrets: Arc::new(crate::egress::inject::testing::Fixed::default()),
    };
    let rule = super::super::policy::Rule {
        host: parse_host_pattern("a.mock.test").unwrap(),
        ports: vec![443],
    };
    starter
        .start(
            sock,
            SessionEgress {
                policy: Policy::new(vec![rule], vec![]),
                max_connections,
                body_caps: (1 << 20, 1 << 20),
                session: "s-1".into(),
                level: AuditLevel::default(),
                audit: audit as Arc<dyn AuditSink>,
                ca: false,
                timeout: Duration::from_secs(60),
                grants: Vec::new(),
                interception: None,
                fetch: roots.is_some(),
                roots,
            },
        )
        .unwrap()
}

/// Sends a CONNECT to `target` and reads the whole answer.
async fn exchange(sock: &Path, target: &str) -> String {
    let mut s = UnixStream::connect(sock).await.unwrap();
    s.write_all(format!("CONNECT {target} HTTP/1.1\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    out
}

#[test]
fn bind_makes_an_owner_only_socket() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let dir = scratch("bind");
    let sock = dir.join("net.sock");
    let _l = rt.block_on(async { bind(&sock) }).unwrap();
    let mode = std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    assert!(
        rt.block_on(async { bind(&sock) }).is_err(),
        "an existing path is refused"
    );
    let deep = dir.join("d".repeat(120));
    std::fs::create_dir_all(&deep).unwrap();
    let long = deep.join("net.sock");
    assert!(long.as_os_str().len() > 108);
    let _l2 = rt.block_on(async { bind(&long) }).unwrap();
    let ft = std::fs::metadata(&long).unwrap().file_type();
    assert!(std::os::unix::fs::FileTypeExt::is_socket(&ft));
    assert!(rt.block_on(async { bind(Path::new("/")) }).is_err());
    // The link points at an empty directory, so following it would succeed.
    let target = dir.join("target");
    std::fs::create_dir(&target).unwrap();
    let link = dir.join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(
        rt.block_on(async { bind(&link.join("net.sock")) }).is_err(),
        "a symlinked parent is refused"
    );
    assert!(!target.join("net.sock").exists());
    // Write and search but no read: an O_PATH open works where a plain O_RDONLY one would
    // fail with EACCES (root ignores the mode, so the check needs a non-root user).
    if !rustix::process::geteuid().is_root() {
        let wx = dir.join("wx");
        std::fs::create_dir(&wx).unwrap();
        std::fs::set_permissions(&wx, std::fs::Permissions::from_mode(0o300)).unwrap();
        let got = rt.block_on(async { bind(&wx.join("net.sock")) });
        std::fs::set_permissions(&wx, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(got.is_ok(), "a parent without read permission: {got:?}");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

struct OnePublic;
impl Resolver for OnePublic {
    async fn resolve(&self, _: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        Ok(vec![SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(93, 184, 215, 1)),
            port,
        )])
    }
}
struct Echo;
impl Dialer for Echo {
    type Stream = tokio::io::DuplexStream;
    async fn dial(&self, _: SocketAddr) -> io::Result<Self::Stream> {
        let (near, mut far) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            let (mut r, mut w) = tokio::io::split(&mut far);
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });
        Ok(near)
    }
}
struct NoneOwned;
impl HostAddrs for NoneOwned {
    async fn own(&self) -> io::Result<Vec<IpAddr>> {
        Ok(vec![])
    }
}
/// Records "event end-or-reason" per entry; with a gate, each append waits there first.
#[derive(Default)]
struct Ends {
    rows: std::sync::Mutex<Vec<String>>,
    gate: Option<Arc<Gate>>,
}
impl Ends {
    fn rows(&self) -> Vec<String> {
        self.rows.lock().unwrap().clone()
    }
}
impl AuditSink for Ends {
    fn append(
        &self,
        e: sally_core::audit::NewEntry,
        _: AuditLevel,
    ) -> Result<(), sally_core::audit::AuditError> {
        if let Some(g) = &self.gate {
            g.pass();
        }
        let a = e.arguments();
        let why = a["end"]
            .as_str()
            .or(a["reason"].as_str())
            .unwrap_or_default();
        let origin = a
            .get("origin")
            .map_or_else(String::new, |o| format!(" origin={o}"));
        self.rows
            .lock()
            .unwrap()
            .push(format!("{} {why}{origin}", e.event()));
        Ok(())
    }
}

#[tokio::test]
async fn the_listener_serves_each_connection_and_stops_in_order() {
    let dir = scratch("serve");
    let sock = dir.join("net.sock");
    let audit = Arc::new(Ends::default());
    let handle = start(Arc::new(OnePublic), Arc::clone(&audit), 4, &sock);
    let mut denied = tokio::net::UnixStream::connect(&sock).await.unwrap();
    denied
        .write_all(b"CONNECT evil.test:443 HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    let mut out = String::new();
    denied.read_to_string(&mut out).await.unwrap();
    assert!(out.starts_with("HTTP/1.1 403 "), "{out}");
    let mut open = tokio::net::UnixStream::connect(&sock).await.unwrap();
    open.write_all(b"CONNECT a.mock.test:443 HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    let mut ok = vec![0u8; super::super::server::ESTABLISHED.len()];
    open.read_exact(&mut ok).await.unwrap();
    handle.shutdown().await;
    assert_eq!(
        audit.rows(),
        [
            "egress.deny host-not-allowed",
            "egress.allow ",
            "egress.close session-stopped"
        ]
    );
    let mut rest = Vec::new();
    open.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty());
    assert!(tokio::net::UnixStream::connect(&sock).await.is_err());
    std::fs::remove_dir_all(&dir).unwrap();
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sallyd-net-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
