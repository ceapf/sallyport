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
    let clients = connect_paced(&sock, bound + 1).await;
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

/// RT-AUD-02, `net.sock` leg: a flood of connections cannot grow the audit log
/// faster than the admission rate. Each session admits [`ADMISSION_BURST`] connections back to
/// back and [`ADMISSION_RATE`] per second after; the rest are closed unread, without an entry
/// each, and one `egress.shed` per [`SHED_INTERVAL`] says how many.
#[tokio::test(start_paused = true)]
async fn rt_aud_02_a_connection_flood_on_net_sock_is_closed_and_counted() {
    use super::super::server::{ADMISSION_BURST, ADMISSION_RATE};
    let dir = scratch("flood");
    let sock = dir.join("net.sock");
    let audit = Arc::new(Ends::default());
    let frozen = freeze();
    let handle = start(Arc::new(OnePublic), Arc::clone(&audit), 32, &sock);
    let refused = "evil.test:443";

    let out = bounded("the control", exchange(&sock, refused)).await;
    assert!(
        out.starts_with("HTTP/1.1 403 "),
        "control: a refused CONNECT within the rate is answered: {out}"
    );
    assert_eq!(
        audit.rows(),
        ["egress.deny host-not-allowed"],
        "control: and has its entry"
    );
    // The control took one slot of the burst; one second at the rate gives it back.
    tokio::time::advance(Duration::from_secs(1)).await;

    let started = tokio::time::Instant::now();
    let before = audit.rows().len();
    let (mut answered, mut closed) = (0usize, 0usize);
    for _ in 0..1000 {
        match flood_exchange(&sock, refused).await {
            Some(out) if out.starts_with("HTTP/1.1 403 ") => answered += 1,
            None => closed += 1,
            Some(out) => panic!("neither a 403 nor closed unread: {out:?}"),
        }
        let rows = audit.rows().len() - before;
        let elapsed = started.elapsed().as_secs_f64();
        let bound = f64::from(ADMISSION_BURST) + f64::from(ADMISSION_RATE) * elapsed;
        assert!(rows as f64 <= bound, "{rows} entries after {elapsed} s");
    }
    assert_eq!(started.elapsed(), Duration::ZERO, "the clock stood still");
    assert_eq!(answered, ADMISSION_BURST as usize, "the burst is answered");
    let rows = audit.rows();
    let new = rows.get(before..).unwrap();
    assert_eq!(new.len(), answered, "one entry per answered connection");
    assert!(
        new.iter().all(|r| r == "egress.deny host-not-allowed"),
        "no entry per closed connection, no count yet: {new:?}"
    );

    tokio::time::advance(SHED_INTERVAL).await;
    let shed = format!("egress.shed rate closed={closed} window_ms=1000");
    settle("the count entry", || audit.rows().len() > before + answered).await;
    assert_eq!(audit.rows().get(before + answered..).unwrap(), [shed]);
    assert_eq!(answered + closed, 1000);

    let out = bounded("the exchange after", exchange(&sock, refused)).await;
    assert!(
        out.starts_with("HTTP/1.1 403 "),
        "closing is not a latch: {out}"
    );
    frozen.thaw().await;
    handle.shutdown().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

/// No connection closed, no `egress.shed`: not per interval, not at the stop.
#[tokio::test(start_paused = true)]
async fn within_the_rate_nothing_is_counted() {
    use super::super::server::ADMISSION_BURST;
    let dir = scratch("noshed");
    let sock = dir.join("net.sock");
    let audit = Arc::new(Ends::default());
    let frozen = freeze();
    let handle = start(Arc::new(OnePublic), Arc::clone(&audit), 32, &sock);
    let burst = ADMISSION_BURST as usize;
    assert_eq!(flood(&sock, burst).await, (burst, 0));
    tokio::time::advance(SHED_INTERVAL * 2).await;
    frozen.thaw().await;
    handle.shutdown().await;
    let rows = audit.rows();
    assert_eq!(rows.len(), burst);
    assert!(
        rows.iter().all(|r| r == "egress.deny host-not-allowed"),
        "{rows:?}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A stop in the middle of an interval writes its count, with the window so far.
#[tokio::test(start_paused = true)]
async fn a_stop_writes_the_count_of_an_unfinished_interval() {
    use super::super::server::ADMISSION_BURST;
    let dir = scratch("stopshed");
    let sock = dir.join("net.sock");
    let audit = Arc::new(Ends::default());
    let frozen = freeze();
    let handle = start(Arc::new(OnePublic), Arc::clone(&audit), 32, &sock);
    let burst = ADMISSION_BURST as usize;
    assert_eq!(flood(&sock, burst + 5).await, (burst, 5));
    tokio::time::advance(Duration::from_millis(300)).await;
    // Still frozen, so the window is exact; bounded in real time instead.
    bounded("the stop", handle.shutdown()).await;
    frozen.thaw().await;
    assert_eq!(
        audit.rows().last().map(String::as_str),
        Some("egress.shed rate closed=5 window_ms=300")
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A count whose entry could not be written is kept, window and all, and goes into the next
/// entry one interval later.
#[tokio::test(start_paused = true)]
async fn a_failed_count_entry_carries_its_count_into_the_next() {
    use super::super::server::{ADMISSION_BURST, ADMISSION_RATE};
    use std::sync::atomic::Ordering::SeqCst;
    let dir = scratch("failshed");
    let sock = dir.join("net.sock");
    let audit = Arc::new(Ends {
        fail_sheds: 1.into(),
        ..Ends::default()
    });
    let frozen = freeze();
    let handle = start(Arc::new(OnePublic), Arc::clone(&audit), 32, &sock);
    let (burst, rate) = (ADMISSION_BURST as usize, ADMISSION_RATE as usize);
    assert_eq!(flood(&sock, burst + 5).await, (burst, 5));
    tokio::time::advance(SHED_INTERVAL).await;
    settle("the first try", || audit.shed_tries.load(SeqCst) == 1).await;
    assert!(!audit.rows().iter().any(|r| r.starts_with("egress.shed")));
    // One interval gave the rate back: `rate` more are answered, 5 more closed.
    assert_eq!(flood(&sock, rate + 5).await, (rate, 5));
    tokio::time::advance(SHED_INTERVAL).await;
    settle("the second try", || audit.shed_tries.load(SeqCst) == 2).await;
    assert_eq!(
        audit.rows().last().map(String::as_str),
        Some("egress.shed rate closed=10 window_ms=2000")
    );
    frozen.thaw().await;
    handle.shutdown().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Broker-originated connections never cross `net.sock`; with the session's
/// burst spent they are still served, and they are not in the count.
#[tokio::test(start_paused = true)]
async fn a_connectors_connections_are_served_and_uncounted_while_the_rate_is_spent() {
    use super::super::server::ADMISSION_BURST;
    let dir = scratch("localshed");
    let sock = dir.join("net.sock");
    let audit = Arc::new(Ends::default());
    let frozen = freeze();
    let roots = super::super::roots::Roots {
        store: Arc::new(rustls::RootCertStore::empty()),
        pem: String::new(),
        skipped: 0,
        path: "/test-roots.pem".into(),
    };
    let handle = start_with(
        Arc::new(OnePublic),
        Arc::clone(&audit),
        32,
        &sock,
        Some(roots),
    );
    let burst = ADMISSION_BURST as usize;
    assert_eq!(flood(&sock, burst + 3).await, (burst, 3));
    let mut local = handle
        .connector()
        .unwrap()
        .open(serde_json::json!({"call": 1}))
        .unwrap();
    let out = bounded("the connector's exchange", async {
        local
            .write_all(b"CONNECT evil.test:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let mut out = String::new();
        local.read_to_string(&mut out).await.unwrap();
        out
    })
    .await;
    assert!(out.starts_with("HTTP/1.1 403 "), "served: {out}");
    tokio::time::advance(SHED_INTERVAL).await;
    settle("the count entry", || {
        audit.rows().iter().any(|r| r.starts_with("egress.shed"))
    })
    .await;
    let rows = audit.rows();
    assert_eq!(
        rows.iter().filter(|r| r.contains("origin=")).count(),
        1,
        "{rows:?}"
    );
    assert_eq!(
        rows.last().map(String::as_str),
        Some("egress.shed rate closed=3 window_ms=1000")
    );
    frozen.thaw().await;
    handle.shutdown().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The count's timer comes before accepting: with connections waiting on the listener when the
/// interval ends, its entry counts the closes of that interval, not the waiting ones.
#[tokio::test(start_paused = true)]
async fn the_count_is_written_before_waiting_connections_are_accepted() {
    use super::super::server::ADMISSION_BURST;
    let dir = scratch("shedfirst");
    let sock = dir.join("net.sock");
    let audit = Arc::new(Ends::default());
    let frozen = freeze();
    let handle = start(Arc::new(OnePublic), Arc::clone(&audit), 32, &sock);
    let burst = ADMISSION_BURST as usize;
    assert_eq!(flood(&sock, burst + 10).await, (burst, 10));
    // Queued without yielding, so the accept loop sees them only once the interval has ended:
    // that second gives back 20 connections, and the other 40 would be closed.
    let waiting: Vec<_> = (0..60)
        .map(|_| std::os::unix::net::UnixStream::connect(&sock).unwrap())
        .collect();
    tokio::time::advance(SHED_INTERVAL).await;
    let shed = || {
        audit
            .rows()
            .into_iter()
            .find(|r| r.starts_with("egress.shed"))
    };
    settle("the count entry", || shed().is_some()).await;
    assert_eq!(
        shed().as_deref(),
        Some("egress.shed rate closed=10 window_ms=1000"),
        "the interval's closes, before any waiting connection"
    );
    frozen.thaw().await;
    handle.shutdown().await;
    drop(waiting);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The rate comes before the 429: a flood against a full cap is answered 429, each with its
/// entry, only within the burst; the rest is closed unread and counted.
#[tokio::test(start_paused = true)]
async fn past_the_cap_the_rate_closes_before_the_429() {
    use super::super::server::ADMISSION_BURST;
    let dir = scratch("capshed");
    let sock = dir.join("net.sock");
    let audit = Arc::new(Ends::default());
    let frozen = freeze();
    let handle = start(Arc::new(OnePublic), Arc::clone(&audit), 1, &sock);
    // Takes the one live slot (and one connection of the burst), and sends nothing. Accepted
    // first and its task spawned first, so on this current-thread runtime it holds the slot
    // before any flood connection asks (if not, the flood's 403 fails the test loudly).
    let held = UnixStream::connect(&sock).await.unwrap();
    let (mut answered, mut closed) = (0usize, 0usize);
    for _ in 0..100 {
        match flood_exchange(&sock, "evil.test:443").await {
            Some(out) if out.starts_with("HTTP/1.1 429 ") => answered += 1,
            None => closed += 1,
            Some(out) => panic!("neither a 429 nor closed unread: {out:?}"),
        }
    }
    let within = ADMISSION_BURST as usize - 1;
    assert_eq!((answered, closed), (within, 100 - within));
    let rows = audit.rows();
    assert_eq!(rows.len(), within, "one entry per 429: {rows:?}");
    assert!(
        rows.iter()
            .all(|r| r == "egress.limit too-many-connections"),
        "{rows:?}"
    );
    tokio::time::advance(SHED_INTERVAL).await;
    settle("the count entry", || audit.rows().len() > within).await;
    assert_eq!(
        audit.rows().last().cloned(),
        Some(format!("egress.shed rate closed={closed} window_ms=1000"))
    );
    frozen.thaw().await;
    drop(held);
    handle.shutdown().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

fn shedding(rate: u32, burst: u32) -> Shedding {
    Shedding::of(&Limits {
        admission_rate: rate,
        admission_burst: burst,
        ..Limits::new(4)
    })
}

#[tokio::test(start_paused = true)]
async fn shedding_admits_the_burst_then_counts_closes_from_the_first() {
    let mut s = shedding(2, 3);
    let t0 = tokio::time::Instant::now();
    for _ in 0..3 {
        assert!(s.admit(t0));
    }
    assert_eq!(
        (s.due(), s.report(t0)),
        (None, None),
        "nothing closed, nothing owed"
    );
    assert!(!s.admit(t0));
    tokio::time::advance(Duration::from_millis(100)).await;
    let t1 = tokio::time::Instant::now();
    assert!(!s.admit(t1));
    assert_eq!(
        s.due(),
        Some(t0 + SHED_INTERVAL),
        "due an interval after the first close"
    );
    assert_eq!(s.report(t1), Some((2, 100)));
    // Half a second at 2/s gives one connection back.
    tokio::time::advance(Duration::from_millis(400)).await;
    let t2 = tokio::time::Instant::now();
    assert!(s.admit(t2));
    assert_eq!(s.report(t2), Some((2, 500)));
    s.written();
    assert_eq!(
        (s.due(), s.report(t2)),
        (None, None),
        "written: nothing owed"
    );
    assert!(!s.admit(t2));
    assert_eq!(
        s.due(),
        Some(t2 + SHED_INTERVAL),
        "the next close opens a new window"
    );
    assert_eq!(s.report(t2), Some((1, 0)));
}

#[tokio::test(start_paused = true)]
async fn a_failed_shed_keeps_count_and_window_and_is_due_an_interval_later() {
    let mut s = shedding(1, 1);
    s.failed(tokio::time::Instant::now());
    assert_eq!(s.due(), None, "nothing owed: a failure arms nothing");
    let t0 = tokio::time::Instant::now();
    assert!(s.admit(t0));
    assert!(!s.admit(t0));
    tokio::time::advance(SHED_INTERVAL).await;
    let t1 = tokio::time::Instant::now();
    s.failed(t1);
    assert_eq!(s.due(), Some(t1 + SHED_INTERVAL));
    assert!(s.admit(t1), "one second at 1/s gives one back");
    assert!(!s.admit(t1));
    assert_eq!(
        s.due(),
        Some(t1 + SHED_INTERVAL),
        "a later close does not move it"
    );
    assert_eq!(
        s.report(t1),
        Some((2, 1000)),
        "the window runs from the first close"
    );
    s.closed = u64::MAX;
    assert!(!s.admit(t1));
    assert_eq!(s.report(t1), Some((u64::MAX, 1000)), "the count saturates");
}

/// Holds a paused clock still while it lives: tokio does not auto-advance time while a
/// blocking task runs, so waiting on real socket IO cannot move it; only `advance` does.
struct Frozen {
    hold: std::sync::mpsc::Sender<()>,
    task: tokio::task::JoinHandle<Option<()>>,
}

fn freeze() -> Frozen {
    let (hold, held) = std::sync::mpsc::channel::<()>();
    let task = tokio::task::spawn_blocking(move || held.recv().ok());
    Frozen { hold, task }
}

impl Frozen {
    /// Lets time auto-advance again.
    async fn thaw(self) {
        drop(self.hold);
        self.task.await.unwrap();
    }
}

/// `n` refused CONNECTs one after another: how many were answered 403 and how many closed
/// unread.
async fn flood(sock: &Path, n: usize) -> (usize, usize) {
    let mut answered = 0;
    for _ in 0..n {
        match flood_exchange(sock, "evil.test:443").await {
            Some(out) if out.starts_with("HTTP/1.1 403 ") => answered += 1,
            None => {}
            Some(out) => panic!("neither a 403 nor closed unread: {out:?}"),
        }
    }
    (answered, n - answered)
}

/// A CONNECT to `target`: its whole answer, or `None` when the connection was closed unread
/// (nothing came back, or the write or read met the closed end). Bounded in real time.
async fn flood_exchange(sock: &Path, target: &str) -> Option<String> {
    bounded("a flood exchange", async {
        let mut s = UnixStream::connect(sock).await.unwrap();
        let closed = |e: io::Error| {
            assert!(
                matches!(
                    e.kind(),
                    io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
                ),
                "{e}"
            );
        };
        if let Err(e) = s
            .write_all(format!("CONNECT {target} HTTP/1.1\r\n\r\n").as_bytes())
            .await
        {
            closed(e);
            return None;
        }
        let mut out = String::new();
        match s.read_to_string(&mut out).await {
            Ok(_) if out.is_empty() => None,
            Ok(_) => Some(out),
            Err(e) => {
                closed(e);
                None
            }
        }
    })
    .await
}

/// Connects `n` clients no faster than the admission rate lets in: the burst at once, then one
/// per `1 s / ADMISSION_RATE` with a margin, so none is closed over the rate (a test that needs
/// more than a burst of admitted connections is paced; its assertions are unchanged).
async fn connect_paced(sock: &Path, n: usize) -> Vec<UnixStream> {
    use super::super::server::{ADMISSION_BURST, ADMISSION_RATE};
    let step = Duration::from_secs(1) / ADMISSION_RATE + Duration::from_millis(10);
    let mut clients = Vec::new();
    for i in 0..n {
        if i >= ADMISSION_BURST as usize {
            tokio::time::sleep(step).await;
        }
        clients.push(UnixStream::connect(sock).await.unwrap());
    }
    clients
}

/// How long a frozen-clock test waits on the server in real time before it fails.
const REAL_LIMIT: Duration = Duration::from_secs(10);

/// Waits up to [`REAL_LIMIT`] of real time for `f`, without moving a paused clock.
async fn settle(what: &str, f: impl Fn() -> bool) {
    let deadline = std::time::Instant::now() + REAL_LIMIT;
    while !f() {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::task::spawn_blocking(|| std::thread::sleep(Duration::from_millis(1)))
            .await
            .unwrap();
    }
}

/// Awaits `fut` for at most [`REAL_LIMIT`] of real time, without moving a paused clock: while
/// [`Frozen`] holds the clock no server timeout can fire, so a server that stops answering fails
/// the test instead of hanging it. The watchdog is a blocking task, which holds the clock too.
async fn bounded<T>(what: &str, fut: impl Future<Output = T>) -> T {
    let (done, wait) = std::sync::mpsc::channel::<()>();
    let mut watchdog = tokio::task::spawn_blocking(move || wait.recv_timeout(REAL_LIMIT));
    tokio::pin!(fut);
    tokio::select! {
        biased;
        out = &mut fut => {
            drop(done);
            let _ = watchdog.await;
            out
        }
        _ = &mut watchdog => panic!("{what}: no end after {REAL_LIMIT:?} of real time"),
    }
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
    let clients = connect_paced(&sock, bound - 1).await;
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
    let clients = connect_paced(&sock, bound).await;
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
/// Records "event end-or-reason" per entry; with a gate, each append waits there first. The
/// first `fail_sheds` `egress.shed` appends fail; `shed_tries` counts them all.
#[derive(Default)]
struct Ends {
    rows: std::sync::Mutex<Vec<String>>,
    gate: Option<Arc<Gate>>,
    fail_sheds: std::sync::atomic::AtomicUsize,
    shed_tries: std::sync::atomic::AtomicUsize,
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
        if e.event() == "egress.shed" {
            use std::sync::atomic::Ordering::SeqCst;
            self.shed_tries.fetch_add(1, SeqCst);
            let fail = self
                .fail_sheds
                .try_update(SeqCst, SeqCst, |n| n.checked_sub(1));
            if fail.is_ok() {
                return Err(sally_core::audit::AuditError::Io {
                    path: "test".into(),
                    source: io::Error::other("refused"),
                });
            }
        }
        let a = e.resolved(&sally_core::audit::Redactor::default());
        let why = a["end"]
            .as_str()
            .or(a["reason"].as_str())
            .unwrap_or_default();
        let origin = a
            .get("origin")
            .map_or_else(String::new, |o| format!(" origin={o}"));
        let shed = if e.event() == "egress.shed" {
            format!(" closed={} window_ms={}", a["closed"], a["window_ms"])
        } else {
            String::new()
        };
        self.rows
            .lock()
            .unwrap()
            .push(format!("{} {why}{origin}{shed}", e.event()));
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
