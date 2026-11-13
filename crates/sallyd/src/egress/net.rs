//! The real network side of the egress proxy: the system resolver, the TCP dialer, the host's own
//! addresses from `/proc`, the session's `net.sock` listener and its accept loop, and the starter
//! the launcher holds (architect Q7). The decisions live in `server.rs`; this file only performs
//! them, so its tests are the `rt_net_*` rows plus the unit tests below.

use std::io::{self, Read};
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use rustix::fs::{Mode, OFlags};
use sally_core::manifest::{AuditLevel, ValidatedManifest};
use tokio::net::{TcpStream, UnixListener, UnixStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::task::{JoinHandle, JoinSet};

use super::ca::{self, CaError, SessionTls, Validity};
use super::hostaddrs;
use super::inject::{Credentials, CredentialsError, SecretSource, Spec};
use super::policy::Policy;
use super::roots::{BundleFiles, RootsError};
use super::server::{Dialer, HostAddrs, Interception, Limits, Parts, Proxy, Resolver, until_true};
use crate::sandbox::AuditSink;

/// File name of the egress socket in the workspace socket directory (ARCHITECTURE §3.1).
pub const NET_SOCK: &str = "net.sock";
/// Largest `/proc` file read for the host's addresses; more refuses the connection.
pub const MAX_PROC_BYTES: u64 = 1024 * 1024;
/// Pause after a failed `accept` (EMFILE and the like) before the next one.
pub const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);
/// How long a stopping listener waits for its connections to write `egress.close`.
pub const STOP_GRACE: Duration = Duration::from_secs(5);

/// `getaddrinfo` calls in flight at once, across every session (architect Q19).
// TODO(#47): a per-session share, so one session cannot hold every slot for a resolver timeout.
pub const MAX_LOOKUPS: usize = 64;

/// A blocking name lookup of an absolute name and a port.
pub type Lookup = Arc<dyn Fn(&str, u16) -> io::Result<Vec<SocketAddr>> + Send + Sync>;

/// Name lookups off the runtime, at most as many at once as `slots` holds. A lookup that finds no
/// free slot fails at once and never queues; a slot stays taken until its blocking call returns,
/// even after the caller gave up. Lookups and audit appends share tokio's blocking pool: stuck
/// lookups take at most `slots` of its threads, so the audit log is never held up while the pool
/// is larger than that (tokio's default is 512).
// TODO(#47): the daemon's runtime builder must keep `max_blocking_threads` well above
// MAX_LOOKUPS, and its test must use that builder.
#[derive(Clone)]
pub struct SystemResolver {
    slots: Arc<Semaphore>,
    lookup: Lookup,
}

impl SystemResolver {
    /// A resolver over `lookup`, limited to the permits of `slots`.
    #[must_use]
    pub fn new(slots: Arc<Semaphore>, lookup: Lookup) -> Self {
        Self { slots, lookup }
    }
}

impl Default for SystemResolver {
    /// [`getaddrinfo`] with [`MAX_LOOKUPS`] slots.
    fn default() -> Self {
        Self::new(Arc::new(Semaphore::new(MAX_LOOKUPS)), Arc::new(getaddrinfo))
    }
}

impl std::fmt::Debug for SystemResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SystemResolver")
            .field("free_slots", &self.slots.available_permits())
            .finish_non_exhaustive()
    }
}

impl Resolver for SystemResolver {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let slot = Arc::clone(&self.slots)
            .try_acquire_owned()
            .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "every lookup slot is busy"))?;
        let (name, lookup) = (absolute(host), Arc::clone(&self.lookup));
        tokio::task::spawn_blocking(move || {
            let _slot = slot;
            lookup(&name, port)
        })
        .await
        .map_err(io::Error::other)?
    }
}

/// The absolute form of a hostname (one trailing dot), so the resolver applies no search list.
/// Authorities never end in a dot (`authority::parse` strips it).
#[must_use]
pub fn absolute(host: &str) -> String {
    format!("{host}.")
}

/// The system resolver (`getaddrinfo` through std), blocking.
///
/// # Errors
/// The resolver's error.
pub fn getaddrinfo(name: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    Ok(std::net::ToSocketAddrs::to_socket_addrs(&(name, port))?.collect())
}

/// Plain TCP connects to a pinned address.
#[derive(Debug, Clone, Copy, Default)]
pub struct TcpDialer;

impl Dialer for TcpDialer {
    type Stream = TcpStream;
    async fn dial(&self, addr: SocketAddr) -> io::Result<TcpStream> {
        let s = TcpStream::connect(addr).await?;
        s.set_nodelay(true)?;
        Ok(s)
    }
}

/// The host's addresses from `/proc/net/fib_trie` and `/proc/net/if_inet6`, read on every
/// connection (addresses change; the files are small).
#[derive(Debug, Clone)]
pub struct ProcHostAddrs {
    fib_trie: PathBuf,
    if_inet6: PathBuf,
}

impl Default for ProcHostAddrs {
    fn default() -> Self {
        Self {
            fib_trie: "/proc/net/fib_trie".into(),
            if_inet6: "/proc/net/if_inet6".into(),
        }
    }
}

impl HostAddrs for ProcHostAddrs {
    async fn own(&self) -> io::Result<Vec<IpAddr>> {
        let me = self.clone();
        tokio::task::spawn_blocking(move || me.read())
            .await
            .map_err(io::Error::other)?
    }
}

impl ProcHostAddrs {
    fn read(&self) -> io::Result<Vec<IpAddr>> {
        let fib = read_bounded(&self.fib_trie)?;
        let v6 = match read_bounded(&self.if_inet6) {
            Ok(s) => Some(s),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        hostaddrs::parse(&fib, v6.as_deref()).map_err(io::Error::other)
    }
}

/// Reads at most [`MAX_PROC_BYTES`]; a longer file is an error.
fn read_bounded(path: &Path) -> io::Result<String> {
    let mut text = String::new();
    std::fs::File::open(path)?
        .take(MAX_PROC_BYTES + 1)
        .read_to_string(&mut text)?;
    if u64::try_from(text.len()).unwrap_or(u64::MAX) > MAX_PROC_BYTES {
        return Err(io::Error::other(format!(
            "{}: over the size bound",
            path.display()
        )));
    }
    Ok(text)
}

/// Binds the session's `net.sock` at `path`, owner-only (the directory is 0700 already).
///
/// The bind goes through `/proc/self/fd/<dir>/<name>` of the opened parent directory, so a deep
/// runtime directory or a long session id can never exceed `sun_path` (107 bytes).
///
/// # Errors
/// `InvalidInput` for a path without a parent or file name; the open, bind or chmod error.
pub fn bind(path: &Path) -> io::Result<UnixListener> {
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(io::ErrorKind::InvalidInput.into());
    };
    let flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW;
    let dir = sally_core::fd::open(parent, flags, Mode::empty())?;
    let short = Path::new("/proc/self/fd")
        .join(std::os::fd::AsRawFd::as_raw_fd(&dir).to_string())
        .join(name);
    let l = std::os::unix::net::UnixListener::bind(&short)?;
    std::fs::set_permissions(&short, std::fs::Permissions::from_mode(0o600))?;
    l.set_nonblocking(true)?;
    UnixListener::from_std(l)
}

/// A running session listener. [`EgressHandle::shutdown`] stops it in order (no new connections,
/// open tunnels end with `session-stopped` and are audited); dropping it aborts the accept loop
/// and every connection task.
#[derive(Debug)]
pub struct EgressHandle {
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
}

impl EgressHandle {
    /// Stops accepting, ends every connection and waits up to [`STOP_GRACE`] for their
    /// `egress.close` entries; then aborts what is left.
    pub async fn shutdown(mut self) {
        self.stop.send_replace(true);
        if let Some(mut task) = self.task.take()
            && tokio::time::timeout(STOP_GRACE, &mut task).await.is_err()
        {
            task.abort();
        }
    }
}

impl Drop for EgressHandle {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// Runs the accept loop of `listener` for `proxy`: one task per connection, at most
/// [`Limits::in_flight`](super::server::Limits::in_flight) at once (architect Q20); past that
/// nothing more is accepted until a connection ends.
pub fn serve<R, D, H>(listener: UnixListener, proxy: Arc<Proxy<R, D, H>>) -> EgressHandle
where
    R: Resolver,
    D: Dialer,
    H: HostAddrs,
{
    let (stop, stopping) = watch::channel(false);
    let in_flight = Arc::new(Semaphore::new(proxy.limits().in_flight()));
    let task = tokio::spawn(async move {
        let mut conns = JoinSet::new();
        let stopped = until_true(stopping);
        tokio::pin!(stopped);
        loop {
            tokio::select! {
                biased;
                () = &mut stopped => break,
                // TODO(#49): log a connection task that panicked.
                Some(_) = conns.join_next(), if !conns.is_empty() => {}
                admitted = admit(&in_flight, &listener) => match admitted {
                    Ok((slot, stream)) => {
                        let p = Arc::clone(&proxy);
                        conns.spawn(async move {
                            let _slot = slot;
                            p.serve(stream).await;
                        });
                    }
                    Err(_) => tokio::time::sleep(ACCEPT_BACKOFF).await,
                },
            }
        }
        drop(listener);
        proxy.stop();
        while conns.join_next().await.is_some() {}
    });
    EgressHandle {
        stop,
        task: Some(task),
    }
}

/// Waits for an in-flight slot, then accepts; the slot goes with the connection. Dropping it
/// mid-way (stop won) releases the slot, and `accept` is cancel-safe.
async fn admit(
    in_flight: &Arc<Semaphore>,
    listener: &UnixListener,
) -> io::Result<(OwnedSemaphorePermit, UnixStream)> {
    let slot = Arc::clone(in_flight)
        .acquire_owned()
        .await
        .map_err(io::Error::other)?;
    let (stream, _) = listener.accept().await?;
    Ok((slot, stream))
}

/// A session's egress settings.
pub struct SessionEgress {
    /// The session's policy.
    pub policy: Policy,
    /// `network.max_connections`.
    pub max_connections: usize,
    /// `network.max_request_bytes` and `network.max_response_bytes`: body caps of each
    /// intercepted request and response.
    pub body_caps: (u64, u64),
    /// The session id.
    pub session: String,
    /// The session's audit level.
    pub level: AuditLevel,
    /// The audit log.
    pub audit: Arc<dyn AuditSink>,
    /// Whether the session gets a session CA ([`ca::wanted`]).
    pub ca: bool,
    /// `runtime.timeout`: the CA is valid this long plus [`ca::GRACE`].
    pub timeout: Duration,
    /// The secret grants: names, hosts, headers and formats, no value.
    pub grants: Vec<Spec>,
    /// The CA, its leaves, the upstream roots and the credentials, once
    /// [`EgressStarter::prepare`] made them.
    pub interception: Option<Interception>,
}

impl SessionEgress {
    /// The settings of a validated manifest.
    #[must_use]
    pub fn from_manifest(v: &ValidatedManifest, session: &str, audit: Arc<dyn AuditSink>) -> Self {
        let m = v.manifest();
        Self {
            policy: Policy::from_manifest(v),
            max_connections: usize::try_from(m.network.max_connections).unwrap_or(usize::MAX),
            body_caps: (
                m.network.max_request_bytes.bytes(),
                m.network.max_response_bytes.bytes(),
            ),
            session: session.to_owned(),
            level: m.audit.level,
            audit,
            ca: ca::wanted(m),
            timeout: Duration::from_secs(m.runtime.timeout.as_secs()),
            grants: Spec::from_manifest(v),
            interception: None,
        }
    }
}

/// Why a session's egress could not be set up. Each refuses the launch.
#[derive(Debug, thiserror::Error)]
pub enum EgressError {
    /// No upstream trust roots.
    #[error(transparent)]
    Roots(#[from] RootsError),
    /// The session CA could not be made.
    #[error(transparent)]
    Ca(#[from] CaError),
    /// `ca-bundle.pem` or `session-ca.pem` could not be written.
    #[error("CA files: {0}")]
    Files(#[source] io::Error),
    /// `net.sock` could not be bound.
    #[error("net.sock: {0}")]
    Listener(#[source] io::Error),
    /// The secrets store could not be read (Task 9a-3, architect D7).
    #[error("secrets store: {0}")]
    Store(#[source] sally_core::secrets::SecretsError),
    /// The grants' credentials could not be built: a secret missing from the store, a `{basic}`
    /// grant (Task 9b), or a grant that cannot be injected.
    #[error(transparent)]
    Credentials(#[from] CredentialsError),
}

/// Starts a session's listener. Dyn-compatible, so the launcher holds `Arc<dyn EgressStarter>`;
/// the resolver, dialer, host addresses and trust roots behind it are constructor arguments
/// (decision 10; Task 9a decision 6).
pub trait EgressStarter: Send + Sync {
    /// For a session with a session CA ([`SessionEgress::ca`]): refuses a `{basic}` grant (before
    /// the store is opened), reads the grants' values from the secrets source and builds the
    /// credentials, loads the upstream trust roots, mints the CA and its leaves, and writes
    /// `ca-bundle.pem` and `session-ca.pem` into `dir` (the workspace socket directory), before
    /// the container exists. Blocking: the launcher runs it off the runtime. Other sessions pass
    /// through unchanged.
    ///
    /// # Errors
    /// [`EgressError::Credentials`], [`EgressError::Store`], [`EgressError::Roots`],
    /// [`EgressError::Ca`] or [`EgressError::Files`].
    fn prepare(&self, dir: &Path, s: SessionEgress) -> Result<SessionEgress, EgressError>;

    /// Binds `sock` and serves it for the session.
    ///
    /// # Errors
    /// The bind error.
    fn start(&self, sock: &Path, s: SessionEgress) -> io::Result<EgressHandle>;
}

/// The starter over a resolver, a dialer, a host-address source, the trust-root files and the
/// secrets source, shared by every session. No `Default`: a secrets source is always named
/// (architect D7).
#[derive(Debug)]
pub struct Egress<R, D, H> {
    /// Name lookups.
    pub resolver: Arc<R>,
    /// Upstream connections.
    pub dialer: Arc<D>,
    /// The host's own addresses.
    pub host: Arc<H>,
    /// Where the upstream trust roots are read from, per session ([`BundleFiles::default`] in
    /// production).
    pub roots: BundleFiles,
    /// Where secret values come from, per session ([`super::inject::StoreFile`] in production).
    pub secrets: Arc<dyn SecretSource>,
}

/// The production starter. Build it once and share it by every session: each
/// [`SystemResolver::default`] has its own [`MAX_LOOKUPS`] slots, so the bound is global only
/// while one resolver serves them all.
pub type SystemEgress = Egress<SystemResolver, TcpDialer, ProcHostAddrs>;

impl<R: Resolver, D: Dialer, H: HostAddrs> EgressStarter for Egress<R, D, H> {
    fn prepare(&self, dir: &Path, mut s: SessionEgress) -> Result<SessionEgress, EgressError> {
        if !s.ca {
            return Ok(s);
        }
        if let Some(g) = s.grants.iter().find(|g| g.is_basic()) {
            return Err(CredentialsError::Basic(g.name.clone()).into());
        }
        let mut names: Vec<String> = Vec::new();
        for g in &s.grants {
            if !names.contains(&g.name) {
                names.push(g.name.clone());
            }
        }
        let values = self.secrets.load(&names).map_err(EgressError::Store)?;
        let credentials = Credentials::new(&s.grants, values)?;
        let roots = self.roots.load()?;
        let validity = Validity::for_session(SystemTime::now(), s.timeout)?;
        let tls = SessionTls::mint(&s.policy.grant_hosts(), validity)?;
        // Built before anything is written: a session refused here leaves no file behind
        // (security review L6).
        let interception = Interception::new(tls, roots, credentials)?;
        ca::write_files(dir, &interception.tls, &interception.roots.pem)
            .map_err(EgressError::Files)?;
        s.interception = Some(interception);
        Ok(s)
    }

    fn start(&self, sock: &Path, s: SessionEgress) -> io::Result<EgressHandle> {
        let listener = bind(sock)?;
        let proxy = Proxy::new(Parts {
            policy: s.policy,
            resolver: Arc::clone(&self.resolver),
            dialer: Arc::clone(&self.dialer),
            host: Arc::clone(&self.host),
            audit: s.audit,
            session: s.session,
            level: s.level,
            limits: Limits::of_session(s.max_connections, s.body_caps),
            interception: s.interception,
        });
        Ok(serve(listener, Arc::new(proxy)))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
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
        assert_eq!(audit.rows(), ["egress.allow "], "aborted: no close entry");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Starts a listener at `sock` that allows `a.mock.test:443` only.
    fn start<R: Resolver>(
        resolver: Arc<R>,
        audit: Arc<Ends>,
        max_connections: usize,
        sock: &Path,
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
            self.rows
                .lock()
                .unwrap()
                .push(format!("{} {why}", e.event()));
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
}

#[cfg(test)]
#[path = "net_ca_tests.rs"]
mod ca_tests;
