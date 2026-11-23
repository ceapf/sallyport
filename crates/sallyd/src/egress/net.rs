//! The real network side of the egress proxy: the system resolver, the TCP dialer, the host's own
//! addresses from `/proc`, the session's `net.sock` listener and its accept loop, and the starter
//! the launcher holds (architect Q7). The decisions live in `server.rs`; this file only performs
//! them, so its tests are the `rt_net_*` rows plus the unit tests below.

use std::io::{self, Read};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use rustix::fs::{Mode, OFlags};
use sally_core::manifest::{AuditLevel, BuiltinTool, ValidatedManifest};
use tokio::net::{TcpStream, UnixListener, UnixStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::Instant;

use super::addr::HostNets;
use super::ca::{self, CaError, SessionTls, Validity};
use super::hostaddrs::{self, HostAddrsError, Table};
use super::inject::{Credentials, CredentialsError, SecretSource, Spec};
use super::local::{ClientTls, Connector, LOCAL_QUEUE, Local, ORIGIN, Opened, Reach, host_grants};
use super::policy::Policy;
use super::roots::{BundleFiles, Roots, RootsError};
use super::server::{Dialer, HostAddrs, Interception, Limits, Parts, Proxy, Resolver, until_true};
use crate::rpc::rate::Rate;
use crate::sandbox::AuditSink;

/// File name of the egress socket in the workspace socket directory (ARCHITECTURE §3.1).
pub const NET_SOCK: &str = "net.sock";
/// Largest `/proc` file read for the host's addresses; more refuses the connection.
pub const MAX_PROC_BYTES: u64 = 1024 * 1024;
/// Pause after a failed `accept` (EMFILE and the like) before the next one.
pub const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);
/// How long connections closed over the admission rate are counted before their one
/// `egress.shed` entry is written.
pub const SHED_INTERVAL: Duration = Duration::from_secs(1);
/// How long a stopping listener waits for its connections to write `egress.close`.
pub const STOP_GRACE: Duration = Duration::from_secs(5);

/// `getaddrinfo` calls in flight at once, across every session (architect Q19). One session may
/// hold at most a quarter of them (`session::lookup::SESSION_LOOKUPS`, through
/// `session_resolver` and `globally_bounded`), so it cannot take every slot for a resolver timeout.
pub const MAX_LOOKUPS: usize = 64;

/// A blocking name lookup of an absolute name and a port.
pub type Lookup = Arc<dyn Fn(&str, u16) -> io::Result<Vec<SocketAddr>> + Send + Sync>;

/// Name lookups off the runtime, at most as many at once as `slots` holds. A lookup that finds no
/// free slot fails at once and never queues; a slot stays taken until its blocking call returns,
/// even after the caller gave up. Lookups and audit appends share tokio's blocking pool: stuck
/// lookups take at most `slots` of its threads, so lookups alone never hold the audit log up
/// while the pool is larger than that. The daemon's runtime builder (`daemon::runtime`) sets
/// the pool to `MAX_BLOCKING_THREADS`, which its test
/// `the_blocking_pool_stays_well_above_the_lookup_cap` keeps well above [`MAX_LOOKUPS`]. Appends
/// wait on the one audit writer whatever the pool; what bounds how many a sandbox causes is each
/// socket's rate (on `net.sock`, the admission rate of [`serve_with`]).
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

/// The host's addresses and connected networks from `/proc/net/fib_trie`, `/proc/net/if_inet6`
/// and `/proc/net/ipv6_route`, read together on every connection (addresses and routes change;
/// the files are small).
#[derive(Debug, Clone)]
pub struct ProcHostAddrs {
    fib_trie: PathBuf,
    if_inet6: PathBuf,
    ipv6_route: PathBuf,
}

impl Default for ProcHostAddrs {
    fn default() -> Self {
        Self {
            fib_trie: "/proc/net/fib_trie".into(),
            if_inet6: "/proc/net/if_inet6".into(),
            ipv6_route: "/proc/net/ipv6_route".into(),
        }
    }
}

impl HostAddrs for ProcHostAddrs {
    async fn own(&self) -> Result<HostNets, HostAddrsError> {
        let me = self.clone();
        tokio::task::spawn_blocking(move || me.read())
            .await
            .map_err(|_| HostAddrsError::ReaderFailed)?
    }
}

impl ProcHostAddrs {
    fn read(&self) -> Result<HostNets, HostAddrsError> {
        let fib = read_bounded(&self.fib_trie, Table::FibTrie)?;
        let addrs = read_optional(&self.if_inet6, Table::IfInet6)?;
        let routes = read_optional(&self.ipv6_route, Table::Ipv6Route)?;
        let v6 = hostaddrs::Ipv6Tables {
            addrs: addrs.as_deref(),
            routes: routes.as_deref(),
        };
        hostaddrs::parse(&fib, v6)
    }
}

/// [`read_bounded`], with a file that does not exist read as `None` (IPv6 is off).
fn read_optional(path: &Path, table: Table) -> Result<Option<String>, HostAddrsError> {
    match read_bounded(path, table) {
        Ok(s) => Ok(Some(s)),
        Err(HostAddrsError::Unreadable {
            kind: io::ErrorKind::NotFound,
            ..
        }) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Reads at most [`MAX_PROC_BYTES`]; a longer file is an error. Errors name the table and how
/// the read failed, never the path.
fn read_bounded(path: &Path, table: Table) -> Result<String, HostAddrsError> {
    let unreadable = |e: io::Error| HostAddrsError::Unreadable {
        table,
        kind: e.kind(),
    };
    let mut text = String::new();
    std::fs::File::open(path)
        .map_err(unreadable)?
        .take(MAX_PROC_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(unreadable)?;
    if u64::try_from(text.len()).unwrap_or(u64::MAX) > MAX_PROC_BYTES {
        return Err(HostAddrsError::TooLarge { table });
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
    connector: Option<Local>,
}

impl EgressHandle {
    /// The session's [`Connector`] for the `fetch` tool, when the session has upstream trust
    /// roots (a session with secret grants, or one granting `fetch`; architect ruling Q2).
    #[must_use]
    pub fn connector(&self) -> Option<Arc<dyn Connector>> {
        self.connector
            .clone()
            .map(|c| Arc::new(c) as Arc<dyn Connector>)
    }

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
/// nothing more is accepted until a connection ends. An accepted connection over the session's
/// admission rate ([`Limits::admission_rate`], [`Limits::admission_burst`]) is closed at once,
/// unread and without an entry of its own; one `egress.shed` per [`SHED_INTERVAL`] says how many
/// were, and a stop writes the count of an unfinished interval (an abort before that entry is
/// written, past [`STOP_GRACE`] or on drop, loses it, as it does an `egress.close`). No
/// broker-originated connections.
pub fn serve<R, D, H>(listener: UnixListener, proxy: Arc<Proxy<R, D, H>>) -> EgressHandle
where
    R: Resolver,
    D: Dialer,
    H: HostAddrs,
{
    serve_with(listener, proxy, None)
}

/// [`serve`], and with `reach` the broker-originated connections of a [`Local`] connector
/// (`local.rs`): each waits for an in-flight slot like an accepted stream, is served in the same
/// set (so a stop waits for its `egress.close` too), inside its origin's scope. They never cross
/// `net.sock` and draw nothing from the admission rate: each is one `tools/call`, already held to
/// `agent.sock`'s rate, and a shared bucket would let the workspace starve the harness's fetch.
pub fn serve_with<R, D, H>(
    listener: UnixListener,
    proxy: Arc<Proxy<R, D, H>>,
    reach: Option<Reach>,
) -> EgressHandle
where
    R: Resolver,
    D: Dialer,
    H: HostAddrs,
{
    let (stop, stopping) = watch::channel(false);
    let (tx, rx) = mpsc::channel::<Opened>(LOCAL_QUEUE);
    let connector = reach.map(|r| Local::new(tx, r));
    let task = tokio::spawn(accept_loop(listener, proxy, rx, stopping));
    EgressHandle {
        stop,
        task: Some(task),
        connector,
    }
}

/// The accept task of [`serve_with`]: admits from `listener` and `rx` until `stopping`, then
/// stops the proxy, writes the count still owed and waits for every connection to end.
async fn accept_loop<R, D, H>(
    listener: UnixListener,
    proxy: Arc<Proxy<R, D, H>>,
    mut rx: mpsc::Receiver<Opened>,
    stopping: watch::Receiver<bool>,
) where
    R: Resolver,
    D: Dialer,
    H: HostAddrs,
{
    let in_flight = Arc::new(Semaphore::new(proxy.limits().in_flight()));
    let mut conns = JoinSet::new();
    let stopped = until_true(stopping);
    tokio::pin!(stopped);
    let mut local_open = true;
    let mut shedding = Shedding::of(proxy.limits());
    loop {
        let due = shedding.due();
        let at = due.unwrap_or_else(Instant::now);
        tokio::select! {
            biased;
            () = &mut stopped => break,
            // TODO(#49): log a connection task that panicked.
            Some(_) = conns.join_next(), if !conns.is_empty() => {}
            // Before `admit`, so a flood cannot hold the count back.
            () = tokio::time::sleep_until(at), if due.is_some() => {
                write_shed(&proxy, &mut shedding).await;
            }
            admitted = admit(&in_flight, &listener, &mut rx, local_open) => match admitted {
                Ok(Admitted::Accepted(slot, stream)) => {
                    if shedding.admit(Instant::now()) {
                        let p = Arc::clone(&proxy);
                        conns.spawn(async move {
                            let _slot = slot;
                            p.serve(stream).await;
                        });
                    } else {
                        drop((slot, stream));
                    }
                }
                Ok(Admitted::Local(slot, (stream, origin))) => {
                    let p = Arc::clone(&proxy);
                    conns.spawn(ORIGIN.scope(origin, async move {
                        let _slot = slot;
                        p.serve(stream).await;
                    }));
                }
                Ok(Admitted::LocalGone) => local_open = false,
                Err(_) => tokio::time::sleep(ACCEPT_BACKOFF).await,
            },
        }
    }
    drop(listener);
    rx.close();
    proxy.stop();
    // No next try at the stop: a count whose entry fails here is lost, as a failed
    // `egress.close` is.
    write_shed(&proxy, &mut shedding).await;
    while conns.join_next().await.is_some() {}
}

/// The admission rate of one session's `net.sock` and the connections it closed since the last
/// `egress.shed`. Owned by the accept task.
struct Shedding {
    rate: Rate,
    /// Connections closed over the rate and not yet in an entry.
    closed: u64,
    /// When the first of them was closed.
    first: Option<Instant>,
    /// When their entry is next due.
    due: Option<Instant>,
}

impl Shedding {
    /// Nothing closed yet, the burst whole.
    fn of(limits: &Limits) -> Self {
        Self {
            rate: Rate::new(limits.admission_rate, limits.admission_burst),
            closed: 0,
            first: None,
            due: None,
        }
    }

    /// Whether a connection accepted at `now` is admitted; one that is not is counted, and the
    /// first of an interval sets when its entry is due.
    fn admit(&mut self, now: Instant) -> bool {
        if self.rate.take().is_ok() {
            return true;
        }
        self.closed = self.closed.saturating_add(1);
        if self.first.is_none() {
            self.first = Some(now);
            self.due = Some(now + SHED_INTERVAL);
        }
        false
    }

    /// When an entry is due, while one is owed.
    fn due(&self) -> Option<Instant> {
        self.due
    }

    /// The owed entry's `(closed, window_ms)` at `now`: the count and the milliseconds since the
    /// first close it counts.
    fn report(&self, now: Instant) -> Option<(u64, u64)> {
        let first = self.first?;
        let ms = now.saturating_duration_since(first).as_millis();
        Some((self.closed, u64::try_from(ms).unwrap_or(u64::MAX)))
    }

    /// The entry was written: the next close opens a new interval.
    fn written(&mut self) {
        self.closed = 0;
        self.first = None;
        self.due = None;
    }

    /// The entry was not written: the count and its window stay, and the next try is one
    /// interval after `now`. Only at the stop, with no next try, does a failed entry lose its
    /// count.
    fn failed(&mut self, now: Instant) {
        if self.first.is_some() {
            self.due = Some(now + SHED_INTERVAL);
        }
    }
}

/// Writes the `egress.shed` owed, if any, and records whether it was written.
async fn write_shed<R, D, H>(proxy: &Proxy<R, D, H>, shedding: &mut Shedding)
where
    R: Resolver,
    D: Dialer,
    H: HostAddrs,
{
    let now = Instant::now();
    if let Some((closed, window_ms)) = shedding.report(now) {
        if proxy.shed(closed, window_ms).await {
            shedding.written();
        } else {
            shedding.failed(now);
        }
    }
}

/// What [`admit`] let in.
enum Admitted {
    /// A stream accepted on the listener.
    Accepted(OwnedSemaphorePermit, UnixStream),
    /// A broker-originated connection.
    Local(OwnedSemaphorePermit, Opened),
    /// Every connector is gone (no slot is held).
    LocalGone,
}

/// Waits for one in-flight slot, then for whichever comes first: an accepted stream or, while
/// `local` holds, a broker-originated connection; the slot goes with it. One slot for both, so a
/// queued fetch is never kept waiting by a slot held for `accept` (rust review M2, security
/// review L2). Dropping it mid-way (stop won) releases the slot; `accept` and `recv` are
/// cancel-safe.
async fn admit(
    in_flight: &Arc<Semaphore>,
    listener: &UnixListener,
    rx: &mut mpsc::Receiver<Opened>,
    local: bool,
) -> io::Result<Admitted> {
    let slot = Arc::clone(in_flight)
        .acquire_owned()
        .await
        .map_err(io::Error::other)?;
    tokio::select! {
        accepted = listener.accept() => Ok(Admitted::Accepted(slot, accepted?.0)),
        opened = rx.recv(), if local => Ok(match opened {
            Some(o) => Admitted::Local(slot, o),
            None => Admitted::LocalGone,
        }),
    }
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
    /// Whether the manifest grants the `fetch` tool: the session then needs upstream trust roots
    /// even without secret grants (architect ruling Q2).
    pub fetch: bool,
    /// The upstream trust roots of a session that grants `fetch` but has no session CA, once
    /// [`EgressStarter::prepare`] loaded them (a CA session keeps its own in `interception`).
    pub roots: Option<Roots>,
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
            fetch: m.tools.builtin.contains(&BuiltinTool::Fetch),
            roots: None,
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
    /// The grants' credentials could not be built: a secret missing from the store, or a grant
    /// that cannot be injected or redacted.
    #[error(transparent)]
    Credentials(#[from] CredentialsError),
}

/// Starts a session's listener. Dyn-compatible, so the launcher holds `Arc<dyn EgressStarter>`;
/// the resolver, dialer, host addresses and trust roots behind it are constructor arguments
/// (decision 10; Task 9a decision 6).
pub trait EgressStarter: Send + Sync {
    /// For a session with a session CA ([`SessionEgress::ca`]): reads the grants' values from
    /// the secrets source and builds the credentials, loads the upstream trust roots, mints the
    /// CA and its leaves, and writes `ca-bundle.pem` and `session-ca.pem` into `dir` (the
    /// workspace socket directory), before the container exists. Blocking: the launcher runs it
    /// off the runtime. A session without a CA that grants `fetch` only gets its upstream trust
    /// roots loaded (architect ruling Q2; no CA, no file); other sessions pass through unchanged.
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
            if s.fetch {
                s.roots = Some(self.roots.load()?);
            }
            return Ok(s);
        }
        let mut names: Vec<String> = Vec::new();
        for g in &s.grants {
            if !names.contains(&g.name) {
                names.push(g.name.clone());
            }
        }
        let values = self.secrets.load(&names).map_err(EgressError::Store)?;
        let credentials = Credentials::new(&s.grants, values)?;
        // A file that fails the roots checks refuses the launch here (RT-SEC-16).
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
        let reach = if s.fetch {
            ClientTls::of(s.interception.as_ref(), s.roots.as_ref())
                .map_err(io::Error::other)?
                .map(|tls| Reach {
                    tls,
                    grants: host_grants(&s.policy, &s.grants),
                })
        } else {
            None
        };
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
        Ok(serve_with(listener, Arc::new(proxy), reach))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[path = "net_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "net_ca_tests.rs"]
mod ca_tests;
