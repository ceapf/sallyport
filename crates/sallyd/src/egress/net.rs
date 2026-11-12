//! The real network side of the egress proxy: the system resolver, the TCP dialer, the host's own
//! addresses from `/proc`, the session's `net.sock` listener and its accept loop, and the starter
//! the launcher holds (architect Q7). The decisions live in `server.rs`; this file only performs
//! them, so its tests are the `rt_net_*` rows plus the unit tests below.

use std::io::{self, Read};
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sally_core::manifest::{AuditLevel, ValidatedManifest};
use tokio::net::{TcpStream, UnixListener};
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};

use super::hostaddrs;
use super::policy::Policy;
use super::server::{Dialer, HostAddrs, Limits, Parts, Proxy, Resolver};
use crate::sandbox::AuditSink;

/// File name of the egress socket in the workspace socket directory (ARCHITECTURE §3.1).
pub const NET_SOCK: &str = "net.sock";
/// Largest `/proc` file read for the host's addresses; more refuses the connection.
pub const MAX_PROC_BYTES: u64 = 1024 * 1024;
/// Pause after a failed `accept` (EMFILE and the like) before the next one.
pub const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);
/// How long a stopping listener waits for its connections to write `egress.close`.
pub const STOP_GRACE: Duration = Duration::from_secs(5);

/// `getaddrinfo` through tokio, off the runtime.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        Ok(tokio::net::lookup_host((host, port)).await?.collect())
    }
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
    let flags = rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY;
    let dir = sally_core::fd::open(parent, flags, rustix::fs::Mode::empty())?;
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

/// Runs the accept loop of `listener` for `proxy`: one task per connection.
pub fn serve<R, D, H>(listener: UnixListener, proxy: Arc<Proxy<R, D, H>>) -> EgressHandle
where
    R: Resolver,
    D: Dialer,
    H: HostAddrs,
{
    let (stop, stopping) = watch::channel(false);
    let task = tokio::spawn(async move {
        let mut conns = JoinSet::new();
        let stopped = until_true(stopping);
        tokio::pin!(stopped);
        loop {
            tokio::select! {
                biased;
                () = &mut stopped => break,
                Some(_) = conns.join_next(), if !conns.is_empty() => {}
                accepted = listener.accept() => match accepted {
                    Ok((stream, _)) => {
                        let p = Arc::clone(&proxy);
                        conns.spawn(async move { p.serve(stream).await });
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

/// Resolves once `rx` holds `true`, or its sender is gone.
async fn until_true(mut rx: watch::Receiver<bool>) {
    let _ = rx.wait_for(|s| *s).await.map(drop);
}

/// A session's egress settings.
pub struct SessionEgress {
    /// The session's policy.
    pub policy: Policy,
    /// `network.max_connections`.
    pub max_connections: usize,
    /// The session id.
    pub session: String,
    /// The session's audit level.
    pub level: AuditLevel,
    /// The audit log.
    pub audit: Arc<dyn AuditSink>,
}

impl SessionEgress {
    /// The settings of a validated manifest.
    #[must_use]
    pub fn from_manifest(v: &ValidatedManifest, session: &str, audit: Arc<dyn AuditSink>) -> Self {
        let m = v.manifest();
        Self {
            policy: Policy::from_manifest(v),
            max_connections: usize::try_from(m.network.max_connections).unwrap_or(usize::MAX),
            session: session.to_owned(),
            level: m.audit.level,
            audit,
        }
    }
}

/// Starts a session's listener. Dyn-compatible, so the launcher holds `Arc<dyn EgressStarter>`;
/// the resolver, dialer and host addresses behind it are constructor arguments (decision 10).
pub trait EgressStarter: Send + Sync {
    /// Binds `sock` and serves it for the session.
    ///
    /// # Errors
    /// The bind error.
    fn start(&self, sock: &Path, s: SessionEgress) -> io::Result<EgressHandle>;
}

/// The starter over a resolver, a dialer and a host-address source, shared by every session.
#[derive(Debug, Default)]
pub struct Egress<R, D, H> {
    /// Name lookups.
    pub resolver: Arc<R>,
    /// Upstream connections.
    pub dialer: Arc<D>,
    /// The host's own addresses.
    pub host: Arc<H>,
}

/// The production starter.
pub type SystemEgress = Egress<SystemResolver, TcpDialer, ProcHostAddrs>;

impl<R: Resolver, D: Dialer, H: HostAddrs> EgressStarter for Egress<R, D, H> {
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
            limits: Limits::new(s.max_connections),
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

    #[tokio::test]
    async fn the_system_resolver_resolves_localhost_without_a_network() {
        let got = SystemResolver.resolve("localhost", 443).await.unwrap();
        assert!(
            got.iter().all(|a| a.ip().is_loopback() && a.port() == 443),
            "{got:?}"
        );
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
    #[derive(Default)]
    struct Ends(std::sync::Mutex<Vec<String>>);
    impl AuditSink for Ends {
        fn append(
            &self,
            e: sally_core::audit::NewEntry,
            _: AuditLevel,
        ) -> Result<(), sally_core::audit::AuditError> {
            let end = e.arguments()["end"].as_str().unwrap_or_default().to_owned();
            self.0.lock().unwrap().push(format!("{} {end}", e.event()));
            Ok(())
        }
    }

    #[tokio::test]
    async fn the_listener_serves_each_connection_and_stops_in_order() {
        use sally_core::manifest::parse_host_pattern;
        let dir = scratch("serve");
        let sock = dir.join("net.sock");
        let audit = Arc::new(Ends::default());
        let starter = Egress {
            resolver: Arc::new(OnePublic),
            dialer: Arc::new(Echo),
            host: Arc::new(NoneOwned),
        };
        let rule = super::super::policy::Rule {
            host: parse_host_pattern("a.mock.test").unwrap(),
            ports: vec![443],
        };
        let handle = starter
            .start(
                &sock,
                SessionEgress {
                    policy: Policy::new(vec![rule], vec![]),
                    max_connections: 4,
                    session: "s-1".into(),
                    level: AuditLevel::default(),
                    audit: Arc::clone(&audit) as Arc<dyn AuditSink>,
                },
            )
            .unwrap();
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
        let ends = audit.0.lock().unwrap().clone();
        assert_eq!(
            ends,
            [
                "egress.deny ",
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
