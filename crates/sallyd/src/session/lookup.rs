//! The daemon's egress starter with a per-session share of the name lookups (#47, architect
//! Q44). The egress proxy caps `getaddrinfo` calls at [`MAX_LOOKUPS`] in flight across the
//! daemon; a lookup that finds no free slot fails at once (`resolve-failed`) and a slot stays
//! taken until its blocking call returns. Without a share, one session naming slow-resolving
//! hosts could hold all of them for a resolver timeout.
//!
//! Each session gets its own [`SystemResolver`] with [`SESSION_LOOKUPS`] slots, over a lookup
//! that also takes one of the daemon's [`MAX_LOOKUPS`] global slots (never waiting), so both
//! bounds hold and both slots are held until the blocking call returns. The proxy itself
//! (`egress/`) is unchanged: this module only builds what it is given.

use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use tokio::sync::Semaphore;

use crate::egress::inject::SecretSource;
use crate::egress::net::{
    Egress, EgressError, EgressHandle, EgressStarter, Lookup, MAX_LOOKUPS, ProcHostAddrs,
    SessionEgress, SystemResolver, TcpDialer,
};
use crate::egress::roots::BundleFiles;
use sally_core::secrets::{Secret, SecretsError};

/// Lookups one session may have in flight: a quarter of the daemon's.
pub const SESSION_LOOKUPS: usize = MAX_LOOKUPS / 4;

/// A lookup that first takes one of `global`'s slots, without waiting, and holds it until the
/// blocking `inner` call returns.
#[must_use]
pub(crate) fn globally_bounded(global: Arc<Semaphore>, inner: Lookup) -> Lookup {
    Arc::new(
        move |name: &str, port: u16| -> io::Result<Vec<SocketAddr>> {
            let _slot = Arc::clone(&global).try_acquire_owned().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "every daemon lookup slot is busy",
                )
            })?;
            inner(name, port)
        },
    )
}

/// A session's resolver: [`SESSION_LOOKUPS`] slots of its own over `lookup`.
#[must_use]
pub(crate) fn session_resolver(lookup: &Lookup) -> SystemResolver {
    SystemResolver::new(
        Arc::new(Semaphore::new(SESSION_LOOKUPS)),
        Arc::clone(lookup),
    )
}

/// A secrets source that holds no value, so every secret grant is refused `secret-missing`
/// before anything is created. PR A wires it in production: the secret set is outside PR A
/// (maintainer), and values must not be loaded before the redactor swap of #85.
/// TODO(#99): replace it with the store file, `<config_home>/sallyport/secrets.toml`.
#[derive(Debug, Clone, Copy)]
pub struct NoSecrets;

impl SecretSource for NoSecrets {
    fn load(&self, _names: &[String]) -> Result<Vec<(String, Secret<String>)>, SecretsError> {
        Ok(Vec::new())
    }
}

/// The production starter: system resolver, plain TCP, `/proc` host addresses, the default
/// trust-root files and the named secrets source, with a fresh per-session resolver for every
/// session. No `Default`: the secrets source is always named (architect D7).
#[derive(Clone)]
pub struct SharedEgress {
    lookup: Lookup,
    dialer: Arc<TcpDialer>,
    host: Arc<ProcHostAddrs>,
    roots: BundleFiles,
    secrets: Arc<dyn SecretSource>,
}

impl std::fmt::Debug for SharedEgress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedEgress").finish_non_exhaustive()
    }
}

impl SharedEgress {
    /// A starter over `lookup`, bounded by one global set of [`MAX_LOOKUPS`] slots, reading
    /// secret values from `secrets`.
    #[must_use]
    pub fn new(lookup: Lookup, secrets: Arc<dyn SecretSource>) -> Self {
        Self {
            lookup: globally_bounded(Arc::new(Semaphore::new(MAX_LOOKUPS)), lookup),
            dialer: Arc::new(TcpDialer),
            host: Arc::new(ProcHostAddrs::default()),
            roots: BundleFiles::default(),
            secrets,
        }
    }

    fn session(&self) -> Egress<SystemResolver, TcpDialer, ProcHostAddrs> {
        Egress {
            resolver: Arc::new(session_resolver(&self.lookup)),
            dialer: Arc::clone(&self.dialer),
            host: Arc::clone(&self.host),
            roots: self.roots.clone(),
            secrets: Arc::clone(&self.secrets),
        }
    }
}

impl EgressStarter for SharedEgress {
    fn prepare(&self, dir: &Path, s: SessionEgress) -> Result<SessionEgress, EgressError> {
        self.session().prepare(dir, s)
    }

    fn start(&self, sock: &Path, s: SessionEgress) -> io::Result<EgressHandle> {
        self.session().start(sock, s)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::egress::server::Resolver;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn a_session_gets_a_quarter_of_the_daemons_lookups() {
        assert_eq!(SESSION_LOOKUPS * 4, MAX_LOOKUPS);
        assert_eq!(SESSION_LOOKUPS, 16);
    }

    /// Each session's egress resolves through the starter's own lookup (not a default one).
    #[test]
    fn a_session_egress_uses_the_starters_lookup() {
        crate::daemon::runtime().unwrap().block_on(async {
            let (inner, _release, _) = stuck();
            let starter = SharedEgress::new(inner, Arc::new(NoSecrets));
            assert!(format!("{starter:?}").starts_with("SharedEgress"));
            let got = starter
                .session()
                .resolver
                .resolve("fast.test", 443)
                .await
                .unwrap();
            assert_eq!(got, [SocketAddr::from(([192, 0, 2, 1], 443))]);
        });
    }

    /// PR A's production source holds no value: every grant is refused `secret-missing`.
    #[test]
    fn no_secrets_holds_no_value() {
        let got = NoSecrets.load(&["GH".into()]).unwrap();
        assert!(got.is_empty());
    }

    /// Each session's egress reads secrets through the starter's own source.
    #[test]
    fn a_session_egress_uses_the_starters_secret_source() {
        let src: Arc<dyn SecretSource> = Arc::new(crate::egress::inject::testing::Fixed::default());
        let starter =
            SharedEgress::new(Arc::new(crate::egress::net::getaddrinfo), Arc::clone(&src));
        assert!(Arc::ptr_eq(&starter.session().secrets, &src));
    }

    /// A lookup that blocks until released (names starting with `slow`) and answers at once
    /// otherwise. The counter is how many slow lookups are inside it, every permit held.
    fn stuck() -> (Lookup, mpsc::Sender<()>, Arc<AtomicUsize>) {
        let (tx, rx) = mpsc::channel::<()>();
        let rx = Arc::new(Mutex::new(rx));
        let entered = Arc::new(AtomicUsize::new(0));
        let inside = Arc::clone(&entered);
        let lookup: Lookup = Arc::new(move |name: &str, _port: u16| {
            if name.starts_with("slow") {
                inside.fetch_add(1, Ordering::SeqCst);
                let _ = rx.lock().unwrap().recv();
            }
            Ok(vec![SocketAddr::from(([192, 0, 2, 1], 443))])
        });
        (lookup, tx, entered)
    }

    /// Waits until `n` slow lookups are inside, or fails after 10 s.
    async fn entered(count: &AtomicUsize, n: usize) {
        let end = tokio::time::Instant::now() + Duration::from_secs(10);
        while count.load(Ordering::SeqCst) < n {
            assert!(
                tokio::time::Instant::now() < end,
                "{n} lookups never started"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    /// #47: session 1 saturates its share; its next lookup fails at once while session 2 still
    /// resolves. Runs on the daemon's own runtime builder (architect Q44).
    #[test]
    fn one_session_cannot_take_another_sessions_lookups() {
        crate::daemon::runtime().unwrap().block_on(async {
            let (inner, release, inside) = stuck();
            let lookup = globally_bounded(Arc::new(Semaphore::new(MAX_LOOKUPS)), inner);
            let (s1, s2) = (
                Arc::new(session_resolver(&lookup)),
                session_resolver(&lookup),
            );
            let mut held = Vec::new();
            for _ in 0..SESSION_LOOKUPS {
                let r = Arc::clone(&s1);
                held.push(tokio::spawn(
                    async move { r.resolve("slow.test", 443).await },
                ));
            }
            entered(&inside, SESSION_LOOKUPS).await;
            let e = s1.resolve("fast.test", 443).await.unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::WouldBlock, "{e}");
            assert_eq!(s2.resolve("fast.test", 443).await.unwrap().len(), 1);
            for _ in 0..SESSION_LOOKUPS {
                release.send(()).unwrap();
            }
            drop(release);
            for h in held {
                assert!(h.await.unwrap().is_ok());
            }
            // Released: session 1 resolves again.
            assert!(s1.resolve("fast.test", 443).await.is_ok());
        });
    }

    /// The daemon-wide bound still holds: with every global slot held across four sessions, a
    /// fifth session's lookup is refused at once.
    #[test]
    fn the_global_bound_holds_across_sessions() {
        crate::daemon::runtime().unwrap().block_on(async {
            let (inner, release, inside) = stuck();
            let lookup = globally_bounded(Arc::new(Semaphore::new(MAX_LOOKUPS)), inner);
            let mut held = Vec::new();
            for _ in 0..4 {
                let r = Arc::new(session_resolver(&lookup));
                for _ in 0..SESSION_LOOKUPS {
                    let r = Arc::clone(&r);
                    held.push(tokio::spawn(
                        async move { r.resolve("slow.test", 443).await },
                    ));
                }
            }
            entered(&inside, MAX_LOOKUPS).await;
            let fifth = session_resolver(&lookup);
            let e = fifth.resolve("fast.test", 443).await.unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::WouldBlock, "{e}");
            assert!(e.to_string().contains("daemon"), "{e}");
            for _ in 0..MAX_LOOKUPS {
                release.send(()).unwrap();
            }
            // A lookup that starts only now returns at once: a wrong share fails the test
            // below instead of hanging it.
            drop(release);
            for h in held {
                assert!(h.await.unwrap().is_ok());
            }
            assert!(fifth.resolve("fast.test", 443).await.is_ok());
        });
    }
}
