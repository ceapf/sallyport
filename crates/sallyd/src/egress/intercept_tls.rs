//! The TLS setup of intercepted tunnels (Task 9a; moved out of `intercept.rs`, #73): the session
//! CA's leaves toward the client and the verifying client configuration toward the upstream.
//!
//! Toward the client: one server configuration per grant host, presenting that host's leaf, ALPN
//! `http/1.1` only (decision 4). Toward the upstream: rustls defaults (TLS 1.2 and 1.3), the
//! session's upstream trust roots, ALPN `http/1.1`. The session CA is never an upstream trust
//! anchor.

use std::collections::BTreeSet;
use std::sync::Arc;

use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use rustls::{ClientConfig, ServerConfig};

use super::super::ca::{CaError, Leaf, SessionTls};
use super::super::inject::Credentials;
use super::super::roots::Roots;

/// The only ALPN protocol offered either way (decision 4).
const HTTP_1_1: &[u8] = b"http/1.1";

/// What the proxy intercepts grant hosts with (Task 9a): the session CA's leaves, the upstream
/// trust roots, the TLS configurations built from them, and the grants' credentials with their
/// redaction (Task 9a-3). Every leaf host has a credential and every credential a leaf.
#[derive(Debug)]
pub struct Interception {
    /// The session CA and one leaf per grant host; the CA key is already gone.
    pub tls: SessionTls,
    /// The upstream verifier's roots.
    pub roots: Roots,
    upstream: Arc<ClientConfig>,
    servers: Vec<(String, Arc<ServerConfig>)>,
    credentials: Arc<Credentials>,
}

impl Interception {
    /// Builds the upstream client configuration (rustls defaults: TLS 1.2 and 1.3, the given
    /// roots, ALPN `http/1.1`) and one server configuration per leaf, and takes the credentials.
    ///
    /// # Errors
    /// [`CaError::Unmatched`] when the leaves and the credentials name different hosts;
    /// [`CaError::Generate`] when rustls refuses a configuration or a leaf.
    pub fn new(tls: SessionTls, roots: Roots, credentials: Credentials) -> Result<Self, CaError> {
        Self::build(tls, roots, credentials)
    }

    /// [`Self::new`]'s work, in a function cargo-mutants mutates (it leaves `new` alone; #87).
    fn build(tls: SessionTls, roots: Roots, credentials: Credentials) -> Result<Self, CaError> {
        hosts_match(&tls, &credentials)?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut upstream = ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .map_err(tls_error)?
            .with_root_certificates(Arc::clone(&roots.store))
            .with_no_client_auth();
        upstream.alpn_protocols = vec![HTTP_1_1.to_vec()];
        let mut servers = Vec::with_capacity(tls.leaves.len());
        for leaf in &tls.leaves {
            let mut cfg = ServerConfig::builder_with_provider(Arc::clone(&provider))
                .with_safe_default_protocol_versions()
                .map_err(tls_error)?
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified(leaf)?)));
            cfg.alpn_protocols = vec![HTTP_1_1.to_vec()];
            servers.push((leaf.host.clone(), Arc::new(cfg)));
        }
        Ok(Self {
            tls,
            roots,
            upstream: Arc::new(upstream),
            servers,
            credentials: Arc::new(credentials),
        })
    }

    /// The credentials and their redaction; a weak handle shows when they are gone.
    #[must_use]
    pub fn credentials(&self) -> &Arc<Credentials> {
        &self.credentials
    }

    /// The server configuration presenting `host`'s leaf, if the session CA made one.
    #[must_use]
    pub fn server(&self, host: &str) -> Option<Arc<ServerConfig>> {
        self.servers
            .iter()
            .find(|(h, _)| h == host)
            .map(|(_, c)| Arc::clone(c))
    }

    /// What intercepting `host` takes, if the session CA made its leaf.
    pub(super) fn host_tls(&self, host: &str) -> Option<HostTls> {
        Some(HostTls {
            server: self.server(host)?,
            upstream: Arc::clone(&self.upstream),
            credentials: Arc::clone(&self.credentials),
        })
    }
}

/// What a cleared grant host is intercepted with: its leaf toward the client, the verifying
/// client configuration toward the upstream, and the session's credentials.
pub(super) struct HostTls {
    pub(super) server: Arc<ServerConfig>,
    pub(super) upstream: Arc<ClientConfig>,
    pub(super) credentials: Arc<Credentials>,
}

/// Every leaf host has a credential and every credential a leaf (architect D10). Outside
/// `Interception::new`, so cargo-mutants mutates it.
fn hosts_match(tls: &SessionTls, credentials: &Credentials) -> Result<(), CaError> {
    let leaves: BTreeSet<&str> = tls.leaves.iter().map(|l| l.host.as_str()).collect();
    let granted: BTreeSet<&str> = credentials.hosts().into_iter().collect();
    if leaves == granted {
        Ok(())
    } else {
        Err(CaError::Unmatched)
    }
}

/// The leaf and its signing key, read from the leaf's DER key in place (architect ruling R7):
/// the proxy makes no copy of the key bytes of its own; the only plain copy outside ring is the
/// leaf's `Secret`, wiped when the session ends. ring's parsed key and rustls's objects built
/// from it are freed, not wiped (THREAT_MODEL, Session CA limits (3); TODO(#69)).
fn certified(leaf: &Leaf) -> Result<CertifiedKey, CaError> {
    let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf.key.expose().as_slice()));
    let key = rustls::crypto::ring::sign::any_supported_type(&der).map_err(tls_error)?;
    let ck = CertifiedKey::new(vec![leaf.cert.clone()], key);
    ck.keys_match().map_err(tls_error)?;
    Ok(ck)
}

fn tls_error(e: rustls::Error) -> CaError {
    CaError::Generate(e.to_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::time::{Duration, SystemTime};

    use rustls::RootCertStore;

    use super::*;
    use crate::egress::ca::Validity;
    use crate::egress::inject::testing::credentials;

    fn mint(hosts: &[&str]) -> SessionTls {
        let v = Validity::for_session(SystemTime::now(), Duration::from_secs(600)).unwrap();
        let hosts: Vec<String> = hosts.iter().map(|h| (*h).to_owned()).collect();
        SessionTls::mint(&hosts, v).unwrap()
    }

    /// Architect D10: every leaf host has a credential and every credential a leaf.
    #[test]
    fn leaves_and_credentials_must_name_the_same_hosts() {
        let both = ["a.mock.test", "b.mock.test"];
        let i = Interception::new(mint(&both), roots(), credentials(&both)).unwrap();
        assert_eq!(i.credentials().hosts(), both);
        assert!(i.host_tls("a.mock.test").is_some());
        assert!(i.host_tls("c.mock.test").is_none());
        for (leaves, granted) in [
            (&both[..], &both[..1]),
            (&both[..1], &both[..]),
            (&["a.mock.test"][..], &["c.mock.test"][..]),
        ] {
            assert!(matches!(
                Interception::new(mint(leaves), roots(), credentials(granted)),
                Err(CaError::Unmatched)
            ));
        }
    }

    fn roots() -> Roots {
        Roots {
            store: Arc::new(RootCertStore::empty()),
            pem: String::new(),
            skipped: 0,
            path: "/test-roots.pem".into(),
        }
    }

    /// Architect ruling R7: each leaf's signer is built from its key in place, and a key that
    /// does not belong to its certificate is refused (as `with_single_cert` refused it before).
    #[test]
    fn a_leaf_whose_key_is_not_its_certificates_is_refused() {
        let hosts = ["a.mock.test", "b.mock.test"];
        assert!(Interception::new(mint(&hosts), roots(), credentials(&hosts)).is_ok());
        let mut swapped = mint(&hosts);
        let (a, b) = swapped.leaves.split_at_mut(1);
        std::mem::swap(&mut a[0].key, &mut b[0].key);
        assert!(matches!(
            Interception::new(swapped, roots(), credentials(&hosts)),
            Err(CaError::Generate(_))
        ));
    }
}
