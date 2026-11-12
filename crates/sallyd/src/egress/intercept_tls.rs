//! The TLS setup of intercepted tunnels (Task 9a; moved out of `intercept.rs`, #73): the session
//! CA's leaves toward the client and the verifying client configuration toward the upstream.
//!
//! Toward the client: one server configuration per grant host, presenting that host's leaf, ALPN
//! `http/1.1` only (decision 4). Toward the upstream: rustls defaults (TLS 1.2 and 1.3), the
//! session's upstream trust roots, ALPN `http/1.1`. The session CA is never an upstream trust
//! anchor.

use std::sync::Arc;

use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use rustls::{ClientConfig, ServerConfig};

use super::super::ca::{CaError, Leaf, SessionTls};
use super::super::roots::Roots;

/// The only ALPN protocol offered either way (decision 4).
const HTTP_1_1: &[u8] = b"http/1.1";

/// What the proxy intercepts grant hosts with (Task 9a): the session CA's leaves and the upstream
/// trust roots, and the TLS configurations built from them. It holds no secret store and no
/// credential (architect Q27 (1)).
#[derive(Debug)]
pub struct Interception {
    /// The session CA and one leaf per grant host; the CA key is already gone.
    pub tls: SessionTls,
    /// The upstream verifier's roots.
    pub roots: Roots,
    upstream: Arc<ClientConfig>,
    servers: Vec<(String, Arc<ServerConfig>)>,
}

impl Interception {
    /// Builds the upstream client configuration (rustls defaults: TLS 1.2 and 1.3, the given
    /// roots, ALPN `http/1.1`) and one server configuration per leaf.
    ///
    /// # Errors
    /// [`CaError::Generate`] when rustls refuses a configuration or a leaf.
    pub fn new(tls: SessionTls, roots: Roots) -> Result<Self, CaError> {
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
        })
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
        })
    }
}

/// The TLS configurations a cleared grant host is intercepted with: its leaf toward the client,
/// the verifying client configuration toward the upstream.
pub(super) struct HostTls {
    pub(super) server: Arc<ServerConfig>,
    pub(super) upstream: Arc<ClientConfig>,
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
        let v = Validity::for_session(SystemTime::now(), Duration::from_secs(600)).unwrap();
        let hosts = ["a.mock.test".to_owned(), "b.mock.test".to_owned()];
        assert!(Interception::new(SessionTls::mint(&hosts, v).unwrap(), roots()).is_ok());
        let mut swapped = SessionTls::mint(&hosts, v).unwrap();
        let (a, b) = swapped.leaves.split_at_mut(1);
        std::mem::swap(&mut a[0].key, &mut b[0].key);
        assert!(matches!(
            Interception::new(swapped, roots()),
            Err(CaError::Generate(_))
        ));
    }
}
