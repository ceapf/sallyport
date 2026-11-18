//! One connection to one Hub host: resolved on this host, every address checked, a pinned
//! address dialled, then TLS verified for that host name against the anchors of a checked CA
//! bundle file (production: the system bundle owned by root, through
//! [`crate::egress::roots::BundleFiles`]).
//!
//! The rule is the egress proxy's (SI-9's reason applies to `sallyd`'s own credential-carrying
//! connection): one lookup, at most [`MAX_ANSWER`] answers; if any answer is loopback, private,
//! link-local or one of this host's own addresses, nothing is dialled; otherwise at most
//! [`MAX_DIALS`] of the answers are tried in order, each by address, never by name. The host
//! name only chooses the certificate the server must present.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use super::PullError;
use crate::egress::addr;
use crate::egress::server::{Dialer, HostAddrs, MAX_ANSWER, MAX_DIALS, Resolver};

/// Longest wait for the lookup.
pub const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);
/// Longest wait for one connect.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest wait for the TLS handshake.
pub const TLS_TIMEOUT: Duration = Duration::from_secs(10);
/// The only port.
const HTTPS_PORT: u16 = 443;

/// The pinned addresses for `host`, or the refusal.
pub(super) async fn pinned<R: Resolver, H: HostAddrs>(
    resolver: &R,
    own: &H,
    host: &str,
) -> Result<Vec<SocketAddr>, PullError> {
    let own = own
        .own()
        .await
        .map_err(|_| PullError::AddressDenied(host.to_owned()))?;
    let lookup = resolver.resolve(host, HTTPS_PORT);
    let found = match tokio::time::timeout(RESOLVE_TIMEOUT, lookup).await {
        Ok(Ok(found)) if !found.is_empty() && found.len() <= MAX_ANSWER => found,
        _ => return Err(PullError::ResolveFailed(host.to_owned())),
    };
    if found.iter().any(|s| addr::is_denied(s.ip(), &own)) {
        return Err(PullError::AddressDenied(host.to_owned()));
    }
    Ok(found
        .iter()
        .take(MAX_DIALS)
        .map(|s| SocketAddr::new(s.ip(), HTTPS_PORT))
        .collect())
}

/// The first of `addrs` that connects in time.
pub(super) async fn dial<D: Dialer>(
    dialer: &D,
    addrs: &[SocketAddr],
    host: &str,
) -> Result<D::Stream, PullError> {
    for a in addrs {
        if let Ok(Ok(s)) = tokio::time::timeout(CONNECT_TIMEOUT, dialer.dial(*a)).await {
            return Ok(s);
        }
    }
    Err(PullError::ConnectFailed(host.to_owned()))
}

/// TLS over `stream`, verified for `host`.
pub(super) async fn tls<S: AsyncRead + AsyncWrite + Unpin>(
    config: &Arc<rustls::ClientConfig>,
    stream: S,
    host: &str,
) -> Result<TlsStream<S>, PullError> {
    let name =
        ServerName::try_from(host.to_owned()).map_err(|_| PullError::TlsFailed(host.to_owned()))?;
    let handshake = TlsConnector::from(Arc::clone(config)).connect(name, stream);
    match tokio::time::timeout(TLS_TIMEOUT, handshake).await {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(_)) => Err(PullError::TlsFailed(host.to_owned())),
        Err(_) => Err(PullError::Timeout("TLS handshake")),
    }
}

/// The client TLS configuration: the anchors [`super::HfClient::with_roots`] loaded, the ring
/// provider's safe defaults, HTTP/1.1 only, no client certificate.
///
/// # Errors
/// rustls's, if it refuses the provider's protocol versions.
pub(super) fn client_config(
    roots: Arc<rustls::RootCertStore>,
) -> Result<Arc<rustls::ClientConfig>, rustls::Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut c = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    c.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(c))
}
