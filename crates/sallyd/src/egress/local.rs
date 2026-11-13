//! Broker-originated connections into a session's proxy: the `fetch` tool's way out (#75;
//! architect rulings Q1, Q2 and Q7).
//!
//! `fetch` is a client of the session's own [`Proxy`](super::server::Proxy): it opens an
//! in-memory stream with a [`Connector`], sends `CONNECT`, and speaks TLS and HTTP/1.1 inside the
//! tunnel like any workspace client. The stream is handed to the session's accept loop
//! (`net.rs`), so it takes an in-flight slot, is served like an accepted stream and gets the same
//! grace at a stop; every check, every `egress.*` entry, the request rewrite, the injection, the
//! redaction and the caps run in the proxy's own code, unchanged. One copy of the policy.
//!
//! - **Origin.** Every `egress.*` entry of such a connection carries `origin` (for `fetch`,
//!   `{"tool": "fetch", "call": N}`); entries of accepted connections have none. The accept loop
//!   serves the stream inside [`ORIGIN`]'s scope, and the proxy takes its audit sink through
//!   [`sink`], which tags each entry while it is built, on the connection's task.
//! - **TLS toward the proxy** ([`ClientTls::choose`]): a host the session CA has a leaf for is
//!   intercepted, so the client trusts the session CA only; any other host is spliced, so the
//!   client verifies the real upstream against the session's upstream trust roots only. Never a
//!   union of the two: the wrong choice fails the handshake either way.

use std::io;
use std::sync::Arc;

use rustls::ClientConfig;
use sally_core::audit::{AuditError, NewEntry};
use sally_core::manifest::AuditLevel;
use serde_json::{Map, Value};
use tokio::io::DuplexStream;
use tokio::sync::mpsc;

use super::ca::CaError;
use super::inject::Spec;
use super::policy::Policy;
use super::roots::Roots;
use super::server::{Interception, trusting, upstream_client};
use crate::sandbox::AuditSink;

/// Bytes buffered each way in an in-memory connection.
pub const LOCAL_BUFFER: usize = 65_536;
/// Connections opened but not yet taken by the accept loop.
pub const LOCAL_QUEUE: usize = 8;

/// One opened connection on its way to the accept loop: the proxy's half and its origin.
pub type Opened = (DuplexStream, Value);

tokio::task_local! {
    /// The origin of the connection a task serves (absent: an accepted connection).
    pub static ORIGIN: Value;
}

/// The proxy's audit sink for the connection on this task: `inner` itself for an accepted
/// connection, or one that adds the task's [`ORIGIN`] to every entry.
pub fn sink(inner: &Arc<dyn AuditSink>) -> Arc<dyn AuditSink> {
    match ORIGIN.try_with(Clone::clone) {
        Ok(origin) => Arc::new(Tagged {
            inner: Arc::clone(inner),
            origin,
        }),
        Err(_) => Arc::clone(inner),
    }
}

/// Adds `origin` to the arguments of every entry it passes on.
struct Tagged {
    inner: Arc<dyn AuditSink>,
    origin: Value,
}

impl AuditSink for Tagged {
    fn append(&self, entry: NewEntry, level: AuditLevel) -> Result<(), AuditError> {
        // Every egress entry has an object; anything else is kept whole under `args`.
        let mut args = match entry.arguments() {
            Value::Object(o) => o.clone(),
            Value::Null => Map::new(),
            other => Map::from_iter([("args".to_owned(), other.clone())]),
        };
        args.insert("origin".to_owned(), self.origin.clone());
        self.inner.append(entry.args(Value::Object(args)), level)
    }
}

/// The client TLS configurations of broker-originated connections.
#[derive(Debug, Clone)]
pub struct ClientTls {
    /// Verifies a spliced host against the session's upstream trust roots.
    upstream: Arc<ClientConfig>,
    /// Trusts the session CA only, with the hosts it has leaves for.
    session_ca: Option<(Arc<ClientConfig>, Vec<String>)>,
}

impl ClientTls {
    /// The configurations of a session: from its interception when it has one (the same
    /// upstream configuration the proxy verifies with, and one trusting its CA), else built from
    /// `roots`. `None` when the session has neither.
    ///
    /// # Errors
    /// [`CaError::Generate`] when rustls refuses a configuration.
    pub fn of(i: Option<&Interception>, roots: Option<&Roots>) -> Result<Option<Self>, CaError> {
        if let Some(i) = i {
            return Ok(Some(Self {
                upstream: Arc::clone(i.upstream()),
                session_ca: Some((trusting(&i.tls.ca)?, i.leaf_hosts())),
            }));
        }
        Ok(match roots {
            Some(r) => Some(Self {
                upstream: upstream_client(r)?,
                session_ca: None,
            }),
            None => None,
        })
    }

    /// The configuration to reach `host` through the proxy with.
    #[must_use]
    pub fn choose(&self, host: &str) -> Arc<ClientConfig> {
        match &self.session_ca {
            Some((cfg, hosts)) if hosts.iter().any(|h| h == host) => Arc::clone(cfg),
            _ => Arc::clone(&self.upstream),
        }
    }
}

/// What a request to one grant host gets, by name only: the header names the proxy drops from
/// the client (lower-case, from [`Policy::grant_headers`](super::policy::Policy::grant_headers))
/// and the credentials it injects (`secret:NAME`). Never a value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostGrants {
    /// The grant header names, lower-case.
    pub headers: Vec<String>,
    /// The injected credentials, `secret:NAME`.
    pub names: Vec<String>,
}

/// Opens broker-originated connections into one session's proxy. Dyn-compatible: the tools hold
/// `Arc<dyn Connector>`.
pub trait Connector: Send + Sync {
    /// Opens an in-memory connection; the accept loop serves it once an in-flight slot is free,
    /// and every `egress.*` entry of it carries `origin`.
    ///
    /// # Errors
    /// The session's proxy stopped, or [`LOCAL_QUEUE`] connections already wait.
    fn open(&self, origin: Value) -> io::Result<DuplexStream>;

    /// The client TLS configuration to reach `host` with ([`ClientTls::choose`]).
    fn client_tls(&self, host: &str) -> Arc<ClientConfig>;

    /// The grants of `host` (empty for a host without one).
    fn grants(&self, host: &str) -> HostGrants;
}

/// What a session's [`Local`] connector is built with: the client TLS configurations and the
/// grants of each grant host.
#[derive(Debug, Clone)]
pub struct Reach {
    /// The client TLS configurations.
    pub tls: ClientTls,
    /// Each grant host with its grants.
    pub grants: Vec<(String, HostGrants)>,
}

/// The connector of a session's accept loop.
#[derive(Debug, Clone)]
pub struct Local {
    tx: mpsc::Sender<Opened>,
    reach: Reach,
}

impl Local {
    /// A connector sending to `tx`, the accept loop's queue.
    #[must_use]
    pub fn new(tx: mpsc::Sender<Opened>, reach: Reach) -> Self {
        Self { tx, reach }
    }
}

impl Connector for Local {
    fn open(&self, origin: Value) -> io::Result<DuplexStream> {
        let (ours, theirs) = tokio::io::duplex(LOCAL_BUFFER);
        self.tx.try_send((theirs, origin)).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => io::Error::from(io::ErrorKind::WouldBlock),
            mpsc::error::TrySendError::Closed(_) => io::Error::from(io::ErrorKind::BrokenPipe),
        })?;
        Ok(ours)
    }

    fn client_tls(&self, host: &str) -> Arc<ClientConfig> {
        self.reach.tls.choose(host)
    }

    fn grants(&self, host: &str) -> HostGrants {
        self.reach
            .grants
            .iter()
            .find(|(h, _)| h == host)
            .map(|(_, g)| g.clone())
            .unwrap_or_default()
    }
}

/// The grants of every grant host of a session: header names from `policy`, credential names
/// from `specs` (each name once, in manifest order).
#[must_use]
pub fn host_grants(policy: &Policy, specs: &[Spec]) -> Vec<(String, HostGrants)> {
    let mut out: Vec<(String, HostGrants)> = Vec::new();
    for host in policy.grant_hosts() {
        if out.iter().any(|(h, _)| *h == host) {
            continue;
        }
        let mut names: Vec<String> = Vec::new();
        for s in specs.iter().filter(|s| s.host == host) {
            let n = format!("secret:{}", s.name);
            if !names.contains(&n) {
                names.push(n);
            }
        }
        let headers = policy.grant_headers(&host);
        out.push((host, HostGrants { headers, names }));
    }
    out
}

#[cfg(test)]
#[path = "local_tests.rs"]
mod tests;
