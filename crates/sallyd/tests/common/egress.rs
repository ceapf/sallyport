//! Fake network side of the egress proxy for container tests (Task 8 decision 10): the launcher
//! gets them through `LauncherParts::egress`, the same constructor seam production fills with the
//! system resolver and TCP dialer. No test-only code path exists in `sallyd`.
//!
//! The upstream is an in-process echo server: no packet leaves the host. Addresses are built with
//! `Ipv4Addr::new` (the guard hooks refuse dotted IPv4 literals).

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use sallyd::egress::net::Egress;
use sallyd::egress::server::{Dialer, HostAddrs, Resolver};
use tokio::io::{AsyncWriteExt, DuplexStream};

/// A globally routed address for fake answers.
pub fn public(n: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(93, 184, 215, n))
}

/// Answers per name, one list per lookup (the last repeats); records every lookup.
#[derive(Default)]
pub struct Names {
    answers: Mutex<HashMap<String, Vec<Vec<IpAddr>>>>,
    lookups: Mutex<Vec<String>>,
}

impl Names {
    /// Sets the answers for `host`, one list per lookup.
    pub fn set(&self, host: &str, answers: Vec<Vec<IpAddr>>) {
        self.answers
            .lock()
            .unwrap()
            .insert(host.to_owned(), answers);
    }

    /// Every name looked up so far, in order.
    pub fn lookups(&self) -> Vec<String> {
        self.lookups.lock().unwrap().clone()
    }
}

impl Resolver for Names {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let n = {
            let mut l = self.lookups.lock().unwrap();
            l.push(host.to_owned());
            l.iter().filter(|h| *h == host).count()
        };
        let answers = self.answers.lock().unwrap();
        let list = answers.get(host).ok_or(io::ErrorKind::NotFound)?;
        let pick = list.get(n - 1).or(list.last()).cloned().unwrap_or_default();
        Ok(pick
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect())
    }
}

/// Connects every pinned address to an in-process echo server; records the attempts.
#[derive(Default)]
pub struct Upstream {
    dials: Mutex<Vec<SocketAddr>>,
}

impl Upstream {
    /// Every address dialled so far, in order.
    pub fn dials(&self) -> Vec<SocketAddr> {
        self.dials.lock().unwrap().clone()
    }
}

impl Dialer for Upstream {
    type Stream = DuplexStream;
    async fn dial(&self, to: SocketAddr) -> io::Result<DuplexStream> {
        self.dials.lock().unwrap().push(to);
        let (near, mut far) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let (mut r, mut w) = tokio::io::split(&mut far);
            let _ = tokio::io::copy(&mut r, &mut w).await;
            let _ = w.shutdown().await;
        });
        Ok(near)
    }
}

/// The host's own addresses, as the test sets them.
#[derive(Default)]
pub struct Owned(Mutex<Vec<IpAddr>>);

impl Owned {
    /// Replaces the list.
    pub fn set(&self, ips: Vec<IpAddr>) {
        *self.0.lock().unwrap() = ips;
    }
}

impl HostAddrs for Owned {
    async fn own(&self) -> io::Result<Vec<IpAddr>> {
        Ok(self.0.lock().unwrap().clone())
    }
}

/// The starter the fixtures hand the launcher.
pub type FakeEgress = Egress<Names, Upstream, Owned>;

/// A starter with no names, an echo upstream and no own addresses.
pub fn fake_egress() -> Arc<FakeEgress> {
    Arc::new(Egress {
        resolver: Arc::new(Names::default()),
        dialer: Arc::new(Upstream::default()),
        host: Arc::new(Owned::default()),
    })
}
