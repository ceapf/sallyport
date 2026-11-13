//! Fake network side of the egress proxy for container tests (Task 8 decision 10): the launcher
//! gets them through `LauncherParts::egress`, the same constructor seam production fills with the
//! system resolver and TCP dialer. No test-only code path exists in `sallyd`.
//!
//! The upstream is an in-process echo server: no packet leaves the host. Addresses are built with
//! `Ipv4Addr::new` (the guard hooks refuse dotted IPv4 literals).

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sallyd::egress::net::Egress;
use sallyd::egress::server::{Dialer, HostAddrs, Resolver};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, DuplexStream};

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

/// The address a name must resolve to for its upstream to speak TLS (Task 9a-2).
pub fn tls_upstream() -> IpAddr {
    public(200)
}

/// Connects every pinned address to an in-process server: [`tls_upstream`] to a TLS mock HTTP
/// server presenting [`Pki::server`], any other to an echo server. Records the attempts and the
/// requests the TLS server received.
pub struct Upstream {
    dials: Mutex<Vec<SocketAddr>>,
    seen: Arc<Mutex<Vec<String>>>,
    /// The test PKI the TLS server uses.
    pub pki: Pki,
}

impl Upstream {
    /// Every address dialled so far, in order.
    pub fn dials(&self) -> Vec<SocketAddr> {
        self.dials.lock().unwrap().clone()
    }

    /// Every request (head and body) the TLS server received, in order.
    pub fn seen(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }
}

impl Dialer for Upstream {
    type Stream = DuplexStream;
    async fn dial(&self, to: SocketAddr) -> io::Result<DuplexStream> {
        self.dials.lock().unwrap().push(to);
        let (near, mut far) = tokio::io::duplex(64 * 1024);
        if to.ip() == tls_upstream() {
            let (cfg, seen) = (Arc::clone(&self.pki.server), Arc::clone(&self.seen));
            tokio::spawn(serve_tls(far, cfg, seen));
            return Ok(near);
        }
        tokio::spawn(async move {
            let (mut r, mut w) = tokio::io::split(&mut far);
            let _ = tokio::io::copy(&mut r, &mut w).await;
            let _ = w.shutdown().await;
        });
        Ok(near)
    }
}

/// A test CA and one leaf for `mock.test`, `*.mock.test`, `mock2.test` and `mock3.test`, as an
/// upstream would
/// have; the CA is the only certificate in the roots file the starter loads.
pub struct Pki {
    /// The CA certificate (PEM), as written to the roots file.
    pub ca_pem: String,
    /// The leaf the TLS upstream presents.
    pub leaf: CertificateDer<'static>,
    /// Its server configuration.
    pub server: Arc<rustls::ServerConfig>,
}

impl Pki {
    fn new() -> Self {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
        let ca_key = KeyPair::generate().unwrap();
        let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.distinguished_name
            .push(DnType::CommonName, "Test upstream CA");
        let ca_cert = ca.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca, ca_key);
        let leaf_key = KeyPair::generate().unwrap();
        let names = ["mock.test", "*.mock.test", "mock2.test", "mock3.test"].map(str::to_owned);
        let leaf = CertificateParams::new(names.to_vec())
            .unwrap()
            .signed_by(&leaf_key, &issuer)
            .unwrap();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let server = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![leaf.der().clone()], key)
        .unwrap();
        Self {
            ca_pem: ca_cert.pem(),
            leaf: leaf.der().clone(),
            server: Arc::new(server),
        }
    }
}

/// The TLS mock HTTP server: one request at a time; `/echo-headers` returns the request it got
/// as its body and the request's `Authorization` value in an `X-Echo-Authorization` header
/// (RT-SEC-06), `/redirect` a 302 to `https://mock2.test/echo-headers`, `/echo-gzip` a
/// gzip-encoded body, `/echo-forms` the encodings of `GIT_TOKEN` chunked ([`echo_forms`],
/// RT-SEC-12), anything else `ok`.
async fn serve_tls(
    far: DuplexStream,
    cfg: Arc<rustls::ServerConfig>,
    seen: Arc<Mutex<Vec<String>>>,
) {
    let Ok(mut tls) = tokio_rustls::TlsAcceptor::from(cfg).accept(far).await else {
        return;
    };
    let mut buf = Vec::new();
    while let Some(req) = read_request(&mut tls, &mut buf).await {
        seen.lock().unwrap().push(req.clone());
        let path = req.split(' ').nth(1).unwrap_or("/");
        if path == "/echo-forms" {
            if echo_forms(&mut tls, &req).await.is_err() {
                return;
            }
            continue;
        }
        let (status, extra, body) = match path {
            "/echo-headers" => {
                let auth = req
                    .split("\r\n")
                    .find_map(|l| {
                        let (n, v) = l.split_once(':')?;
                        n.eq_ignore_ascii_case("authorization").then(|| v.trim())
                    })
                    .map(|v| format!("X-Echo-Authorization: {v}\r\n"))
                    .unwrap_or_default();
                ("200 OK", auth, req.clone())
            }
            "/redirect" => (
                "302 Found",
                "Location: https://mock2.test/echo-headers\r\n".into(),
                String::new(),
            ),
            "/echo-gzip" => (
                "200 OK",
                "Content-Encoding: gzip\r\n".into(),
                "GZIPPED".into(),
            ),
            _ => ("200 OK", String::new(), "ok".into()),
        };
        let resp = format!(
            "HTTP/1.1 {status}\r\n{extra}Content-Length: {}\r\n\r\n{body}",
            body.len()
        );
        if tls.write_all(resp.as_bytes()).await.is_err() || tls.flush().await.is_err() {
            return;
        }
    }
}

/// The size of each chunk `/echo-forms` sends (RT-SEC-12: every form is split across chunks).
pub const FORMS_CHUNK: usize = 5;

/// RT-SEC-12's `/echo-forms`: [`super::forms::echo_body`] for `GIT_TOKEN`'s canary and the
/// `Basic` credential the request carried, chunked in [`FORMS_CHUNK`]-byte chunks, each written
/// and flushed on its own.
async fn echo_forms<S: AsyncWriteExt + Unpin>(tls: &mut S, req: &str) -> io::Result<()> {
    let blob = req
        .split("\r\n")
        .find_map(|l| {
            let (n, v) = l.split_once(':')?;
            n.eq_ignore_ascii_case("authorization").then(|| v.trim())
        })
        .and_then(|v| v.strip_prefix("Basic "))
        .unwrap_or_default();
    let body = super::forms::echo_body(&canary("GIT_TOKEN"), blob, req);
    tls.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
        .await?;
    for chunk in body.as_bytes().chunks(FORMS_CHUNK) {
        tls.write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
            .await?;
        tls.write_all(chunk).await?;
        tls.write_all(b"\r\n").await?;
        tls.flush().await?;
    }
    tls.write_all(b"0\r\n\r\n").await?;
    tls.flush().await
}

/// One request (head, and a `Content-Length` body) from `s`.
async fn read_request<S: AsyncRead + Unpin>(s: &mut S, buf: &mut Vec<u8>) -> Option<String> {
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end + 4]).to_ascii_lowercase();
            let n = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length: "))
                .map_or(0, |v| v.trim().parse::<usize>().unwrap_or(0));
            if buf.len() >= end + 4 + n {
                let req: Vec<u8> = buf.drain(..end + 4 + n).collect();
                return Some(String::from_utf8_lossy(&req).into_owned());
            }
        }
        let mut chunk = [0u8; 4096];
        match s.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
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

/// The secrets the fixtures' store holds (the names the test manifests grant).
pub const STORED: [&str; 3] = ["GITHUB_TOKEN", "MOCK3_TOKEN", "GIT_TOKEN"];

/// The canary value the fixtures' store holds for `name`: assembled at runtime, so no
/// credential-shaped literal is in the tree; `CANARY` makes it easy to grep for (RT-SEC-07).
/// `GIT_TOKEN`'s also holds characters a percent-encoder escapes (`/ + ? & = %` and a space),
/// so each percent spelling differs from the raw value (architect ruling A4); none of the
/// canaries holds `*`, so a session's filler is `*`.
pub fn canary(name: &str) -> String {
    let base = format!("SALLY_CANARY_{name}_{}", "c0ffee".repeat(4));
    if name == "GIT_TOKEN" {
        format!("{base}/a+b c?d&e=f%g")
    } else {
        base
    }
}

/// The production secrets store file, 0600 in a 0700 directory of its own (`egress-secrets`,
/// so no test that makes its own `secrets` directory collides), holding [`canary`] for each of
/// [`STORED`] (architect D12: container tests use the production source).
pub fn canary_store(dir: &Path) -> std::path::PathBuf {
    let sub = dir.join("egress-secrets");
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = sub.join("secrets.toml");
    let mut store = sally_core::secrets::SecretStore::empty(path.clone());
    for name in STORED {
        store.set(name, canary(name)).unwrap();
    }
    store.save().unwrap();
    path
}

/// A starter with no names, the echo and TLS upstreams, no own addresses, as trust roots the
/// test CA only: written to `dir/upstream-ca.pem` (0644, owned by the test user, the owner the
/// starter is built to require; production passes the system bundle and uid 0), and as secrets
/// source the production store file at [`canary_store`].
pub fn fake_egress(dir: &Path) -> Arc<FakeEgress> {
    let pki = Pki::new();
    let roots = dir.join("upstream-ca.pem");
    std::fs::write(&roots, &pki.ca_pem).unwrap();
    std::fs::set_permissions(&roots, std::fs::Permissions::from_mode(0o644)).unwrap();
    let secrets = canary_store(dir);
    Arc::new(Egress {
        resolver: Arc::new(Names::default()),
        dialer: Arc::new(Upstream {
            dials: Mutex::default(),
            seen: Arc::default(),
            pki,
        }),
        host: Arc::new(Owned::default()),
        roots: sallyd::egress::roots::BundleFiles {
            paths: vec![roots],
            owner: rustix::process::getuid().as_raw(),
        },
        secrets: Arc::new(sallyd::egress::inject::StoreFile { path: secrets }),
    })
}
