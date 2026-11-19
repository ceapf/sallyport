//! A mock Hub for the client's tests: one TLS server behind the [`Dialer`] seam (an in-memory
//! duplex stream; no listener of any kind), a resolver that answers whatever address a test
//! sets, an own-address list, a connected-network list, and a recorder of every lookup, dial and
//! request.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use sally_core::library::Library;
use sally_core::model::hash::{Digest, Hasher};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream, duplex};

use super::{HfClient, SharedLibrary};
use crate::egress::addr::{HostNets, Net};
use crate::egress::hostaddrs::HostAddrsError;
use crate::egress::roots::BundleFiles;
use crate::egress::scratch::{Scratch, scratch};
use crate::egress::server::{Dialer, HostAddrs, Resolver};

/// A public address (TEST-NET would be refused as reserved).
pub(super) const PUBLIC: IpAddr = IpAddr::V4(Ipv4Addr::new(93, 184, 215, 9));
/// The commit every mock list names.
pub(super) const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
/// The hosts the mock's certificate names.
const NAMES: [&str; 2] = ["huggingface.co", "cdn-lfs.hf.co"];
/// Longest request head the mock reads.
const MAX_HEAD: usize = 65_536;
/// In a reply, where the mock stops writing and never writes or closes again; it only waits for
/// the client to close the connection, and counts that ([`Hub::closed`]).
pub(super) const STALL: &[u8] = b"\0stall\0";

/// One request the mock received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Seen {
    /// The `Host` header.
    pub(super) host: String,
    /// The request target.
    pub(super) path: String,
    /// The `Range` header, if any.
    pub(super) range: Option<String>,
    /// The `Authorization` header, if any.
    pub(super) auth: Option<String>,
    /// The `Accept-Encoding` header, if any.
    pub(super) accept_encoding: Option<String>,
}

type Handler = Arc<dyn Fn(&Seen, usize) -> Vec<u8> + Send + Sync>;

/// The mock Hub and its recorder. Clones share everything.
#[derive(Clone)]
pub(super) struct Hub {
    server: Arc<rustls::ServerConfig>,
    roots: BundleFiles,
    bundles: Arc<Bundles>,
    handler: Handler,
    answer: Arc<Mutex<Vec<IpAddr>>>,
    own: Arc<Mutex<Vec<IpAddr>>>,
    connected: Arc<Mutex<Vec<Net>>>,
    lookups: Arc<Mutex<Vec<String>>>,
    dials: Arc<Mutex<usize>>,
    closed: Arc<Mutex<usize>>,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Hub {
    /// A Hub answering each request with `handler(request, index)`.
    pub(super) fn new(handler: impl Fn(&Seen, usize) -> Vec<u8> + Send + Sync + 'static) -> Self {
        let (ca_pem, server) = pki();
        let bundles = Bundles::new();
        Self {
            server,
            roots: bundles.write("roots.pem", &ca_pem),
            bundles: Arc::new(bundles),
            handler: Arc::new(handler),
            answer: Arc::new(Mutex::new(vec![PUBLIC])),
            own: Arc::new(Mutex::new(Vec::new())),
            connected: Arc::new(Mutex::new(Vec::new())),
            lookups: Arc::new(Mutex::new(Vec::new())),
            dials: Arc::new(Mutex::new(0)),
            closed: Arc::new(Mutex::new(0)),
            seen: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// A client over this Hub, with `token`.
    pub(super) fn client(&self, token: Option<&str>) -> HfClient<Self, Self, Self> {
        HfClient::with_roots(
            self.clone(),
            self.clone(),
            self.clone(),
            &self.roots,
            token.map(|t| sally_core::secrets::Secret::new(t.to_owned())),
        )
        .unwrap()
    }

    /// The bundle file holding the mock's CA, owned by this user at 0644.
    pub(super) fn roots(&self) -> &BundleFiles {
        &self.roots
    }

    /// The scratch directory the mock's bundle lives in, for other bundles a test writes.
    pub(super) fn bundles(&self) -> &Bundles {
        &self.bundles
    }

    /// Every lookup answers `ip` from now on.
    pub(super) fn answer(&self, ip: IpAddr) {
        self.answer_all(&[ip]);
    }

    /// Every lookup answers `ips`, in order, from now on.
    pub(super) fn answer_all(&self, ips: &[IpAddr]) {
        *self.answer.lock().unwrap() = ips.to_vec();
    }

    /// This host owns `ip` from now on.
    pub(super) fn own(&self, ip: IpAddr) {
        self.own.lock().unwrap().push(ip);
    }

    /// This host is directly connected to `net` from now on.
    pub(super) fn connected(&self, net: Net) {
        self.connected.lock().unwrap().push(net);
    }

    pub(super) fn lookups(&self) -> Vec<String> {
        self.lookups.lock().unwrap().clone()
    }

    pub(super) fn dials(&self) -> usize {
        *self.dials.lock().unwrap()
    }

    pub(super) fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    /// Stalled connections the client has closed.
    pub(super) fn closed(&self) -> usize {
        *self.closed.lock().unwrap()
    }

    async fn serve(&self, far: DuplexStream) {
        let Ok(mut tls) = tokio_rustls::TlsAcceptor::from(Arc::clone(&self.server))
            .accept(far)
            .await
        else {
            return;
        };
        let mut buf = Vec::new();
        let head = loop {
            if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break String::from_utf8_lossy(&buf[..end]).into_owned();
            }
            let mut chunk = [0_u8; 4096];
            match tls.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
            if buf.len() > MAX_HEAD {
                return;
            }
        };
        let seen = parse_head(&head);
        let index = {
            let mut all = self.seen.lock().unwrap();
            all.push(seen.clone());
            all.len() - 1
        };
        let resp = (self.handler)(&seen, index);
        let stall = resp.windows(STALL.len()).position(|w| w == STALL);
        let _ = tls.write_all(&resp[..stall.unwrap_or(resp.len())]).await;
        let _ = tls.flush().await;
        if stall.is_some() {
            let mut sink = [0_u8; 256];
            while matches!(tls.read(&mut sink).await, Ok(n) if n > 0) {}
            *self.closed.lock().unwrap() += 1;
            return;
        }
        let _ = tls.shutdown().await;
    }
}

impl Resolver for Hub {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        self.lookups.lock().unwrap().push(host.to_owned());
        let ips = self.answer.lock().unwrap().clone();
        Ok(ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect())
    }
}

impl Dialer for Hub {
    type Stream = DuplexStream;
    async fn dial(&self, _: SocketAddr) -> io::Result<DuplexStream> {
        *self.dials.lock().unwrap() += 1;
        let (near, far) = duplex(1 << 20);
        let hub = self.clone();
        tokio::spawn(async move { hub.serve(far).await });
        Ok(near)
    }
}

impl HostAddrs for Hub {
    async fn own(&self) -> Result<HostNets, HostAddrsError> {
        Ok(HostNets {
            own: self.own.lock().unwrap().clone(),
            connected: self.connected.lock().unwrap().clone(),
        })
    }
}

fn parse_head(head: &str) -> Seen {
    let mut lines = head.split("\r\n");
    let path = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .unwrap_or_default()
        .to_owned();
    let mut seen = Seen {
        host: String::new(),
        path,
        range: None,
        auth: None,
        accept_encoding: None,
    };
    for l in lines {
        let Some((k, v)) = l.split_once(": ") else {
            continue;
        };
        match k.to_ascii_lowercase().as_str() {
            "host" => seen.host = v.to_owned(),
            "range" => seen.range = Some(v.to_owned()),
            "authorization" => seen.auth = Some(v.to_owned()),
            "accept-encoding" => seen.accept_encoding = Some(v.to_owned()),
            _ => {}
        }
    }
    seen
}

/// CA bundle files minted at test time in a fresh scratch directory under `target/` (removed on
/// drop): each created new at 0644, never through a name someone else chose.
pub(super) struct Bundles(Scratch);

impl Bundles {
    pub(super) fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        Self(scratch("hf-roots", &n.to_string()))
    }

    /// `pem` written to a new file `name`, as the roots a client loads (owned by this user).
    pub(super) fn write(&self, name: &str, pem: &str) -> BundleFiles {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let path = self.0.join(name);
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&path)
            .unwrap()
            .write_all(pem.as_bytes())
            .unwrap();
        BundleFiles {
            paths: vec![path],
            owner: rustix::process::getuid().as_raw(),
        }
    }

    /// A path in the scratch directory that nothing creates.
    pub(super) fn absent(&self) -> PathBuf {
        self.0.join("absent.pem")
    }
}

/// A self-signed CA's key pair, parameters and PEM.
fn ca(name: &str) -> (KeyPair, CertificateParams, String) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name.push(DnType::CommonName, name);
    let pem = params.self_signed(&key).unwrap().pem();
    (key, params, pem)
}

/// The PEM of a CA unrelated to any Hub's.
pub(super) fn foreign_ca_pem() -> String {
    ca("unrelated CA").2
}

/// A CA (as PEM) and one leaf for the Hub's names.
fn pki() -> (String, Arc<rustls::ServerConfig>) {
    let (ca_key, ca, ca_pem) = ca("mock hub CA");
    let issuer = rcgen::Issuer::new(ca, ca_key);
    let leaf_key = KeyPair::generate().unwrap();
    let names: Vec<String> = NAMES.iter().map(|n| (*n).to_owned()).collect();
    let leaf = CertificateParams::new(names)
        .unwrap()
        .signed_by(&leaf_key, &issuer)
        .unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![leaf.der().clone()], key)
    .unwrap();
    (ca_pem, Arc::new(cfg))
}

/// A response: status line, the given header lines, a Content-Length for `body`, the body.
pub(super) fn reply(status: &str, headers: &[&str], body: &[u8]) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {status}\r\nConnection: close\r\n");
    for h in headers {
        out.push_str(h);
        out.push_str("\r\n");
    }
    out.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    let mut out = out.into_bytes();
    out.extend_from_slice(body);
    out
}

/// A response with the body sent as one chunk (no Content-Length).
pub(super) fn chunked(status: &str, headers: &[&str], body: &[u8]) -> Vec<u8> {
    let mut out =
        format!("HTTP/1.1 {status}\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n");
    for h in headers {
        out.push_str(h);
        out.push_str("\r\n");
    }
    out.push_str(&format!("\r\n{:x}\r\n", body.len()));
    let mut out = out.into_bytes();
    out.extend_from_slice(body);
    out.extend_from_slice(b"\r\n0\r\n\r\n");
    out
}

/// A 302 to `location`.
pub(super) fn found(location: &str) -> Vec<u8> {
    reply("302 Found", &[&format!("Location: {location}")], b"")
}

/// The file-list JSON naming each `(path, bytes)` with its size and SHA-256.
pub(super) fn list_json(files: &[(&str, &[u8])]) -> Vec<u8> {
    let siblings: Vec<String> = files
        .iter()
        .map(|(p, b)| {
            format!(
                r#"{{"rfilename":"{p}","size":{n},"lfs":{{"sha256":"{h}","size":{n}}}}}"#,
                n = b.len(),
                h = sha(b).as_hex()
            )
        })
        .collect();
    format!(r#"{{"sha":"{SHA}","siblings":[{}]}}"#, siblings.join(",")).into_bytes()
}

/// The SHA-256 of `bytes`.
pub(super) fn sha(bytes: &[u8]) -> Digest {
    let mut h = Hasher::default();
    h.update(bytes);
    h.finish()
}

/// A small valid GGUF v3 file: two string keys (the second is `tag`), one F32 tensor of 8.
pub(super) fn gguf(tag: &str) -> Vec<u8> {
    fn s(out: &mut Vec<u8>, v: &[u8]) {
        out.extend_from_slice(&(v.len() as u64).to_le_bytes());
        out.extend_from_slice(v);
    }
    const STRING: u32 = 8;
    let mut out = b"GGUF".to_vec();
    out.extend_from_slice(&3_u32.to_le_bytes());
    out.extend_from_slice(&1_u64.to_le_bytes());
    out.extend_from_slice(&2_u64.to_le_bytes());
    for (k, v) in [("general.architecture", "llama"), ("general.name", tag)] {
        s(&mut out, k.as_bytes());
        out.extend_from_slice(&STRING.to_le_bytes());
        s(&mut out, v.as_bytes());
    }
    s(&mut out, b"w");
    out.extend_from_slice(&1_u32.to_le_bytes());
    out.extend_from_slice(&8_u64.to_le_bytes());
    out.extend_from_slice(&0_u32.to_le_bytes());
    out.extend_from_slice(&0_u64.to_le_bytes());
    out.resize(out.len().next_multiple_of(32), 0);
    out.extend_from_slice(&[0_u8; 32]);
    out
}

/// A private data directory with a library in it, removed on drop.
pub(super) struct TmpLib {
    root: PathBuf,
    pub(super) lib: SharedLibrary,
}

impl TmpLib {
    pub(super) fn open(tag: &str, reserve: u64) -> Self {
        use std::os::unix::fs::PermissionsExt as _;
        let root = std::env::temp_dir().join(format!("sp-hf-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let lib = Library::open(&root, reserve).unwrap();
        Self {
            root,
            lib: Arc::new(Mutex::new(lib)),
        }
    }

    pub(super) fn path(&self, rel: &str) -> PathBuf {
        self.root.join("library").join(rel)
    }

    /// The names in a library directory, sorted.
    pub(super) fn names(&self, rel: &str) -> Vec<String> {
        let mut out: Vec<String> = std::fs::read_dir(self.path(rel))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        out.sort();
        out
    }

    pub(super) fn rows(&self) -> usize {
        self.lib.lock().unwrap().list().unwrap().len()
    }

    pub(super) fn root(&self) -> &Path {
        &self.root
    }
}

impl Drop for TmpLib {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
