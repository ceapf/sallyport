//! [`EgressStarter::prepare`]: the session CA, its files and the trust roots (Task 9a-1), and
//! the credentials from the secrets store (Task 9a-3).
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::os::unix::fs::PermissionsExt;

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, PKCS_ECDSA_P256_SHA256};
use sally_core::audit::NewEntry;
use sally_core::manifest::{AuditLevel, parse_host_pattern};

use super::super::ca::{BUNDLE_FILE, CA_FILE, GRACE};
use super::super::inject::StoreFile;
use super::super::policy::{Grant, Rule};
use super::super::server::{Dialer, HostAddrs, Resolver};
use super::*;

struct Nothing;

impl Resolver for Nothing {
    async fn resolve(&self, _: &str, _: u16) -> io::Result<Vec<SocketAddr>> {
        Err(io::ErrorKind::NotFound.into())
    }
}

impl Dialer for Nothing {
    type Stream = tokio::io::DuplexStream;
    async fn dial(&self, _: SocketAddr) -> io::Result<Self::Stream> {
        Err(io::ErrorKind::ConnectionRefused.into())
    }
}

impl HostAddrs for Nothing {
    async fn own(&self) -> io::Result<Vec<IpAddr>> {
        Ok(Vec::new())
    }
}

struct Sink;

impl AuditSink for Sink {
    fn append(&self, _: NewEntry, _: AuditLevel) -> Result<(), sally_core::audit::AuditError> {
        Ok(())
    }
}

fn scratch(tag: &str) -> crate::egress::scratch::Scratch {
    crate::egress::scratch::scratch("net-ca-unit", tag)
}

/// The settings carry the CA condition and the timeout the manifest gives.
#[test]
fn session_settings_carry_the_ca_condition_and_the_timeout() {
    use sally_core::manifest::{HostEnv, load};
    let dir = scratch("settings");
    let env = HostEnv {
        home: dir.to_path_buf(),
        other_homes: Vec::new(),
        xdg_config_home: None,
        xdg_data_home: None,
        xdg_runtime_dir: None,
        podman_storage: Vec::new(),
        nproc: 8,
        mem_bytes: 16 << 30,
    };
    let head = "apiVersion: sallyport/v1\nkind: Manifest\nname: t\nmodel:\n  ref: any\n\
                runtime:\n  timeout: 90m\nnetwork:\n  mode: proxy\n  allow:\n    - host: a.mock.test\n";
    let grant = "secrets:\n  - name: GITHUB_TOKEN\n    inject: {host: a.mock.test, \
                 header: Authorization, format: \"Bearer {value}\"}\n";
    let names: std::collections::BTreeSet<String> = ["GITHUB_TOKEN".to_owned()].into();
    for (body, ca) in [(format!("{head}{grant}"), true), (head.to_owned(), false)] {
        let v = load(&body, &env, &names).unwrap().manifest;
        let s = SessionEgress::from_manifest(&v, "s-x", Arc::new(Sink));
        assert_eq!(s.ca, ca, "{body}");
        assert_eq!(s.ca, ca::wanted(v.manifest()));
        assert_eq!(s.timeout, Duration::from_secs(90 * 60));
        assert!(s.interception.is_none());
        // Task 9a-3: the grants as the proxy needs them, names and text only.
        let want = if ca {
            vec![Spec {
                name: "GITHUB_TOKEN".into(),
                host: "a.mock.test".into(),
                header: "Authorization".into(),
                format: "Bearer {value}".into(),
            }]
        } else {
            Vec::new()
        };
        assert_eq!(s.grants, want, "{body}");
    }
}

/// A roots file owned by this user, holding one self-signed CA.
fn roots_file(dir: &Path) -> (BundleFiles, String) {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name.push(DnType::CommonName, "test root");
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let pem = p.self_signed(&key).unwrap().pem();
    let f = dir.join("roots.pem");
    std::fs::write(&f, &pem).unwrap();
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
    let files = BundleFiles {
        paths: vec![f],
        owner: rustix::process::getuid().as_raw(),
    };
    (files, pem)
}

/// The value grant `i` holds in the test store, assembled at runtime.
fn value(i: usize) -> String {
    format!("store-{i}-{}", "s".repeat(24))
}

/// A 0600 secrets store in `dir/store/` holding `G0` .. `G{n-1}` (the production format and
/// checks).
fn store(dir: &Path, n: usize) -> PathBuf {
    let sub = dir.join("store");
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = sub.join("secrets.toml");
    let mut s = sally_core::secrets::SecretStore::empty(path.clone());
    for i in 0..n {
        s.set(&format!("G{i}"), value(i)).unwrap();
    }
    s.save().unwrap();
    path
}

/// The production starter over `roots` and the secrets store at `secrets`.
fn starter_with(roots: BundleFiles, secrets: PathBuf) -> Egress<Nothing, Nothing, Nothing> {
    Egress {
        resolver: Arc::new(Nothing),
        dialer: Arc::new(Nothing),
        host: Arc::new(Nothing),
        roots,
        secrets: Arc::new(StoreFile { path: secrets }),
    }
}

/// A starter whose store in `dir` holds a value for each of the first eight grants.
fn starter(dir: &Path, roots: BundleFiles) -> Egress<Nothing, Nothing, Nothing> {
    starter_with(roots, store(dir, 8))
}

/// Grant `i` of `grants`: secret `G{i}`, header `X-Key-{i}`, `Bearer {value}`.
fn spec(i: usize, host: &str) -> Spec {
    Spec {
        name: format!("G{i}"),
        host: host.to_owned(),
        header: format!("X-Key-{i}"),
        format: "Bearer {value}".into(),
    }
}

fn session(ca: bool, grants: &[&str]) -> SessionEgress {
    session_of(
        ca,
        grants.iter().enumerate().map(|(i, h)| spec(i, h)).collect(),
    )
}

fn session_of(ca: bool, specs: Vec<Spec>) -> SessionEgress {
    let rule = Rule {
        host: parse_host_pattern("*.mock.test").unwrap(),
        ports: vec![443],
    };
    SessionEgress {
        policy: Policy::new(
            vec![rule],
            specs
                .iter()
                .map(|g| Grant {
                    host: g.host.clone(),
                    header: g.header.clone(),
                })
                .collect(),
        ),
        max_connections: 4,
        body_caps: (1 << 20, 1 << 20),
        session: "s-ca".into(),
        level: AuditLevel::default(),
        audit: Arc::new(Sink),
        ca,
        timeout: Duration::from_secs(3600),
        grants: specs,
        interception: None,
    }
}

fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

#[test]
fn a_session_without_a_ca_passes_through_and_nothing_is_read_or_written() {
    let dir = scratch("none");
    let missing = BundleFiles {
        paths: vec![dir.join("no-roots.pem")],
        owner: 0,
    };
    // A store the starter would refuse (0644): a session without a CA never opens it.
    let st = scratch("none-store");
    let path = store(&st, 1);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let s = starter_with(missing, path)
        .prepare(&dir, session(false, &[]))
        .unwrap();
    assert!(s.interception.is_none());
    assert!(entries(&dir).is_empty());
}

#[test]
fn a_session_with_a_ca_gets_its_files_leaves_and_roots() {
    let dir = scratch("ca");
    let ws = dir.join("ws");
    std::fs::create_dir(&ws).unwrap();
    let (roots, root_pem) = roots_file(&dir);
    let before = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let grants = ["b.mock.test", "a.mock.test", "b.mock.test"];
    let s = starter(&dir, roots)
        .prepare(&ws, session(true, &grants))
        .unwrap();
    let i = s.interception.as_ref().unwrap();
    let hosts: Vec<&str> = i.tls.leaves.iter().map(|l| l.host.as_str()).collect();
    assert_eq!(hosts, ["a.mock.test", "b.mock.test"]);
    // Task 9a-3: the credentials hold each grant's value from the store, and nothing more.
    let c = i.credentials();
    assert_eq!(c.hosts(), ["b.mock.test", "a.mock.test"]);
    assert_eq!(c.prepare("b.mock.test").names(), ["secret:G0", "secret:G2"]);
    let mut h = hyper::http::HeaderMap::new();
    c.prepare("a.mock.test").apply(&mut h);
    assert_eq!(
        h.get("x-key-1").unwrap(),
        format!("Bearer {}", value(1)).as_str()
    );
    assert_eq!(c.redaction().scan(value(2).as_bytes()).1, Some(0));
    assert_eq!(c.redaction().scan(value(3).as_bytes()).1, None);
    assert_eq!(i.roots.store.len(), 1);
    assert_eq!(i.roots.pem, root_pem);
    let v = i.tls.validity;
    let start = u64::try_from(v.not_before).unwrap();
    assert!(
        start >= before && start <= before + 5,
        "{start} vs {before}"
    );
    let span = u64::try_from(v.not_after - v.not_before).unwrap();
    assert_eq!(span, 3600 + GRACE.as_secs());
    assert_eq!(entries(&ws), [BUNDLE_FILE, CA_FILE]);
    let bundle = std::fs::read_to_string(ws.join(BUNDLE_FILE)).unwrap();
    assert_eq!(bundle, format!("{root_pem}{}", i.tls.ca_pem));
    assert_eq!(
        std::fs::read_to_string(ws.join(CA_FILE)).unwrap(),
        i.tls.ca_pem
    );
}

#[test]
fn without_trust_roots_the_session_is_refused_before_anything_is_written() {
    let dir = scratch("noroots");
    let missing = BundleFiles {
        paths: vec![dir.join("no-roots.pem")],
        owner: 0,
    };
    let st = scratch("noroots-store");
    let e = starter(&st, missing)
        .prepare(&dir, session(true, &["a.mock.test"]))
        .err()
        .unwrap();
    assert!(matches!(e, EgressError::Roots(_)), "{e}");
    assert!(entries(&dir).is_empty());
}

/// Architect D7 (MANIFEST_SPEC §3 `secrets[].name`): a grant whose secret left the store refuses
/// the session by name, before the trust roots are read or anything is written.
#[test]
fn a_secret_missing_from_the_store_refuses_the_session_before_anything_else() {
    let dir = scratch("missing");
    let missing_roots = BundleFiles {
        paths: vec![dir.join("no-roots.pem")],
        owner: 0,
    };
    let st = scratch("missing-store");
    let e = starter_with(missing_roots, store(&st, 1))
        .prepare(&dir, session(true, &["a.mock.test", "b.mock.test"]))
        .err()
        .unwrap();
    assert!(
        matches!(&e, EgressError::Credentials(CredentialsError::Missing(n)) if n == "G1"),
        "{e}"
    );
    assert!(entries(&dir).is_empty());
    // Allow: with both values in the store the same session passes this step.
    let (roots, _) = roots_file(&st);
    let ws = dir.join("ws");
    std::fs::create_dir(&ws).unwrap();
    assert!(
        starter_with(roots, store(&st, 2))
            .prepare(&ws, session(true, &["a.mock.test", "b.mock.test"]))
            .is_ok()
    );
}

/// Architect D7: a store that cannot be read (here: mode 0644) refuses the session.
#[test]
fn an_unreadable_store_refuses_the_session() {
    let dir = scratch("badstore");
    let path = store(&dir, 1);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let (roots, _) = roots_file(&dir);
    let ws = dir.join("ws");
    std::fs::create_dir(&ws).unwrap();
    let e = starter_with(roots, path)
        .prepare(&ws, session(true, &["a.mock.test"]))
        .err()
        .unwrap();
    assert!(matches!(e, EgressError::Store(_)), "{e}");
    assert!(!e.to_string().contains(&value(0)));
    assert!(entries(&ws).is_empty());
}

/// Architect D11: a `{basic}` grant refuses the session before the store is opened (here the
/// store is unreadable, so opening it would fail differently).
#[test]
fn a_basic_grant_is_refused_before_the_store_is_opened() {
    let dir = scratch("basic");
    let path = store(&dir, 2);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let (roots, _) = roots_file(&dir);
    let mut specs = vec![spec(0, "a.mock.test"), spec(1, "b.mock.test")];
    specs[1].format = "Basic {basic}".into();
    let e = starter_with(roots, path)
        .prepare(&dir, session_of(true, specs))
        .err()
        .unwrap();
    assert!(
        matches!(&e, EgressError::Credentials(CredentialsError::Basic(n)) if n == "G1"),
        "{e}"
    );
}

/// Decision 5 (architect D8): the credentials live with the session's proxy and are gone (their
/// `Secret`s wiped on drop) once the listener has shut down.
#[tokio::test]
async fn the_credentials_are_dropped_when_the_session_listener_shuts_down() {
    let dir = scratch("weak");
    let (roots, _) = roots_file(&dir);
    let s = starter(&dir, roots)
        .prepare(&dir, session(true, &["a.mock.test"]))
        .unwrap();
    let weak = Arc::downgrade(s.interception.as_ref().unwrap().credentials());
    let sock = dir.join("n.sock");
    let (roots, _) = roots_file(&dir);
    let handle = starter(&dir, roots).start(&sock, s).unwrap();
    assert!(weak.upgrade().is_some(), "held while the session runs");
    handle.shutdown().await;
    assert!(
        weak.upgrade().is_none(),
        "the credentials outlived the session"
    );
}

/// Each secret is asked for once, whatever the number of its grants, and only the grants'.
#[test]
fn the_source_is_asked_for_the_grants_names_once_each() {
    #[derive(Debug, Default)]
    struct Asked(std::sync::Mutex<Vec<Vec<String>>>);
    impl SecretSource for Asked {
        fn load(
            &self,
            names: &[String],
        ) -> Result<
            Vec<(String, sally_core::secrets::Secret<String>)>,
            sally_core::secrets::SecretsError,
        > {
            self.0.lock().unwrap().push(names.to_vec());
            Ok(names
                .iter()
                .map(|n| {
                    (
                        n.clone(),
                        sally_core::secrets::Secret::new(format!("{n}-{}", "q".repeat(20))),
                    )
                })
                .collect())
        }
    }
    let dir = scratch("asked");
    let (roots, _) = roots_file(&dir);
    let asked = Arc::new(Asked::default());
    let starter = Egress {
        resolver: Arc::new(Nothing),
        dialer: Arc::new(Nothing),
        host: Arc::new(Nothing),
        roots,
        secrets: Arc::clone(&asked) as Arc<dyn SecretSource>,
    };
    let mut specs = vec![spec(0, "a.mock.test"), spec(1, "b.mock.test")];
    specs[1].name = "G0".into();
    starter.prepare(&dir, session_of(true, specs)).unwrap();
    assert_eq!(*asked.0.lock().unwrap(), [vec!["G0".to_owned()]]);
}

#[test]
fn a_planted_file_refuses_the_session() {
    let dir = scratch("planted");
    let ws = dir.join("ws");
    std::fs::create_dir(&ws).unwrap();
    std::fs::write(ws.join(CA_FILE), "planted").unwrap();
    let (roots, _) = roots_file(&dir);
    let e = starter(&dir, roots)
        .prepare(&ws, session(true, &["a.mock.test"]))
        .err()
        .unwrap();
    assert!(matches!(e, EgressError::Files(_)), "{e}");
    assert_eq!(
        std::fs::read_to_string(ws.join(CA_FILE)).unwrap(),
        "planted"
    );
}

/// Security review L6: the interception is built before the CA files are written, so a session
/// whose leaves and credentials name different hosts leaves no file behind.
#[test]
fn a_refused_interception_writes_no_file() {
    let dir = scratch("unmatched");
    let ws = dir.join("ws");
    std::fs::create_dir(&ws).unwrap();
    let (roots, _) = roots_file(&dir);
    let mut s = session(true, &["a.mock.test", "b.mock.test"]);
    s.grants.truncate(1);
    let e = starter(&dir, roots).prepare(&ws, s).err().unwrap();
    assert!(matches!(e, EgressError::Ca(CaError::Unmatched)), "{e}");
    assert!(entries(&ws).is_empty());
}

#[test]
fn a_session_flagged_for_a_ca_without_grant_hosts_is_refused() {
    let dir = scratch("nohosts");
    let ws = dir.join("ws");
    std::fs::create_dir(&ws).unwrap();
    let (roots, _) = roots_file(&dir);
    let e = starter(&dir, roots)
        .prepare(&ws, session(true, &[]))
        .err()
        .unwrap();
    assert!(matches!(e, EgressError::Ca(CaError::NoHosts)), "{e}");
    assert!(entries(&ws).is_empty());
}
