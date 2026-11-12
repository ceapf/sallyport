//! [`EgressStarter::prepare`]: the session CA, its files and the trust roots (Task 9a-1).
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::os::unix::fs::PermissionsExt;

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, PKCS_ECDSA_P256_SHA256};
use sally_core::audit::NewEntry;
use sally_core::manifest::{AuditLevel, parse_host_pattern};

use super::super::ca::{BUNDLE_FILE, CA_FILE, GRACE};
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

fn starter(roots: BundleFiles) -> Egress<Nothing, Nothing, Nothing> {
    Egress {
        resolver: Arc::new(Nothing),
        dialer: Arc::new(Nothing),
        host: Arc::new(Nothing),
        roots,
    }
}

fn session(ca: bool, grants: &[&str]) -> SessionEgress {
    let rule = Rule {
        host: parse_host_pattern("*.mock.test").unwrap(),
        ports: vec![443],
    };
    SessionEgress {
        policy: Policy::new(
            vec![rule],
            grants
                .iter()
                .map(|g| Grant {
                    host: (*g).to_owned(),
                    header: "Authorization".to_owned(),
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
    let s = starter(missing).prepare(&dir, session(false, &[])).unwrap();
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
    let s = starter(roots).prepare(&ws, session(true, &grants)).unwrap();
    let i = s.interception.as_ref().unwrap();
    let hosts: Vec<&str> = i.tls.leaves.iter().map(|l| l.host.as_str()).collect();
    assert_eq!(hosts, ["a.mock.test", "b.mock.test"]);
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
    let e = starter(missing)
        .prepare(&dir, session(true, &["a.mock.test"]))
        .err()
        .unwrap();
    assert!(matches!(e, EgressError::Roots(_)), "{e}");
    assert!(entries(&dir).is_empty());
}

#[test]
fn a_planted_file_refuses_the_session() {
    let dir = scratch("planted");
    let ws = dir.join("ws");
    std::fs::create_dir(&ws).unwrap();
    std::fs::write(ws.join(CA_FILE), "planted").unwrap();
    let (roots, _) = roots_file(&dir);
    let e = starter(roots)
        .prepare(&ws, session(true, &["a.mock.test"]))
        .err()
        .unwrap();
    assert!(matches!(e, EgressError::Files(_)), "{e}");
    assert_eq!(
        std::fs::read_to_string(ws.join(CA_FILE)).unwrap(),
        "planted"
    );
}

#[test]
fn a_session_flagged_for_a_ca_without_grant_hosts_is_refused() {
    let dir = scratch("nohosts");
    let ws = dir.join("ws");
    std::fs::create_dir(&ws).unwrap();
    let (roots, _) = roots_file(&dir);
    let e = starter(roots)
        .prepare(&ws, session(true, &[]))
        .err()
        .unwrap();
    assert!(matches!(e, EgressError::Ca(CaError::NoHosts)), "{e}");
    assert!(entries(&ws).is_empty());
}
