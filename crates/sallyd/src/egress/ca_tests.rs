#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use rcgen::SanType;
use rustls::RootCertStore;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::ServerCertVerifier;
use rustls_pki_types::{ServerName, UnixTime};
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

use super::*;

const T0: u64 = 1_800_000_000;

fn at(secs: u64, nanos: u32) -> SystemTime {
    UNIX_EPOCH + Duration::new(secs, nanos)
}

fn hosts(list: &[&str]) -> Vec<String> {
    list.iter().map(|h| (*h).to_owned()).collect()
}

fn validity() -> Validity {
    Validity::for_session(at(T0, 0), Duration::from_secs(7200)).unwrap()
}

fn parsed(der: &[u8]) -> X509Certificate<'_> {
    let (rest, cert) = X509Certificate::from_der(der).unwrap();
    assert!(rest.is_empty());
    cert
}

fn verifier(ca: &CertificateDer<'static>) -> Arc<WebPkiServerVerifier> {
    let mut roots = RootCertStore::empty();
    roots.add(ca.clone()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
        .build()
        .unwrap()
}

fn verifies(
    v: &WebPkiServerVerifier,
    chain: &[CertificateDer<'static>],
    name: ServerName<'static>,
) -> bool {
    let (leaf, rest) = chain.split_first().unwrap();
    let now = UnixTime::since_unix_epoch(Duration::from_secs(T0 + 60));
    v.verify_server_cert(leaf, rest, &name, &[], now).is_ok()
}

fn dns(h: &str) -> ServerName<'static> {
    ServerName::try_from(h.to_owned()).unwrap()
}

#[test]
fn validity_starts_at_the_second_and_ends_after_timeout_plus_five_minutes() {
    let v = Validity::for_session(at(T0, 999_999_999), Duration::from_secs(7200)).unwrap();
    assert_eq!(v.not_before, 1_800_000_000);
    assert_eq!(v.not_after, 1_800_000_000 + 7200 + 300);
    assert_eq!(GRACE, Duration::from_secs(300));
}

#[test]
fn validity_refuses_a_clock_before_the_epoch_and_an_end_that_does_not_fit() {
    let before = UNIX_EPOCH - Duration::from_secs(1);
    assert_eq!(
        Validity::for_session(before, Duration::from_secs(60)),
        Err(CaError::Validity)
    );
    assert_eq!(
        Validity::for_session(at(T0, 0), Duration::MAX),
        Err(CaError::Validity)
    );
    let huge = Duration::from_secs(u64::try_from(i64::MAX).unwrap());
    assert_eq!(
        Validity::for_session(at(T0, 0), huge),
        Err(CaError::Validity)
    );
    let past_x509 = Validity {
        not_before: 0,
        not_after: i64::MAX,
    };
    assert_eq!(
        ca_params(&hosts(&["a.test"]), past_x509).err(),
        Some(CaError::Validity)
    );
    let bad_start = Validity {
        not_before: i64::MIN,
        not_after: 0,
    };
    assert_eq!(
        leaf_params("a.test", bad_start).err(),
        Some(CaError::Validity)
    );
}

#[test]
fn wanted_needs_proxy_mode_and_a_secret_grant() {
    let head = "apiVersion: sallyport/v1\nkind: Manifest\nname: t\nmodel:\n  ref: any\n";
    let grant = "secrets:\n  - name: GITHUB_TOKEN\n    inject: {host: api.github.com, \
                 header: Authorization, format: \"Bearer {value}\"}\n";
    let m = |body: &str| sally_core::manifest::parse(&format!("{head}{body}")).unwrap();
    assert!(
        !wanted(&m("network:\n  mode: proxy\n")),
        "proxy without secrets"
    );
    assert!(wanted(&m(&format!("network:\n  mode: proxy\n{grant}"))));
    assert!(
        !wanted(&m(&format!("network:\n  mode: none\n{grant}"))),
        "secrets without proxy"
    );
}

#[test]
fn grant_hosts_are_sorted_and_unique() {
    assert_eq!(
        grant_hosts(&hosts(&["b.test", "a.test", "b.test"])),
        hosts(&["a.test", "b.test"])
    );
}

#[test]
fn a_host_with_another_grant_host_beneath_it_keeps_its_subdomains() {
    assert_eq!(
        subdomain_exclusions(&hosts(&["api.github.com", "github.com"])),
        hosts(&[".api.github.com"])
    );
    assert_eq!(
        subdomain_exclusions(&hosts(&["a.test", "b.test", "xgithub.com", "github.com"])),
        hosts(&[".a.test", ".b.test", ".xgithub.com", ".github.com"]),
        "a suffix that is not a whole label is not beneath"
    );
}

#[test]
fn no_grant_host_means_no_ca() {
    assert_eq!(ca_params(&[], validity()).err(), Some(CaError::NoHosts));
    assert_eq!(
        SessionTls::mint(&[], validity()).err(),
        Some(CaError::NoHosts)
    );
}

#[test]
fn the_ca_carries_exactly_the_documented_parameters() {
    let tls = SessionTls::mint(&hosts(&["mock.test", "api.mock.test"]), validity()).unwrap();
    let ca = parsed(&tls.ca);
    assert_eq!(ca.subject(), ca.issuer(), "self-signed");
    assert!(ca.subject().to_string().contains(CA_NAME));
    let bc = ca.basic_constraints().unwrap().unwrap();
    assert!(bc.critical && bc.value.ca);
    assert_eq!(bc.value.path_len_constraint, Some(0));
    let ku = ca.key_usage().unwrap().unwrap().value;
    assert!(ku.key_cert_sign());
    assert_eq!(ku.flags, 1 << 5, "keyCertSign only");
    let eku = ca.extended_key_usage().unwrap().unwrap().value;
    assert!(eku.server_auth && !eku.client_auth && !eku.any && eku.other.is_empty());
    assert!(!eku.code_signing && !eku.email_protection && !eku.time_stamping);
    let nc = ca.name_constraints().unwrap().unwrap();
    assert!(nc.critical);
    let names = |list: &Option<Vec<x509_parser::extensions::GeneralSubtree<'_>>>| {
        list.as_ref()
            .unwrap()
            .iter()
            .map(|s| match &s.base {
                GeneralName::DNSName(d) => format!("dns:{d}"),
                GeneralName::IPAddress(ip) => format!("ip:{ip:?}"),
                other => format!("other:{other:?}"),
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        names(&nc.value.permitted_subtrees),
        ["dns:api.mock.test", "dns:mock.test"]
    );
    assert_eq!(
        names(&nc.value.excluded_subtrees),
        [
            "dns:.api.mock.test".to_owned(),
            format!("ip:{:?}", [0u8; 8]),
            format!("ip:{:?}", [0u8; 32]),
        ]
    );
    assert_eq!(ca.validity().not_before.timestamp(), 1_800_000_000);
    assert_eq!(ca.validity().not_after.timestamp(), 1_800_007_500);
    assert_eq!(tls.validity, validity());
    let pk = ca.public_key();
    assert_eq!(
        pk.algorithm.algorithm.to_id_string(),
        "1.2.840.10045.2.1",
        "EC public key"
    );
    assert_eq!(
        pk.algorithm
            .parameters
            .as_ref()
            .unwrap()
            .as_oid()
            .unwrap()
            .to_id_string(),
        "1.2.840.10045.3.1.7",
        "P-256"
    );
    assert!(tls.ca_pem.starts_with("-----BEGIN CERTIFICATE-----"));
    assert_eq!(
        pem::parse(&tls.ca_pem).unwrap().contents(),
        tls.ca.as_ref(),
        "the PEM is the same certificate"
    );
}

#[test]
fn each_leaf_names_one_host_and_is_no_ca() {
    let tls = SessionTls::mint(
        &hosts(&["mock.test", "api.mock.test", "mock.test"]),
        validity(),
    )
    .unwrap();
    let ca = parsed(&tls.ca);
    let got: Vec<&str> = tls.leaves.iter().map(|l| l.host.as_str()).collect();
    assert_eq!(got, ["api.mock.test", "mock.test"]);
    for leaf in &tls.leaves {
        let c = parsed(&leaf.cert);
        assert_eq!(c.issuer(), ca.subject());
        assert!(c.subject().to_string().contains(&leaf.host));
        let san = c.subject_alternative_name().unwrap().unwrap().value;
        assert_eq!(san.general_names, [GeneralName::DNSName(&leaf.host)]);
        let bc = c.basic_constraints().unwrap().unwrap().value;
        assert!(!bc.ca);
        let ku = c.key_usage().unwrap().unwrap().value;
        assert_eq!(ku.flags, 1, "digitalSignature only");
        let eku = c.extended_key_usage().unwrap().unwrap().value;
        assert!(eku.server_auth && !eku.client_auth && !eku.any && eku.other.is_empty());
        assert!(c.iter_extensions().any(|e| matches!(
            e.parsed_extension(),
            x509_parser::extensions::ParsedExtension::AuthorityKeyIdentifier(_)
        )));
        assert_eq!(c.validity().not_before.timestamp(), 1_800_000_000);
        assert_eq!(c.validity().not_after.timestamp(), 1_800_007_500);
        let key = KeyPair::try_from(leaf.key.expose().as_slice()).unwrap();
        assert_eq!(
            key.public_key_raw(),
            &*c.public_key().subject_public_key.data
        );
        assert!(!format!("{leaf:?}").contains(&format!("{:?}", leaf.key.expose())));
    }
    let [a, b] = &tls.leaves[..] else {
        panic!("two leaves")
    };
    assert_ne!(a.key.expose(), b.key.expose(), "one key per leaf");
}

#[test]
fn a_stock_verifier_accepts_each_leaf_for_its_own_host_only() {
    let tls = SessionTls::mint(&hosts(&["mock.test", "api.mock.test"]), validity()).unwrap();
    let v = verifier(&tls.ca);
    for leaf in &tls.leaves {
        let chain = std::slice::from_ref(&leaf.cert);
        assert!(verifies(&v, chain, dns(&leaf.host)), "{}", leaf.host);
        assert!(!verifies(&v, chain, dns("evil.test")));
    }
}

/// Rogue leaves signed by a CA built from the production parameters with a test key (architect
/// Q33): the name constraints refuse each, while a leaf for the grant host passes.
#[test]
fn the_name_constraints_refuse_other_names_subdomains_and_addresses() {
    let grants = hosts(&["mock.test", "api.mock.test"]);
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let params = ca_params(&grants, validity()).unwrap();
    let ca = params.self_signed(&key).unwrap().der().clone();
    let issuer = Issuer::new(params, key);
    let v = verifier(&ca);
    let leaf = |sans: Vec<SanType>| {
        let mut p = leaf_params("mock.test", validity()).unwrap();
        p.subject_alt_names = sans;
        let k = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        p.signed_by(&k, &issuer).unwrap().der().clone()
    };
    let name = |h: &str| SanType::DnsName(h.try_into().unwrap());
    assert!(verifies(
        &v,
        &[leaf(vec![name("mock.test")])],
        dns("mock.test")
    ));
    // The documented residual: `api.mock.test` lies beneath `mock.test`, so `.mock.test` is not
    // excluded and the CA could vouch for another name under it, had anyone its key.
    assert!(verifies(
        &v,
        &[leaf(vec![name("x.mock.test")])],
        dns("x.mock.test")
    ));
    for rogue in ["evil.test", "sub.api.mock.test", "mock.test.evil.test"] {
        assert!(
            !verifies(&v, &[leaf(vec![name(rogue)])], dns(rogue)),
            "{rogue}"
        );
    }
    let ip = IpAddr::V4(Ipv4Addr::new(93, 184, 215, 1));
    assert!(!verifies(
        &v,
        &[leaf(vec![SanType::IpAddress(ip)])],
        ServerName::IpAddress(ip.into())
    ));
    let ip6 = IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0x4860, 0, 0, 0, 0, 0, 1));
    assert!(!verifies(
        &v,
        &[leaf(vec![SanType::IpAddress(ip6)])],
        ServerName::IpAddress(ip6.into())
    ));
}

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::current_dir()
        .unwrap()
        .join("../../target/ca-unit")
        .join(std::process::id().to_string())
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn the_ca_files_hold_the_ca_and_the_roots_then_the_ca_read_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = scratch("files");
    let tls = SessionTls::mint(&hosts(&["mock.test"]), validity()).unwrap();
    let roots = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
    write_files(&dir, &tls, roots).unwrap();
    let ca = std::fs::read_to_string(dir.join(CA_FILE)).unwrap();
    assert_eq!(ca, tls.ca_pem);
    let bundle = std::fs::read_to_string(dir.join(BUNDLE_FILE)).unwrap();
    assert_eq!(bundle, format!("{roots}{}", tls.ca_pem));
    for f in [CA_FILE, BUNDLE_FILE] {
        let mode = std::fs::metadata(dir.join(f)).unwrap().permissions().mode();
        assert_eq!(mode & 0o7777, 0o444, "{f}");
    }
    assert_eq!((CA_FILE, BUNDLE_FILE), ("session-ca.pem", "ca-bundle.pem"));
    let names: std::collections::BTreeSet<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names.len(), 2, "{names:?}");
}

#[test]
fn an_existing_name_or_a_symlinked_directory_is_refused() {
    let tls = SessionTls::mint(&hosts(&["mock.test"]), validity()).unwrap();
    let dir = scratch("exists");
    std::fs::write(dir.join(CA_FILE), "planted").unwrap();
    assert!(write_files(&dir, &tls, "").is_err());
    assert_eq!(
        std::fs::read_to_string(dir.join(CA_FILE)).unwrap(),
        "planted"
    );
    let dir = scratch("bundle-link");
    let target = dir.join("elsewhere");
    std::os::unix::fs::symlink(&target, dir.join(BUNDLE_FILE)).unwrap();
    assert!(write_files(&dir, &tls, "").is_err());
    assert!(!target.exists(), "the symlink was not followed");
    let dir = scratch("dir-link");
    let real = dir.join("real");
    std::fs::create_dir(&real).unwrap();
    let link = dir.join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert!(write_files(&link, &tls, "").is_err());
    assert_eq!(std::fs::read_dir(&real).unwrap().count(), 0);
}
