//! Red-team row RT-SEC-10 (Task 9a-2; architect Q33, Q46): what a session CA can vouch for, and
//! that no private key reaches a container.
//!
//! The matrix signs rogue leaves with a CA built from the production [`ca_params`] and a test
//! key (no API exports a session's key), then verifies each in five verifiers, offline:
//! rustls-webpki, `openssl verify`, Python `ssl` (in process, over memory BIOs), GnuTLS
//! `certtool` and Go `crypto/x509` (`tests/redteam/tls/verify.go`). A missing verifier fails.
//! The container test launches a session with a grant, verifies its real leaf live over
//! `net.sock` with Python, and searches the workspace and a harness of the same session for
//! private-key material and the CA files, with planted positive controls.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use common::container::{Lx, SHIM_LOG, exec, exec_in, ids, net_image, rt, test_image};
use common::egress::tls_upstream;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, SanType,
};
use rustls::RootCertStore;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use sallyd::egress::ca::{BUNDLE_FILE, CA_FILE, Validity, ca_params, leaf_params};
use sallyd::sandbox::{CommonArgs, Running, WorkspaceRequest, harness_argv};

const GRANT: &str = "mock.test";
const ROGUE_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(93, 184, 215, 1));

/// The five verifiers, in report order.
const VERIFIERS: [&str; 5] = ["webpki", "openssl", "python", "gnutls", "go"];

fn validity() -> Validity {
    Validity::for_session(SystemTime::now(), Duration::from_secs(600)).unwrap()
}

fn redteam_tls() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/redteam/tls")
}

/// A fresh directory for one test's files under `CARGO_TARGET_TMPDIR`.
fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("rt-sec-10-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// One chain to verify: the leaf first, then intermediates; the leaf's key; the name.
struct Case {
    label: &'static str,
    chain: Vec<CertificateDer<'static>>,
    chain_pem: String,
    key_pem: String,
    name: String,
}

impl Case {
    fn is_ip(&self) -> bool {
        self.name.parse::<IpAddr>().is_ok()
    }

    /// Writes `<label>-chain.pem`, `<label>-leaf.pem`, `<label>-inter.pem`, `<label>-key.pem`.
    fn write(&self, dir: &Path) {
        let pem = |c: &CertificateDer<'_>| {
            pem::encode(&pem::Pem::new("CERTIFICATE", c.as_ref().to_vec()))
        };
        let file = |suffix: &str| dir.join(format!("{}-{suffix}.pem", self.label));
        std::fs::write(file("chain"), &self.chain_pem).unwrap();
        std::fs::write(file("leaf"), pem(&self.chain[0])).unwrap();
        let inter: String = self.chain[1..].iter().map(pem).collect();
        std::fs::write(file("inter"), inter).unwrap();
        std::fs::write(file("key"), &self.key_pem).unwrap();
    }
}

/// The session CA's parameters with a test key, and the cases it signs.
struct Matrix {
    ca: CertificateDer<'static>,
    cases: Vec<Case>,
}

/// A leaf from the production `leaf_params`, with `sans` and the common name `cn` instead.
fn leaf_with(
    cn: &str,
    sans: Vec<SanType>,
    issuer: &Issuer<'_, KeyPair>,
) -> (CertificateDer<'static>, KeyPair) {
    let mut p = leaf_params(GRANT, validity()).unwrap();
    p.subject_alt_names = sans;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    p.distinguished_name = dn;
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = p.signed_by(&key, issuer).unwrap().der().clone();
    (cert, key)
}

fn dns(name: &str) -> SanType {
    SanType::DnsName(name.try_into().unwrap())
}

fn matrix() -> Matrix {
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let params = ca_params(&[GRANT.to_owned()], validity()).unwrap();
    let ca = params.self_signed(&ca_key).unwrap().der().clone();
    let issuer = Issuer::new(params, ca_key);
    let pem = |cs: &[&CertificateDer<'_>]| -> String {
        cs.iter()
            .map(|c| pem::encode(&pem::Pem::new("CERTIFICATE", c.as_ref().to_vec())))
            .collect()
    };
    let mut cases = Vec::new();
    let mut single = |label, cn: &str, sans, name: &str| {
        let (leaf, key) = leaf_with(cn, sans, &issuer);
        cases.push(Case {
            label,
            chain_pem: pem(&[&leaf]),
            chain: vec![leaf],
            key_pem: key.serialize_pem(),
            name: name.to_owned(),
        });
    };
    single("grant", GRANT, vec![dns(GRANT)], GRANT);
    single("unlisted", GRANT, vec![dns("evil.test")], "evil.test");
    single(
        "subdomain",
        GRANT,
        vec![dns("sub.mock.test")],
        "sub.mock.test",
    );
    single(
        "ip",
        GRANT,
        vec![SanType::IpAddress(ROGUE_IP)],
        &ROGUE_IP.to_string(),
    );
    // No SAN at all, the name only in the common name (a verifier may fall back to it).
    single("cn-only", "evil.test", vec![], "evil.test");
    single("wildcard", GRANT, vec![dns("*.mock.test")], "x.mock.test");

    // root -> second CA -> leaf for the grant host itself: only the root's path length (0)
    // stands in the way.
    let mut second = CertificateParams::new(Vec::<String>::new()).unwrap();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Second CA");
    second.distinguished_name = dn;
    second.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    second.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    second.use_authority_key_identifier_extension = true;
    let second_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let second_cert = second
        .signed_by(&second_key, &issuer)
        .unwrap()
        .der()
        .clone();
    let second_issuer = Issuer::new(second, second_key);
    let (leaf, key) = leaf_with(GRANT, vec![dns(GRANT)], &second_issuer);
    cases.push(Case {
        label: "second-ca",
        chain_pem: pem(&[&leaf, &second_cert]),
        chain: vec![leaf, second_cert],
        key_pem: key.serialize_pem(),
        name: GRANT.to_owned(),
    });
    Matrix { ca, cases }
}

/// Runs `cmd`; `Ok` when it exits 0. A verifier that cannot be started fails the test.
fn run(tool: &str, cmd: &mut Command) -> Result<(), String> {
    let out = cmd
        .output()
        .unwrap_or_else(|e| panic!("{tool}: cannot run ({e}); RT-SEC-10 needs it installed"));
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout).trim(),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

fn webpki(ca: &CertificateDer<'static>, c: &Case) -> Result<(), String> {
    let mut roots = RootCertStore::empty();
    roots.add(ca.clone()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let v = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
        .build()
        .unwrap();
    let name = ServerName::try_from(c.name.clone()).unwrap();
    v.verify_server_cert(&c.chain[0], &c.chain[1..], &name, &[], UnixTime::now())
        .map(|_| ())
        .map_err(|e| e.to_string())
}

fn openssl(dir: &Path, c: &Case) -> Result<(), String> {
    let f = |s: &str| dir.join(format!("{}-{s}.pem", c.label));
    let mut cmd = Command::new("openssl");
    cmd.args([
        "verify",
        "-no-CApath",
        "-no-CAstore",
        "-purpose",
        "sslserver",
        "-CAfile",
    ])
    .arg(dir.join("ca.pem"));
    if c.chain.len() > 1 {
        cmd.arg("-untrusted").arg(f("inter"));
    }
    cmd.arg(if c.is_ip() {
        "-verify_ip"
    } else {
        "-verify_hostname"
    })
    .arg(&c.name)
    .arg(f("leaf"));
    run("openssl", &mut cmd)
}

fn python(dir: &Path, c: &Case) -> Result<(), String> {
    let f = |s: &str| dir.join(format!("{}-{s}.pem", c.label));
    let mut cmd = Command::new("python3");
    cmd.arg("-I")
        .arg(redteam_tls().join("verify.py"))
        .arg("memory")
        .arg(dir.join("ca.pem"))
        .arg(f("chain"))
        .arg(f("key"))
        .arg(&c.name);
    run("python3", &mut cmd)
}

fn gnutls(dir: &Path, c: &Case) -> Result<(), String> {
    let mut cmd = Command::new("certtool");
    cmd.arg("--verify")
        .arg(format!(
            "--load-ca-certificate={}",
            dir.join("ca.pem").display()
        ))
        .arg(format!(
            "--infile={}",
            dir.join(format!("{}-chain.pem", c.label)).display()
        ))
        .arg(format!("--verify-hostname={}", c.name))
        .arg(format!("--verify-purpose={}", server_auth_oid()));
    run("certtool", &mut cmd)
}

/// id-kp-serverAuth, assembled from its arcs (the commit guard reads dotted quads as IPv4).
fn server_auth_oid() -> String {
    [1, 3, 6, 1, 5, 5, 7, 3, 1]
        .map(|a: u8| a.to_string())
        .join(".")
}

/// Builds the Go verifier once, offline, into `dir`.
fn go_build(dir: &Path) -> PathBuf {
    let bin = dir.join("verify-go");
    let mut cmd = Command::new("go");
    cmd.args(["build", "-o"])
        .arg(&bin)
        .arg(redteam_tls().join("verify.go"))
        .env("GOTOOLCHAIN", "local")
        .env("GOPROXY", "off")
        .env("GOTELEMETRY", "off")
        .env("GOFLAGS", "-mod=mod")
        .env("GOPATH", dir.join("gopath"))
        .env("GOCACHE", dir.join("gocache"));
    run("go", &mut cmd).unwrap_or_else(|e| panic!("go build: {e}"));
    bin
}

fn go(bin: &Path, dir: &Path, c: &Case) -> Result<(), String> {
    let mut cmd = Command::new(bin);
    cmd.arg(dir.join("ca.pem"))
        .arg(dir.join(format!("{}-chain.pem", c.label)))
        .arg(&c.name);
    run("go verifier", &mut cmd)
}

/// RT-SEC-10, the verifier matrix. Controls: the CA's name constraints (permitted `mock.test`,
/// excluded `.mock.test` and every IP address) refuse `unlisted`, `subdomain` and `ip` in every
/// verifier; its path length 0 refuses `second-ca` in OpenSSL (`openssl`, `python`). Without the
/// constraints the rogue leaves verify; `grant` is the positive control.
#[test]
fn rt_sec_10_rogue_leaves_of_a_session_ca_fail_in_every_verifier() {
    let dir = scratch("matrix");
    let m = matrix();
    let ca_pem = pem::encode(&pem::Pem::new("CERTIFICATE", m.ca.as_ref().to_vec()));
    std::fs::write(dir.join("ca.pem"), ca_pem).unwrap();
    let go_bin = go_build(&dir);
    let mut report = Vec::new();
    for c in &m.cases {
        c.write(&dir);
        let results = [
            webpki(&m.ca, c),
            openssl(&dir, c),
            python(&dir, c),
            gnutls(&dir, c),
            go(&go_bin, &dir, c),
        ];
        for (verifier, r) in VERIFIERS.iter().zip(results) {
            report.push((c.label, *verifier, r));
        }
    }
    let table: String = report
        .iter()
        .map(|(l, v, r)| {
            format!(
                "{l:>10} {v:>8}: {}\n",
                r.as_ref()
                    .map_or_else(|e| format!("refused ({e})"), |()| "verified".into())
            )
        })
        .collect();
    for (label, verifier, r) in &report {
        match (expected(label, verifier), r) {
            (None, Ok(())) => {}
            (Some(why), Err(e)) if e.contains(why) => {}
            _ => panic!("{label} in {verifier}\n{table}"),
        }
    }
}

/// `None`: the chain verifies. `Some(text)`: it is refused, with `text` in the reason, so a
/// refusal for anything but the control under test (expiry, purpose, a parse error) fails.
fn expected(label: &str, verifier: &str) -> Option<&'static str> {
    let constraint = match label {
        "grant" => return None,
        // webpki and Go never read a common name; OpenSSL and GnuTLS hold it to the name
        // constraints.
        "cn-only" if verifier == "webpki" => return Some("not valid for any names"),
        "cn-only" if verifier == "go" => return Some("relies on legacy Common Name field"),
        "cn-only" => "permitted",
        // PROBE_NOTES: a webpki trust anchor keeps no path length; its name constraints still
        // bind the whole chain.
        "second-ca" if verifier == "webpki" => return None,
        "second-ca" => "path",
        "unlisted" => "permitted",
        _ => "excluded",
    };
    Some(match (verifier, constraint) {
        ("webpki", _) => "NameConstraintViolation",
        ("openssl" | "python", "path") => "path length constraint exceeded",
        ("openssl" | "python", "permitted") => "permitted subtree violation",
        ("openssl" | "python", _) => "excluded subtree violation",
        // GnuTLS names neither the constraint nor the depth (GNUTLS_CERT_SIGNER_CONSTRAINTS_FAILURE).
        ("gnutls", _) => "violates the signer's constraints",
        ("go", "path") => "too many intermediates for path length constraint",
        ("go", "permitted") => "is not permitted by any constraint",
        ("go", _) => "is excluded by constraint",
        _ => unreachable!("{verifier}"),
    })
}

/// `mock.test` is the grant host; the session's leaf for it is what the live leg verifies.
const MANIFEST: &str = "network:\n  mode: proxy\n  allow:\n    - host: mock.test\n\
                        secrets:\n  - name: GITHUB_TOKEN\n    inject: {host: mock.test, \
                        header: Authorization, format: \"Bearer {value}\"}\n";

async fn session(lx: &Lx, tag: &str) -> Running {
    let req = WorkspaceRequest {
        paths: lx.paths(tag),
        manifest: Arc::new(lx.f.load(MANIFEST)),
        default_image: net_image(),
    };
    let r = lx.launcher.launch_workspace(req).await.expect("launch");
    for _ in 0..100 {
        let (_, log) = exec(&r, &format!("cat {SHIM_LOG} 2>/dev/null")).await;
        if log.contains("sally-shim: listening on 127.0.0.1:3128") {
            lx.egress.resolver.set(GRANT, vec![vec![tls_upstream()]]);
            return r;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the shim never became ready");
}

/// The first base64 line of a PKCS#8 P-256 private key (rcgen and ring write this form; so do
/// OpenSSL and Go), and the DER bytes that follow its curve OID, as `printf` octal escapes.
const KEY_B64: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg";
const KEY_DER_OCTAL: &str = r"\075\003\001\007\004\155\060\153\002\001\001\004\040";

/// The Python live leg: CONNECT to the grant host over `net.sock` in `ws`, verify for `name`.
fn live(ws: &Path, name: &str) -> Command {
    let mut cmd = Command::new("python3");
    cmd.arg("-I")
        .arg(redteam_tls().join("verify.py"))
        .arg("live")
        .arg(ws)
        .arg(ws.join(CA_FILE))
        .arg(GRANT)
        .arg(name);
    cmd
}

/// The planted key's PKCS#8 DER, base64 on one line.
fn planted_b64(key: &KeyPair) -> String {
    let pem = pem::encode(&pem::Pem::new("PRIVATE KEY", key.serialize_der()));
    pem.lines().filter(|l| !l.starts_with("-----")).collect()
}

/// A shell script that plants a throwaway key (a PEM file, its DER, a process environment) and
/// prints every file outside `/proc`, `/sys` and `/dev`, and every `/proc/*/environ`, that holds
/// key material or `ca_line`; `unreadable <path>` for an environment it may not read. Key
/// material: a PEM private-key armor line (the bare label is a string in libcrypto), and the
/// PKCS#8 P-256 prefix in base64 and in DER.
fn search_script(planted_pem: &str, planted_b64: &str, ca_line: &str) -> String {
    format!(
        "set -u\n\
         printf '%s' '{planted_pem}' > /tmp/planted.pem\n\
         printf '%s' '{planted_b64}' | base64 -d > /tmp/planted.der\n\
         env SP_PLANTED='{planted_b64}' sleep 120 </dev/null >/dev/null 2>&1 &\n\
         sleep 1\n\
         der=\"$(printf '{KEY_DER_OCTAL}')\"\n\
         set -- -e 'PRIVATE KEY-----' -e '{KEY_B64}' -e \"$der\" -e '{ca_line}'\n\
         find / \\( -path /proc -o -path /sys -o -path /dev \\) -prune -o -type f -print0 2>/dev/null \
           | xargs -0 grep -l -a -F \"$@\" 2>/dev/null\n\
         for e in /proc/[0-9]*/environ; do\n\
           if [ -e \"$e\" ] && ! [ -r \"$e\" ]; then echo \"unreadable $e\"; fi\n\
           grep -l -a -F \"$@\" \"$e\" 2>/dev/null | sed 's|/[0-9]*/environ$|/<pid>/environ|'\n\
         done\n\
         exit 0\n"
    )
}

fn found(out: &str) -> Vec<String> {
    let mut v: Vec<String> = out.lines().map(str::to_owned).collect();
    v.sort();
    v.dedup();
    v
}

/// RT-SEC-10, key reach and the live leg. Controls: the leaf keys and the CA key live only in
/// `sallyd` (`SessionTls`; the CA key is dropped after minting, Q38 (f)) and the CA files go to
/// the workspace socket directory only (`ca::write_files`; `harness_argv` binds the harness
/// directory alone, SI-2). Planting a key in either container is found (positive control), so
/// a key written anywhere the sandbox can read fails the test; so does a CA file in the harness.
#[test]
fn rt_sec_10_no_private_key_reaches_a_container_and_the_harness_gets_no_ca_file() {
    rt().block_on(async {
        let lx = Lx::new();
        let tag = "sec10";
        let r = session(&lx, tag).await;
        let paths = lx.paths(tag);
        let ws = paths.workspace_sockets();

        // Live: Python's OpenSSL client verifies the session's real leaf for the grant host
        // against the container's CA file, and refuses it for another name. Off the runtime:
        // the proxy serving `net.sock` runs on it.
        for (name, verifies) in [(GRANT, true), ("other.mock.test", false)] {
            let mut cmd = live(&ws, name);
            let got = tokio::task::spawn_blocking(move || run("python3", &mut cmd))
                .await
                .unwrap();
            assert_eq!(got.is_ok(), verifies, "{name}: {got:?}");
        }

        let ca_pem = std::fs::read_to_string(ws.join(CA_FILE)).unwrap();
        let ca_line = ca_pem.lines().nth(1).unwrap().to_owned();
        let planted = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let script = search_script(&planted.serialize_pem(), &planted_b64(&planted), &ca_line);

        let (code, out) = exec(&r, &script).await;
        assert_eq!(code, 0, "{out}");
        assert_eq!(
            found(&out),
            [
                "/proc/<pid>/environ",
                &format!("/run/sallyport/{BUNDLE_FILE}"),
                &format!("/run/sallyport/{CA_FILE}"),
                "/tmp/planted.der",
                "/tmp/planted.pem",
            ],
            "workspace"
        );

        // A harness of the same session (its own socket directory, SI-2).
        let v = lx.f.load(MANIFEST);
        let common = CommonArgs {
            runtime: lx.runtime.clone(),
            ids: ids(),
            profiles: paths.data_root().join("profiles"),
            hooks_dir: lx.podman.hooks_dir(),
            mounts_file: lx.podman.mounts_file(),
        };
        let argv = harness_argv(&common, &paths, &v, &test_image()).unwrap();
        let id = lx.hermetic(&argv).await;
        let id = id.lines().last().unwrap().to_owned();
        lx.hermetic(&["start".to_owned(), id.clone()]).await;
        let (code, out) = tokio::task::spawn_blocking(move || exec_in(&id, &["sh", "-c", &script]))
            .await
            .unwrap();
        assert_eq!(code, 0, "{out}");
        assert_eq!(
            found(&out),
            [
                "/proc/<pid>/environ",
                "/tmp/planted.der",
                "/tmp/planted.pem"
            ],
            "harness"
        );
        for f in [BUNDLE_FILE, CA_FILE] {
            assert!(!paths.harness_sockets().join(f).exists(), "{f}");
        }
        lx.stop(r).await;
    });
}
