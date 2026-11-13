//! The per-session interception CA (ARCHITECTURE §7; Task 9a decision 3, architect Q38).
//!
//! At launch of a session with secret grants, `sallyd` makes a CA that can only vouch for the
//! session's grant hosts, mints one leaf per grant host, and drops the CA key. The CA key never
//! leaves this function; the leaf keys stay in `sallyd` memory as [`Secret`] for the life of the
//! session's proxy. The workspace gets only the CA certificate (`session-ca.pem`, and inside
//! `ca-bundle.pem`).
//!
//! CA: ECDSA P-256; `basicConstraints` CA:true, pathlen 0; `keyUsage` keyCertSign only; EKU
//! serverAuth; critical `nameConstraints` permitting `dNSName` = each grant host, excluding
//! `dNSName` `.<host>` (its subdomains; omitted where another grant host lies beneath it) and every
//! IPv4 and IPv6 address. Validity: from now, rounded down to the second, to now +
//! `runtime.timeout` + [`GRACE`]. Leaves: one SAN (the host), EKU serverAuth, `keyUsage`
//! digitalSignature, not a CA, the CA's validity.

use std::io::{self, Write};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rcgen::{
    BasicConstraints, CertificateParams, CidrSubnet, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    NameConstraints, PKCS_ECDSA_P256_SHA256,
};
use rustix::fd::AsFd;
use rustix::fs::{Mode, OFlags};
use rustls_pki_types::CertificateDer;
use sally_core::manifest::{Manifest, NetworkMode};
use sally_core::secrets::Secret;
use time::OffsetDateTime;

/// Validity past the session's `runtime.timeout` (decision 3: "the session plus 5 minutes").
pub const GRACE: Duration = Duration::from_secs(5 * 60);

/// Common name of the session CA.
pub const CA_NAME: &str = "Sallyport session CA";

/// The workspace's bundle: the session's system roots, then the session CA.
pub const BUNDLE_FILE: &str = "ca-bundle.pem";

/// The session CA alone (`NODE_EXTRA_CA_CERTS`).
pub const CA_FILE: &str = "session-ca.pem";

/// Whether a session gets a session CA and the two CA files: proxy mode with at least one secret
/// grant. `sandbox::argv` sets the CA variables under the same condition (architect Q38 (g)).
#[must_use]
pub fn wanted(m: &Manifest) -> bool {
    m.network.mode == NetworkMode::Proxy && !m.secrets.is_empty()
}

/// Why the session CA could not be made.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CaError {
    /// No grant host to constrain the CA to.
    #[error("session CA: no grant host")]
    NoHosts,
    /// The clock is before 1970 or the validity end is out of range.
    #[error("session CA: validity out of range")]
    Validity,
    /// Certificate generation failed.
    #[error("session CA: {0}")]
    Generate(String),
    /// The leaves and the credentials name different hosts (Task 9a-3, architect D10).
    #[error("session CA: the leaves and the credentials name different hosts")]
    Unmatched,
}

impl From<rcgen::Error> for CaError {
    fn from(e: rcgen::Error) -> Self {
        Self::Generate(e.to_string())
    }
}

/// The validity of the session CA and its leaves, in whole seconds since the epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Validity {
    /// Start: `now`, rounded down to the second.
    pub not_before: i64,
    /// End: start + `timeout` + [`GRACE`].
    pub not_after: i64,
}

impl Validity {
    /// The validity of a session that starts at `now` and may run for `timeout`.
    ///
    /// # Errors
    /// [`CaError::Validity`] for a clock before the epoch or an end past what fits.
    pub fn for_session(now: SystemTime, timeout: Duration) -> Result<Self, CaError> {
        let start = now
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CaError::Validity)?;
        let not_before = i64::try_from(start.as_secs()).map_err(|_| CaError::Validity)?;
        let span = timeout.checked_add(GRACE).ok_or(CaError::Validity)?;
        let span = i64::try_from(span.as_secs()).map_err(|_| CaError::Validity)?;
        let not_after = not_before.checked_add(span).ok_or(CaError::Validity)?;
        Ok(Self {
            not_before,
            not_after,
        })
    }

    fn apply(self, p: &mut CertificateParams) -> Result<(), CaError> {
        let at = |s| OffsetDateTime::from_unix_timestamp(s).map_err(|_| CaError::Validity);
        p.not_before = at(self.not_before)?;
        p.not_after = at(self.not_after)?;
        Ok(())
    }
}

/// The grant hosts, sorted and without duplicates (one host may carry several grants).
#[must_use]
pub fn grant_hosts(hosts: &[String]) -> Vec<String> {
    let mut out = hosts.to_vec();
    out.sort();
    out.dedup();
    out
}

/// The subdomain exclusions: `.<host>` for each grant host, except a host that has another grant
/// host beneath it (excluding `.github.com` would refuse `api.github.com`'s own leaf). The
/// residual: the CA could vouch for other names under such a host, had anyone its key.
#[must_use]
pub fn subdomain_exclusions(hosts: &[String]) -> Vec<String> {
    hosts
        .iter()
        .filter(|h| {
            let below = format!(".{h}");
            !hosts.iter().any(|g| g.ends_with(&below))
        })
        .map(|h| format!(".{h}"))
        .collect()
}

/// The parameters of the session CA for `hosts` (already normalized: lowercase, no trailing dot).
/// Public so tests build a CA from these exact parameters with their own key; no API exports the
/// session's key or mints a leaf for another name (architect Q33).
///
/// # Errors
/// [`CaError::NoHosts`] for an empty list, [`CaError::Validity`], [`CaError::Generate`].
pub fn ca_params(hosts: &[String], v: Validity) -> Result<CertificateParams, CaError> {
    let hosts = grant_hosts(hosts);
    if hosts.is_empty() {
        return Err(CaError::NoHosts);
    }
    let mut p = CertificateParams::new(Vec::<String>::new())?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, CA_NAME);
    p.distinguished_name = dn;
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let mut excluded: Vec<GeneralSubtree> = subdomain_exclusions(&hosts)
        .into_iter()
        .map(GeneralSubtree::DnsName)
        .collect();
    excluded.push(GeneralSubtree::IpAddress(CidrSubnet::V4([0; 4], [0; 4])));
    excluded.push(GeneralSubtree::IpAddress(CidrSubnet::V6([0; 16], [0; 16])));
    p.name_constraints = Some(NameConstraints {
        permitted_subtrees: hosts.into_iter().map(GeneralSubtree::DnsName).collect(),
        excluded_subtrees: excluded,
    });
    v.apply(&mut p)?;
    Ok(p)
}

/// The parameters of the leaf for `host`.
///
/// # Errors
/// [`CaError::Validity`], [`CaError::Generate`] (a name rcgen cannot encode).
pub fn leaf_params(host: &str, v: Validity) -> Result<CertificateParams, CaError> {
    let mut p = CertificateParams::new(vec![host.to_owned()])?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, host);
    p.distinguished_name = dn;
    p.is_ca = IsCa::ExplicitNoCa;
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    p.use_authority_key_identifier_extension = true;
    v.apply(&mut p)?;
    Ok(p)
}

/// The certificate and key one grant host is served with.
pub struct Leaf {
    /// The grant host (the leaf's only SAN).
    pub host: String,
    /// The leaf certificate.
    pub cert: CertificateDer<'static>,
    /// Its PKCS#8 private key.
    pub key: Secret<Vec<u8>>,
}

impl std::fmt::Debug for Leaf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Leaf")
            .field("host", &self.host)
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

/// A session's CA certificate and its leaves. The CA key is gone by the time this exists.
#[derive(Debug)]
pub struct SessionTls {
    /// The CA certificate.
    pub ca: CertificateDer<'static>,
    /// The CA certificate, PEM (`session-ca.pem`).
    pub ca_pem: String,
    /// One leaf per grant host, sorted by host.
    pub leaves: Vec<Leaf>,
    /// The validity of the CA and every leaf.
    pub validity: Validity,
}

impl SessionTls {
    /// Makes the CA for `hosts`, mints one leaf per host, and drops the CA key (architect
    /// Q38 (f)).
    ///
    /// # Errors
    /// [`CaError`].
    pub fn mint(hosts: &[String], v: Validity) -> Result<Self, CaError> {
        let params = ca_params(hosts, v)?;
        // `Secret` zeroizes rcgen's DER copy of each key on drop, error paths included.
        let ca_key = Secret::new(KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?);
        let ca = params.self_signed(ca_key.expose())?;
        let issuer = Issuer::new(params, ca_key.expose());
        let leaves = grant_hosts(hosts)
            .into_iter()
            .map(|host| {
                let key = Secret::new(KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?);
                let cert = leaf_params(&host, v)?.signed_by(key.expose(), &issuer)?;
                Ok(Leaf {
                    host,
                    cert: cert.der().clone(),
                    key: Secret::new(key.expose().serialize_der()),
                })
            })
            .collect::<Result<Vec<_>, CaError>>()?;
        drop(issuer);
        drop(ca_key);
        Ok(Self {
            ca: ca.der().clone(),
            ca_pem: ca.pem(),
            leaves,
            validity: v,
        })
    }
}

/// Writes [`CA_FILE`] (the CA) and [`BUNDLE_FILE`] (`roots_pem`, then the CA) into `dir`, the
/// workspace's socket directory, before the container starts (architect Q38 (g), (h)). Each is
/// created new (an existing name, a symlink included, fails), mode exactly 0444 whatever the
/// umask, through the `sally_core::fd` wrappers; `dir` itself may not be a symlink.
///
/// # Errors
/// The open, chmod or write error, naming the path.
pub fn write_files(dir: &Path, tls: &SessionTls, roots_pem: &str) -> io::Result<()> {
    let named = |name: &str| {
        let path = dir.join(name);
        move |e: io::Error| io::Error::new(e.kind(), format!("{}: {e}", path.display()))
    };
    let flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW;
    let fd = sally_core::fd::open(dir, flags, Mode::empty()).map_err(|e| named("")(e.into()))?;
    write_new(&fd, CA_FILE, tls.ca_pem.as_bytes()).map_err(named(CA_FILE))?;
    let bundle = format!("{roots_pem}{}", tls.ca_pem);
    write_new(&fd, BUNDLE_FILE, bundle.as_bytes()).map_err(named(BUNDLE_FILE))
}

fn write_new(dir: impl AsFd, name: &str, body: &[u8]) -> io::Result<()> {
    let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW;
    let mode = Mode::RUSR | Mode::RGRP | Mode::ROTH;
    let fd = sally_core::fd::openat(dir, name, flags, mode)?;
    rustix::fs::fchmod(&fd, mode)?;
    std::fs::File::from(fd).write_all(body)
}

#[cfg(test)]
#[path = "ca_tests.rs"]
mod tests;
