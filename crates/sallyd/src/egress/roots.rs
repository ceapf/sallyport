//! The upstream trust roots of the token proxy (Task 9a decision 4 and 6, architect Q31).
//!
//! Loaded per session at launch from the first CA bundle file that exists in a fixed list; the
//! list and the required owner are constructor arguments ([`BundleFiles`]), and production passes
//! [`SYSTEM_BUNDLES`] owned by root. `SSL_CERT_FILE` and `SSL_CERT_DIR` in `sallyd`'s environment
//! are not honoured: the environment never chooses the anchors of a credential-carrying
//! connection. The file must be a regular file (after symlinks), owned by the expected user, not
//! group- or other-writable, and at most [`MAX_BUNDLE_BYTES`]. Certificates the verifier cannot use
//! are skipped and counted; no usable certificate is an error. One load feeds both the upstream
//! verifier and the workspace's `ca-bundle.pem`, which is re-encoded from the accepted
//! certificates, never copied.

use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustix::fs::{FileType, Mode, OFlags};
use rustls::RootCertStore;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;

/// Where distributions keep the system CA bundle, tried in order (Debian/Ubuntu/Alpine/Arch,
/// Fedora/RHEL, openSUSE/macOS-style, RHEL extracted).
pub const SYSTEM_BUNDLES: [&str; 4] = [
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/cert.pem",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
];

/// The largest bundle read (Debian's is about 220 KiB).
pub const MAX_BUNDLE_BYTES: u64 = 4 << 20;

/// Why no trust roots were loaded. Each refuses the launch of a session with secrets.
#[derive(Debug, thiserror::Error)]
pub enum RootsError {
    /// None of the candidate files exists.
    #[error("trust roots: no CA bundle found (tried {0})")]
    NotFound(String),
    /// The file exists but may not be trusted.
    #[error("trust roots: {path}: {why}")]
    Untrusted {
        /// The file.
        path: PathBuf,
        /// What is wrong with it.
        why: &'static str,
    },
    /// Opening or reading failed.
    #[error("trust roots: {path}: {err}")]
    Io {
        /// The file.
        path: PathBuf,
        /// The error.
        #[source]
        err: io::Error,
    },
    /// A PEM section is malformed.
    #[error("trust roots: {path}: malformed PEM")]
    Pem {
        /// The file.
        path: PathBuf,
    },
    /// No certificate in the file is usable as a trust anchor.
    #[error("trust roots: {path}: no usable certificate")]
    Empty {
        /// The file.
        path: PathBuf,
    },
}

/// The trust roots of one session. `Debug` shows the file and the counts, never the bundle.
#[derive(Clone)]
pub struct Roots {
    /// The upstream verifier's anchors.
    pub store: Arc<RootCertStore>,
    /// The accepted certificates, PEM (LF line ends), in file order.
    pub pem: String,
    /// Certificates in the file that the verifier could not use.
    // TODO(#56): audit the path and this count once interception uses the roots (Task 9a-2).
    pub skipped: usize,
    /// The file they came from.
    pub path: PathBuf,
}

impl std::fmt::Debug for Roots {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Roots")
            .field("path", &self.path)
            .field("anchors", &self.store.len())
            .field("skipped", &self.skipped)
            .finish_non_exhaustive()
    }
}

/// The candidate bundle files and their required owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleFiles {
    /// Tried in order; the first that exists is used, and only it.
    pub paths: Vec<PathBuf>,
    /// The uid that must own it.
    pub owner: u32,
}

impl Default for BundleFiles {
    /// [`SYSTEM_BUNDLES`], owned by root.
    fn default() -> Self {
        Self {
            paths: SYSTEM_BUNDLES.iter().map(PathBuf::from).collect(),
            owner: 0,
        }
    }
}

impl BundleFiles {
    /// Loads the roots from the first candidate that exists.
    ///
    /// # Errors
    /// [`RootsError`]; a candidate that exists but fails a check is an error, never skipped.
    pub fn load(&self) -> Result<Roots, RootsError> {
        for path in &self.paths {
            match read(path, self.owner) {
                Ok(bytes) => return parse(path, &bytes),
                Err(RootsError::Io { err, .. }) if err.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        let tried: Vec<String> = self.paths.iter().map(|p| p.display().to_string()).collect();
        Err(RootsError::NotFound(tried.join(", ")))
    }
}

/// Opens `path` without blocking (a FIFO must not hang the launch), checks the opened file, and
/// reads it within the cap. The open precedes the type check, so a device node at a candidate
/// path would be opened (security review L3, accepted): placing one there takes root, which
/// already controls the roots.
fn read(path: &Path, owner: u32) -> Result<Vec<u8>, RootsError> {
    let io = |err: io::Error| RootsError::Io {
        path: path.to_owned(),
        err,
    };
    let untrusted = |why| RootsError::Untrusted {
        path: path.to_owned(),
        why,
    };
    let flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOCTTY;
    let fd = sally_core::fd::open(path, flags, Mode::empty()).map_err(|e| io(e.into()))?;
    let st = rustix::fs::fstat(&fd).map_err(|e| io(e.into()))?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Err(untrusted("not a regular file"));
    }
    if st.st_uid != owner {
        return Err(untrusted("not owned by the expected user"));
    }
    if st.st_mode & 0o022 != 0 {
        return Err(untrusted("group- or other-writable"));
    }
    let mut bytes = Vec::new();
    std::fs::File::from(fd)
        .take(MAX_BUNDLE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_BUNDLE_BYTES {
        return Err(untrusted("larger than 4 MiB"));
    }
    Ok(bytes)
}

/// The usable certificates of `bytes`: added to the store and re-encoded.
fn parse(path: &Path, bytes: &[u8]) -> Result<Roots, RootsError> {
    let mut store = RootCertStore::empty();
    let (mut pem, mut skipped) = (String::new(), 0usize);
    for item in CertificateDer::pem_slice_iter(bytes) {
        let der = item.map_err(|_| RootsError::Pem {
            path: path.to_owned(),
        })?;
        if store.add(der.clone()).is_ok() {
            pem.push_str(&encode(&der));
        } else {
            skipped += 1;
        }
    }
    if store.is_empty() {
        return Err(RootsError::Empty {
            path: path.to_owned(),
        });
    }
    Ok(Roots {
        store: Arc::new(store),
        pem,
        skipped,
        path: path.to_owned(),
    })
}

/// One certificate as PEM with LF line ends.
#[must_use]
pub fn encode(der: &CertificateDer<'_>) -> String {
    let config = pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF);
    pem::encode_config(&pem::Pem::new("CERTIFICATE", der.as_ref()), config)
}

#[cfg(test)]
#[path = "roots_tests.rs"]
mod tests;
