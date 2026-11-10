//! Semantic validation: `Manifest` + host facts + secret catalog → `ValidatedManifest`.
//!
//! Every check here has an allow and a deny unit test (CLAUDE.md, MANIFEST_SPEC §3).

mod ack;
mod exposure;
mod fs;
mod net;
mod rest;
mod secrets;

use std::collections::{BTreeSet, HashSet};
use std::hash::BuildHasher;
use std::path::PathBuf;

use super::diag::{Code, Diagnostic, Diags, Rejected};
use super::host::HostPattern;
use super::hostenv::HostEnv;
use super::parse::parse;
use super::paths::DirId;
use super::types::{ApproveGlobs, Manifest, MountMode};

pub(crate) use exposure::data_can_leave;

/// The set of secret names present in the secrets store. Validation only asks whether a name
/// exists; it never sees values (SI-3).
pub trait SecretCatalog {
    /// Whether a secret with this name exists.
    fn contains(&self, name: &str) -> bool;
}

impl SecretCatalog for BTreeSet<String> {
    fn contains(&self, name: &str) -> bool {
        BTreeSet::contains(self, name)
    }
}

impl<S: BuildHasher> SecretCatalog for HashSet<String, S> {
    fn contains(&self, name: &str) -> bool {
        HashSet::contains(self, name)
    }
}

/// A mount after validation: the host side is the realpath at validation time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedMount {
    /// Host realpath (what the user sees in messages; what the sandbox driver mounts).
    pub host: PathBuf,
    /// Guest path under `/workspace/`.
    pub guest: String,
    /// Access mode.
    pub mode: MountMode,
    /// Approval globs (empty unless `brokered`).
    pub approve: ApproveGlobs,
    /// Directory identity at validation; private so only validation can construct this.
    id: DirId,
}

impl ResolvedMount {
    /// `(st_dev, st_ino)` of the host directory at validation. The sandbox driver pins the mount
    /// root to it: the launch scan opens the root without following symlinks and compares, and
    /// the post-init check compares what the container sees (AMENDMENTS-02 B4).
    #[must_use]
    pub fn identity(&self) -> (u64, u64) {
        (self.id.dev, self.id.ino)
    }
}

/// One egress allow rule after validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressRule {
    /// Host pattern.
    pub host: HostPattern,
    /// Allowed ports (non-empty, unique, non-zero).
    pub ports: Vec<u16>,
}

/// A manifest that passed validation. Only [`validate`] constructs one.
///
/// This is the canonical struct launch works from (RT-MAN-03): it owns all data, so editing or
/// deleting the manifest file after validation cannot change what is launched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedManifest {
    manifest: Manifest,
    mounts: Vec<ResolvedMount>,
    egress: Vec<EgressRule>,
    acknowledged: Vec<String>,
}

impl ValidatedManifest {
    /// The parsed manifest.
    #[must_use]
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Mounts with resolved host realpaths, in manifest order.
    #[must_use]
    pub fn mounts(&self) -> &[ResolvedMount] {
        &self.mounts
    }

    /// Egress rules with parsed host patterns, in manifest order. Empty when
    /// `network.mode: none`.
    #[must_use]
    pub fn egress(&self) -> &[EgressRule] {
        &self.egress
    }

    /// The acknowledgements that are set and in effect: `network.acknowledge_unrestricted_egress`
    /// and `tools.acknowledge_unapproved: <entry>`. Launch records a
    /// `manifest.acknowledged_risk` audit event for each, and the UI shows a red banner.
    #[must_use]
    pub fn acknowledged_risks(&self) -> &[String] {
        &self.acknowledged
    }

    /// Launch-time TOCTOU re-check (RT-FS-06): every mount root must still pass the host checks
    /// *and* still resolve to the realpath recorded at validation.
    ///
    /// This narrows but does not close the race with the container runtime; the sandbox driver
    /// must additionally pin the directory (task 6). Performs blocking filesystem I/O.
    ///
    /// # Errors
    /// [`Rejected`] listing every mount that changed or now fails a check.
    pub fn recheck_mounts(&self, env: &HostEnv) -> Result<(), Rejected> {
        let mut d = Diags::default();
        let deny = fs::denylist(&self.manifest, env, &mut d);
        for (i, (raw, resolved)) in self
            .manifest
            .filesystem
            .mounts
            .iter()
            .zip(&self.mounts)
            .enumerate()
        {
            let path = format!("filesystem.mounts[{i}].host");
            match super::paths::check_mount_host(&raw.host, &env.home, &deny) {
                Ok((real, id)) if real == resolved.host && id == resolved.id => {}
                Ok((real, _)) if real == resolved.host => d.error(
                    path,
                    Code::MountChanged,
                    format!(
                        "{:?} was replaced by a different directory since validation",
                        raw.host
                    ),
                ),
                Ok((real, _)) => d.error(
                    path,
                    Code::MountChanged,
                    format!(
                        "{:?} now resolves to {:?}, not {:?} as validated",
                        raw.host,
                        real.display().to_string(),
                        resolved.host.display().to_string()
                    ),
                ),
                Err((code, msg)) => d.error(path, code, msg),
            }
        }
        d.finish().map(|_| ())
    }
}

/// Successful validation: the manifest plus any warnings to show the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Validated {
    /// The validated manifest.
    pub manifest: ValidatedManifest,
    /// Non-fatal findings.
    pub warnings: Vec<Diagnostic>,
}

/// Validates a parsed manifest against the host and the secrets store.
///
/// All checks run (errors do not short-circuit) so the user sees every problem at once.
/// Performs blocking filesystem I/O (`lstat`, `realpath`); use `spawn_blocking` from async code.
///
/// # Errors
/// [`Rejected`] with every error found, plus warnings.
pub fn validate(
    manifest: Manifest,
    env: &HostEnv,
    secrets: &dyn SecretCatalog,
) -> Result<Validated, Rejected> {
    let mut d = Diags::default();
    rest::check_identity(&manifest, &mut d);
    rest::check_harness(manifest.harness.as_ref(), &mut d);
    rest::check_runtime(&manifest.runtime, env, &mut d);
    rest::check_model(&manifest.model, &mut d);
    let mounts = fs::check_filesystem(&manifest, env, &mut d);
    let egress = net::check_network(&manifest.network, &mut d);
    secrets::check_secrets(&manifest, &egress, secrets, &mut d);
    rest::check_tools(&manifest, &mut d);
    secrets::check_mcp(&manifest.tools.mcp, &mut d);
    rest::check_approvals_and_policy(&manifest, &mut d);
    let wildcard_live = wildcard_acknowledged(&manifest, &egress);
    let egress = match manifest.network.mode {
        super::types::NetworkMode::Proxy => egress,
        super::types::NetworkMode::None => Vec::new(),
    };
    let finding = exposure::data_can_leave(&manifest, &mounts, &egress);
    ack::check(&manifest, finding.is_some(), &mut d);
    let mut acknowledged: Vec<String> = wildcard_live.into_iter().map(str::to_owned).collect();
    acknowledged.extend(ack::acknowledged(&manifest, finding.is_some()));
    if let Some(finding) = finding {
        d.warn("network.allow", Code::DataCanLeave, finding);
    }
    let warnings = d.finish()?;
    Ok(Validated {
        manifest: ValidatedManifest {
            manifest,
            mounts,
            egress,
            acknowledged,
        },
        warnings,
    })
}

/// `network.acknowledge_unrestricted_egress` when it is set and its risk is live (the same
/// predicate the check uses). Tool acknowledgements come from [`ack::acknowledged`].
fn wildcard_acknowledged(m: &Manifest, parsed_egress: &[EgressRule]) -> Option<&'static str> {
    (m.network.acknowledge_unrestricted_egress
        && m.network.mode == super::types::NetworkMode::Proxy
        && rest::wildcard_needs_ack(parsed_egress))
    .then_some("network.acknowledge_unrestricted_egress")
}

/// Parses and validates manifest text in one step. Performs blocking filesystem I/O.
///
/// # Errors
/// [`Rejected`] from parsing or validation.
pub fn load(text: &str, env: &HostEnv, secrets: &dyn SecretCatalog) -> Result<Validated, Rejected> {
    validate(parse(text)?, env, secrets)
}
