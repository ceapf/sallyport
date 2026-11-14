//! The OCI config verifier (Task 14, #15, RT-SUP-04). After `podman init` and the in-container
//! mount check, and before `podman start`, the config the runtime was given must equal what the
//! argv builder intended for the role ([`intent`]), plus what podman adds for every container of
//! that role, and nothing else. It is an allowlist: an unknown key, an extra mount, an extra
//! environment variable or a capability in any set is a [`Mismatch`], and the launch is refused.
//!
//! - [`config`]: the strict, bounded parse;
//! - [`facts`]: the container's own directories and the image's `Config`, checked;
//! - [`process`], [`linux`], [`mounts`]: the comparisons;
//! - [`seccomp`]: the filter derived from the embedded profile, compared by content.
//!
//! Scope (architect Q111): workspace, harness and CPU inference. GPU inference adds CDI hooks,
//! devices and mounts this verifier cannot account for, so it is refused until M3. TODO(#116).

pub mod config;
pub mod facts;
pub mod intent;
pub mod linux;
pub mod mounts;
pub mod process;
pub mod seccomp;
#[cfg(test)]
mod tests;

use sally_core::text::escape_capped;

use self::facts::Facts;
use self::intent::Intent;

/// Bytes of escaped text kept for each part of a [`Mismatch`].
const PART_CAP: usize = 160;

/// The first field of the config that is not what was intended. Its parts are escaped and
/// capped; they never hold an environment value, an argument or the config's body (architect
/// Q110).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{field}: {why}")]
pub struct Mismatch {
    /// The field's path, such as `process.capabilities.bounding` or `mounts[/workspace/p]`.
    pub field: String,
    /// What is wrong with it.
    pub why: String,
}

impl Mismatch {
    /// A mismatch of `field`; both parts are escaped and capped.
    #[must_use]
    pub fn new(field: impl AsRef<str>, why: impl AsRef<str>) -> Self {
        Self::escaped(field.as_ref(), why.as_ref())
    }

    /// [`new`](Self::new), out of a `fn new` so the escaping is mutation-tested (CLAUDE.md).
    fn escaped(field: &str, why: &str) -> Self {
        Self {
            field: escape_capped(field.as_bytes(), PART_CAP),
            why: escape_capped(why.as_bytes(), PART_CAP),
        }
    }
}

/// `Err` of `field` unless `ok`.
pub(crate) fn ensure(ok: bool, field: &str, why: &str) -> Result<(), Mismatch> {
    if ok {
        Ok(())
    } else {
        Err(Mismatch::new(field, why))
    }
}

/// Verifies the config podman wrote (`bytes`) against `intent` and `facts`.
///
/// # Errors
/// The first [`Mismatch`].
pub fn verify(bytes: &[u8], intent: &Intent, facts: &Facts) -> Result<(), Mismatch> {
    ensure(
        !intent.gpu,
        "linux.devices",
        "GPU inference is not verified before M3",
    )?;
    let c = config::parse(bytes)?;
    ensure(c.oci_version == "1.1.0", "ociVersion", "not 1.1.0")?;
    linux::check_hostname(&c.hostname, intent, facts)?;
    process::check(&c.process, intent, facts, &c.hostname)?;
    linux::check_root(&c.root, facts)?;
    linux::check_annotations(&c.annotations, intent, facts)?;
    linux::check(&c.linux, intent, facts)?;
    mounts::check(&c.mounts, intent, facts)
}
