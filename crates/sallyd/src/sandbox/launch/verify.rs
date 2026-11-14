//! Reading the generated OCI config through hermetic podman and verifying it (Task 14, #15,
//! RT-SUP-04; architect Q99, Q111). The comparison is pure (`sandbox::oci`); this file only
//! fetches its inputs, each bounded: the container's directories (`podman inspect`), the image's
//! `Config` (`podman image inspect`), and the config itself (`podman unshare cat`: the userdata
//! directory belongs to the subordinate root). A podman command that fails is `podman`; output
//! over its bound, not UTF-8 or not of the expected shape is `config-mismatch`.

use std::ffi::OsString;

use rustix::process::{Resource, getrlimit};

use super::{LaunchError, Launcher};
use crate::sandbox::oci::config::MAX_CONFIG;
use crate::sandbox::oci::facts::{
    ContainerPaths, Facts, IMAGE_FORMAT, INSPECT_FORMAT, ImageConfig, MAX_INSPECT,
};
use crate::sandbox::oci::intent::Intent;
use crate::sandbox::oci::{Mismatch, verify};

/// `sallyd`'s own hard limit of `r`; `u64::MAX` when unlimited.
fn own_hard(r: Resource) -> u64 {
    getrlimit(r).maximum.unwrap_or(u64::MAX)
}

impl Launcher {
    /// Verifies the OCI config of the created and initialised `container` (its 64-digit id)
    /// against the argv's `intent`. The workspace launcher calls it after the in-container mount
    /// check and right before `podman start`; the container tests call it on their own
    /// containers. TODO(#123): the harness and inference launchers of Task 13 call it too.
    ///
    /// # Errors
    /// [`LaunchError::ConfigMismatch`] naming the first field that differs, or
    /// [`LaunchError::Command`] when a podman command fails.
    pub async fn verify_config(&self, container: &str, intent: &Intent) -> Result<(), LaunchError> {
        let mismatch = LaunchError::ConfigMismatch;
        let out = self
            .run_raw(
                "inspect",
                os(["inspect", "--format", INSPECT_FORMAT, container]),
                MAX_INSPECT + 1,
            )
            .await?;
        let paths = ContainerPaths::parse(&out, container).map_err(mismatch)?;
        let out = self
            .run_raw(
                "inspect",
                os(["image", "inspect", "--format", IMAGE_FORMAT, &intent.image]),
                MAX_INSPECT + 1,
            )
            .await?;
        let image = ImageConfig::parse(&out).map_err(mismatch)?;
        let config = self
            .run_raw(
                "unshare",
                os(["unshare", "cat", "--", &paths.config]),
                MAX_CONFIG + 1,
            )
            .await?;
        let init = self
            .podman
            .init_path()
            .to_str()
            .ok_or_else(|| mismatch(Mismatch::new("init", "not UTF-8")))?
            .to_owned();
        let facts = Facts {
            paths,
            image,
            init,
            arch: std::env::consts::ARCH,
            own_nofile: own_hard(Resource::Nofile),
            own_nproc: own_hard(Resource::Nproc),
        };
        verify(&config, intent, &facts).map_err(mismatch)
    }
}

fn os<const N: usize>(args: [&str; N]) -> [OsString; N] {
    args.map(OsString::from)
}
