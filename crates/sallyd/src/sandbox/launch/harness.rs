//! The harness launch (#123; architect Q130, Q139, Q142): into a live session only, beside its
//! workspace. The harness binds only its own socket directory, which the session's workspace
//! launch made, and creates nothing; its claim on the session's harness keeps a second launch
//! from creating, or cleaning up, a container of the same name.
//!
//! The session layer stops the harness before the workspace: the workspace's stop releases the
//! session, and with it the harness claim, while the harness would still run. TODO(#133): the
//! session layer launches and stops no harness yet.

use std::sync::Arc;

use sally_core::manifest::ValidatedManifest;

use super::parts::{HostPin, Subject};
use super::start::{Extra, Prepared, Recheck, Request, RoleRunning};
use super::{LaunchError, Launcher, blocking};
use crate::sandbox::argv::{SOCKETS_GUEST, harness_build};
use crate::sandbox::dirs::check_harness_dirs;
use crate::sandbox::types::{CheckedRuntime, ImageRef, SessionPaths};

/// What a harness launch needs.
#[derive(Debug, Clone)]
pub struct HarnessRequest {
    /// The session's directories: its workspace launch made them.
    pub paths: SessionPaths,
    /// The session's validated manifest.
    pub manifest: Arc<ValidatedManifest>,
    /// The bundled harness image, used when the manifest names none. `None` while no bundled
    /// image is installed: such a launch is refused `no-default-image` first (TODO(#88)).
    pub default_image: Option<ImageRef>,
}

impl Launcher {
    /// Launches the harness container of a live session and starts it once every check passed,
    /// through the one launch path. The work runs in its own task, like
    /// [`Launcher::launch_workspace`].
    ///
    /// # Errors
    /// [`LaunchError`]; the container is removed and `sandbox.refuse` (or a mismatch event) is
    /// audited, as for the workspace. [`LaunchError::Lost`] has no entry of its own.
    pub async fn launch_harness(
        self: &Arc<Self>,
        req: HarnessRequest,
    ) -> Result<RoleRunning, LaunchError> {
        self.spawn_role(Request::Harness(req)).await
    }

    /// Step 0: the image, then the session's harness claimed (only while it is live), then the
    /// session's directories checked; a failure frees the claim.
    pub(super) async fn admit_harness(
        &self,
        req: &HarnessRequest,
    ) -> Result<ImageRef, LaunchError> {
        let image = req.image()?;
        let sid = req.paths.id().as_str();
        self.sessions.claim_harness(sid)?;
        let paths = req.paths.clone();
        if let Err(e) =
            blocking(move || check_harness_dirs(&paths).map_err(LaunchError::NoSession)).await
        {
            self.sessions.free_harness(sid);
            return Err(e);
        }
        Ok(image)
    }

    /// The image found, the socket directory pinned, the argv built.
    pub(super) async fn prepare_harness(
        &self,
        req: &HarnessRequest,
        image: &ImageRef,
        runtime: CheckedRuntime,
    ) -> Result<(Prepared, Extra), LaunchError> {
        let present = self.image_present(image).await?;
        let sockets = req.paths.harness_sockets();
        let pin = blocking(move || Ok(HostPin::dir(&sockets, SOCKETS_GUEST)?)).await?;
        let common = self.common_args(runtime, req.paths.data_root().join("profiles"));
        let built = harness_build(&common, &req.paths, &req.manifest, image)?;
        let sid = req.paths.id();
        let prepared = Prepared {
            subject: Subject::Session(sid.clone()),
            level: req.manifest.manifest().audit.level,
            // TODO(#135): one container-name function for every role.
            name: format!("sp-h-{}", sid.as_str()),
            launch_args: vec![("image", present.as_str().into())],
            image: present,
            built,
            recheck: Recheck::Pins(vec![pin]),
        };
        Ok((prepared, Extra::Role { dirs: Vec::new() }))
    }
}
