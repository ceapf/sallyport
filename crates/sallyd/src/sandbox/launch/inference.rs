//! The CPU inference launch (#123; architect Q131, Q140): GPU inference is refused first
//! (TODO(#116), M3). An instance is not a session: its entries carry `instance` in their args,
//! and its two directories (the socket directory and the profiles) are made fresh by this
//! launch, which is also its claim on the id, and removed by its stop. The model blob and the
//! socket directory are pinned, re-checked on the host after `create` and compared inside the
//! container after `init`.
//!
//! TODO(#134): the orphan sweeps do not cover `sp-infer-<id>` containers; that must be fixed
//! before any RPC or daemon path reaches this launch.

use std::sync::Arc;

use sally_core::manifest::{AuditLevel, ByteSize, Cpus};

use super::parts::{HostPin, Subject};
use super::start::{Extra, Prepared, Recheck, Request, RoleRunning};
use super::{LaunchError, Launcher, Progress, blocking};
use crate::sandbox::argv::{MODEL_GUEST, SOCKETS_GUEST, inference_build};
use crate::sandbox::dirs::InstanceDirs;
use crate::sandbox::types::{
    CheckedRuntime, ImageRef, InferenceSpec, InstancePaths, SessionId, VerifiedModel,
};

/// What an inference launch needs: [`InferenceSpec`] without its socket directory, which the
/// launcher derives from the instance id (`$XDG_RUNTIME_DIR/sallyport/infer/<id>`, architect
/// Q140), and the audit level of its entries.
#[derive(Debug, Clone)]
pub struct InferenceRequest {
    /// Instance id; never reused.
    pub instance: SessionId,
    /// The verified model blob (SI-6), mounted read-only.
    pub model: VerifiedModel,
    /// Inference image.
    pub image: ImageRef,
    /// GPU passthrough: refused `gpu-unsupported` until M3 (TODO(#116)).
    pub gpu: bool,
    /// `-ngl`.
    pub gpu_layers: u32,
    /// `-c`.
    pub context: u32,
    /// `--cpus`.
    pub cpus: Cpus,
    /// `--memory`; optional because mmap'd weights count as page cache.
    pub memory: Option<ByteSize>,
    /// The audit level of the instance's entries.
    pub level: AuditLevel,
}

impl Launcher {
    /// Launches a CPU inference container and starts it once every check passed, through the
    /// one launch path. The work runs in its own task, like [`Launcher::launch_workspace`].
    ///
    /// # Errors
    /// [`LaunchError`]: [`LaunchError::GpuUnsupported`] first for a GPU request; otherwise as
    /// for the workspace, with the instance's directories removed on a failure.
    pub async fn launch_inference(
        self: &Arc<Self>,
        req: InferenceRequest,
    ) -> Result<RoleRunning, LaunchError> {
        let paths = InstancePaths::under(
            req.instance.clone(),
            &self.xdg_runtime_dir.join(crate::daemon::startup::STATE_DIR),
            &self.data_dir,
        );
        // TODO(#135): refuse inside the spawned task, so a dropped caller cannot cut the entry.
        match paths {
            Ok(p) => self.spawn_role(Request::Inference(req, p)).await,
            Err(e) => {
                let subject = Subject::Instance(req.instance.clone());
                Err(self
                    .refused(
                        &subject,
                        crate::sandbox::types::Role::Inference,
                        e.into(),
                        req.level,
                        "nothing to clean up".into(),
                    )
                    .await)
            }
        }
    }

    /// The image found, the instance's directories made (recorded in `progress`), the socket
    /// directory and the model pinned, the argv built.
    pub(super) async fn prepare_inference(
        &self,
        req: &InferenceRequest,
        paths: &InstancePaths,
        image: &ImageRef,
        runtime: CheckedRuntime,
        progress: &mut Progress,
    ) -> Result<(Prepared, Extra), LaunchError> {
        let present = self.image_present(image).await?;
        let (p, xdg) = (paths.clone(), self.xdg_runtime_dir.clone());
        let created = blocking(move || Ok(InstanceDirs::create(&p, &xdg))).await?;
        let made = paths.created_dirs();
        progress.dirs = match &created {
            Ok(_) => made.clone(),
            Err(e) => e.created.clone(),
        };
        let dirs = created?;
        let sockets = paths.socket_dir().to_owned();
        let socket_pin = blocking(move || Ok(HostPin::dir(&sockets, SOCKETS_GUEST)?)).await?;
        let model_pin = HostPin::model(&req.model, MODEL_GUEST);
        let spec = InferenceSpec {
            instance: req.instance.clone(),
            socket_dir: paths.socket_dir().to_owned(),
            model: req.model.clone(),
            image: image.clone(),
            // Refused at admission (TODO(#116)): no GPU before M3.
            gpu: false,
            gpu_layers: req.gpu_layers,
            context: req.context,
            cpus: req.cpus,
            memory: req.memory,
        };
        let common = self.common_args(runtime, dirs.profiles().to_owned());
        let built = inference_build(&common, &spec)?;
        let prepared = Prepared {
            subject: Subject::Instance(req.instance.clone()),
            level: req.level,
            name: format!("sp-infer-{}", req.instance.as_str()),
            launch_args: vec![("image", present.as_str().into())],
            image: present,
            built,
            recheck: Recheck::Pins(vec![model_pin, socket_pin]),
        };
        Ok((prepared, Extra::Role { dirs: made }))
    }
}
