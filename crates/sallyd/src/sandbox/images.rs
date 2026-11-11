//! The pinned image must already be in local storage (MANIFEST_SPEC §3, RT-SUP-01, RT-SUP-02).
//!
//! This check exists for a clear refusal reason (`digest-mismatch`) only. The enforcement is the
//! digest reference plus `--pull=never` at `podman create`: nothing depends on the gap between
//! this check and the create. It runs through hermetic podman, after its configuration has been
//! re-checked, and fails closed on any podman error or ambiguous result.

use super::commands::Stored;
use super::launch::{LaunchError, Launcher, WorkspaceRequest};

impl WorkspaceRequest {
    /// The workspace image: the manifest's `runtime.image`, or the bundled default.
    pub(super) fn image(&self) -> &str {
        let m = self.manifest.manifest();
        m.runtime
            .image
            .as_deref()
            .unwrap_or(self.default_image.as_str())
    }
}

impl Launcher {
    // TODO(#28): the harness and inference launchers (Task 13) call this too.
    /// Refuses unless hermetic podman finds `image` (a digest-pinned reference) in local storage
    /// and the image it resolves to carries the pinned digest.
    ///
    /// The name is checked by `podman image exists` alone (it resolves `name@digest` as a
    /// whole); the inspect step compares the digest only. A reference holds one `@` (the
    /// validator's pinned grammar), so `split_once` here and `rsplit_once` on podman's output
    /// agree.
    ///
    /// # Errors
    /// [`LaunchError::ImageMissing`] when the image is absent, or when `podman image inspect`
    /// does not print exactly one list of references with one carrying the pinned digest;
    /// [`LaunchError::Command`] when podman fails or times out.
    pub(super) async fn image_present(&self, image: &str) -> Result<(), LaunchError> {
        let Some((_, digest)) = image.split_once('@') else {
            return Err(missing(image, "no digest"));
        };
        if !self.exists(Stored::Image, image).await? {
            return Err(missing(
                image,
                "not in local storage (images are never pulled)",
            ));
        }
        let args = [
            "image",
            "inspect",
            "--format",
            "{{json .RepoDigests}}",
            image,
        ];
        let out = self
            .run("image inspect", args.into_iter().map(Into::into))
            .await?;
        if carries_digest(&out, digest) {
            Ok(())
        } else {
            Err(missing(
                image,
                "the local image does not carry the pinned digest",
            ))
        }
    }
}

fn missing(image: &str, why: &str) -> LaunchError {
    LaunchError::ImageMissing(format!("{image}: {why}"))
}

/// `inspect` is podman's output for one image: a single JSON list of `name@digest` strings. Any
/// other shape (several lines, not JSON, not strings) is ambiguous and does not match.
fn carries_digest(inspect: &str, digest: &str) -> bool {
    let Ok(refs) = serde_json::from_str::<Vec<String>>(inspect.trim()) else {
        return false;
    };
    refs.iter()
        .any(|r| r.rsplit_once('@').is_some_and(|(_, d)| d == digest))
}

#[cfg(test)]
mod tests {
    use super::carries_digest;

    const D: &str = "sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc";

    #[test]
    fn the_pinned_digest_must_be_among_the_repo_digests() {
        let one = format!("[\"docker.io/library/alpine@{D}\"]\n");
        assert!(carries_digest(&one, D));
        let two = format!(
            "[\"docker.io/library/alpine@sha256:{}\",\"x@{D}\"]",
            "c".repeat(64)
        );
        assert!(carries_digest(&two, D));
        assert!(!carries_digest(
            &format!("[\"x@sha256:{}\"]", "c".repeat(64)),
            D
        ));
    }

    #[test]
    fn ambiguous_or_malformed_output_does_not_match() {
        let line = format!("[\"x@{D}\"]");
        for bad in [
            String::new(),
            "null".to_owned(),
            "[]".to_owned(),
            format!("{line}\n{line}"),
            format!("[{{\"r\":\"x@{D}\"}}]"),
            format!("x@{D}"),
            format!("[\"x@{D}x\"]"),
        ] {
            assert!(!carries_digest(&bad, D), "{bad:?}");
        }
    }

    /// The manifest's `runtime.image` wins; without one the bundled default is used.
    #[test]
    fn the_workspace_image_is_the_manifests_else_the_default() {
        #![allow(clippy::unwrap_used)]
        use std::sync::Arc;

        use sally_core::manifest::{HostEnv, load};

        use super::super::launch::WorkspaceRequest;
        use super::super::types::{ImageRef, SessionId, SessionPaths};

        let env = HostEnv {
            home: "/nonexistent/home".into(),
            other_homes: Vec::new(),
            xdg_config_home: None,
            xdg_data_home: None,
            xdg_runtime_dir: None,
            podman_storage: Vec::new(),
            nproc: 8,
            mem_bytes: 16 << 30,
        };
        let header = "apiVersion: sallyport/v1\nkind: Manifest\nname: t\nmodel:\n  ref: any\n";
        let custom = format!("ghcr.io/x/tools@{D}");
        let default = format!("ghcr.io/sallyport/workspace@{D}");
        let request = |body: &str| WorkspaceRequest {
            paths: SessionPaths::new(
                SessionId::parse("s-1").unwrap(),
                "/s".as_ref(),
                "/d".as_ref(),
            )
            .unwrap(),
            manifest: Arc::new(
                load(
                    &format!("{header}{body}"),
                    &env,
                    &std::collections::BTreeSet::new(),
                )
                .unwrap()
                .manifest,
            ),
            default_image: ImageRef::parse(&default).unwrap(),
        };
        let named = request(&format!("runtime:\n  image: {custom}\n"));
        assert_eq!(named.image(), custom);
        assert_eq!(request("").image(), default);
    }
}
