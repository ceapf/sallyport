//! The pinned image must already be in local storage (MANIFEST_SPEC §3, RT-SUP-01, RT-SUP-02).
//!
//! This check exists for a clear refusal reason (`digest-mismatch`) only. The enforcement is the
//! digest reference plus `--pull=never` at `podman create`: nothing depends on the gap between
//! this check and the create. It runs through hermetic podman, after its configuration has been
//! re-checked, and fails closed on any podman error or ambiguous result.

use super::commands::Stored;
use super::launch::{HarnessRequest, LaunchError, Launcher, WorkspaceRequest};
use super::types::ImageRef;

impl WorkspaceRequest {
    /// The workspace image: the manifest's `runtime.image`, or the bundled default.
    ///
    /// # Errors
    /// [`LaunchError::NoDefaultImage`] when there is neither (architect Q58);
    /// [`LaunchError::Argv`] for a manifest image that is not a pinned reference.
    pub(super) fn image(&self) -> Result<ImageRef, LaunchError> {
        match (&self.manifest.manifest().runtime.image, &self.default_image) {
            (Some(i), _) => Ok(ImageRef::parse(i)?),
            (None, Some(d)) => Ok(d.clone()),
            (None, None) => Err(LaunchError::NoDefaultImage),
        }
    }
}

impl HarnessRequest {
    /// The harness image: the manifest's `harness.image`, or the bundled default.
    ///
    /// # Errors
    /// [`LaunchError::NoHarnessImage`] when there is neither (architect Q142);
    /// [`LaunchError::Argv`] for a manifest image that is not a pinned reference.
    pub(super) fn image(&self) -> Result<ImageRef, LaunchError> {
        match (&self.manifest.manifest().harness, &self.default_image) {
            (Some(h), _) => Ok(ImageRef::parse(&h.image)?),
            (None, Some(d)) => Ok(d.clone()),
            (None, None) => Err(LaunchError::NoHarnessImage),
        }
    }
}

/// An image [`Launcher::image_present`] found in local storage with its pinned digest. Only that
/// check makes one, and every role's launch must hand one to the one start path, which compares
/// it with the argv's image (architect Q143): a launch that skips the check does not compile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PresentImage(ImageRef);

impl PresentImage {
    /// The reference.
    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// The argv runs exactly the image that was checked (architect Q143).
    ///
    /// # Errors
    /// [`LaunchError::Internal`] naming both when it does not (a bug).
    pub(crate) fn matches(&self, argv_image: &str) -> Result<(), LaunchError> {
        if self.as_str() == argv_image {
            Ok(())
        } else {
            Err(LaunchError::Internal(format!(
                "the checked image {} is not the argv's {argv_image}",
                self.as_str()
            )))
        }
    }
}

impl Launcher {
    /// Refuses unless hermetic podman finds `image` (a digest-pinned reference) in local storage
    /// and the image it resolves to carries the pinned digest. Every role's launch calls it
    /// before its directories and argv are made.
    ///
    /// The name is checked by `podman image exists` alone (it resolves `name@digest` as a
    /// whole); the inspect step compares the digest only. A reference holds one `@` (the
    /// validator's pinned grammar), so `split_once` here and `rsplit_once` on podman's output
    /// agree.
    ///
    /// # Errors
    /// [`LaunchError::ImageMissing`] when the image is absent, or when `podman image inspect`
    /// does not print exactly one list of references with one carrying the pinned digest;
    /// [`LaunchError::Command`] when podman fails or times out, or when its output is over the
    /// 64 KiB cap (a `RepoDigests` list that long is refused whole, never cut or parsed).
    pub(super) async fn image_present(
        &self,
        pinned: &ImageRef,
    ) -> Result<PresentImage, LaunchError> {
        let image = pinned.as_str();
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
            Ok(PresentImage(pinned.clone()))
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

    /// Architect Q143: the start path runs only the image that was found.
    #[test]
    fn a_checked_image_matches_only_itself() {
        #![allow(clippy::unwrap_used)]
        let r = format!("ghcr.io/x/tools@{D}");
        let present = super::PresentImage(super::ImageRef::parse(&r).unwrap());
        assert_eq!(present.as_str(), r);
        present.matches(&r).unwrap();
        let other = format!("ghcr.io/x/other@{D}");
        let e = present.matches(&other).unwrap_err();
        assert_eq!(
            e.to_string(),
            format!("internal: the checked image {r} is not the argv's {other}")
        );
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

    /// The manifest's `runtime.image` wins; without one the bundled default is used, and with
    /// no default either the launch is refused `no-default-image` (architect Q58).
    #[test]
    fn the_workspace_image_is_the_manifests_else_the_default() {
        #![allow(clippy::unwrap_used)]
        use std::sync::Arc;

        use sally_core::manifest::{HostEnv, load};

        use super::super::launch::{LaunchError, WorkspaceRequest};
        use super::super::types::{ImageRef, SessionId, SessionPaths};

        let env = HostEnv {
            home: "/nonexistent/home".into(),
            other_homes: Vec::new(),
            xdg_config_home: None,
            xdg_data_home: None,
            xdg_state_home: None,
            xdg_runtime_dir: None,
            podman_storage: Vec::new(),
            env_dirs: Vec::new(),
            nproc: 8,
            mem_bytes: 16 << 30,
        };
        let header = "apiVersion: sallyport/v1\nkind: Manifest\nname: t\nmodel:\n  ref: any\n";
        let custom = format!("ghcr.io/x/tools@{D}");
        let default = format!("ghcr.io/sallyport/workspace@{D}");
        let request = |body: &str, default: Option<&str>| WorkspaceRequest {
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
            default_image: default.map(|d| ImageRef::parse(d).unwrap()),
            crash: crate::daemon::crash::CrashReporter::channel().0,
        };
        let named = format!("runtime:\n  image: {custom}\n");
        for d in [Some(default.as_str()), None] {
            assert_eq!(request(&named, d).image().unwrap().as_str(), custom);
        }
        let bundled = request("", Some(&default)).image().unwrap();
        assert_eq!(bundled.as_str(), default);
        let e = request("", None).image().unwrap_err();
        assert!(matches!(e, LaunchError::NoDefaultImage), "{e}");
        assert!(e.to_string().starts_with("runtime.image: "), "{e}");
        // The harness (architect Q142): `harness.image`, else its bundled default.
        let harness = |body: &str, default: Option<&str>| {
            let w = request(body, None);
            super::super::launch::HarnessRequest {
                paths: w.paths,
                manifest: w.manifest,
                default_image: default.map(|d| ImageRef::parse(d).unwrap()),
            }
        };
        let named = format!("harness:\n  image: {custom}\n");
        for d in [Some(default.as_str()), None] {
            assert_eq!(harness(&named, d).image().unwrap().as_str(), custom);
        }
        let workspace_named = format!("runtime:\n  image: {custom}\n");
        let bundled = harness(&workspace_named, Some(&default)).image().unwrap();
        assert_eq!(
            bundled.as_str(),
            default,
            "runtime.image is the workspace's"
        );
        let e = harness(&workspace_named, None).image().unwrap_err();
        assert!(matches!(e, LaunchError::NoHarnessImage), "{e}");
    }
}
