//! Shared fixture of the sallyd integration tests: a throwaway `$HOME`, runtime and state
//! directories under `CARGO_TARGET_TMPDIR`, and manifest helpers.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use sally_core::manifest::{HostEnv, ValidatedManifest, load};
use sallyd::sandbox::{
    CheckedRuntime, CommonArgs, ImageRef, LaunchScan, ScanLimits, SessionId, SessionPaths, UserIds,
    scan_mounts,
};

pub const D0: &str = "0000000000000000000000000000000000000000000000000000000000000000";
pub const D1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
pub const D2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
pub const HEADER: &str = "apiVersion: sallyport/v1\nkind: Manifest\nname: t\nmodel:\n  ref: any\n";

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A throwaway `$HOME`, runtime and state directories, removed on drop. Lives under
/// `CARGO_TARGET_TMPDIR`: a target directory under `/tmp` cannot host it, because the runtime
/// check refuses a world-writable ancestor and the manifest denylist refuses `/tmp` mounts.
pub struct Fx {
    pub root: PathBuf,
    pub env: HostEnv,
    pub common: CommonArgs,
    pub paths: SessionPaths,
}

impl Fx {
    pub fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("sallyd-argv-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let home = root.join("home");
        for d in [
            "code/myproject",
            "code/other",
            "Documents/research",
            ".config/sallyport",
            ".local/share/sallyport",
        ] {
            std::fs::create_dir_all(home.join(d)).unwrap();
        }
        for d in ["run", "bin", "profiles", "hooks"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        let root = std::fs::canonicalize(&root).unwrap();
        let crun = root.join("bin/crun");
        std::fs::write(&crun, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&crun, std::fs::Permissions::from_mode(0o755)).unwrap();
        let home = root.join("home");
        let env = HostEnv {
            home: home.clone(),
            other_homes: Vec::new(),
            xdg_config_home: None,
            xdg_data_home: None,
            xdg_runtime_dir: Some(root.join("run")),
            podman_storage: vec![home.join(".local/share/containers/storage")],
            nproc: 8,
            mem_bytes: 16 << 30,
        };
        let common = CommonArgs {
            runtime: CheckedRuntime::check(&crun).unwrap(),
            ids: UserIds {
                uid: 1000,
                gid: 1000,
            },
            profiles: root.join("profiles"),
            hooks_dir: root.join("hooks"),
            mounts_file: root.join("mounts.conf"),
        };
        let paths = SessionPaths::new(
            SessionId::parse("s-0001").unwrap(),
            &root.join("run/sallyport"),
            &home.join(".local/share/sallyport"),
        )
        .unwrap();
        Self {
            root,
            env,
            common,
            paths,
        }
    }

    pub fn load(&self, body: &str) -> ValidatedManifest {
        let secrets: BTreeSet<String> = ["GITHUB_TOKEN".to_owned()].into_iter().collect();
        match load(&format!("{HEADER}{body}"), &self.env, &secrets) {
            Ok(v) => v.manifest,
            Err(e) => panic!("{e:#?}"),
        }
    }

    /// Creates `.git` directories and `.git` files under `~/<at>`.
    pub fn tree(&self, at: &str, dirs: &[&str], files: &[&str]) {
        let base = self.root.join("home").join(at);
        for d in dirs {
            std::fs::create_dir_all(base.join(d)).unwrap();
        }
        for f in files {
            let p = base.join(f);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, "gitdir: elsewhere\n").unwrap();
        }
    }

    /// The launch scan of `v`, as the launcher would run it.
    pub fn scan(&self, v: &ValidatedManifest) -> LaunchScan {
        scan_mounts(v, &ScanLimits::default()).unwrap()
    }

    pub fn redact(&self, args: &[String]) -> String {
        let root = self.root.display().to_string();
        args.iter()
            .map(|a| a.replace(&root, "$ROOT"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

pub fn image(name: &str, digest: &str) -> ImageRef {
    ImageRef::parse(&format!("ghcr.io/sallyport/{name}@sha256:{digest}")).unwrap()
}

pub fn ws_image() -> ImageRef {
    image("workspace", D1)
}

pub fn mount(host: &str, guest: &str, mode: &str) -> String {
    format!("    - host: \"{host}\"\n      guest: {guest}\n      mode: {mode}\n")
}

pub fn mounts(list: &[String]) -> String {
    format!("filesystem:\n  mounts:\n{}", list.concat())
}

pub const PROXY: &str = "network:\n  mode: proxy\n  allow:\n    - host: pypi.org\n";
