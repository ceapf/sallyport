//! Shared fixtures: a throwaway `$HOME` with the sensitive directories real homes have.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use sally_core::manifest::{Code, HostEnv, Rejected, Severity, Validated, load};

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A credential-shaped test value assembled at runtime from split parts, so that no literal in
/// the source tree matches a real token format (secret scanners and the repository's guard hooks
/// match these prefixes). `fake_token(&["gh", "p_"], "abc")` is the classic-PAT shape.
pub fn fake_token(prefix: &[&str], body: &str) -> String {
    let mut s = prefix.concat();
    s.push_str(body);
    s
}

/// A temp root containing `home/` (with `.ssh`, `.config/sallyport`, `code/myproject`, …) and
/// `run/` (as `$XDG_RUNTIME_DIR`). Removed on drop.
pub struct Fixture {
    pub root: PathBuf,
    pub env: HostEnv,
}

impl Fixture {
    pub fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        // Not under /tmp: /tmp is denylisted (it holds other programs' Unix sockets).
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("sally-core-test-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let home = root.join("home");
        for d in [
            ".ssh",
            ".gnupg",
            ".aws",
            ".config/sallyport",
            ".local/share/sallyport",
            ".local/share/containers/storage",
            "code/myproject",
            "code/other",
            "Documents/research",
        ] {
            std::fs::create_dir_all(home.join(d)).unwrap();
        }
        std::fs::create_dir_all(root.join("run")).unwrap();
        std::fs::write(home.join("code/file.txt"), "x").unwrap();
        let env = HostEnv {
            home: home.clone(),
            other_homes: Vec::new(),
            xdg_config_home: None,
            xdg_data_home: None,
            xdg_runtime_dir: Some(root.join("run")),
            podman_storage: vec![
                home.join(".local/share/containers/storage"),
                PathBuf::from("/var/lib/containers/storage"),
            ],
            nproc: 8,
            mem_bytes: 16 << 30,
        };
        Self { root, env }
    }

    pub fn home(&self) -> &Path {
        &self.env.home
    }

    /// Validates `body` appended to a minimal header, with `secrets` in the store.
    pub fn load(&self, body: &str) -> Result<Validated, Rejected> {
        self.load_with(body, &["GITHUB_TOKEN", "BRAVE_SEARCH_KEY", "X"])
    }

    pub fn load_with(&self, body: &str, secrets: &[&str]) -> Result<Validated, Rejected> {
        let catalog: BTreeSet<String> = secrets.iter().map(|s| (*s).to_owned()).collect();
        load(&format!("{HEADER}{body}"), &self.env, &catalog)
    }

    /// Replaces the temp root in messages so snapshots are stable.
    pub fn redact(&self, s: &str) -> String {
        s.replace(&self.root.display().to_string(), "$ROOT")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

pub const HEADER: &str = "apiVersion: sallyport/v1\nkind: Manifest\nname: t\nmodel:\n  ref: any\n";

/// `(path, code)` of every error.
pub fn errors(r: &Result<Validated, Rejected>) -> Vec<(String, Code)> {
    match r {
        Ok(_) => Vec::new(),
        Err(e) => e.errors.iter().map(|d| (d.path.clone(), d.code)).collect(),
    }
}

/// `(path, code)` of every warning (from success or rejection).
pub fn warnings(r: &Result<Validated, Rejected>) -> Vec<(String, Code)> {
    let w = match r {
        Ok(v) => &v.warnings,
        Err(e) => &e.warnings,
    };
    assert!(w.iter().all(|d| d.severity == Severity::Warning));
    w.iter().map(|d| (d.path.clone(), d.code)).collect()
}

/// Asserts exactly one error with this path and code.
#[track_caller]
pub fn assert_rejects(r: &Result<Validated, Rejected>, path: &str, code: Code) {
    assert_eq!(errors(r), vec![(path.to_owned(), code)], "{r:#?}");
}

#[track_caller]
pub fn assert_ok(r: &Result<Validated, Rejected>) {
    assert!(r.is_ok(), "{:#?}", r.as_ref().err());
}

/// Rejected messages rendered like the CLI prints them.
pub fn rendered(r: &Result<Validated, Rejected>) -> Vec<String> {
    match r {
        Ok(_) => Vec::new(),
        Err(e) => e.errors.iter().map(ToString::to_string).collect(),
    }
}
