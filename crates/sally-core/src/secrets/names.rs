//! The names in the secrets store, as the manifest validator's `SecretCatalog` (#99; architect
//! Q221). `sallyd` (each `sessions.create`) and the CLI (`manifest validate|summary`) build one
//! per validation over the same path, so their verdicts agree and a `sally secrets set|rm`
//! counts from the next validation on: nothing is cached across validations.
//!
//! The store is opened lazily, on the first lookup, and at most once: a manifest that names no
//! secret never opens it. Only the names are kept; the values are dropped (wiped) as soon as the
//! store is read. No writers' lock is taken: `save` replaces the file by rename, so this reads
//! the old store or the new one. A store that cannot be read answers every lookup "missing",
//! and [`StoreNames::failed`] keeps the error, so the caller refuses on the store itself
//! (`secret-store`) instead of reporting a missing name.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use super::{SecretStore, SecretsError};
use crate::manifest::SecretCatalog;

/// A secrets store's names, read on the first lookup.
#[derive(Debug)]
pub struct StoreNames {
    path: PathBuf,
    names: OnceLock<Result<BTreeSet<String>, SecretsError>>,
}

impl StoreNames {
    /// The names of the store at `path`, not read yet.
    #[must_use]
    pub const fn new(path: PathBuf) -> Self {
        Self {
            path,
            names: OnceLock::new(),
        }
    }

    /// The store's path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Why the store could not be read, once a lookup tried; `None` before any lookup, and for a
    /// store that was read (a missing file is an empty store).
    #[must_use]
    pub fn failed(&self) -> Option<&SecretsError> {
        self.names.get().and_then(|r| r.as_ref().err())
    }

    /// The names, reading the store on the first call.
    fn read(&self) -> &Result<BTreeSet<String>, SecretsError> {
        self.names.get_or_init(|| {
            SecretStore::open(&self.path).map(|s| s.names().map(str::to_owned).collect())
        })
    }
}

impl SecretCatalog for StoreNames {
    fn contains(&self, name: &str) -> bool {
        self.read().as_ref().is_ok_and(|n| n.contains(name))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// A fresh 0700 directory under `target/`.
    fn scratch(name: &str) -> PathBuf {
        static N: AtomicUsize = AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let d = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/secrets-names-tests")
            .join(format!("{name}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        d
    }

    /// A store at `dir/secrets.toml` holding `names`, each with a value assembled at runtime.
    fn store(dir: &Path, names: &[&str]) -> PathBuf {
        let path = dir.join("secrets.toml");
        let mut s = SecretStore::empty(path.clone());
        for n in names {
            s.set(n, format!("sp-names-{n}-{}", "v".repeat(20)))
                .unwrap();
        }
        s.save().unwrap();
        path
    }

    #[test]
    fn a_stored_name_is_in_the_catalog_and_another_is_not() {
        let d = scratch("named");
        let names = StoreNames::new(store(&d, &["GITHUB_TOKEN"]));
        assert!(names.contains("GITHUB_TOKEN"));
        assert!(!names.contains("OTHER"));
        assert!(names.failed().is_none());
        assert_eq!(names.path(), d.join("secrets.toml"));
    }

    #[test]
    fn a_missing_store_is_empty_not_failed() {
        let d = scratch("missing");
        let names = StoreNames::new(d.join("secrets.toml"));
        assert!(!names.contains("GITHUB_TOKEN"));
        assert!(names.failed().is_none());
    }

    /// The store is opened on the first lookup only, and once: a change after it is not seen by
    /// this catalog, and is seen by the next one (nothing is cached across validations).
    #[test]
    fn the_store_is_read_lazily_once_per_catalog() {
        let d = scratch("lazy");
        let names = StoreNames::new(d.join("secrets.toml"));
        store(&d, &["A_KEY"]);
        assert!(
            names.contains("A_KEY"),
            "read at the first lookup, not at new"
        );
        store(&d, &["B_KEY"]);
        assert!(names.contains("A_KEY") && !names.contains("B_KEY"));
        let next = StoreNames::new(d.join("secrets.toml"));
        assert!(next.contains("B_KEY") && !next.contains("A_KEY"));
    }

    /// An unreadable store answers "missing" and keeps its error, which names the path and
    /// never the file's text; before any lookup there is no error.
    #[test]
    fn an_unreadable_store_is_latched_as_failed() {
        let d = scratch("bad");
        let path = d.join("secrets.toml");
        std::fs::write(&path, "A_KEY = \"sp-text-of-the-file\"\nnot toml\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let names = StoreNames::new(path);
        assert!(names.failed().is_none(), "nothing read yet");
        assert!(!names.contains("A_KEY"));
        let e = names.failed().unwrap().to_string();
        assert!(e.contains("secrets.toml"), "{e}");
        assert!(!e.contains("sp-text-of-the-file"), "{e}");
    }
}
