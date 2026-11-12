//! Test-only scratch directories under `target/`, removed when dropped.
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};

/// A fresh directory for one test; removed (with its contents) on drop.
pub(crate) struct Scratch(PathBuf);

impl std::ops::Deref for Scratch {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for Scratch {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `target/<group>/<pid>-<name>`, empty.
pub(crate) fn scratch(group: &str, name: &str) -> Scratch {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(group)
        .join(format!("{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Scratch(dir)
}
