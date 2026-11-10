//! On-disk layout of the audit directory: monthly log files, the head file, the lock file.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::entry::{VerifyErrorKind, is_hex64};

/// Name of the head file: `{"seq":N,"hash":"…"}` for the newest entry.
pub(crate) const HEAD_FILE: &str = "audit.head";
pub(crate) const HEAD_TMP: &str = "audit.head.tmp";
pub(crate) const LOCK_FILE: &str = "audit.lock";
const LOG_PREFIX: &str = "audit-";
const LOG_SUFFIX: &str = ".jsonl";

/// What the writer records after every entry so deleting the newest entries is detectable
/// (a prefix of a valid hash chain is itself a valid chain).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Head {
    pub(crate) seq: u64,
    pub(crate) hash: String,
}

impl Head {
    pub(crate) fn line(&self) -> String {
        format!("{}\n", serde_json::to_string(self).unwrap_or_default())
    }

    /// `Ok(None)` if there is no head file.
    pub(crate) fn read(dir: &Path) -> Result<Option<Self>, VerifyErrorKind> {
        let bytes = match std::fs::read(dir.join(HEAD_FILE)) {
            Ok(b) if b.len() <= 512 => b,
            Ok(_) => return Err(VerifyErrorKind::HeadInvalid),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(VerifyErrorKind::Unreadable),
        };
        let head: Self =
            serde_json::from_slice(&bytes).map_err(|_| VerifyErrorKind::HeadInvalid)?;
        if head.seq == 0 || !is_hex64(&head.hash) || head.line().as_bytes() != bytes {
            return Err(VerifyErrorKind::HeadInvalid);
        }
        Ok(Some(head))
    }
}

/// `audit-YYYYMM.jsonl` for a `YYYYMM` month.
pub(crate) fn log_file_name(month: &str) -> String {
    format!("{LOG_PREFIX}{month}{LOG_SUFFIX}")
}

/// The `YYYYMM` of a log file name, if it is one.
pub(crate) fn month_of(name: &str) -> Option<&str> {
    let m = name.strip_prefix(LOG_PREFIX)?.strip_suffix(LOG_SUFFIX)?;
    (m.len() == 6 && m.bytes().all(|b| b.is_ascii_digit())).then_some(m)
}

/// Log files in chain order (oldest first): `(month, path)`.
pub(crate) fn list_log_files(dir: &Path) -> std::io::Result<Vec<(String, PathBuf)>> {
    let mut files: Vec<(String, PathBuf)> = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        if let Some(month) = name.to_str().and_then(month_of) {
            files.push((month.to_owned(), entry.path()));
        }
    }
    files.sort();
    Ok(files)
}
