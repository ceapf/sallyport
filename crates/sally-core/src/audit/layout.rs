//! On-disk layout of the audit directory: monthly log files, the head file, the lock file.

use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use rustix::fs::{Mode, OFlags};
use serde::{Deserialize, Serialize};

use super::entry::{VerifyErrorKind, is_hex64};

/// Name of the head file: `{"seq":N,"hash":"…"}` for the newest entry.
pub(crate) const HEAD_FILE: &str = "audit.head";
pub(crate) const HEAD_TMP: &str = "audit.head.tmp";
pub(crate) const LOCK_FILE: &str = "audit.lock";
/// A head line is about 90 bytes; anything larger is not one.
const MAX_HEAD_BYTES: usize = 512;
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

    /// Strict parse: bounded, canonical bytes only.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, VerifyErrorKind> {
        if bytes.len() > MAX_HEAD_BYTES {
            return Err(VerifyErrorKind::HeadInvalid);
        }
        let head: Self = serde_json::from_slice(bytes).map_err(|_| VerifyErrorKind::HeadInvalid)?;
        if head.seq == 0 || !is_hex64(&head.hash) || head.line().as_bytes() != bytes {
            return Err(VerifyErrorKind::HeadInvalid);
        }
        Ok(head)
    }

    /// `Ok(None)` if there is no head file. Refuses a symlink or a non-regular file, checks the
    /// size before reading, and never reads more than the limit.
    pub(crate) fn read(dir: &Path) -> Result<Option<Self>, VerifyErrorKind> {
        let fd = match crate::fd::open(
            dir.join(HEAD_FILE),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(_) => return Err(VerifyErrorKind::Unreadable),
        };
        let file = File::from(fd);
        let meta = file.metadata().map_err(|_| VerifyErrorKind::Unreadable)?;
        if !meta.is_file() {
            return Err(VerifyErrorKind::Unreadable);
        }
        if meta.uid() != rustix::process::geteuid().as_raw()
            || usize::try_from(meta.len()).map_or(true, |n| n > MAX_HEAD_BYTES)
        {
            return Err(VerifyErrorKind::HeadInvalid);
        }
        let mut bytes = Vec::with_capacity(MAX_HEAD_BYTES + 1);
        file.take(u64::try_from(MAX_HEAD_BYTES + 1).unwrap_or(u64::MAX))
            .read_to_end(&mut bytes)
            .map_err(|_| VerifyErrorKind::Unreadable)?;
        Self::parse(&bytes).map(Some)
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

#[cfg(test)]
mod tests {
    use super::month_of;

    /// A log file name holds exactly six digits: both checks apply, each alone refuses.
    #[test]
    fn a_month_is_exactly_six_digits() {
        assert_eq!(month_of("audit-202601.jsonl"), Some("202601"));
        for bad in [
            "audit-20261.jsonl",
            "audit-2026011.jsonl",
            "audit-2026x1.jsonl",
            "audit-202601.json",
            "x-202601.jsonl",
        ] {
            assert_eq!(month_of(bad), None, "{bad}");
        }
    }
}
