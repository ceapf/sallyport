//! The secrets file: strict loading, atomic 0600 saving. Errors never contain a value, a name
//! the caller supplied, or any text from the file (a pasted credential can land in either).
#![deny(clippy::indexing_slicing)]

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rustix::fs::{Mode, OFlags};
use zeroize::{Zeroize, Zeroizing};

use super::Secret;

/// Largest accepted `secrets.toml`.
pub const MAX_STORE_BYTES: usize = 1024 * 1024;
/// Most secrets in one store.
pub const MAX_SECRETS: usize = 256;
/// Longest secret value, in bytes.
pub const MAX_VALUE_BYTES: usize = 8 * 1024;
/// Values shorter than this are stored but flagged: redaction skips collision-prone short
/// patterns (ARCHITECTURE §7, Redaction; the CLI's warning is TODO(#98)).
pub const SHORT_SECRET_BYTES: usize = 16;

/// How long [`SecretStore::lock`] waits for another writer before giving up.
pub const LOCK_WAIT: Duration = Duration::from_secs(10);
/// How often a waiting writer retries the lock.
const LOCK_RETRY: Duration = Duration::from_millis(50);

const MAX_NAME_BYTES: usize = 64;
/// Distinguishes temporary files of concurrent saves within one process.
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);
/// Any group or other permission bit.
const GROUP_OTHER: u32 = 0o077;

/// Why a store operation was refused. Messages never include secret material.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SecretsError {
    /// Not `[A-Z][A-Z0-9_]{0,63}`. The offending name is deliberately not echoed.
    #[error("invalid secret name: use 1-64 characters of A-Z, 0-9 and _, starting with a letter")]
    InvalidName,
    /// The value cannot be stored. The value is deliberately not echoed.
    #[error("invalid secret value: {0}")]
    InvalidValue(&'static str),
    /// More than [`MAX_SECRETS`] entries.
    #[error("the secrets store is limited to {MAX_SECRETS} secrets")]
    TooMany,
    /// The file exceeds [`MAX_STORE_BYTES`].
    #[error("secrets.toml is larger than {MAX_STORE_BYTES} bytes")]
    TooLarge,
    /// The file is not a flat table of `NAME = "string"` entries.
    #[error("secrets.toml: syntax error or unexpected entry{} (file text is not shown)", at_line(*.line))]
    Parse {
        /// 1-based line of the problem, when known.
        line: Option<usize>,
    },
    /// The file or its directory is not private enough, or is not what it should be.
    #[error("{path}: {msg}")]
    Permissions {
        /// Host path.
        path: String,
        /// What is wrong and how to fix it.
        msg: String,
    },
    /// Another writer kept the lock for the whole wait ([`SecretStore::lock_within`]).
    #[error(
        "{path}: another `sally secrets` command is changing the store; gave up after {:.1} s \
         and nothing changed (try again when it ends)",
        waited.as_secs_f64()
    )]
    LockHeld {
        /// Host path of the lock file.
        path: String,
        /// How long this writer waited.
        waited: Duration,
    },
    /// An I/O error.
    #[error("{path}: {source}")]
    Io {
        /// Host path.
        path: String,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
}

fn at_line(line: Option<usize>) -> String {
    line.map_or_else(String::new, |n| format!(" at line {n}"))
}

/// What [`SecretStore::set`] did besides storing the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetOutcome {
    /// The value is shorter than [`SHORT_SECRET_BYTES`]; callers should warn that response
    /// redaction is weaker for it.
    pub short: bool,
}

/// Whether `s` is a legal secret name: `[A-Z][A-Z0-9_]{0,63}`. The manifest validator uses the
/// same rule. TODO(#7): refuse credential-shaped names (e.g. AWS key IDs) as well.
#[must_use]
pub fn is_secret_name(s: &str) -> bool {
    let mut b = s.bytes();
    s.len() <= MAX_NAME_BYTES
        && b.next().is_some_and(|c| c.is_ascii_uppercase())
        && b.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_')
}

fn validate_name(name: &str) -> Result<(), SecretsError> {
    if is_secret_name(name) {
        Ok(())
    } else {
        Err(SecretsError::InvalidName)
    }
}

/// Printable ASCII, no leading or trailing space, at most [`MAX_VALUE_BYTES`]. Stricter than TOML
/// on purpose: values end up in HTTP header lines, where a control character is an injection.
fn validate_value(value: &str) -> Result<(), SecretsError> {
    let bad = |msg| Err(SecretsError::InvalidValue(msg));
    if value.is_empty() {
        return bad("must not be empty");
    }
    if value.len() > MAX_VALUE_BYTES {
        return bad("is longer than 8192 bytes");
    }
    if !value.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        return bad("may only contain printable ASCII (no control characters or non-ASCII)");
    }
    if value.starts_with(' ') || value.ends_with(' ') {
        return bad("must not start or end with a space");
    }
    Ok(())
}

/// The writers' lock of a store ([`SecretStore::lock`]); released on drop.
#[derive(Debug)]
pub struct EditLock {
    /// Held only for its `flock`, which closing the file releases.
    _file: File,
}

/// The in-memory secrets store and its backing file.
pub struct SecretStore {
    path: PathBuf,
    entries: BTreeMap<String, Secret<String>>,
}

impl fmt::Debug for SecretStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretStore")
            .field("path", &self.path)
            .field("names", &self.entries.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl SecretStore {
    /// An empty store that [`save`](Self::save)s to `path`. Does not touch the disk. Saving it
    /// **replaces** whatever file is there: use [`open`](Self::open) to edit an existing store.
    #[must_use]
    pub const fn empty(path: PathBuf) -> Self {
        Self {
            path,
            entries: BTreeMap::new(),
        }
    }

    /// Loads the store at `path`; a missing file is an empty store.
    ///
    /// Refuses a symlink, a non-regular file, a file not owned by the current user or with any
    /// group/other permission bit, a parent directory writable by group or others, an
    /// oversized file, and any syntax or rule violation. Permissions are checked on the opened
    /// file descriptor, not the path.
    ///
    /// # Errors
    /// [`SecretsError`]; messages name the path and never include file text.
    pub fn open(path: &Path) -> Result<Self, SecretsError> {
        let io_err = |e: std::io::Error| SecretsError::Io {
            path: path.display().to_string(),
            source: e,
        };
        if !check_parent(path)? {
            return Ok(Self::empty(path.to_owned()));
        }
        let fd = match crate::fd::open(
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => return Ok(Self::empty(path.to_owned())),
            Err(rustix::io::Errno::LOOP) => {
                return Err(perm(
                    path,
                    "is a symbolic link; the store must be a regular file",
                ));
            }
            Err(e) => return Err(io_err(e.into())),
        };
        let file = File::from(fd);
        let meta = file.metadata().map_err(io_err)?;
        if !meta.is_file() {
            return Err(perm(path, "is not a regular file"));
        }
        if meta.uid() != rustix::process::geteuid().as_raw() {
            return Err(perm(path, "is not owned by the current user"));
        }
        let mode = meta.permissions().mode() & 0o7777;
        if mode & GROUP_OTHER != 0 {
            return Err(perm(
                path,
                &format!(
                    "mode is {mode:04o}; it must be 0600 (no group or other access); run chmod 600"
                ),
            ));
        }
        let len = usize::try_from(meta.len()).map_err(|_| SecretsError::TooLarge)?;
        if len > MAX_STORE_BYTES {
            return Err(SecretsError::TooLarge);
        }
        let bytes = read_bounded(file, len, path)?;
        Self::from_bytes(path.to_owned(), &bytes)
    }

    /// Builds a store from file bytes without touching the disk, applying every content rule
    /// [`open`](Self::open) applies (size, UTF-8, flat `NAME = "string"` table, names, values,
    /// count). This is what `open` calls, and the fuzz target's entry point.
    ///
    /// # Errors
    /// [`SecretsError`]; messages never include any of `bytes`.
    pub fn from_bytes(path: PathBuf, bytes: &[u8]) -> Result<Self, SecretsError> {
        if bytes.len() > MAX_STORE_BYTES {
            return Err(SecretsError::TooLarge);
        }
        Ok(Self {
            path,
            entries: parse(bytes)?,
        })
    }

    /// Names in sorted order. Never values.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }

    /// Whether a secret with this name exists.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.entries.contains_key(name)
    }

    /// The secret named `name`. Use [`Secret::expose`] only where the value is injected.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Secret<String>> {
        self.entries.get(name)
    }

    /// Adds or replaces a secret in memory; call [`save`](Self::save) to persist. The rejected
    /// or replaced value is zeroized.
    ///
    /// # Errors
    /// [`SecretsError::InvalidName`], [`SecretsError::InvalidValue`] or
    /// [`SecretsError::TooMany`]; none echo the input.
    pub fn set(&mut self, name: &str, mut value: String) -> Result<SetOutcome, SecretsError> {
        let checked = validate_name(name)
            .and_then(|()| validate_value(&value))
            .and_then(|()| {
                if self.entries.len() >= MAX_SECRETS && !self.entries.contains_key(name) {
                    Err(SecretsError::TooMany)
                } else {
                    Ok(())
                }
            });
        if let Err(e) = checked {
            value.zeroize();
            return Err(e);
        }
        let short = value.len() < SHORT_SECRET_BYTES;
        self.entries.insert(name.to_owned(), Secret::new(value));
        Ok(SetOutcome { short })
    }

    /// Removes a secret from memory; returns whether it existed.
    pub fn remove(&mut self, name: &str) -> bool {
        self.entries.remove(name).is_some()
    }

    /// Takes the writers' lock for the store at `path`: an exclusive `flock` on `secrets.lock`
    /// (the store's name with `.lock`) beside it, 0600, never through a symlink, waiting at most
    /// [`LOCK_WAIT`] for another writer. An editor holds it across [`open`](Self::open), its
    /// changes and [`save`](Self::save), so two editors cannot undo each other (architect Q108);
    /// readers take no lock. Creates the directory with mode 0700 if missing.
    ///
    /// # Errors
    /// As [`lock_within`](Self::lock_within).
    pub fn lock(path: &Path) -> Result<EditLock, SecretsError> {
        Self::lock_within(path, LOCK_WAIT)
    }

    /// [`lock`](Self::lock), waiting at most `wait`: the lock is tried at once, then every
    /// 50 ms until `wait` has passed (a free lock is taken even when `wait` is zero).
    ///
    /// # Errors
    /// [`SecretsError::LockHeld`] when another writer kept it for the whole wait;
    /// [`SecretsError::Permissions`] if the directory is writable by group or others or the lock
    /// is a symlink; [`SecretsError::Io`] otherwise.
    pub fn lock_within(path: &Path, wait: Duration) -> Result<EditLock, SecretsError> {
        let lock = path.with_extension("lock");
        let io_err = |e: std::io::Error| SecretsError::Io {
            path: lock.display().to_string(),
            source: e,
        };
        let dir = parent_of(path);
        if !dir.exists() {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .map_err(io_err)?;
        }
        check_parent(path)?;
        let fd = match crate::fd::open(
            &lock,
            OFlags::WRONLY | OFlags::CREATE | OFlags::NOFOLLOW,
            Mode::from_raw_mode(0o600),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::LOOP) => return Err(perm(&lock, "is a symbolic link")),
            Err(e) => return Err(io_err(e.into())),
        };
        let file = File::from(fd);
        let start = Instant::now();
        loop {
            match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
                Ok(()) => return Ok(EditLock { _file: file }),
                Err(rustix::io::Errno::WOULDBLOCK) => {}
                Err(e) => return Err(io_err(e.into())),
            }
            let waited = start.elapsed();
            let Some(left) = wait.checked_sub(waited).filter(|l| !l.is_zero()) else {
                return Err(SecretsError::LockHeld {
                    path: lock.display().to_string(),
                    waited,
                });
            };
            std::thread::sleep(left.min(LOCK_RETRY));
        }
    }

    /// Writes the store atomically: a 0600 temporary file in the same directory, fsync, rename,
    /// fsync of the directory. Creates the directory with mode 0700 if missing. A crash leaves
    /// either the old file or the new one.
    ///
    /// # Errors
    /// [`SecretsError::Permissions`] if the directory is writable by group or others,
    /// [`SecretsError::Io`] otherwise.
    pub fn save(&self) -> Result<(), SecretsError> {
        let path = self.path.as_path();
        let io_err = |e: std::io::Error| SecretsError::Io {
            path: path.display().to_string(),
            source: e,
        };
        let dir = parent_of(path);
        if !dir.exists() {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .map_err(io_err)?;
        }
        check_parent(path)?;
        let name = path
            .file_name()
            .ok_or_else(|| perm(path, "has no file name"))?;
        let tmp = dir.join(format!(
            ".{}.{}.{}.tmp",
            name.to_string_lossy(),
            std::process::id(),
            TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        sweep_stale_tmp(dir, &name.to_string_lossy());
        let text = self.render();
        // `create_new` fails if the name exists, and only a file this call created is ever
        // removed on the error path.
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(io_err)?;
        let written = write_private(&mut file, text.as_bytes()).and_then(|()| {
            drop(file);
            std::fs::rename(&tmp, path)
        });
        if let Err(e) = written {
            let _ = std::fs::remove_file(&tmp);
            return Err(io_err(e));
        }
        // The new file is already in place; a failed directory fsync only weakens durability
        // across a power loss, so it is not reported as a failed save.
        let _ = File::open(dir).and_then(|d| d.sync_all());
        Ok(())
    }

    fn render(&self) -> Zeroizing<String> {
        // Exact worst-case size up front: a growing String would free un-wiped prefixes.
        let cap = self.entries.iter().fold(0usize, |n, (k, v)| {
            n.saturating_add(k.len())
                .saturating_add(v.expose().len().saturating_mul(2))
                .saturating_add(6)
        });
        let mut out = Zeroizing::new(String::with_capacity(cap));
        for (name, secret) in &self.entries {
            out.push_str(name);
            out.push_str(" = \"");
            for c in secret.expose().chars() {
                if c == '"' || c == '\\' {
                    out.push('\\');
                }
                out.push(c);
            }
            out.push_str("\"\n");
        }
        out
    }
}

impl crate::manifest::SecretCatalog for SecretStore {
    fn contains(&self, name: &str) -> bool {
        Self::contains(self, name)
    }
}

fn perm(path: &Path, msg: &str) -> SecretsError {
    SecretsError::Permissions {
        path: path.display().to_string(),
        msg: msg.to_owned(),
    }
}

/// Reads the `len` bytes fstat reported. One exact-size zeroized buffer, filled by hand: no
/// reallocation and no std probe buffer on the stack, so no plaintext copies are left behind.
/// One spare byte detects a file that grew after the fstat.
fn read_bounded(
    mut file: File,
    len: usize,
    path: &Path,
) -> Result<Zeroizing<Vec<u8>>, SecretsError> {
    let mut buf = Zeroizing::new(vec![0u8; len.saturating_add(1)]);
    let mut filled = 0usize;
    while let Some(spare) = buf.get_mut(filled..).filter(|s| !s.is_empty()) {
        let n = file.read(spare).map_err(|e| SecretsError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        if n == 0 {
            break;
        }
        filled = filled.saturating_add(n);
    }
    if filled > len {
        return Err(perm(path, "changed while it was being read"));
    }
    buf.truncate(filled);
    Ok(buf)
}

fn parent_of(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

/// Checks the directory that holds the store (see [`crate::fsutil::check_private_dir`]).
/// `Ok(false)` if it does not exist yet.
fn check_parent(path: &Path) -> Result<bool, SecretsError> {
    Ok(crate::fsutil::check_private_dir(parent_of(path))?)
}

impl From<crate::fsutil::FsIssue> for SecretsError {
    fn from(issue: crate::fsutil::FsIssue) -> Self {
        match issue {
            crate::fsutil::FsIssue::Permissions { path, msg } => Self::Permissions { path, msg },
            crate::fsutil::FsIssue::Io { path, source } => Self::Io { path, source },
        }
    }
}

fn write_private(f: &mut File, bytes: &[u8]) -> std::io::Result<()> {
    // The create mode is subject to the umask, which can only remove bits; make it exact.
    f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    f.write_all(bytes)?;
    f.sync_all()
}

/// Removes leftovers of a crashed save (`.<name>.<pid>.<n>.tmp`, regular, owned by us) from other
/// processes: they hold plaintext, possibly of a secret the user has since removed. Best effort.
/// A save in another live process that loses its temporary file fails cleanly (its rename
/// errors); writers hold [`SecretStore::lock`], so only a writer that skipped it can lose one.
fn sweep_stale_tmp(dir: &Path, name: &str) {
    let prefix = format!(".{name}.");
    let own = format!("{prefix}{}.", std::process::id());
    let euid = rustix::process::geteuid().as_raw();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let file_name = entry.file_name().to_string_lossy().into_owned();
        if !file_name.starts_with(&prefix)
            || !file_name.ends_with(".tmp")
            || file_name.starts_with(&own)
        {
            continue;
        }
        let path = entry.path();
        if std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_file() && m.uid() == euid) {
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// Parses file bytes into validated entries. Parser diagnostics are reduced to a line number:
/// the `toml` error text quotes the offending line, which holds a secret.
fn parse(bytes: &[u8]) -> Result<BTreeMap<String, Secret<String>>, SecretsError> {
    let text = std::str::from_utf8(bytes).map_err(|_| SecretsError::Parse { line: None })?;
    // `Zeroizing` values: a partial map is wiped if deserialization stops partway.
    let raw: BTreeMap<String, Zeroizing<String>> =
        toml::from_str(text).map_err(|e| SecretsError::Parse {
            line: e
                .span()
                .and_then(|s| text.get(..s.start))
                .map(|head| head.matches('\n').count().saturating_add(1)),
        })?;
    // Wrap first so every value is zeroized on an early return below.
    let entries: BTreeMap<String, Secret<String>> = raw
        .into_iter()
        .map(|(k, mut v)| (k, Secret::new(std::mem::take(&mut *v))))
        .collect();
    if entries.len() > MAX_SECRETS {
        return Err(SecretsError::TooMany);
    }
    for (name, secret) in &entries {
        validate_name(name)?;
        validate_value(secret.expose())?;
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A store that holds more bytes than its fstat reported (it grew in between) is refused;
    /// exactly the reported size is read whole.
    #[test]
    fn a_store_longer_than_its_reported_size_is_refused() {
        let path = std::env::temp_dir().join(format!("sp-read-bounded-{}", std::process::id()));
        std::fs::write(&path, b"abcdef").unwrap();
        let open = || File::open(&path).unwrap();
        let grown = read_bounded(open(), 5, &path);
        let exact = read_bounded(open(), 6, &path);
        std::fs::remove_file(&path).unwrap();
        match grown {
            Err(e) => assert!(e.to_string().contains("changed while"), "{e}"),
            Ok(_) => panic!("a store that grew after the fstat was read"),
        }
        assert_eq!(exact.unwrap().as_slice(), b"abcdef");
    }
}
