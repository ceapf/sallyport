//! The library's index: one SQLite file, one STRICT table, one row per model.
//!
//! The row is an index, never proof of content: inspect checks and parses the blob again. Every
//! column holds a value the library chose or checked (the digest's hex, the size, the format's
//! name, the time, and the source name that passed [`detect::by_name`]); every statement is a
//! static string with bound parameters. A row that fails those checks on the way out is
//! [`LibraryError::IndexCorrupt`].

use std::ffi::OsStr;
use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags, OptionalExtension, Row, params};
use rustix::fd::OwnedFd;
use rustix::fs::{FileType, Mode, OFlags};
use rustix::io::Errno;

use super::{Entry, LibraryError, RESOLVE};
use crate::fsutil::check_private_dir;
use crate::model::detect::{self, Format};
use crate::model::hash::Digest;

/// The index file's name in the library directory.
pub(super) const INDEX_FILE: &str = "library.db";
/// How long a statement waits for another connection's lock before it fails.
pub(super) const BUSY_TIMEOUT: Duration = Duration::from_secs(1);
/// The only mode the index file may have.
const FILE_MODE: u32 = 0o600;
/// Longest source name kept, in bytes (`NAME_MAX`).
const MAX_SOURCE_NAME: usize = 255;

/// Settings applied to every connection.
const SETTINGS: &str = "PRAGMA temp_store = MEMORY; PRAGMA trusted_schema = OFF;";
/// The schema, written once into a fresh file with its version.
const CREATE: &str = "BEGIN IMMEDIATE; \
    CREATE TABLE models ( \
        digest TEXT PRIMARY KEY NOT NULL, \
        size INTEGER NOT NULL, \
        format TEXT NOT NULL, \
        source_name TEXT NOT NULL, \
        imported_at INTEGER NOT NULL \
    ) STRICT; \
    PRAGMA user_version = 1; \
    COMMIT;";
const INSERT: &str = "INSERT INTO models (digest, size, format, source_name, imported_at) \
    VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT (digest) DO NOTHING";
const SELECT_ONE: &str =
    "SELECT digest, size, format, source_name, imported_at FROM models WHERE digest = ?1";
const SELECT_ALL: &str =
    "SELECT digest, size, format, source_name, imported_at FROM models ORDER BY digest";
const DELETE: &str = "DELETE FROM models WHERE digest = ?1";

/// What opening does with a file of a given schema version.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Schema {
    /// A fresh file: write the schema.
    Create,
    /// This schema.
    Ready,
}

/// A row as stored.
type Raw = (String, i64, String, String, i64);

/// The open index.
pub(super) struct Index {
    pub(super) conn: Connection,
}

impl Index {
    /// Opens the index in the library directory `lib` (at `lib_path`), creating it at 0600.
    ///
    /// The file is first opened beneath `lib` (created 0600 if missing) and checked on that
    /// descriptor: a regular file of the current user with mode exactly 0600. Anything else is
    /// refused and left as found, never repaired. SQLite then opens the same name in the checked
    /// directory, refusing a symlink.
    pub(super) fn open(lib: &OwnedFd, lib_path: &Path) -> Result<Self, LibraryError> {
        let path = lib_path.join(INDEX_FILE);
        if !check_private_dir(lib_path).map_err(super::dirs::from_issue)? {
            return Err(LibraryError::io(
                "open the library directory",
                std::io::Error::from(std::io::ErrorKind::NotFound),
            ));
        }
        pre_create(lib, &path)?;
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            .union(OpenFlags::SQLITE_OPEN_CREATE)
            .union(OpenFlags::SQLITE_OPEN_NOFOLLOW)
            .union(OpenFlags::SQLITE_OPEN_NO_MUTEX);
        let conn = Connection::open_with_flags(&path, flags)?;
        conn.busy_timeout(BUSY_TIMEOUT)?;
        conn.execute_batch(SETTINGS)?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        match schema_action(version)? {
            Schema::Create => conn.execute_batch(CREATE)?,
            Schema::Ready => {}
        }
        Ok(Self { conn })
    }

    /// Adds `entry` unless its digest is already listed.
    pub(super) fn insert(&self, entry: &Entry) -> Result<(), LibraryError> {
        let size = i64::try_from(entry.size).map_err(|_| LibraryError::IndexCorrupt)?;
        self.conn.execute(
            INSERT,
            params![
                entry.digest.as_hex(),
                size,
                format_name(entry.format),
                entry.source_name,
                entry.imported_at.as_second(),
            ],
        )?;
        Ok(())
    }

    /// The row for `digest`, if any.
    pub(super) fn get(&self, digest: &Digest) -> Result<Option<Entry>, LibraryError> {
        let raw = self
            .conn
            .query_row(SELECT_ONE, [digest.as_hex()], read_row)
            .optional()?;
        raw.map(decode).transpose()
    }

    /// Every row, in digest order.
    pub(super) fn list(&self) -> Result<Vec<Entry>, LibraryError> {
        let mut stmt = self.conn.prepare(SELECT_ALL)?;
        let rows = stmt.query_map([], read_row)?;
        rows.map(|r| decode(r?)).collect()
    }

    /// Deletes the row for `digest`; whether there was one.
    pub(super) fn delete(&self, digest: &Digest) -> Result<bool, LibraryError> {
        Ok(self.conn.execute(DELETE, [digest.as_hex()])? > 0)
    }
}

/// Opens (creating at 0600) the index file beneath `lib` and checks it on the descriptor.
fn pre_create(lib: &OwnedFd, path: &Path) -> Result<(), LibraryError> {
    let refuse = || LibraryError::IndexNotPrivate {
        path: path.display().to_string(),
    };
    let flags = OFlags::RDONLY.union(OFlags::CREATE).union(OFlags::NONBLOCK);
    let fd = match crate::fd::openat2(
        lib,
        INDEX_FILE,
        flags,
        Mode::from_raw_mode(FILE_MODE),
        RESOLVE,
    ) {
        Ok(fd) => fd,
        Err(Errno::LOOP | Errno::ISDIR) => return Err(refuse()),
        Err(e) => return Err(LibraryError::io("open the library index", e)),
    };
    let st = rustix::fs::fstat(&fd).map_err(|e| LibraryError::io("stat the library index", e))?;
    if private_file(st.st_mode, st.st_uid, rustix::process::geteuid().as_raw()) {
        Ok(())
    } else {
        Err(refuse())
    }
}

/// A regular file of `euid` with mode exactly 0600.
pub(super) fn private_file(st_mode: u32, uid: u32, euid: u32) -> bool {
    FileType::from_raw_mode(st_mode) == FileType::RegularFile
        && uid == euid
        && st_mode & 0o7777 == FILE_MODE
}

/// Version 0 is a fresh file, 1 is this schema; any other refuses (no migration).
pub(super) fn schema_action(version: i64) -> Result<Schema, LibraryError> {
    match version {
        0 => Ok(Schema::Create),
        1 => Ok(Schema::Ready),
        other => Err(LibraryError::UnknownIndexVersion(other)),
    }
}

/// A source name the library keeps: one the allowlist accepts, of at most 255 bytes.
pub(super) fn source_name_ok(name: &str) -> bool {
    name.len() <= MAX_SOURCE_NAME && detect::by_name(OsStr::new(name)).is_ok()
}

/// The format's name in the index.
const fn format_name(format: Format) -> &'static str {
    match format {
        Format::Gguf => "gguf",
    }
}

fn read_row(r: &Row<'_>) -> rusqlite::Result<Raw> {
    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
}

/// A stored row as an entry, refusing any value the library would not have written.
fn decode((digest, size, format, source_name, at): Raw) -> Result<Entry, LibraryError> {
    let digest = Digest::parse(&digest).map_err(|_| LibraryError::IndexCorrupt)?;
    let size = u64::try_from(size).map_err(|_| LibraryError::IndexCorrupt)?;
    let format = match format.as_str() {
        "gguf" => Format::Gguf,
        _ => return Err(LibraryError::IndexCorrupt),
    };
    if !source_name_ok(&source_name) {
        return Err(LibraryError::IndexCorrupt);
    }
    let imported_at = jiff::Timestamp::from_second(at).map_err(|_| LibraryError::IndexCorrupt)?;
    Ok(Entry {
        digest,
        size,
        format,
        source_name,
        imported_at,
    })
}

#[cfg(test)]
#[path = "index_tests.rs"]
mod tests;
