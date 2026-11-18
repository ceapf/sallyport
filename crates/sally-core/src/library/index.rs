//! The library's index: one SQLite file, one STRICT table, one row per model.
//!
//! The row is an index, never proof of content: inspect checks and parses the blob again. Every
//! column holds a value the library chose or checked (the digest's hex, the size, the format's
//! name, the time, and a [`SourceName`]); every statement is a static string with bound
//! parameters. A row that fails those checks on the way out is [`LibraryError::IndexCorrupt`].
//!
//! The connection runs in SQLite's defensive mode, and every open checks that the schema is
//! exactly this library's one table and its key index: a file holding a trigger, a view or
//! anything else is [`LibraryError::IndexCorrupt`]. The bundled SQLite compiles URI filenames
//! and extension loading in; neither is reachable here (the path is absolute, the URI flag is
//! not passed, and rusqlite's extension-loading feature is off).

use std::path::Path;
use std::time::Duration;

use rusqlite::config::DbConfig;
use rusqlite::{Connection, OpenFlags, OptionalExtension, Row, TransactionBehavior, params};
use rustix::fd::OwnedFd;
use rustix::fs::{FileType, Mode, OFlags};
use rustix::io::Errno;

use super::dirs::path_is_fd;
use super::{Entry, LibraryError, RESOLVE, SourceName};
use crate::fsutil::check_private_dir;
use crate::model::detect::Format;
use crate::model::hash::Digest;

/// The index file's name in the library directory.
pub(super) const INDEX_FILE: &str = "library.db";
/// How long a statement waits for another connection's lock before it fails.
pub(super) const BUSY_TIMEOUT: Duration = Duration::from_secs(1);
/// The only mode the index file may have.
const FILE_MODE: u32 = 0o600;

/// Settings applied to every connection.
const SETTINGS: &str = "PRAGMA temp_store = MEMORY; PRAGMA trusted_schema = OFF;";
/// The one table, as created and as `sqlite_schema` must hold it.
pub(super) const TABLE_SQL: &str = "CREATE TABLE models (digest TEXT PRIMARY KEY NOT NULL, \
    size INTEGER NOT NULL, format TEXT NOT NULL, source_name TEXT NOT NULL, \
    imported_at INTEGER NOT NULL) STRICT";
/// The automatic index of the table's primary key.
pub(super) const KEY_INDEX: &str = "sqlite_autoindex_models_1";
/// Stamps a fresh file with this schema's version.
const SET_VERSION: &str = "PRAGMA user_version = 1";
const SCHEMA: &str = "SELECT type, name, sql FROM sqlite_schema ORDER BY name";
const COUNT_OBJECTS: &str = "SELECT count(*) FROM sqlite_schema";
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
/// A `sqlite_schema` row: type, name, sql.
pub(super) type SchemaRow = (String, String, Option<String>);

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
    /// directory, refusing a symlink; the directory's path and the file's path must still name
    /// the objects the descriptors hold.
    pub(super) fn open(lib: &OwnedFd, lib_path: &Path) -> Result<Self, LibraryError> {
        let path = lib_path.join(INDEX_FILE);
        if !check_private_dir(lib_path).map_err(super::dirs::from_issue)? {
            return Err(LibraryError::io(
                "open the library directory",
                std::io::Error::from(std::io::ErrorKind::NotFound),
            ));
        }
        path_is_fd(lib_path, lib)?;
        let file = pre_create(lib, &path)?;
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            .union(OpenFlags::SQLITE_OPEN_CREATE)
            .union(OpenFlags::SQLITE_OPEN_NOFOLLOW)
            .union(OpenFlags::SQLITE_OPEN_NO_MUTEX);
        let mut conn = Connection::open_with_flags(&path, flags)?;
        conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
        path_is_fd(&path, &file)?;
        conn.busy_timeout(BUSY_TIMEOUT)?;
        conn.execute_batch(SETTINGS)?;
        init_schema(&mut conn)?;
        let rows = conn
            .prepare(SCHEMA)?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<Result<Vec<SchemaRow>, _>>()?;
        if !schema_ok(&rows) {
            return Err(LibraryError::IndexCorrupt);
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
                entry.source_name.as_raw_str(),
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

/// Writes the schema into a fresh file, deciding by the version and the objects it holds, read
/// inside an immediate transaction so two openers cannot both decide "fresh".
fn init_schema(conn: &mut Connection) -> Result<(), LibraryError> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let version: i64 = tx.pragma_query_value(None, "user_version", |r| r.get(0))?;
    let objects: i64 = tx.query_row(COUNT_OBJECTS, [], |r| r.get(0))?;
    match schema_action(version, objects)? {
        Schema::Create => {
            tx.execute_batch(TABLE_SQL)?;
            tx.execute_batch(SET_VERSION)?;
        }
        Schema::Ready => {}
    }
    tx.commit()?;
    Ok(())
}

/// Opens (creating at 0600) the index file beneath `lib`, checks it on the descriptor, and
/// returns the descriptor.
fn pre_create(lib: &OwnedFd, path: &Path) -> Result<OwnedFd, LibraryError> {
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
        Ok(fd)
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

/// Version 0 with no objects is a fresh file, 1 is this schema. Version 0 holding objects is
/// some other database; any other version refuses (no migration).
pub(super) fn schema_action(version: i64, objects: i64) -> Result<Schema, LibraryError> {
    match version {
        0 if objects == 0 => Ok(Schema::Create),
        0 => Err(LibraryError::IndexCorrupt),
        1 => Ok(Schema::Ready),
        other => Err(LibraryError::UnknownIndexVersion(other)),
    }
}

/// The schema holds exactly the table and its key index, as this library creates them.
pub(super) fn schema_ok(rows: &[SchemaRow]) -> bool {
    match rows {
        [(t_type, t_name, Some(t_sql)), (i_type, i_name, None)] => {
            t_type == "table"
                && t_name == "models"
                && t_sql == TABLE_SQL
                && i_type == "index"
                && i_name == KEY_INDEX
        }
        _ => false,
    }
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
    let source_name = SourceName::checked(&source_name).ok_or(LibraryError::IndexCorrupt)?;
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
