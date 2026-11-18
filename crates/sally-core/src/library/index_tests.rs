#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::os::unix::fs::symlink;
use std::time::Instant;

use rusqlite::Connection;

use super::*;
use crate::library::Library;
use crate::library::testkit::{TmpRoot, chmod, gguf, mode, sha};

const FILE: u32 = 0o100_000;
const DIR: u32 = 0o040_000;
const ME: u32 = 1000;

fn raw(root: &TmpRoot) -> Connection {
    Connection::open(root.index()).unwrap()
}

/// A fresh index is created 0600 and opens again.
#[test]
fn a_fresh_index_is_0600_and_reopens() {
    let root = TmpRoot::new("idx-fresh");
    drop(Library::open(root.path()).unwrap());
    assert_eq!(mode(&root.index()), 0o600);
    let version: i64 = raw(&root)
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    assert_eq!(version, 1);
    assert!(
        Library::open(root.path())
            .unwrap()
            .list()
            .unwrap()
            .is_empty()
    );
}

/// An existing index with another mode is refused, never repaired: the mode and the bytes stay.
#[test]
fn an_index_with_another_mode_is_refused_unchanged() {
    for bad in [0o644, 0o400, 0o640, 0o604, 0o700] {
        let root = TmpRoot::new("idx-mode");
        drop(Library::open(root.path()).unwrap());
        let before = std::fs::read(root.index()).unwrap();
        chmod(&root.index(), bad);
        let err = Library::open(root.path()).err().unwrap();
        assert_eq!(err.code(), "index_not_private", "{bad:o}");
        assert!(err.to_string().contains("chmod 600"), "{err}");
        assert!(err.to_string().contains("library.db"), "{err}");
        assert_eq!(mode(&root.index()), bad);
        assert_eq!(std::fs::read(root.index()).unwrap(), before);
    }
}

/// A symlink or a directory where the index belongs is refused and left in place.
#[test]
fn a_symlink_or_dir_index_is_refused_unchanged() {
    let root = TmpRoot::new("idx-link");
    drop(Library::open(root.path()).unwrap());
    std::fs::remove_file(root.index()).unwrap();
    let target = root.path().join("other.db");
    std::fs::write(&target, b"").unwrap();
    chmod(&target, 0o600);
    symlink(&target, root.index()).unwrap();
    let err = Library::open(root.path()).err().unwrap();
    assert_eq!(err.code(), "index_not_private");
    assert!(
        std::fs::symlink_metadata(root.index())
            .unwrap()
            .is_symlink()
    );
    assert_eq!(std::fs::read(&target).unwrap(), b"");

    std::fs::remove_file(root.index()).unwrap();
    std::fs::create_dir(root.index()).unwrap();
    chmod(&root.index(), 0o700);
    let err = Library::open(root.path()).err().unwrap();
    assert_eq!(err.code(), "index_not_private");
    assert!(root.index().is_dir());
}

/// The fd check: a regular file, the current user's, mode exactly 0600.
#[test]
fn private_file_is_exactly_an_own_0600_file() {
    assert!(private_file(FILE | 0o600, ME, ME));
    assert!(!private_file(FILE | 0o600, ME + 1, ME), "other owner");
    assert!(!private_file(FILE | 0o600, 0, ME), "root-owned");
    assert!(!private_file(DIR | 0o600, ME, ME), "not a file");
    for bad in [0o400, 0o644, 0o660, 0o606, 0o700, 0o4600] {
        assert!(!private_file(FILE | bad, ME, ME), "{bad:o}");
    }
}

/// The journal of an open write transaction has the index's mode, 0600.
#[test]
fn the_journal_is_0600_inside_a_write_transaction() {
    let root = TmpRoot::new("idx-journal");
    let lib = Library::open(root.path()).unwrap();
    let tx = lib.index.conn.unchecked_transaction().unwrap();
    tx.execute(
        "INSERT INTO models (digest, size, format, source_name, imported_at) \
         VALUES (?1, 1, 'gguf', 'a.gguf', 0)",
        [sha(b"j").as_hex()],
    )
    .unwrap();
    let journal = root.lib().join("library.db-journal");
    assert_eq!(mode(&journal), 0o600);
    tx.rollback().unwrap();
}

/// An index whose schema version is not this one refuses to open and is left as found.
#[test]
fn an_unknown_version_refuses_unchanged() {
    for v in [2, 7, -1] {
        let root = TmpRoot::new("idx-version");
        drop(Library::open(root.path()).unwrap());
        raw(&root).pragma_update(None, "user_version", v).unwrap();
        let err = Library::open(root.path()).err().unwrap();
        assert_eq!(err.code(), "unknown_index_version", "{v}");
        assert!(err.to_string().contains(&v.to_string()), "{err}");
        let after: i64 = raw(&root)
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(after, v);
    }
}

/// Version 0 is a fresh file, 1 is this schema, anything else refuses.
#[test]
fn schema_action_by_version() {
    assert_eq!(schema_action(0).unwrap(), Schema::Create);
    assert_eq!(schema_action(1).unwrap(), Schema::Ready);
    for v in [-1, 2, i64::MAX] {
        assert_eq!(
            schema_action(v).unwrap_err().code(),
            "unknown_index_version"
        );
    }
}

/// A row the library did not write (a bad value in any column) makes list refuse.
#[test]
fn a_bad_row_is_index_corrupt() {
    let good = sha(b"row");
    let other = sha(b"row2");
    for (digest, size, format, name, at) in [
        ("NOTHEX".to_owned(), 1, "gguf", "a.gguf", 0),
        (good.as_hex().to_uppercase(), 1, "gguf", "a.gguf", 0),
        (good.as_hex().to_owned(), -1, "gguf", "a.gguf", 0),
        (good.as_hex().to_owned(), 1, "pickle", "a.gguf", 0),
        (good.as_hex().to_owned(), 1, "gguf", "a.bin", 0),
        (good.as_hex().to_owned(), 1, "gguf", "dir/a.gguf", 0),
        (
            good.as_hex().to_owned(),
            1,
            "gguf",
            &format!("{}.gguf", "x".repeat(251)),
            0,
        ),
        (good.as_hex().to_owned(), 1, "gguf", "a.gguf", i64::MAX),
    ] {
        let root = TmpRoot::new("idx-corrupt");
        let lib = Library::open(root.path()).unwrap();
        raw(&root)
            .execute(
                "INSERT INTO models (digest, size, format, source_name, imported_at) \
                 VALUES (?1, 1, 'gguf', 'ok.gguf', 0), (?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![other.as_hex(), digest, size, format, name, at],
            )
            .unwrap();
        let err = lib.list().unwrap_err();
        assert_eq!(
            err.code(),
            "index_corrupt",
            "{digest} {size} {format} {name} {at}"
        );
    }
}

/// Source names: what detect allows, up to 255 bytes.
#[test]
fn source_names_are_checked() {
    let longest = format!("{}.gguf", "x".repeat(250));
    assert_eq!(longest.len(), 255);
    assert!(source_name_ok(&longest));
    assert!(!source_name_ok(&format!("x{longest}")));
    assert!(source_name_ok("m.gguf"));
    assert!(!source_name_ok("m.bin"));
    assert!(!source_name_ok("a/m.gguf"));
}

/// A database another connection holds locked fails within the busy timeout, never hangs.
#[test]
fn a_locked_index_fails_bounded() {
    let root = TmpRoot::new("idx-busy");
    let mut lib = Library::open(root.path()).unwrap();
    let source = root.source("m.gguf", &gguf("busy"));
    let holder = raw(&root);
    holder.execute_batch("BEGIN EXCLUSIVE").unwrap();
    let started = Instant::now();
    let err = lib.import_file(&source, None).unwrap_err();
    assert_eq!(err.code(), "index_error");
    assert!(started.elapsed() < BUSY_TIMEOUT * 4);
    holder.execute_batch("ROLLBACK").unwrap();
}
