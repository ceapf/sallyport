#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::os::unix::fs::{MetadataExt, symlink};

use rusqlite::Connection;

use super::*;
use crate::library::Library;
use crate::library::testkit::{TmpRoot, assert_nothing_stored, chmod, gguf, mode, names, sha};
use crate::model::gguf::build::{F32, Gguf, Tensor};

/// A valid file is copied into blobs/sha256/<hex> at exactly 0444 (RT-MDL-07), named by its
/// SHA-256, listed once, the quarantine empty, and the source left alone (copied, never linked).
#[test]
fn a_valid_file_is_stored_by_digest_0444() {
    let root = TmpRoot::new("imp-ok");
    let mut lib = Library::open(root.path(), 0).unwrap();
    let bytes = gguf("ok");
    let source = root.source("model.gguf", &bytes);
    let entry = lib.import_file(&source, None).unwrap();
    let digest = sha(&bytes);
    assert_eq!(entry.digest(), &digest);
    assert_eq!(entry.size(), bytes.len() as u64);
    assert_eq!(entry.format(), Format::Gguf);
    assert_eq!(entry.source_name().as_raw_str(), "model.gguf");
    let blob = root.blobs().join(digest.as_hex());
    assert_eq!(std::fs::read(&blob).unwrap(), bytes);
    assert_eq!(mode(&blob), 0o444);
    assert_eq!(lib.list().unwrap(), [entry]);
    assert!(names(&root.quarantine()).is_empty());
    let src = std::fs::metadata(&source).unwrap();
    assert_eq!(src.nlink(), 1, "the source was linked");
    assert_ne!(src.ino(), std::fs::metadata(&blob).unwrap().ino());
    assert_eq!(std::fs::read(&source).unwrap(), bytes);
}

/// A file larger than one copy buffer arrives whole.
#[test]
fn a_file_over_one_buffer_is_copied_whole() {
    let root = TmpRoot::new("imp-big");
    let mut lib = Library::open(root.path(), 0).unwrap();
    let mut g = Gguf::valid();
    g.trailing = 200_000;
    let bytes = g.bytes();
    let source = root.source("big.gguf", &bytes);
    let entry = lib.import_file(&source, None).unwrap();
    assert_eq!(entry.digest(), &sha(&bytes));
    let blob = root.blobs().join(entry.digest().as_hex());
    assert_eq!(std::fs::read(blob).unwrap(), bytes);
}

/// With an expected digest: equal is stored; different is hash_mismatch with nothing stored
/// (RT-MDL-04).
#[test]
fn the_expected_digest_is_enforced() {
    let root = TmpRoot::new("imp-hash");
    let mut lib = Library::open(root.path(), 0).unwrap();
    let bytes = gguf("hash");
    let source = root.source("m.gguf", &bytes);
    let err = lib.import_file(&source, Some(&sha(b"other"))).unwrap_err();
    assert_eq!(err.code(), "hash_mismatch");
    assert!(err.to_string().contains(sha(&bytes).as_hex()), "{err}");
    assert_nothing_stored(&root, &lib);
    lib.import_file(&source, Some(&sha(&bytes))).unwrap();
    assert_eq!(lib.list().unwrap().len(), 1);
}

/// Names off the allowlist are refused before the file is opened: a mode-000 file still
/// answers format_not_allowed, not an I/O error (RT-MDL-01).
#[test]
fn a_name_off_the_allowlist_is_refused_unopened() {
    let root = TmpRoot::new("imp-name");
    let mut lib = Library::open(root.path(), 0).unwrap();
    for name in [
        "m.bin",
        "m.pt",
        "m.pkl",
        "m.safetensors",
        "m.GGUF",
        "gguf",
        "m.gguf.bin",
    ] {
        let source = root.source(name, &gguf("name"));
        chmod(&source, 0o000);
        let err = lib.import_file(&source, None).unwrap_err();
        assert_eq!(err.code(), "format_not_allowed", "{name}");
        assert_nothing_stored(&root, &lib);
    }
    let err = lib
        .import_file(std::path::Path::new("/"), None)
        .unwrap_err();
    assert_eq!(err.code(), "format_not_allowed");
}

/// Wrong magic, an empty file and a short file are refused with nothing stored (RT-MDL-02).
#[test]
fn a_wrong_magic_is_refused() {
    let root = TmpRoot::new("imp-magic");
    let mut lib = Library::open(root.path(), 0).unwrap();
    for bytes in [&b"PK\x03\x04rest"[..], b"", b"GGU", b"\x80\x02}q"] {
        let source = root.source("m.gguf", bytes);
        let err = lib.import_file(&source, None).unwrap_err();
        assert_eq!(err.code(), "magic_mismatch", "{bytes:?}");
        assert_nothing_stored(&root, &lib);
    }
}

/// The strict parse runs on the copy: a refused header stores nothing (RT-MDL-03).
#[test]
fn a_refused_header_stores_nothing() {
    let root = TmpRoot::new("imp-parse");
    let mut lib = Library::open(root.path(), 0).unwrap();
    let mut truncated = gguf("t");
    truncated.truncate(30);
    let mut bad_version = Gguf::valid();
    bad_version.version = 9;
    for (bytes, code) in [
        (truncated, "truncated"),
        (bad_version.bytes(), "bad_version"),
        (Gguf::empty().bytes(), "no_tensors"),
    ] {
        let source = root.source("m.gguf", &bytes);
        let err = lib.import_file(&source, None).unwrap_err();
        assert_eq!(err.code(), code);
        assert_nothing_stored(&root, &lib);
    }
}

/// A symlink source is refused symlink_in_import; its target is untouched (RT-MDL-06).
#[test]
fn a_symlink_source_is_refused() {
    let root = TmpRoot::new("imp-link");
    let mut lib = Library::open(root.path(), 0).unwrap();
    let target = root.source("real.gguf", &gguf("link"));
    let link = root.path().join("src").join("link.gguf");
    symlink(&target, &link).unwrap();
    let err = lib.import_file(&link, None).unwrap_err();
    assert_eq!(err.code(), "symlink_in_import");
    assert_nothing_stored(&root, &lib);
    assert_eq!(std::fs::read(&target).unwrap(), gguf("link"));
}

/// A directory or a FIFO named like a model is refused not_regular_file, without blocking.
#[test]
fn a_non_regular_source_is_refused() {
    let root = TmpRoot::new("imp-kind");
    let mut lib = Library::open(root.path(), 0).unwrap();
    let dir = root.path().join("d.gguf");
    std::fs::create_dir(&dir).unwrap();
    assert_eq!(
        lib.import_file(&dir, None).unwrap_err().code(),
        "not_regular_file"
    );
    let fifo = root.path().join("f.gguf");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::FileType::Fifo,
        Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    assert_eq!(
        lib.import_file(&fifo, None).unwrap_err().code(),
        "not_regular_file"
    );
    assert_nothing_stored(&root, &lib);
}

/// A source that cannot be opened is an I/O error, with nothing stored.
#[test]
fn an_unreadable_source_is_an_io_error() {
    let root = TmpRoot::new("imp-missing");
    let mut lib = Library::open(root.path(), 0).unwrap();
    let missing = root.path().join("missing.gguf");
    assert_eq!(
        lib.import_file(&missing, None).unwrap_err().code(),
        "io_error"
    );
    assert_nothing_stored(&root, &lib);
}

/// Changing the source after the import leaves the blob as imported (RT-MDL-06).
#[test]
fn a_source_changed_after_import_leaves_the_blob() {
    let root = TmpRoot::new("imp-after");
    let mut lib = Library::open(root.path(), 0).unwrap();
    let bytes = gguf("after");
    let source = root.source("m.gguf", &bytes);
    let entry = lib.import_file(&source, None).unwrap();
    std::fs::write(&source, gguf("changed")).unwrap();
    let blob = root.blobs().join(entry.digest().as_hex());
    assert_eq!(std::fs::read(&blob).unwrap(), bytes);
    assert_eq!(lib.inspect(entry.digest()).unwrap().entry(), &entry);
}

/// Importing the same bytes again keeps one row, the first one, and one blob.
#[test]
fn a_second_import_of_the_same_bytes_keeps_the_first_row() {
    let root = TmpRoot::new("imp-again");
    let mut lib = Library::open(root.path(), 0).unwrap();
    let bytes = gguf("again");
    let first = lib
        .import_file(&root.source("one.gguf", &bytes), None)
        .unwrap();
    let second = lib
        .import_file(&root.source("two.gguf", &bytes), None)
        .unwrap();
    assert_eq!(second, first);
    assert_eq!(lib.list().unwrap(), [first]);
    assert_eq!(names(&root.blobs()).len(), 1);
    assert!(names(&root.quarantine()).is_empty());
}

/// A blob already in place with no row (left by a crash) is kept and gains its row.
#[test]
fn an_orphan_blob_gains_its_row() {
    let root = TmpRoot::new("imp-orphan");
    let mut lib = Library::open(root.path(), 0).unwrap();
    let bytes = gguf("orphan");
    let source = root.source("m.gguf", &bytes);
    let entry = lib.import_file(&source, None).unwrap();
    Connection::open(root.index())
        .unwrap()
        .execute("DELETE FROM models", [])
        .unwrap();
    let blob = root.blobs().join(entry.digest().as_hex());
    let ino = std::fs::metadata(&blob).unwrap().ino();
    let again = lib.import_file(&source, None).unwrap();
    assert_eq!(again.digest(), entry.digest());
    assert_eq!(std::fs::metadata(&blob).unwrap().ino(), ino);
    assert_eq!(lib.list().unwrap().len(), 1);
}

/// A failed row insert removes the blob this import created, but never one it found.
#[test]
fn a_failed_insert_unlinks_only_its_own_blob() {
    let root = TmpRoot::new("imp-insert");
    let mut lib = Library::open(root.path(), 0).unwrap();
    let refuse =
        "CREATE TRIGGER refuse BEFORE INSERT ON models BEGIN SELECT RAISE(ABORT, 'no'); END";
    Connection::open(root.index())
        .unwrap()
        .execute_batch(refuse)
        .unwrap();
    let source = root.source("m.gguf", &gguf("insert"));
    let err = lib.import_file(&source, None).unwrap_err();
    assert_eq!(err.code(), "index_error");
    assert!(names(&root.blobs()).is_empty());
    assert!(names(&root.quarantine()).is_empty());

    // A blob already there (an orphan) stays when the insert fails.
    let conn = Connection::open(root.index()).unwrap();
    conn.execute_batch("DROP TRIGGER refuse").unwrap();
    let entry = lib.import_file(&source, None).unwrap();
    conn.execute("DELETE FROM models", []).unwrap();
    conn.execute_batch(refuse).unwrap();
    assert_eq!(
        lib.import_file(&source, None).unwrap_err().code(),
        "index_error"
    );
    assert_eq!(names(&root.blobs()), [entry.digest().as_hex()]);
    assert!(names(&root.quarantine()).is_empty());
}

/// The tail links by name but checked the file by descriptor: when the name it linked is
/// another file, the new blob is removed, no row is written and the name is left as found;
/// the control, the same file under its own name, is stored.
#[test]
fn store_refuses_a_name_that_is_not_its_file() {
    let root = TmpRoot::new("imp-changed");
    let lib = Library::open(root.path(), 0).unwrap();
    let bytes = gguf("changed");
    let own = root.source("own.gguf", &bytes);
    let other = root.source("other.gguf", b"other bytes");
    let dir = crate::fd::open(
        root.path().join("src"),
        OFlags::RDONLY.union(OFlags::DIRECTORY),
        Mode::empty(),
    )
    .unwrap();
    let file = File::open(&own).unwrap();
    let entry = Entry {
        digest: sha(&bytes),
        size: bytes.len() as u64,
        format: Format::Gguf,
        source_name: SourceName::checked("own.gguf").unwrap(),
        imported_at: jiff::Timestamp::now(),
    };
    let err = store(&lib, &file, &dir, "other.gguf", entry.clone()).unwrap_err();
    assert_eq!(err.code(), "blob_changed");
    assert!(names(&root.blobs()).is_empty());
    assert!(lib.list().unwrap().is_empty());
    assert_eq!(std::fs::read(&other).unwrap(), b"other bytes");
    assert_eq!(std::fs::metadata(&other).unwrap().nlink(), 1);

    let stored = store(&lib, &file, &dir, "own.gguf", entry).unwrap();
    assert_eq!(stored.digest(), &sha(&bytes));
    assert_eq!(names(&root.blobs()), [sha(&bytes).as_hex()]);
}

/// A blob found under the digest is used only if it passes inspect's checks; otherwise the
/// import is refused, the found file is left exactly as it was, and no row is written.
#[test]
fn a_found_blob_that_fails_its_checks_is_refused() {
    let bytes = gguf("found");
    let digest = sha(&bytes);
    let mut longer = bytes.clone();
    longer.push(0);
    type Place<'a> = &'a dyn Fn(&std::path::Path);
    let cases: [(&str, Place); 3] = [
        ("writable", &|p| {
            std::fs::write(p, &bytes).unwrap();
            chmod(p, 0o644);
        }),
        ("wrong size", &|p| {
            std::fs::write(p, &longer).unwrap();
            chmod(p, 0o444);
        }),
        ("directory", &|p| {
            std::fs::create_dir(p).unwrap();
            chmod(p, 0o700);
        }),
    ];
    for (what, place) in cases {
        let root = TmpRoot::new("imp-found");
        let mut lib = Library::open(root.path(), 0).unwrap();
        let blob = root.blobs().join(digest.as_hex());
        place(&blob);
        let before = std::fs::symlink_metadata(&blob).unwrap();
        let source = root.source("m.gguf", &bytes);
        let err = lib.import_file(&source, None).unwrap_err();
        assert_eq!(err.code(), "blob_mismatch", "{what}");
        let after = std::fs::symlink_metadata(&blob).unwrap();
        assert_eq!(
            (after.ino(), after.mode(), after.len()),
            (before.ino(), before.mode(), before.len()),
            "{what}"
        );
        assert!(lib.list().unwrap().is_empty(), "{what}");
        assert!(names(&root.quarantine()).is_empty(), "{what}");
    }
}

/// The import time is the time of the import, to the second, and survives a reopen.
#[test]
fn imported_at_is_the_import_time() {
    let root = TmpRoot::new("imp-time");
    let mut lib = Library::open(root.path(), 0).unwrap();
    let before = jiff::Timestamp::now().as_second();
    let entry = lib
        .import_file(&root.source("m.gguf", &gguf("time")), None)
        .unwrap();
    let after = jiff::Timestamp::now().as_second();
    let at = entry.imported_at().as_second();
    assert!(before <= at && at <= after, "{before} {at} {after}");
    drop(lib);
    let lib = Library::open(root.path(), 0).unwrap();
    assert_eq!(lib.list().unwrap()[0].imported_at().as_second(), at);
}

/// A name with an allowed extension but a control character is refused before the file is
/// opened (a mode-000 file still answers this, not an I/O error); a non-ASCII name is kept.
#[test]
fn a_name_with_a_control_character_is_refused_unopened() {
    let root = TmpRoot::new("imp-ctrl");
    let mut lib = Library::open(root.path(), 0).unwrap();
    for name in ["a\x1b[31m.gguf", "a\nb.gguf", "a\x7f.gguf", "a\u{85}.gguf"] {
        let source = root.source(name, &gguf("ctrl"));
        chmod(&source, 0o000);
        let err = lib.import_file(&source, None).unwrap_err();
        assert_eq!(err.code(), "source_name_not_allowed", "{name:?}");
        assert_nothing_stored(&root, &lib);
    }
    let entry = lib
        .import_file(&root.source("modèle\u{202e}.gguf", &gguf("ok")), None)
        .unwrap();
    assert_eq!(entry.source_name().as_raw_str(), "modèle\u{202e}.gguf");
    assert!(entry.source_name().to_string().is_ascii());
}

/// A file larger than the free space less the reserve is refused before anything is created.
#[test]
fn a_file_that_does_not_fit_is_refused() {
    let root = TmpRoot::new("imp-disk");
    let mut lib = Library::open(root.path(), u64::MAX).unwrap();
    let source = root.source("m.gguf", &gguf("disk"));
    let err = lib.import_file(&source, None).unwrap_err();
    assert_eq!(err.code(), "insufficient_disk");
    assert!(
        err.to_string().contains(&gguf("disk").len().to_string()),
        "{err}"
    );
    assert_nothing_stored(&root, &lib);
    assert_eq!(lib.next_quarantine, 0, "a quarantine name was tried");
    // A real, small reserve still admits a small file.
    let mut lib = Library::open(root.path(), 1 << 20).unwrap();
    lib.import_file(&source, None).unwrap();
    assert_eq!(lib.list().unwrap().len(), 1);
}

/// Admission: the file must fit in what is available after the reserve.
#[test]
fn admits_leaves_the_reserve() {
    assert!(admits(10, 30, 20));
    assert!(admits(5, 30, 20));
    assert!(!admits(11, 30, 20));
    assert!(admits(0, 20, 20));
    assert!(!admits(1, 20, 20));
    assert!(!admits(0, 19, 20), "less available than the reserve");
    assert!(admits(u64::MAX, u64::MAX, 0));
}

/// The copy stops one byte past the source's size; that byte means the source grew.
#[test]
fn not_grown_refuses_a_byte_past_the_size() {
    assert!(not_grown(10, 10).is_ok());
    assert!(not_grown(9, 10).is_ok());
    assert_eq!(not_grown(11, 10).unwrap_err().code(), "source_changed");
}

/// No refusal's message carries the source's path or name, and file-chosen text from the
/// header reaches the message only escaped.
#[test]
fn refusals_do_not_echo_the_source() {
    let root = TmpRoot::new("imp-echo");
    let mut lib = Library::open(root.path(), 0).unwrap();
    let dup = Gguf::valid()
        .tensor(Tensor::of("w\u{202e}", F32, &[8]))
        .tensor(Tensor::of("w\u{202e}", F32, &[8]))
        .bytes();
    for (name, bytes) in [
        ("secret\u{202e}.bin", gguf("e")),
        ("secret\u{202e}.gguf", b"nope".to_vec()),
        ("secret\u{202e}.gguf", gguf("e")),
        ("secret\u{202e}.gguf", dup),
    ] {
        let source = root.source(name, &bytes);
        let got = lib.import_file(&source, Some(&sha(b"x")));
        let text = format!("{}", got.unwrap_err());
        assert!(!text.contains("secret"), "{text}");
        assert!(text.is_ascii(), "{text}");
    }
}

/// The copy's length on disk must equal the bytes copied.
#[test]
fn same_length_compares_copied_and_on_disk() {
    assert_eq!(same_length(10, 10).unwrap(), 10);
    assert_eq!(
        same_length(10, 11).unwrap_err().code(),
        "quarantine_changed"
    );
    assert_eq!(
        same_length(11, 10).unwrap_err().code(),
        "quarantine_changed"
    );
}
