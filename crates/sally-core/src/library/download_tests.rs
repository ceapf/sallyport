#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::os::unix::fs::{MetadataExt, symlink};

use super::*;
use crate::library::Library;
use crate::library::testkit::{TmpRoot, assert_nothing_stored, chmod, gguf, mode, names, sha};

/// The partial file's name for `bytes`.
fn part(bytes: &[u8]) -> String {
    format!("{}.part", sha(bytes).as_hex())
}

/// Writes `bytes` at 0600 under a temporary name in `dir`, then renames it over `name`.
fn replace(dir: &std::path::Path, name: &str, bytes: &[u8]) {
    let tmp = dir.join("replacement.tmp");
    std::fs::write(&tmp, bytes).unwrap();
    chmod(&tmp, 0o600);
    std::fs::rename(&tmp, dir.join(name)).unwrap();
}

/// A whole download, written in one chunk, is verified and promoted: the blob is stored at 0444
/// under its digest, the row written, and downloads/ left empty.
#[test]
fn a_whole_download_is_promoted() {
    let root = TmpRoot::new("dl-ok");
    let mut lib = Library::open(root.path(), 0).unwrap();
    let bytes = gguf("dl-ok");
    let size = bytes.len() as u64;
    let mut d = lib.begin_download("m.gguf", &sha(&bytes), size).unwrap();
    assert_eq!((d.written(), d.size()), (0, size));
    assert_eq!(names(&root.downloads()), [part(&bytes)]);
    assert_eq!(mode(&root.downloads().join(part(&bytes))), 0o600);
    d.append(&bytes).unwrap();
    assert_eq!(d.written(), size);
    let v = d.verify().unwrap();
    assert_eq!(v.digest(), &sha(&bytes));
    let entry = lib.promote(v).unwrap();
    assert_eq!(entry.digest(), &sha(&bytes));
    assert_eq!(entry.size(), size);
    assert_eq!(entry.source_name().as_raw_str(), "m.gguf");
    let blob = root.blobs().join(sha(&bytes).as_hex());
    assert_eq!(std::fs::read(&blob).unwrap(), bytes);
    assert_eq!(mode(&blob), 0o444);
    assert_eq!(std::fs::metadata(&blob).unwrap().nlink(), 1);
    assert_eq!(lib.list().unwrap(), [entry]);
    assert!(names(&root.downloads()).is_empty());
    assert!(names(&root.quarantine()).is_empty());
}

/// A download stopped half way keeps its bytes; the next begin resumes at that offset and the
/// verify covers every byte, whichever run wrote it.
#[test]
fn a_stopped_download_resumes_where_it_stopped() {
    let root = TmpRoot::new("dl-resume");
    let mut lib = Library::open(root.path(), 0).unwrap();
    let bytes = gguf("dl-resume");
    let size = bytes.len() as u64;
    let half = bytes.len() / 2;
    let mut d = lib.begin_download("m.gguf", &sha(&bytes), size).unwrap();
    d.append(&bytes[..half]).unwrap();
    drop(d);
    let mut d = lib.begin_download("m.gguf", &sha(&bytes), size).unwrap();
    assert_eq!(d.written(), half as u64);
    d.append(&bytes[half..]).unwrap();
    let entry = lib.promote(d.verify().unwrap()).unwrap();
    assert_eq!(entry.digest(), &sha(&bytes));
    assert!(names(&root.downloads()).is_empty());
}

/// A verified download that is dropped before its promote leaves a 0600 partial, never a
/// read-only one; the next begin resumes it at its full length and verifies it again from
/// byte 0: one byte changed meanwhile at the same length is a hash mismatch, nothing stored.
/// The control, the same steps with the bytes untouched, is promoted.
#[test]
fn a_dropped_verified_download_is_verified_again() {
    let root = TmpRoot::new("dl-dropv");
    let mut lib = Library::open(root.path(), 0).unwrap();
    let bytes = gguf("dl-dropv");
    let size = bytes.len() as u64;
    let path = root.downloads().join(part(&bytes));
    let verified_then_dropped = |lib: &mut Library| {
        let mut d = lib.begin_download("m.gguf", &sha(&bytes), size).unwrap();
        d.append(&bytes).unwrap();
        drop(d.verify().unwrap());
        assert_eq!(mode(&path), 0o600);
        assert!(names(&root.blobs()).is_empty());
    };

    verified_then_dropped(&mut lib);
    let mut changed = bytes.clone();
    let last = changed.len() - 1;
    changed[last] ^= 1;
    std::fs::write(&path, &changed).unwrap();
    let d = lib.begin_download("m.gguf", &sha(&bytes), size).unwrap();
    assert_eq!(d.written(), size);
    assert_eq!(d.verify().unwrap_err().code(), "hash_mismatch");
    assert_nothing_stored(&root, &lib);

    verified_then_dropped(&mut lib);
    let d = lib.begin_download("m.gguf", &sha(&bytes), size).unwrap();
    assert_eq!(d.written(), size);
    lib.promote(d.verify().unwrap()).unwrap();
    assert_eq!(names(&root.blobs()), [sha(&bytes).as_hex()]);
}

/// Bytes that do not hash to the expected digest are deleted with nothing stored; the control,
/// a matching download through the same library, is stored (RT-MDL-04's filesystem half).
#[test]
fn a_hash_mismatch_deletes_the_partial_and_stores_nothing() {
    let root = TmpRoot::new("dl-hash");
    let mut lib = Library::open(root.path(), 0).unwrap();
    let good = gguf("dl-hash-good");
    let bad = gguf("dl-hash-badd");
    assert_eq!(good.len(), bad.len());
    let size = good.len() as u64;

    let mut d = lib.begin_download("m.gguf", &sha(&good), size).unwrap();
    d.append(&bad).unwrap();
    let err = d.verify().unwrap_err();
    assert_eq!(err.code(), "hash_mismatch");
    assert_nothing_stored(&root, &lib);

    let mut d = lib.begin_download("m.gguf", &sha(&good), size).unwrap();
    d.append(&good).unwrap();
    lib.promote(d.verify().unwrap()).unwrap();
    assert_eq!(names(&root.blobs()), [sha(&good).as_hex()]);
}

/// The hash is checked before anything else reads the bytes: a file with the wrong magic and
/// the wrong digest is refused for its digest, not its magic; with the right digest the same
/// bytes are refused for their magic, and deleted.
#[test]
fn the_hash_is_checked_before_the_magic() {
    let root = TmpRoot::new("dl-order");
    let mut lib = Library::open(root.path(), 0).unwrap();
    let junk = b"NOTGGUF and some more bytes".to_vec();
    let size = junk.len() as u64;

    let mut d = lib.begin_download("m.gguf", &sha(b"other"), size).unwrap();
    d.append(&junk).unwrap();
    assert_eq!(d.verify().unwrap_err().code(), "hash_mismatch");
    assert_nothing_stored(&root, &lib);

    let mut d = lib.begin_download("m.gguf", &sha(&junk), size).unwrap();
    d.append(&junk).unwrap();
    assert_eq!(d.verify().unwrap_err().code(), "magic_mismatch");
    assert_nothing_stored(&root, &lib);
}

/// Bytes with the publisher's digest that the strict parser refuses are deleted.
#[test]
fn a_matching_file_the_parser_refuses_is_deleted() {
    let root = TmpRoot::new("dl-parse");
    let mut lib = Library::open(root.path(), 0).unwrap();
    let mut bytes = gguf("dl-parse");
    bytes.truncate(12);
    let size = bytes.len() as u64;
    let mut d = lib.begin_download("m.gguf", &sha(&bytes), size).unwrap();
    d.append(&bytes).unwrap();
    let err = d.verify().unwrap_err();
    assert!(matches!(err, LibraryError::Gguf(_)), "{err:?}");
    assert_nothing_stored(&root, &lib);
}

/// A short download is not verified: it is incomplete and its bytes are kept for a resume.
#[test]
fn a_short_download_is_kept_for_a_resume() {
    let root = TmpRoot::new("dl-short");
    let mut lib = Library::open(root.path(), 0).unwrap();
    let bytes = gguf("dl-short");
    let size = bytes.len() as u64;
    let mut d = lib.begin_download("m.gguf", &sha(&bytes), size).unwrap();
    d.append(&bytes[..10]).unwrap();
    let err = d.verify().unwrap_err();
    assert_eq!(err.code(), "download_incomplete");
    assert!(err.to_string().contains(&format!("10 of {size}")), "{err}");
    let kept = root.downloads().join(part(&bytes));
    assert_eq!(std::fs::read(kept).unwrap(), &bytes[..10]);
    assert!(names(&root.blobs()).is_empty());
    assert!(lib.list().unwrap().is_empty());
}

/// A chunk that would take the file past its size is refused and nothing of it is written; the
/// last byte that fits is accepted.
#[test]
fn append_stops_at_the_listed_size() {
    let root = TmpRoot::new("dl-long");
    let mut lib = Library::open(root.path(), 0).unwrap();
    let bytes = gguf("dl-long");
    let size = bytes.len() as u64;
    let mut d = lib.begin_download("m.gguf", &sha(&bytes), size).unwrap();
    d.append(&bytes[..bytes.len() - 1]).unwrap();
    let err = d.append(b"xy").unwrap_err();
    assert_eq!(err.code(), "download_too_long");
    assert_eq!(d.written(), size - 1);
    d.append(&bytes[bytes.len() - 1..]).unwrap();
    assert_eq!(d.append(b"z").unwrap_err().code(), "download_too_long");
    let on_disk = std::fs::metadata(root.downloads().join(part(&bytes))).unwrap();
    assert_eq!(on_disk.len(), size);
    lib.promote(d.verify().unwrap()).unwrap();
}

/// Append writes at the download's own offset, wherever the descriptor's cursor is.
#[test]
fn append_writes_at_the_written_offset() {
    let root = TmpRoot::new("dl-at");
    let mut lib = Library::open(root.path(), 0).unwrap();
    let bytes = gguf("dl-at");
    let size = bytes.len() as u64;
    let mut d = lib.begin_download("m.gguf", &sha(&bytes), size).unwrap();
    d.append(&bytes[..5]).unwrap();
    (&d.file).seek(SeekFrom::Start(0)).unwrap();
    d.append(&bytes[5..]).unwrap();
    let path = root.downloads().join(part(&bytes));
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    lib.promote(d.verify().unwrap()).unwrap();
}

/// Every append checks the room again before writing: with no space left it is refused, the
/// chunk unwritten and the partial kept; the reserve the download began with counts; the
/// control, the same chunk with room, is written.
#[test]
fn append_checks_the_room_before_writing() {
    let root = TmpRoot::new("dl-room");
    let reserve = 10;
    let mut lib = Library::open(root.path(), reserve).unwrap();
    let bytes = gguf("dl-room");
    let size = bytes.len() as u64;
    let need = size + size.div_ceil(20);
    let mut d = lib.begin_download("m.gguf", &sha(&bytes), size).unwrap();
    let path = root.downloads().join(part(&bytes));
    for available in [0, need, need + reserve - 1] {
        let err = d.append_with(&bytes[..5], available).unwrap_err();
        assert_eq!(err.code(), "insufficient_disk", "{available}");
        assert_eq!(d.written(), 0);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
    }
    d.append_with(&bytes[..5], need + reserve).unwrap();
    assert_eq!(d.written(), 5);
    assert_eq!(std::fs::read(&path).unwrap(), &bytes[..5]);
    d.append_with(&bytes[5..], u64::MAX).unwrap();
    // Complete: an empty chunk needs no room.
    d.append_with(&[], 0).unwrap();
    lib.promote(d.verify().unwrap()).unwrap();
}

/// A partial longer than the listed size is refused as too long at verify and deleted; the
/// control, a partial of exactly its size written the same way, is promoted.
#[test]
fn a_partial_longer_than_its_size_is_refused_at_verify() {
    let root = TmpRoot::new("dl-grown");
    let mut lib = Library::open(root.path(), 0).unwrap();
    let exact = gguf("dl-exact");
    let d = lib
        .begin_download("m.gguf", &sha(&exact), exact.len() as u64)
        .unwrap();
    std::fs::write(root.downloads().join(part(&exact)), &exact).unwrap();
    lib.promote(d.verify().unwrap()).unwrap();
    lib.remove(&sha(&exact)).unwrap();

    let bytes = gguf("dl-grown");
    let size = bytes.len() as u64;
    let d = lib.begin_download("m.gguf", &sha(&bytes), size).unwrap();
    let path = root.downloads().join(part(&bytes));
    let mut grown = bytes.clone();
    grown.push(0);
    std::fs::write(&path, &grown).unwrap();
    assert_eq!(d.verify().unwrap_err().code(), "download_too_long");
    assert_nothing_stored(&root, &lib);
}

/// A partial found longer than the listed size is emptied when the download begins.
#[test]
fn an_overlong_partial_starts_again_from_zero() {
    let root = TmpRoot::new("dl-over");
    let mut lib = Library::open(root.path(), 0).unwrap();
    let bytes = gguf("dl-over");
    let size = bytes.len() as u64;
    drop(lib.begin_download("m.gguf", &sha(&bytes), size).unwrap());
    let path = root.downloads().join(part(&bytes));
    let mut grown = bytes.clone();
    grown.push(0);
    std::fs::write(&path, &grown).unwrap();
    let d = lib.begin_download("m.gguf", &sha(&bytes), size).unwrap();
    assert_eq!(d.written(), 0);
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
}

/// Restart empties the file and writes again from byte 0 (a 200 answered to a range request).
#[test]
fn restart_empties_the_partial() {
    let root = TmpRoot::new("dl-restart");
    let mut lib = Library::open(root.path(), 0).unwrap();
    let bytes = gguf("dl-restart");
    let size = bytes.len() as u64;
    let mut d = lib.begin_download("m.gguf", &sha(&bytes), size).unwrap();
    d.append(b"garbage").unwrap();
    d.restart().unwrap();
    assert_eq!(d.written(), 0);
    d.append(&bytes).unwrap();
    lib.promote(d.verify().unwrap()).unwrap();
}

/// Discard removes the partial.
#[test]
fn discard_removes_the_partial() {
    let root = TmpRoot::new("dl-discard");
    let mut lib = Library::open(root.path(), 0).unwrap();
    let bytes = gguf("dl-discard");
    let mut d = lib
        .begin_download("m.gguf", &sha(&bytes), bytes.len() as u64)
        .unwrap();
    d.append(&bytes[..5]).unwrap();
    d.discard().unwrap();
    assert_nothing_stored(&root, &lib);
}

/// A second download of the same digest while the first holds it is refused busy; once the
/// first is dropped it may begin, with the first one's bytes.
#[test]
fn a_held_download_is_busy() {
    let root = TmpRoot::new("dl-busy");
    let mut lib = Library::open(root.path(), 0).unwrap();
    let bytes = gguf("dl-busy");
    let size = bytes.len() as u64;
    let mut first = lib.begin_download("m.gguf", &sha(&bytes), size).unwrap();
    first.append(&bytes[..3]).unwrap();
    let err = lib
        .begin_download("m.gguf", &sha(&bytes), size)
        .err()
        .unwrap();
    assert_eq!(err.code(), "download_busy");
    drop(first);
    let again = lib.begin_download("m.gguf", &sha(&bytes), size).unwrap();
    assert_eq!(again.written(), 3);
}

/// The lock is bound to the name: a partial whose name was replaced or removed between the
/// open and the lock is refused busy and the replacement left as found; the control, the same
/// two steps with the name untouched, binds.
#[test]
fn the_lock_is_bound_to_the_name() {
    let root = TmpRoot::new("dl-bind");
    let lib = Library::open(root.path(), 0).unwrap();
    let dir = &lib.dirs.downloads;
    let name = part(b"bind");

    let fd = open_unlocked(&lib, &name, 100).unwrap();
    replace(&root.downloads(), &name, b"replacement");
    let err = lock_and_bind(fd, dir, &name).err().unwrap();
    assert_eq!(err.code(), "download_busy");
    let path = root.downloads().join(&name);
    assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
    assert_eq!(mode(&path), 0o600);
    std::fs::remove_file(&path).unwrap();

    let fd = open_unlocked(&lib, &name, 100).unwrap();
    std::fs::remove_file(&path).unwrap();
    let err = lock_and_bind(fd, dir, &name).err().unwrap();
    assert_eq!(err.code(), "download_busy");
    assert!(names(&root.downloads()).is_empty());

    // Moved away (still one link, still 0600) and a new partial made under the name: only the
    // binding tells the two apart.
    let moved = root.downloads().join("moved");
    let fd = open_unlocked(&lib, &name, 100).unwrap();
    std::fs::rename(&path, &moved).unwrap();
    drop(open_unlocked(&lib, &name, 100).unwrap());
    let err = lock_and_bind(fd, dir, &name).err().unwrap();
    assert_eq!(err.code(), "download_busy");
    assert_eq!(mode(&moved), 0o600);
    assert_eq!(mode(&path), 0o600);
    std::fs::remove_file(&moved).unwrap();
    std::fs::remove_file(&path).unwrap();

    let fd = open_unlocked(&lib, &name, 100).unwrap();
    drop(lock_and_bind(fd, dir, &name).unwrap());
}

/// The partial is checked again on the locked descriptor: one whose mode changed, or that
/// gained a second link, between the open and the lock is refused and left as found; the
/// control, the same two steps with the file untouched, binds.
#[test]
fn the_partial_is_checked_again_after_the_lock() {
    let root = TmpRoot::new("dl-recheck");
    let lib = Library::open(root.path(), 0).unwrap();
    let dir = &lib.dirs.downloads;
    let name = part(b"recheck");
    let path = root.downloads().join(&name);

    let fd = open_unlocked(&lib, &name, 100).unwrap();
    chmod(&path, 0o644);
    let err = lock_and_bind(fd, dir, &name).err().unwrap();
    assert_eq!(err.code(), "download_not_private");
    assert_eq!(mode(&path), 0o644);
    chmod(&path, 0o600);

    let second = root.downloads().join("second");
    let fd = open_unlocked(&lib, &name, 100).unwrap();
    std::fs::hard_link(&path, &second).unwrap();
    let err = lock_and_bind(fd, dir, &name).err().unwrap();
    assert_eq!(err.code(), "download_not_private");
    assert_eq!(std::fs::metadata(&path).unwrap().nlink(), 2);
    std::fs::remove_file(&second).unwrap();

    let fd = open_unlocked(&lib, &name, 100).unwrap();
    drop(lock_and_bind(fd, dir, &name).unwrap());
}

/// A partial that is not a private regular file of the current user is refused and left as it
/// was: another mode, or a symlink in its place.
#[test]
fn a_partial_that_is_not_private_is_refused_unchanged() {
    let root = TmpRoot::new("dl-mode");
    let mut lib = Library::open(root.path(), 0).unwrap();
    let bytes = gguf("dl-mode");
    let size = bytes.len() as u64;
    let path = root.downloads().join(part(&bytes));
    // Control: the same partial at 0600 is resumed from its length.
    std::fs::write(&path, b"abc").unwrap();
    chmod(&path, 0o600);
    let ok = lib.begin_download("m.gguf", &sha(&bytes), size).unwrap();
    assert_eq!(ok.written(), 3);
    drop(ok);
    std::fs::remove_file(&path).unwrap();
    for bad in [0o644, 0o400, 0o700] {
        std::fs::write(&path, b"abc").unwrap();
        chmod(&path, bad);
        let err = lib
            .begin_download("m.gguf", &sha(&bytes), size)
            .err()
            .unwrap();
        assert_eq!(err.code(), "download_not_private", "{bad:o}");
        assert_eq!(mode(&path), bad, "the mode was changed");
        assert_eq!(std::fs::read(&path).unwrap(), b"abc");
        chmod(&path, 0o600);
        std::fs::remove_file(&path).unwrap();
    }
    let target = root.source("t.gguf", b"target");
    symlink(&target, &path).unwrap();
    let err = lib
        .begin_download("m.gguf", &sha(&bytes), size)
        .err()
        .unwrap();
    assert_eq!(err.code(), "download_not_private");
    assert_eq!(std::fs::read(&target).unwrap(), b"target");
    assert!(std::fs::symlink_metadata(&path).unwrap().is_symlink());
}

/// A partial with a second hard link is refused and the other file left as it was: a 0600
/// canary linked in as the partial keeps its bytes (longer than the size, so a begin that took
/// it would have emptied it) and its mode.
#[test]
fn a_partial_with_a_second_link_is_refused_unchanged() {
    let root = TmpRoot::new("dl-nlink");
    let mut lib = Library::open(root.path(), 0).unwrap();
    let bytes = gguf("dl-nlink");
    let size = bytes.len() as u64;
    let canary_bytes = vec![b'c'; bytes.len() + 10];
    let canary = root.source("canary.gguf", &canary_bytes);
    chmod(&canary, 0o600);
    let path = root.downloads().join(part(&bytes));
    std::fs::hard_link(&canary, &path).unwrap();
    let err = lib
        .begin_download("m.gguf", &sha(&bytes), size)
        .err()
        .unwrap();
    assert_eq!(err.code(), "download_not_private");
    assert_eq!(std::fs::read(&canary).unwrap(), canary_bytes);
    assert_eq!(mode(&canary), 0o600);
    // Control: once the second link is gone the same file is a partial again.
    std::fs::remove_file(&canary).unwrap();
    let d = lib.begin_download("m.gguf", &sha(&bytes), size).unwrap();
    assert_eq!(d.written(), 0);
}

/// A name off the allowlist, or one the library will not keep, is refused before any file is
/// created.
#[test]
fn a_name_is_checked_before_any_file_exists() {
    let root = TmpRoot::new("dl-name");
    let mut lib = Library::open(root.path(), 0).unwrap();
    let d = sha(b"x");
    for (name, code) in [
        ("m.bin", "format_not_allowed"),
        ("m.pkl", "format_not_allowed"),
        ("a/m.gguf", "format_not_allowed"),
        ("m\u{7}.gguf", "source_name_not_allowed"),
    ] {
        let err = lib.begin_download(name, &d, 10).err().unwrap();
        assert_eq!(err.code(), code, "{name:?}");
    }
    assert!(names(&root.downloads()).is_empty());
    // Control: an allowed name begins and creates its partial.
    drop(lib.begin_download("m.gguf", &d, 10).unwrap());
    assert_eq!(names(&root.downloads()), [format!("{}.part", d.as_hex())]);
}

/// A download that does not fit is refused before its file is created; the control, the same
/// download with no reserve, begins.
#[test]
fn a_download_that_does_not_fit_creates_nothing() {
    let root = TmpRoot::new("dl-disk");
    let bytes = gguf("dl-disk");
    let size = bytes.len() as u64;
    let mut lib = Library::open(root.path(), u64::MAX).unwrap();
    let err = lib
        .begin_download("m.gguf", &sha(&bytes), size)
        .err()
        .unwrap();
    assert_eq!(err.code(), "insufficient_disk");
    assert!(names(&root.downloads()).is_empty());
    drop(lib);
    let mut lib = Library::open(root.path(), 0).unwrap();
    drop(lib.begin_download("m.gguf", &sha(&bytes), size).unwrap());
    assert_eq!(names(&root.downloads()), [part(&bytes)]);
}

/// Bytes already in the library are promoted to their existing row, and the partial removed.
#[test]
fn a_download_of_stored_bytes_returns_the_row() {
    let root = TmpRoot::new("dl-dup");
    let mut lib = Library::open(root.path(), 0).unwrap();
    let bytes = gguf("dl-dup");
    let first = lib
        .import_file(&root.source("a.gguf", &bytes), None)
        .unwrap();
    let mut d = lib
        .begin_download("b.gguf", &sha(&bytes), bytes.len() as u64)
        .unwrap();
    d.append(&bytes).unwrap();
    assert_eq!(lib.promote(d.verify().unwrap()).unwrap(), first);
    assert_eq!(lib.list().unwrap(), [first]);
    assert!(names(&root.downloads()).is_empty());
}

/// A partial whose name was replaced after it was verified is refused at promote as changed:
/// no blob, no row, and the name left as found; the control, the same steps with the name
/// untouched, is promoted.
#[test]
fn a_partial_replaced_after_verify_is_not_promoted() {
    let root = TmpRoot::new("dl-swap");
    let mut lib = Library::open(root.path(), 0).unwrap();
    let bytes = gguf("dl-swap");
    let size = bytes.len() as u64;
    let mut d = lib.begin_download("m.gguf", &sha(&bytes), size).unwrap();
    d.append(&bytes).unwrap();
    let v = d.verify().unwrap();
    replace(&root.downloads(), &part(&bytes), b"replacement");
    let err = lib.promote(v).unwrap_err();
    assert_eq!(err.code(), "blob_changed");
    assert!(names(&root.blobs()).is_empty());
    assert!(lib.list().unwrap().is_empty());
    let path = root.downloads().join(part(&bytes));
    assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
    assert_eq!(mode(&path), 0o600);
    std::fs::remove_file(&path).unwrap();

    let mut d = lib.begin_download("m.gguf", &sha(&bytes), size).unwrap();
    d.append(&bytes).unwrap();
    lib.promote(d.verify().unwrap()).unwrap();
    assert_eq!(names(&root.blobs()), [sha(&bytes).as_hex()]);
}

/// Admission counts what is left to fetch plus a twentieth of the size (rounded up) against
/// the room above the reserve: equal fits, one byte less does not.
#[test]
fn admission_counts_the_rest_and_a_twentieth() {
    // size 100, nothing on disk: 100 + 5.
    assert!(admits_download(100, 0, 105, 0));
    assert!(!admits_download(100, 0, 104, 0));
    // 40 on disk: 60 + 5.
    assert!(admits_download(100, 40, 65, 0));
    assert!(!admits_download(100, 40, 64, 0));
    // ceil(101 / 20) = 6.
    assert!(admits_download(101, 0, 107, 0));
    assert!(!admits_download(101, 0, 106, 0));
    // The reserve comes off the room.
    assert!(admits_download(100, 0, 115, 10));
    assert!(!admits_download(100, 0, 114, 10));
    assert!(!admits_download(1, 0, 5, 10));
    // No overflow.
    assert!(!admits_download(u64::MAX, 0, u64::MAX, 0));
    assert!(admits_download(
        u64::MAX,
        u64::MAX,
        u64::MAX,
        u64::MAX - u64::MAX / 20 - 1
    ));
}

/// A complete partial needs no room: one byte short needs that byte plus the slack, all of
/// it needs nothing, even with no space and a reserve.
#[test]
fn admission_admits_a_complete_partial() {
    assert!(admits_download(100, 99, 6, 0));
    assert!(!admits_download(100, 99, 5, 0));
    assert!(admits_download(100, 100, 0, 0));
    assert!(admits_download(100, 100, 0, 10));
    assert!(admits_download(100, 101, 0, 10));
}

/// The offset a download starts at: what is on disk, or 0 when that is more than the size.
#[test]
fn the_start_offset_is_what_is_on_disk_up_to_the_size() {
    assert_eq!(start_offset(0, 10), 0);
    assert_eq!(start_offset(4, 10), 4);
    assert_eq!(start_offset(10, 10), 10);
    assert_eq!(start_offset(11, 10), 0);
}

/// The partial's rule: a regular file of the current user, exactly 0600, one link.
#[test]
fn part_ok_wants_a_private_regular_file() {
    const FILE: u32 = 0o100_000;
    assert!(part_ok(FILE | 0o600, 1, 7, 7));
    assert!(!part_ok(FILE | 0o600, 2, 7, 7));
    assert!(!part_ok(FILE | 0o600, 0, 7, 7));
    assert!(!part_ok(FILE | 0o600, 1, 8, 7));
    assert!(!part_ok(FILE | 0o640, 1, 7, 7));
    assert!(!part_ok(FILE | 0o4600, 1, 7, 7));
    assert!(!part_ok(0o040_000 | 0o600, 1, 7, 7));
}
