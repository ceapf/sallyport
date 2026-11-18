#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use super::*;
use crate::library::Library;
use crate::library::testkit::{TmpRoot, gguf, names};

/// The name is the process id and the counter.
#[test]
fn the_name_is_pid_dash_counter() {
    assert_eq!(name(1234, 7), "1234-7");
    assert_eq!(name(1, 0), "1-0");
}

/// A name that already exists is skipped, never opened, reused or removed.
#[test]
fn an_existing_name_is_skipped_and_kept() {
    let root = TmpRoot::new("q-skip");
    let mut lib = Library::open(root.path(), 0).unwrap();
    let taken = root.quarantine().join(name(std::process::id(), 0));
    std::fs::create_dir(&taken).unwrap();
    std::fs::write(taken.join("blob"), b"theirs").unwrap();
    let source = root.source("m.gguf", &gguf("skip"));
    lib.import_file(&source, None).unwrap();
    assert_eq!(std::fs::read(taken.join("blob")).unwrap(), b"theirs");
    assert_eq!(names(&root.quarantine()), [name(std::process::id(), 0)]);
}

/// 64 names taken: the import is refused quarantine_busy and nothing is stored; 63 taken still
/// leaves the 64th try.
#[test]
fn the_tries_are_bounded_at_64() {
    for (taken, ok) in [(63, true), (64, false)] {
        let root = TmpRoot::new("q-busy");
        let mut lib = Library::open(root.path(), 0).unwrap();
        for n in 0..taken {
            std::fs::create_dir(root.quarantine().join(name(std::process::id(), n))).unwrap();
        }
        let source = root.source("m.gguf", &gguf("busy"));
        let got = lib.import_file(&source, None);
        assert_eq!(got.is_ok(), ok, "{taken}: {got:?}");
        if !ok {
            assert_eq!(got.unwrap_err().code(), "quarantine_busy");
            assert!(names(&root.blobs()).is_empty());
            assert!(lib.list().unwrap().is_empty());
        }
        assert_eq!(names(&root.quarantine()).len(), taken as usize);
    }
}

/// Successive imports take successive names, and each leaves the quarantine empty.
#[test]
fn the_counter_moves_on_and_quarantine_empties() {
    let root = TmpRoot::new("q-next");
    let mut lib = Library::open(root.path(), 0).unwrap();
    for tag in ["a", "b", "c"] {
        let source = root.source(&format!("{tag}.gguf"), &gguf(tag));
        lib.import_file(&source, None).unwrap();
        assert!(names(&root.quarantine()).is_empty());
    }
    assert_eq!(lib.next_quarantine, 3);
}

/// The quarantine directory an import makes is 0700 while it exists.
#[test]
fn a_quarantine_dir_is_private() {
    let root = TmpRoot::new("q-mode");
    let mut lib = Library::open(root.path(), 0).unwrap();
    let q = Quarantine::create(&lib.dirs.quarantine, &mut lib.next_quarantine).unwrap();
    let path = root.quarantine().join(name(std::process::id(), 0));
    assert_eq!(crate::library::testkit::mode(&path), 0o700);
    let file = q.create_file().unwrap();
    drop(file);
    assert_eq!(crate::library::testkit::mode(&path.join("blob")), 0o600);
    drop(q);
    assert!(!path.exists());
}
