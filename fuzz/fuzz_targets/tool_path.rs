//! Fuzz target: arbitrary text → the file tools' guest-path parser and the `.git` check
//! (SI-8; maintainer's Task 11 decision 8; CLAUDE.md: every parser of untrusted bytes has one).
//!
//! Invariants: never panics; a located path names a mount that exists, and its relative path is
//! canonical (no empty, `.` or `..` segment, no leading or trailing `/`), within the length bound
//! and free of control bytes; the guest root plus that path names the same place as the input
//! once its `.` and empty segments are dropped; a path with a `..` segment is never located.
#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use sallyd::tools::path::{MAX_PATH, locate, protected};

const GUESTS: [&str; 4] = [
    "/workspace/notes",
    "/workspace/p",
    "/workspace/p2",
    "/workspace/a/b",
];

fuzz_target!(|data: &[u8]| {
    let Ok(path) = std::str::from_utf8(data) else {
        return;
    };
    let _ = protected(path);
    for root_ok in [false, true] {
        let Ok(l) = locate(&GUESTS, path, root_ok) else {
            continue;
        };
        let guest = GUESTS.get(l.mount).expect("a located path names a mount");
        assert!(root_ok || !l.rel.is_empty(), "the root located for a file");
        if !l.rel.is_empty() {
            assert!(
                l.rel.split('/').all(|s| !matches!(s, "" | "." | "..")),
                "rel not canonical: {:?}",
                l.rel
            );
        }
        assert!(l.rel.len() <= MAX_PATH, "rel too long");
        assert!(l.rel.bytes().all(|b| b >= 0x20 && b != 0x7f), "control byte in rel");
        let segs: Vec<&str> = path
            .split('/')
            .filter(|s| !s.is_empty() && *s != ".")
            .collect();
        assert!(!segs.contains(&".."), "a path with .. was located");
        let joined = if l.rel.is_empty() {
            (*guest).to_owned()
        } else {
            format!("{guest}/{}", l.rel)
        };
        assert_eq!(format!("/{}", segs.join("/")), joined, "located elsewhere");
    }
});
