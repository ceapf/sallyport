//! Fuzz target: arbitrary bytes → the parser of the kernel's mount table
//! (`/proc/self/mountinfo`) that the manifest validator reads, on WSL, to refuse a mount root on
//! a Windows drive's filesystem type (RT-FS-11). The kernel writes the table, but mount points
//! and FUSE subtypes in it are chosen by users; CLAUDE.md: every such parser has a fuzz target.
//!
//! Input: eight bytes of mount id (little-endian), then the table's bytes.
//!
//! Invariants: never panics; an accepted type is non-empty and holds no space, newline or `.`,
//! exactly one line of the table begins with the id's decimal and a space, and the type is that
//! line's field after the first `-` past the six fixed fields, up to its first `.`; the table with
//! that line appended again is an error; the table with every trailing newline removed is an
//! error (one removed may leave a table that ends in a blank line, which is whole).
#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use sally_core::manifest::mount_fs_type;

fuzz_target!(|data: &[u8]| {
    let Some((id, table)) = data.split_first_chunk::<8>() else {
        return;
    };
    let id = u64::from_le_bytes(*id);
    let Ok(ty) = mount_fs_type(table, id) else {
        return;
    };
    assert!(!ty.is_empty(), "an empty type");
    assert!(
        !ty.bytes().any(|b| matches!(b, b' ' | b'\n' | b'.')),
        "a type holding a separator: {ty:?}"
    );
    let head = format!("{id} ");
    let matching: Vec<&[u8]> = table
        .split(|&b| b == b'\n')
        .filter(|l| l.starts_with(head.as_bytes()))
        .collect();
    assert_eq!(matching.len(), 1, "lines with the id");
    // The type is the field after the first `-` past the six fixed fields, up to its first `.`.
    let fields: Vec<&[u8]> = matching[0].split(|&b| b == b' ').collect();
    let sep = 6 + fields[6..].iter().position(|f| *f == b"-").unwrap();
    let want = fields[sep + 1].split(|&b| b == b'.').next().unwrap();
    assert_eq!(ty.as_bytes(), want, "another field given");
    let mut twice = table.to_vec();
    twice.extend_from_slice(matching[0]);
    twice.push(b'\n');
    assert!(mount_fs_type(&twice, id).is_err(), "a second line accepted");
    let end = table.iter().rposition(|&b| b != b'\n').map_or(0, |i| i + 1);
    assert!(mount_fs_type(&table[..end], id).is_err(), "a cut table accepted");
});
