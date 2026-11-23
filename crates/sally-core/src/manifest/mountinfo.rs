//! The kernel's mount table (`/proc/self/mountinfo`), read for one question: the type of the
//! filesystem a mount root lies on, found by the root's mount id (RT-FS-11: on WSL a root on a
//! Windows drive's filesystem type is refused, wherever the drive is mounted).
//!
//! The kernel writes the table, but mount points and FUSE subtypes in it are chosen by users,
//! so it is parsed as untrusted bytes: bounds first, no indexing, a fuzz target
//! (`fuzz/fuzz_targets/mountinfo.rs`). A line is
//! `id parent major:minor root mount-point options [optional fields…] - type source super-options`.
#![deny(clippy::indexing_slicing)]

/// The largest mount table read, in bytes; a longer one is refused, never cut (RT-FS-11).
pub const MAX_MOUNT_TABLE: usize = 1 << 20;

/// Why the mount table gave no filesystem type for a mount. The messages never quote the
/// table's bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MountInfoError {
    /// The table is empty or does not end in a newline (a cut read).
    #[error("the mount table is empty or cut short")]
    Unterminated,
    /// No line has the mount id.
    #[error("the mount table has no entry for the mount")]
    NoEntry,
    /// More than one line has the mount id.
    #[error("the mount table has more than one entry for the mount")]
    Duplicate,
    /// The line with the mount id has no separator, no type, or a type that is not text.
    #[error("the mount table's entry for the mount is malformed")]
    Malformed,
}

/// The type part of the filesystem type on the one line of `table` whose first field is
/// `mnt_id`: the text before the first `.` (the table writes FUSE filesystems `fuse.<subtype>`).
///
/// The id is matched by bytes against its decimal form, so `13` never matches `135` or `013`,
/// nor a line whose parent is 13. The type is the field after the first `-` field past the six
/// fixed ones. Every line is read, so a second line with the id is an error.
///
/// # Errors
/// [`MountInfoError`]: a table that is empty or does not end in a newline, no line or more than
/// one line with the id, or a matching line with no separator or no type.
pub fn mount_fs_type(table: &[u8], mnt_id: u64) -> Result<&str, MountInfoError> {
    if table.last() != Some(&b'\n') {
        return Err(MountInfoError::Unterminated);
    }
    let id = mnt_id.to_string();
    let mut found = None;
    for line in table.split(|&b| b == b'\n') {
        let mut fields = line.split(|&b| b == b' ');
        if fields.next() != Some(id.as_bytes()) {
            continue;
        }
        if found.is_some() {
            return Err(MountInfoError::Duplicate);
        }
        found = Some(type_part(fields)?);
    }
    found.ok_or(MountInfoError::NoEntry)
}

/// The fixed fields after the id: parent, `major:minor`, root, mount point, options.
const FIXED_AFTER_ID: usize = 5;

/// The type part of a line's fields after its id: past the fixed fields, the field after the
/// first `-`, up to its first `.`, non-empty text.
fn type_part<'a>(mut fields: impl Iterator<Item = &'a [u8]>) -> Result<&'a str, MountInfoError> {
    for _ in 0..FIXED_AFTER_ID {
        fields.next().ok_or(MountInfoError::Malformed)?;
    }
    fields
        .find(|f| *f == b"-")
        .ok_or(MountInfoError::Malformed)?;
    let ty = fields.next().ok_or(MountInfoError::Malformed)?;
    let part = ty.split(|&b| b == b'.').next().unwrap_or_default();
    match std::str::from_utf8(part) {
        Ok(s) if !s.is_empty() => Ok(s),
        _ => Err(MountInfoError::Malformed),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    /// A made-up table line: `id parent 0:1 / <point> rw,relatime <optional> - <ty> none rw`.
    fn line(id: &str, parent: &str, point: &str, optional: &str, ty: &str) -> String {
        format!("{id} {parent} 0:1 / {point} rw,relatime {optional}- {ty} none rw\n")
    }

    fn table(lines: &[String]) -> Vec<u8> {
        lines.concat().into_bytes()
    }

    #[test]
    fn the_type_of_the_line_with_the_id_is_given() {
        let t = table(&[
            line("21", "1", "/", "shared:1 ", "ext4"),
            line("135", "21", "/mnt/x", "", "9p"),
            line("136", "21", "/mnt/y", "master:2 shared:3 ", "virtiofs"),
        ]);
        assert_eq!(mount_fs_type(&t, 21), Ok("ext4"));
        assert_eq!(mount_fs_type(&t, 135), Ok("9p"));
        assert_eq!(mount_fs_type(&t, 136), Ok("virtiofs"));
    }

    /// The type part is the text before the first `.`: `9p.x` is 9p, `fuse.9p` is fuse.
    #[test]
    fn the_type_part_is_before_the_first_dot() {
        for (ty, part) in [
            ("9p.x", "9p"),
            ("virtiofs.a.b", "virtiofs"),
            ("fuse.9p", "fuse"),
            ("fuse.virtiofs", "fuse"),
            ("fuse.sshfs", "fuse"),
            ("fuseblk", "fuseblk"),
            ("fuse", "fuse"),
        ] {
            let t = table(&[line("7", "1", "/m", "", ty)]);
            assert_eq!(mount_fs_type(&t, 7), Ok(part), "{ty}");
        }
    }

    /// Only the first field is the id, matched as written: not a prefix, not a leading zero,
    /// not the parent.
    #[test]
    fn the_id_is_the_first_field_matched_exactly() {
        let t = table(&[
            line("135", "13", "/a", "", "9p"),
            line("013", "1", "/b", "", "9p"),
            line("+13", "1", "/c", "", "9p"),
            line("1", "13", "/d", "", "9p"),
        ]);
        assert_eq!(mount_fs_type(&t, 13), Err(MountInfoError::NoEntry));
        let t = table(&[
            line("13", "1", "/a", "", "ext4"),
            line("135", "13", "/b", "", "9p"),
        ]);
        assert_eq!(mount_fs_type(&t, 13), Ok("ext4"));
    }

    #[test]
    fn a_second_line_with_the_id_is_an_error() {
        let t = table(&[
            line("5", "1", "/a", "", "ext4"),
            line("6", "1", "/b", "", "ext4"),
            line("5", "1", "/c", "", "ext4"),
        ]);
        assert_eq!(mount_fs_type(&t, 5), Err(MountInfoError::Duplicate));
        assert_eq!(mount_fs_type(&t, 6), Ok("ext4"));
    }

    /// The separator is looked for only past the six fixed fields: a `-` mount point or
    /// option field is not it.
    #[test]
    fn a_dash_among_the_fixed_fields_is_not_the_separator() {
        let t = b"9 1 0:1 - - - shared:1 - tmpfs none rw\n".to_vec();
        assert_eq!(mount_fs_type(&t, 9), Ok("tmpfs"));
        // With only five fixed fields, the `-` at the sixth is a field, and none follows.
        let t = b"9 1 0:1 / - 9p none rw\n".to_vec();
        assert_eq!(mount_fs_type(&t, 9), Err(MountInfoError::Malformed));
    }

    #[test]
    fn a_matching_line_without_a_type_is_malformed() {
        for l in [
            "9 1 0:1 / /m rw shared:1 9p none rw\n", // no separator
            "9 1 0:1 / /m rw -\n",                   // nothing after it
            "9 1 0:1 / /m rw - \n",                  // an empty type
            "9 1 0:1 / /m rw - .x none rw\n",        // an empty type part
            "9 1 0:1 / /m\n",                        // short of the fixed fields
            "9\n",
        ] {
            assert_eq!(
                mount_fs_type(l.as_bytes(), 9),
                Err(MountInfoError::Malformed),
                "{l:?}"
            );
        }
        let t = b"9 1 0:1 / /m rw - \xff none rw\n".to_vec();
        assert_eq!(mount_fs_type(&t, 9), Err(MountInfoError::Malformed));
    }

    /// A malformed line without the id is skipped.
    #[test]
    fn a_malformed_line_of_another_mount_is_ignored() {
        let mut t = b"8 1 0:1 / /x\n\xff\xfe\n\n".to_vec();
        t.extend(table(&[line("9", "1", "/m", "", "ext4")]));
        assert_eq!(mount_fs_type(&t, 9), Ok("ext4"));
    }

    #[test]
    fn an_empty_or_cut_table_is_an_error() {
        assert_eq!(mount_fs_type(b"", 9), Err(MountInfoError::Unterminated));
        let mut t = table(&[line("9", "1", "/m", "", "ext4")]);
        t.pop();
        assert_eq!(mount_fs_type(&t, 9), Err(MountInfoError::Unterminated));
        assert_eq!(mount_fs_type(b"\n", 9), Err(MountInfoError::NoEntry));
    }

    #[test]
    fn the_cap_is_one_mebibyte() {
        assert_eq!(MAX_MOUNT_TABLE, 1_048_576);
    }

    #[test]
    fn the_messages_quote_no_table_bytes() {
        for e in [
            MountInfoError::Unterminated,
            MountInfoError::NoEntry,
            MountInfoError::Duplicate,
            MountInfoError::Malformed,
        ] {
            assert!(e.to_string().starts_with("the mount table"), "{e}");
        }
    }
}
