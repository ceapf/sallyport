//! Guest paths of the file tools (ARCHITECTURE §4.3; architect rulings Q35 and Q38). Pure: a
//! harness path and the mounts' guest roots in, the mount and the canonical relative path out.
//! This only names the target; the file system is reached through `fs.rs` (openat2 beneath the
//! mount's pinned root, SI-8), never through a string check.
//!
//! A path is absolute; `.` and empty segments are dropped; any `..` segment, a relative path and
//! a path under no mount escape the mount (`path_escapes_mount`, RT-FS-04 spelling). Control
//! bytes and paths longer than [`MAX_PATH`] are `bad-path`. A `.git` component, in any ASCII case,
//! is a protected path for writes and deletes (#19; MANIFEST_SPEC Mount "Git metadata").

use crate::approvals::glob;

/// Longest path accepted, in bytes (the glob matcher's bound).
pub const MAX_PATH: usize = glob::MAX_PATH;

/// Why a path names no target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum PathError {
    /// Outside every mount: relative, `..`, under no mount, or a symlink or mount crossing met
    /// during resolution.
    Escapes,
    /// Not a path a tool takes: control bytes, too long, or the mount root where a file is
    /// needed.
    Bad,
}

impl PathError {
    /// The `denied: <code>` text.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Escapes => "path_escapes_mount",
            Self::Bad => "bad-path",
        }
    }
}

/// A path on a mount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Located {
    /// Index of the mount (in the order given).
    pub mount: usize,
    /// Canonical path relative to the mount root: no leading `/`, no `.`, `..` or empty
    /// segment; empty for the root itself.
    pub rel: String,
}

/// Locates `path` on the mount whose guest root is its longest prefix at a segment boundary.
/// `root_ok`: whether the mount root itself is a target (`fs_list`).
///
/// # Errors
/// [`PathError`].
pub fn locate<S: AsRef<str>>(
    guests: &[S],
    path: &str,
    root_ok: bool,
) -> Result<Located, PathError> {
    if path.len() > MAX_PATH || path.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(PathError::Bad);
    }
    if !path.starts_with('/') {
        return Err(PathError::Escapes);
    }
    let segs: Vec<&str> = segments(path).collect();
    if segs.contains(&"..") {
        return Err(PathError::Escapes);
    }
    let mut best: Option<(usize, usize)> = None;
    for (i, g) in guests.iter().enumerate() {
        let root: Vec<&str> = segments(g.as_ref()).collect();
        let longer = best.is_none_or(|(_, n)| root.len() > n);
        if !root.is_empty() && segs.starts_with(&root) && longer {
            best = Some((i, root.len()));
        }
    }
    let (mount, depth) = best.ok_or(PathError::Escapes)?;
    let rel = segs.get(depth..).unwrap_or_default().join("/");
    if rel.is_empty() && !root_ok {
        return Err(PathError::Bad);
    }
    Ok(Located { mount, rel })
}

/// The non-empty segments of `p` other than `.`.
fn segments(p: &str) -> impl Iterator<Item = &str> {
    p.split('/').filter(|s| !s.is_empty() && *s != ".")
}

/// Whether `rel` has a `.git` component in any ASCII case: writes and deletes there are refused
/// in every mode (#19).
#[must_use]
pub fn protected(rel: &str) -> bool {
    rel.split('/').any(|s| s.eq_ignore_ascii_case(".git"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const GUESTS: [&str; 3] = ["/workspace/notes", "/workspace/p", "/workspace/p2"];

    fn at(path: &str) -> Result<(usize, String), PathError> {
        locate(&GUESTS, path, false).map(|l| (l.mount, l.rel))
    }

    #[test]
    fn a_path_names_its_mount_and_canonical_rel() {
        assert_eq!(at("/workspace/notes/a.md"), Ok((0, "a.md".into())));
        assert_eq!(at("/workspace/p/d/e"), Ok((1, "d/e".into())));
        assert_eq!(at("/workspace/p2/x"), Ok((2, "x".into())));
        // `.` and empty segments are dropped.
        assert_eq!(at("//workspace/./p//d/./e/"), Ok((1, "d/e".into())));
        assert_eq!(at("/workspace/notes/.hidden"), Ok((0, ".hidden".into())));
        assert_eq!(at("/workspace/notes/a..b"), Ok((0, "a..b".into())));
        assert_eq!(at("/workspace/notes/é"), Ok((0, "é".into())));
    }

    #[test]
    fn rt_fs_04_traversal_and_paths_outside_every_mount_escape() {
        for p in [
            "../../../etc/passwd",
            "/workspace/notes/../../.bashrc",
            "/workspace/notes/a/../b",
            "/workspace/notes/..",
            "notes/a.md",
            "",
            "/",
            "/etc/passwd",
            "/workspace",
            "/workspace/note",
            "/workspace/notesx/a",
            "/workspace/p3/a",
        ] {
            assert_eq!(at(p), Err(PathError::Escapes), "{p:?}");
        }
    }

    #[test]
    fn the_mount_root_is_a_target_only_where_allowed() {
        for p in ["/workspace/p", "/workspace/p/", "/workspace/p/."] {
            assert_eq!(at(p), Err(PathError::Bad), "{p}");
            let l = locate(&GUESTS, p, true).unwrap();
            assert_eq!((l.mount, l.rel.as_str()), (1, ""));
        }
    }

    #[test]
    fn the_longest_guest_root_wins() {
        let nested = ["/workspace/a", "/workspace/a/b"];
        let l = locate(&nested, "/workspace/a/b/c", false).unwrap();
        assert_eq!((l.mount, l.rel.as_str()), (1, "c"));
        let l = locate(
            &["/workspace/a/b", "/workspace/a"],
            "/workspace/a/b/c",
            false,
        )
        .unwrap();
        assert_eq!((l.mount, l.rel.as_str()), (0, "c"));
        let l = locate(&nested, "/workspace/a/bc", false).unwrap();
        assert_eq!((l.mount, l.rel.as_str()), (0, "bc"));
        // A guest root with no segment matches nothing.
        assert_eq!(locate(&["/"], "/a", false), Err(PathError::Escapes));
        // Only a strictly longer root replaces a match: of equal ones the first stays.
        let twice = ["/workspace/a", "//workspace/a/"];
        assert_eq!(locate(&twice, "/workspace/a/c", false).unwrap().mount, 0);
    }

    #[test]
    fn control_bytes_and_overlong_paths_are_bad() {
        for p in [
            "/workspace/p/a\nb",
            "/workspace/p/a\0b",
            "/workspace/p/\x1b[2J",
            "/workspace/p/a\x7f",
            "../\t",
        ] {
            assert_eq!(at(p), Err(PathError::Bad), "{p:?}");
        }
        let head = "/workspace/p/";
        // A space is the first byte past the control range.
        assert!(at("/workspace/p/a b").is_ok());
        let at_bound = format!("{head}{}", "a".repeat(MAX_PATH - head.len()));
        assert!(at(&at_bound).is_ok());
        let over = format!("{at_bound}a");
        assert_eq!(at(&over), Err(PathError::Bad));
    }

    #[test]
    fn codes_are_the_wire_spellings() {
        assert_eq!(PathError::Escapes.code(), "path_escapes_mount");
        assert_eq!(PathError::Bad.code(), "bad-path");
        assert_eq!(PathError::Escapes.to_string(), "path_escapes_mount");
    }

    #[test]
    fn git_components_are_protected_in_any_ascii_case() {
        for rel in [
            ".git",
            ".git/hooks/pre-commit",
            "sub/.git/config",
            "a/.GIT",
            ".Git/x",
        ] {
            assert!(protected(rel), "{rel}");
        }
        for rel in [
            "",
            "a.git",
            ".gitignore",
            "git/x",
            ".git_x/y",
            "x.git/y",
            ".gi",
        ] {
            assert!(!protected(rel), "{rel}");
        }
    }
}
