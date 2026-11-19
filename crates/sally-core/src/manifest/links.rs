//! Links out of protected folders (MANIFEST_SPEC §2): the bounded read that finds them.
//!
//! A symlink inside a folder the host runs or loads code from (`~/.local/bin/t ->
//! ~/dotfiles/bin/t`) makes its target part of what the host runs, so the denylist protects the
//! target too. This module only finds the links: it reads a folder's entries to a fixed depth,
//! never entering a linked folder, and counts every entry it reads against one budget per
//! validation. What becomes a rule is the denylist's decision (`paths.rs`).
#![deny(clippy::indexing_slicing)]

use std::collections::HashMap;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

/// Directory entries read per validation, across every folder scanned.
pub(crate) const BUDGET: usize = 65_536;

/// How deep a protected folder is read: its entries, and its subfolders' entries.
pub(crate) const DEPTH: usize = 2;

/// A symlink found in a scanned folder, and where it points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Link {
    /// The link itself.
    pub(crate) link: PathBuf,
    /// Its target as the kernel reads it: the link text, joined, when relative, to the real
    /// path of the folder holding the link, and not normalized (a `..` after a linked
    /// component must resolve physically). The denylist matches its normalized form and,
    /// when it resolves, its canonical form.
    pub(crate) target: PathBuf,
    /// The reason of the rule whose folder holds the link.
    pub(crate) reason: &'static str,
}

/// Why the scan could not finish; the denylist is then incomplete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Incomplete {
    /// The budget ran out while reading `folder`.
    Budget {
        /// The folder being read when the last entry was counted.
        folder: PathBuf,
    },
    /// `folder`, or an entry in it, could not be read for a reason other than its absence or
    /// the user's own lack of access.
    Unreadable {
        /// The folder being read.
        folder: PathBuf,
        /// The error, as the OS gave it.
        error: String,
    },
}

/// One validation's scan: what is left of the budget, the folders read (real path, and the
/// depth they were read to), and the links found.
#[derive(Debug)]
pub(crate) struct Scan {
    left: usize,
    seen: HashMap<PathBuf, usize>,
    links: Vec<Link>,
}

/// Whether an I/O error means "nothing there to load" (gone, not a folder, or not readable by
/// the user, whose tools then cannot load it either) rather than a failed read.
fn absent(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::NotFound | ErrorKind::NotADirectory | ErrorKind::PermissionDenied
    )
}

/// One read's result while reading `dir`: the value, `None` when the error is [`absent`] (skip
/// it), or [`Incomplete::Unreadable`] naming `dir` for any other error. Every read of the scan
/// goes through here, so the classification is decided, and tested, in one place.
fn settle<T>(read: std::io::Result<T>, dir: &Path) -> Result<Option<T>, Incomplete> {
    match read {
        Ok(v) => Ok(Some(v)),
        Err(e) if absent(e.kind()) => Ok(None),
        Err(e) => Err(Incomplete::Unreadable {
            folder: dir.to_owned(),
            error: e.to_string(),
        }),
    }
}

impl Scan {
    /// A scan with `budget` entries to read.
    pub(crate) fn with_budget(budget: usize) -> Self {
        Self {
            left: budget,
            seen: HashMap::new(),
            links: Vec::new(),
        }
    }

    /// Reads `dir`'s entries to `depth` levels (1: its entries only) and records every symlink
    /// among them with `reason`. A folder already read to at least `depth` (under any spelling)
    /// is skipped; a linked folder is recorded, never entered.
    ///
    /// # Errors
    /// [`Incomplete`]: the budget ran out, or a read failed other than by [`absent`]. The links
    /// found before that are kept.
    pub(crate) fn read(
        &mut self,
        dir: &Path,
        depth: usize,
        reason: &'static str,
    ) -> Result<(), Incomplete> {
        self.walk(dir, depth, reason, |_| true)
    }

    /// Reads only `home`'s own entries and records the symlinks whose names start with `.`
    /// (dotfiles, which shells and tools load). Every entry read counts. Called after every
    /// [`Scan::read`]: a home already read whole is not read again for its dotfiles.
    ///
    /// # Errors
    /// As [`Scan::read`].
    pub(crate) fn read_dotfiles(
        &mut self,
        home: &Path,
        reason: &'static str,
    ) -> Result<(), Incomplete> {
        self.walk(home, 1, reason, |name| {
            name.as_encoded_bytes().starts_with(b".")
        })
    }

    fn walk(
        &mut self,
        dir: &Path,
        depth: usize,
        reason: &'static str,
        keep: fn(&std::ffi::OsStr) -> bool,
    ) -> Result<(), Incomplete> {
        if depth == 0 {
            return Ok(());
        }
        // The real folder: relative link text resolves against it, as the kernel resolves it,
        // and a folder is read again only to a greater depth than before.
        let real = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_owned());
        if self.seen.get(&real).is_some_and(|read| *read >= depth) {
            return Ok(());
        }
        self.seen.insert(real.clone(), depth);
        let Some(entries) = settle(std::fs::read_dir(dir), dir)? else {
            return Ok(());
        };
        for entry in entries {
            self.left = self.left.checked_sub(1).ok_or_else(|| Incomplete::Budget {
                folder: dir.to_owned(),
            })?;
            let Some(entry) = settle(entry, dir)? else {
                continue;
            };
            let Some(kind) = settle(entry.file_type(), dir)? else {
                continue;
            };
            let path = entry.path();
            if kind.is_symlink() {
                if !keep(&entry.file_name()) {
                    continue;
                }
                let Some(text) = settle(std::fs::read_link(&path), dir)? else {
                    continue;
                };
                self.links.push(Link {
                    link: path,
                    target: real.join(text),
                    reason,
                });
            } else if kind.is_dir() {
                self.walk(&real.join(entry.file_name()), depth - 1, reason, keep)?;
            }
        }
        Ok(())
    }

    /// The links found, in the order read.
    pub(crate) fn into_links(self) -> Vec<Link> {
        self.links
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    /// A temp tree, removed on drop. Under the workspace's target dir, not /tmp.
    struct Tree(PathBuf);

    impl Tree {
        fn new(tag: &str) -> Self {
            let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/tmp")
                .join(format!("sp-links-{}-{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).unwrap();
            Self(std::fs::canonicalize(root).unwrap())
        }
        fn dir(&self, rel: &str) -> PathBuf {
            let p = self.0.join(rel);
            std::fs::create_dir_all(&p).unwrap();
            p
        }
        fn file(&self, rel: &str) -> PathBuf {
            let p = self.0.join(rel);
            std::fs::write(&p, "").unwrap();
            p
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const WHY: &str = "test reason";

    fn links(dir: &Path, depth: usize, budget: usize) -> Result<Vec<Link>, Incomplete> {
        let mut s = Scan::with_budget(budget);
        s.read(dir, depth, WHY)?;
        let mut found = s.into_links();
        found.sort_by(|a, b| a.link.cmp(&b.link));
        Ok(found)
    }

    #[test]
    fn links_to_depth_two_are_found_with_their_reason() {
        let t = Tree::new("depth");
        let bin = t.dir("p/bin");
        t.dir("p/one/two");
        let target = t.file("elsewhere");
        symlink(&target, bin.join("t")).unwrap();
        symlink(&target, t.0.join("p/top")).unwrap();
        symlink(&target, t.0.join("p/one/two/deep")).unwrap();
        let found = links(&t.0.join("p"), DEPTH, BUDGET).unwrap();
        let want: Vec<Link> = [bin.join("t"), t.0.join("p/top")]
            .into_iter()
            .map(|link| Link {
                link,
                target: target.clone(),
                reason: WHY,
            })
            .collect();
        assert_eq!(found, want);
        // Depth 1 reads the folder's own entries only.
        let top = links(&t.0.join("p"), 1, BUDGET).unwrap();
        assert_eq!(top.len(), 1, "{top:?}");
        assert_eq!(links(&t.0.join("p"), 0, BUDGET).unwrap(), Vec::new());
    }

    /// Q-I: the target is the link text made absolute, unresolved, even when it resolves
    /// elsewhere (a two-hop chain) or nowhere (a dangling link).
    #[test]
    fn the_target_is_the_link_text_made_absolute() {
        let t = Tree::new("lexical");
        let p = t.dir("p");
        t.dir("hop");
        let last = t.file("last");
        symlink(&last, t.0.join("hop/one")).unwrap();
        symlink("../hop/one", p.join("chain")).unwrap();
        symlink("../gone/x", p.join("rel")).unwrap();
        symlink("/nowhere/abs", p.join("abs")).unwrap();
        let targets: Vec<PathBuf> = links(&p, DEPTH, BUDGET)
            .unwrap()
            .into_iter()
            .map(|l| l.target)
            .collect();
        assert_eq!(
            targets,
            [
                PathBuf::from("/nowhere/abs"),
                p.join("../hop/one"),
                p.join("../gone/x")
            ]
        );
    }

    #[test]
    fn a_linked_folder_is_recorded_not_entered() {
        let t = Tree::new("dirlink");
        let real = t.dir("real");
        symlink(t.file("real/inner"), real.join("inner-link")).unwrap();
        let p = t.dir("p");
        symlink(&real, p.join("d")).unwrap();
        let found = links(&p, DEPTH, BUDGET).unwrap();
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found.first().map(|l| &l.target), Some(&real));
    }

    #[test]
    fn every_entry_counts_and_the_last_folder_is_named() {
        let t = Tree::new("budget");
        let p = t.dir("p");
        let sub = t.dir("p/sub");
        for n in 0..3 {
            t.file(&format!("p/sub/f{n}"));
        }
        // 1 (sub) + 3 inside it = 4 entries.
        assert!(links(&p, DEPTH, 4).is_ok());
        assert_eq!(links(&p, DEPTH, 3), Err(Incomplete::Budget { folder: sub }));
        assert_eq!(links(&p, DEPTH, 0), Err(Incomplete::Budget { folder: p }));
    }

    #[test]
    fn a_folder_is_read_once() {
        let t = Tree::new("once");
        let p = t.dir("p");
        t.file("p/a");
        let mut s = Scan::with_budget(1);
        assert_eq!(s.read(&p, DEPTH, WHY), Ok(()));
        // Read again (also by another spelling of the same folder): nothing counted.
        assert_eq!(s.read(&p, DEPTH, WHY), Ok(()));
        assert_eq!(s.read(&t.0.join("p/../p"), DEPTH, WHY), Ok(()));
    }

    /// A folder first reached as a subfolder (read to depth 1) is read again to depth 2 when it
    /// is a scan root of its own (`$DOCKER_CONFIG=~/.config/docker` after `~/.config`).
    #[test]
    fn a_folder_reached_shallower_is_read_again_deeper() {
        let t = Tree::new("deeper");
        let p = t.dir("p");
        let x = t.dir("p/sub/x");
        symlink(t.file("tgt"), x.join("l")).unwrap();
        let mut s = Scan::with_budget(BUDGET);
        s.read(&p, DEPTH, WHY).unwrap();
        s.read(&p.join("sub"), DEPTH, WHY).unwrap();
        let found: Vec<PathBuf> = s.into_links().into_iter().map(|l| l.link).collect();
        assert_eq!(found, [x.join("l")]);
    }

    /// A relative link text resolves against the folder's real path, as the kernel resolves
    /// it: through a linked folder (`~/.local/bin -> ~/dotfiles/bin`, `t -> ../tools/t`) the
    /// target is `~/dotfiles/tools/t`. The link keeps the spelling it was found under.
    #[test]
    fn a_relative_link_resolves_against_the_real_folder() {
        let t = Tree::new("realdir");
        let real = t.dir("dotfiles/bin");
        symlink("../tools/t", real.join("t")).unwrap();
        t.dir("local");
        symlink(&real, t.0.join("local/bin")).unwrap();
        let found = links(&t.0.join("local/bin"), DEPTH, BUDGET).unwrap();
        assert_eq!(
            found,
            [Link {
                link: t.0.join("local/bin/t"),
                target: real.join("../tools/t"),
                reason: WHY,
            }]
        );
    }

    #[test]
    fn a_missing_or_non_folder_path_reads_nothing() {
        let t = Tree::new("missing");
        let file = t.file("f");
        assert_eq!(links(&t.0.join("absent"), DEPTH, 0), Ok(Vec::new()));
        assert_eq!(links(&file, DEPTH, 0), Ok(Vec::new()));
    }

    /// A read's value passes; an absent one is skipped; any other error stops the scan, naming
    /// the folder and the error.
    #[test]
    fn settle_skips_absence_and_stops_on_other_errors() {
        let dir = Path::new("/d");
        assert_eq!(settle(Ok(7), dir), Ok(Some(7)));
        for k in [ErrorKind::NotFound, ErrorKind::PermissionDenied] {
            assert_eq!(settle::<u8>(Err(k.into()), dir), Ok(None), "{k:?}");
        }
        let e = std::io::Error::other("boom");
        assert_eq!(
            settle::<u8>(Err(e), dir),
            Err(Incomplete::Unreadable {
                folder: dir.to_owned(),
                error: "boom".to_owned(),
            })
        );
    }

    #[test]
    fn absent_means_gone_not_a_folder_or_no_access() {
        for k in [
            ErrorKind::NotFound,
            ErrorKind::NotADirectory,
            ErrorKind::PermissionDenied,
        ] {
            assert!(absent(k), "{k:?}");
        }
        for k in [
            ErrorKind::Other,
            ErrorKind::InvalidData,
            ErrorKind::Interrupted,
        ] {
            assert!(!absent(k), "{k:?}");
        }
    }

    /// Only dot-named links of the home's own entries; nothing below them is read, and every
    /// entry read counts.
    #[test]
    fn home_dotfiles_only() {
        let t = Tree::new("dots");
        let home = t.dir("home");
        let target = t.file("df");
        symlink(&target, home.join(".bashrc")).unwrap();
        symlink(&target, home.join("work")).unwrap();
        let sub = t.dir("home/.tool");
        symlink(&target, sub.join(".inner")).unwrap();
        let mut s = Scan::with_budget(BUDGET);
        s.read_dotfiles(&home, WHY).unwrap();
        let found: Vec<PathBuf> = s.into_links().into_iter().map(|l| l.link).collect();
        assert_eq!(found, [home.join(".bashrc")]);
        let mut s = Scan::with_budget(2);
        assert_eq!(
            s.read_dotfiles(&home, WHY),
            Err(Incomplete::Budget { folder: home })
        );
    }
}
