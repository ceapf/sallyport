//! `filesystem.*` checks.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use super::super::diag::{Code, Diags};
use super::super::hostenv::HostEnv;
use super::super::paths::{self, Denylist, DirId};
use super::super::types::{ApproveGlobs, BuiltinTool, Manifest, MountMode};
use super::ResolvedMount;

const MAX_MOUNTS: usize = 64;
const MAX_GLOBS: usize = 256;
const MAX_GLOB_LEN: usize = 256;

/// Builds the denylist from built-ins plus `filesystem.deny`, reporting malformed entries. With
/// mounts it also reads the protected folders for links (MANIFEST_SPEC §2) and reports a list it
/// could not complete as `denylist-incomplete` at `filesystem`; with none, nothing is checked
/// against it, so no folder is read.
pub(super) fn denylist(m: &Manifest, env: &HostEnv, d: &mut Diags) -> Denylist {
    let extra: Vec<PathBuf> = m
        .filesystem
        .deny
        .iter()
        .enumerate()
        .filter_map(|(i, raw)| match paths::expand(raw, &env.home) {
            Ok(p) => Some(paths::normalize(&p)),
            Err(msg) => {
                d.error(format!("filesystem.deny[{i}]"), Code::InvalidValue, msg);
                None
            }
        })
        .collect();
    if m.filesystem.mounts.is_empty() {
        return Denylist::without_links(env, &extra);
    }
    let (list, incomplete) = Denylist::for_env(env, &extra);
    if let Some(why) = incomplete {
        d.error("filesystem", Code::DenylistIncomplete, why);
    }
    list
}

pub(super) fn check_filesystem(m: &Manifest, env: &HostEnv, d: &mut Diags) -> Vec<ResolvedMount> {
    let deny = denylist(m, env, d);
    let mounts = &m.filesystem.mounts;
    if mounts.len() > MAX_MOUNTS {
        d.error(
            "filesystem.mounts",
            Code::OutOfRange,
            format!("at most {MAX_MOUNTS} mounts"),
        );
        return Vec::new();
    }
    let mut resolved = Vec::with_capacity(mounts.len());
    for (i, mount) in mounts.iter().enumerate() {
        let at = |f: &str| format!("filesystem.mounts[{i}].{f}");
        let host = match paths::check_mount_host(&mount.host, &env.home, &deny) {
            Ok((real, _)) if mount.mode != MountMode::Ro && in_git_metadata(&real) => {
                d.error(
                    at("host"),
                    Code::ProtectedPath,
                    format!(
                        "{:?} is inside git metadata, which your host runs (hooks, config); \
                         mount the project directory instead, or use mode: ro",
                        mount.host
                    ),
                );
                None
            }
            Ok((real, id)) => match chain_of(&mount.host, &real, id) {
                Ok(chain) => Some((real, id, chain)),
                Err((code, msg)) => {
                    d.error(at("host"), code, msg);
                    None
                }
            },
            Err((code, msg)) => {
                d.error(at("host"), code, msg);
                None
            }
        };
        if let Err(msg) = paths::check_guest(&mount.guest) {
            d.error(at("guest"), Code::GuestPath, msg);
        }
        let approve = check_approve(m, mount.mode, mount.approve.as_ref(), &at("approve"), d);
        if let Some((host, id, chain)) = host {
            resolved.push((
                i,
                ResolvedMount {
                    host,
                    guest: mount.guest.clone(),
                    mode: mount.mode,
                    approve,
                    id,
                },
                chain,
            ));
        }
    }
    check_overlaps(m, &resolved, d);
    resolved.into_iter().map(|(_, r, _)| r).collect()
}

/// The identity chain of a checked mount root, failing closed: a walk that fails refuses the
/// mount, and so does a chain that does not start at the identity the root's check saw (the
/// folder was swapped in between).
fn chain_of(raw: &str, real: &Path, id: DirId) -> Result<Vec<DirId>, (Code, String)> {
    let chain = paths::identity_chain(real)
        .map_err(|e| (Code::NotFound, format!("{raw:?} cannot be inspected: {e}")))?;
    if chain.first() != Some(&id) {
        return Err((
            Code::MountChanged,
            format!("{raw:?} was replaced by a different directory during validation"),
        ));
    }
    Ok(chain)
}

fn check_approve(
    m: &Manifest,
    mode: MountMode,
    approve: Option<&ApproveGlobs>,
    path: &str,
    d: &mut Diags,
) -> ApproveGlobs {
    match (mode, approve) {
        // Omission never disables a gate (SI-5): no globs = everything needs approval.
        (MountMode::Brokered, None) => ApproveGlobs::everything(),
        (MountMode::Brokered, Some(globs)) => {
            let ops = [
                ("writes", &globs.writes, BuiltinTool::FsWrite),
                ("deletes", &globs.deletes, BuiltinTool::FsDelete),
            ];
            for (kind, list, tool) in ops {
                check_glob_list(&format!("{path}.{kind}"), list, d);
                if list.is_empty() && m.tools.builtin.contains(&tool) {
                    d.warn(
                        format!("{path}.{kind}"),
                        Code::Risky,
                        format!("empty: {} here runs without approval", tool.as_str()),
                    );
                }
            }
            globs.clone()
        }
        (MountMode::Ro | MountMode::Rw | MountMode::Staged, Some(_)) => {
            d.warn(
                path,
                Code::Inconsistent,
                "approve is ignored unless mode is brokered",
            );
            ApproveGlobs::not_applicable()
        }
        (MountMode::Ro | MountMode::Rw | MountMode::Staged, None) => ApproveGlobs::not_applicable(),
    }
}

fn check_glob_list(path: &str, list: &[String], d: &mut Diags) {
    if list.len() > MAX_GLOBS {
        d.error(path, Code::OutOfRange, format!("at most {MAX_GLOBS} globs"));
    }
    for (j, g) in list.iter().enumerate() {
        if let Err(e) = check_glob(g) {
            let msg = e.to_string();
            d.error(format!("{path}[{j}]"), Code::InvalidValue, msg);
        }
    }
}

/// Git metadata: a realpath with a `.git` component, or a root that is (or is inside) a git
/// directory by structure — bare repos (`proj.git`) and separate git dirs (`--separate-git-dir`,
/// dotfile repos). Writable access there is host code execution (hooks, `core.fsmonitor`), and
/// the in-mount protected-path overlays (`.git/hooks/**`, `.git/config`, AMENDMENTS §6.3) would
/// not match from inside it. Performs a few `lstat`s per ancestor.
fn in_git_metadata(real: &Path) -> bool {
    real.components().any(|c| c.as_os_str() == ".git") || real.ancestors().any(is_git_dir)
}

/// `HEAD` file + `objects/` + `refs/` directories: what git itself checks for a git dir.
fn is_git_dir(dir: &Path) -> bool {
    let kind = |name: &str| std::fs::symlink_metadata(dir.join(name)).ok();
    kind("HEAD").is_some_and(|m| m.is_file())
        && kind("objects").is_some_and(|m| m.is_dir())
        && kind("refs").is_some_and(|m| m.is_dir())
}

/// The syntax of an `approve` glob (MANIFEST_SPEC §1 Mount, "Glob syntax"; architect ruling
/// Q20): relative to the mount root, never climbing out of it, and only `*`, `?` and whole-segment
/// `**` as wildcards. Anything a user could read as another wildcard (classes, braces, escapes,
/// negation) or as a directory shorthand (empty or `.` segments, a trailing `/`) is refused: the
/// matcher would take it literally and silently ask less than the user meant. The broker's matcher
/// uses this same check and treats a glob it refuses as `**`.
///
/// # Errors
/// What is wrong with `g`, for the diagnostic.
pub fn check_glob(g: &str) -> Result<(), GlobError> {
    let own = || g.to_owned();
    if g.is_empty() || g.len() > MAX_GLOB_LEN {
        return Err(GlobError::Length);
    }
    if g.starts_with('/') {
        return Err(GlobError::Absolute(own()));
    }
    if g.chars().any(char::is_control) {
        return Err(GlobError::Control(own()));
    }
    if g.ends_with('/') {
        return Err(GlobError::TrailingSlash(own()));
    }
    if let Some(c) = g
        .chars()
        .find(|c| matches!(c, '[' | ']' | '{' | '}' | '\\'))
    {
        return Err(GlobError::Metachar(own(), c));
    }
    if g.starts_with('!') {
        return Err(GlobError::Negated(own()));
    }
    for s in g.split('/') {
        match s {
            ".." => return Err(GlobError::Parent(own())),
            "" | "." => return Err(GlobError::EmptySegment(own())),
            "**" => {}
            _ if s.contains("**") => return Err(GlobError::PartialDoubleStar(own())),
            _ => {}
        }
    }
    Ok(())
}

/// Why an `approve` glob is refused ([`check_glob`]).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GlobError {
    /// Empty or longer than the limit.
    #[error("glob must be 1 to {} bytes", MAX_GLOB_LEN)]
    Length,
    /// Starts with `/`.
    #[error("{0:?} must be relative to the mount")]
    Absolute(String),
    /// Contains a control character.
    #[error("{0:?} contains a control character")]
    Control(String),
    /// Ends with `/`.
    #[error("{0:?} ends with \"/\"; use \"dir/**\" for a directory")]
    TrailingSlash(String),
    /// Contains a character other glob dialects treat as syntax.
    #[error("{0:?} contains {1:?}; only *, ? and ** are wildcards")]
    Metachar(String, char),
    /// Starts with `!`.
    #[error("{0:?} starts with \"!\"; globs cannot be negated")]
    Negated(String),
    /// Has a `..` segment.
    #[error("{0:?} contains \"..\"")]
    Parent(String),
    /// Has an empty or `.` segment.
    #[error("{0:?} contains an empty or \".\" segment")]
    EmptySegment(String),
    /// Has `**` inside a longer segment, where it would match within one segment only.
    #[error("{0:?} has \"**\" inside a segment; it must be a whole segment, as in \"**/*.md\"")]
    PartialDoubleStar(String),
}

/// Guests must be unique and non-nested (a nested mount shadows part of another). Hosts must not
/// overlap, by path or by directory identity: a `rw` mount of a parent would bypass a `brokered`
/// child's approvals, and two views of one directory with different modes are never what the
/// user meant.
///
/// A guest that failed its own check (it already has that error) takes no part in the guest
/// checks, and the host-overlap error names the other mount by index, never by its guest: a
/// diagnostic about one field never echoes another field's unchecked value (Q376, Q395).
///
/// TODO(#241): a hard-linked file shared by a `rw` mount and a `brokered` mount is one inode
/// under two unrelated folders, which neither test sees; a write through the `rw` name is not
/// approved.
fn check_overlaps(m: &Manifest, resolved: &[(usize, ResolvedMount, Vec<DirId>)], d: &mut Diags) {
    let checked = |guest: &str| paths::check_guest(guest).is_ok();
    // TODO(#195): a guest that passed its check and a host realpath both hold `/`, so a quoted
    // one is not masked. Only a realpath can hold a `"` or a backtick: a `"` in one (written
    // `\"`) re-pairs `mask_quoted`'s spans, after which a backtick can open one too, so a part of
    // either realpath can still be judged, and masked, on its own.
    let mounts = &m.filesystem.mounts;
    let mut seen_guest = HashSet::new();
    for (i, a) in mounts.iter().enumerate() {
        if !checked(&a.guest) {
            continue;
        }
        if !seen_guest.insert(a.guest.as_str()) {
            d.error(
                format!("filesystem.mounts[{i}].guest"),
                Code::Duplicate,
                format!("{:?} is used twice", a.guest),
            );
            continue;
        }
        let nested = mounts.iter().take(i).find(|b| {
            b.guest != a.guest
                && paths::overlaps(
                    std::path::Path::new(&a.guest),
                    std::path::Path::new(&b.guest),
                )
                && checked(&b.guest)
        });
        if let Some(b) = nested {
            d.error(
                format!("filesystem.mounts[{i}].guest"),
                Code::Overlap,
                format!("{:?} is nested with {:?}", a.guest, b.guest),
            );
        }
    }
    let roots: Vec<Root<'_>> = resolved
        .iter()
        .map(|(index, r, chain)| Root {
            index: *index,
            host: &r.host,
            chain,
        })
        .collect();
    check_host_overlaps(&roots, d);
}

/// A checked mount root as the host-overlap check sees it: its index in the manifest, its
/// realpath and its identity chain ([`paths::identity_chain`]).
struct Root<'a> {
    index: usize,
    host: &'a Path,
    chain: &'a [DirId],
}

/// How two mount roots overlap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Overlap {
    /// One realpath is at or under the other.
    Path,
    /// The paths are unrelated, but one root's identity is in the other's chain: a bind alias or
    /// a second mount of one folder, or of a folder that contains the other.
    Identity,
}

/// Whether `a` overlaps `b`, by path first, else by identity.
fn overlap(a: &Root<'_>, b: &Root<'_>) -> Option<Overlap> {
    if paths::overlaps(a.host, b.host) {
        return Some(Overlap::Path);
    }
    let holds = |x: &Root<'_>, y: &Root<'_>| x.chain.first().is_some_and(|r| y.chain.contains(r));
    (holds(a, b) || holds(b, a)).then_some(Overlap::Identity)
}

/// Each root that overlaps an earlier one is refused `overlap` at its own `host`, naming the
/// first such earlier root by index: one error per mount, whatever the modes.
fn check_host_overlaps(roots: &[Root<'_>], d: &mut Diags) {
    for (n, a) in roots.iter().enumerate() {
        let mut earlier = roots.iter().take(n);
        if let Some((b, kind)) = earlier.find_map(|b| Some((b, overlap(a, b)?))) {
            d.error(
                format!("filesystem.mounts[{}].host", a.index),
                Code::Overlap,
                overlap_message(a.host, b.host, b.index, kind),
            );
        }
    }
}

/// The host-overlap message: it names the other mount by its index `j`, never by its guest. An
/// overlap seen only by identity says why two unrelated paths overlap.
fn overlap_message(host: &Path, other: &Path, j: usize, kind: Overlap) -> String {
    let why = match kind {
        Overlap::Path => "",
        Overlap::Identity => {
            ": the two paths reach the same directory (a bind mount, or a second mount of one \
             filesystem)"
        }
    };
    format!(
        "{:?} overlaps {:?} (filesystem.mounts[{j}]){why}",
        host.display().to_string(),
        other.display().to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pinned on short paths: through the validator, a long checkout path can push the index
    /// past the diagnostic cut.
    #[test]
    fn a_host_overlap_names_the_other_mount_by_index() {
        assert_eq!(
            overlap_message(Path::new("/h/a/b"), Path::new("/h/a"), 3, Overlap::Path),
            "\"/h/a/b\" overlaps \"/h/a\" (filesystem.mounts[3])"
        );
    }

    /// An overlap seen only by identity says why two unrelated paths overlap, quoting only the
    /// two realpaths and the index.
    #[test]
    fn an_identity_overlap_says_the_paths_reach_one_directory() {
        assert_eq!(
            overlap_message(Path::new("/h/m"), Path::new("/h/p/d"), 0, Overlap::Identity),
            "\"/h/m\" overlaps \"/h/p/d\" (filesystem.mounts[0]): the two paths reach the same \
             directory (a bind mount, or a second mount of one filesystem)"
        );
    }

    const fn id(ino: u64) -> DirId {
        DirId { dev: 7, ino }
    }

    fn root<'a>(index: usize, host: &'a str, chain: &'a [DirId]) -> Root<'a> {
        Root {
            index,
            host: Path::new(host),
            chain,
        }
    }

    /// The chains below: `/` = 1, `/h` = 2, `/h/p` = 3, `/h/p/d` = 4, `/h/q` = 5; `/h/m` is a
    /// bind alias of `/h/p`, so its chain starts with 3 and climbs its own path.
    const P: [DirId; 3] = [id(3), id(2), id(1)];
    const D: [DirId; 4] = [id(4), id(3), id(2), id(1)];
    const Q: [DirId; 3] = [id(5), id(2), id(1)];
    const M: [DirId; 3] = [id(3), id(2), id(1)];
    const M_D: [DirId; 4] = [id(4), id(3), id(2), id(1)];

    #[test]
    fn mounts_overlap_by_identity_whatever_their_paths() {
        // The same folder under two paths.
        let (p, m) = (root(0, "/h/p", &P), root(1, "/h/m", &M));
        assert_eq!(overlap(&m, &p), Some(Overlap::Identity));
        // The alias holds a brokered folder's parent: its root is in the child's chain.
        let d = root(1, "/h/p/d", &D);
        assert_eq!(overlap(&m, &d), Some(Overlap::Identity));
        assert_eq!(overlap(&d, &m), Some(Overlap::Identity));
        // A folder reached through the alias, beside the real parent.
        let md = root(1, "/h/m/d", &M_D);
        assert_eq!(overlap(&md, &p), Some(Overlap::Identity));
        assert_eq!(overlap(&p, &md), Some(Overlap::Identity));
    }

    #[test]
    fn siblings_and_unknown_chains_do_not_overlap() {
        // Siblings share only ancestors.
        assert_eq!(overlap(&root(0, "/h/p", &P), &root(1, "/h/q", &Q)), None);
        assert_eq!(overlap(&root(0, "/h/q", &Q), &root(1, "/h/m", &M)), None);
        // Empty chains decide nothing on their own.
        assert_eq!(overlap(&root(0, "/h/p", &[]), &root(1, "/h/q", &[])), None);
        assert_eq!(overlap(&root(0, "/h/p", &[]), &root(1, "/h/q", &Q)), None);
        assert_eq!(overlap(&root(0, "/h/p", &P), &root(1, "/h/q", &[])), None);
    }

    /// A path overlap stays a path overlap (and keeps its message) when identity agrees.
    #[test]
    fn a_path_overlap_is_reported_as_a_path_overlap() {
        assert_eq!(
            overlap(&root(1, "/h/p/d", &D), &root(0, "/h/p", &P)),
            Some(Overlap::Path)
        );
        assert_eq!(
            overlap(&root(1, "/h/p/d", &[]), &root(0, "/h/p", &[])),
            Some(Overlap::Path)
        );
    }

    fn errors(roots: &[Root<'_>]) -> Vec<(String, Code, String)> {
        let mut d = Diags::default();
        check_host_overlaps(roots, &mut d);
        match d.finish() {
            Ok(_) => Vec::new(),
            Err(r) => r
                .errors
                .into_iter()
                .map(|e| (e.path, e.code, e.message))
                .collect(),
        }
    }

    #[test]
    fn the_later_mount_of_an_identity_overlap_is_refused_naming_the_earlier_by_index() {
        let got = errors(&[
            root(0, "/h/q", &Q),
            root(1, "/h/m", &M),
            root(2, "/h/p/d", &D),
        ]);
        assert_eq!(
            got,
            vec![(
                "filesystem.mounts[2].host".to_owned(),
                Code::Overlap,
                overlap_message(Path::new("/h/p/d"), Path::new("/h/m"), 1, Overlap::Identity),
            )]
        );
        let got = errors(&[root(0, "/h/p/d", &D), root(3, "/h/p", &P)]);
        assert_eq!(
            got,
            vec![(
                "filesystem.mounts[3].host".to_owned(),
                Code::Overlap,
                overlap_message(Path::new("/h/p"), Path::new("/h/p/d"), 0, Overlap::Path),
            )]
        );
        assert_eq!(errors(&[root(0, "/h/p", &P), root(1, "/h/q", &Q)]), vec![]);
    }

    /// One diagnostic per mount: the first earlier mount it overlaps, by either test.
    #[test]
    fn a_mount_overlapping_several_earlier_ones_gets_one_error() {
        let got = errors(&[
            root(0, "/h/p", &P),
            root(1, "/h/q", &Q),
            root(2, "/h/m", &M),
        ]);
        assert_eq!(got.len(), 1, "{got:?}");
        let got = errors(&[
            root(0, "/h/p", &P),
            root(1, "/h/m", &M),
            root(2, "/h/p/d", &D),
        ]);
        assert_eq!(
            got.iter().map(|e| e.0.as_str()).collect::<Vec<_>>(),
            ["filesystem.mounts[1].host", "filesystem.mounts[2].host"]
        );
        assert!(got[1].2.ends_with("(filesystem.mounts[0])"), "{got:?}");
    }

    /// The chain of a checked root starts at the identity its check saw; a walk that fails, or
    /// a chain that starts elsewhere (the root was swapped in between), refuses the mount.
    #[test]
    fn a_root_chain_fails_closed() {
        use std::os::unix::fs::MetadataExt;
        let base = std::env::temp_dir().join(format!("sp-core-root-chain-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("d")).unwrap();
        let meta = std::fs::metadata(base.join("d")).unwrap();
        let real = DirId {
            dev: meta.dev(),
            ino: meta.ino(),
        };
        let other = DirId {
            dev: meta.dev(),
            ino: meta.ino() ^ 1,
        };
        let good = chain_of("~/d", &base.join("d"), real);
        let swapped = chain_of("~/d", &base.join("d"), other);
        let gone = chain_of("~/gone", &base.join("gone"), real);
        std::fs::remove_dir_all(&base).unwrap();
        let good = good.unwrap();
        assert_eq!(good.first(), Some(&real));
        assert!(good.len() >= 2, "{good:?}");
        let (code, msg) = swapped.unwrap_err();
        assert_eq!(code, Code::MountChanged);
        assert!(msg.starts_with("\"~/d\" "), "{msg}");
        let (code, msg) = gone.unwrap_err();
        assert_eq!(code, Code::NotFound);
        assert!(msg.starts_with("\"~/gone\" cannot be inspected: "), "{msg}");
    }
}
