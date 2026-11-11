//! Mount path checks: the built-in denylist (MANIFEST_SPEC §2, SI-7), host-root checks
//! (realpath, is-dir, not-symlink), and guest-path rules.
//!
//! Denylist semantics: a candidate is refused if it equals a rule, is inside a rule, or
//! *contains* a rule (is a strict ancestor of it). Two rules (`/` and `$HOME`) are "root only":
//! the root itself is refused, and their descendants are fine. "Contains" refers to real
//! directory nesting, not symlinks: a symlink inside a mount resolves inside the container's
//! rootfs (RT-FS-03), so `~/code` with `~/code/.ssh -> ~/.ssh` is allowed.
#![deny(clippy::indexing_slicing)]

use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};

use super::diag::Code;
use super::hostenv::HostEnv;

/// Longest accepted host or guest path.
const MAX_PATH_LEN: usize = 4096;

const CREDENTIALS: &str = "credential folders are never mountable";
const CONFIG: &str = "configuration folders are never mountable";
const SALLYPORT: &str = "Sallyport's own state is never mountable";
const EXECUTED: &str = "your host runs or loads code from here, so it is never mountable";
const CACHE: &str = "caches hold tokens and code your tools load, so they are never mountable";
const SYSTEM: &str = "system folders are never mountable";
const SHARED_TMP: &str = "shared temp folders hold other programs' sockets (a network path), so they are never mountable";
const RUNTIME: &str = "the runtime folder holds your session's sockets, so it is never mountable";
const STORAGE: &str = "container storage is never mountable";
const USER_DENY: &str = "listed in filesystem.deny";

/// Under each home directory. Credentials, Sallyport's own state, and anything the host
/// executes or loads on the user's behalf (persistence → host code execution, THREAT_MODEL G4).
const HOME_SUBTREES: &[(&str, &str)] = &[
    (".ssh", CREDENTIALS),
    (".gnupg", CREDENTIALS),
    (".aws", CREDENTIALS),
    (".kube", CREDENTIALS),
    (".docker", CREDENTIALS),
    (".netrc.d", CREDENTIALS),
    (".password-store", CREDENTIALS),
    (".pki", CREDENTIALS),
    (".local/share/keyrings", CREDENTIALS),
    (".mozilla", CREDENTIALS),
    (".claude", CREDENTIALS),
    (".ollama", CREDENTIALS), // holds the Ollama identity key next to models
    (".m2", CREDENTIALS),     // settings.xml
    (".gradle", EXECUTED),    // init.d scripts, gradle.properties credentials
    (".var/app", CONFIG),     // Flatpak app config and data
    ("snap", CONFIG),
    (".config", CONFIG),
    (".local/share/sallyport", SALLYPORT),
    (".cache", CACHE),
    (".npm", CACHE),
    (".local/bin", EXECUTED),
    ("bin", EXECUTED),
    (".local/share/applications", EXECUTED),
    (".cargo", EXECUTED),
    (".rustup", EXECUTED),
    (".vscode-server", EXECUTED),
    (".local/lib", EXECUTED), // user site-packages: .pth files run on every host `python`
    (".nvm", EXECUTED),
    (".pyenv", EXECUTED),
];

/// System paths. `/tmp` and `/var/tmp` hold other programs' Unix sockets (ssh-agent, X11); a
/// read-only bind does not stop `connect()` on a socket, so mounting them is a network path
/// around SI-1.
const SYSTEM_SUBTREES: &[(&str, &str)] = &[
    ("/etc", SYSTEM),
    ("/proc", SYSTEM),
    ("/sys", SYSTEM),
    ("/dev", SYSTEM),
    ("/run", SYSTEM),
    ("/var/run", SYSTEM),
    ("/boot", SYSTEM),
    ("/root", SYSTEM),
    ("/mnt", SYSTEM),
    ("/usr/lib/wsl", SYSTEM),
    ("/tmp", SHARED_TMP),
    ("/var/tmp", SHARED_TMP),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    /// Only the path itself is refused (`/`, `$HOME`).
    RootOnly,
    /// The path, everything under it, and every ancestor of it are refused.
    Subtree,
}

#[derive(Debug, Clone)]
struct Rule {
    /// Lexical form (as configured) and real form (if it exists). Both are checked so a rule
    /// matches whether or not the protected path currently exists.
    forms: Vec<PathBuf>,
    scope: Scope,
    /// User-facing description, e.g. `the home directory root` or `/home/u/.ssh`.
    label: String,
    /// The rule in words, when the path alone does not make it obvious.
    reason: Option<&'static str>,
    /// Identities of the forms that exist (RT-FS-14: a bind alias has the same identity).
    ids: Vec<DirId>,
    /// Subtree rules: identities of the existing real ancestors, each with its path.
    ancestors: Vec<(DirId, PathBuf)>,
}

/// The effective mount denylist for one validation run.
#[derive(Debug, Clone)]
pub(crate) struct Denylist {
    rules: Vec<Rule>,
}

impl Denylist {
    /// Built-in rules for `env`, plus the manifest's `filesystem.deny` entries (already
    /// expanded to absolute paths).
    pub(crate) fn new(env: &HostEnv, extra: &[PathBuf]) -> Self {
        let mut rules = vec![root_rule(Path::new("/"), "the filesystem root")];
        for h in std::iter::once(&env.home).chain(&env.other_homes) {
            rules.push(root_rule(h, "the home directory root"));
            rules.extend(
                HOME_SUBTREES
                    .iter()
                    .map(|(p, why)| subtree_rule(&h.join(p), why)),
            );
        }
        rules.extend(
            SYSTEM_SUBTREES
                .iter()
                .map(|(p, why)| subtree_rule(Path::new(p), why)),
        );
        if let Some(dir) = &env.xdg_runtime_dir {
            rules.push(subtree_rule(dir, RUNTIME));
        }
        for dir in [&env.xdg_config_home, &env.xdg_data_home]
            .into_iter()
            .flatten()
        {
            rules.push(subtree_rule(dir, CONFIG));
        }
        let xdg = [
            &env.xdg_runtime_dir,
            &env.xdg_config_home,
            &env.xdg_data_home,
        ];
        for dir in xdg.into_iter().flatten() {
            rules.push(subtree_rule(&dir.join("sallyport"), SALLYPORT));
        }
        rules.extend(env.podman_storage.iter().map(|p| subtree_rule(p, STORAGE)));
        rules.extend(extra.iter().map(|p| subtree_rule(p, USER_DENY)));
        Self { rules }
    }

    /// Returns a description of why `candidate` (absolute, normalized) is refused, if it is.
    pub(crate) fn refusal(&self, candidate: &Path) -> Option<String> {
        self.rules.iter().find_map(|r| {
            let why = r.reason.map_or_else(String::new, |w| format!(" — {w}"));
            r.forms.iter().find_map(|f| match r.scope {
                Scope::RootOnly if candidate == f => Some(format!("is {}{why}", r.label)),
                Scope::RootOnly => None,
                Scope::Subtree if candidate.starts_with(f) => {
                    Some(format!("is inside {}{why}", r.label))
                }
                Scope::Subtree if f.starts_with(candidate) => {
                    Some(format!("contains {}{why}", r.label))
                }
                Scope::Subtree => None,
            })
        })
    }

    /// Returns why a directory with identity `id` is refused, if it is: it is a rule's
    /// directory, or an ancestor of a subtree rule's, under another path (a bind mount or a
    /// second mount of the same filesystem; RT-FS-14). Aliases of directories *inside* a rule
    /// are not detected (THREAT_MODEL residual M-2).
    pub(crate) fn refusal_by_id(&self, id: DirId) -> Option<String> {
        let why = |r: &Rule| r.reason.map_or_else(String::new, |w| format!(" — {w}"));
        let same = self.rules.iter().find(|r| r.ids.contains(&id));
        if let Some(r) = same {
            return Some(format!("is the same directory as {}{}", r.label, why(r)));
        }
        self.rules.iter().find_map(|r| {
            let (_, a) = r.ancestors.iter().find(|(i, _)| *i == id)?;
            Some(format!(
                "is the same directory as {}, which contains {}{}",
                a.display(),
                r.label,
                why(r)
            ))
        })
    }
}

/// The identity of the directory at `p` (symlinks followed), if it exists.
fn dir_id(p: &Path) -> Option<DirId> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(p).ok().map(|m| DirId {
        dev: m.dev(),
        ino: m.ino(),
    })
}

fn root_rule(p: &Path, label: &str) -> Rule {
    rule(p, Scope::RootOnly, Some(label), None)
}

fn subtree_rule(p: &Path, reason: &'static str) -> Rule {
    rule(p, Scope::Subtree, None, Some(reason))
}

fn rule(p: &Path, scope: Scope, label: Option<&str>, reason: Option<&'static str>) -> Rule {
    let lexical = normalize(p);
    let mut forms = vec![lexical.clone()];
    if let Ok(real) = std::fs::canonicalize(p)
        && real != lexical
    {
        forms.push(real);
    }
    let label = label.map_or_else(|| lexical.display().to_string(), str::to_owned);
    let mut ids: Vec<DirId> = forms.iter().filter_map(|f| dir_id(f)).collect();
    ids.dedup();
    let mut ancestors = Vec::new();
    if scope == Scope::Subtree {
        // Ancestors of every form: the real one where the rule exists, the lexical one (whose
        // ancestors are resolved by `metadata`) where it does not yet.
        for a in forms.iter().flat_map(|f| f.ancestors().skip(1)) {
            if let Some(id) = dir_id(a)
                && !ancestors.iter().any(|(i, _)| *i == id)
            {
                ancestors.push((id, a.to_owned()));
            }
        }
    }
    Rule {
        forms,
        scope,
        label,
        reason,
        ids,
        ancestors,
    }
}

/// Lexical normalization: drops `.`, resolves `..` textually. Used only for the *early*
/// denylist check; the authoritative check runs on the kernel's realpath.
pub(crate) fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other),
        }
    }
    out
}

/// Expands `~` / `~/…` against `home`; requires an absolute result.
pub(crate) fn expand(raw: &str, home: &Path) -> Result<PathBuf, String> {
    if raw.is_empty() {
        return Err("path is empty".into());
    }
    if raw.len() > MAX_PATH_LEN {
        return Err(format!("path is longer than {MAX_PATH_LEN} bytes"));
    }
    if raw.contains('\0') {
        return Err("path contains a NUL byte".into());
    }
    let p = if raw == "~" {
        home.to_path_buf()
    } else if let Some(rest) = raw.strip_prefix("~/") {
        home.join(rest)
    } else if raw.starts_with('~') {
        return Err(format!(
            "{raw:?}: only \"~\" and \"~/…\" are supported, not \"~user\""
        ));
    } else {
        PathBuf::from(raw)
    };
    if p.is_absolute() {
        Ok(p)
    } else {
        Err(format!("{raw:?} must be absolute or start with \"~/\""))
    }
}

/// Characters that would break `podman run -v host:guest:opts` / `--mount k=v,…` parsing.
fn has_separator_char(s: &str) -> bool {
    s.chars().any(|c| c == ':' || c == ',' || c.is_control())
}

/// Identity of a directory: `(st_dev, st_ino)`. Detects a mount root that was replaced by a
/// different directory at the same path between validation and launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DirId {
    pub(crate) dev: u64,
    pub(crate) ino: u64,
}

/// Checks a mount host path and returns its realpath and directory identity.
///
/// Order matters: a lexical denylist check first (so `/mnt/c` is `denylisted` even where it
/// does not exist), then the root's own type via `lstat` (symlink / not-dir / missing), then the
/// authoritative denylist check on the realpath.
pub(crate) fn check_mount_host(
    raw: &str,
    home: &Path,
    deny: &Denylist,
) -> Result<(PathBuf, DirId), (Code, String)> {
    use std::os::unix::fs::MetadataExt;
    let expanded = expand(raw, home).map_err(|m| (Code::InvalidValue, m))?;
    if let Some(why) = deny.refusal(&normalize(&expanded)) {
        return Err((Code::Denylisted, format!("{raw:?} {why} (denylisted)")));
    }
    let meta = std::fs::symlink_metadata(&expanded).map_err(|e| match e.kind() {
        ErrorKind::NotFound => (Code::NotFound, format!("{raw:?} does not exist")),
        _ => (Code::NotFound, format!("{raw:?} cannot be inspected: {e}")),
    })?;
    if meta.file_type().is_symlink() {
        return Err((
            Code::IsSymlink,
            format!("{raw:?} is a symlink; mount its target directly"),
        ));
    }
    if !meta.is_dir() {
        return Err((Code::NotDirectory, format!("{raw:?} is not a directory")));
    }
    let real = std::fs::canonicalize(&expanded)
        .map_err(|e| (Code::NotFound, format!("{raw:?} cannot be resolved: {e}")))?;
    let Some(real_str) = real.to_str() else {
        return Err((
            Code::PathChars,
            format!("{raw:?} resolves to a non-UTF-8 path"),
        ));
    };
    if has_separator_char(real_str) {
        return Err((
            Code::PathChars,
            format!("{real_str:?} contains ':', ',' or a control character"),
        ));
    }
    if let Some(why) = deny.refusal(&real) {
        return Err((
            Code::Denylisted,
            format!("{raw:?} resolves to {real_str:?}, which {why} (denylisted)"),
        ));
    }
    // The root is not a symlink (checked above), so lstat describes the directory itself.
    let id = DirId {
        dev: meta.dev(),
        ino: meta.ino(),
    };
    if let Some(why) = deny.refusal_by_id(id) {
        return Err((Code::Denylisted, format!("{raw:?} {why} (denylisted)")));
    }
    Ok((real, id))
}

/// Guest paths: `/workspace/<seg>(/<seg>)*`, each segment `[A-Za-z0-9._-]`, not `.`/`..`.
pub(crate) fn check_guest(raw: &str) -> Result<(), String> {
    if raw.len() > MAX_PATH_LEN {
        return Err(format!("path is longer than {MAX_PATH_LEN} bytes"));
    }
    let Some(rest) = raw.strip_prefix("/workspace/") else {
        return Err(format!("{raw:?} must be under /workspace/"));
    };
    for seg in rest.split('/') {
        if seg.is_empty() {
            return Err(format!("{raw:?} has an empty segment or trailing '/'"));
        }
        if seg == "." || seg == ".." {
            return Err(format!("{raw:?} contains {seg:?}"));
        }
        if !seg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(format!(
                "{raw:?}: segments may only contain A-Z a-z 0-9 . _ -"
            ));
        }
    }
    Ok(())
}

/// Whether two absolute paths are equal or nested (component-wise).
pub(crate) fn overlaps(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(home: &str) -> HostEnv {
        HostEnv {
            home: home.into(),
            xdg_config_home: None,
            xdg_data_home: None,
            other_homes: Vec::new(),
            xdg_runtime_dir: Some("/run/user/1000".into()),
            podman_storage: vec![format!("{home}/.local/share/containers/storage").into()],
            nproc: 8,
            mem_bytes: 16 << 30,
        }
    }

    #[test]
    fn root_only_rules_allow_descendants() {
        let d = Denylist::new(&env("/home/u"), &[]);
        assert!(d.refusal(Path::new("/")).is_some());
        assert!(d.refusal(Path::new("/home/u")).is_some());
        assert_eq!(d.refusal(Path::new("/home/u/code")), None);
        assert_eq!(d.refusal(Path::new("/opt/data")), None);
    }

    #[test]
    fn subtree_rules_refuse_inside_and_ancestors() {
        let d = Denylist::new(&env("/home/u"), &[]);
        for p in [
            "/home/u/.ssh",
            "/home/u/.ssh/keys",
            "/etc/ssl",
            "/mnt/c",
            "/home/u/.local",
            "/home/u/.local/share",
            "/var",
            "/usr",
            "/home",
        ] {
            assert!(d.refusal(Path::new(p)).is_some(), "{p}");
        }
    }

    #[test]
    fn other_homes_are_protected_too() {
        let mut e = env("/tmp/fakehome");
        e.other_homes.push("/home/user".into());
        let d = Denylist::new(&e, &[]);
        assert!(d.refusal(Path::new("/home/user/.ssh")).is_some());
        assert!(d.refusal(Path::new("/home/user")).is_some());
        assert_eq!(d.refusal(Path::new("/home/user/code")), None);
    }

    #[test]
    fn extra_rules_apply() {
        let d = Denylist::new(&env("/home/u"), &[PathBuf::from("/home/u/private")]);
        assert!(d.refusal(Path::new("/home/u/private/x")).is_some());
        assert_eq!(d.refusal(Path::new("/home/u/public")), None);
    }

    #[test]
    fn expand_tilde_forms() {
        let h = Path::new("/home/u");
        assert_eq!(expand("~", h), Ok(PathBuf::from("/home/u")));
        assert_eq!(expand("~/code", h), Ok(PathBuf::from("/home/u/code")));
        assert!(expand("~root/x", h).is_err());
        assert!(expand("code", h).is_err());
        assert!(expand("", h).is_err());
        assert!(expand("/a\0b", h).is_err());
    }

    #[test]
    fn normalize_resolves_dots_lexically() {
        assert_eq!(
            normalize(Path::new("/home/u/code/../.ssh/./x")),
            PathBuf::from("/home/u/.ssh/x")
        );
        assert_eq!(normalize(Path::new("/../..")), PathBuf::from("/"));
    }

    #[test]
    fn guest_rules() {
        assert!(check_guest("/workspace/proj").is_ok());
        assert!(check_guest("/workspace/a/b-c_d.e").is_ok());
        for bad in [
            "/workspace",
            "/workspace/",
            "/etc",
            "/workspace/../root",
            "/workspace/a//b",
            "/workspace/a/",
            "/workspace/./a",
            "/workspace/a:b",
            "/workspace/a,ro",
            "workspace/a",
            "/workspace/a b",
            "/workspace/ä",
        ] {
            assert!(check_guest(bad).is_err(), "{bad:?}");
        }
    }

    /// A real home with `.ssh` and `.local`, removed on drop.
    struct TmpHome(PathBuf);

    impl TmpHome {
        fn new(tag: &str) -> Self {
            let root = std::env::temp_dir().join(format!("sp-ids-{}-{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            for d in ["home/.ssh", "home/.local/share", "home/code/x"] {
                std::fs::create_dir_all(root.join(d)).unwrap();
            }
            Self(std::fs::canonicalize(root).unwrap())
        }
        fn home(&self) -> PathBuf {
            self.0.join("home")
        }
        fn id(&self, rel: &str) -> DirId {
            dir_id(&self.0.join(rel)).unwrap()
        }
    }

    impl Drop for TmpHome {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// RT-FS-14: a root with the identity of a protected folder (a bind alias of it) is refused.
    #[test]
    fn the_identity_of_a_protected_folder_is_refused() {
        let t = TmpHome::new("same");
        let d = Denylist::new(&env(t.home().to_str().unwrap()), &[]);
        let why = d.refusal_by_id(t.id("home/.ssh")).unwrap();
        assert!(
            why.contains("same directory as") && why.contains(".ssh"),
            "{why}"
        );
        let why = d.refusal_by_id(t.id("home")).unwrap();
        assert!(why.contains("the home directory root"), "{why}");
    }

    /// RT-FS-14: a root with the identity of an ancestor of a subtree rule (an alias of `~`'s
    /// parent, or of `~/.local`) is refused: it contains the protected folder.
    #[test]
    fn the_identity_of_an_ancestor_of_a_protected_folder_is_refused() {
        let t = TmpHome::new("anc");
        let d = Denylist::new(&env(t.home().to_str().unwrap()), &[]);
        for rel in ["home/.local", "home/.local/share", ""] {
            let why = d.refusal_by_id(t.id(rel)).unwrap();
            assert!(why.contains("which contains"), "{rel}: {why}");
        }
    }

    /// Ordinary directories, inside or beside the home, keep their identities free.
    #[test]
    fn other_identities_are_allowed() {
        let t = TmpHome::new("ok");
        let d = Denylist::new(&env(t.home().to_str().unwrap()), &[]);
        for rel in ["home/code", "home/code/x"] {
            assert_eq!(d.refusal_by_id(t.id(rel)), None, "{rel}");
        }
    }

    #[test]
    fn overlap_is_component_wise() {
        assert!(overlaps(Path::new("/a/b"), Path::new("/a")));
        assert!(overlaps(Path::new("/a"), Path::new("/a")));
        assert!(!overlaps(Path::new("/a/bc"), Path::new("/a/b")));
    }
}
