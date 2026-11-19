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
use super::hostenv::{EnvDir, HostEnv};
use super::links::{self, Incomplete, Link, Scan};

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
const DOTFILES: &str =
    "your shell and tools load your home's dotfiles, so their targets are never mountable";
const ENV_DIR: &str =
    "your environment names it for code your host runs or loads, so it is never mountable";

/// At most this many `$PATH` entries become rules; more leave the denylist incomplete
/// (`denylist-incomplete`, MANIFEST_SPEC §2).
pub(crate) const MAX_PATH_DIRS: usize = 256;

/// At most this many `$GOPATH` folders (`bin` and `pkg` of 16 elements) become rules; more leave
/// the denylist incomplete.
pub(crate) const MAX_GOPATH_DIRS: usize = 32;

/// The variables that name a list of folders, each with the most of its folders that become
/// rules. With one folder for each single-folder variable (`hostenv.rs`), the environment adds
/// at most that many plus 32 + 256 rules and scan roots.
const LIST_BOUNDS: [(&str, usize); 2] = [("PATH", MAX_PATH_DIRS), ("GOPATH", MAX_GOPATH_DIRS)];

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
    (".azure", CREDENTIALS),
    (".terraform.d", CREDENTIALS), // credentials.tfrc.json
    (".oci", CREDENTIALS),
    (".minikube", CREDENTIALS), // client keys
    (".gradle", EXECUTED),      // init.d scripts, gradle.properties credentials
    (".var/app", CONFIG),       // Flatpak app config and data
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
    (".vscode", EXECUTED), // extensions
    (".vim", EXECUTED),
    (".emacs.d", EXECUTED),
    (".ipython", EXECUTED), // profile startup scripts
    (".oh-my-zsh", EXECUTED),
    (".bun", EXECUTED),
    (".deno", EXECUTED),
    (".volta", EXECUTED),
    ("go/bin", EXECUTED),
    ("go/pkg", EXECUTED),
    (".local/share/pipx", EXECUTED),
    (".local/share/uv", EXECUTED),
    (".local/share/nvim", EXECUTED),
    (".local/share/mise", EXECUTED),
    (".local/share/pnpm", EXECUTED),
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
    /// The complete denylist for `env` and the manifest's `filesystem.deny` entries (already
    /// expanded to absolute paths): [`Denylist::without_links`], then a rule for each link out
    /// of a protected folder. The second value says why the list is incomplete, if it is; the
    /// rules built up to that point are kept.
    #[must_use]
    pub(crate) fn for_env(env: &HostEnv, extra: &[PathBuf]) -> (Self, Option<String>) {
        Self::with_budget(env, extra, links::BUDGET)
    }

    /// [`Denylist::for_env`], reading at most `budget` directory entries for links.
    #[must_use]
    pub(crate) fn with_budget(
        env: &HostEnv,
        extra: &[PathBuf],
        budget: usize,
    ) -> (Self, Option<String>) {
        let mut list = Self::without_links(env, extra);
        let mut scan = Scan::with_budget(budget);
        let read = scan_folders(env, &mut scan);
        list.add_links(scan.into_links());
        let mut why = over_bound(env);
        match read {
            Ok(()) => {}
            Err(Incomplete::Budget { folder }) => why.push(format!(
                "reading {:?} for links out of protected folders passed the budget of {budget} \
                 entries",
                folder.display().to_string()
            )),
            Err(Incomplete::Unreadable { folder, error }) => why.push(format!(
                "{:?} could not be read for links out of protected folders: {error}",
                folder.display().to_string()
            )),
        }
        let why = (!why.is_empty())
            .then(|| format!("the denylist could not be completed: {}", why.join("; ")));
        (list, why)
    }

    /// Every rule but the link rules: the built-in list, the XDG folders, the folders the
    /// environment names (the first [`MAX_PATH_DIRS`] `$PATH` and [`MAX_GOPATH_DIRS`] `$GOPATH`
    /// folders), and `extra`. Reads no
    /// folder's entries: for a manifest with no mounts, which nothing is checked against.
    pub(crate) fn without_links(env: &HostEnv, extra: &[PathBuf]) -> Self {
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
        rules.extend(env_rule_dirs(env).map(|d| {
            let label = format!("{} (from ${})", normalize(&d.path).display(), d.var);
            rule(&d.path, Scope::Subtree, Some(&label), Some(ENV_DIR))
        }));
        rules.extend(extra.iter().map(|p| subtree_rule(p, USER_DENY)));
        Self { rules }
    }

    /// Appends a rule for each link's target, labelled with the link and carrying the reason of
    /// the folder that holds it, unless every form of the target is already at or inside a
    /// subtree rule.
    ///
    /// Coverage is checked against the rules that are not link rules, and a target already
    /// made a rule is skipped by its exact path, so the work grows linearly with the links.
    fn add_links(&mut self, links: Vec<Link>) {
        let fixed = self.rules.len();
        let mut targets = std::collections::HashSet::new();
        for l in links {
            // Keyed by the target as the kernel reads it, not its normalized form: `s/../x`
            // through a linked `s` and a plain `x` normalize alike but resolve apart.
            if !targets.insert(l.target.clone()) {
                continue;
            }
            let shown = normalize(&l.target);
            let label = format!("{}, which {} points to", shown.display(), l.link.display());
            let r = rule(&l.target, Scope::Subtree, Some(&label), Some(l.reason));
            if !r.forms.iter().all(|f| self.covers(f, fixed)) {
                self.rules.push(r);
            }
        }
    }

    /// Whether `p` is at or inside one of the first `upto` rules that is a subtree rule.
    fn covers(&self, p: &Path, upto: usize) -> bool {
        self.rules
            .iter()
            .take(upto)
            .filter(|r| r.scope == Scope::Subtree)
            .any(|r| r.forms.iter().any(|f| p.starts_with(f)))
    }

    /// Returns a description of why `candidate` (absolute, normalized) is refused, if it is.
    pub(crate) fn refusal(&self, candidate: &Path) -> Option<String> {
        self.rules.iter().find_map(|r| {
            let why = r.reason.map_or_else(String::new, |w| format!(": {w}"));
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
    /// are not detected: TODO(#28) (the same ancestry gap as the overlap rule's re-review M-2,
    /// #17).
    pub(crate) fn refusal_by_id(&self, id: DirId) -> Option<String> {
        let why = |r: &Rule| r.reason.map_or_else(String::new, |w| format!(": {w}"));
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

/// The most folders of `var` that become rules, if it names a list ([`LIST_BOUNDS`]).
fn bound_of(var: &str) -> Option<usize> {
    LIST_BOUNDS
        .iter()
        .find(|(v, _)| *v == var)
        .map(|(_, bound)| *bound)
}

/// The environment's folders that become rules: all of them but, for each variable that names
/// a list, the folders past its bound.
fn env_rule_dirs(env: &HostEnv) -> impl Iterator<Item = &EnvDir> {
    let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    env.env_dirs.iter().filter(move |d| {
        let Some(bound) = bound_of(d.var) else {
            return true;
        };
        let n = counts.entry(d.var).or_insert(0);
        *n = n.saturating_add(1);
        *n <= bound
    })
}

/// One sentence for each list variable that names more folders than its bound.
fn over_bound(env: &HostEnv) -> Vec<String> {
    LIST_BOUNDS
        .iter()
        .filter(|(var, bound)| env.env_dirs.iter().filter(|d| d.var == *var).count() > *bound)
        .map(|(var, bound)| format!("${var} names more than {bound} folders"))
        .collect()
}

/// The homes: `$HOME` and the others that get the same protection.
fn homes(env: &HostEnv) -> impl Iterator<Item = &PathBuf> {
    std::iter::once(&env.home).chain(&env.other_homes)
}

/// A path's lexical form and, when it resolves, its real one.
fn forms_of(p: &Path) -> impl Iterator<Item = PathBuf> {
    [Some(normalize(p)), std::fs::canonicalize(p).ok()]
        .into_iter()
        .flatten()
}

/// Whether `p`, lexically or resolved, lies at or under one of `homes` (each home's forms).
fn under_a_home(homes: &[PathBuf], p: &Path) -> bool {
    forms_of(p).any(|f| homes.iter().any(|h| f.starts_with(h)))
}

/// Reads the folders whose links become rules (MANIFEST_SPEC §2), each to [`links::DEPTH`]:
/// every home folder of the built-in list, the XDG config and data folders, the environment's
/// folders (a `$PATH` entry only when it lies under a home), then each home's dotfiles.
fn scan_folders(env: &HostEnv, scan: &mut Scan) -> Result<(), Incomplete> {
    for h in homes(env) {
        for (p, why) in HOME_SUBTREES {
            scan.read(&h.join(p), links::DEPTH, why)?;
        }
    }
    for dir in [&env.xdg_config_home, &env.xdg_data_home]
        .into_iter()
        .flatten()
    {
        scan.read(dir, links::DEPTH, CONFIG)?;
    }
    let home_forms: Vec<PathBuf> = homes(env).flat_map(|h| forms_of(h)).collect();
    for d in env_rule_dirs(env) {
        if d.var != "PATH" || under_a_home(&home_forms, &d.path) {
            scan.read(&d.path, links::DEPTH, ENV_DIR)?;
        }
    }
    for h in homes(env) {
        scan.read_dotfiles(h, DOTFILES)?;
    }
    Ok(())
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
    // TODO(#28): a rule that is a dangling symlink contributes neither its target nor the
    // target's ancestors.
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
            "{raw:?}: only \"~\" and \"~/...\" are supported, not \"~user\""
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
// TODO(#195): these errors quote the host as written, or its realpath (of `expand`'s errors, the
// `~user` and not-absolute ones quote it as written). One holding a backslash, space, slash or
// any character `{:?}` escapes (such as a quote, a control or a non-printable character) is not
// masked; a `"` in a value (written `\"`) re-pairs `mask_quoted`'s spans across the message,
// after which a backtick can open one too, so a part of a value can still be judged, and masked,
// on its own. Past `expand` both hold `/` (a bare `~` as written holds none, and no token
// either).
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
// TODO(#195): these errors, all but the length one, quote the rejected guest. One holding a
// backslash, space, slash or any character `{:?}` escapes (such as a quote, a control or a
// non-printable character) is not masked; a `"` in it (written `\"`) re-pairs `mask_quoted`'s
// spans, after which a backtick can open one too, so a part of it can still be judged, and
// masked, on its own. Past the `/workspace/` prefix check it holds `/`.
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
            env_dirs: Vec::new(),
            nproc: 8,
            mem_bytes: 16 << 30,
        }
    }

    /// Every rule but the link rules, for an `env` whose homes are made up (`/home/u`): no
    /// folder of the test host is read.
    fn fixed(e: &HostEnv, extra: &[PathBuf]) -> Denylist {
        Denylist::without_links(e, extra)
    }

    /// The complete denylist (the test fails if it could not be completed).
    #[track_caller]
    fn deny(e: &HostEnv, extra: &[PathBuf]) -> Denylist {
        let (d, why) = Denylist::for_env(e, extra);
        assert_eq!(why, None);
        d
    }

    #[test]
    fn root_only_rules_allow_descendants() {
        let d = fixed(&env("/home/u"), &[]);
        assert!(d.refusal(Path::new("/")).is_some());
        assert!(d.refusal(Path::new("/home/u")).is_some());
        assert_eq!(d.refusal(Path::new("/home/u/code")), None);
        assert_eq!(d.refusal(Path::new("/opt/data")), None);
    }

    #[test]
    fn subtree_rules_refuse_inside_and_ancestors() {
        let d = fixed(&env("/home/u"), &[]);
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

    /// Credential folders and folders the host runs or loads code from, beyond the first
    /// list, are refused (and so is anything inside them).
    #[test]
    fn the_second_list_of_home_folders_is_refused() {
        let d = fixed(&env("/home/u"), &[]);
        for p in [
            ".azure",
            ".terraform.d",
            ".oci",
            ".minikube",
            ".vscode",
            ".vim",
            ".emacs.d",
            ".ipython",
            ".oh-my-zsh",
            ".bun",
            ".deno",
            ".volta",
            "go/bin",
            "go/pkg",
            ".local/share/pipx",
            ".local/share/uv",
            ".local/share/nvim",
            ".local/share/mise",
            ".local/share/pnpm",
        ] {
            let why = d.refusal(&Path::new("/home/u").join(p).join("x"));
            assert!(
                why.is_some_and(|w| w.starts_with("is inside /home/u/")),
                "{p}"
            );
        }
        assert_eq!(d.refusal(Path::new("/home/u/go/src")), None);
    }

    #[test]
    fn other_homes_are_protected_too() {
        let mut e = env("/tmp/fakehome");
        e.other_homes.push("/home/user".into());
        let d = fixed(&e, &[]);
        assert!(d.refusal(Path::new("/home/user/.ssh")).is_some());
        assert!(d.refusal(Path::new("/home/user")).is_some());
        assert_eq!(d.refusal(Path::new("/home/user/code")), None);
    }

    #[test]
    fn extra_rules_apply() {
        let d = fixed(&env("/home/u"), &[PathBuf::from("/home/u/private")]);
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

    /// A real home with `.ssh` and `.local`, removed on drop. Under the workspace's target dir,
    /// not /tmp, whose own rule would answer first for every path in it.
    struct TmpHome(PathBuf);

    impl TmpHome {
        fn new(tag: &str) -> Self {
            let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/tmp")
                .join(format!("sp-ids-{}-{tag}", std::process::id()));
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
        let d = deny(&env(t.home().to_str().unwrap()), &[]);
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
        let d = deny(&env(t.home().to_str().unwrap()), &[]);
        for rel in ["home/.local", "home/.local/share", ""] {
            let why = d.refusal_by_id(t.id(rel)).unwrap();
            assert!(why.contains("which contains"), "{rel}: {why}");
        }
    }

    /// Ordinary directories, inside or beside the home, keep their identities free.
    #[test]
    fn other_identities_are_allowed() {
        let t = TmpHome::new("ok");
        let d = deny(&env(t.home().to_str().unwrap()), &[]);
        for rel in ["home/code", "home/code/x"] {
            assert_eq!(d.refusal_by_id(t.id(rel)), None, "{rel}");
        }
    }

    /// MANIFEST_SPEC §2: a rule is matched in its realpath form as well as its lexical one. With
    /// `~/.ssh -> ~/dotfiles/ssh`, the link's target, anything inside it and its parent are
    /// refused by path (#33: `rule` keeps the canonical form exactly when it differs).
    #[test]
    fn a_symlinked_rule_is_also_matched_at_its_target() {
        let t = TmpHome::new("link");
        let home = t.home();
        std::fs::remove_dir(home.join(".ssh")).unwrap();
        std::fs::create_dir_all(home.join("dotfiles/ssh/keys")).unwrap();
        std::os::unix::fs::symlink(home.join("dotfiles/ssh"), home.join(".ssh")).unwrap();
        let d = deny(&env(home.to_str().unwrap()), &[]);
        let ssh = home.join(".ssh").display().to_string();
        for (rel, how) in [
            ("dotfiles/ssh", "is inside"),
            ("dotfiles/ssh/keys", "is inside"),
            ("dotfiles", "contains"),
        ] {
            let why = d.refusal(&home.join(rel)).unwrap_or_default();
            assert!(why.starts_with(&format!("{how} {ssh}")), "{rel}: {why:?}");
        }
        // RT-FS-14 half: the target's parent is an ancestor by identity too, so an alias of
        // `~/dotfiles` "contains" the protected folder.
        let why = d.refusal_by_id(t.id("home/dotfiles")).unwrap_or_default();
        assert!(
            why.contains("which contains") && why.contains(&ssh),
            "{why:?}"
        );
        // No over-match: a sibling is allowed.
        assert_eq!(d.refusal(&home.join("code/x")), None);
    }

    /// Makes `link -> target` under `home` (both relative to it), creating the link's folder.
    fn link(home: &Path, link: &str, target: &str) -> PathBuf {
        let l = home.join(link);
        std::fs::create_dir_all(l.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(home.join(target), &l).unwrap();
        l
    }

    /// The refusal of `rel` under `home`, or "".
    fn why(d: &Denylist, home: &Path, rel: &str) -> String {
        d.refusal(&home.join(rel)).unwrap_or_default()
    }

    /// A link rule carries the reason of the folder holding it (here CONFIG, and the dotfile
    /// reason for a home dotfile); of a home's own entries only dot names are followed, so a
    /// non-dot home link is not.
    #[test]
    fn link_rules_carry_their_folders_reason_and_dotfiles_only() {
        let t = TmpHome::new("reasons");
        let home = t.home();
        let gh = link(&home, ".config/gh", "dotfiles/gh");
        let rc = link(&home, ".bashrc", "dotfiles2/bashrc");
        link(&home, "work", "data/work");
        std::fs::create_dir_all(home.join("data/work")).unwrap();
        let d = deny(&env(home.to_str().unwrap()), &[]);
        let w = why(&d, &home, "dotfiles");
        assert!(
            w.contains(&gh.display().to_string()) && w.ends_with(CONFIG),
            "{w}"
        );
        let w = why(&d, &home, "dotfiles2");
        assert!(
            w.contains(&rc.display().to_string()) && w.ends_with(DOTFILES),
            "{w}"
        );
        assert_eq!(d.refusal(&home.join("data/work")), None);
        assert_eq!(d.refusal(&home.join("data")), None);
    }

    /// Every other holding folder passes its own reason on: a credential folder, a cache,
    /// Sallyport's state, the XDG config and data folders (outside the home, so only their
    /// scan finds these links) and an environment folder.
    #[test]
    fn link_rules_carry_each_holding_folders_reason() {
        let t = TmpHome::new("classes");
        let home = t.home();
        let conf = t.0.join("xdgconf");
        let data = t.0.join("xdgdata");
        let cargo = t.0.join("cargo");
        for dir in [&conf, &data, &cargo] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let ext = |dir: &Path, name: &str, target: &str| {
            let l = dir.join(name);
            std::os::unix::fs::symlink(home.join(target), &l).unwrap();
            l
        };
        let cases = [
            (link(&home, ".ssh/k", "credt/k"), "credt", CREDENTIALS),
            (link(&home, ".cache/c", "cachet/c"), "cachet", CACHE),
            (
                link(&home, ".local/share/sallyport/s", "statet/s"),
                "statet",
                SALLYPORT,
            ),
            (ext(&conf, "app", "conft/app"), "conft", CONFIG),
            (ext(&data, "app", "datat/app"), "datat", CONFIG),
            (ext(&cargo, "c", "envt/c"), "envt", ENV_DIR),
        ];
        let mut e = env(home.to_str().unwrap());
        e.xdg_config_home = Some(conf.clone());
        e.xdg_data_home = Some(data.clone());
        e.env_dirs = vec![env_dir(&cargo, "CARGO_HOME")];
        let d = deny(&e, &[]);
        for (l, target, reason) in &cases {
            let w = why(&d, &home, target);
            assert!(
                w.contains(&format!("which {} points to", l.display())) && w.ends_with(reason),
                "{target}: {w}"
            );
        }
        // Control: without the XDG and environment folders their links are not found.
        let d = deny(&env(home.to_str().unwrap()), &[]);
        for target in ["conft", "datat", "envt"] {
            assert_eq!(d.refusal(&home.join(target)), None, "{target}");
        }
    }

    /// Link rules come after every other rule, so a path both refuse keeps the built-in's
    /// message. A link whose target is inside a rule adds no rule.
    #[test]
    fn built_in_messages_win_and_covered_links_add_nothing() {
        let t = TmpHome::new("order");
        let home = t.home();
        let before = deny(&env(home.to_str().unwrap()), &[]).rules.len();
        link(&home, ".local/bin/k", ".ssh/key");
        assert_eq!(deny(&env(home.to_str().unwrap()), &[]).rules.len(), before);
        link(&home, ".local/bin/x", ".local/share/foo/x");
        let d = deny(&env(home.to_str().unwrap()), &[]);
        assert_eq!(d.rules.len(), before + 1);
        let w = why(&d, &home, ".local");
        assert!(
            w.starts_with("contains ") && w.ends_with(CREDENTIALS),
            "{w}"
        );
        let w = why(&d, &home, ".local/share/foo");
        assert!(w.contains(".local/bin/x") && w.ends_with(EXECUTED), "{w}");
    }

    /// The rule is made from the lexical target, and `rule` adds the canonical one: with a
    /// two-hop chain both the first hop's folder and the final target's are refused.
    #[test]
    fn a_two_hop_link_protects_both_hops() {
        let t = TmpHome::new("hops");
        let home = t.home();
        std::fs::create_dir_all(home.join("final")).unwrap();
        std::fs::write(home.join("final/rc"), "").unwrap();
        link(&home, "hop/rc", "final/rc");
        let l = link(&home, ".local/bin/rc", "hop/rc");
        let d = deny(&env(home.to_str().unwrap()), &[]);
        for rel in ["hop", "final"] {
            let w = why(&d, &home, rel);
            assert!(w.contains(&l.display().to_string()), "{rel}: {w}");
        }
    }

    /// A relative link in a protected folder that is itself a link (a stow-folded
    /// `~/.local/bin -> ~/dotfiles/bin` holding `t -> ../tools/t`) protects where the kernel
    /// resolves it, `~/dotfiles/tools/t`, not `~/.local/tools/t`.
    #[test]
    fn a_relative_link_in_a_linked_folder_protects_the_real_target() {
        let t = TmpHome::new("folded");
        let home = t.home();
        std::fs::create_dir_all(home.join("dotfiles/bin")).unwrap();
        std::fs::create_dir_all(home.join("dotfiles/tools")).unwrap();
        std::os::unix::fs::symlink("../tools/t", home.join("dotfiles/bin/t")).unwrap();
        link(&home, ".local/bin", "dotfiles/bin");
        let d = deny(&env(home.to_str().unwrap()), &[]);
        let w = why(&d, &home, "dotfiles/tools");
        assert!(w.contains(".local/bin/t points to"), "{w}");
    }

    /// Two links whose targets normalize alike but resolve apart (`s/../x` through a linked `s`,
    /// and a plain `x`) each make a rule, in either order.
    #[test]
    fn targets_that_resolve_apart_are_not_merged() {
        let t = TmpHome::new("apart");
        let home = t.home();
        let r = home.join(".local/bin");
        std::fs::create_dir_all(&r).unwrap();
        std::fs::create_dir_all(home.join("data/q")).unwrap();
        std::fs::write(home.join("data/x"), "").unwrap();
        std::os::unix::fs::symlink(home.join("data/q"), r.join("s")).unwrap();
        let via = Link {
            link: r.join("a"),
            target: r.join("s/../x"),
            reason: EXECUTED,
        };
        let plain = Link {
            link: r.join("b"),
            target: r.join("x"),
            reason: EXECUTED,
        };
        for order in [[via.clone(), plain.clone()], [plain, via]] {
            let mut d = Denylist::without_links(&env(home.to_str().unwrap()), &[]);
            d.add_links(order.to_vec());
            // `s/../x` resolves to `~/data/x`: its folder `~/data` contains it.
            let w = why(&d, &home, "data");
            assert!(
                w.contains("contains") && w.contains(".local/bin/a points to"),
                "{w}"
            );
        }
    }

    /// Two links to one target make one rule.
    #[test]
    fn a_target_named_by_two_links_is_one_rule() {
        let t = TmpHome::new("twice");
        let home = t.home();
        let before = deny(&env(home.to_str().unwrap()), &[]).rules.len();
        link(&home, ".local/bin/a", "tools/x");
        link(&home, ".local/bin/b", "tools/x");
        assert_eq!(
            deny(&env(home.to_str().unwrap()), &[]).rules.len(),
            before + 1
        );
    }

    /// A dangling link protects its lexical target, which may appear later.
    #[test]
    fn a_dangling_link_protects_its_lexical_target() {
        let t = TmpHome::new("dangle");
        let home = t.home();
        let l = link(&home, ".local/bin/gone", "later/bin/gone");
        let d = deny(&env(home.to_str().unwrap()), &[]);
        assert!(why(&d, &home, "later").contains(&l.display().to_string()));
    }

    fn env_dir(path: &Path, var: &'static str) -> EnvDir {
        EnvDir {
            path: path.to_owned(),
            var,
        }
    }

    /// An environment folder is a rule naming its variable, and its links are read
    /// wherever it lies; a `$PATH` entry's links are read only under a home.
    #[test]
    fn env_folders_are_rules_and_their_links_are_read() {
        let t = TmpHome::new("envdirs");
        let home = t.home();
        let cargo = t.0.join("elsewhere/cargo");
        let sys_bin = t.0.join("sysbin");
        std::fs::create_dir_all(&cargo).unwrap();
        std::fs::create_dir_all(&sys_bin).unwrap();
        let venv = home.join("proj/.venv/bin");
        link(&home, "proj/.venv/bin/py", "pydist/py");
        std::os::unix::fs::symlink(home.join("cargolink/c"), cargo.join("c")).unwrap();
        std::os::unix::fs::symlink(home.join("syslink/s"), sys_bin.join("s")).unwrap();
        let mut e = env(home.to_str().unwrap());
        e.env_dirs = vec![
            env_dir(&cargo, "CARGO_HOME"),
            env_dir(&venv, "PATH"),
            env_dir(&sys_bin, "PATH"),
        ];
        let d = deny(&e, &[]);
        let w = d.refusal(&cargo.join("x")).unwrap_or_default();
        assert!(
            w.contains("(from $CARGO_HOME)") && w.ends_with(ENV_DIR),
            "{w}"
        );
        assert!(why(&d, &home, "proj").contains("(from $PATH)"));
        let w = why(&d, &home, "cargolink");
        assert!(w.contains(&cargo.join("c").display().to_string()), "{w}");
        assert!(why(&d, &home, "pydist").contains(".venv/bin/py"));
        assert_eq!(d.refusal(&home.join("syslink")), None);
    }

    /// An environment folder that is a home is kept as a rule: every mount under it is
    /// refused, and the message names the variable.
    #[test]
    fn an_env_folder_that_is_the_home_refuses_under_it() {
        let mut e = env("/home/u");
        e.env_dirs = vec![env_dir(Path::new("/home/u"), "CARGO_HOME")];
        let d = fixed(&e, &[]);
        let w = d.refusal(Path::new("/home/u/code/x")).unwrap_or_default();
        assert!(w.contains("/home/u (from $CARGO_HOME)"), "{w}");
        // The same for an exported `ZDOTDIR=$HOME`, though it names zsh's default place.
        e.env_dirs = vec![env_dir(Path::new("/home/u"), "ZDOTDIR")];
        let w = fixed(&e, &[])
            .refusal(Path::new("/home/u/code/x"))
            .unwrap_or_default();
        assert!(w.contains("/home/u (from $ZDOTDIR)"), "{w}");
    }

    /// The first 256 `$PATH` entries are rules; one more leaves the list incomplete,
    /// naming `$PATH`, with those 256 still rules.
    #[test]
    fn path_entries_past_the_bound_leave_the_list_incomplete() {
        // A home that does not exist, so the scan reads nothing of the test host's.
        let entry = |n: usize| PathBuf::from(format!("/opt/p{n}"));
        let mut e = env("/sp-absent-root/home/u");
        e.env_dirs = (1..=MAX_PATH_DIRS)
            .map(|n| env_dir(&entry(n), "PATH"))
            .collect();
        let d = deny(&e, &[]);
        assert!(d.refusal(&entry(MAX_PATH_DIRS)).is_some());
        e.env_dirs.push(env_dir(&entry(MAX_PATH_DIRS + 1), "PATH"));
        e.env_dirs
            .push(env_dir(Path::new("/opt/cargo"), "CARGO_HOME"));
        let (d, why) = Denylist::for_env(&e, &[]);
        let why = why.unwrap_or_default();
        assert!(why.contains("$PATH names more than 256 folders"), "{why}");
        assert!(d.refusal(&entry(MAX_PATH_DIRS)).is_some());
        assert_eq!(d.refusal(&entry(MAX_PATH_DIRS + 1)), None);
        assert!(d.refusal(Path::new("/opt/cargo")).is_some());
        // Without links (no mounts) the first 256 are still rules; nothing is reported, as
        // `without_links` returns no reason.
        let d = Denylist::without_links(&e, &[]);
        assert!(d.refusal(&entry(MAX_PATH_DIRS)).is_some());
        assert_eq!(d.refusal(&entry(MAX_PATH_DIRS + 1)), None);
    }

    /// A search-only folder in a protected folder leaves the list incomplete, naming it.
    #[test]
    fn an_enterable_unlistable_folder_leaves_the_list_incomplete() {
        use std::os::unix::fs::PermissionsExt;
        struct Restore(PathBuf);
        impl Drop for Restore {
            fn drop(&mut self) {
                let open = std::fs::Permissions::from_mode(0o755);
                let _ = std::fs::set_permissions(&self.0, open);
            }
        }
        let t = TmpHome::new("unlistable");
        let home = t.home();
        let sub = home.join(".cargo/sub");
        std::fs::create_dir_all(&sub).unwrap();
        let _restore = Restore(sub.clone());
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o311)).unwrap();
        assert!(std::fs::read_dir(&sub).is_err(), "control: unlistable here");
        let (_, why) = Denylist::for_env(&env(home.to_str().unwrap()), &[]);
        assert_eq!(
            why,
            Some(format!(
                "the denylist could not be completed: {:?} could not be read for links out of \
                 protected folders: it can be entered but not listed",
                sub.display().to_string()
            ))
        );
    }

    /// The first 32 `$GOPATH` folders are rules; one more leaves the list incomplete naming
    /// `$GOPATH`, while a variable listed after it is still a rule. With both list variables
    /// over their bounds one sentence names both.
    #[test]
    fn gopath_folders_past_the_bound_leave_the_list_incomplete() {
        // Under a root that does not exist: `$GOPATH` folders are read wherever they lie.
        let entry = |n: usize| PathBuf::from(format!("/sp-absent-root/g{n}"));
        let mut e = env("/sp-absent-root/home/u");
        e.env_dirs = (1..=MAX_GOPATH_DIRS)
            .map(|n| env_dir(&entry(n), "GOPATH"))
            .collect();
        let d = deny(&e, &[]);
        assert!(d.refusal(&entry(MAX_GOPATH_DIRS)).is_some());
        e.env_dirs
            .push(env_dir(&entry(MAX_GOPATH_DIRS + 1), "GOPATH"));
        e.env_dirs.push(env_dir(Path::new("/opt/p1"), "PATH"));
        let (d, why) = Denylist::for_env(&e, &[]);
        assert_eq!(
            why.as_deref(),
            Some("the denylist could not be completed: $GOPATH names more than 32 folders")
        );
        assert!(d.refusal(&entry(MAX_GOPATH_DIRS)).is_some());
        assert_eq!(d.refusal(&entry(MAX_GOPATH_DIRS + 1)), None);
        assert!(d.refusal(Path::new("/opt/p1")).is_some());
        e.env_dirs.extend(
            (2..=MAX_PATH_DIRS + 1).map(|n| env_dir(&PathBuf::from(format!("/opt/p{n}")), "PATH")),
        );
        let (_, why) = Denylist::for_env(&e, &[]);
        assert_eq!(
            why.as_deref(),
            Some(
                "the denylist could not be completed: $PATH names more than 256 folders; \
                 $GOPATH names more than 32 folders"
            )
        );
    }

    /// The scan's budget, through the named constructor: exactly enough entries completes
    /// the list, one fewer names the folder being read and the budget; links found before
    /// that are kept. The bounds are pinned.
    #[test]
    fn the_scan_budget_names_the_folder() {
        assert_eq!(
            (links::BUDGET, links::DEPTH, MAX_PATH_DIRS, MAX_GOPATH_DIRS),
            (65_536, 2, 256, 32)
        );
        let t = TmpHome::new("budget");
        let home = t.home();
        let l = link(&home, ".cargo/a", "kept/a");
        for n in 0..3 {
            std::fs::write(home.join(format!(".cargo/f{n}")), "").unwrap();
        }
        // Entries read: .ssh 0, .cargo 4 (a, f0..f2), the other listed folders are absent,
        // then the home's own 4 (.ssh, .local, code, .cargo): 8.
        let e = env(home.to_str().unwrap());
        let (_, msg) = Denylist::with_budget(&e, &[], 8);
        assert_eq!(msg, None);
        let (d, msg) = Denylist::with_budget(&e, &[], 7);
        let msg = msg.unwrap_or_default();
        assert!(
            msg.contains(&format!("reading {:?}", home.display().to_string()))
                && msg.contains("budget of 7 entries"),
            "{msg}"
        );
        assert!(
            msg.starts_with("the denylist could not be completed: "),
            "{msg}"
        );
        assert!(why(&d, &home, "kept").contains(&l.display().to_string()));
    }

    /// A link inside a protected folder protects its target. `~/.local/bin/t ->
    /// ~/dotfiles/bin/t` (the target outside every listed rule): mounting `~/dotfiles` would let
    /// the sandbox rewrite what the host runs, so it is refused, and the refusal names the link.
    #[test]
    fn a_link_in_a_protected_folder_protects_its_target() {
        let t = TmpHome::new("dl");
        let home = t.home();
        std::fs::create_dir_all(home.join(".local/bin")).unwrap();
        std::fs::create_dir_all(home.join("dotfiles/bin")).unwrap();
        std::fs::write(home.join("dotfiles/bin/t"), "").unwrap();
        let link = home.join(".local/bin/t");
        std::os::unix::fs::symlink(home.join("dotfiles/bin/t"), &link).unwrap();
        let d = deny(&env(home.to_str().unwrap()), &[]);
        for rel in ["dotfiles", "dotfiles/bin"] {
            let why = d.refusal(&home.join(rel)).unwrap_or_default();
            assert!(
                why.starts_with("contains ") && why.contains(&link.display().to_string()),
                "{rel}: {why:?}"
            );
        }
    }

    #[test]
    fn overlap_is_component_wise() {
        assert!(overlaps(Path::new("/a/b"), Path::new("/a")));
        assert!(overlaps(Path::new("/a"), Path::new("/a")));
        assert!(!overlaps(Path::new("/a/bc"), Path::new("/a/b")));
    }
}
