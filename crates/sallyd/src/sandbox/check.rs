//! The argv gate (CLAUDE.md hard rules; THREAT_MODEL SI-1, SI-2, SI-11). An **allowlist** per
//! role: every podman option must be one that role's builder emits, with a value of the exact
//! expected shape, at most once unless it is a mount or an environment variable; every hardening
//! option must be present; every `-v` source must be a declared [`Source`] with a grant that
//! covers the requested access; overlay scratch must lie in the session's scratch directory; the
//! image must be digest-pinned; and the command after the image must be the role's fixed command.
//! An unforeseen flag fails closed instead of slipping past a denylist. The red-team harness also
//! greps argv for the forbidden flags; this is the same rule enforced in-process before launch.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use super::argv::{
    CA_BUNDLE, CA_BUNDLE_VARS, ENTRY, HARNESS_API_KEY, INFER_SOCKET, MODEL_GUEST, OPENAI_BASE_URL,
    PLACEHOLDER, PROXY_URL, PROXY_VARS, SESSION_CA,
};
use super::types::{ArgvError, ImageRef, Role, UserIds};

/// Options written `--flag value`, as two tokens; `--flag=value` is refused, so the argv has one
/// spelling and does not depend on how podman parses either form.
const SPACE_FLAGS: [&str; 13] = [
    "--name",
    "--ulimit",
    "--tmpfs",
    "--security-opt",
    "--user",
    "--pids-limit",
    "--cpus",
    "--memory",
    "--memory-swap",
    "--hostname",
    "--env",
    "-v",
    "--device",
];
/// Options written `--flag=value`, as one token; the two-token form is refused.
const EQ_FLAGS: [&str; 8] = [
    "--pull",
    "--http-proxy",
    "--log-driver",
    "--network",
    "--read-only-tmpfs",
    "--cap-drop",
    "--userns",
    "--env-host",
];
/// Options that take no value.
const BARE_FLAGS: [&str; 4] = ["--rm", "--no-hosts", "--read-only", "--init"];
/// Options that may appear more than once (with distinct values).
const REPEATABLE: [&str; 3] = ["-v", "--env", "--security-opt"];
/// Options every role must carry exactly once (`--security-opt` is counted per kind in
/// [`require`]).
const REQUIRED: [&str; 18] = [
    "--rm",
    "--name",
    "--pull",
    "--http-proxy",
    "--log-driver",
    "--ulimit",
    "--network",
    "--no-hosts",
    "--read-only",
    "--read-only-tmpfs",
    "--cap-drop",
    "--userns",
    "--user",
    "--init",
    "--env-host",
    "--tmpfs",
    "--pids-limit",
    "--cpus",
];
/// Inference may only pass the NVIDIA CDI device (CLAUDE.md hard rules).
const GPU_DEVICE: &str = "nvidia.com/gpu=all";

/// What a host path may be mounted as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grant {
    /// A read-only bind of exactly this path.
    Ro,
    /// A read-write bind of exactly this path; binds and overlays of paths strictly inside it,
    /// at the matching guest path, are also allowed (the `.git` shields of AMENDMENTS-02 B2(a):
    /// they only ever narrow what the `rw` bind already grants).
    Rw,
    /// An overlay of exactly this path (a `staged` mount).
    Overlay,
}

/// A host path a role's argv may use as a `-v` source, and where it must appear.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    /// Absolute host path.
    pub path: PathBuf,
    /// Absolute guest path it is mounted at; a path inside an [`Grant::Rw`] source appears at
    /// the same relative path under this.
    pub guest: String,
    /// What it may be mounted as.
    pub grant: Grant,
}

/// Everything [`check_argv`] holds an argv to.
#[derive(Debug, Clone)]
pub struct Allowed {
    /// The role the argv is for.
    pub role: Role,
    /// The checked OCI runtime (`--runtime`, AMENDMENTS-02 B5).
    pub runtime: PathBuf,
    /// Sallyport's empty OCI hooks directory (`--hooks-dir`, #11).
    pub hooks_dir: PathBuf,
    /// Sallyport's empty mounts file (`--default-mounts-file`).
    pub mounts_file: PathBuf,
    /// The host user (`--user <uid>:<gid>`).
    pub ids: UserIds,
    /// The seccomp profile directory; the profile must be `<profiles>/seccomp-<role>.json`.
    pub profiles: PathBuf,
    /// The permitted `-v` sources.
    pub sources: Vec<Source>,
    /// Where overlay upper and work directories may live; `None` forbids overlays.
    pub scratch: Option<PathBuf>,
}

fn forbid<T>(msg: impl Into<String>) -> Result<T, ArgvError> {
    Err(ArgvError::Forbidden(msg.into()))
}

/// Checks a podman argv (the arguments after the program name) against `allowed`.
///
/// # Errors
/// [`ArgvError::Forbidden`] naming the first offending option.
pub fn check_argv(args: &[String], allowed: &Allowed) -> Result<(), ArgvError> {
    check_allowed(allowed)?;
    check_globals(args, allowed)?;
    let (options, image_at) = split_options(args)?;
    let mut seen = Seen::default();
    for (flag, value) in &options {
        seen.note(flag, value.as_deref())?;
        check_option(flag, value.as_deref(), allowed, &mut seen)?;
    }
    require(&seen, allowed.role)?;
    check_tail(args.get(image_at..).unwrap_or_default(), allowed.role)
}

/// Number of tokens before the first `create` option:
/// `--runtime <p> --hooks-dir <d> --default-mounts-file <f> create`.
const GLOBALS: usize = 7;

/// The global options are exactly the checked runtime, Sallyport's hooks directory and mounts
/// file, and the verb is `create` (the launcher inspects the container before it starts it).
fn check_globals(args: &[String], a: &Allowed) -> Result<(), ArgvError> {
    let is = |tok: &String, p: &Path| Path::new(tok) == p;
    match args {
        [f1, runtime, f2, hooks, f3, mounts, verb, ..]
            if f1 == "--runtime"
                && is(runtime, &a.runtime)
                && f2 == "--hooks-dir"
                && is(hooks, &a.hooks_dir)
                && f3 == "--default-mounts-file"
                && is(mounts, &a.mounts_file)
                && verb == "create" =>
        {
            Ok(())
        }
        _ => forbid(
            "argv must start with --runtime <checked runtime> --hooks-dir <sallyport hooks dir> \
             --default-mounts-file <sallyport mounts file> create",
        ),
    }
}

fn check_allowed(a: &Allowed) -> Result<(), ArgvError> {
    let paths = a.sources.iter().map(|s| s.path.as_path());
    let guests = a.sources.iter().map(|s| Path::new(&s.guest));
    let all = paths.chain(guests).chain(a.scratch.as_deref()).chain([
        a.profiles.as_path(),
        a.runtime.as_path(),
        a.hooks_dir.as_path(),
        a.mounts_file.as_path(),
    ]);
    for p in all {
        // `/` as a source, scratch or profile directory would make every host path "inside" it.
        if !p.to_str().is_some_and(|s| abs_clean(s) && s != "/") {
            return forbid(format!(
                "allowed path {} must be absolute and not /",
                p.display()
            ));
        }
    }
    Ok(())
}

type Options = Vec<(String, Option<String>)>;

/// Splits the options (after the globals and the verb) from the image and command. Each option
/// must use its one spelling: [`SPACE_FLAGS`] as two tokens, [`EQ_FLAGS`] as `--flag=value`,
/// [`BARE_FLAGS`] alone; anything else is refused in [`check_option`].
fn split_options(args: &[String]) -> Result<(Options, usize), ArgvError> {
    let mut out = Vec::new();
    let mut i = GLOBALS;
    loop {
        let Some(tok) = args.get(i) else {
            return forbid("no image");
        };
        if !tok.starts_with('-') {
            return Ok((out, i));
        }
        let (flag, value) = if SPACE_FLAGS.contains(&tok.as_str()) {
            i += 1;
            let Some(v) = args.get(i) else {
                return forbid(format!("{tok} has no value"));
            };
            (tok.clone(), Some(v.clone()))
        } else if let Some((f, v)) = tok.split_once('=') {
            if !EQ_FLAGS.contains(&f) {
                return forbid(format!("{f} must not be written as {f}=…"));
            }
            (f.to_owned(), Some(v.to_owned()))
        } else if BARE_FLAGS.contains(&tok.as_str()) {
            (tok.clone(), None)
        } else if EQ_FLAGS.contains(&tok.as_str()) {
            return forbid(format!("{tok} must be written as {tok}=<value>"));
        } else {
            return forbid(format!("podman option {tok} is not allowed here"));
        };
        out.push((flag, value));
        i += 1;
    }
}

/// What has been seen so far: option counts, mount destinations, env names.
#[derive(Default)]
struct Seen {
    flags: Vec<String>,
    security: HashSet<String>,
    dests: HashSet<String>,
    env: HashSet<String>,
    /// Overlay upper and work directories so far: no two may be equal or nested.
    scratch: Vec<PathBuf>,
    /// The values of `--memory` and `--memory-swap`, compared in [`require`].
    memory: Option<String>,
    swap: Option<String>,
}

impl Seen {
    fn note(&mut self, flag: &str, value: Option<&str>) -> Result<(), ArgvError> {
        if flag == "--security-opt" {
            let key = value.unwrap_or_default();
            let kind = key.split_once('=').map_or(key, |(k, _)| k);
            if !self.security.insert(kind.to_owned()) {
                return forbid(format!("--security-opt {kind} appears twice"));
            }
        } else if !REPEATABLE.contains(&flag) && self.count(flag) > 0 {
            return forbid(format!("{flag} appears twice"));
        }
        self.flags.push(flag.to_owned());
        Ok(())
    }

    fn count(&self, flag: &str) -> usize {
        self.flags.iter().filter(|f| *f == flag).count()
    }
}

fn check_option(
    flag: &str,
    value: Option<&str>,
    a: &Allowed,
    seen: &mut Seen,
) -> Result<(), ArgvError> {
    let fixed = |want: &str| match value {
        Some(v) if v == want => Ok(()),
        _ => forbid(format!("{flag} must be {want}")),
    };
    let ok = |cond: bool| {
        if cond {
            Ok(())
        } else {
            forbid(format!(
                "{flag} {} is not allowed here",
                value.unwrap_or("")
            ))
        }
    };
    match (flag, value) {
        ("--rm" | "--no-hosts" | "--read-only" | "--init", None) => Ok(()),
        ("--pull", _) => fixed("never"),
        ("--http-proxy" | "--read-only-tmpfs" | "--env-host", _) => fixed("false"),
        ("--log-driver" | "--network", _) => fixed("none"),
        ("--cap-drop", _) => fixed("ALL"),
        ("--userns", _) => fixed("keep-id"),
        ("--ulimit", _) => fixed("core=0"),
        ("--hostname", _) if a.role != Role::Inference => fixed("sandbox"),
        ("--user", _) => fixed(&format!("{}:{}", a.ids.uid, a.ids.gid)),
        ("--device", _) if a.role == Role::Inference => fixed(GPU_DEVICE),
        ("--security-opt", Some(v)) => security_opt(v, a),
        ("--name", Some(v)) => ok(name_ok(v, a.role)),
        ("--pids-limit", Some(v)) => ok(positive(v)),
        ("--cpus", Some(v)) => ok(cpus_ok(v)),
        ("--memory", Some(v)) => {
            seen.memory = Some(v.to_owned());
            ok(v.strip_suffix('b').is_some_and(positive))
        }
        ("--memory-swap", Some(v)) => {
            seen.swap = Some(v.to_owned());
            Ok(())
        }
        ("--tmpfs", Some(v)) => ok(tmpfs_ok(v)),
        ("--env", Some(v)) => env(v, a.role, seen),
        ("-v", Some(v)) => volume(v, a, seen),
        _ => forbid(format!("podman option {flag} is not allowed here")),
    }
}

fn name_ok(v: &str, role: Role) -> bool {
    let prefix = match role {
        Role::Workspace => "sp-ws-",
        Role::Harness => "sp-h-",
        Role::Inference => "sp-infer-",
    };
    v.strip_prefix(prefix).is_some_and(|id| {
        id.bytes().next().is_some_and(|b| b != b'-')
            && id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    })
}

fn positive(v: &str) -> bool {
    !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) && v.bytes().any(|b| b != b'0')
}

fn cpus_ok(v: &str) -> bool {
    let (int, frac) = v.split_once('.').unwrap_or((v, "0"));
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    digits(int) && digits(frac) && v.bytes().any(|b| b.is_ascii_digit() && b != b'0')
}

/// Exactly `/tmp:rw,{exec|noexec},nosuid,nodev,size=<bytes>`.
fn tmpfs_ok(v: &str) -> bool {
    let Some(opts) = v.strip_prefix("/tmp:") else {
        return false;
    };
    match opts.split(',').collect::<Vec<_>>().as_slice() {
        ["rw", exec, "nosuid", "nodev", size] => {
            matches!(*exec, "exec" | "noexec") && size.strip_prefix("size=").is_some_and(positive)
        }
        _ => false,
    }
}

fn security_opt(v: &str, a: &Allowed) -> Result<(), ArgvError> {
    let profile = a.profiles.join(a.role.profile());
    let seccomp = v
        .strip_prefix("seccomp=")
        .is_some_and(|p| Path::new(p) == profile);
    if v == "no-new-privileges" || v == "label=disable" || seccomp {
        Ok(())
    } else {
        forbid(format!("--security-opt {v} is not allowed"))
    }
}

/// Each role's variables, as exact name/value pairs; the workspace may also carry token-style
/// names set to the public placeholder (`secrets[].expose_env`, validated by the manifest).
fn env(v: &str, role: Role, seen: &mut Seen) -> Result<(), ArgvError> {
    let Some((name, value)) = v.split_once('=') else {
        return forbid(format!("--env {v} is not NAME=value"));
    };
    if !seen.env.insert(name.to_owned()) {
        return forbid(format!("--env {name} appears twice"));
    }
    let ok = match role {
        Role::Workspace => workspace_env(name, value),
        Role::Harness => {
            (name, value) == ("OPENAI_BASE_URL", OPENAI_BASE_URL)
                || (name, value) == ("OPENAI_API_KEY", HARNESS_API_KEY)
        }
        Role::Inference => false,
    };
    if ok {
        Ok(())
    } else {
        forbid(format!("--env {name} is not allowed for this role"))
    }
}

fn workspace_env(name: &str, value: &str) -> bool {
    if PROXY_VARS.contains(&name) {
        return value == PROXY_URL;
    }
    if CA_BUNDLE_VARS.contains(&name) {
        return value == CA_BUNDLE;
    }
    match name {
        "NO_PROXY" | "no_proxy" => value.is_empty(),
        "NODE_EXTRA_CA_CERTS" => value == SESSION_CA,
        _ => {
            value == PLACEHOLDER
                && !name.starts_with("LD_")
                && !name.starts_with("SALLY")
                && name.bytes().next().is_some_and(|b| b.is_ascii_uppercase())
                && name
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        }
    }
}

/// `src:dst:opts`: `src` a declared [`Source`] (or a path inside an `rw` one) whose grant covers
/// the access, `dst` its guest path and not mounted before, opts exactly
/// `{ro|rw},nosuid,nodev,bind` or `O,upperdir=<scratch>/…,workdir=<scratch>/…`.
fn volume(v: &str, a: &Allowed, seen: &mut Seen) -> Result<(), ArgvError> {
    let parts: Vec<&str> = v.split(':').collect();
    let [src, dst, opts] = parts.as_slice() else {
        return forbid(format!("-v {v} is not src:dst:options"));
    };
    if !abs_clean(src) || !abs_clean(dst) || *dst == "/" {
        return forbid(format!("-v {src}:{dst}: paths must be absolute, below /"));
    }
    if !seen.dests.insert((*dst).to_owned()) {
        return forbid(format!("-v destination {dst} is mounted twice"));
    }
    let kind = match opts.split(',').collect::<Vec<_>>().as_slice() {
        ["ro", "nosuid", "nodev", "bind"] => Kind::Ro,
        ["rw", "nosuid", "nodev", "bind"] => Kind::Rw,
        ["O", upper, work] if overlay_dirs_ok(upper, work, a, seen) => Kind::Overlay,
        _ => {
            return forbid(format!(
                "-v options {opts} must be ro|rw,nosuid,nodev,bind or an overlay in session scratch"
            ));
        }
    };
    let (src, dst) = (Path::new(src), Path::new(dst));
    if a.sources.iter().any(|s| granted(s, src, dst, kind)) {
        Ok(())
    } else {
        forbid(format!(
            "-v {}:{} ({kind:?}) is not granted by a validated mount or session directory",
            src.display(),
            dst.display()
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Ro,
    Rw,
    Overlay,
}

fn granted(s: &Source, src: &Path, dst: &Path, kind: Kind) -> bool {
    if src == s.path {
        return dst == Path::new(&s.guest)
            && matches!(
                (s.grant, kind),
                (Grant::Ro, Kind::Ro)
                    | (Grant::Rw, Kind::Ro | Kind::Rw)
                    | (Grant::Overlay, Kind::Overlay)
            );
    }
    // Inside an `rw` source: any kind, at the same relative guest path.
    s.grant == Grant::Rw
        && src
            .strip_prefix(&s.path)
            .is_ok_and(|rel| !rel.as_os_str().is_empty() && dst == Path::new(&s.guest).join(rel))
}

/// Upper and work directories inside session scratch, and disjoint from each other and from
/// every other overlay's: a shared upper directory would leak one overlay's writes into another
/// (a `.git` overlay's hooks into a staged mount's changes).
fn overlay_dirs_ok(upper: &str, work: &str, a: &Allowed, seen: &mut Seen) -> bool {
    let Some(scratch) = &a.scratch else {
        return false;
    };
    let dir = |opt: &str, key: &str| {
        opt.strip_prefix(key)
            .filter(|p| abs_clean(p) && strictly_under(Path::new(p), scratch))
            .map(PathBuf::from)
    };
    let (Some(upper), Some(work)) = (dir(upper, "upperdir="), dir(work, "workdir=")) else {
        return false;
    };
    let overlaps = |x: &Path, y: &Path| x.starts_with(y) || y.starts_with(x);
    if overlaps(&upper, &work)
        || seen
            .scratch
            .iter()
            .any(|s| overlaps(s, &upper) || overlaps(s, &work))
    {
        return false;
    }
    seen.scratch.extend([upper, work]);
    true
}

fn strictly_under(p: &Path, root: &Path) -> bool {
    p != root && p.starts_with(root)
}

/// Absolute, in one spelling only: no `.`/`..` segment, no empty segment, no trailing `/`
/// (`/a/` and `/a` would be two mounts of one guest path).
fn abs_clean(p: &str) -> bool {
    p == "/"
        || (p.starts_with('/')
            && p.split('/')
                .skip(1)
                .all(|s| !s.is_empty() && s != "." && s != ".."))
}

/// The hardening every argv carries exactly once.
fn require(seen: &Seen, role: Role) -> Result<(), ArgvError> {
    for flag in REQUIRED {
        if seen.count(flag) != 1 {
            return forbid(format!("{flag} must appear exactly once"));
        }
    }
    for kind in ["no-new-privileges", "seccomp", "label"] {
        if !seen.security.contains(kind) {
            return forbid(format!("--security-opt {kind} is required"));
        }
    }
    if role != Role::Inference {
        for flag in ["--memory", "--hostname"] {
            if seen.count(flag) != 1 {
                return forbid(format!("{flag} must appear exactly once"));
            }
        }
    }
    // No swap: `--memory-swap` equals `--memory`, and appears exactly when it does.
    if seen.swap != seen.memory {
        return forbid("--memory-swap must equal --memory (no swap)");
    }
    Ok(())
}

/// The image (digest-pinned) and the role's fixed command (AMENDMENTS-01 §2, §6.2).
fn check_tail(tail: &[String], role: Role) -> Result<(), ArgvError> {
    let Some((image, cmd)) = tail.split_first() else {
        return forbid("no image");
    };
    ImageRef::parse(image)
        .map_err(|_| ArgvError::Forbidden("image must be pinned by digest".into()))?;
    let cmd: Vec<&str> = cmd.iter().map(String::as_str).collect();
    let ok = match role {
        Role::Workspace => cmd == [ENTRY, "--idle"],
        Role::Harness => cmd == [ENTRY],
        Role::Inference => llama_ok(&cmd),
    };
    if ok {
        Ok(())
    } else {
        forbid(format!(
            "the {role:?} command must be the fixed one, not {cmd:?}"
        ))
    }
}

fn llama_ok(cmd: &[&str]) -> bool {
    let num = |s: &str| !s.is_empty() && s.len() <= 9 && s.bytes().all(|b| b.is_ascii_digit());
    match cmd {
        [
            "llama-server",
            "--host",
            host,
            "-m",
            model,
            "-ngl",
            ngl,
            "-c",
            ctx,
            "--jinja",
            "--no-webui",
            "-np",
            "1",
            "--log-disable",
        ] => *host == INFER_SOCKET && *model == MODEL_GUEST && num(ngl) && num(ctx),
        _ => false,
    }
}
