//! Pure `podman` argv builders, one per role (AMENDMENTS-01 §2): workspace (mounts, egress
//! socket, toolchain), harness (model and tool sockets only), inference (GPU, read-only weights).
//!
//! Every builder returns the arguments that follow the `podman` program name, starting with
//! `--runtime <checked path> --hooks-dir <empty dir> --default-mounts-file <empty file> create`,
//! and runs [`check_argv`] on its own
//! output, against an [`Allowed`] policy derived from the role and the manifest, before
//! returning it. The launcher creates the container, checks it, and only then starts it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use sally_core::manifest::{ByteSize, MountMode, NetworkMode, ValidatedManifest};

use super::check::{Allowed, Grant, Source, check_argv};
use super::scan::{GitScan, LaunchScan};
use super::types::{
    ArgvError, CommonArgs, ImageRef, InferenceSpec, OverlayDirs, Role, SessionPaths, input,
};

/// The entry point baked into the workspace and harness images.
pub(super) const ENTRY: &str = "/opt/sallyport/entry";
/// Where each role's socket directory appears inside its container.
pub(super) const SOCKETS_GUEST: &str = "/run/sallyport";
/// The shim inside the workspace listens here and forwards to `net.sock` (SI-1).
pub(super) const PROXY_URL: &str = "http://127.0.0.1:3128";
/// `secrets[].expose_env` value: a public constant, never the secret (MANIFEST_SPEC).
pub(super) const PLACEHOLDER: &str = "sallyport-placeholder";
/// Trust bundles for the session CA when the proxy intercepts TLS (AMENDMENTS-01 §4).
pub(super) const CA_BUNDLE: &str = "/run/sallyport/ca-bundle.pem";
pub(super) const SESSION_CA: &str = "/run/sallyport/session-ca.pem";
pub(super) const CA_BUNDLE_VARS: [&str; 7] = [
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "GIT_SSL_CAINFO",
    "PIP_CERT",
    "CARGO_HTTP_CAINFO",
    "AWS_CA_BUNDLE",
];
pub(super) const PROXY_VARS: [&str; 6] = [
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
];
/// The harness reaches the model through the shim on this port (AMENDMENTS-01 §3.2).
pub(super) const OPENAI_BASE_URL: &str = "http://127.0.0.1:8080/v1";
/// A dummy key: the broker answers on `llm.sock` and needs none (AMENDMENTS-01 §3.2).
pub(super) const HARNESS_API_KEY: &str = "sallyport";
/// Where the model file appears in the inference container.
pub(super) const MODEL_GUEST: &str = "/models/model.gguf";
/// `llama-server` listens here, inside the inference socket directory.
pub(super) const INFER_SOCKET: &str = "/run/sallyport/infer.sock";
/// Harness resources are fixed in v1 (AMENDMENTS-01 §2).
const HARNESS_CPUS: &str = "1";
const HARNESS_MEMORY: u64 = 1024 * 1024 * 1024;
const HARNESS_PIDS: u32 = 128;
/// `/tmp` of the harness and inference containers.
const SMALL_TMP: u64 = 256 * 1024 * 1024;
const INFERENCE_PIDS: u32 = 64;

/// A path as it may appear in a `-v`, `--security-opt` or `--runtime` argument: absolute, UTF-8,
/// and free of `:`, `,` and control characters, which would change the meaning of the argument.
pub(crate) fn path_arg(p: &Path, what: &str) -> Result<String, ArgvError> {
    let Some(s) = p.to_str() else {
        return input(format!("{what}: not valid UTF-8"));
    };
    if !p.is_absolute() {
        return input(format!("{what}: must be an absolute path"));
    }
    if s.chars().any(|c| c == ':' || c == ',' || c.is_control())
        || s.split('/')
            .skip(1)
            .any(|seg| seg.is_empty() || seg == "." || seg == "..")
    {
        return input(format!(
            "{what}: contains ':', ',', a control character, or an empty, . or .. segment"
        ));
    }
    Ok(s.to_owned())
}

/// A `.git` path found by the launch scan, relative to its mount: plain segments only, ending in
/// `.git`, with no `.git` segment before the last (the scanner does not descend into one).
fn git_rel(p: &Path, what: &str) -> Result<String, ArgvError> {
    let bad = || {
        input(format!(
            "{what}: must be a relative path of plain segments ending in .git, with no other \
             .git segment"
        ))
    };
    let Some(s) = p.to_str() else { return bad() };
    let segs: Vec<&str> = s.split('/').collect();
    let Some((last, parents)) = segs.split_last() else {
        return bad();
    };
    let plain = segs
        .iter()
        .all(|seg| !seg.is_empty() && *seg != "." && *seg != "..");
    if s.starts_with('/') || !plain || *last != ".git" || parents.contains(&".git") {
        return bad();
    }
    if s.chars().any(|c| c == ':' || c == ',' || c.is_control()) {
        return bad();
    }
    Ok(s.to_owned())
}

struct Argv(Vec<String>);

impl Argv {
    fn new(c: &CommonArgs, name: String, role: Role) -> Result<Self, ArgvError> {
        let mut a = Self(Vec::new());
        a.push([
            "--runtime",
            &path_arg(c.runtime.path(), "runtime")?,
            "--hooks-dir",
            &path_arg(&c.hooks_dir, "hooks directory")?,
            "--default-mounts-file",
            &path_arg(&c.mounts_file, "mounts file")?,
            "create",
            "--rm",
        ]);
        a.push(["--name", &name]);
        // AMENDMENTS-01 §6.1: never contact a registry, never inherit host proxies, keep no logs,
        // write no core files.
        a.push([
            "--pull=never",
            "--http-proxy=false",
            "--log-driver=none",
            "--ulimit",
            "core=0",
        ]);
        a.push([
            "--network=none",
            "--no-hosts",
            "--read-only",
            "--read-only-tmpfs=false",
        ]);
        let seccomp = path_arg(&c.profiles.join(role.profile()), "seccomp profile")?;
        a.push(["--cap-drop=ALL", "--security-opt", "no-new-privileges"]);
        a.push(["--security-opt", &format!("seccomp={seccomp}")]);
        a.push(["--security-opt", "label=disable"]);
        a.push([
            "--userns=keep-id",
            "--user",
            &format!("{}:{}", c.ids.uid, c.ids.gid),
        ]);
        Ok(a)
    }

    fn push<const N: usize>(&mut self, items: [&str; N]) {
        self.0.extend(items.iter().map(|s| (*s).to_owned()));
    }

    fn tmpfs(&mut self, bytes: u64, exec: bool) {
        let exec = if exec { "exec" } else { "noexec" };
        self.push([
            "--tmpfs",
            &format!("/tmp:rw,{exec},nosuid,nodev,size={bytes}"),
        ]);
    }

    fn limits(&mut self, pids: u32, cpus: &str, memory: Option<u64>) {
        self.push(["--pids-limit", &pids.to_string(), "--cpus", cpus]);
        if let Some(m) = memory {
            self.push(["--memory", &format!("{m}b")]);
        }
    }

    fn env(&mut self, name: &str, value: &str) {
        self.push(["--env", &format!("{name}={value}")]);
    }

    fn bind(&mut self, host: &str, guest: &str, access: &str) {
        self.push(["-v", &format!("{host}:{guest}:{access},nosuid,nodev,bind")]);
    }

    /// Podman refuses other options next to `O` (probed on 4.9.3), so an overlay carries no
    /// `nosuid,nodev`; `no-new-privileges`, `--cap-drop=ALL` and the seccomp profile (no
    /// `mknod`) are what keep set-id files and device nodes inert there.
    fn overlay(&mut self, host: &str, guest: &str, dirs: &OverlayDirs) -> Result<(), ArgvError> {
        let upper = path_arg(&dirs.upper, "overlay upper directory")?;
        let work = path_arg(&dirs.work, "overlay work directory")?;
        self.push([
            "-v",
            &format!("{host}:{guest}:O,upperdir={upper},workdir={work}"),
        ]);
        Ok(())
    }

    fn finish(self, allowed: &Allowed) -> Result<Vec<String>, ArgvError> {
        check_argv(&self.0, allowed)?;
        Ok(self.0)
    }
}

/// The parts of [`Allowed`] every role shares.
fn allowed(c: &CommonArgs, role: Role, sources: Vec<Source>, scratch: Option<&Path>) -> Allowed {
    Allowed {
        role,
        runtime: c.runtime.path().to_owned(),
        hooks_dir: c.hooks_dir.clone(),
        mounts_file: c.mounts_file.clone(),
        ids: c.ids,
        profiles: c.profiles.clone(),
        sources,
        scratch: scratch.map(Path::to_owned),
    }
}

fn source(path: &Path, guest: &str, grant: Grant) -> Source {
    Source {
        path: path.to_owned(),
        guest: guest.to_owned(),
        grant,
    }
}

/// The workspace container: the manifest's mounts, the egress socket in proxy mode, and the
/// toolchain image; it idles until the broker execs into it (AMENDMENTS-01 §2).
///
/// `scan` is the launch scan of the manifest's mounts (AMENDMENTS-02 B2(a)), which holds one git
/// scan per `rw` mount, empty if it found nothing: every `.git` directory becomes an overlay over
/// session scratch,
/// every `.git` file a read-only bind, and every directory between the mount root and either is
/// bound onto itself so it cannot be renamed away from under its shield (EBUSY).
///
/// # Errors
/// [`ArgvError::Input`] for a malformed input; [`ArgvError::Forbidden`] if the result fails
/// [`check_argv`] (a bug).
pub fn workspace_argv(
    c: &CommonArgs,
    paths: &SessionPaths,
    v: &ValidatedManifest,
    scan: &LaunchScan,
    default_image: &ImageRef,
) -> Result<Vec<String>, ArgvError> {
    let m = v.manifest();
    if !scan.is_for(v) {
        return input("the launch scan belongs to another manifest");
    }
    let scans = scans_by_mount(v, scan.git())?;
    let mut a = Argv::new(c, format!("sp-ws-{}", paths.id().as_str()), Role::Workspace)?;
    a.tmpfs(m.runtime.tmp_size.bytes(), m.runtime.tmp_exec);
    a.limits(
        m.runtime.pids,
        &m.runtime.cpus.to_string(),
        Some(m.runtime.memory.bytes()),
    );
    a.push(["--init", "--env-host=false", "--hostname", "sandbox"]);
    workspace_env(&mut a, v);
    let mut sources = workspace_mounts(&mut a, paths, v, &scans)?;
    let sockets = paths.workspace_sockets();
    a.bind(
        &path_arg(&sockets, "workspace socket directory")?,
        SOCKETS_GUEST,
        "ro",
    );
    sources.push(source(&sockets, SOCKETS_GUEST, Grant::Ro));
    let image = match &m.runtime.image {
        Some(i) => ImageRef::parse(i).map_err(|e| field_err("runtime.image", e))?,
        None => default_image.clone(),
    };
    a.push([image.as_str(), ENTRY, "--idle"]);
    a.finish(&allowed(
        c,
        Role::Workspace,
        sources,
        Some(paths.data_root()),
    ))
}

fn field_err(field: &str, e: ArgvError) -> ArgvError {
    match e {
        ArgvError::Input(msg) => ArgvError::Input(format!("{field}: {msg}")),
        other => other,
    }
}

/// Proxy variables (proxy mode), CA bundle variables (proxy mode with secrets), and the
/// placeholder for every `expose_env` name.
fn workspace_env(a: &mut Argv, v: &ValidatedManifest) {
    let m = v.manifest();
    if m.network.mode == NetworkMode::Proxy {
        for var in PROXY_VARS {
            a.env(var, PROXY_URL);
        }
        a.env("NO_PROXY", "");
        a.env("no_proxy", "");
        if !m.secrets.is_empty() {
            for var in CA_BUNDLE_VARS {
                a.env(var, CA_BUNDLE);
            }
            a.env("NODE_EXTRA_CA_CERTS", SESSION_CA);
        }
    }
    let exposed: BTreeSet<&str> = m
        .secrets
        .iter()
        .filter_map(|s| s.expose_env.as_deref())
        .collect();
    for name in exposed {
        a.env(name, PLACEHOLDER);
    }
}

/// Emits every manifest mount and returns the sources the checker may accept.
fn workspace_mounts(
    a: &mut Argv,
    paths: &SessionPaths,
    v: &ValidatedManifest,
    scans: &BTreeMap<usize, &GitScan>,
) -> Result<Vec<Source>, ArgvError> {
    let mut sources = Vec::new();
    let mut overlays = 0usize;
    for (i, mt) in v.mounts().iter().enumerate() {
        let host = path_arg(&mt.host, &format!("filesystem.mounts[{i}].host"))?;
        let guest = path_arg(
            Path::new(&mt.guest),
            &format!("filesystem.mounts[{i}].guest"),
        )?;
        let grant = match mt.mode {
            MountMode::Ro | MountMode::Brokered => {
                a.bind(&host, &guest, "ro");
                Grant::Ro
            }
            MountMode::Staged => {
                a.overlay(&host, &guest, &paths.stage(i))?;
                Grant::Overlay
            }
            MountMode::Rw => {
                a.bind(&host, &guest, "rw");
                let scan = scans.get(&i).ok_or_else(|| {
                    ArgvError::Input(format!("filesystem.mounts[{i}]: rw mount has no git scan"))
                })?;
                git_shields(a, paths, (&host, &guest), scan, &mut overlays)?;
                Grant::Rw
            }
        };
        sources.push(source(&mt.host, &guest, grant));
    }
    Ok(sources)
}

/// AMENDMENTS-02 B2(a) inside one `rw` mount: pin the parents, overlay `.git` directories, bind
/// `.git` files read-only.
fn git_shields(
    a: &mut Argv,
    paths: &SessionPaths,
    (host, guest): (&str, &str),
    scan: &GitScan,
    overlays: &mut usize,
) -> Result<(), ArgvError> {
    let at = |kind: &str, j: usize| {
        format!(
            "git scan of filesystem.mounts[{}].{kind}[{j}]",
            scan.mount()
        )
    };
    let dirs = scan
        .dirs()
        .iter()
        .enumerate()
        .map(|(j, d)| git_rel(d, &at("dirs", j)))
        .collect::<Result<Vec<_>, _>>()?;
    let files = scan
        .files()
        .iter()
        .enumerate()
        .map(|(j, f)| git_rel(f, &at("files", j)))
        .collect::<Result<Vec<_>, _>>()?;
    let parents: BTreeSet<&str> = dirs
        .iter()
        .chain(&files)
        .flat_map(|rel| {
            rel.match_indices('/')
                .map(move |(k, _)| rel.get(..k).unwrap_or(rel))
        })
        .collect();
    for p in parents {
        a.bind(&format!("{host}/{p}"), &format!("{guest}/{p}"), "rw");
    }
    for rel in &dirs {
        a.overlay(
            &format!("{host}/{rel}"),
            &format!("{guest}/{rel}"),
            &paths.git_overlay(*overlays),
        )?;
        *overlays += 1;
    }
    for rel in &files {
        a.bind(&format!("{host}/{rel}"), &format!("{guest}/{rel}"), "ro");
    }
    Ok(())
}

/// Checks the git scans: each names an existing `rw` mount, once, with unique `.git` paths.
fn scans_by_mount<'a>(
    v: &ValidatedManifest,
    git: &'a [GitScan],
) -> Result<BTreeMap<usize, &'a GitScan>, ArgvError> {
    let mut out = BTreeMap::new();
    for scan in git {
        let at = format!("git scan of filesystem.mounts[{}]", scan.mount());
        match v.mounts().get(scan.mount()) {
            Some(mt) if mt.mode == MountMode::Rw => {}
            Some(_) => return input(format!("{at}: git scans apply only to rw mounts")),
            None => return input(format!("{at}: no such mount")),
        }
        if out.insert(scan.mount(), scan).is_some() {
            return input(format!("{at}: listed twice"));
        }
        let mut seen = BTreeSet::new();
        if !scan
            .dirs()
            .iter()
            .chain(scan.files())
            .all(|p| seen.insert(p))
        {
            return input(format!("{at}: a .git path is listed twice"));
        }
    }
    Ok(out)
}

/// The harness container: no mounts, no egress, no GPU; only its own socket directory with
/// `llm.sock` and `agent.sock`, read-only (it only connects). Resources are fixed in v1
/// (AMENDMENTS-01 §2).
///
/// # Errors
/// As [`workspace_argv`].
pub fn harness_argv(
    c: &CommonArgs,
    paths: &SessionPaths,
    v: &ValidatedManifest,
    default_image: &ImageRef,
) -> Result<Vec<String>, ArgvError> {
    let mut a = Argv::new(c, format!("sp-h-{}", paths.id().as_str()), Role::Harness)?;
    a.tmpfs(SMALL_TMP, false);
    a.limits(HARNESS_PIDS, HARNESS_CPUS, Some(HARNESS_MEMORY));
    a.push(["--init", "--env-host=false", "--hostname", "sandbox"]);
    a.env("OPENAI_BASE_URL", OPENAI_BASE_URL);
    a.env("OPENAI_API_KEY", HARNESS_API_KEY);
    let sockets = paths.harness_sockets();
    a.bind(
        &path_arg(&sockets, "harness socket directory")?,
        SOCKETS_GUEST,
        "ro",
    );
    let image = match &v.manifest().harness {
        Some(h) => ImageRef::parse(&h.image).map_err(|e| field_err("harness.image", e))?,
        None => default_image.clone(),
    };
    a.push([image.as_str(), ENTRY]);
    a.finish(&allowed(
        c,
        Role::Harness,
        vec![source(&sockets, SOCKETS_GUEST, Grant::Ro)],
        None,
    ))
}

/// The inference container (ARCHITECTURE §3.2, AMENDMENTS-01 §6.2): the GPU, one read-only
/// model file, its socket directory (read-write: `llama-server` creates the socket), and a fixed
/// `llama-server` command that always passes `-m` and never a flag granting file or network
/// reach.
///
/// # Errors
/// As [`workspace_argv`].
pub fn inference_argv(c: &CommonArgs, s: &InferenceSpec) -> Result<Vec<String>, ArgvError> {
    let mut a = Argv::new(
        c,
        format!("sp-infer-{}", s.instance.as_str()),
        Role::Inference,
    )?;
    a.tmpfs(SMALL_TMP, false);
    a.limits(
        INFERENCE_PIDS,
        &s.cpus.to_string(),
        s.memory.map(ByteSize::bytes),
    );
    a.push(["--init", "--env-host=false"]);
    if s.gpu {
        a.push(["--device", "nvidia.com/gpu=all"]);
    }
    a.bind(&path_arg(s.model.path(), "model file")?, MODEL_GUEST, "ro");
    let sockets = path_arg(&s.socket_dir, "inference socket directory")?;
    a.bind(&sockets, SOCKETS_GUEST, "rw");
    a.push([s.image.as_str(), "llama-server", "--host", INFER_SOCKET]);
    a.push(["-m", MODEL_GUEST, "-ngl", &s.gpu_layers.to_string()]);
    a.push([
        "-c",
        &s.context.to_string(),
        "--jinja",
        "--no-webui",
        "-np",
        "1",
        "--log-disable",
    ]);
    a.finish(&allowed(
        c,
        Role::Inference,
        vec![
            source(s.model.path(), MODEL_GUEST, Grant::Ro),
            source(&s.socket_dir, SOCKETS_GUEST, Grant::Rw),
        ],
        None,
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::path::PathBuf;

    use super::*;

    /// The scanner is the only constructor of a [`GitScan`] outside this crate; the builder still
    /// re-validates every entry (defense in depth) and these are its refusals.
    #[test]
    fn git_entries_are_plain_relative_paths_ending_in_one_git_segment() {
        for ok in [".git", "a/.git", "a/b-c/.git"] {
            assert!(git_rel(Path::new(ok), "x").is_ok(), "{ok}");
        }
        for bad in [
            "../x/.git",
            "/abs/.git",
            "a:b/.git",
            "a,ro/.git",
            "not-git",
            "a//.git",
            ".git/modules/x/.git",
            "x/./.git",
            "",
            "a/.git/",
            "a\n/.git",
        ] {
            assert!(git_rel(Path::new(bad), "x").is_err(), "{bad:?}");
        }
    }

    fn scan(mount: usize, dirs: &[&str], files: &[&str]) -> GitScan {
        GitScan::unchecked(
            mount,
            dirs.iter().map(PathBuf::from).collect(),
            files.iter().map(PathBuf::from).collect(),
        )
    }

    fn manifest(dir: &Path) -> ValidatedManifest {
        use sally_core::manifest::{HostEnv, load};
        let home = dir.join("home");
        for d in ["a", "b"] {
            std::fs::create_dir_all(home.join(d)).unwrap();
        }
        let env = HostEnv {
            home: home.clone(),
            other_homes: Vec::new(),
            xdg_config_home: None,
            xdg_data_home: None,
            xdg_runtime_dir: None,
            podman_storage: Vec::new(),
            nproc: 8,
            mem_bytes: 16 << 30,
        };
        let body = "apiVersion: sallyport/v1\nkind: Manifest\nname: t\nmodel:\n  ref: any\n\
                    filesystem:\n  mounts:\n    - {host: \"~/a\", guest: /workspace/a, mode: rw}\n\
                    \x20   - {host: \"~/b\", guest: /workspace/b, mode: staged}\n";
        load(body, &env, &std::collections::BTreeSet::new())
            .unwrap()
            .manifest
    }

    #[test]
    fn scans_must_cover_each_rw_mount_exactly_once() {
        let dir = std::env::current_dir()
            .unwrap()
            .join("../../target/argv-unit")
            .join(std::process::id().to_string());
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let dir = std::fs::canonicalize(&dir).unwrap();
        let v = manifest(&dir);
        assert!(scans_by_mount(&v, &[scan(0, &[], &[])]).is_ok());
        for bad in [
            vec![scan(0, &[], &[]), scan(0, &[], &[])],
            vec![scan(0, &[], &[]), scan(1, &[".git"], &[])],
            vec![scan(0, &[], &[]), scan(7, &[".git"], &[])],
            vec![scan(0, &[".git"], &[".git"])],
        ] {
            let e = scans_by_mount(&v, &bad).unwrap_err();
            assert!(e.to_string().contains("filesystem.mounts["), "{e}");
        }
        // A missing scan is refused when the argv is built.
        let mut a = Argv(Vec::new());
        let paths = SessionPaths::new(
            super::super::types::SessionId::parse("s").unwrap(),
            &dir.join("run"),
            &dir.join("data"),
        )
        .unwrap();
        let e = workspace_mounts(&mut a, &paths, &v, &BTreeMap::new()).unwrap_err();
        assert!(e.to_string().contains("rw mount has no git scan"), "{e}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
