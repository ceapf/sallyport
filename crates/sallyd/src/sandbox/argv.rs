//! Pure `podman` argv builders, one per role (AMENDMENTS-01 §2): workspace (mounts, egress
//! socket, toolchain), harness (model and tool sockets only), inference (GPU, read-only weights).
//!
//! Every builder returns the arguments that follow the `podman` program name, starting with
//! `--runtime <checked path> run`, and runs [`check_argv`] on its own output before returning it.

use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};

use sally_core::manifest::{ByteSize, MountMode, NetworkMode, ValidatedManifest};

use super::check::check_argv;
use super::types::{ArgvError, CommonArgs, GitScan, ImageRef, InferenceSpec, SessionPaths, input};

/// The entry point baked into the workspace and harness images.
const ENTRY: &str = "/opt/sallyport/entry";
/// Where each role's socket directory appears inside its container.
const SOCKETS_GUEST: &str = "/run/sallyport";
/// The shim inside the workspace listens here and forwards to `net.sock` (SI-1).
const PROXY_URL: &str = "http://127.0.0.1:3128";
/// `secrets[].expose_env` value: a public constant, never the secret (MANIFEST_SPEC).
const PLACEHOLDER: &str = "sallyport-placeholder";
/// Trust bundles for the session CA when the proxy intercepts TLS (AMENDMENTS-01 §4).
const CA_BUNDLE: &str = "/run/sallyport/ca-bundle.pem";
const SESSION_CA: &str = "/run/sallyport/session-ca.pem";
const CA_BUNDLE_VARS: [&str; 7] = [
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "GIT_SSL_CAINFO",
    "PIP_CERT",
    "CARGO_HTTP_CAINFO",
    "AWS_CA_BUNDLE",
];
const PROXY_VARS: [&str; 6] = [
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
];
/// Harness resources are fixed in v1 (AMENDMENTS-01 §2).
const HARNESS_CPUS: &str = "1";
const HARNESS_MEMORY: u64 = 1024 * 1024 * 1024;
const HARNESS_PIDS: u32 = 128;
/// `/tmp` of the harness and inference containers.
const SMALL_TMP: u64 = 256 * 1024 * 1024;
const INFERENCE_PIDS: u32 = 64;
/// The harness reaches the model through the shim on this port (AMENDMENTS-01 §3.2).
const OPENAI_BASE_URL: &str = "http://127.0.0.1:8080/v1";

/// Role-specific seccomp profile file names under [`CommonArgs::profiles`].
#[derive(Clone, Copy)]
enum Role {
    Workspace,
    Harness,
    Inference,
}

impl Role {
    const fn profile(self) -> &'static str {
        match self {
            Self::Workspace => "seccomp-workspace.json",
            Self::Harness => "seccomp-harness.json",
            Self::Inference => "seccomp-inference.json",
        }
    }
}

/// A path as it may appear in a `-v`, `--security-opt` or `--runtime` argument: absolute, UTF-8,
/// and free of `:`, `,` and control characters, which would change the meaning of the argument.
pub(crate) fn path_arg(p: &Path, what: &str) -> Result<String, ArgvError> {
    let Some(s) = p.to_str() else {
        return input(format!("{what} is not valid UTF-8"));
    };
    if !p.is_absolute() {
        return input(format!("{what} must be an absolute path"));
    }
    if s.chars().any(|c| c == ':' || c == ',' || c.is_control())
        || s.split('/').any(|seg| seg == "." || seg == "..")
    {
        return input(format!(
            "{what} contains ':', ',', a control character, or a . or .. segment"
        ));
    }
    Ok(s.to_owned())
}

/// A `.git` path found by the launch scan, relative to its mount: plain segments only, ending in
/// `.git`.
fn git_rel(p: &Path) -> Result<String, ArgvError> {
    let bad = || input("git scan entries are relative paths of plain segments ending in .git");
    let Some(s) = p.to_str() else { return bad() };
    let segs: Vec<&str> = s.split('/').collect();
    let plain = segs
        .iter()
        .all(|seg| !seg.is_empty() && *seg != "." && *seg != "..");
    if s.starts_with('/') || !plain || segs.last() != Some(&".git") {
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
            "run",
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
        a.push(["--cap-drop=ALL", "--security-opt=no-new-privileges"]);
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
    fn overlay(
        &mut self,
        host: &str,
        guest: &str,
        (upper, work): (PathBuf, PathBuf),
    ) -> Result<(), ArgvError> {
        let upper = path_arg(&upper, "overlay upper directory")?;
        let work = path_arg(&work, "overlay work directory")?;
        self.push([
            "-v",
            &format!("{host}:{guest}:O,upperdir={upper},workdir={work}"),
        ]);
        Ok(())
    }

    fn finish(self, roots: &[PathBuf]) -> Result<Vec<String>, ArgvError> {
        let roots: Vec<&Path> = roots.iter().map(PathBuf::as_path).collect();
        check_argv(&self.0, &roots)?;
        Ok(self.0)
    }
}

/// The workspace container: the manifest's mounts, the egress socket in proxy mode, and the
/// toolchain image; it idles until the broker execs into it (AMENDMENTS-01 §2).
///
/// `git` lists what the launch scan found in each `rw` mount (AMENDMENTS-02 B2(a)): every `.git`
/// directory becomes an overlay over session scratch, every `.git` file a read-only bind.
///
/// # Errors
/// [`ArgvError::Input`] for a malformed input; [`ArgvError::Forbidden`] if the result fails
/// [`check_argv`] (a bug).
pub fn workspace_argv(
    c: &CommonArgs,
    paths: &SessionPaths,
    v: &ValidatedManifest,
    git: &[GitScan],
    default_image: &ImageRef,
) -> Result<Vec<String>, ArgvError> {
    let m = v.manifest();
    let scans = scans_by_mount(v, git)?;
    let mut a = Argv::new(c, format!("sp-ws-{}", paths.id().as_str()), Role::Workspace)?;
    a.tmpfs(m.runtime.tmp_size.bytes(), m.runtime.tmp_exec);
    a.limits(
        m.runtime.pids,
        &m.runtime.cpus.to_string(),
        Some(m.runtime.memory.bytes()),
    );
    a.push(["--init", "--env-host=false", "--hostname", "sandbox"]);
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
    let mut roots = vec![paths.data_root().to_owned(), paths.socket_root().to_owned()];
    let mut overlays = 0usize;
    for (i, mt) in v.mounts().iter().enumerate() {
        let host = path_arg(&mt.host, "mount host")?;
        let guest = path_arg(Path::new(&mt.guest), "mount guest")?;
        roots.push(mt.host.clone());
        match mt.mode {
            MountMode::Ro | MountMode::Brokered => a.bind(&host, &guest, "ro"),
            MountMode::Staged => a.overlay(&host, &guest, paths.stage(i))?,
            MountMode::Rw => {
                a.bind(&host, &guest, "rw");
                if let Some(scan) = scans.get(&i) {
                    for dir in &scan.dirs {
                        let rel = git_rel(dir)?;
                        a.overlay(
                            &format!("{host}/{rel}"),
                            &format!("{guest}/{rel}"),
                            paths.git_overlay(overlays),
                        )?;
                        overlays += 1;
                    }
                    for file in &scan.files {
                        let rel = git_rel(file)?;
                        a.bind(&format!("{host}/{rel}"), &format!("{guest}/{rel}"), "ro");
                    }
                }
            }
        }
    }
    let sockets = path_arg(&paths.workspace_sockets(), "workspace socket directory")?;
    a.bind(&sockets, SOCKETS_GUEST, "rw");
    let image = match &m.runtime.image {
        Some(i) => ImageRef::parse(i)?,
        None => default_image.clone(),
    };
    a.push([image.as_str(), ENTRY, "--idle"]);
    a.finish(&roots)
}

/// Checks the git scans: each names an existing `rw` mount, once, with unique `.git` paths.
fn scans_by_mount<'a>(
    v: &ValidatedManifest,
    git: &'a [GitScan],
) -> Result<std::collections::BTreeMap<usize, &'a GitScan>, ArgvError> {
    let mut out = std::collections::BTreeMap::new();
    for scan in git {
        match v.mounts().get(scan.mount) {
            Some(mt) if mt.mode == MountMode::Rw => {}
            Some(_) => return input("git scans apply only to rw mounts"),
            None => return input("git scan names a mount that does not exist"),
        }
        if out.insert(scan.mount, scan).is_some() {
            return input("two git scans for the same mount");
        }
        let mut seen = HashSet::new();
        if !scan.dirs.iter().chain(&scan.files).all(|p| seen.insert(p)) {
            return input("a .git path is listed twice");
        }
    }
    Ok(out)
}

/// The harness container: no mounts, no egress, no GPU; only its own socket directory with
/// `llm.sock` and `agent.sock`. Resources are fixed in v1 (AMENDMENTS-01 §2).
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
    // A dummy: the broker answers on llm.sock and needs no key (AMENDMENTS-01 §3.2).
    a.env("OPENAI_API_KEY", "sallyport");
    let sockets = path_arg(&paths.harness_sockets(), "harness socket directory")?;
    a.bind(&sockets, SOCKETS_GUEST, "rw");
    let image = match &v.manifest().harness {
        Some(h) => ImageRef::parse(&h.image)?,
        None => default_image.clone(),
    };
    a.push([image.as_str(), ENTRY]);
    a.finish(&[paths.socket_root().to_owned()])
}

/// The inference container (ARCHITECTURE §3.2, AMENDMENTS-01 §6.2): the GPU, one read-only
/// model file, its socket directory, and a fixed `llama-server` command that always passes `-m`
/// and never a flag granting file or network reach.
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
    let model = path_arg(&s.model, "model file")?;
    a.bind(&model, "/models/model.gguf", "ro");
    let sockets = path_arg(&s.socket_dir, "inference socket directory")?;
    a.bind(&sockets, SOCKETS_GUEST, "rw");
    a.push([
        s.image.as_str(),
        "llama-server",
        "--host",
        "/run/sallyport/infer.sock",
    ]);
    a.push([
        "-m",
        "/models/model.gguf",
        "-ngl",
        &s.gpu_layers.to_string(),
    ]);
    a.push([
        "-c",
        &s.context.to_string(),
        "--jinja",
        "--no-webui",
        "-np",
        "1",
        "--log-disable",
    ]);
    a.finish(&[s.model.clone(), s.socket_dir.clone()])
}
