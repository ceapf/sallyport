//! Real-container fixture (rootless Podman) shared by `launch.rs` and `roles.rs`: the test
//! images, a launcher with hermetic podman, and `podman exec`.
//!
//! These tests never skip: without podman or the base image they fail. CI pulls the base image
//! by digest first (`ci.yml`); the test images are built from it offline.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock};

use sally_core::audit::{AuditError, NewEntry};
use sally_core::manifest::{AuditLevel, ValidatedManifest};
use sallyd::sandbox::{
    AuditSink, CheckedRuntime, DiskFloor, ImageRef, LaunchError, Launcher, LauncherParts, Podman,
    PodmanHost, Running, ScanLimits, SessionId, SessionPaths, Sessions, UserIds, WorkspaceRequest,
    resolve_podman,
};

use super::Fx;

/// The base image CI pulls by digest; everything else is built from it without a network.
pub const BASE: &str = "docker.io/library/alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc";
/// Container name prefixes of every role (`sp-ws-`, `sp-h-`, `sp-infer-` + session id).
const PREFIXES: [&str; 3] = ["sp-ws-", "sp-h-", "sp-infer-"];
/// The red-team syscall probe inside the test image (`tests/redteam/probe/probe.c`).
pub const PROBE: &str = "/usr/local/bin/sp-probe";

pub fn podman(args: &[&str]) -> std::process::Output {
    Command::new("podman")
        .args(args)
        .output()
        .expect("podman must be installed")
}

pub fn executable(path: &Path, body: &[u8]) {
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// The probe, compiled static from the red-team tree. Test-only: it goes into the throwaway test
/// image and nowhere else (CLAUDE.md).
fn probe_binary(out: &Path) {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/redteam/probe/probe.c");
    let status = Command::new("cc")
        .args(["-static", "-O2", "-Wall", "-Wextra", "-Werror", "-o"])
        .arg(out)
        .arg(&src)
        .status()
        .expect("a C compiler (cc) must be installed");
    assert!(status.success(), "cc {}", src.display());
}

/// An exclusive or shared `flock` on `<CARGO_TARGET_TMPDIR>/<name>.lock`, held until the file is
/// dropped. It works across nextest's processes and `cargo test`'s threads alike.
pub fn lock(name: &str, exclusive: bool) -> std::fs::File {
    let f = std::fs::File::create(
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}.lock")),
    )
    .unwrap();
    let op = if exclusive {
        rustix::fs::FlockOperation::LockExclusive
    } else {
        rustix::fs::FlockOperation::LockShared
    };
    rustix::fs::flock(&f, op).unwrap();
    f
}

/// The I/O lock: ordinary container tests share it; tests that write hundreds of MiB at full
/// speed take it exclusively, so their disk saturation never stalls another test's container
/// (seen on CI: `podman rm` timing out on a process blocked in I/O).
pub fn io_lock(exclusive: bool) -> std::fs::File {
    lock("container-io", exclusive)
}

/// Builds `localhost/<name>:<input key>` once and returns `localhost/<name>@sha256:…`. The tag
/// is a hash of every input (the base reference, the entry, the stand-in, the probe source), and
/// the build runs under a lock: a process finding the tag reuses it. So a tag never moves to
/// another image, and an earlier process's `name@digest` always resolves (CI saw "image not
/// known" when parallel builds re-tagged one name).
fn build(name: &str, entry: &str) -> String {
    use std::hash::{Hash, Hasher};
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/redteam/probe/probe.c");
    let mut h = std::hash::DefaultHasher::new();
    (BASE, entry, STAND_IN, std::fs::read(&src).unwrap()).hash(&mut h);
    let tag = format!("localhost/{name}:{:016x}", h.finish());
    let _held = lock("test-image", true);
    if !podman(&["image", "exists", &tag]).status.success() {
        build_image(&tag, entry);
    }
    let out = podman(&["image", "inspect", "--format", "{{.Digest}}", &tag]);
    assert!(
        out.status.success(),
        "inspect: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    format!(
        "localhost/{name}@{}",
        String::from_utf8_lossy(&out.stdout).trim()
    )
}

/// The `llama-server` stand-in: it idles.
const STAND_IN: &str = "#!/bin/sh\nexec sleep 2147483647\n";

fn build_image(tag: &str, entry: &str) {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("test-image-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("Containerfile"),
        format!(
            "FROM {BASE}\nCOPY entry /opt/sallyport/entry\nCOPY llama-server \
             /usr/local/bin/llama-server\nCOPY probe {PROBE}\n"
        ),
    )
    .unwrap();
    executable(&dir.join("entry"), entry.as_bytes());
    executable(&dir.join("llama-server"), STAND_IN.as_bytes());
    probe_binary(&dir.join("probe"));
    let out = podman(&[
        "build",
        "--pull=never",
        "--network=none",
        "--timestamp",
        "0",
        "-q",
        "-t",
        tag,
        dir.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "build: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `localhost/sallyport-test@sha256:…`: the base image, an entry and a `llama-server` that both
/// idle, and the probe.
pub fn test_image() -> ImageRef {
    static IMAGE: OnceLock<String> = OnceLock::new();
    let r = IMAGE.get_or_init(|| build("sallyport-test", "#!/bin/sh\nexec sleep 2147483647\n"));
    ImageRef::parse(r).unwrap()
}

/// As [`test_image`], but the entry cannot be executed: its interpreter does not exist, so
/// `execve` fails as soon as the container starts, with no shell start-up to race the launcher's
/// grace period (6c-1 Rust review M4).
pub fn exiting_image() -> ImageRef {
    static IMAGE: OnceLock<String> = OnceLock::new();
    let r = IMAGE.get_or_init(|| build("sallyport-test-exit", "#!/nonexistent/sh\nexit 3\n"));
    ImageRef::parse(r).unwrap()
}

/// Records every audit entry's event name and arguments.
#[derive(Default)]
pub struct Events(Mutex<Vec<(String, serde_json::Value)>>);

impl AuditSink for Events {
    fn append(&self, e: NewEntry, _: AuditLevel) -> Result<(), AuditError> {
        let args = e.arguments().clone();
        self.0.lock().unwrap().push((e.event().to_owned(), args));
        Ok(())
    }
}

impl Events {
    pub fn list(&self) -> Vec<String> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .map(|(e, _)| e.clone())
            .collect()
    }

    /// The arguments of the last entry named `event`.
    pub fn args(&self, event: &str) -> Option<serde_json::Value> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|(e, _)| e == event)
            .map(|(_, a)| a.clone())
    }
}

pub struct Lx {
    pub f: Fx,
    pub launcher: Arc<Launcher>,
    pub podman: Podman,
    pub runtime: CheckedRuntime,
    pub events: Arc<Events>,
    pub xdg: PathBuf,
    /// Prefix of every session id this fixture makes: `t<pid>-<n>`.
    pub scope: String,
    /// The shared I/O lock ([`io_lock`]); released after `Drop` has removed the containers.
    _io: Option<std::fs::File>,
}

fn host_env(var: &str) -> Option<PathBuf> {
    std::env::var_os(var).map(PathBuf::from)
}

/// The OCI runtime the tests use; `SALLYPORT_TEST_RUNTIME` overrides `/usr/bin/crun`.
pub fn test_runtime() -> PathBuf {
    PathBuf::from(
        std::env::var("SALLYPORT_TEST_RUNTIME").unwrap_or_else(|_| "/usr/bin/crun".into()),
    )
}

impl Lx {
    pub fn new() -> Self {
        Self::build(None, None, None, DiskFloor::default(), Some(io_lock(false)))
    }

    /// `podman_home`: the `$HOME` hermetic podman is given (default: the real one).
    pub fn with_home(podman_home: Option<PathBuf>) -> Self {
        Self::build(
            podman_home,
            None,
            None,
            DiskFloor::default(),
            Some(io_lock(false)),
        )
    }

    /// `runtime`: the OCI runtime podman is given (default: [`test_runtime`]).
    pub fn with_runtime(runtime: &Path) -> Self {
        Self::build(
            None,
            Some(runtime),
            None,
            DiskFloor::default(),
            Some(io_lock(false)),
        )
    }

    /// `wrap` turns the real podman binary into the one the launcher runs (a test wrapper that
    /// ends by running the real one). It bypasses `resolve_podman`'s trust check, so test-only.
    pub fn with_podman(wrap: impl FnOnce(&Path) -> PathBuf) -> Self {
        let real = resolve_podman(None, std::env::var_os("PATH").as_deref()).unwrap();
        Self::build(
            None,
            None,
            Some(wrap(&real)),
            DiskFloor::default(),
            Some(io_lock(false)),
        )
    }

    /// `floor`: the launcher's free-space floor, as `sallyd`'s configuration would set it. For
    /// the disk-filling tests, whose caller already holds [`io_lock`] exclusively.
    pub fn with_floor(floor: DiskFloor) -> Self {
        Self::build(None, None, None, floor, None)
    }

    fn build(
        podman_home: Option<PathBuf>,
        runtime: Option<&Path>,
        podman_bin: Option<PathBuf>,
        floor: DiskFloor,
        io: Option<std::fs::File>,
    ) -> Self {
        let f = Fx::new();
        let xdg = f.root.join("run");
        std::fs::set_permissions(&xdg, std::fs::Permissions::from_mode(0o700)).unwrap();
        let real_home = host_env("HOME").unwrap();
        let host = PodmanHost {
            home: podman_home.unwrap_or_else(|| real_home.clone()),
            xdg_runtime_dir: host_env("XDG_RUNTIME_DIR").expect("XDG_RUNTIME_DIR"),
            xdg_data_home: Some(
                host_env("XDG_DATA_HOME").unwrap_or(real_home.join(".local/share")),
            ),
        };
        let runtime = CheckedRuntime::check(runtime.unwrap_or(&test_runtime())).unwrap();
        let state = f.root.join("home/.local/share/sallyport/podman");
        std::fs::create_dir_all(state.parent().unwrap()).unwrap();
        let bin = podman_bin
            .unwrap_or_else(|| resolve_podman(None, std::env::var_os("PATH").as_deref()).unwrap());
        let podman = Podman::setup(bin, &runtime, &state, &host).unwrap();
        let events = Arc::new(Events::default());
        let launcher = Launcher::new(LauncherParts {
            podman: podman.clone(),
            runtime: runtime.clone(),
            ids: ids(),
            xdg_runtime_dir: xdg.clone(),
            sessions: Arc::new(Sessions::default()),
            audit: events.clone(),
            limits: ScanLimits::default(),
            disk_floor: floor,
        });
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self {
            f,
            launcher,
            podman,
            runtime,
            events,
            xdg,
            scope: format!("t{}-{n}", std::process::id()),
            _io: io,
        }
    }

    pub fn paths(&self, tag: &str) -> SessionPaths {
        let id = SessionId::parse(&format!("{}-{tag}", self.scope)).unwrap();
        SessionPaths::new(
            id,
            &self.xdg.join("sallyport"),
            &self.f.root.join("home/.local/share/sallyport"),
        )
        .unwrap()
    }

    pub fn request(&self, v: &ValidatedManifest, tag: &str) -> WorkspaceRequest {
        WorkspaceRequest {
            paths: self.paths(tag),
            manifest: Arc::new(v.clone()),
            default_image: test_image(),
        }
    }

    pub async fn launch(&self, v: &ValidatedManifest, tag: &str) -> Result<Running, LaunchError> {
        self.launcher.launch_workspace(self.request(v, tag)).await
    }

    pub async fn stop(&self, r: Running) {
        self.launcher.stop(r).await.unwrap();
    }

    /// Runs hermetic podman with `args` (as the launcher would); stdout on success.
    pub async fn hermetic(&self, args: &[String]) -> String {
        let out = self.podman.command().args(args).output().await.unwrap();
        assert!(
            out.status.success(),
            "podman {}: {}",
            args.first().map(String::as_str).unwrap_or_default(),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }
}

pub fn ids() -> UserIds {
    UserIds {
        uid: rustix::process::getuid().as_raw(),
        gid: rustix::process::getgid().as_raw(),
    }
}

impl Drop for Lx {
    /// Removes this fixture's containers even when a test failed, then its files (overlay work
    /// directories belong to the container's user namespace).
    fn drop(&mut self) {
        let names = podman(&["ps", "--all", "--format", "{{.Names}}"]);
        for name in String::from_utf8_lossy(&names.stdout).lines() {
            if PREFIXES
                .iter()
                .any(|p| name.starts_with(&format!("{p}{}-", self.scope)))
            {
                let _ = podman(&["rm", "--force", "--time", "0", name]);
            }
        }
        let _ = podman(&["unshare", "rm", "-rf", "--", self.f.root.to_str().unwrap()]);
    }
}

/// `podman exec` in the container: (exit code, stdout + stderr).
pub fn exec_in(container: &str, args: &[&str]) -> (i32, String) {
    let mut all = vec!["exec", container];
    all.extend_from_slice(args);
    let out = podman(&all);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.code().unwrap_or(-1), text)
}

/// `sh -c <script>` in the workspace container, as the broker will exec: holding the session's
/// exec gate (so it never meets a container frozen for a measurement), off the runtime (the
/// watchdog runs on it).
pub async fn exec(r: &Running, script: &str) -> (i32, String) {
    let gate = r.exec_gate();
    let _held = gate.lock().await;
    let (c, s) = (r.container().to_owned(), script.to_owned());
    tokio::task::spawn_blocking(move || exec_in(&c, &["sh", "-c", &s]))
        .await
        .unwrap()
}

pub fn exists(container: &str) -> bool {
    podman(&["container", "exists", container]).status.success()
}

pub fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}
