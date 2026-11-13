//! Real-container fixture (rootless Podman) shared by `launch.rs`, `roles.rs` and `rpc.rs`: the
//! test images, a launcher with hermetic podman, and `podman exec`.
//!
//! These tests never skip: without podman or the base image they fail. CI pulls the base image
//! by digest first (`ci.yml`); the test images are built from it offline.

use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock};

use sally_core::audit::{AuditError, NewEntry};
use sally_core::manifest::{AuditLevel, ValidatedManifest};
use sallyd::sandbox::{
    AuditSink, CheckedRuntime, CommonArgs, DiskFloor, ImageRef, LaunchError, Launcher,
    LauncherParts, Podman, PodmanHost, Running, ScanLimits, SessionDirs, SessionId, SessionPaths,
    Sessions, UserIds, WorkspaceRequest, resolve_podman,
};

use sallyd::session::{Registry, RegistryParts};

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

/// This run's id: `SALLYPORT_TEST_RUN` when `scripts/test-run.sh` set it (a malformed value
/// panics, never falls back), otherwise a per-process token of the same shape (architect Q24).
/// Every container name a fixture makes carries it ([`Lx::scope`]), so the wrapper's sweep finds
/// exactly this run's leftovers and a reused pid never meets another run's.
pub fn run_id() -> &'static str {
    static ID: OnceLock<String> = OnceLock::new();
    ID.get_or_init(|| {
        resolve_run_id(std::env::var("SALLYPORT_TEST_RUN"), random_run_id)
            .unwrap_or_else(|e| panic!("{e}"))
    })
}

/// The run id from the variable's value: unset → `random()`; set → it must parse as a run id,
/// including a value that is not UTF-8 (it panics in [`run_id`], never falls back).
pub fn resolve_run_id(
    var: Result<String, std::env::VarError>,
    random: impl FnOnce() -> String,
) -> Result<String, String> {
    let bad = |v: &dyn std::fmt::Debug| format!("SALLYPORT_TEST_RUN must be 8 of [a-z0-9]: {v:?}");
    match var {
        Ok(v) => parse_run_id(&v).map(str::to_owned).ok_or_else(|| bad(&v)),
        Err(std::env::VarError::NotPresent) => Ok(random()),
        Err(std::env::VarError::NotUnicode(v)) => Err(bad(&v)),
    }
}

/// 8 characters of `[a-z0-9]` from `/dev/urandom` (a slight modulo bias is fine: a label that
/// keeps concurrent runs apart, not a secret).
pub fn random_run_id() -> String {
    let mut b = [0u8; 8];
    std::io::Read::read_exact(&mut std::fs::File::open("/dev/urandom").unwrap(), &mut b).unwrap();
    let alphabet = b"abcdefghijklmnopqrstuvwxyz0123456789";
    b.iter()
        .map(|x| char::from(alphabet[usize::from(*x) % alphabet.len()]))
        .collect()
}

/// `s` if it is a run id: exactly 8 of `[a-z0-9]` (no dash, so `t<run>-` ends the run part).
pub fn parse_run_id(s: &str) -> Option<&str> {
    (s.len() == 8
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()))
    .then_some(s)
}

/// The run part of test image tags: the wrapper's id, or `local` for ad-hoc runs, whose images
/// stay cached and are never swept (architect Q25).
pub fn image_run() -> &'static str {
    if std::env::var_os("SALLYPORT_TEST_RUN").is_some() {
        run_id()
    } else {
        "local"
    }
}

/// `<xdg>/sallyport-test`, created 0700. Panics unless both it and `xdg` are real directories
/// owned by this user with no group or other access (architect Q23): the locks are shared by
/// every worktree of this user, so nobody else may plant or hold them.
pub fn lock_dir_in(xdg: &Path) -> PathBuf {
    let private = |d: &Path| {
        sallyd::sandbox::check_runtime_dir(d)
            .unwrap_or_else(|e| panic!("test lock directory {}: {e}", d.display()));
    };
    private(xdg);
    let dir = xdg.join("sallyport-test");
    match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => panic!("{}: {e}", dir.display()),
    }
    private(&dir);
    dir
}

/// Where the lock `name` lives: `$XDG_RUNTIME_DIR/sallyport-test/<name>.lock`. Read at run time,
/// no fallback: a per-worktree place would let two worktrees' disk tests overlap.
pub fn lock_path(name: &str) -> PathBuf {
    let xdg = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .expect("XDG_RUNTIME_DIR must be set to an absolute path");
    lock_dir_in(&xdg).join(format!("{name}.lock"))
}

/// Opens (creating) a lock file without truncating it, and never through a symlink.
pub fn open_lock(path: &Path) -> std::fs::File {
    use std::os::unix::fs::OpenOptionsExt;
    let nofollow = i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits()).unwrap();
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .custom_flags(nofollow)
        .open(path)
        .unwrap_or_else(|e| panic!("lock {}: {e}", path.display()))
}

/// How long a disk-floor test waits for the [`disk_free_lock`] (maintainer, 9a-2 part 4).
pub const DISK_FREE_WAIT: std::time::Duration = std::time::Duration::from_secs(20 * 60);

/// The `disk-free` lock, exclusive. A local mutation run holds it shared for its whole length
/// (`scripts/disk-lock.sh`): its tree copies and builds move the free space that the disk-floor
/// writer tests set their floor against. Those tests take it exclusively, before the I/O lock.
/// Past [`DISK_FREE_WAIT`] the test fails naming the lock. Back-to-back mutation runs in both
/// lanes can starve it (shared holders win over a polling exclusive one); that ends in the same
/// named failure, never a hang.
pub fn disk_free_lock() -> std::fs::File {
    lock_exclusive_within(
        &lock_path("disk-free"),
        DISK_FREE_WAIT,
        "a local mutation run (scripts/disk-lock.sh) in either lane",
    )
}

/// An exclusive `flock` on `path`, waited for at most `wait`. While it waits it says so once on
/// stderr, naming the lock and its likely `holder`; past `wait` it panics with the same names.
pub fn lock_exclusive_within(
    path: &Path,
    wait: std::time::Duration,
    holder: &str,
) -> std::fs::File {
    let f = open_lock(path);
    let started = std::time::Instant::now();
    let mut told = false;
    loop {
        match rustix::fs::flock(&f, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => return f,
            Err(rustix::io::Errno::WOULDBLOCK) => {}
            Err(e) => panic!("lock {}: {e}", path.display()),
        }
        assert!(
            started.elapsed() < wait,
            "the lock {} was not free within {wait:?}; likely holder: {holder}",
            path.display()
        );
        if !told {
            eprintln!(
                "waiting up to {wait:?} for the lock {}; likely holder: {holder}",
                path.display()
            );
            told = true;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// An exclusive or shared `flock` on [`lock_path`]`(name)`, held until the file is dropped. It
/// works across worktrees, nextest's processes and `cargo test`'s threads alike. Order: the
/// disk-free lock ([`disk_free_lock`]), then the I/O lock, then the image lock; `build` never
/// takes the I/O lock.
pub fn lock(name: &str, exclusive: bool) -> std::fs::File {
    let f = open_lock(&lock_path(name));
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
/// (seen on CI: `podman rm` timing out on a process blocked in I/O). The lock is per user, so
/// two worktrees share it. `flock` gives a waiting exclusive holder no priority: if two runs'
/// shared holders ever starve a disk test, add a turnstile lock rather than a longer timeout
/// (architect Q23 (6); not seen in the two-worktree proof).
pub fn io_lock(exclusive: bool) -> std::fs::File {
    lock("container-io", exclusive)
}

/// Builds `localhost/<name>:<run>-<input key>` once and returns that tag and
/// `localhost/<name>@sha256:…`.
/// `<run>` is [`image_run`]; the key is a hash of every input (the base reference, the entry,
/// the stand-in, the probe source). The build runs under the per-user image lock: a process
/// finding the tag reuses it. So a tag never moves to another image, and an earlier process's
/// `name@digest` always resolves (CI saw "image not known" when parallel builds re-tagged one
/// name). Each run owns its tags: `scripts/test-run.sh` untags only its own afterwards, and
/// `--layers=false` leaves no untagged intermediate images (architect Q25).
fn build(name: &str, entry: &str, shim: Option<&[u8]>) -> (String, String) {
    use std::hash::{Hash, Hasher};
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/redteam/probe/probe.c");
    let mut h = std::hash::DefaultHasher::new();
    (BASE, entry, STAND_IN, std::fs::read(&src).unwrap(), shim).hash(&mut h);
    let tag = format!("localhost/{name}:{}-{:016x}", image_run(), h.finish());
    let _held = lock("test-image", true);
    if !podman(&["image", "exists", &tag]).status.success() {
        build_image(&tag, entry, shim);
    }
    let out = podman(&["image", "inspect", "--format", "{{.Digest}}", &tag]);
    assert!(
        out.status.success(),
        "inspect: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let pinned = format!(
        "localhost/{name}@{}",
        String::from_utf8_lossy(&out.stdout).trim()
    );
    (tag, pinned)
}

/// The `llama-server` stand-in: it idles.
const STAND_IN: &str = "#!/bin/sh\nexec sleep 2147483647\n";

fn build_image(tag: &str, entry: &str, shim: Option<&[u8]>) {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("test-image-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut file = format!(
        "FROM {BASE}\nCOPY entry /opt/sallyport/entry\nCOPY llama-server \
         /usr/local/bin/llama-server\nCOPY probe {PROBE}\n"
    );
    if let Some(bytes) = shim {
        executable(&dir.join("sally-shim"), bytes);
        file.push_str(&format!("COPY sally-shim {SHIM}\n"));
    }
    std::fs::write(dir.join("Containerfile"), file).unwrap();
    executable(&dir.join("entry"), entry.as_bytes());
    executable(&dir.join("llama-server"), STAND_IN.as_bytes());
    probe_binary(&dir.join("probe"));
    let out = podman(&[
        "build",
        "--pull=never",
        "--network=none",
        "--layers=false",
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
    ImageRef::parse(&test_image_built().1).unwrap()
}

/// The tag [`test_image`] was built under: `localhost/sallyport-test:<run>-<input key>`.
pub fn test_image_tag() -> &'static str {
    &test_image_built().0
}

fn test_image_built() -> &'static (String, String) {
    static IMAGE: OnceLock<(String, String)> = OnceLock::new();
    IMAGE.get_or_init(|| build("sallyport-test", "#!/bin/sh\nexec sleep 2147483647\n", None))
}

/// Where the net image keeps the shim.
pub const SHIM: &str = "/usr/local/bin/sally-shim";
/// Where the net image's entry sends the shim's stderr (its readiness line).
pub const SHIM_LOG: &str = "/tmp/shim.log";

/// The static shim, built as `make shim` builds the shipped one. A missing musl target or a
/// failed build fails the test (architect Q15).
fn shim_binary() -> Vec<u8> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let target = "x86_64-unknown-linux-musl";
    // Its own target directory: `cargo test` holds the workspace one's lock while tests run.
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("shim-build");
    let status = Command::new(cargo)
        .current_dir(&root)
        .args([
            "build",
            "-q",
            "--locked",
            "--release",
            "-p",
            "sally-shim",
            "--target",
            target,
        ])
        .arg("--target-dir")
        .arg(&dir)
        // A plain release build even under coverage or a wrapper (Rust review L11).
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("CARGO_BUILD_RUSTFLAGS")
        .env_remove("CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS")
        .env_remove("RUSTC_WRAPPER")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .status()
        .expect("cargo must run");
    assert!(status.success(), "building the musl sally-shim failed");
    std::fs::read(dir.join(format!("{target}/release/sally-shim"))).unwrap()
}

/// `localhost/sallyport-test-net@sha256:…`: [`test_image`] plus the static shim, whose entry
/// starts it with the normative argv (`--listen 127.0.0.1:3128=/run/sallyport/net.sock`, its
/// stderr in [`SHIM_LOG`]) and then idles.
pub fn net_image() -> ImageRef {
    static IMAGE: OnceLock<String> = OnceLock::new();
    let r = IMAGE.get_or_init(|| {
        let entry = format!(
            "#!/bin/sh\n{SHIM} --listen 127.0.0.1:3128=/run/sallyport/net.sock 2>{SHIM_LOG} &\n\
             exec sleep 2147483647\n"
        );
        let shim = shim_binary();
        build("sallyport-test-net", &entry, Some(&shim)).1
    });
    ImageRef::parse(r).unwrap()
}

/// As [`test_image`], but the entry cannot be executed: its interpreter does not exist, so
/// `execve` fails as soon as the container starts, with no shell start-up to race the launcher's
/// grace period (6c-1 Rust review M4).
pub fn exiting_image() -> ImageRef {
    static IMAGE: OnceLock<String> = OnceLock::new();
    let r =
        IMAGE.get_or_init(|| build("sallyport-test-exit", "#!/nonexistent/sh\nexit 3\n", None).1);
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

    /// Every entry's event name and arguments, oldest first.
    pub fn all(&self) -> Vec<(String, serde_json::Value)> {
        self.0.lock().unwrap().clone()
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
    /// The fake network side of every session's egress listener.
    pub egress: Arc<super::egress::FakeEgress>,
    /// Prefix of every session id this fixture makes: `t<run>-<pid>-<n>`, with [`run_id`]
    /// (architect Q24), so every container name carries the run and `Drop` and the wrapper's
    /// sweep remove only their own.
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
        let egress = super::egress::fake_egress(&f.root);
        let launcher = Launcher::new(LauncherParts {
            podman: podman.clone(),
            runtime: runtime.clone(),
            ids: ids(),
            xdg_runtime_dir: xdg.clone(),
            // Well past what the test sessions need; the budget is unit-tested in `overlap.rs`.
            sessions: Arc::new(Sessions::new(1 << 20)),
            audit: events.clone(),
            limits: ScanLimits::default(),
            disk_floor: floor,
            egress: egress.clone(),
            oplog: sallyd::oplog::Oplog::new(std::io::sink()),
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
            egress,
            scope: format!("t{}-{}-{n}", run_id(), std::process::id()),
            _io: io,
        }
    }

    pub fn paths(&self, tag: &str) -> SessionPaths {
        self.session_paths(&format!("{}-{tag}", self.scope))
    }

    /// The directories of session `id` (one the registry made, or [`Lx::paths`]).
    pub fn session_paths(&self, id: &str) -> SessionPaths {
        SessionPaths::new(
            SessionId::parse(id).unwrap(),
            &self.xdg.join("sallyport"),
            &self.f.root.join("home/.local/share/sallyport"),
        )
        .unwrap()
    }

    /// A session registry over this fixture's launcher, appending to `audit`, its session ids
    /// scoped like [`Lx::paths`] (so `Drop` removes its containers).
    pub fn registry(
        &self,
        audit: Arc<dyn AuditSink>,
        default_image: Option<ImageRef>,
    ) -> Arc<Registry> {
        Registry::new(RegistryParts {
            launcher: self.launcher.clone(),
            audit,
            podman: self.podman.clone(),
            ids: ids(),
            sockets: self.xdg.join("sallyport"),
            data: self.f.root.join("home/.local/share/sallyport"),
            default_image,
            oplog: sallyd::oplog::Oplog::new(std::io::sink()),
            // A supervisor panic shows as a missing stop in the test; nobody reads these.
            crash: sallyd::rpc::listen::CrashReporter::channel().0,
            scope: self.scope.clone(),
        })
    }

    pub fn request(&self, v: &ValidatedManifest, tag: &str) -> WorkspaceRequest {
        WorkspaceRequest {
            paths: self.paths(tag),
            manifest: Arc::new(v.clone()),
            default_image: Some(test_image()),
            // A watchdog panic is not what these tests watch; nobody reads the reports.
            crash: sallyd::rpc::listen::CrashReporter::channel().0,
        }
    }

    pub async fn launch(&self, v: &ValidatedManifest, tag: &str) -> Result<Running, LaunchError> {
        self.launcher.launch_workspace(self.request(v, tag)).await
    }

    pub async fn stop(&self, r: Running) {
        self.launcher.stop(r).await.unwrap();
    }

    /// The common argv inputs for a session's directories.
    pub fn common_args(&self, dirs: &SessionDirs) -> CommonArgs {
        CommonArgs {
            runtime: self.runtime.clone(),
            ids: ids(),
            profiles: dirs.profiles().to_owned(),
            hooks_dir: self.podman.hooks_dir(),
            mounts_file: self.podman.mounts_file(),
        }
    }

    /// `podman create <argv>` then `podman start`, both hermetic; the container id.
    pub async fn create_and_start(&self, argv: Vec<String>) -> String {
        let out = self.hermetic(&argv).await;
        let id = out.lines().last().unwrap().to_owned();
        self.hermetic(&["start".to_owned(), id.clone()]).await;
        id
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
