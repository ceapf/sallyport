//! Real-container fixture (rootless Podman) shared by `launch.rs`, `roles.rs` and `rpc.rs`: the
//! test images, a launcher with hermetic podman, and `podman exec`.
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
    AuditSink, CheckedRuntime, CleanupSchedule, CommonArgs, DiskFloor, HarnessRequest, ImageRef,
    InferenceRequest, Installation, InstancePaths, LaunchError, Launcher, LauncherParts, Podman,
    PodmanHost, Running, ScanLimits, SessionDirs, SessionId, SessionPaths, Sessions, UserIds,
    VerifiedModel, WorkspaceRequest, resolve_podman,
};

use sallyd::session::{Registry, RegistryParts};

use super::Fx;

/// The base image CI pulls by digest; everything else is built from it without a network.
pub const BASE: &str = "docker.io/library/alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc";
/// Container name prefixes of every role and of its mount-link probe (`sp-ws-`, `sp-h-`,
/// `sp-infer-`, each also after `sp-probe-`; then the session or instance id).
const PREFIXES: [&str; 6] = [
    "sp-ws-",
    "sp-h-",
    "sp-infer-",
    "sp-probe-ws-",
    "sp-probe-h-",
    "sp-probe-infer-",
];
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

/// A podman wrapper at `<at>/podman`, whose script is `body(at, real)` with both paths as text.
/// The scripts write the paths unescaped, so neither may hold a quote, a backslash or a space.
pub fn wrap_podman(at: &Path, real: &Path, body: impl FnOnce(&str, &str) -> String) -> PathBuf {
    let (at, real) = (at.display().to_string(), real.display().to_string());
    for p in [&at, &real] {
        assert!(
            !p.contains(['\'', '"', '\\', ' ']),
            "the test writes {p:?} into a script unescaped"
        );
    }
    let bin = PathBuf::from(&at).join("podman");
    executable(&bin, body(&at, &real).as_bytes());
    bin
}

/// Removes a test's directory when dropped.
pub struct RemoveOnDrop(pub PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
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

pub use super::locks::*;

/// Builds `localhost/<name>:<run>-<input key>` once and returns that tag and
/// `localhost/<name>@sha256:…`.
/// `<run>` is [`image_run`]; the key is a hash of every input (the base reference, the entry,
/// the stand-in, the probe source). The build runs under the per-user image lock: a process
/// finding the tag reuses it. So a tag never moves to another image, and an earlier process's
/// `name@digest` always resolves (CI saw "image not known" when parallel builds re-tagged one
/// name). Each run owns its tags: `scripts/test-run.sh` untags only its own afterwards, and
/// `--layers=false` leaves no untagged intermediate images (architect Q25).
fn build(name: &str, entry: &str, shim: Option<&[u8]>) -> (String, String) {
    build_with(name, entry, shim, "", None)
}

/// As [`build`], with `extra` appended to the Containerfile and, when `format` is set, built in
/// that image format instead of the default OCI one (both are part of the input key).
fn build_with(
    name: &str,
    entry: &str,
    shim: Option<&[u8]>,
    extra: &str,
    format: Option<&str>,
) -> (String, String) {
    use std::hash::{Hash, Hasher};
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/redteam/probe/probe.c");
    let mut h = std::hash::DefaultHasher::new();
    (BASE, entry, STAND_IN, std::fs::read(&src).unwrap(), shim).hash(&mut h);
    if !extra.is_empty() {
        extra.hash(&mut h);
    }
    // After `extra`, and tagged by `Option`, so no `extra` reads as a format.
    format.hash(&mut h);
    let tag = format!("localhost/{name}:{}-{:016x}", image_run(), h.finish());
    let _held = lock("test-image", true);
    if !podman(&["image", "exists", &tag]).status.success() {
        build_image(&tag, entry, shim, extra, format);
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

fn build_image(tag: &str, entry: &str, shim: Option<&[u8]>, extra: &str, format: Option<&str>) {
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
    file.push_str(extra);
    std::fs::write(dir.join("Containerfile"), file).unwrap();
    executable(&dir.join("entry"), entry.as_bytes());
    executable(&dir.join("llama-server"), STAND_IN.as_bytes());
    probe_binary(&dir.join("probe"));
    let mut args = vec![
        "build",
        "--pull=never",
        "--network=none",
        "--layers=false",
        "--timestamp",
        "0",
        "-q",
    ];
    if let Some(f) = format {
        args.extend(["--format", f]);
    }
    args.extend(["-t", tag, dir.to_str().unwrap()]);
    let out = podman(&args);
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

/// As [`test_image`], with Containerfile lines `extra` (an image config or root filesystem an
/// attacker chose). Same name, its own tag (the input key differs), so `scripts/test-run.sh`
/// untags it with the run's other test images.
pub fn image_with(extra: &str) -> ImageRef {
    // The entry idles, as the stand-in does.
    let (_, pinned) = build_with("sallyport-test", STAND_IN, None, extra, None);
    ImageRef::parse(&pinned).unwrap()
}

/// As [`image_with`], built in Docker format.
#[allow(dead_code)] // Only the image-metadata tests build one.
pub fn docker_image_with(extra: &str) -> ImageRef {
    let (_, pinned) = build_with("sallyport-test", STAND_IN, None, extra, Some("docker"));
    ImageRef::parse(&pinned).unwrap()
}

/// Records every audit entry's event name and arguments; appends of the events named by
/// [`Events::fail`] fail, unrecorded.
#[derive(Default)]
pub struct Events(
    Mutex<Vec<(String, serde_json::Value)>>,
    Mutex<Vec<&'static str>>,
    /// Appends of these events wait (outside every lock) until released.
    Mutex<Vec<&'static str>>,
    /// The event of each append waiting in a hold now, one per append.
    Mutex<Vec<String>>,
    /// Every recorded entry's `Debug` form (which shows its session id), oldest first.
    Mutex<Vec<String>>,
);

impl AuditSink for Events {
    fn append(&self, e: NewEntry, _: AuditLevel) -> Result<(), AuditError> {
        let mut parked = false;
        while self.2.lock().unwrap().contains(&e.event()) {
            if !parked {
                parked = true;
                self.3.lock().unwrap().push(e.event().to_owned());
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        if parked {
            let mut p = self.3.lock().unwrap();
            if let Some(at) = p.iter().position(|x| x == e.event()) {
                p.remove(at);
            }
        }
        if self.1.lock().unwrap().contains(&e.event()) {
            return Err(AuditError::InvalidEntry("fake failure"));
        }
        // The args as a writer with no secrets writes them, declared texts included (Q290).
        let args = e.resolved(&sally_core::audit::Redactor::default());
        self.4.lock().unwrap().push(format!("{e:?}"));
        self.0.lock().unwrap().push((e.event().to_owned(), args));
        Ok(())
    }
}

impl Events {
    /// From now on, appends of `events` fail (an empty list: none does).
    #[allow(dead_code)] // Not every test binary that includes this module fails appends.
    pub fn fail(&self, events: &[&'static str]) {
        *self.1.lock().unwrap() = events.to_vec();
    }

    /// From now on, appends of `events` wait until released (an empty list: none does).
    #[allow(dead_code)] // Not every test binary that includes this module holds appends.
    pub fn hold(&self, events: &[&'static str]) {
        *self.2.lock().unwrap() = events.to_vec();
    }

    /// [`hold`](Self::hold), and a guard that lifts every hold when dropped: a failed assertion
    /// inside the held window then fails the test instead of hanging it (a parked append is a
    /// blocking task, which the runtime's drop waits for).
    #[allow(dead_code)] // Not every test binary that includes this module holds appends.
    pub fn held(&self, events: &[&'static str]) -> Unhold<'_> {
        self.hold(events);
        Unhold(self)
    }
}

/// Lifts every hold of its [`Events`] when dropped ([`Events::held`]).
pub struct Unhold<'a>(&'a Events);

impl Drop for Unhold<'_> {
    fn drop(&mut self) {
        self.0.hold(&[]);
    }
}

impl Events {
    /// Waits until `n` appends of `event` are waiting in a hold; panics after 10 s.
    #[allow(dead_code)] // Not every test binary that includes this module holds appends.
    pub async fn until_parked(&self, event: &str, n: usize) {
        let end = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let now = self
                .3
                .lock()
                .unwrap()
                .iter()
                .filter(|e| *e == event)
                .count();
            if now == n {
                return;
            }
            assert!(
                std::time::Instant::now() < end,
                "{n} appends of {event} never waited in the hold ({now} do)"
            );
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }

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

    /// Every recorded entry's `Debug` form (event, session id; arguments omitted), oldest first.
    #[allow(dead_code)] // Not every test binary that includes this module reads them.
    pub fn debug(&self) -> Vec<String> {
        self.4.lock().unwrap().clone()
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

/// A redactor target that keeps the last redactor it was given.
#[derive(Default)]
pub struct Swapped(Mutex<Option<sally_core::audit::Redactor>>);

impl sallyd::session::secrets::RedactorTarget for Swapped {
    fn set_redactor(&self, redactor: sally_core::audit::Redactor) {
        *self.0.lock().unwrap() = Some(redactor);
    }
}

impl Swapped {
    /// `text` through the last redactor swapped in (unchanged before the first).
    pub fn redact(&self, text: &str) -> String {
        self.0
            .lock()
            .unwrap()
            .as_ref()
            .map_or(text.to_owned(), |r| r.redact_str(text).into_owned())
    }
}

/// What a fixture's launcher varies from production.
#[derive(Clone, Copy)]
struct Knobs {
    /// The failed-launch cleanup's pauses.
    cleanup: CleanupSchedule,
    /// The uid the trust roots file must have (`None`: the test's own).
    roots_owner: Option<u32>,
}

impl Knobs {
    const PRODUCTION: Self = Self {
        cleanup: CleanupSchedule::PRODUCTION,
        roots_owner: None,
    };
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
    /// The launcher's live secrets, and the last redactor they swapped in. The test sink
    /// ([`Events`]) never applies it, so no red-team row is passed by a redaction it does not
    /// name.
    pub redactors: Arc<sallyd::session::secrets::Redactors>,
    pub redacted: Arc<Swapped>,
    /// An operational log that is the redactors' second target, as the daemon's is, and what it
    /// wrote: a registry built over it (`registry_logged`) shows what production's oplog
    /// redacts.
    pub oplog: sallyd::oplog::Oplog,
    pub oplog_lines: super::Lines,
    /// Prefix of every session id this fixture makes: `t<run>-<pid>-<n>`, with [`run_id`]
    /// (architect Q24), so every container name carries the run and `Drop` and the wrapper's
    /// sweep remove only their own.
    pub scope: String,
    /// This fixture's installation id: the label of every container its launcher creates.
    pub installation: Installation,
    /// The launcher's crash receiver: a panic in a task it spawns (a failed launch's retried
    /// cleanup) is read here ([`Lx::assert_no_crash`]), as `sallyd` reads its own.
    crashes: Mutex<sallyd::daemon::crash::CrashReceiver>,
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
    /// ends by running the real one). The wrapper enters as `sandbox.podman_path` would name it:
    /// the root-or-user checks, never the system search's root rule.
    pub fn with_podman(wrap: impl FnOnce(&Path) -> PathBuf) -> Self {
        Self::with_home_and_podman(None, wrap)
    }

    /// [`with_podman`](Self::with_podman), with `cleanup` as the failed-launch cleanup's
    /// pauses in place of the production schedule, passed in as `sallyd` passes its own.
    #[allow(dead_code)] // Only the cleanup tests shorten the schedule.
    pub fn with_podman_and_cleanup(
        wrap: impl FnOnce(&Path) -> PathBuf,
        cleanup: CleanupSchedule,
    ) -> Self {
        let real = resolve_podman(None).unwrap().path().to_owned();
        Self::build_as(
            None,
            None,
            Some(wrap(&real)),
            DiskFloor::default(),
            Some(io_lock(false)),
            None,
            Knobs {
                cleanup,
                ..Knobs::PRODUCTION
            },
        )
    }

    /// [`with_podman`](Self::with_podman), and `podman_home` as the host `$HOME` hermetic podman
    /// is set up from (default: the real one).
    pub fn with_home_and_podman(
        podman_home: Option<PathBuf>,
        wrap: impl FnOnce(&Path) -> PathBuf,
    ) -> Self {
        let real = resolve_podman(None).unwrap().path().to_owned();
        Self::build(
            podman_home,
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

    /// The egress starter requires the trust roots file to be owned by `owner` instead of the
    /// test's own uid (RT-SEC-16's owner case).
    #[allow(dead_code)] // Only RT-SEC-16 changes the required owner.
    pub fn with_roots_owner(owner: u32) -> Self {
        Self::build_as(
            None,
            None,
            None,
            DiskFloor::default(),
            Some(io_lock(false)),
            None,
            Knobs {
                roots_owner: Some(owner),
                ..Knobs::PRODUCTION
            },
        )
    }

    /// The next `sallyd` of this fixture's installation (same id, so the same label): a new
    /// launcher with no live sessions, as after a crash (architect Q64).
    #[allow(dead_code)] // Only the orphan tests play a second sallyd.
    pub fn next_sallyd(&self) -> Self {
        Self::build_as(
            None,
            None,
            None,
            DiskFloor::default(),
            Some(io_lock(false)),
            Some(self.installation.clone()),
            Knobs::PRODUCTION,
        )
    }

    /// [`next_sallyd`](Self::next_sallyd) over a podman wrapper, as
    /// [`with_podman`](Self::with_podman). Its `Drop` still removes leftovers through the real
    /// podman, never the wrapper.
    #[allow(dead_code)] // Only the orphan tests play a second sallyd over a wrapper.
    pub fn next_sallyd_with_podman(&self, wrap: impl FnOnce(&Path) -> PathBuf) -> Self {
        let real = resolve_podman(None).unwrap().path().to_owned();
        Self::build_as(
            None,
            None,
            Some(wrap(&real)),
            DiskFloor::default(),
            Some(io_lock(false)),
            Some(self.installation.clone()),
            Knobs::PRODUCTION,
        )
    }

    fn build(
        podman_home: Option<PathBuf>,
        runtime: Option<&Path>,
        podman_bin: Option<PathBuf>,
        floor: DiskFloor,
        io: Option<std::fs::File>,
    ) -> Self {
        Self::build_as(
            podman_home,
            runtime,
            podman_bin,
            floor,
            io,
            None,
            Knobs::PRODUCTION,
        )
    }

    /// `installation`: `None` for a fresh one, so no two fixtures sweep each other's containers.
    fn build_as(
        podman_home: Option<PathBuf>,
        runtime: Option<&Path>,
        podman_bin: Option<PathBuf>,
        floor: DiskFloor,
        io: Option<std::fs::File>,
        installation: Option<Installation>,
        knobs: Knobs,
    ) -> Self {
        let installation =
            installation.unwrap_or_else(|| Installation::fresh().expect("an installation id"));
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
        // A test wrapper enters as a configured podman, through the product's own resolution
        // (architect Q128): no root-rule bypass.
        let bin = resolve_podman(podman_bin.as_deref()).unwrap();
        let podman = Podman::setup(bin, &runtime, &state, &host).unwrap();
        let events = Arc::new(Events::default());
        let egress = match knobs.roots_owner {
            Some(owner) => super::egress::fake_egress_owned(&f.root, owner),
            None => super::egress::fake_egress(&f.root),
        };
        let redacted = Arc::new(Swapped::default());
        let oplog_lines = super::Lines::default();
        let oplog = sallyd::oplog::Oplog::new(oplog_lines.clone());
        let redactors = Arc::new(sallyd::session::secrets::Redactors::new(vec![
            Arc::clone(&redacted) as Arc<dyn sallyd::session::secrets::RedactorTarget>,
            Arc::new(oplog.clone()) as Arc<dyn sallyd::session::secrets::RedactorTarget>,
        ]));
        let (crash, crashes) = sallyd::daemon::crash::CrashReporter::channel();
        let launcher = Launcher::new(LauncherParts {
            podman: podman.clone(),
            runtime: runtime.clone(),
            ids: ids(),
            xdg_runtime_dir: xdg.clone(),
            data_dir: f.root.join("home/.local/share/sallyport"),
            // Well past what the test sessions need; the budget and the session limit are
            // unit-tested in `overlap.rs`.
            sessions: Arc::new(Sessions::new(
                1 << 20,
                sallyd::sandbox::budget::MAX_LIVE_SESSIONS,
            )),
            audit: events.clone(),
            limits: ScanLimits::default(),
            disk_floor: floor,
            egress: egress.clone(),
            redactors: Arc::clone(&redactors),
            // The same readable oplog as the redactors' second target, so a test reads the
            // launcher's lines too (`session.closed` not audited, for one).
            oplog: oplog.clone(),
            installation: installation.clone(),
            crash,
            cleanup: knobs.cleanup,
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
            redactors,
            redacted,
            oplog,
            oplog_lines,
            scope: format!("t{}-{}-{n}", run_id(), std::process::id()),
            installation,
            crashes: Mutex::new(crashes),
            _io: io,
        }
    }

    /// Fails the test with the panic's task and text if a task the launcher spawned (a failed
    /// launch's retried cleanup) has panicked, so a test waiting on that task fails at once
    /// rather than at its bound. `Drop` checks it too.
    pub fn assert_no_crash(&self) {
        let got = self
            .crashes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .try_recv();
        if let Ok(c) = got {
            panic!("task {} panicked: {}", c.task, c.payload);
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
        self.registry_logged(
            audit,
            default_image,
            sallyd::oplog::Oplog::new(std::io::sink()),
        )
    }

    /// [`registry`](Self::registry) with its operational log written to `oplog`; the production
    /// hub with no watcher, so every prompt is denied `no-approver`.
    pub fn registry_logged(
        &self,
        audit: Arc<dyn AuditSink>,
        default_image: Option<ImageRef>,
        oplog: sallyd::oplog::Oplog,
    ) -> Arc<Registry> {
        let hub = Arc::new(sallyd::approvals::hub::Hub::default());
        self.registry_hub(audit, default_image, oplog, hub)
    }

    /// [`registry_logged`](Self::registry_logged) with its prompts going to `hub`.
    pub fn registry_hub(
        &self,
        audit: Arc<dyn AuditSink>,
        default_image: Option<ImageRef>,
        oplog: sallyd::oplog::Oplog,
        hub: Arc<sallyd::approvals::hub::Hub>,
    ) -> Arc<Registry> {
        Registry::new(RegistryParts {
            launcher: self.launcher.clone(),
            audit,
            podman: self.podman.clone(),
            ids: ids(),
            sockets: self.xdg.join("sallyport"),
            data: self.f.root.join("home/.local/share/sallyport"),
            default_image,
            oplog,
            approver: hub,
            // A supervisor panic shows as a missing stop in the test; nobody reads these.
            crash: sallyd::daemon::crash::CrashReporter::channel().0,
            scope: self.scope.clone(),
        })
    }

    pub fn request(&self, v: &ValidatedManifest, tag: &str) -> WorkspaceRequest {
        WorkspaceRequest {
            paths: self.paths(tag),
            manifest: Arc::new(v.clone()),
            default_image: Some(test_image()),
            // A watchdog panic is not what these tests watch; nobody reads the reports.
            crash: sallyd::daemon::crash::CrashReporter::channel().0,
        }
    }

    pub async fn launch(&self, v: &ValidatedManifest, tag: &str) -> Result<Running, LaunchError> {
        self.launcher.launch_workspace(self.request(v, tag)).await
    }

    pub async fn stop(&self, r: Running) {
        // A launcher-level stop: no registry, so no `session.closed` (the token is dropped).
        let _done = self.launcher.stop(r).await.unwrap();
    }

    /// Whether `podman ps --all` lists a container of this fixture: its scope is part of every
    /// session id, so of every container name. The probe of the "nothing was created" checks; a
    /// failed `ps` panics at the check itself, so it never reads as "nothing was created".
    #[allow(dead_code)] // Only the launch-refusal tests probe for created containers.
    pub fn listed(&self) -> bool {
        let out = podman(&["ps", "--all", "--format", "{{.Names}}"]);
        listed_names(&out).iter().any(|n| self.owns(n))
    }

    /// Whether a container name is one of this fixture's: a known prefix, then the scope and a
    /// dash, so scope `…-1` never matches `…-10`. The one match of [`Lx::listed`] and `Drop`.
    fn owns(&self, name: &str) -> bool {
        PREFIXES
            .iter()
            .any(|p| name.starts_with(&format!("{p}{}-", self.scope)))
    }

    /// The control of a "nothing was created" check (#122): `v`, which the launcher accepts,
    /// launched as `tag` on this fixture is [`Lx::listed`], and is no longer once stopped. Returns
    /// the number of audit entries written so far, so a refusal's entries can be read after them.
    #[allow(dead_code)] // Only the launch-refusal tests probe for created containers.
    pub async fn listed_control(&self, v: &ValidatedManifest, tag: &str) -> usize {
        assert!(!self.listed(), "control: listed before any launch");
        let r = self.launch(v, tag).await.expect("control: the launch");
        assert!(self.listed(), "control: the launched container is listed");
        self.stop(r).await;
        assert!(!self.listed(), "control: still listed after its stop");
        self.events.list().len()
    }

    /// The harness request of the session `tag` (its workspace launched first).
    #[allow(dead_code)] // Only the role launch tests launch a harness.
    pub fn harness(&self, v: &ValidatedManifest, tag: &str) -> HarnessRequest {
        HarnessRequest {
            paths: self.paths(tag),
            manifest: Arc::new(v.clone()),
            default_image: Some(test_image()),
        }
    }

    /// A CPU inference request for instance `tag` serving `model`.
    #[allow(dead_code)] // Only the role launch tests launch inference.
    pub fn inference(&self, model: VerifiedModel, tag: &str) -> InferenceRequest {
        InferenceRequest {
            instance: SessionId::parse(&format!("{}-{tag}", self.scope)).unwrap(),
            model,
            image: test_image(),
            gpu: false,
            gpu_layers: 0,
            context: 512,
            cpus: sally_core::manifest::Cpus::from_millis(1000),
            memory: None,
            level: AuditLevel::default(),
        }
    }

    /// A model blob (the stand-in `llama-server` never reads it) pinned from this fixture's
    /// library.
    #[allow(dead_code)] // Only the role launch tests launch inference.
    pub fn model(&self) -> VerifiedModel {
        let blobs = self.f.root.join("blobs");
        let digest = "a".repeat(64);
        let blob = blobs.join("sha256").join(&digest);
        if !blob.exists() {
            std::fs::create_dir_all(blob.parent().unwrap()).unwrap();
            std::fs::write(&blob, b"GGUF").unwrap();
            std::fs::set_permissions(&blob, std::fs::Permissions::from_mode(0o444)).unwrap();
        }
        VerifiedModel::pin(&blobs, &digest).unwrap()
    }

    /// The instance paths of inference instance `tag`.
    #[allow(dead_code)] // Only the role launch tests launch inference.
    pub fn instance_paths(&self, tag: &str) -> InstancePaths {
        InstancePaths::under(
            SessionId::parse(&format!("{}-{tag}", self.scope)).unwrap(),
            &self.xdg.join("sallyport"),
            &self.f.root.join("home/.local/share/sallyport"),
        )
        .unwrap()
    }

    /// The common argv inputs for a session's directories.
    pub fn common_args(&self, dirs: &SessionDirs) -> CommonArgs {
        CommonArgs {
            runtime: self.runtime.clone(),
            ids: ids(),
            profiles: dirs.profiles().to_owned(),
            hooks_dir: self.podman.hooks_dir(),
            mounts_file: self.podman.mounts_file(),
            installation: self.installation.clone(),
        }
    }

    /// `podman create <argv>`, `podman init`, then `podman start`, all hermetic, in the
    /// launcher's order (conmon, and a `--timeout` clock, start at `init`); the container id.
    pub async fn create_and_start(&self, argv: Vec<String>) -> String {
        let out = self.hermetic(&argv).await;
        let id = out.lines().last().unwrap().to_owned();
        self.hermetic(&["init".to_owned(), id.clone()]).await;
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

    /// A red-team control (#122, architect Q155): the product-built workspace argv for `v` and
    /// session `tag` with exactly one defence left out (`leave_out`), created and started by
    /// hermetic podman outside the launcher; the container id. The container carries the
    /// session's name, so the fixture removes it.
    #[allow(dead_code)] // Only the escape, launch and session tests run workspace controls.
    pub async fn control_workspace(
        &self,
        v: &ValidatedManifest,
        tag: &str,
        leave_out: LeaveOut<'_>,
    ) -> String {
        let argv = self.product_workspace_argv(v, tag, &test_image());
        self.control(argv, leave_out).await
    }

    /// [`Lx::control_workspace`] from `image` (an [`image_with`] image) instead of the test
    /// image. The [`LeaveOut`] variants that add binds need the test image, so they panic here.
    #[allow(dead_code)] // Only the escape tests run image controls.
    pub async fn control_workspace_image(
        &self,
        v: &ValidatedManifest,
        tag: &str,
        image: &ImageRef,
        leave_out: LeaveOut<'_>,
    ) -> String {
        assert!(
            !matches!(leave_out, LeaveOut::Bind { .. } | LeaveOut::Binds(_)),
            "an image control adds no bind (they are placed before the test image)"
        );
        let argv = self.product_workspace_argv(v, tag, image);
        self.control(argv, leave_out).await
    }

    /// The product-built workspace argv for `v`, session `tag` and `image`, its directories
    /// made.
    fn product_workspace_argv(
        &self,
        v: &ValidatedManifest,
        tag: &str,
        image: &ImageRef,
    ) -> Vec<String> {
        let paths = self.paths(tag);
        let dirs = SessionDirs::create(&paths, &self.xdg, &[], 0).unwrap();
        let scan = sallyd::sandbox::scan_mounts(v, &ScanLimits::default()).unwrap();
        sallyd::sandbox::workspace_argv(&self.common_args(&dirs), &paths, v, &scan, Some(image))
            .unwrap()
    }

    /// RT-AG-16 (#92, architect Q196): the product-built workspace argv for `v` and session
    /// `tag`, checked to carry exactly one `--timeout` of `runtime.timeout` + 300 s, with that
    /// value replaced by `secs` (a short stand-in), created and started by hermetic podman with
    /// no `sallyd` at all; the container id.
    #[allow(dead_code)] // Only the launch tests run the backstop.
    pub async fn backstop_workspace(&self, v: &ValidatedManifest, tag: &str, secs: u64) -> String {
        let mut argv = self.product_workspace_argv(v, tag, &test_image());
        let at = only_flag(&argv, "--timeout", "--timeout");
        let want = v.manifest().runtime.timeout.as_secs() + 300;
        let got = value_after(&argv, at, "the product backstop");
        assert_eq!(got, want.to_string(), "the product backstop");
        argv[at + 1] = secs.to_string();
        self.create_and_start(argv).await
    }

    /// [`Lx::control_workspace`] for any role: `argv` is a product builder's output
    /// (`workspace_argv`, `harness_argv` or `inference_argv`), never one written by hand.
    ///
    /// A [`LeaveOut::Bind`] source must lie strictly below this fixture's root (it panics
    /// otherwise), so a control never mounts anything of the real host.
    #[allow(dead_code)] // Only the escape, launch, roles and session tests run controls.
    pub async fn control(&self, argv: Vec<String>, leave_out: LeaveOut<'_>) -> String {
        let argv = self.left_out(argv, leave_out);
        self.create_and_start(argv).await
    }

    /// The product-built `argv` with exactly the defence `leave_out` left out, as
    /// [`Lx::control`] creates it.
    #[allow(dead_code)] // Only the escape, launch, oci, roles and session tests run controls.
    pub fn left_out(&self, mut argv: Vec<String>, leave_out: LeaveOut<'_>) -> Vec<String> {
        match leave_out {
            LeaveOut::Bind { host, guest } => self.add_binds(&mut argv, &[(host, guest)]),
            LeaveOut::Binds(binds) => self.add_binds(&mut argv, binds),
            LeaveOut::Source { guest, host } => {
                let host = self.below_root(host);
                let suffix = format!(":{guest}:");
                let spec = argv.iter_mut().find(|a| a.contains(&suffix)).unwrap();
                let (_, options) = spec.split_once(&suffix).unwrap();
                *spec = format!("{}{suffix}{options}", host.display());
            }
            LeaveOut::NonRecursive { guest } => {
                let suffix = format!(":{guest}:");
                let spec = argv
                    .iter_mut()
                    .find(|a| a.contains(&suffix) && a.ends_with(",bind"))
                    .unwrap();
                let recursive = format!("{}rbind", spec.strip_suffix("bind").unwrap());
                *spec = recursive;
            }
            LeaveOut::Timeout => {
                let at = only_flag(&argv, "--timeout", "--timeout");
                value_after(&argv, at, "the product backstop");
                argv.drain(at..at + 2);
            }
            LeaveOut::Workdir => {
                let at = only_flag(&argv, "--workdir", "--workdir");
                let dir = value_after(&argv, at, "the product working directory");
                assert_eq!(dir, "/", "the product working directory");
                argv.drain(at..at + 2);
            }
            LeaveOut::ImageVolume => {
                let at = only_flag(&argv, "--image-volume", "--image-volume=ignore");
                argv.remove(at);
            }
            LeaveOut::Healthcheck => {
                let at = only_flag(&argv, "--no-healthcheck", "--no-healthcheck");
                argv.remove(at);
            }
            LeaveOut::Probe => {}
        }
        argv
    }

    /// `path` canonicalized; panics unless it lies strictly below this fixture's root.
    fn below_root(&self, path: &Path) -> PathBuf {
        let root = self.f.root.canonicalize().unwrap();
        let path = path.canonicalize().unwrap();
        assert!(
            path != root && path.starts_with(&root),
            "a control binds only below the fixture root: {}",
            path.display()
        );
        path
    }

    /// Inserts one `ro` bind per `(host, guest)` just before the argv's image.
    fn add_binds(&self, argv: &mut Vec<String>, binds: &[(&Path, &str)]) {
        let image = test_image();
        let at = argv.iter().position(|a| a == image.as_str()).unwrap();
        let specs = binds.iter().flat_map(|(host, guest)| {
            let host = self.below_root(host);
            [
                "-v".to_owned(),
                format!("{}:{guest}:ro,nosuid,nodev,bind", host.display()),
            ]
        });
        let specs: Vec<String> = specs.collect();
        argv.splice(at..at, specs);
    }
}

/// The one defence a [`Lx::control`] container leaves out: an edit of the product argv, or (for
/// [`LeaveOut::Probe`]) a launcher-side check, with the argv unedited.
#[allow(dead_code)] // Only the escape, launch, roles and session tests run controls.
pub enum LeaveOut<'a> {
    /// The mount set: one more `ro` bind of `host` (below the fixture root) at `guest`.
    Bind { host: &'a Path, guest: &'a str },
    /// The mount set, for one class of host state (architect Q167): one `ro` bind per
    /// `(host, guest)`, each below the fixture root.
    Binds(&'a [(&'a Path, &'a str)]),
    /// The mount set at `guest`: its bind's source becomes `host` (below the fixture root).
    Source { guest: &'a str, host: &'a Path },
    /// Non-recursive binds: the bind at `guest` becomes `rbind`.
    NonRecursive { guest: &'a str },
    /// The conmon backstop (#92): `--timeout` and its value are removed.
    Timeout,
    /// The fixed working directory: `--workdir` and its value are removed, so the image's own
    /// working directory applies.
    Workdir,
    /// Disabled image volumes: `--image-volume=ignore` is removed, so the image's volumes are
    /// created.
    ImageVolume,
    /// Disabled image health checks: `--no-healthcheck` is removed, so the image's health check
    /// applies.
    Healthcheck,
    /// The mount-link probe (security review): the argv is unedited. Running it outside the
    /// launcher leaves out every launcher-side check, and of those only the probe runs before
    /// `init`, so it is the one defence left out of what the runtime does at `init`.
    Probe,
}

/// The index of the argv's one argument starting with `flag`; panics unless there is exactly
/// one such argument and it is exactly `token` (the flag alone when its value follows as the
/// next token, or `flag=value`).
fn only_flag(argv: &[String], flag: &str, token: &str) -> usize {
    let at: Vec<usize> = argv
        .iter()
        .enumerate()
        .filter(|(_, a)| a.starts_with(flag))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(at.len(), 1, "exactly one {flag} in {argv:?}");
    assert_eq!(argv[at[0]], token, "{flag} is {token}");
    at[0]
}

/// The token after `argv[at]` (a two-token flag's value); panics, naming `what`, when the
/// argv ends there.
fn value_after<'a>(argv: &'a [String], at: usize, what: &str) -> &'a str {
    argv.get(at + 1)
        .map(String::as_str)
        .unwrap_or_else(|| panic!("{what}: no value after {}", argv[at]))
}

/// Whether `podman ps --all` lists a container named exactly `name`; a failed `ps` panics, so
/// it never reads as "gone".
#[allow(dead_code)] // Only the launch tests probe one name.
pub fn listed_name(name: &str) -> bool {
    let out = podman(&["ps", "--all", "--format", "{{.Names}}"]);
    listed_names(&out).iter().any(|n| n == name)
}

/// The names a `podman ps --all --format {{.Names}}` run printed. Its status is checked at the
/// moment of the probe: a failed `ps` panics, so it never reads as "nothing listed".
fn listed_names(out: &std::process::Output) -> Vec<String> {
    assert!(
        out.status.success(),
        "podman ps: {} ({})",
        out.status,
        String::from_utf8_lossy(&out.stderr).trim()
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_owned)
        .collect()
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
            if self.owns(name) {
                // With its anonymous volumes: a control without `--image-volume=ignore` makes
                // them.
                let _ = podman(&["rm", "--force", "--volumes", "--time", "0", name]);
            }
        }
        let _ = podman(&["unshare", "rm", "-rf", "--", self.f.root.to_str().unwrap()]);
        // A panic a test never waited on still fails it, after the cleanup above.
        if !std::thread::panicking() {
            self.assert_no_crash();
        }
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

/// Whether `container` exists. `podman container exists` exits 0 when it does and 1 when it does
/// not; any other status is podman failing, which panics rather than reading as gone.
pub fn exists(container: &str) -> bool {
    let out = podman(&["container", "exists", container]);
    match out.status.code() {
        Some(0) => true,
        Some(1) => false,
        _ => panic!(
            "podman container exists {container}: {} ({})",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ),
    }
}

pub fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}
