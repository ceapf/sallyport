//! Task 6b with real containers (rootless Podman): the hardened launch, teardown, the B4 overlap
//! rule and post-init mount check, hermetic podman (#11), RT-FS-12 variants (EBUSY parents),
//! RT-FS-13 (socket in a mount) and RT-FS-16 (a nested host mount is not visible).
//!
//! These tests never skip: without podman or the base image they fail. CI pulls the base image
//! by digest first (`ci.yml`); the test image is built from it offline.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock};

use sally_core::audit::{AuditError, NewEntry};
use sally_core::manifest::{AuditLevel, ValidatedManifest};
use sallyd::sandbox::{
    AuditSink, CheckedRuntime, Expect, ImageRef, LaunchError, Launcher, LauncherParts, Podman,
    PodmanHost, Running, ScanLimits, SessionId, SessionPaths, Sessions, UserIds, WorkspaceRequest,
    check_in_container, resolve_podman,
};

mod common;
use common::*;

/// The base image CI pulls by digest; everything else is built from it without a network.
const BASE: &str = "docker.io/library/alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc";

fn podman(args: &[&str]) -> std::process::Output {
    Command::new("podman")
        .args(args)
        .output()
        .expect("podman must be installed")
}

/// `localhost/sallyport-test@sha256:…`: the base image plus `/opt/sallyport/entry`, which idles.
fn test_image() -> ImageRef {
    static IMAGE: OnceLock<String> = OnceLock::new();
    let r = IMAGE.get_or_init(|| {
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("sallyport-test-image");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("Containerfile"),
            format!("FROM {BASE}\nCOPY entry /opt/sallyport/entry\n"),
        )
        .unwrap();
        std::fs::write(dir.join("entry"), "#!/bin/sh\nexec sleep 2147483647\n").unwrap();
        std::fs::set_permissions(dir.join("entry"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        let out = podman(&[
            "build",
            "--pull=never",
            "--network=none",
            "-q",
            "-t",
            "localhost/sallyport-test:6b",
            dir.to_str().unwrap(),
        ]);
        assert!(
            out.status.success(),
            "build: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let out = podman(&[
            "image",
            "inspect",
            "--format",
            "{{.Digest}}",
            "localhost/sallyport-test:6b",
        ]);
        format!(
            "localhost/sallyport-test@{}",
            String::from_utf8_lossy(&out.stdout).trim()
        )
    });
    ImageRef::parse(r).unwrap()
}

/// Records every audit entry's event name.
#[derive(Default)]
struct Events(Mutex<Vec<String>>);

impl AuditSink for Events {
    fn append(&self, e: NewEntry, _: AuditLevel) -> Result<(), AuditError> {
        let line = format!("{e:?}");
        let event = line
            .split("event: \"")
            .nth(1)
            .and_then(|r| r.split('"').next())
            .unwrap_or_default()
            .to_owned();
        self.0.lock().unwrap().push(event);
        Ok(())
    }
}

impl Events {
    fn list(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
}

struct Lx {
    f: Fx,
    launcher: Launcher,
    events: Arc<Events>,
    xdg: PathBuf,
}

fn host_env(var: &str) -> Option<PathBuf> {
    std::env::var_os(var).map(PathBuf::from)
}

impl Lx {
    fn new() -> Self {
        Self::with_home(None)
    }

    /// `podman_home`: the `$HOME` hermetic podman is given (default: the real one).
    fn with_home(podman_home: Option<PathBuf>) -> Self {
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
        let runtime = CheckedRuntime::check(Path::new(
            &std::env::var("SALLYPORT_TEST_RUNTIME").unwrap_or_else(|_| "/usr/bin/crun".into()),
        ))
        .unwrap();
        let state = f.root.join("home/.local/share/sallyport/podman");
        std::fs::create_dir_all(state.parent().unwrap()).unwrap();
        let bin = resolve_podman(None, std::env::var_os("PATH").as_deref()).unwrap();
        let podman = Podman::setup(bin, &runtime, &state, &host).unwrap();
        let events = Arc::new(Events::default());
        let launcher = Launcher::new(LauncherParts {
            podman,
            runtime,
            ids: UserIds {
                uid: rustix::process::getuid().as_raw(),
                gid: rustix::process::getgid().as_raw(),
            },
            xdg_runtime_dir: xdg.clone(),
            sessions: Arc::new(Sessions::default()),
            audit: events.clone(),
            limits: ScanLimits::default(),
        });
        Self {
            f,
            launcher,
            events,
            xdg,
        }
    }

    fn paths(&self, tag: &str) -> SessionPaths {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let id = SessionId::parse(&format!("t{}-{n}-{tag}", std::process::id())).unwrap();
        SessionPaths::new(
            id,
            &self.xdg.join("sallyport"),
            &self.f.root.join("home/.local/share/sallyport"),
        )
        .unwrap()
    }

    async fn launch(&self, v: &ValidatedManifest, tag: &str) -> Result<Running, LaunchError> {
        self.launcher
            .launch_workspace(WorkspaceRequest {
                paths: self.paths(tag),
                manifest: v.clone(),
                default_image: test_image(),
            })
            .await
    }
}

impl Drop for Lx {
    /// Overlay work directories belong to the container's user namespace.
    fn drop(&mut self) {
        let _ = podman(&["unshare", "rm", "-rf", "--", self.f.root.to_str().unwrap()]);
    }
}

/// `podman exec` in the container: (exit code, stdout + stderr).
fn exec(r: &Running, script: &str) -> (i32, String) {
    let out = podman(&["exec", &r.container, "sh", "-c", script]);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.code().unwrap_or(-1), text)
}

fn exists(container: &str) -> bool {
    podman(&["container", "exists", container]).status.success()
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn a_launch_is_hardened_audited_and_torn_down() {
    rt().block_on(async {
        let x = Lx::new();
        x.f.tree("code/myproject", &[".git"], &[]);
        let v = x.f.load(&mounts(&[
            mount("~/code/myproject", "/workspace/p", "rw"),
            mount("~/code/other", "/workspace/o", "staged"),
            mount("~/Documents/research", "/workspace/r", "ro"),
        ]));
        let r = x.launch(&v, "ok").await.unwrap();
        let (code, out) = exec(
            &r,
            "id -u; grep CapEff /proc/self/status; grep NoNewPrivs /proc/self/status; \
             grep Seccomp: /proc/self/status; ls /workspace; touch /workspace/r/x 2>&1; \
             echo staged > /workspace/o/new; echo ok > /workspace/p/.git/probe; \
             cat /proc/net/route 2>/dev/null | wc -l",
        );
        assert_eq!(code, 0, "{out}");
        let uid = rustix::process::getuid().as_raw().to_string();
        assert!(out.starts_with(&format!("{uid}\n")), "{out}");
        assert!(out.contains("CapEff:\t0000000000000000"), "{out}");
        assert!(out.contains("NoNewPrivs:\t1"), "{out}");
        assert!(out.contains("Seccomp:\t2"), "{out}");
        assert!(out.contains("Read-only file system"), "{out}");
        // Staged and .git writes land in session scratch, never on the host.
        let home = x.f.root.join("home");
        assert!(!home.join("code/other/new").exists());
        assert!(!home.join("code/myproject/.git/probe").exists());
        let data = r.paths.data_root().to_owned();
        let sockets = r.paths.socket_root().to_owned();
        assert_eq!(x.events.list(), ["sandbox.launch"]);
        let container = r.container.clone();
        x.launcher.stop(r).await.unwrap();
        assert!(!exists(&container));
        assert!(!data.join("git").exists() && !data.join("profiles").exists());
        assert!(
            data.join("stage/1/upper/new").exists(),
            "staged changes are kept"
        );
        assert!(!sockets.exists());
        assert_eq!(x.events.list(), ["sandbox.launch", "sandbox.stop"]);
    });
}

/// RT-FS-13 at launch: refused before anything is created, and audited.
#[test]
fn rt_fs_13_a_socket_in_a_mount_refuses_the_launch() {
    rt().block_on(async {
        let x = Lx::new();
        let dir = x.f.root.join("home/code/myproject");
        let short = std::env::temp_dir().join(format!("sp-l-{}", std::process::id()));
        let _ = std::fs::remove_file(&short);
        std::os::unix::fs::symlink(&dir, &short).unwrap();
        let _l = std::os::unix::net::UnixListener::bind(short.join("agent.sock")).unwrap();
        std::fs::remove_file(&short).unwrap();
        let v =
            x.f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", "ro")]));
        let e = x.launch(&v, "sock").await.unwrap_err();
        assert!(e.to_string().contains("socket-in-mount"), "{e}");
        assert_eq!(x.events.list(), ["sandbox.refuse"]);
        let out = podman(&["ps", "-a", "--format", "{{.Names}}"]);
        let names = String::from_utf8_lossy(&out.stdout);
        assert!(!names.lines().any(|n| n.ends_with("-sock")), "{names}");
    });
}

/// AMENDMENTS-02 B4 (RT-AG-08b): a second live session may not overlap a writable mount.
#[test]
fn overlapping_sessions_are_refused_while_the_first_is_live() {
    rt().block_on(async {
        let x = Lx::new();
        std::fs::create_dir_all(x.f.root.join("home/code/myproject/sub")).unwrap();
        let a =
            x.f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", "rw")]));
        let b = x.f.load(&mounts(&[mount(
            "~/code/myproject/sub",
            "/workspace/s",
            "ro",
        )]));
        let ra = x.launch(&a, "a").await.unwrap();
        let e = x.launch(&b, "b").await.unwrap_err();
        assert!(matches!(e, LaunchError::Overlap(_)), "{e}");
        x.launcher.stop(ra).await.unwrap();
        let rb = x.launch(&b, "b2").await.unwrap();
        x.launcher.stop(rb).await.unwrap();
        assert_eq!(
            x.events.list(),
            [
                "sandbox.launch",
                "sandbox.refuse",
                "sandbox.stop",
                "sandbox.launch",
                "sandbox.stop"
            ]
        );
    });
}

/// The B4 post-init check sees the container's mounts from the host: a correct expectation
/// passes, any other identity is a mismatch.
#[test]
fn the_in_container_check_compares_identities_from_the_host() {
    rt().block_on(async {
        let x = Lx::new();
        x.f.tree("code/myproject", &[], &["m/.git"]);
        let v =
            x.f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", "rw")]));
        let r = x.launch(&v, "pin").await.unwrap();
        let out = podman(&["inspect", "--format", "{{.State.Pid}}", &r.container]);
        let pid: u32 = String::from_utf8_lossy(&out.stdout).trim().parse().unwrap();
        let id = |rel: &str| {
            use std::os::unix::fs::MetadataExt;
            let m =
                std::fs::symlink_metadata(x.f.root.join("home/code/myproject").join(rel)).unwrap();
            (m.dev(), m.ino())
        };
        let want = |guest: &str, (dev, ino): (u64, u64)| Expect {
            guest: guest.into(),
            dev,
            ino,
        };
        check_in_container(
            pid,
            &[
                want("/workspace/p", id("")),
                want("/workspace/p/m/.git", id("m/.git")),
            ],
        )
        .unwrap();
        let wrong = check_in_container(pid, &[want("/workspace/p/m", id("m/.git"))]).unwrap_err();
        assert!(wrong.to_string().contains("pinned"), "{wrong}");
        let missing = check_in_container(pid, &[want("/workspace/nothing", id(""))]).unwrap_err();
        assert!(
            missing.to_string().contains("cannot be opened"),
            "{missing}"
        );
        x.launcher.stop(r).await.unwrap();
    });
}

/// RT-FS-12 variants (security review of 6a): parents of a nested repository and of a submodule
/// pointer cannot be renamed away (EBUSY); `.git` writes stay in the overlay; the pointer file is
/// read-only; the host `.git` is byte-identical.
#[test]
fn rt_fs_12_git_shields_hold_inside_the_container() {
    rt().block_on(async {
        let x = Lx::new();
        x.f.tree("code/myproject", &["sub/.git/hooks"], &["mod/.git"]);
        let host = x.f.root.join("home/code/myproject");
        std::fs::write(host.join("sub/.git/config"), "[core]\n").unwrap();
        let v =
            x.f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", "rw")]));
        let r = x.launch(&v, "git").await.unwrap();
        let (_, out) = exec(
            &r,
            "cd /workspace/p; mv sub sub2; echo mv-sub=$?; mv mod mod2; echo mv-mod=$?; \
             printf '#!/bin/sh\\ntouch /tmp/pwned\\n' > sub/.git/hooks/pre-commit; echo hook=$?; \
             echo '[core] fsmonitor = evil' >> sub/.git/config; echo cfg=$?; \
             echo gitdir: /etc > mod/.git; echo ptr=$?",
        );
        assert!(
            out.contains("mv-sub=1") && out.contains("mv-mod=1"),
            "{out}"
        );
        assert!(
            out.contains("Resource busy") || out.contains("busy"),
            "{out}"
        );
        assert!(
            out.contains("hook=0") && out.contains("cfg=0"),
            "overlay accepts writes: {out}"
        );
        assert!(out.contains("ptr=1") || out.contains("ptr=2"), "{out}");
        assert!(!host.join("sub/.git/hooks/pre-commit").exists());
        assert_eq!(
            std::fs::read_to_string(host.join("sub/.git/config")).unwrap(),
            "[core]\n"
        );
        assert_eq!(
            std::fs::read_to_string(host.join("mod/.git")).unwrap(),
            "gitdir: elsewhere\n"
        );
        x.launcher.stop(r).await.unwrap();
    });
}

/// Removes a mount made in podman's rootless namespace, even when the test fails.
struct NestedMount(PathBuf);

impl Drop for NestedMount {
    fn drop(&mut self) {
        let _ = podman(&["unshare", "umount", self.0.to_str().unwrap()]);
    }
}

/// RT-FS-16: a filesystem mounted below a granted directory (an sshfs, a drive, a bind of a
/// secret folder) is not visible in the sandbox, in every mount mode: binds are non-recursive and
/// overlays take one filesystem. The nested mount is made in podman's own mount namespace, where
/// the runtime builds the container.
#[test]
fn rt_fs_16_a_nested_host_mount_is_not_visible() {
    rt().block_on(async {
        let x = Lx::new();
        let granted = x.f.root.join("home/code/myproject");
        let secret = x.f.root.join("secret");
        std::fs::create_dir_all(granted.join("nested")).unwrap();
        std::fs::create_dir_all(&secret).unwrap();
        std::fs::write(secret.join("canary"), "NESTED-SECRET").unwrap();
        let out = podman(&[
            "unshare",
            "mount",
            "--bind",
            secret.to_str().unwrap(),
            granted.join("nested").to_str().unwrap(),
        ]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let _guard = NestedMount(granted.join("nested"));
        let check = podman(&[
            "unshare",
            "cat",
            granted.join("nested/canary").to_str().unwrap(),
        ]);
        assert_eq!(
            String::from_utf8_lossy(&check.stdout),
            "NESTED-SECRET",
            "the nested mount exists"
        );
        for mode in ["ro", "rw", "brokered"] {
            let v =
                x.f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", mode)]));
            let r = x.launch(&v, mode).await.unwrap();
            let (_, out) = exec(
                &r,
                "ls -a /workspace/p/nested; cat /workspace/p/nested/canary 2>&1",
            );
            assert!(!out.contains("NESTED-SECRET"), "{mode}: {out}");
            assert!(out.contains("No such file"), "{mode}: {out}");
            x.launcher.stop(r).await.unwrap();
        }
        // `staged`: Podman 4.9.3 refuses an overlay whose lower directory has a mount inside it
        // in the keep-id user namespace (EINVAL, probed in Task 6b), so the launch is refused
        // after `init` and nothing ever runs.
        let v = x.f.load(&mounts(&[mount(
            "~/code/myproject",
            "/workspace/p",
            "staged",
        )]));
        let e = x.launch(&v, "staged").await.unwrap_err();
        assert!(
            matches!(e, LaunchError::Command { verb: "init", .. }),
            "{e}"
        );
        assert_eq!(
            x.events.list().last().map(String::as_str),
            Some("sandbox.refuse")
        );
    });
}

/// #11: a hostile user `containers.conf`, `mounts.conf` and `storage.conf` under the `$HOME`
/// podman is given have no effect: `CONTAINERS_CONF` replaces them and `XDG_CONFIG_HOME` is
/// Sallyport's own empty directory. (RT-SUP-04 with the OCI config verifier: Task 14, #15.)
#[test]
fn hostile_user_podman_configuration_is_ignored() {
    let fx_home = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("hostile-home-{}", std::process::id()));
    let conf = fx_home.join(".config/containers");
    std::fs::create_dir_all(conf.join("oci/hooks.d")).unwrap();
    let leak = fx_home.join("leak");
    std::fs::create_dir_all(&leak).unwrap();
    std::fs::write(leak.join("canary"), "HOSTILE").unwrap();
    std::fs::write(
        conf.join("containers.conf"),
        format!(
            "[containers]\nvolumes = [\"{}:/hostile:rw\"]\ndefault_capabilities = [\"SYS_ADMIN\", \"NET_RAW\"]\nenv = [\"HOSTILE=1\"]\nnetns = \"host\"\n",
            leak.display()
        ),
    )
    .unwrap();
    std::fs::write(
        conf.join("mounts.conf"),
        format!("{}:/run/secrets/hostile\n", leak.display()),
    )
    .unwrap();
    // Read only if podman saw the user's config directory: an empty image store, so the launch
    // would fail with the image unknown.
    std::fs::write(
        conf.join("storage.conf"),
        format!(
            "[storage]\ndriver = \"vfs\"\ngraphroot = \"{0}/store\"\nrunroot = \"{0}/run\"\n",
            fx_home.display()
        ),
    )
    .unwrap();
    rt().block_on(async {
        let x = Lx::with_home(Some(fx_home.clone()));
        let v =
            x.f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", "ro")]));
        let r = x.launch(&v, "hostile").await.unwrap();
        let (_, out) = exec(
            &r,
            "ls /hostile /run/secrets 2>&1; env | grep HOSTILE; grep CapEff /proc/self/status; \
             ls /sys/class/net",
        );
        assert!(
            !out.contains("canary") && !out.contains("HOSTILE=1"),
            "{out}"
        );
        assert!(out.contains("CapEff:\t0000000000000000"), "{out}");
        assert_eq!(
            out.lines().last(),
            Some("lo"),
            "own network namespace: {out}"
        );
        x.launcher.stop(r).await.unwrap();
    });
    std::fs::remove_dir_all(&fx_home).unwrap();
}
