//! Task 6b with real containers (rootless Podman): the hardened launch, teardown, the B4 overlap
//! rule and post-init mount check, hermetic podman (#11), RT-FS-12 variants (EBUSY parents),
//! RT-FS-13 (socket in a mount) and RT-FS-16 (a nested host mount is not visible).
//!
//! The fixture is `common::container`; these tests never skip.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;

use sallyd::sandbox::{Expect, LaunchError, check_in_container};

mod common;
use common::container::*;
use common::*;

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
        )
        .await;
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
        let data = r.paths().data_root().to_owned();
        let sockets = r.paths().socket_root().to_owned();
        assert_eq!(x.events.list(), ["sandbox.launch"]);
        let container = r.container().to_owned();
        x.stop(r).await;
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

/// #17 (Task 6c): `podman start` succeeds even when the entry point exits at once. The launcher
/// confirms the container is running, and otherwise refuses, removes it and its directories, and
/// releases its claims.
#[test]
fn an_entry_that_exits_at_once_refuses_the_launch() {
    rt().block_on(async {
        let x = Lx::new();
        let v =
            x.f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", "rw")]));
        let mut req = x.request(&v, "exit");
        req.default_image = Some(exiting_image());
        let paths = req.paths.clone();
        let e = x.launcher.launch_workspace(req).await.unwrap_err();
        assert!(matches!(e, LaunchError::NotRunning(_)), "{e}");
        assert_eq!(x.events.list(), ["sandbox.launch", "sandbox.refuse"]);
        let refuse = x.events.args("sandbox.refuse").unwrap();
        assert_eq!(refuse["reason"], "not-running", "{refuse}");
        assert!(!exists(&format!("sp-ws-{}", paths.id().as_str())));
        assert!(!paths.data_root().exists() && !paths.socket_root().exists());
        let r = x.launch(&v, "after-exit").await.unwrap();
        x.stop(r).await;
    });
}

/// Architect Q58: with no bundled image, a manifest without `runtime.image` is refused
/// `no-default-image` before anything is reserved or created: one `sandbox.refuse`, no
/// `sandbox.launch`, no directories, and the same writable mount launches next.
#[test]
fn no_default_image_refuses_before_anything_is_reserved() {
    rt().block_on(async {
        let x = Lx::new();
        let v =
            x.f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", "rw")]));
        let mut req = x.request(&v, "noimg");
        req.default_image = None;
        let paths = req.paths.clone();
        let e = x.launcher.launch_workspace(req).await.unwrap_err();
        assert!(matches!(e, LaunchError::NoDefaultImage), "{e}");
        assert_eq!(x.events.list(), ["sandbox.refuse"]);
        let refuse = x.events.args("sandbox.refuse").unwrap();
        assert_eq!(refuse["reason"], "no-default-image", "{refuse}");
        assert_eq!(refuse["cleanup"], "nothing to clean up", "{refuse}");
        assert!(!paths.data_root().exists() && !paths.socket_root().exists());
        let r = x.launch(&v, "after-noimg").await.unwrap();
        x.stop(r).await;
    });
}

/// AMENDMENTS-02 B4, launcher level (#17): the mount source is swapped after the host re-check,
/// while `podman init` runs (a runtime wrapper renames the granted directory and puts another in
/// its place when `crun create` is called). The post-init check sees another object, the launch
/// is refused before `start` and audited as `sandbox.mount_mismatch`, and nothing ran.
#[test]
fn a_mount_swapped_during_init_is_a_mismatch() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("swap-runtime-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let _cleanup = RemoveOnDrop(dir.clone());
    let marker = dir.join("swapped");
    let wrapper = dir.join("crun-swap");
    let write_wrapper = |granted: &std::path::Path| {
        let script = format!(
            "#!/bin/sh\nfor a in \"$@\"; do\n  if [ \"$a\" = create ] && [ ! -e '{m}' ]; then\n    \
             touch '{m}'; mv '{g}' '{g}.orig' && mkdir '{g}'\n  fi\ndone\nexec '{rt}' \"$@\"\n",
            m = marker.display(),
            g = granted.display(),
            rt = test_runtime().display(),
        );
        std::fs::write(&wrapper, script).unwrap();
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).unwrap();
    };
    // The fixture's paths are only known once it exists; the wrapper must exist first.
    write_wrapper(std::path::Path::new("/nonexistent"));
    rt().block_on(async {
        let x = Lx::with_runtime(&wrapper);
        let granted = x.f.root.join("home/code/myproject");
        write_wrapper(&granted);
        let v =
            x.f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", "rw")]));
        let req = x.request(&v, "swap");
        let paths = req.paths.clone();
        let e = x.launcher.launch_workspace(req).await.unwrap_err();
        assert!(marker.exists(), "the wrapper ran");
        assert!(matches!(e, LaunchError::MountMismatch(_)), "{e}");
        assert_eq!(
            x.events.list(),
            ["sandbox.launch", "sandbox.mount_mismatch"]
        );
        assert!(!exists(&format!("sp-ws-{}", paths.id().as_str())));
        assert!(!paths.data_root().exists() && !paths.socket_root().exists());
    });
}

/// Waits up to 20 s for the container to be gone.
async fn gone_within_deadline(container: &str) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while std::time::Instant::now() < deadline {
        if !exists(container) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    false
}

/// RT-AG-09, `runtime.stage_size` (#14): a sandbox that writes past the limit into a staged
/// mount is killed and `session.resource_limit` is audited first. Within the limit it keeps
/// running, and so does another session (6c-1 security review L4). `stop` still tears the killed
/// session down and keeps its staged data.
#[test]
fn rt_ag_09_writing_past_stage_size_kills_the_session() {
    rt().block_on(async {
        let x = Lx::new();
        let body = format!(
            "{}runtime:\n  stage_size: 4MiB\n",
            mounts(&[
                mount("~/code/myproject", "/workspace/p", "ro"),
                mount("~/code/other", "/workspace/o", "staged"),
            ])
        );
        let v = x.f.load(&body);
        let small = x.launch(&v, "stage").await.unwrap();
        let other = x.f.load(&format!(
            "{}runtime:\n  stage_size: 4MiB\n",
            mounts(&[mount("~/Documents/research", "/workspace/r", "staged")])
        ));
        let bystander = x.launch(&other, "bystander").await.unwrap();
        let (code, out) = exec(
            &small,
            "dd if=/dev/zero of=/workspace/o/ok bs=1024 count=1024",
        )
        .await;
        assert_eq!(code, 0, "{out}");
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert!(exists(small.container()), "within the limit: still running");
        // The write itself may be cut short by the kill.
        let _ = exec(&small, "dd if=/dev/zero of=/workspace/o/big bs=1M count=16").await;
        assert!(
            gone_within_deadline(small.container()).await,
            "the watchdog killed the session"
        );
        let limit = x.events.args("session.resource_limit").expect("audited");
        assert_eq!(limit["resource"], "stage_size", "{limit}");
        assert_eq!(limit["limit"], 4 << 20, "{limit}");
        assert_eq!(limit["area"], "filesystem.mounts[1]", "{limit}");
        assert_eq!(limit["reason"], "stage_size", "{limit}");
        assert!(limit["measured"].as_u64().unwrap() > 4 << 20, "{limit}");
        assert!(exists(bystander.container()), "the other session is alive");
        let paths = small.paths().clone();
        x.stop(small).await;
        x.stop(bystander).await;
        assert!(
            paths.stage(1).upper.join("ok").exists(),
            "staged data is kept"
        );
        assert_eq!(
            x.events.list(),
            [
                "sandbox.launch",
                "sandbox.launch",
                "session.resource_limit",
                "sandbox.stop",
                "sandbox.stop"
            ]
        );
    });
}

/// RT-AG-09, `runtime.stage_size` through a `.git` overlay (6c-1 Rust review H2): an `rw` mount
/// with no staged mount still cannot fill the host disk through `<mount>/.git`.
#[test]
fn rt_ag_09_writing_past_stage_size_into_a_git_overlay_kills_the_session() {
    rt().block_on(async {
        let x = Lx::new();
        x.f.tree("code/myproject", &[".git"], &[]);
        let v = x.f.load(&format!(
            "{}runtime:\n  stage_size: 4MiB\n",
            mounts(&[mount("~/code/myproject", "/workspace/p", "rw")])
        ));
        let r = x.launch(&v, "git-fill").await.unwrap();
        let _ = exec(
            &r,
            "dd if=/dev/zero of=/workspace/p/.git/pack bs=1M count=16",
        )
        .await;
        assert!(
            gone_within_deadline(r.container()).await,
            "the watchdog killed the session"
        );
        let limit = x.events.args("session.resource_limit").expect("audited");
        assert_eq!(limit["area"], "filesystem.mounts[0].git[0]", "{limit}");
        assert_eq!(limit["reason"], "stage_size", "{limit}");
        assert!(
            !x.f.root.join("home/code/myproject/.git/pack").exists(),
            "the host .git is untouched"
        );
        x.stop(r).await;
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
fn rt_ag_08b_overlapping_sessions_are_refused_while_the_first_is_live() {
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
        x.stop(ra).await;
        let rb = x.launch(&b, "b2").await.unwrap();
        x.stop(rb).await;
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
        let out = podman(&["inspect", "--format", "{{.State.Pid}}", r.container()]);
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
        let dir = sally_core::fd::open(
            format!("/proc/{pid}").as_str(),
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        check_in_container(
            &dir,
            &[
                want("/workspace/p", id("")),
                want("/workspace/p/m/.git", id("m/.git")),
            ],
        )
        .unwrap();
        let wrong = check_in_container(&dir, &[want("/workspace/p/m", id("m/.git"))]).unwrap_err();
        assert!(wrong.to_string().contains("pinned"), "{wrong}");
        let missing = check_in_container(&dir, &[want("/workspace/nothing", id(""))]).unwrap_err();
        assert!(
            missing.to_string().contains("cannot be opened"),
            "{missing}"
        );
        x.stop(r).await;
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
        )
        .await;
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
        x.stop(r).await;
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
            )
            .await;
            assert!(!out.contains("NESTED-SECRET"), "{mode}: {out}");
            assert!(out.contains("No such file"), "{mode}: {out}");
            x.stop(r).await;
        }
        // `staged`: Podman 4.9.3 refuses an overlay whose lower directory has a mount inside it
        // in the keep-id user namespace (EINVAL, probed in Task 6b), so the launch is refused
        // after `init` and nothing ever runs.
        let v = x.f.load(&mounts(&[mount(
            "~/code/myproject",
            "/workspace/p",
            "staged",
        )]));
        let req = x.request(&v, "staged");
        let paths = req.paths.clone();
        let e = x.launcher.launch_workspace(req).await.unwrap_err();
        assert!(
            matches!(e, LaunchError::Command { verb: "init", .. }),
            "{e}"
        );
        assert_eq!(
            x.events.list().last().map(String::as_str),
            Some("sandbox.refuse")
        );
        // 6b reviews: a failed launch removes its container (by name) and everything it
        // created, and releases its claims.
        assert!(!exists(&format!("sp-ws-{}", paths.id().as_str())));
        assert!(!paths.data_root().exists() && !paths.socket_root().exists());
        let rw =
            x.f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", "rw")]));
        let r = x.launch(&rw, "after").await.unwrap();
        x.stop(r).await;
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
    let _cleanup = RemoveOnDrop(fx_home.clone());
    rt().block_on(async {
        let x = Lx::with_home(Some(fx_home.clone()));
        let v =
            x.f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", "ro")]));
        let r = x.launch(&v, "hostile").await.unwrap();
        let (_, out) = exec(
            &r,
            "ls /hostile /run/secrets 2>&1; env | grep HOSTILE; grep CapEff /proc/self/status; \
             ls /sys/class/net",
        )
        .await;
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
        x.stop(r).await;
    });
}

struct RemoveOnDrop(PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// 6b reviews (Rust H1, security M3): relaunching a stopped session's id is refused before
/// anything is created, and the kept staged changes survive.
#[test]
fn a_reused_session_id_never_deletes_kept_staged_changes() {
    rt().block_on(async {
        let x = Lx::new();
        let v =
            x.f.load(&mounts(&[mount("~/code/other", "/workspace/o", "staged")]));
        let req = x.request(&v, "reuse");
        let r = x.launcher.launch_workspace(req.clone()).await.unwrap();
        let (code, out) = exec(&r, "echo keep > /workspace/o/work.txt").await;
        assert_eq!(code, 0, "{out}");
        x.stop(r).await;
        let kept = req.paths.stage(0).upper.join("work.txt");
        assert!(kept.exists());
        let e = x.launcher.launch_workspace(req).await.unwrap_err();
        assert!(matches!(&e, LaunchError::Dirs(d) if d.reused), "{e}");
        assert!(kept.exists(), "the refused launch removed nothing");
        assert_eq!(
            x.events.list(),
            ["sandbox.launch", "sandbox.stop", "sandbox.refuse"]
        );
    });
}

/// 6b reviews (Rust H2, security M1): claims are released once the container is confirmed
/// gone, also when something else removed it first.
#[test]
fn stop_releases_the_claims_once_the_container_is_gone() {
    rt().block_on(async {
        let x = Lx::new();
        let v =
            x.f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", "rw")]));
        let r = x.launch(&v, "gone").await.unwrap();
        assert!(
            podman(&["rm", "--force", "--time", "0", r.name()])
                .status
                .success()
        );
        x.stop(r).await;
        let again = x.launch(&v, "again").await.unwrap();
        x.stop(again).await;
    });
}

/// 6b security review M1: containers a crashed `sallyd` left behind are removed before the
/// first launch, so the overlap rule starts from what is really running.
#[test]
fn orphans_of_a_previous_sallyd_are_removed() {
    rt().block_on(async {
        let x = Lx::new();
        let v =
            x.f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", "rw")]));
        let r = x.launch(&v, "orphan").await.unwrap();
        let name = r.name().to_owned();
        drop(r); // the handle dies with the "crashed" sallyd; the container keeps running
        assert!(exists(&name));
        // A session live in this launcher is never an orphan.
        assert!(
            x.launcher
                .remove_orphans(&x.scope)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(exists(&name));
        // The next sallyd starts with no live sessions and removes it.
        let next = Lx::new();
        let removed = next.launcher.remove_orphans(&x.scope).await.unwrap();
        assert_eq!(removed, std::slice::from_ref(&name));
        assert!(!exists(&name));
        assert_eq!(next.events.list(), ["sandbox.orphan_removed"]);
    });
}

/// 6b Rust review H3: a caller that stops waiting (an outer timeout, a closed connection)
/// leaves no container and no claim behind: the launch finishes in its own task and stops
/// what nobody received.
#[test]
fn a_dropped_launch_cleans_up_after_itself() {
    rt().block_on(async {
        let x = Lx::new();
        let v =
            x.f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", "rw")]));
        let req = x.request(&v, "cancel");
        let name = format!("sp-ws-{}", req.paths.id().as_str());
        let cancelled =
            tokio::time::timeout(Duration::from_millis(1), x.launcher.launch_workspace(req)).await;
        assert!(cancelled.is_err(), "the launch outlived its caller");
        // Nothing else launches until the cancelled launch has finished in its own task: it must
        // have launched and then stopped what nobody received.
        for _ in 0..600 {
            if x.events.list().len() >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(x.events.list(), ["sandbox.launch", "sandbox.stop"]);
        // `stop` audits first, then removes the container and releases the claims.
        let mut again = None;
        for _ in 0..600 {
            match x.launch(&v, "after-cancel").await {
                Ok(r) => {
                    again = Some(r);
                    break;
                }
                Err(LaunchError::Overlap(_)) => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(e) => panic!("{e}"),
            }
        }
        let again = again.expect("the cancelled launch released its claims");
        assert!(!exists(&name));
        x.stop(again).await;
    });
}

/// 6b security review M4 / L5: everything podman reads from Sallyport's state is re-checked
/// before each launch; a line in the empty mounts file refuses the launch.
#[test]
fn a_tampered_podman_state_refuses_the_launch() {
    rt().block_on(async {
        let x = Lx::new();
        let mounts_file =
            x.f.root
                .join("home/.local/share/sallyport/podman/mounts.conf");
        std::fs::write(&mounts_file, "/etc:/run/secrets\n").unwrap();
        let v =
            x.f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", "ro")]));
        let e = x.launch(&v, "tamper").await.unwrap_err();
        assert!(
            e.to_string().contains("changed since sallyd wrote it"),
            "{e}"
        );
        assert_eq!(x.events.list(), ["sandbox.refuse"]);
    });
}
