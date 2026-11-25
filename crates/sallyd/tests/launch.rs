//! Task 6b with real containers (rootless Podman): the hardened launch, teardown, the B4 overlap
//! rule and post-init mount check, hermetic podman (#11), RT-FS-12 variants (EBUSY parents),
//! RT-FS-13 (socket in a mount) and RT-FS-16 (a nested host mount is not visible).
//!
//! The fixture is `common::container`; these tests never skip.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;

use sallyd::sandbox::{Expect, LaunchError, Running, Sweep, check_in_container};

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
/// its place when `crun create` is called for a bundle whose config mounts it: the real
/// container's, not the mount-link probe's, which has no bind and runs first). The post-init
/// check sees another object, the launch is refused before `start` and audited as
/// `sandbox.mount_mismatch`, and nothing ran.
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
            "#!/bin/sh\ncreate=; bundle=; prev=\nfor a in \"$@\"; do\n  \
             [ \"$a\" = create ] && create=1\n  \
             [ \"$prev\" = --bundle ] || [ \"$prev\" = -b ] && bundle=\"$a\"\n  prev=\"$a\"\ndone\n\
             if [ -n \"$create\" ] && [ ! -e '{m}' ] && grep -qF '{g}' \"$bundle/config.json\"; then\n  \
             touch '{m}'; mv '{g}' '{g}.orig' && mkdir '{g}'\nfi\nexec '{rt}' \"$@\"\n",
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

/// The short stand-in for `runtime.timeout` + 300 s in RT-AG-16, in seconds: long enough for
/// every container to be started and probed, under a parallel test run, well before it.
const BACKSTOP_STAND_IN: u64 = 30;

/// RT-AG-16 (#92, architect Q60, Q196): with no `sallyd` at all, conmon ends a session's
/// workspace container at its `--timeout`, whether it runs or is frozen with `podman pause`
/// (as the disk watchdog freezes one), and the `--rm` cleanup then removes it. The helper
/// asserts the product argv carries exactly `runtime.timeout` + 300 s before a short stand-in
/// replaces the value; every container is created, initialised and started in the product's
/// order. Controls: the same product argv with `--timeout` left out (`LeaveOut::Timeout`), one
/// running and one frozen, started first, are still listed once older than the stand-in.
#[test]
fn rt_ag_16_conmon_ends_a_session_container_with_no_sallyd() {
    rt().block_on(async {
        let x = Lx::new();
        let v =
            x.f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", "ro")]));
        let name = |tag: &str| format!("sp-ws-{}-{tag}", x.scope);
        let stand_in = Duration::from_secs(BACKSTOP_STAND_IN);
        // The controls first, so each has outlived the stand-in by the time it is probed: one
        // running, one frozen like the frozen subject.
        let controls_from = std::time::Instant::now();
        let control = x.control_workspace(&v, "ctl", LeaveOut::Timeout).await;
        let frozen_control = x.control_workspace(&v, "ctlf", LeaveOut::Timeout).await;
        freeze(&x, &frozen_control).await;
        let subjects_from = std::time::Instant::now();
        x.backstop_workspace(&v, "run", BACKSTOP_STAND_IN).await;
        let frozen = x.backstop_workspace(&v, "frz", BACKSTOP_STAND_IN).await;
        freeze(&x, &frozen).await;
        for tag in ["ctl", "ctlf", "run", "frz"] {
            assert!(listed_name(&name(tag)), "{tag}: listed after its start");
        }
        // The probes above ran well before any deadline, so they show the subjects alive.
        assert!(
            subjects_from.elapsed() < stand_in / 2,
            "the subjects took {:?} to start",
            subjects_from.elapsed()
        );

        let cap = std::time::Instant::now() + stand_in + Duration::from_secs(60);
        while (listed_name(&name("run")) || listed_name(&name("frz")))
            && std::time::Instant::now() < cap
        {
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        assert!(
            !listed_name(&name("run")),
            "the running one outlived its --timeout"
        );
        assert!(
            !listed_name(&name("frz")),
            "the frozen one outlived its --timeout"
        );
        while controls_from.elapsed() < stand_in + Duration::from_secs(5) {
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        for tag in ["ctl", "ctlf"] {
            assert!(
                listed_name(&name(tag)),
                "control: {tag}, without --timeout, is still listed past the stand-in"
            );
        }
        for id in [control, frozen_control] {
            x.hermetic(&["rm".into(), "--force".into(), id]).await;
        }
        assert!(
            !listed_name(&name("ctl")) && !listed_name(&name("ctlf")),
            "the controls are removed"
        );
    });
}

/// `podman pause`, as the disk watchdog freezes a container, then checks it is paused.
async fn freeze(x: &Lx, id: &str) {
    x.hermetic(&["pause".into(), id.into()]).await;
    let status = x
        .hermetic(&[
            "inspect".into(),
            "--format".into(),
            "{{.State.Status}}".into(),
            id.into(),
        ])
        .await;
    assert_eq!(status, "paused", "{id}");
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
        assert_eq!(limit["reason"], "stage-size", "{limit}");
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
        assert_eq!(limit["reason"], "stage-size", "{limit}");
        assert!(
            !x.f.root.join("home/code/myproject/.git/pack").exists(),
            "the host .git is untouched"
        );
        x.stop(r).await;
    });
}

/// RT-FS-13 at launch: refused before anything is created, and audited. Control, first: the
/// same manifest before the socket exists launches on the same fixture, and its container is
/// listed by the same probe (`Lx::listed_control`).
#[test]
fn rt_fs_13_a_socket_in_a_mount_refuses_the_launch() {
    rt().block_on(async {
        let x = Lx::new();
        let v =
            x.f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", "ro")]));
        let base = x.listed_control(&v, "sockc").await;
        let dir = x.f.root.join("home/code/myproject");
        let short = std::env::temp_dir().join(format!("sp-l-{}", std::process::id()));
        let _ = std::fs::remove_file(&short);
        std::os::unix::fs::symlink(&dir, &short).unwrap();
        let _l = std::os::unix::net::UnixListener::bind(short.join("agent.sock")).unwrap();
        std::fs::remove_file(&short).unwrap();
        let e = x.launch(&v, "sock").await.unwrap_err();
        assert!(e.to_string().contains("socket-in-mount"), "{e}");
        assert_eq!(x.events.list()[base..], ["sandbox.refuse"]);
        assert!(!x.listed(), "nothing was created");
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

/// RT-FS-16's look into the nested mount point.
const FS16_PROBE: &str = "ls -a /workspace/p/nested; cat /workspace/p/nested/canary 2>&1";

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
        // Control (#122, architect Q156), asserted first: the same probe, in a container from
        // the same product argv with the granted bind made recursive, finds the canary.
        for mode in ["ro", "rw", "brokered"] {
            let v =
                x.f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", mode)]));
            let leave_out = LeaveOut::NonRecursive {
                guest: "/workspace/p",
            };
            let id = x
                .control_workspace(&v, &format!("{mode}c"), leave_out)
                .await;
            let (_, out) = exec_in(&id, &["sh", "-c", FS16_PROBE]);
            assert!(out.contains("NESTED-SECRET"), "control: {mode}: {out}");
        }
        for mode in ["ro", "rw", "brokered"] {
            let v =
                x.f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", mode)]));
            let r = x.launch(&v, mode).await.unwrap();
            let (_, out) = exec(&r, FS16_PROBE).await;
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
        // The handle dies with the "crashed" sallyd; the container keeps running.
        x.drop_as_killed(r);
        assert!(exists(&name));
        // A session live in this launcher is never an orphan.
        assert!(
            x.launcher
                .remove_orphans(&x.scope, Sweep::Startup)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(exists(&name));
        // Another daemon (another installation) never takes it.
        let stranger = Lx::new();
        assert!(
            stranger
                .launcher
                .remove_orphans(&x.scope, Sweep::Startup)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(exists(&name));
        // The next sallyd of this installation starts with no live sessions and removes it.
        let next = x.next_sallyd();
        let removed = next
            .launcher
            .remove_orphans(&x.scope, Sweep::Startup)
            .await
            .unwrap();
        assert_eq!(removed, std::slice::from_ref(&name));
        assert!(!exists(&name));
        assert_eq!(next.events.list(), ["sandbox.orphan_removed"]);
        assert_eq!(
            next.events.args("sandbox.orphan_removed").unwrap()["sweep"],
            "startup"
        );
    });
}

/// A podman whose `ps` prints `<at>/ps-pad` before the real listing while that file exists;
/// otherwise the real one. `ps` is the first argument the launcher passes.
fn ps_padding_podman(at: &std::path::Path, real: &std::path::Path) -> PathBuf {
    wrap_podman(at, real, |at, real| {
        format!(
            "#!/bin/sh\n\
             if [ \"$1\" = ps ] && [ -e '{at}/ps-pad' ]; then /bin/cat '{at}/ps-pad'; fi\n\
             exec '{real}' \"$@\"\n"
        )
    })
}

/// #173 (architect Q295 (5)): a `podman ps` listing longer than `OUTPUT_CAP` is refused, never
/// cut. Here the first 64 KiB end on a line boundary, so a cut listing parses and misses the
/// orphan line past it; the sweep must fail instead, audit nothing, and name no byte of the
/// listing.
#[test]
fn a_ps_listing_over_the_output_cap_is_refused_not_cut() {
    const CAP: usize = 64 * 1024;
    const LINE: usize = 128;
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("launch-ps-pad-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let _cleanup = RemoveOnDrop(dir.clone());
    rt().block_on(async {
        let x = Lx::with_podman(|real| ps_padding_podman(&dir, real));
        // Well-formed lines of no installation (label `""`): skipped by the parser, exactly CAP
        // bytes.
        let filler = format!("\"{}\" \"{}\" \"\"\n", "0".repeat(64), "f".repeat(55));
        assert_eq!(filler.len(), LINE);
        let mut pad = filler.repeat(CAP / LINE);
        // Past the cap: an orphan of this installation, in scope, owned by no live session.
        pad.push_str(&format!(
            "\"{}\" \"sp-ws-{}-lost\" \"{}\"\n",
            "a".repeat(64),
            x.scope,
            x.installation.as_str()
        ));
        std::fs::write(dir.join("ps-pad"), &pad).unwrap();
        let refused = x.launcher.remove_orphans(&x.scope, Sweep::Startup).await;
        match refused {
            Err(LaunchError::Command { verb: "ps", msg }) => {
                assert_eq!(msg, format!("stdout refused: over {CAP} bytes"));
            }
            other => panic!("expected the listing refused, got {other:?}"),
        }
        assert!(x.events.list().is_empty(), "{:?}", x.events.list());
        // The same sweep with the real listing alone runs.
        std::fs::remove_file(dir.join("ps-pad")).unwrap();
        assert!(
            x.launcher
                .remove_orphans(&x.scope, Sweep::Startup)
                .await
                .unwrap()
                .is_empty()
        );
    });
}

/// `podman create` of a session-named container out of band, with `label` if given.
fn create_out_of_band(name: &str, label: Option<&str>) {
    let image = test_image();
    let mut args = vec!["create", "--pull=never", "--network=none", "--name", name];
    let label = label.map(|id| format!("sallyport.installation={id}"));
    if let Some(l) = &label {
        args.extend(["--label", l.as_str()]);
    }
    args.push(image.as_str());
    let made = podman(&args);
    assert!(
        made.status.success(),
        "{}",
        String::from_utf8_lossy(&made.stderr)
    );
}

/// RT-AG-08b, architect Q61 (security review M4) and Q64: a session container of this
/// installation that appears after the startup sweep (a `podman create` a killed `sallyd` left
/// running) is removed by the periodic sweep within one period, audited first, while a live
/// session's container survives the same sweeps. Without the sweep it would hold mounts the
/// overlap rule does not know. A foreign container with a session name survives every sweep:
/// one with no label (another daemon's, a test run's) and one with another installation's id.
/// Controls: the sweep loop and `is_live` (the late orphan, the live session); the label match
/// (the two foreign containers), both layers together: podman's `--filter label=` and the
/// comparison in `sandbox::orphans`. Removing one layer alone leaves the other refusing them,
/// so each is pinned by its own unit test in `sandbox::orphans` (the listing asks podman for
/// the label; only this installation's containers match).
#[test]
fn rt_ag_08b_a_late_orphan_is_swept_while_a_live_session_and_foreign_containers_stay() {
    rt().block_on(async {
        let x = Lx::new();
        let v =
            x.f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", "rw")]));
        let live = x.launch(&v, "live").await.unwrap();
        let unlabelled = format!("sp-ws-{}-f0reign", x.scope);
        let other = format!("sp-ws-{}-0ther", x.scope);
        create_out_of_band(&unlabelled, None);
        create_out_of_band(&other, Some("0123abcd-ef01-4234-8567-89abcdef0123"));
        let sweeping = tokio::spawn(sallyd::daemon::sweep::every(
            x.launcher.clone(),
            x.scope.clone(),
            Duration::from_millis(500),
            sallyd::oplog::Oplog::new(std::io::sink()),
        ));
        let orphan = format!("sp-ws-{}-late0rphan", x.scope);
        create_out_of_band(&orphan, Some(x.installation.as_str()));
        let end = std::time::Instant::now() + Duration::from_secs(30);
        while exists(&orphan) {
            assert!(
                std::time::Instant::now() < end,
                "the late orphan was never swept"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        // Two more periods: the live session and the foreign containers are never taken.
        tokio::time::sleep(Duration::from_millis(1100)).await;
        sweeping.abort();
        assert!(exists(live.name()));
        assert!(
            exists(&unlabelled),
            "a container without the label was swept"
        );
        assert!(exists(&other), "another installation's container was swept");
        for name in [&unlabelled, &other] {
            assert!(podman(&["rm", name]).status.success());
        }
        let swept = x.events.args("sandbox.orphan_removed").unwrap();
        assert_eq!(
            (swept["container"].as_str(), swept["sweep"].as_str()),
            (Some(orphan.as_str()), Some("periodic"))
        );
        // The entry names the ID `rm` was given (security re-review L3).
        let id = swept["id"].as_str().unwrap_or_default();
        assert!(
            id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()),
            "{swept}"
        );
        assert_eq!(
            x.events
                .list()
                .iter()
                .filter(|e| *e == "sandbox.orphan_removed")
                .count(),
            1
        );
        x.stop(live).await;
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

/// The longest a test waits for the launcher to stop a container nobody holds.
const STOP_BOUND: Duration = Duration::from_secs(60);

/// How long a test lets a launch it polled once run on unpolled: well past the start grace, so
/// its task has sent its result into the channel the caller no longer polls.
const PAST_THE_SEND: Duration = Duration::from_secs(5);

/// Polls `done` every 100 ms until it holds; fails the test naming `what` after `bound`.
async fn until(what: &str, bound: Duration, mut done: impl FnMut() -> bool) {
    let end = std::time::Instant::now() + bound;
    while !done() {
        assert!(
            std::time::Instant::now() < end,
            "{what}: not within {bound:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// The positions of the entries named `event` whose `role` is `role`, oldest first.
fn role_entries(x: &Lx, event: &str, role: &str) -> Vec<usize> {
    x.events
        .all()
        .iter()
        .enumerate()
        .filter(|(_, (e, a))| e == event && a["role"] == role)
        .map(|(i, _)| i)
        .collect()
}

/// Asserts one `sandbox.stop` of `role`, after the one `sandbox.launch` of `role`.
fn assert_stopped_after_launch(x: &Lx, role: &str) {
    let launched = role_entries(x, "sandbox.launch", role);
    let stopped = role_entries(x, "sandbox.stop", role);
    assert_eq!(launched.len(), 1, "{:?}", x.events.list());
    assert_eq!(stopped.len(), 1, "{:?}", x.events.list());
    assert!(launched[0] < stopped[0], "{:?}", x.events.list());
}

/// Asserts the oplog line only a dropped handle's guard writes, naming `container`: the stop
/// came from the drop, not from a launch task whose send failed (so the test cannot pass on
/// timing alone).
fn assert_stopped_by_the_drop(x: &Lx, container: &str) {
    let log = x.oplog_text();
    assert!(
        log.lines().any(|l| l
            .contains("a container's handle was dropped without a stop; the launcher stops it")
            && l.contains(container)),
        "{log}"
    );
}

/// Launches `v` as `tag`, retrying while the folder is still claimed (a stop releases the
/// claim after the container is gone); fails the test past [`STOP_BOUND`].
async fn relaunch(x: &Lx, v: &sally_core::manifest::ValidatedManifest, tag: &str) -> Running {
    let end = std::time::Instant::now() + STOP_BOUND;
    loop {
        match x.launch(v, tag).await {
            Ok(r) => return r,
            Err(LaunchError::Overlap(_)) if std::time::Instant::now() < end => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => panic!("the folder is still refused: {e}"),
        }
    }
}

/// Polls `launch` once, so its task starts; the caller then never polls it again.
async fn poll_once<F: std::future::Future + Unpin>(launch: &mut F) {
    tokio::select! {
        biased;
        _ = launch => panic!("the launch finished at its first poll"),
        () = std::future::ready(()) => {}
    }
}

/// RT-AG-08b: a workspace launch whose result was sent while its
/// caller still existed, but never received (the caller's future dropped after the send), is
/// stopped: its container goes, `sandbox.stop` follows `sandbox.launch`, and its claim is
/// freed, so the same folder launches again. Control first: before the drop the container
/// runs and the folder is refused.
#[test]
fn rt_ag_08b_a_launch_result_sent_but_never_received_is_stopped() {
    rt().block_on(async {
        let x = Lx::new();
        let v =
            x.f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", "rw")]));
        let req = x.request(&v, "unreceived");
        let name = format!("sp-ws-{}", req.paths.id().as_str());
        let mut launch = Box::pin(x.launcher.launch_workspace(req));
        poll_once(&mut launch).await;
        until("control: the container runs", STOP_BOUND, || exists(&name)).await;
        tokio::time::sleep(PAST_THE_SEND).await;
        assert!(exists(&name), "control: the container runs before the drop");
        let refused = x.launch(&v, "unreceived-2").await;
        assert!(
            matches!(refused, Err(LaunchError::Overlap(_))),
            "control: the folder is refused while the launch holds it: {:?}",
            refused.map(|r| r.name().to_owned())
        );
        drop(launch);
        until("the container nobody received is gone", STOP_BOUND, || {
            !exists(&name)
        })
        .await;
        assert_stopped_by_the_drop(&x, &name);
        assert_stopped_after_launch(&x, "workspace");
        let again = relaunch(&x, &v, "unreceived-3").await;
        x.stop(again).await;
    });
}

/// RT-AG-08b, the harness twin: a harness launch whose result was
/// sent but never received is stopped, and a second harness of the session is admitted after.
/// Control first: before the drop the container runs and a second harness is refused.
#[test]
fn rt_ag_08b_a_harness_launch_result_sent_but_never_received_is_stopped() {
    rt().block_on(async {
        let x = Lx::new();
        let v = x.f.load("");
        let ws = x.launch(&v, "h-unreceived").await.unwrap();
        let req = x.harness(&v, "h-unreceived");
        let name = format!("sp-h-{}", req.paths.id().as_str());
        let mut launch = Box::pin(x.launcher.launch_harness(req));
        poll_once(&mut launch).await;
        until("control: the harness runs", STOP_BOUND, || exists(&name)).await;
        tokio::time::sleep(PAST_THE_SEND).await;
        assert!(exists(&name), "control: the harness runs before the drop");
        let refused = x
            .launcher
            .launch_harness(x.harness(&v, "h-unreceived"))
            .await;
        assert!(
            matches!(refused, Err(LaunchError::Harness(_))),
            "control: a second harness is refused while the launch holds it: {:?}",
            refused.map(|r| r.name().to_owned())
        );
        drop(launch);
        until("the harness nobody received is gone", STOP_BOUND, || {
            !exists(&name)
        })
        .await;
        assert_stopped_by_the_drop(&x, &name);
        assert_stopped_after_launch(&x, "harness");
        let end = std::time::Instant::now() + STOP_BOUND;
        let second = loop {
            match x
                .launcher
                .launch_harness(x.harness(&v, "h-unreceived"))
                .await
            {
                Ok(h) => break h,
                Err(LaunchError::Harness(_)) if std::time::Instant::now() < end => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(e) => panic!("the session's harness claim is still held: {e}"),
            }
        };
        x.launcher.stop_role(second).await.unwrap();
        x.stop(ws).await;
    });
}

/// RT-AG-08b: a workspace handle its caller received and then dropped
/// without a stop (a lost owner) stops its container, writes `sandbox.stop` and frees its
/// claim. A guard on the launch channel alone would not do this. Control first: before the
/// drop the container runs and the folder is refused.
#[test]
fn rt_ag_08b_a_received_workspace_dropped_without_a_stop_is_stopped() {
    rt().block_on(async {
        let x = Lx::new();
        let v =
            x.f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", "rw")]));
        let r = x.launch(&v, "dropped").await.unwrap();
        let name = r.name().to_owned();
        assert!(exists(&name), "control: the container runs before the drop");
        let refused = x.launch(&v, "dropped-2").await;
        assert!(
            matches!(refused, Err(LaunchError::Overlap(_))),
            "control: the folder is refused while the handle lives: {:?}",
            refused.map(|r| r.name().to_owned())
        );
        let id = name.trim_start_matches("sp-ws-").to_owned();
        assert!(x.launcher.unconfirmed_containers().is_empty(), "control");
        drop(r);
        // Recorded at the drop, so a shutdown meanwhile exits naming it.
        assert_eq!(x.launcher.unconfirmed_containers(), [id]);
        until("the dropped handle's container is gone", STOP_BOUND, || {
            !exists(&name)
        })
        .await;
        until("the stop confirmed", STOP_BOUND, || {
            x.launcher.unconfirmed_containers().is_empty()
        })
        .await;
        assert_stopped_by_the_drop(&x, &name);
        assert_stopped_after_launch(&x, "workspace");
        let again = relaunch(&x, &v, "dropped-3").await;
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

/// The open-file limits, soft and hard, of the container's init and of a process `podman exec`
/// starts (as a tool's command is started), then whether setting the limit, soft and hard, to
/// 513 succeeded (`set`) or not (`refused`).
const NOFILE_PROBE: &str = "grep 'Max open files' /proc/1/limits; \
     grep 'Max open files' /proc/self/limits; \
     if ulimit -n 513 2>/dev/null; then echo set; else echo refused; fi";

/// Soft and hard, as `/proc/<pid>/limits` prints them.
type Limit = (String, String);

/// The init's and the exec'd process's [`Limit`], and the last line, from [`NOFILE_PROBE`]'s
/// output.
fn nofile_read(out: &str) -> (Limit, Limit, String) {
    let limits: Vec<Limit> = out
        .lines()
        .filter(|l| l.starts_with("Max open files"))
        .map(|l| {
            let t: Vec<&str> = l.split_whitespace().collect();
            let field = |i: usize| (*t.get(i).unwrap_or_else(|| panic!("{l}: {out}"))).to_owned();
            (field(3), field(4))
        })
        .collect();
    assert_eq!(limits.len(), 2, "{out}");
    let last = out.lines().last().unwrap_or_default().to_owned();
    (limits[0].clone(), limits[1].clone(), last)
}

/// RT-AG-09: in a launched workspace, the init and a process `podman exec` starts both have 512
/// open files, soft and hard, and raising the limit to 513 is refused. Control first: the
/// product argv with the `nofile` pair left out shows podman's inherited limit, above 512,
/// through the same reads, and there the same `ulimit -n 513` (no raise) succeeds.
#[test]
fn rt_ag_09_the_descriptor_limit_holds_for_init_and_exec() {
    rt().block_on(async {
        let x = Lx::new();
        let v =
            x.f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", "ro")]));
        let control = x.control_workspace(&v, "ctl", LeaveOut::Nofile).await;
        let (code, out) = exec_in(&control, &["sh", "-c", NOFILE_PROBE]);
        assert_eq!(code, 0, "control: {out}");
        let (init, execd, last) = nofile_read(&out);
        let inherited: u64 = init.1.parse().expect("control: a number");
        assert!(inherited > 512, "control: podman's inherited limit: {out}");
        assert_eq!(init, execd, "control: {out}");
        assert_eq!(
            last, "set",
            "control: 513 is within the inherited limit: {out}"
        );

        let r = x.launch(&v, "nofile").await.unwrap();
        let (code, out) = exec(&r, NOFILE_PROBE).await;
        assert_eq!(code, 0, "{out}");
        let (init, execd, last) = nofile_read(&out);
        let limit = ("512".to_owned(), "512".to_owned());
        assert_eq!(init, limit, "the init: {out}");
        assert_eq!(execd, limit, "a process exec started: {out}");
        assert_eq!(last, "refused", "raising the limit: {out}");
        x.stop(r).await;
    });
}

/// RT-AG-09: a launched workspace creates no POSIX message queue. A queue's bytes are charged up
/// to the host account's allowance, so every role's limit is zero and `mq_open` is refused
/// (EMFILE, 24), from a process `podman exec` starts. Control
/// first: the product argv with the `msgqueue` pair left out creates one through the same probe.
#[test]
fn rt_ag_09_a_workspace_creates_no_message_queue() {
    rt().block_on(async {
        let x = Lx::new();
        let v =
            x.f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", "ro")]));
        let control = x.control_workspace(&v, "ctl", LeaveOut::Msgqueue).await;
        let (code, out) = exec_in(&control, &[PROBE, "mqueue"]);
        assert_eq!((code, out.trim()), (0, "ok"), "control: {out}");

        let r = x.launch(&v, "mqueue").await.unwrap();
        let (code, out) = exec(&r, &format!("{PROBE} mqueue")).await;
        assert_eq!((code, out.trim()), (1, "errno=24"), "{out}");
        x.stop(r).await;
    });
}
