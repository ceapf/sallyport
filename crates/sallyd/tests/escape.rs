//! Workspace escape rows with real containers (Task 6c-2): RT-FS-01 (host home invisible),
//! RT-FS-02 (`ro` is read-only), RT-FS-03 (symlinks resolve inside the container), RT-FS-07
//! (no device nodes), RT-FS-08 (no setuid), RT-FS-09 (`/proc` and `/sys`) and RT-FS-11 (no WSL
//! interop). The fixture is `common::container`; these tests never skip.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use sallyd::sandbox::Running;

mod common;
use common::container::*;
use common::*;

/// A value no file in the image or the fixture holds by accident.
fn canary() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("SPCANARY{nanos:x}{}", std::process::id())
}

/// The fixture's `$HOME`.
fn home(x: &Lx) -> std::path::PathBuf {
    x.f.root.join("home")
}

/// Writes `body` to `~/<rel>` on the host.
fn host_file(x: &Lx, rel: &str, body: &str) {
    let p = home(x).join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, body).unwrap();
}

async fn launch_with(x: &Lx, mode: &str, tag: &str) -> Running {
    x.launch(&manifest(x, mode), tag).await.unwrap()
}

/// Every top-level directory of the container except the kernel's pseudo filesystems.
const SEARCH: &str = "$(ls / | grep -vxE 'proc|sys|dev' | sed 's|^|/|')";

/// The workspace manifest [`launch_with`] launches.
fn manifest(x: &Lx, mode: &str) -> sally_core::manifest::ValidatedManifest {
    x.f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", mode)]))
}

/// `sh -c <script>` in a control container (one started outside the launcher).
fn exec_control(id: &str, script: &str) -> (i32, String) {
    exec_in(id, &["sh", "-c", script])
}

/// RT-FS-01's three probes, run in `id` through `run`: the `cat`/`ls` output, the files whose
/// content holds `c`, and the exit code and output of `ls` on the host home by its host path.
async fn fs01_probes<F, Fut>(run: F, c: &str, host: &str) -> (String, String, (i32, String))
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = (i32, String)>,
{
    let cat = format!(
        "cat /home/*/.ssh/* ~/.ssh/* /root/.ssh/* {host}/.ssh/* 2>&1; ls -A /home 2>&1; \
         echo HOME=$HOME"
    );
    let (_, cat) = run(cat).await;
    let (_, grep) = run(format!("grep -rls '{c}' {SEARCH} 2>/dev/null; echo done")).await;
    let ls = run(format!("ls {host} {host}/.ssh 2>&1")).await;
    (cat, grep, ls)
}

/// RT-FS-01: nothing of the host home is visible. The canary sits in `~/.ssh`, in `~` and in a
/// sibling of the granted directory; no path finds it and no file in the container holds it.
/// Control (#122), asserted first: the same probes in a container from the same product argv
/// with the fixture's `~/.ssh` bound at its host path find the canary and list it.
#[test]
fn rt_fs_01_the_host_home_is_invisible() {
    rt().block_on(async {
        let x = Lx::new();
        let c = canary();
        for rel in [".ssh/id_ed25519", "secret.txt", "code/other/notes.txt"] {
            host_file(&x, rel, &c);
        }
        let host = home(&x).display().to_string();
        let ssh = home(&x).join(".ssh");
        let guest = ssh.display().to_string();
        let v = manifest(&x, "rw");
        let id = x
            .control_workspace(
                &v,
                "fs01c",
                LeaveOut::Bind {
                    host: &ssh,
                    guest: &guest,
                },
            )
            .await;
        let id = &id;
        let (cat, grep, (code, ls)) =
            fs01_probes(|s| async move { exec_control(id, &s) }, &c, &host).await;
        assert!(cat.contains(&c), "control: cat: {cat}");
        assert!(grep.contains("id_ed25519"), "control: grep: {grep}");
        assert!(code == 0 && ls.contains("id_ed25519"), "control: ls: {ls}");
        let r = launch_with(&x, "rw", "fs01").await;
        let rr = &r;
        let (cat, grep, (code, ls)) =
            fs01_probes(|s| async move { exec(rr, &s).await }, &c, &host).await;
        assert!(!cat.contains(&c), "{cat}");
        assert_eq!(grep.trim(), "done", "a file holds the canary");
        assert_ne!(code, 0, "{ls}");
        x.stop(r).await;
    });
}

/// RT-FS-02's writes into `/workspace/p`.
const FS02_WRITES: [&str; 4] = [
    "touch /workspace/p/x",
    "echo y >> /workspace/p/README",
    "mkdir /workspace/p/d",
    "rm /workspace/p/README",
];

/// RT-FS-02: an `ro` mount refuses creating and deleting with EROFS; the host is unchanged.
/// Control (#122), asserted first: the same writes into the same directory mounted `rw` succeed
/// and reach the host.
#[test]
fn rt_fs_02_an_ro_mount_is_read_only() {
    rt().block_on(async {
        let x = Lx::new();
        let dir = home(&x).join("code/myproject");
        host_file(&x, "code/myproject/README", "keep\n");
        let r = launch_with(&x, "rw", "fs02c").await;
        for cmd in FS02_WRITES {
            let (code, out) = exec(&r, &format!("{cmd} 2>&1")).await;
            assert_eq!(code, 0, "control: {cmd}: {out}");
        }
        assert!(
            dir.join("x").exists() && dir.join("d").exists() && !dir.join("README").exists(),
            "control: the writes reached the host"
        );
        x.stop(r).await;
        std::fs::remove_file(dir.join("x")).unwrap();
        std::fs::remove_dir(dir.join("d")).unwrap();
        host_file(&x, "code/myproject/README", "keep\n");
        let r = launch_with(&x, "ro", "fs02").await;
        for cmd in FS02_WRITES {
            let (code, out) = exec(&r, &format!("{cmd} 2>&1")).await;
            assert_ne!(code, 0, "{cmd}: {out}");
            assert!(out.contains("Read-only file system"), "{cmd}: EROFS: {out}");
        }
        assert_eq!(
            std::fs::read_to_string(dir.join("README")).unwrap(),
            "keep\n"
        );
        assert!(!dir.join("x").exists() && !dir.join("d").exists());
        x.stop(r).await;
    });
}

/// Every path below `dir`, relative and sorted; links are listed, never followed. Names only,
/// not contents or modes: enough to show that nothing was created.
fn tree(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut todo = vec![dir.to_path_buf()];
    while let Some(d) = todo.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let e = e.unwrap();
            let p = e.path();
            out.push(p.strip_prefix(dir).unwrap().display().to_string());
            if e.file_type().unwrap().is_dir() {
                todo.push(p);
            }
        }
    }
    out.sort();
    out
}

/// Launches the workspace manifest `v` from `image` instead of the test image.
async fn launch_image(
    x: &Lx,
    v: &sally_core::manifest::ValidatedManifest,
    image: sallyd::sandbox::ImageRef,
    tag: &str,
) -> Result<Running, String> {
    let mut req = x.request(v, tag);
    req.default_image = Some(image);
    x.launcher
        .launch_workspace(req)
        .await
        .map_err(|e| format!("{e:?}"))
}

/// Control (#122) for the image tests below: the product workspace argv for `v` (labelled
/// `mode`) from `image`, with `leave_out` taken out, started by hermetic podman; the host folder
/// `dir` must then gain `entry`. The container is removed and the entry deleted, so the host
/// folder is as it was for the product leg.
async fn image_control(
    x: &Lx,
    dir: &Path,
    image: &sallyd::sandbox::ImageRef,
    (v, mode): (&sally_core::manifest::ValidatedManifest, &str),
    leave_out: LeaveOut<'_>,
    entry: &str,
) {
    let before = tree(dir);
    let tag = format!("c{mode}");
    let id = x.control_workspace_image(v, &tag, image, leave_out).await;
    let after = tree(dir);
    x.hermetic(&["rm".to_owned(), "-f".to_owned(), "-v".to_owned(), id])
        .await;
    assert!(
        after.contains(&entry.to_owned()),
        "control: {mode}: the host folder gained no {entry}: {after:?}"
    );
    std::fs::remove_dir(dir.join(entry))
        .unwrap_or_else(|e| panic!("control: {mode}: remove {entry}: {e}"));
    assert_eq!(tree(dir), before, "control: {mode}: cleaned up");
}

/// RT-FS-02, the working directory (security review): an image whose config names a missing
/// working directory below an `ro` or a `brokered` mount's guest path creates nothing in the
/// host folder. The launcher sets the working directory to "/", so the launch starts there.
/// Control (#122), asserted first in each mode: the same image and product argv with
/// `--workdir /` taken out creates `made-at-init` in the host folder.
#[test]
fn rt_fs_02_the_image_working_directory_creates_nothing_in_a_mount() {
    rt().block_on(async {
        let x = Lx::new();
        let dir = home(&x).join("code/myproject");
        host_file(&x, "code/myproject/README", "keep\n");
        let image = image_with("WORKDIR /workspace/p/made-at-init\n");
        for mode in ["ro", "brokered"] {
            let v = manifest(&x, mode);
            image_control(
                &x,
                &dir,
                &image,
                (&v, mode),
                LeaveOut::Workdir,
                "made-at-init",
            )
            .await;
            let before = tree(&dir);
            assert!(before.contains(&"README".to_owned()), "control: {before:?}");
            let got = launch_image(&x, &manifest(&x, mode), image.clone(), mode).await;
            let after = tree(&dir);
            let started = got.as_ref().map(|_| ()).map_err(String::clone);
            if let Ok(r) = got {
                let (code, pwd) = exec(&r, "pwd").await;
                x.stop(r).await;
                assert_eq!((code, pwd.trim()), (0, "/"), "{mode}");
            }
            assert_eq!(
                after, before,
                "{mode}: the host folder changed ({started:?})"
            );
            assert!(started.is_ok(), "{mode}: {started:?}");
        }
    });
}

/// RT-FS-02, image volumes (security review): an image that declares a volume below an `ro` or
/// a `brokered` mount's guest path creates nothing in the host folder. Image-declared volumes
/// are disabled, so the launch starts with no extra mount.
/// Control (#122), asserted first in each mode: the same image and product argv with
/// `--image-volume=ignore` taken out creates `vol` in the host folder.
#[test]
fn rt_fs_02_an_image_volume_creates_nothing_in_a_mount() {
    rt().block_on(async {
        let x = Lx::new();
        let dir = home(&x).join("code/myproject");
        host_file(&x, "code/myproject/README", "keep\n");
        let image = image_with("VOLUME /workspace/p/vol\n");
        for mode in ["ro", "brokered"] {
            let v = manifest(&x, mode);
            image_control(&x, &dir, &image, (&v, mode), LeaveOut::ImageVolume, "vol").await;
            let before = tree(&dir);
            assert!(before.contains(&"README".to_owned()), "control: {before:?}");
            let got = launch_image(&x, &manifest(&x, mode), image.clone(), mode).await;
            let after = tree(&dir);
            let started = got.as_ref().map(|_| ()).map_err(String::clone);
            if let Ok(r) = got {
                x.stop(r).await;
            }
            assert_eq!(
                after, before,
                "{mode}: the host folder changed ({started:?})"
            );
            assert!(started.is_ok(), "{mode}: {started:?}");
        }
    });
}

/// Two mounts: `~/code/myproject` at `a` in `mode`, then `~/code/other` at `b` read-only.
fn two_mounts(x: &Lx, (a, mode): (&str, &str), b: &str) -> sally_core::manifest::ValidatedManifest {
    x.f.load(&mounts(&[
        mount("~/code/myproject", a, mode),
        mount("~/code/other", b, "ro"),
    ]))
}

/// A launch from `image` that the mount-link probe must refuse at `dest`: refused with the
/// probe's own reason naming `dest` (not the post-init mount check, not a podman error), both
/// host folders unchanged, and no container of the fixture left, the probe included.
async fn refused_at(
    x: &Lx,
    dirs: &[std::path::PathBuf; 2],
    (v, image, tag): (
        &sally_core::manifest::ValidatedManifest,
        &sallyd::sandbox::ImageRef,
        &str,
    ),
    dest: &str,
) {
    let before: Vec<_> = dirs.iter().map(|d| tree(d)).collect();
    let got = launch_image(x, v, image.clone(), tag).await;
    let after: Vec<_> = dirs.iter().map(|d| tree(d)).collect();
    let got = match got {
        Ok(r) => {
            x.stop(r).await;
            Err("the launch started".to_owned())
        }
        Err(e) => Ok(e),
    };
    assert_eq!(after, before, "{tag}: a host folder changed ({got:?})");
    let err = got.unwrap_or_else(|e| panic!("{tag}: {e}"));
    assert!(
        err.contains(&format!("MountLink(Refused {{ dest: \"{dest}\"")),
        "{tag}: not the probe's refusal at {dest}: {err}"
    );
    assert!(!x.listed(), "{tag}: a container is left");
}

/// RT-FS-02, mount placement (security review): an image whose root filesystem holds a link at
/// or above a mount destination creates nothing in any host folder; the launcher's mount-link
/// probe walks every destination before the runtime places any mount and refuses.
///
/// - Link above (`/workspace/b -> /workspace/a`, mounts `/workspace/a` then `/workspace/b/c`),
///   for an `ro`, a `brokered` and an `rw` first mount. Control (#122), asserted first in each
///   mode: the same product argv run outside the launcher (no probe) makes the runtime create
///   `c` in the first mount's host folder. Product leg: refused at `/workspace/b/c`.
/// - Allow: the same directories with no link launch, and nothing changes.
/// - Link at (`/workspace/q -> /workspace/p/made-by-link`, mounts `/workspace/p`,
///   `/workspace/q`): refused at `/workspace/q`. For this image the runtime also refuses at
///   `init` (measured), so the host-unchanged clause does not depend on the probe here; the
///   probe's refusal reason is what this leg holds. It rests on the link-above control.
/// - A link at `/tmp` (to a path below the first mount): refused at `/tmp`, so destinations that
///   are not the manifest's are walked too. It rests on the link-above control.
/// - A link at `/etc/hostname`, one of podman's standard destinations (to a path below an `rw`
///   first mount): refused at `/etc/hostname`, so the standard set is walked too. It rests on
///   the link-above control.
#[test]
fn rt_fs_02_an_image_link_at_or_above_a_mount_creates_nothing() {
    rt().block_on(async {
        let x = Lx::new();
        host_file(&x, "code/myproject/README", "keep\n");
        host_file(&x, "code/other/README", "keep\n");
        let dirs = [home(&x).join("code/myproject"), home(&x).join("code/other")];
        let above = image_with("RUN mkdir -p /workspace/a && ln -s /workspace/a /workspace/b\n");
        for mode in ["ro", "brokered", "rw"] {
            let v = two_mounts(&x, ("/workspace/a", mode), "/workspace/b/c");
            image_control(&x, &dirs[0], &above, (&v, mode), LeaveOut::Probe, "c").await;
            refused_at(&x, &dirs, (&v, &above, mode), "/workspace/b/c").await;
        }

        let v = two_mounts(&x, ("/workspace/a", "ro"), "/workspace/b/c");
        let plain = image_with("RUN mkdir -p /workspace/a /workspace/b\n");
        let before: Vec<_> = dirs.iter().map(|d| tree(d)).collect();
        let r = launch_image(&x, &v, plain, "allow")
            .await
            .expect("allow: no link launches");
        x.stop(r).await;
        let after: Vec<_> = dirs.iter().map(|d| tree(d)).collect();
        assert_eq!(after, before, "allow: a host folder changed");
        assert!(
            !x.listed(),
            "allow: a container is left, the probe included"
        );

        let at =
            image_with("RUN mkdir -p /workspace && ln -s /workspace/p/made-by-link /workspace/q\n");
        let v = two_mounts(&x, ("/workspace/p", "ro"), "/workspace/q");
        refused_at(&x, &dirs, (&v, &at, "at"), "/workspace/q").await;

        let tmp =
            image_with("RUN mkdir -p /workspace/a && rm -rf /tmp && ln -s /workspace/a/tmp /tmp\n");
        let v = two_mounts(&x, ("/workspace/a", "ro"), "/workspace/b/c");
        refused_at(&x, &dirs, (&v, &tmp, "tmp"), "/tmp").await;

        // Built in a second stage: the build keeps `/etc/hostname` mounted, so a plain `RUN`
        // cannot replace it.
        let hostname = image_with(
            "RUN mkdir /r && for d in bin etc home lib media mnt opt root sbin srv usr var; \
             do cp -a /$d /r/; done && mkdir -p /r/proc /r/sys /r/dev /r/run /r/tmp \
             /r/workspace/a && rm -f /r/etc/hostname \
             && ln -s /workspace/a/hostname /r/etc/hostname\nFROM scratch\nCOPY --from=0 /r/ /\n",
        );
        let v = two_mounts(&x, ("/workspace/a", "rw"), "/workspace/b/c");
        refused_at(&x, &dirs, (&v, &hostname, "hostname"), "/etc/hostname").await;
    });
}

/// RT-FS-03's reads through the host-made `evil -> ~/.ssh` and the sandbox-made `s2` (a link to
/// the canary's absolute host path).
const FS03_READS: [&str; 3] = [
    "cat /workspace/p/evil/id_ed25519",
    "ls /workspace/p/evil/",
    "cat /workspace/p/s2",
];

/// The sandbox's link to the canary key `key` by its absolute host path.
fn fs03_link(key: &Path) -> String {
    format!("ln -s '{}' /workspace/p/s2 2>&1", key.display())
}

/// RT-FS-03: symlinks resolve inside the container. One made in the sandbox to `/etc/shadow`
/// reads the container's own file (or is refused); one the host made before the launch,
/// `evil -> ~/.ssh`, points at a path that does not exist in the container. Control (#122),
/// asserted first: in a container from the same product argv with the fixture's `~/.ssh`
/// bound at its host path, the same reads through both links find the canary.
#[test]
fn rt_fs_03_symlinks_resolve_inside_the_container() {
    rt().block_on(async {
        let x = Lx::new();
        let c = canary();
        host_file(&x, ".ssh/id_ed25519", &c);
        let dir = home(&x).join("code/myproject");
        let ssh = home(&x).join(".ssh");
        let key = ssh.join("id_ed25519");
        std::os::unix::fs::symlink(&ssh, dir.join("evil")).unwrap();
        let guest = ssh.display().to_string();
        let leave_out = LeaveOut::Bind {
            host: &ssh,
            guest: &guest,
        };
        let id = x
            .control_workspace(&manifest(&x, "rw"), "fs03c", leave_out)
            .await;
        let (code, out) = exec_control(&id, &fs03_link(&key));
        assert_eq!(code, 0, "control: {out}");
        for cmd in FS03_READS {
            let (code, out) = exec_control(&id, &format!("{cmd} 2>&1"));
            assert_eq!(code, 0, "control: {cmd}: {out}");
            assert!(
                out.contains(&c) || out.contains("id_ed25519"),
                "control: {cmd}: {out}"
            );
        }
        std::fs::remove_file(dir.join("s2")).unwrap();
        let r = launch_with(&x, "rw", "fs03").await;
        let (code, out) = exec(&r, "ln -s /etc/shadow /workspace/p/s 2>&1").await;
        assert_eq!(code, 0, "{out}");
        // The link resolves to the container's own /etc/shadow (same st_dev:st_ino), or dangles
        // like it; never to the host's file.
        let (_, ids) = exec(&r, "stat -L -c '%d:%i' /workspace/p/s /etc/shadow 2>&1").await;
        let lines: Vec<&str> = ids.lines().collect();
        let dangling = lines.iter().all(|l| l.contains("No such file"));
        assert!(
            lines.len() == 2 && (lines.first() == lines.get(1) || dangling),
            "s resolves inside the container: {ids}"
        );
        let host = {
            use std::os::unix::fs::MetadataExt;
            let m = std::fs::metadata("/etc/shadow").unwrap();
            format!("{}:{}", m.dev(), m.ino())
        };
        assert!(!ids.contains(&host), "s is the host's /etc/shadow: {ids}");
        // A link the sandbox makes to the canary's absolute host path resolves in the container.
        let (code, out) = exec(&r, &fs03_link(&key)).await;
        assert_eq!(code, 0, "{out}");
        for cmd in FS03_READS {
            let (code, out) = exec(&r, &format!("{cmd} 2>&1")).await;
            assert_ne!(code, 0, "{cmd}: {out}");
            assert!(!out.contains(&c), "{cmd}: {out}");
            assert!(
                out.contains("No such file or directory"),
                "{cmd}: ENOENT: {out}"
            );
        }
        x.stop(r).await;
    });
}

/// RT-FS-07's node paths and the device each attack asks for there. The 0/0 character node is
/// one an unprivileged process may make on kernel 5.8 and later (PROBE_NOTES), so there the
/// profile is the only layer.
const FS07_NODES: [(&str, &str); 3] = [
    ("/tmp/sda", "b 8 0"),
    ("/workspace/p/mem", "c 1 1"),
    ("/tmp/w", "c 0 0"),
];

/// RT-FS-07: no device node can be created, in `/tmp` or in a mount: `mknod` fails with ENOSYS,
/// the seccomp default (the kernel never returns it for `mknod`, so the profile refused).
/// Control (analogue, #122, architect Q154 as superseded for FS-07), asserted first: the same
/// paths are writable. The profile refuses every `mknod`, so no node of any kind is a success
/// analogue; leaving the defence out would need a profile change or `--cap-add`.
#[test]
fn rt_fs_07_device_nodes_cannot_be_created() {
    rt().block_on(async {
        let x = Lx::new();
        let r = launch_with(&x, "rw", "fs07").await;
        for (path, _) in FS07_NODES {
            let cmd = format!("touch {path} && rm {path}");
            let (code, out) = exec(&r, &format!("{cmd} 2>&1")).await;
            assert_eq!(code, 0, "control: {cmd}: {out}");
        }
        for (path, dev) in FS07_NODES {
            let cmd = format!("mknod {path} {dev}");
            let (code, out) = exec(&r, &format!("{cmd} 2>&1")).await;
            assert_ne!(code, 0, "{cmd}: {out}");
            assert!(
                out.contains("Function not implemented"),
                "{cmd}: ENOSYS: {out}"
            );
        }
        assert!(!home(&x).join("code/myproject/mem").exists());
        let (_, out) = exec(&r, "grep -E ' /(tmp|workspace/p) ' /proc/self/mountinfo").await;
        assert_eq!(out.lines().count(), 2, "/tmp and /workspace/p: {out}");
        for line in out.lines() {
            assert!(line.contains("nodev"), "nodev: {line}");
        }
        x.stop(r).await;
    });
}

/// RT-FS-08's search for setuid files under `root` on its own filesystem.
fn find_setuid(root: &str) -> String {
    format!("find {root} -xdev -perm -4000 2>/dev/null; echo done")
}

/// RT-FS-08: the image holds no setuid file; mounts are `nosuid` and `no-new-privileges` is
/// set, so a setuid copy made in the sandbox runs with the same euid. Control (#122), asserted
/// first: a setuid file planted in the mount is found by the same search.
#[test]
fn rt_fs_08_setuid_never_raises_privileges() {
    rt().block_on(async {
        let x = Lx::new();
        let planted = home(&x).join("code/myproject/planted");
        std::fs::write(&planted, "").unwrap();
        std::fs::set_permissions(&planted, std::fs::Permissions::from_mode(0o4755)).unwrap();
        let r = launch_with(&x, "rw", "fs08").await;
        let (_, out) = exec(&r, &find_setuid("/workspace/p")).await;
        assert_eq!(
            out.trim(),
            "/workspace/p/planted\ndone",
            "control: the planted setuid file is found"
        );
        std::fs::remove_file(&planted).unwrap();
        let (_, out) = exec(&r, &find_setuid("/")).await;
        assert_eq!(out.trim(), "done", "setuid files in the image");
        let (_, out) = exec(&r, "grep NoNewPrivs /proc/self/status").await;
        assert_eq!(
            out.split_whitespace().collect::<Vec<_>>(),
            ["NoNewPrivs:", "1"]
        );
        let (_, out) = exec(&r, "grep ' /workspace/p ' /proc/self/mountinfo").await;
        assert!(out.contains("nosuid"), "{out}");
        let (code, out) = exec(
            &r,
            "cp /bin/busybox /workspace/p/sh && chmod u+s /workspace/p/sh && \
             stat -c %a /workspace/p/sh && /workspace/p/sh -c 'id -u' && id -u",
        )
        .await;
        assert_eq!(code, 0, "{out}");
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines.first().copied(),
            Some("4755"),
            "the bit was set: {out}"
        );
        assert_eq!(lines.get(1), lines.get(2), "euid unchanged: {out}");
        x.stop(r).await;
    });
}

/// RT-FS-09's writes: `(value, path)` written as `echo <value> > <path>`.
const FS09_WRITES: [(&str, &str); 5] = [
    ("c", "/proc/sysrq-trigger"),
    ("1", "/proc/sys/kernel/sysrq"),
    ("3", "/proc/sys/vm/drop_caches"),
    ("x", "/proc/sys/kernel/hostname"),
    ("1", "/sys/kernel/mm/ksm/run"),
];

/// RT-FS-09's read of the first 64 bytes of `path`, counted.
fn head64(path: &str) -> String {
    format!("head -c 64 {path} 2>/dev/null | wc -c")
}

/// RT-FS-09: `/proc` and `/sys` give nothing: no sysrq, no `/proc/sys` or `/sys` writes,
/// `/proc/kcore` is masked (it reads as empty), and PID 1 is the container's entry. Control
/// (analogue, #122, architect Q154), asserted first: the same write form to `/tmp` and the same
/// read of `/proc/self/status` succeed; the masks are read directly (`/proc/kcore` is the
/// `/dev/null` node, `/sys` is mounted `ro`). Leaving them out would need `--privileged` or
/// `--security-opt` (a hard rule forbids both).
#[test]
fn rt_fs_09_proc_and_sys_are_closed() {
    rt().block_on(async {
        let x = Lx::new();
        let r = launch_with(&x, "rw", "fs09").await;
        for (value, _) in FS09_WRITES {
            let cmd = format!("echo {value} > /tmp/w && test \"$(cat /tmp/w)\" = {value}");
            let (code, out) = exec(&r, &format!("{cmd} 2>&1")).await;
            assert_eq!(code, 0, "control: {cmd}: {out}");
        }
        let (_, out) = exec(&r, &head64("/proc/self/status")).await;
        assert_eq!(out.trim(), "64", "control: the read sees a /proc file");
        let (_, out) = exec(&r, "stat -c %F:%t:%T /proc/kcore").await;
        assert_eq!(
            out.trim(),
            "character special file:1:3",
            "kcore is /dev/null"
        );
        let (_, out) = exec(&r, "grep ' /sys ' /proc/self/mountinfo").await;
        assert!(out.contains(" /sys ro,"), "/sys is read-only: {out}");
        for (value, path) in FS09_WRITES {
            let cmd = format!("echo {value} > {path}");
            let (code, out) = exec(&r, &format!("{cmd} 2>&1")).await;
            assert_ne!(code, 0, "{cmd}: {out}");
            assert!(out.contains("Read-only file system"), "{cmd}: EROFS: {out}");
        }
        let (code, out) = exec(&r, "touch /sys/x 2>&1").await;
        assert_ne!(code, 0, "{out}");
        assert!(out.contains("Read-only file system"), "EROFS: {out}");
        // Masked: podman binds /dev/null over it, so it reads as empty.
        let (_, out) = exec(&r, &head64("/proc/kcore")).await;
        assert_eq!(out.trim(), "0", "/proc/kcore yields nothing");
        let (_, out) = exec(&r, "tr '\\0' ' ' < /proc/1/cmdline").await;
        assert!(
            out.starts_with("/run/podman-init -- /opt/sallyport/entry"),
            "PID 1 is the container's init running the entry: {out}"
        );
        x.stop(r).await;
    });
}

/// WSL with interop registered (`binfmt_misc/WSLInterop`).
fn wsl_interop() -> Option<std::path::PathBuf> {
    let reg = Path::new("/proc/sys/fs/binfmt_misc/WSLInterop");
    let cmd = Path::new("/mnt/c/Windows/System32/cmd.exe");
    (reg.exists() && cmd.exists()).then(|| cmd.to_owned())
}

/// RT-FS-11's count of the entries in `/mnt`.
const LS_MNT: &str = "ls -A /mnt 2>/dev/null | wc -l";

/// RT-FS-11, first part (every host): `/mnt` is absent or empty in the sandbox. Control (#122),
/// asserted first: the same count, in a container from the same product argv with a host
/// directory bound below `/mnt`, finds it.
#[test]
fn rt_fs_11_mnt_is_absent_or_empty() {
    rt().block_on(async {
        let x = Lx::new();
        let drive = x.f.root.join("drive");
        std::fs::create_dir(&drive).unwrap();
        let leave_out = LeaveOut::Bind {
            host: &drive,
            guest: "/mnt/x",
        };
        let id = x
            .control_workspace(&manifest(&x, "rw"), "fs11c", leave_out)
            .await;
        let (_, out) = exec_control(&id, LS_MNT);
        assert_eq!(out.trim(), "1", "control: /mnt/x is listed");
        let r = launch_with(&x, "rw", "fs11").await;
        let (_, out) = exec(&r, LS_MNT).await;
        assert_eq!(out.trim(), "0", "/mnt is absent or empty");
        x.stop(r).await;
    });
}

/// `cmd.exe /c <line>` on the host, from a Windows working directory.
fn host_cmd(cmd: &Path, line: &str) -> std::process::Output {
    std::process::Command::new(cmd)
        .args(["/c", line])
        .current_dir("/mnt/c/ProgramData")
        .output()
        .unwrap()
}

/// RT-FS-11, second part (local, WSL only): a Windows executable in a mount does not reach
/// Windows. The only approved `#[ignore]` on an `rt_` test (CLAUDE.md): off WSL nextest lists it
/// as skipped, never as passed; on WSL `make redteam` runs it and fails if it did not run. Run
/// anywhere else it fails. A host-side control first creates and deletes one empty canary file
/// under `C:\ProgramData` with the same command, so the sandbox's failure is not vacuous.
#[test]
#[ignore = "requires WSL"]
fn rt_fs_11_wsl_a_windows_executable_does_not_reach_windows() {
    let cmd = wsl_interop().expect("RT-FS-11 .exe part: WSL with interop and cmd.exe required");
    rt().block_on(async {
        let x = Lx::new();
        std::fs::copy(&cmd, home(&x).join("code/myproject/cmd.exe")).unwrap();
        let r = launch_with(&x, "rw", "fs11w").await;
        let name = canary();
        let host_canary = Path::new("/mnt/c/ProgramData").join(&name);
        let write = format!("type nul > C:\\ProgramData\\{name}");
        let made = host_cmd(&cmd, &write);
        let size = std::fs::metadata(&host_canary).map(|m| m.len());
        assert!(matches!(size, Ok(0)), "control create: {size:?} {made:?}");
        let gone = host_cmd(&cmd, &format!("del C:\\ProgramData\\{name}"));
        assert!(!host_canary.exists(), "control delete: {gone:?}");
        let (code, out) = exec(
            &r,
            &format!("cd /workspace/p && ./cmd.exe /c '{write}' 2>&1"),
        )
        .await;
        let reached = host_canary.exists();
        if reached {
            std::fs::remove_file(&host_canary).unwrap();
        }
        assert!(!reached, "the sandbox reached Windows: {out}");
        assert_ne!(code, 0, "{out}");
        x.stop(r).await;
    });
    // A Windows drive is on a filesystem type this host refuses as a mount root, wherever the
    // drive is mounted (the seam leg in sally-core's rt_manifest.rs shows a listed type is
    // refused). Only the mount table's entry for the drive is read (`findmnt --mountpoint`),
    // nothing on the drive is opened.
    let config = sally_core::config::Config::default();
    let env = sally_core::manifest::HostEnv::from_process(&config).unwrap();
    for listed in [sally_core::manifest::V9FS, sally_core::manifest::VIRTIOFS] {
        assert!(
            env.refused_fs_kinds.contains(&listed),
            "{:?}",
            env.refused_fs_kinds
        );
    }
    let o = std::process::Command::new("findmnt")
        .args(["-n", "-o", "FSTYPE", "--mountpoint", "/mnt/c"])
        .output()
        .unwrap();
    assert!(o.status.success(), "findmnt: {o:?}");
    let ty = String::from_utf8(o.stdout).unwrap();
    let part = ty.trim().split('.').next().unwrap();
    assert!(
        env.refused_fs_kinds.iter().any(|k| k.name == part),
        "/mnt/c is of type {part:?}, not refused"
    );
}
