//! Workspace escape rows with real containers (Task 6c-2): RT-FS-01 (host home invisible),
//! RT-FS-02 (`ro` is read-only), RT-FS-03 (symlinks resolve inside the container), RT-FS-07
//! (no device nodes), RT-FS-08 (no setuid), RT-FS-09 (`/proc` and `/sys`) and RT-FS-11 (no WSL
//! interop). The fixture is `common::container`; these tests never skip.
#![allow(clippy::unwrap_used, clippy::expect_used)]

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
    let v =
        x.f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", mode)]));
    x.launch(&v, tag).await.unwrap()
}

/// Every top-level directory of the container except the kernel's pseudo filesystems.
const SEARCH: &str = "$(ls / | grep -vxE 'proc|sys|dev' | sed 's|^|/|')";

/// RT-FS-01: nothing of the host home is visible. The canary sits in `~/.ssh`, in `~` and in a
/// sibling of the granted directory; no path finds it and no file in the container holds it.
#[test]
fn rt_fs_01_the_host_home_is_invisible() {
    rt().block_on(async {
        let x = Lx::new();
        let c = canary();
        for rel in [".ssh/id_ed25519", "secret.txt", "code/other/notes.txt"] {
            host_file(&x, rel, &c);
        }
        let r = launch_with(&x, "rw", "fs01").await;
        let (_, out) = exec(
            &r,
            "cat /home/*/.ssh/* ~/.ssh/* /root/.ssh/* 2>&1; ls -A /home 2>&1; echo HOME=$HOME",
        )
        .await;
        assert!(!out.contains(&c), "{out}");
        let (_, out) = exec(
            &r,
            &format!("grep -rls '{c}' {SEARCH} 2>/dev/null; echo done"),
        )
        .await;
        assert_eq!(out.trim(), "done", "a file holds the canary");
        let host = home(&x).display().to_string();
        let (code, out) = exec(&r, &format!("ls {host} {host}/.ssh 2>&1")).await;
        assert_ne!(code, 0, "{out}");
        x.stop(r).await;
    });
}

/// RT-FS-02: an `ro` mount refuses creating and deleting with EROFS; the host is unchanged.
#[test]
fn rt_fs_02_an_ro_mount_is_read_only() {
    rt().block_on(async {
        let x = Lx::new();
        host_file(&x, "code/myproject/README", "keep\n");
        let r = launch_with(&x, "ro", "fs02").await;
        for cmd in [
            "touch /workspace/p/x",
            "rm /workspace/p/README",
            "echo y >> /workspace/p/README",
            "mkdir /workspace/p/d",
        ] {
            let (code, out) = exec(&r, &format!("{cmd} 2>&1")).await;
            assert_ne!(code, 0, "{cmd}: {out}");
            assert!(out.contains("Read-only file system"), "{cmd}: EROFS: {out}");
        }
        let dir = home(&x).join("code/myproject");
        assert_eq!(
            std::fs::read_to_string(dir.join("README")).unwrap(),
            "keep\n"
        );
        assert!(!dir.join("x").exists() && !dir.join("d").exists());
        x.stop(r).await;
    });
}

/// RT-FS-03: symlinks resolve inside the container. One made in the sandbox to `/etc/shadow`
/// reads the container's own file (or is refused); one the host made before the launch,
/// `evil -> ~/.ssh`, points at a path that does not exist in the container.
#[test]
fn rt_fs_03_symlinks_resolve_inside_the_container() {
    rt().block_on(async {
        let x = Lx::new();
        let c = canary();
        host_file(&x, ".ssh/id_ed25519", &c);
        let dir = home(&x).join("code/myproject");
        std::os::unix::fs::symlink(home(&x).join(".ssh"), dir.join("evil")).unwrap();
        let r = launch_with(&x, "rw", "fs03").await;
        let (_, out) = exec(
            &r,
            "ln -s /etc/shadow /workspace/p/s && cat /workspace/p/s 2>&1; \
             cat /workspace/p/evil/id_ed25519 2>&1; ls /workspace/p/evil/ 2>&1",
        )
        .await;
        assert!(!out.contains(&c), "{out}");
        assert!(
            out.contains("No such file or directory"),
            "evil: ENOENT: {out}"
        );
        let shadow = std::fs::read_to_string("/etc/shadow").unwrap_or_default();
        let (_, mine) = exec(&r, "cat /workspace/p/s 2>&1").await;
        assert!(
            mine.contains("Permission denied")
                || shadow.is_empty()
                || !shadow.contains(mine.trim()),
            "the container's own /etc/shadow, or refused: {mine}"
        );
        x.stop(r).await;
    });
}

/// RT-FS-07: no device node can be created, in `/tmp` or in a mount.
#[test]
fn rt_fs_07_device_nodes_cannot_be_created() {
    rt().block_on(async {
        let x = Lx::new();
        let r = launch_with(&x, "rw", "fs07").await;
        for cmd in ["mknod /tmp/sda b 8 0", "mknod /workspace/p/mem c 1 1"] {
            let (code, out) = exec(&r, &format!("{cmd} 2>&1")).await;
            assert_ne!(code, 0, "{cmd}: {out}");
            assert!(
                out.contains("Function not implemented") || out.contains("Operation not permitted"),
                "{cmd}: ENOSYS or EPERM: {out}"
            );
        }
        assert!(!home(&x).join("code/myproject/mem").exists());
        let (_, out) = exec(&r, "grep -E ' /(tmp|workspace/p) ' /proc/self/mountinfo").await;
        for line in out.lines() {
            assert!(line.contains("nodev"), "nodev: {line}");
        }
        x.stop(r).await;
    });
}

/// RT-FS-08: the image holds no setuid file; mounts are `nosuid` and `no-new-privileges` is
/// set, so a setuid copy made in the sandbox runs with the same euid.
#[test]
fn rt_fs_08_setuid_never_raises_privileges() {
    rt().block_on(async {
        let x = Lx::new();
        let r = launch_with(&x, "rw", "fs08").await;
        let (_, out) = exec(&r, "find / -xdev -perm -4000 2>/dev/null; echo done").await;
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

/// RT-FS-09: `/proc` and `/sys` give nothing: no sysrq, no `/proc/sys` or `/sys` writes,
/// `/proc/kcore` is masked (it reads as empty), and PID 1 is the container's entry.
#[test]
fn rt_fs_09_proc_and_sys_are_closed() {
    rt().block_on(async {
        let x = Lx::new();
        let r = launch_with(&x, "rw", "fs09").await;
        for cmd in [
            "echo c > /proc/sysrq-trigger",
            "echo 1 > /proc/sys/kernel/sysrq",
            "echo 3 > /proc/sys/vm/drop_caches",
            "echo x > /proc/sys/kernel/hostname",
            "echo 1 > /sys/kernel/mm/ksm/run",
            "touch /sys/x",
        ] {
            let (code, out) = exec(&r, &format!("{cmd} 2>&1")).await;
            assert_ne!(code, 0, "{cmd}: {out}");
        }
        // Masked: podman binds /dev/null over it, so it reads as empty.
        let (_, out) = exec(&r, "head -c 64 /proc/kcore 2>/dev/null | wc -c").await;
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

/// RT-FS-11 (as rewritten after 6c-1): `/mnt` is absent or empty, and a Windows executable in a
/// mount does not reach Windows: the canary it would create on `C:` is never created. On a host
/// without WSL interop only the `/mnt` part applies (REDTEAM_SUITE: the `.exe` part is WSL
/// only). The same command run on the host first proves the canary would be created.
#[test]
fn rt_fs_11_a_windows_executable_does_not_reach_windows() {
    rt().block_on(async {
        let x = Lx::new();
        let exe = wsl_interop();
        if let Some(cmd) = &exe {
            std::fs::copy(cmd, home(&x).join("code/myproject/cmd.exe")).unwrap();
        }
        let r = launch_with(&x, "rw", "fs11").await;
        let (_, out) = exec(&r, "ls -A /mnt 2>/dev/null | wc -l").await;
        assert_eq!(out.trim(), "0", "/mnt is absent or empty");
        let Some(cmd) = exe else {
            eprintln!("RT-FS-11: not WSL with interop; the .exe part does not apply");
            x.stop(r).await;
            return;
        };
        let name = canary();
        let host_canary = Path::new("/mnt/c/ProgramData").join(&name);
        let write = format!("echo x > C:\\ProgramData\\{name}");
        let control = std::process::Command::new(&cmd)
            .args(["/c", &write])
            .current_dir("/mnt/c/ProgramData")
            .output()
            .unwrap();
        assert!(host_canary.exists(), "control: {control:?}");
        std::fs::remove_file(&host_canary).unwrap();
        let (code, out) = exec(
            &r,
            &format!("cd /workspace/p && ./cmd.exe /c '{write}' 2>&1"),
        )
        .await;
        assert_ne!(code, 0, "{out}");
        assert!(!host_canary.exists(), "the sandbox reached Windows: {out}");
        x.stop(r).await;
    });
}
