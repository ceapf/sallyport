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
        let key = home(&x).join(".ssh/id_ed25519");
        let (code, out) = exec(
            &r,
            &format!("ln -s '{}' /workspace/p/s2 2>&1", key.display()),
        )
        .await;
        assert_eq!(code, 0, "{out}");
        for cmd in [
            "cat /workspace/p/evil/id_ed25519",
            "ls /workspace/p/evil/",
            "cat /workspace/p/s2",
        ] {
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
        assert_eq!(out.lines().count(), 2, "/tmp and /workspace/p: {out}");
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

/// RT-FS-11, first part (every host): `/mnt` is absent or empty in the sandbox.
#[test]
fn rt_fs_11_mnt_is_absent_or_empty() {
    rt().block_on(async {
        let x = Lx::new();
        let r = launch_with(&x, "rw", "fs11").await;
        let (_, out) = exec(&r, "ls -A /mnt 2>/dev/null | wc -l").await;
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
}
