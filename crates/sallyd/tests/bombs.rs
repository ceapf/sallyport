//! RT-AG-09, the bombs: a fork bomb, a memory bomb and a `/tmp` filler are each contained by the
//! session's limits (`runtime.pids`, `runtime.memory`, `runtime.tmp_size`). These prove
//! containment only: no existing code observes these conditions, so their
//! `session.resource_limit` audit entries are #27 (Task 12). The stage-size and floor parts of
//! the row are in `disk.rs` and `launch.rs`. The fixture is `common::container`; these tests
//! never skip.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use sallyd::sandbox::Running;

mod common;
use common::container::*;
use common::*;

const PIDS: u32 = 64;
const TMP_MIB: u64 = 8;

async fn launch_small(x: &Lx, tag: &str) -> Running {
    let v = x.f.load(&format!(
        "{}runtime:\n  memory: 64MiB\n  pids: {PIDS}\n  tmp_size: {TMP_MIB}MiB\n",
        mounts(&[mount("~/code/myproject", "/workspace/p", "ro")])
    ));
    x.launch(&v, tag).await.unwrap()
}

/// The container's own cgroup on the host (where crun applies the limits), read from the host
/// so it works while the container cannot fork.
async fn cgroup(x: &Lx, r: &Running) -> std::path::PathBuf {
    let path = x
        .hermetic(&[
            "inspect".into(),
            "--format".into(),
            "{{.State.CgroupPath}}".into(),
            r.container().into(),
        ])
        .await;
    let dir = std::path::Path::new("/sys/fs/cgroup")
        .join(path.trim().trim_start_matches('/'))
        .join("container");
    assert!(dir.join("pids.max").exists(), "{}", dir.display());
    dir
}

fn read(dir: &std::path::Path, file: &str) -> String {
    std::fs::read_to_string(dir.join(file)).unwrap()
}

/// The `name` counter of a cgroup `*.events` file.
fn event(text: &str, name: &str) -> u64 {
    text.lines()
        .find_map(|l| l.strip_prefix(name)?.trim().parse().ok())
        .unwrap_or_else(|| panic!("{name} in {text}"))
}

/// A classic shell fork bomb runs for 3 s: the container's process count never exceeds
/// `runtime.pids`, forks are refused (`pids.events` max), the host still forks, and the session
/// stops cleanly.
#[test]
fn rt_ag_09_a_fork_bomb_is_held_by_the_pids_limit() {
    rt().block_on(async {
        let x = Lx::new();
        let r = launch_small(&x, "fork").await;
        let cg = cgroup(&x, &r).await;
        assert_eq!(read(&cg, "pids.max").trim(), PIDS.to_string());
        let (code, out) = exec(&r, "(b() { b | b & }; b) >/dev/null 2>&1 & echo started").await;
        assert_eq!((code, out.trim()), (0, "started"));
        tokio::time::sleep(Duration::from_secs(3)).await;
        // pids.peak where the kernel has it (6.x), else the count now, mid-bomb.
        let file = if cg.join("pids.peak").exists() {
            "pids.peak"
        } else {
            "pids.current"
        };
        let peak: u64 = read(&cg, file).trim().parse().unwrap();
        assert!(peak <= u64::from(PIDS), "{file} {peak}");
        assert!(
            event(&read(&cg, "pids.events"), "max ") > 0,
            "forks were refused"
        );
        for _ in 0..20 {
            let st = std::process::Command::new("true").status().unwrap();
            assert!(st.success(), "the host still forks");
        }
        x.stop(r).await;
    });
}

/// A memory bomb (a string that doubles until allocation fails) is OOM-killed inside the
/// container; the session keeps running.
#[test]
fn rt_ag_09_a_memory_bomb_is_oom_killed_inside_the_container() {
    rt().block_on(async {
        let x = Lx::new();
        let r = launch_small(&x, "oom").await;
        let cg = cgroup(&x, &r).await;
        assert_eq!(read(&cg, "memory.max").trim(), (64u64 << 20).to_string());
        // `--memory-swap` equals `--memory`: no swap, so the bomb cannot push the host to swap.
        assert_eq!(read(&cg, "memory.swap.max").trim(), "0");
        let marker = std::env::current_dir().unwrap().join("oom");
        let _ = std::fs::remove_file(&marker);
        let state = x.podman.hooks_dir().parent().unwrap().join("oom");
        let _ = std::fs::remove_file(&state);
        let (_, out) = exec(
            &r,
            "awk 'BEGIN { s = \"x\"; while (1) s = s s }'; echo \"rc=$?\"",
        )
        .await;
        assert!(out.contains("rc=137"), "SIGKILLed: {out}");
        let (code, events) = exec(&r, "cat /sys/fs/cgroup/memory.events").await;
        assert_eq!(code, 0, "{events}");
        assert!(event(&events, "oom_kill ") > 0, "{events}");
        let (code, out) = exec(&r, "echo alive").await;
        assert_eq!((code, out.trim()), (0, "alive"), "the session survives");
        x.stop(r).await;
        // conmon writes an `oom` marker into the working directory podman started it from: the
        // launcher's podman runs from its private state directory, never the caller's.
        assert!(
            !marker.exists(),
            "conmon wrote into sallyd's working directory"
        );
        // The control: the marker is written, into hermetic podman's state directory.
        assert!(state.exists(), "conmon's oom marker in the state directory");
    });
}

/// `yes > /tmp/f` stops at `runtime.tmp_size` with ENOSPC.
#[test]
fn rt_ag_09_a_tmp_filler_stops_at_the_tmpfs_size() {
    rt().block_on(async {
        let x = Lx::new();
        let r = launch_small(&x, "tmpfs").await;
        let (_, out) = exec(
            &r,
            "yes > /tmp/f; echo \"rc=$?\"; echo \"size=$(stat -c %s /tmp/f)\"; \
             dd if=/dev/zero of=/tmp/g bs=4k count=1 2>&1",
        )
        .await;
        // busybox `yes` exits 1 silently; one more write names the error.
        assert!(out.contains("No space left on device"), "{out}");
        let size: u64 = out
            .lines()
            .find_map(|l| l.strip_prefix("size=")?.trim().parse().ok())
            .unwrap_or_else(|| panic!("{out}"));
        let cap = TMP_MIB << 20;
        assert!(size <= cap && size > cap - (1 << 20), "{size} bytes: {out}");
        assert!(!out.contains("rc=0"), "{out}");
        x.stop(r).await;
    });
}
