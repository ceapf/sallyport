//! RT-AG-09, the bombs: a fork bomb, a memory bomb and a `/tmp` filler are each contained by the
//! session's limits (`runtime.pids`, `runtime.memory`, `runtime.tmp_size`). The fork bomb and
//! the memory bomb are also audited: the watchdog's cgroup observer writes
//! `session.resource_limit` (`pids-max`, `oom-kill`) and the session runs on (#27, architect
//! Q48). The `/tmp` filler is contained only: a tmpfs has no kernel event. The stage-size and
//! floor parts of the row are in `disk.rs` and `launch.rs`. The fixture is `common::container`;
//! these tests never skip.
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

/// The `session.resource_limit` entries naming `resource`, in order.
fn limits(x: &Lx, resource: &str) -> Vec<serde_json::Value> {
    x.events
        .all()
        .into_iter()
        .filter(|(e, a)| e == "session.resource_limit" && a["resource"] == resource)
        .map(|(_, a)| a)
        .collect()
}

/// The observer polls every second: waits up to 5 s for a first entry naming `resource`.
async fn first_limit(x: &Lx, resource: &str) -> serde_json::Value {
    for _ in 0..50 {
        if let Some(a) = limits(x, resource).into_iter().next() {
            return a;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("no {resource} entry in {:?}", x.events.list());
}

/// A classic shell fork bomb runs for 3 s: the container's process count never exceeds
/// `runtime.pids`, forks are refused (`pids.events` max) and audited (`pids-max`, at most one
/// entry per poll), the host still forks, and the session stops cleanly.
#[test]
fn rt_ag_09_a_fork_bomb_is_held_by_the_pids_limit() {
    rt().block_on(async {
        let x = Lx::new();
        // Before the launch: the observer's first tick fires as soon as it is spawned.
        let started = std::time::Instant::now();
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
        let a = first_limit(&x, "pids").await;
        assert_eq!(
            (&a["role"], &a["reason"]),
            (&"workspace".into(), &"pids-max".into()),
            "{a}"
        );
        assert!(a["count"].as_u64().unwrap() > 0, "{a}");
        assert!(limits(&x, "memory").is_empty(), "{:?}", x.events.list());
        x.stop(r).await;
        let polls = started.elapsed().as_secs() + 2;
        let n = limits(&x, "pids").len() as u64;
        assert!(n <= polls, "{n} entries in {polls} polls");
        let counts: Vec<u64> = limits(&x, "pids")
            .iter()
            .map(|a| a["count"].as_u64().unwrap())
            .collect();
        assert!(counts.windows(2).all(|w| w[0] < w[1]), "{counts:?}");
    });
}

/// A memory bomb (a string that doubles until allocation fails) is OOM-killed inside the
/// container and audited (`oom-kill`); the session keeps running.
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
        let a = first_limit(&x, "memory").await;
        assert_eq!(a["reason"], "oom-kill", "{a}");
        assert!(a["count"].as_u64().unwrap() >= 1, "{a}");
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
