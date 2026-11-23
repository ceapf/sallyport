//! RT-AG-09, the bombs: a fork bomb, a memory bomb and a `/tmp` filler are each contained by the
//! session's limits (`runtime.pids`, `runtime.memory`, `runtime.tmp_size`). The fork bomb and
//! the memory bomb are also audited: the watchdog's cgroup observer writes
//! `session.resource_limit` (`pids-max`, `oom-kill`) and the session runs on (#27). The fork
//! bomb runs with `runtime.memory` 256 MiB, memory to spare; the memory bomb and the `/tmp`
//! filler run with 64 MiB (#141). The `/tmp` filler is contained only: a tmpfs has no
//! kernel event. The stage-size and floor parts of the row are in `disk.rs` and `launch.rs`. The
//! fixture is `common::container`; these tests never skip.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use sallyd::sandbox::Running;

mod common;
use common::container::*;
use common::*;

const PIDS: u32 = 64;
const TMP_MIB: u64 = 8;
/// `runtime.memory` of the memory bomb and the `/tmp` filler.
const MEMORY_MIB: u64 = 64;
/// `runtime.memory` of the fork bomb alone, the maintainer's decision on #141: with 64 MiB its
/// `memory.peak` reached the limit in 2 of 50 runs beside a `make test` pass and in 1 of 2 runs
/// without load (PROBE_NOTES), so it runs with memory to spare and `runtime.pids` is the limit
/// it is there to reach.
const FORK_MEMORY_MIB: u64 = 256;

async fn launch_small(x: &Lx, tag: &str, memory_mib: u64) -> Running {
    let v = x.f.load(&format!(
        "{}runtime:\n  memory: {memory_mib}MiB\n  pids: {PIDS}\n  tmp_size: {TMP_MIB}MiB\n",
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

/// A file of the container's cgroup `dir`. A failed read panics at the caller's line, naming the
/// file, whether `dir` is still there, the container's state and the audit so far (#141: a
/// directory gone mid-test means the container ended).
#[track_caller]
fn read(x: &Lx, r: &Running, dir: &std::path::Path, file: &str) -> String {
    match std::fs::read_to_string(dir.join(file)) {
        Ok(text) => text,
        Err(e) => {
            let there = dir.is_dir();
            // Printed before podman is asked; podman then gets at most STATE_LIMIT.
            eprintln!(
                "{file} in {}: {e}; directory still there: {there}",
                dir.display()
            );
            panic!(
                "{file} in {}: {e}; directory still there: {there}; container: {}; audit: {:?}",
                dir.display(),
                container_state(x, r, STATE_LIMIT),
                x.events.list()
            )
        }
    }
}

/// How long a failed [`read`] waits for podman to describe the container. Generous: the failure
/// shows under load, and a false time-out would lose the state on the run that matters.
const STATE_LIMIT: Duration = Duration::from_secs(30);

/// The container's status, exit code and OOM-killed flag from hermetic podman, or why podman
/// could not say within `limit`. Only a failed [`read`] asks, so it blocks the runtime's
/// thread, for at most `limit`.
fn container_state(x: &Lx, r: &Running, limit: Duration) -> String {
    let fields = "{{.State.Status}} exit {{.State.ExitCode}} oom-killed {{.State.OOMKilled}}";
    let mut c = x.podman.command();
    let cmd = c
        .as_std_mut()
        .args(["inspect", "--format", fields, r.container()]);
    bounded_output(cmd, limit, "podman inspect")
}

/// Runs `cmd` in a process group of its own and waits at most `limit` for it to exit and close
/// its pipes (a process it started may hold one); past that the whole group is killed. Never
/// panics: every outcome is text, so it cannot replace the panic it reports for.
fn bounded_output(cmd: &mut std::process::Command, limit: Duration, what: &str) -> String {
    use std::os::unix::process::CommandExt as _;
    let spawned = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .process_group(0)
        .spawn();
    let child = match spawned {
        Ok(child) => child,
        Err(e) => return format!("{what} did not run: {e}"),
    };
    let leader = child.id();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    match rx.recv_timeout(limit) {
        Ok(Ok(o)) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_owned(),
        Ok(Ok(o)) => format!(
            "{what} failed ({}): {}",
            o.status,
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Ok(Err(e)) => format!("{what} did not finish: {e}"),
        Err(_) => {
            kill_group(leader);
            format!("{what} timed out after {limit:?}")
        }
    }
}

/// Kills the process group led by `leader`.
fn kill_group(leader: u32) {
    let pid = i32::try_from(leader)
        .ok()
        .and_then(rustix::process::Pid::from_raw);
    if let Some(pid) = pid {
        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    }
}

/// [`bounded_output`] gives up on a query whose pipes never close, says so, and kills its group.
/// No container: the query is a shell that exits at once, leaving a sleeper that holds its
/// stdout and stderr and writes its pid to a file.
#[test]
fn a_stalled_state_query_times_out_and_its_group_is_killed() {
    let limit = Duration::from_millis(200);
    let file = std::env::temp_dir().join(format!("sp-bombs-sleeper-{}", std::process::id()));
    let mut cmd = std::process::Command::new("sh");
    cmd.args(["-c", "sleep 60 & echo $! > \"$1\"", "sh"])
        .arg(&file);
    let started = std::time::Instant::now();
    let text = bounded_output(&mut cmd, limit, "the query");
    let took = started.elapsed();
    assert_eq!(text, format!("the query timed out after {limit:?}"));
    assert!(took < Duration::from_secs(5), "returned after {took:?}");
    let pid = std::fs::read_to_string(&file).unwrap();
    std::fs::remove_file(&file).unwrap();
    let stat = std::path::Path::new("/proc").join(pid.trim()).join("stat");
    // Killed: gone, or a zombie (Z) or being reaped (X) by its new parent.
    let dead = || {
        std::fs::read_to_string(&stat).map_or(true, |s| {
            s.rsplit_once(") ")
                .is_some_and(|(_, rest)| rest.starts_with(['Z', 'X']))
        })
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut killed = dead();
    while !killed && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
        killed = dead();
    }
    assert!(killed, "the sleeper {} outlived the time-out", pid.trim());
}

/// The `name` counter of a cgroup `*.events` file.
fn event(text: &str, name: &str) -> u64 {
    text.lines()
        .find_map(|l| l.strip_prefix(name)?.trim().parse().ok())
        .unwrap_or_else(|| panic!("{name} in {text}"))
}

/// The prefix of the fork-bomb test's one diagnostic line (#141); `scripts/loaded-repeat.sh` and
/// its test look for the same text.
const FIGURES_PREFIX: &str = "rt_ag_09 fork-bomb figures:";

/// The fork-bomb test's diagnostic line: `memory.peak`, the `memory.events` counters, `pids.peak`
/// and the `pids.events` max counter of the container's cgroup `cg`. A peak file or a counter the
/// kernel does not have prints `absent`. A failed read of an events file, or of a peak file that
/// is there, panics as [`read`] does: the cgroup gone at this point means the container ended.
#[track_caller]
fn figures(x: &Lx, r: &Running, cg: &std::path::Path) -> String {
    let mem = read(x, r, cg, "memory.events");
    let pids = read(x, r, cg, "pids.events");
    let counters = ["max ", "oom ", "oom_kill ", "oom_group_kill "]
        .map(|k| format!("{}={}", k.trim(), counter(&mem, k)))
        .join(" ");
    format!(
        "{FIGURES_PREFIX} memory.peak={} {counters} pids.peak={} pids.events.max={}",
        peak(x, r, cg, "memory.peak"),
        peak(x, r, cg, "pids.peak"),
        counter(&pids, "max ")
    )
}

/// A peak file of `cg`, trimmed, or `absent` where the kernel has none.
#[track_caller]
fn peak(x: &Lx, r: &Running, cg: &std::path::Path, file: &str) -> String {
    if cg.join(file).exists() {
        read(x, r, cg, file).trim().to_string()
    } else {
        "absent".to_string()
    }
}

/// The `name` counter of an events file's `text` for printing, or `absent` (an older kernel
/// without it, or a value that is not a number).
fn counter(text: &str, name: &str) -> String {
    text.lines()
        .find_map(|l| l.strip_prefix(name)?.trim().parse::<u64>().ok())
        .map_or_else(|| "absent".to_string(), |n| n.to_string())
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
        let r = launch_small(&x, "fork", FORK_MEMORY_MIB).await;
        let cg = cgroup(&x, &r).await;
        assert_eq!(read(&x, &r, &cg, "pids.max").trim(), PIDS.to_string());
        assert_eq!(
            read(&x, &r, &cg, "memory.max").trim(),
            (256u64 << 20).to_string()
        );
        let (code, out) = exec(&r, "(b() { b | b & }; b) >/dev/null 2>&1 & echo started").await;
        assert_eq!((code, out.trim()), (0, "started"));
        tokio::time::sleep(Duration::from_secs(3)).await;
        // pids.peak where the kernel has it (6.x), else the count now, mid-bomb.
        let file = if cg.join("pids.peak").exists() {
            "pids.peak"
        } else {
            "pids.current"
        };
        let peak: u64 = read(&x, &r, &cg, file).trim().parse().unwrap();
        assert!(peak <= u64::from(PIDS), "{file} {peak}");
        assert!(
            event(&read(&x, &r, &cg, "pids.events"), "max ") > 0,
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
        // #141 diagnostics, print-only: the container's memory and pids figures at the moment
        // the no-memory-entry assertion is checked (figures only: public CI output).
        eprintln!("{}", figures(&x, &r, &cg));
        assert!(
            limits(&x, "memory").is_empty(),
            "{:?}; memory.events now: {}",
            x.events.list(),
            std::fs::read_to_string(cg.join("memory.events"))
                .map_or_else(|e| format!("unreadable: {e}"), |t| t.replace('\n', " "))
        );
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
        let r = launch_small(&x, "oom", MEMORY_MIB).await;
        let cg = cgroup(&x, &r).await;
        assert_eq!(
            read(&x, &r, &cg, "memory.max").trim(),
            (64u64 << 20).to_string()
        );
        // `--memory-swap` equals `--memory`: no swap, so the bomb cannot push the host to swap.
        assert_eq!(read(&x, &r, &cg, "memory.swap.max").trim(), "0");
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
        let r = launch_small(&x, "tmpfs", MEMORY_MIB).await;
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
