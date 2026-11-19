//! The built-in tools against a real workspace container (Task 11): the RT-AG-02 clauses with the
//! real shell (#66), the shell's kills (#62) and exec gate (#24, RT-AG-09), file tools in the
//! workspace's own view of `rw` and `staged` mounts (architect ruling Q29), and RT-AG-05's
//! read-only bind. The fixture is `common::container`; these tests never skip.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use sally_core::manifest::ValidatedManifest;
use sallyd::approvals::queue::{Client, Decision};
use sallyd::sandbox::DiskFloor;
use sallyd::tools::exec::PodmanExec;
use sallyd::tools::ops::Ops;
use sallyd::tools::shell::{Runner, Status};
use serde_json::{Value, json};

mod common;
use common::container::*;
use common::tools::{seen, session};
use common::*;

const ME: Client = Client { uid: 1000, pid: 7 };

const TOOLS: &str = "tools:\n  builtin: [fs_list, fs_read, fs_write, fs_delete, shell]\n";

fn manifest(x: &Lx, mounts_yaml: &str, shell: &str) -> ValidatedManifest {
    x.f.load(&format!("{mounts_yaml}{TOOLS}  shell: {shell}\n"))
}

/// The `sleep` processes in the container, by their arguments (the entry's own is excluded).
fn sleeps(container: &str, args: &str) -> usize {
    let (_, out) = exec_in(container, &["ps", "-o", "args"]);
    out.lines()
        .filter(|l| l.trim() == format!("sleep {args}"))
        .count()
}

async fn until(what: &str, limit: Duration, mut f: impl FnMut() -> bool) {
    let end = Instant::now() + limit;
    while Instant::now() < end {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for {what}");
}

/// RT-AG-02 with the real shell (#66): a timed-out or denied `touch` leaves the file absent; an
/// approved one creates it and runs once; an identical call asks again.
#[test]
fn rt_ag_02_the_real_shell_runs_an_approved_command_once_and_nothing_else() {
    rt().block_on(async {
        let x = Lx::new();
        let host = x.f.root.join("home/code/myproject");
        std::fs::create_dir_all(&host).unwrap();
        let v = manifest(
            &x,
            &mounts(&[mount("~/code/myproject", "/workspace/p", "rw")]),
            "approve",
        );
        let r = x.launch(&v, "ag02").await.unwrap();
        let s = Arc::new(session(&x, &v, &r, Duration::from_secs(2)));
        let touch = json!({"cmd": ["touch", "/workspace/p/x"]});
        let runs = || x.events.list().iter().filter(|e| *e == "tool.run").count();
        // (a) nobody answers: denied on timeout, the file absent.
        let out = s.call("shell", touch.clone()).await;
        assert_eq!(out.text, "denied: timeout");
        // (b) denied.
        let s2 = Arc::clone(&s);
        let t = touch.clone();
        let h = tokio::spawn(async move { s2.call("shell", t).await });
        let p = s.shown(2).await;
        s.desk
            .decide(&p.id, Decision::Deny, ME, seen(&p))
            .await
            .unwrap();
        assert_eq!(h.await.unwrap().text, "denied: denied");
        assert!(!host.join("x").exists(), "ran without approval");
        assert_eq!(runs(), 0);
        // (c) approved: runs once, the bytes approved.
        let s2 = Arc::clone(&s);
        let t = touch.clone();
        let h = tokio::spawn(async move { s2.call("shell", t).await });
        let p = s.shown(3).await;
        s.desk
            .decide(&p.id, Decision::Approve, ME, seen(&p))
            .await
            .unwrap();
        let out = h.await.unwrap();
        assert!(!out.is_error, "{}", out.text);
        assert!(host.join("x").exists());
        assert_eq!(runs(), 1);
        let run = x.events.args("tool.run").unwrap();
        assert_eq!(run["action_sha256"], p.digest.as_str());
        assert_eq!(run["approval"], p.id.as_str());
        // A replayed decision is refused; an identical call asks again under a new id.
        assert!(
            s.desk
                .decide(&p.id, Decision::Approve, ME, seen(&p))
                .await
                .is_err()
        );
        let s2 = Arc::clone(&s);
        let h = tokio::spawn(async move { s2.call("shell", touch).await });
        let p2 = s.shown(4).await;
        assert_ne!(p2.id, p.id);
        s.desk
            .decide(&p2.id, Decision::Deny, ME, seen(&p2))
            .await
            .unwrap();
        assert_eq!(h.await.unwrap().text, "denied: denied");
        assert_eq!(runs(), 1);
        x.stop(r).await;
    });
}

/// #62, ruling Q32: the time limit kills the command and everything it started; killing only
/// the `podman exec` client would leave them running (probed).
#[test]
fn a_command_past_its_time_limit_is_killed_with_what_it_started() {
    rt().block_on(async {
        let x = Lx::new();
        let v = manifest(&x, "", "allow");
        let r = x.launch(&v, "limit").await.unwrap();
        let run =
            PodmanExec::new(x.podman.clone(), &r, Ops::new()).time_limit(Duration::from_secs(2));
        let argv: Vec<String> = ["sh", "-c", "sleep 300 & exec sleep 301"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        let started = Instant::now();
        let out = run.run(&argv, "/").await;
        assert_eq!(out.status, Status::Killed("timeout"));
        assert!(started.elapsed() < Duration::from_secs(30));
        until("the call's processes gone", Duration::from_secs(10), || {
            sleeps(r.container(), "300") + sleeps(r.container(), "301") == 0
        })
        .await;
        assert!(exists(r.container()), "the session itself is not killed");
        x.stop(r).await;
    });
}

/// One reply per call: what a finished command left running in its session is killed.
#[test]
fn what_a_finished_command_left_running_is_killed() {
    rt().block_on(async {
        let x = Lx::new();
        let v = manifest(&x, "", "allow");
        let r = x.launch(&v, "leftover").await.unwrap();
        let run = PodmanExec::new(x.podman.clone(), &r, Ops::new());
        let argv: Vec<String> = ["sh", "-c", "sleep 302 & echo hi"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        let out = run.run(&argv, "/").await;
        assert_eq!(out.status, Status::Exited(0));
        assert_eq!(out.stdout.kept, b"hi\n");
        until("the leftover gone", Duration::from_secs(10), || {
            sleeps(r.container(), "302") == 0
        })
        .await;
        // Exit codes and stderr are the command's.
        let argv: Vec<String> = ["sh", "-c", "echo err >&2; exit 3"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        let out = run.run(&argv, "/tmp").await;
        assert_eq!(out.status, Status::Exited(3));
        assert_eq!(out.stderr.kept, b"err\n");
        let out = run.run(&["pwd".to_owned()], "/tmp").await;
        assert_eq!(out.stdout.kept, b"/tmp\n");
        let out = run.run(&["/nonexistent".to_owned()], "/").await;
        assert_eq!(out.status, Status::Exited(127));
        x.stop(r).await;
    });
}

/// #66: the approved argv is the command, never podman options. Words that look like `podman
/// exec` flags reach the container as the program name and fail there.
#[test]
fn an_argv_that_looks_like_podman_flags_is_the_command() {
    rt().block_on(async {
        let x = Lx::new();
        let v = manifest(&x, "", "allow");
        let r = x.launch(&v, "flags").await.unwrap();
        let run = PodmanExec::new(x.podman.clone(), &r, Ops::new());
        for argv in [
            &["--privileged", "id"][..],
            &["--user=0", "id"],
            &["-e", "X=1", "env"],
            &["--env=X=1", "env"],
        ] {
            let argv: Vec<String> = argv.iter().map(|s| (*s).to_owned()).collect();
            let out = run.run(&argv, "/").await;
            assert_eq!(out.status, Status::Exited(127), "{argv:?}");
            assert!(out.stdout.kept.is_empty(), "{argv:?}");
        }
        // The command sees the fixed environment, not one the argv names.
        let out = run.run(&["env".to_owned()], "/").await;
        let env = String::from_utf8_lossy(&out.stdout.kept).into_owned();
        assert!(!env.lines().any(|l| l.starts_with("X=")), "{env}");
        x.stop(r).await;
    });
}

/// #62: a call dropped at teardown kills the command it started.
#[test]
fn a_dropped_call_kills_its_command() {
    rt().block_on(async {
        let x = Lx::new();
        let v = manifest(&x, "", "allow");
        let r = x.launch(&v, "drop").await.unwrap();
        let run = PodmanExec::new(x.podman.clone(), &r, Ops::new());
        let h = tokio::spawn(async move { run.run(&["sleep".into(), "303".into()], "/").await });
        // Started and found: the runner gives the exec gate back once it holds the pidfd.
        let gate = r.exec_gate();
        until(
            "the command started and found",
            Duration::from_secs(20),
            || sleeps(r.container(), "303") == 1 && gate.try_lock().is_ok(),
        )
        .await;
        h.abort();
        let _ = h.await;
        until("the command gone", Duration::from_secs(10), || {
            sleeps(r.container(), "303") == 0
        })
        .await;
        x.stop(r).await;
    });
}

/// #24: the exec gate is held only while the command starts. While the gate is held (as the
/// watchdog holds it on a frozen container) nothing starts; once started, the gate is free.
#[test]
fn the_exec_gate_is_held_only_while_a_command_starts() {
    rt().block_on(async {
        let x = Lx::new();
        let v = manifest(&x, "", "allow");
        let r = x.launch(&v, "gate").await.unwrap();
        let gate = r.exec_gate();
        let held = Arc::clone(&gate).lock_owned().await;
        let run = PodmanExec::new(x.podman.clone(), &r, Ops::new());
        let h = tokio::spawn(async move { run.run(&["sleep".into(), "304".into()], "/").await });
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(
            sleeps(r.container(), "304"),
            0,
            "started while the gate was held"
        );
        drop(held);
        until("the command started", Duration::from_secs(20), || {
            sleeps(r.container(), "304") == 1
        })
        .await;
        // The command runs for minutes: the gate comes back long before it ends.
        until(
            "the gate free while it runs",
            Duration::from_secs(20),
            || gate.try_lock().is_ok(),
        )
        .await;
        assert_eq!(sleeps(r.container(), "304"), 1, "the command still runs");
        assert!(!h.is_finished());
        h.abort();
        let _ = h.await;
        until("the command gone", Duration::from_secs(10), || {
            sleeps(r.container(), "304") == 0
        })
        .await;
        x.stop(r).await;
    });
}

/// RT-AG-09 (#24): writing past `stage_size` inside one long gated exec gets the session killed
/// while the command still runs.
#[test]
fn rt_ag_09_stage_size_is_enforced_during_one_long_exec() {
    let _serial = io_lock(true);
    rt().block_on(async {
        let x = Lx::with_floor(DiskFloor::default());
        std::fs::create_dir_all(x.f.root.join("home/code/other")).unwrap();
        let v = x.f.load(&format!(
            "{}runtime:\n  stage_size: 64MiB\n{TOOLS}  shell: allow\n",
            mounts(&[mount("~/code/other", "/workspace/o", "staged")])
        ));
        let r = x.launch(&v, "longexec").await.unwrap();
        let run = PodmanExec::new(x.podman.clone(), &r, Ops::new());
        let script = "dd if=/dev/zero of=/workspace/o/f bs=1M count=96 2>/dev/null; sleep 120";
        let argv: Vec<String> = ["sh", "-c", script]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        let started = Instant::now();
        let out = tokio::time::timeout(Duration::from_secs(90), run.run(&argv, "/")).await;
        let out = out.expect("the command outlived the session");
        assert!(
            started.elapsed() < Duration::from_secs(90),
            "killed only after the command ended: {out:?}"
        );
        until("the session gone", Duration::from_secs(20), || {
            !exists(r.container())
        })
        .await;
        let a = x.events.args("session.resource_limit").expect("audited");
        assert_eq!(a["resource"], "stage_size", "{a}");
        x.stop(r).await;
    });
}

/// The size of each large lower file in the copy-up clause: well above its `stage_size`.
const LOWER: u64 = 1 << 30;
/// The most this process may write while the broker writes one byte to a lower file of [`LOWER`]
/// bytes: an eighth of it.
const COPY_BOUND: u64 = LOWER / 8;
const MIB_BYTES: usize = 1 << 20;

/// One MiB of the lower files' repeating pattern.
fn pattern() -> Vec<u8> {
    (0..MIB_BYTES).map(|i| (i % 251) as u8).collect()
}

/// A lower file of [`LOWER`] bytes of data (not a hole, which a copy-up would skip).
fn lower_file(path: &std::path::Path) {
    use std::io::Write as _;
    let block = pattern();
    let mut f = std::fs::File::create(path).unwrap();
    for _ in 0..LOWER / MIB_BYTES as u64 {
        f.write_all(&block).unwrap();
    }
}

/// Whether the file at `path` is still exactly [`lower_file`]'s content.
fn lower_intact(path: &std::path::Path) -> bool {
    use std::io::Read as _;
    let (block, mut buf) = (pattern(), vec![0_u8; MIB_BYTES]);
    let mut f = std::fs::File::open(path).unwrap();
    let blocks = LOWER / MIB_BYTES as u64;
    (0..blocks).all(|_| f.read_exact(&mut buf).is_ok() && buf == block)
        && f.read(&mut buf).unwrap() == 0
}

/// This process's written-bytes counter (`write_bytes` in `/proc/self/io`): what it caused to be
/// written to storage, counted when page-cache pages are dirtied, over all its threads and the
/// children it reaped. Without task I/O accounting there is no counter and this panics, so the
/// control fails rather than skips.
fn written() -> u64 {
    let io = std::fs::read_to_string("/proc/self/io").expect("task I/O accounting");
    io.lines()
        .find_map(|l| l.strip_prefix("write_bytes:"))
        .expect("a write_bytes line")
        .trim()
        .parse()
        .expect("a byte count")
}

/// Runs `work`; returns its output and what this process wrote meanwhile ([`written`]).
async fn written_by<T>(work: impl std::future::Future<Output = T>) -> (T, u64) {
    let before = written();
    let out = work.await;
    (out, written().saturating_sub(before))
}

/// RT-AG-09: the broker's write to an existing file in a `staged` mount copies nothing up. One
/// `fs_write` of one byte to a lower file far above `stage_size` makes this process write at
/// most [`COPY_BOUND`]: the reopen truncates, so overlayfs copies the file up empty. The tool runs
/// in this process (the blocking pool), so a copy-up's writes count here; the counter is
/// cumulative, not sampled, so nothing can slip between two readings. Control (analogue), first,
/// through the same probe and mount: the unfixed sequence (a write open without `O_TRUNC`, then
/// `ftruncate(0)`, holding the exec gate as the tool does) on a sibling lower file of the same
/// size writes at least half the file. The counter covers every thread and every reaped child.
/// It is near quiet here, not silent: no command runs in the container, the I/O lock keeps
/// other fixtures out, and under nextest each test has its own process; but a stage walk woken
/// by the control's copy can pause and walk the container during the write, and its podman
/// children count when reaped (as can another test in the same process under `cargo test`).
/// Each is a few hundred KiB against a 128 MiB bound, and extra writes can only fail the test.
/// Known limit: where the state directory is on tmpfs or a reflink filesystem (btrfs, XFS with
/// reflink) a copy-up writes no counted pages, and the control fails there.
#[test]
fn rt_ag_09_a_write_to_a_large_lower_file_copies_nothing_up() {
    let _serial = io_lock(true);
    rt().block_on(async {
        let x = Lx::with_floor(DiskFloor::default());
        let st = x.f.root.join("home/code/other");
        std::fs::create_dir_all(&st).unwrap();
        lower_file(&st.join("big"));
        lower_file(&st.join("sibling"));
        let v = x.f.load(&format!(
            "{}runtime:\n  stage_size: 64MiB\n{TOOLS}  shell: deny\n",
            mounts(&[mount("~/code/other", "/workspace/o", "staged")])
        ));
        let r = x.launch(&v, "copyup").await.unwrap();
        let s = session(&x, &v, &r, Duration::from_secs(30));
        let in_view = format!("/proc/{}/root/workspace/o/sibling", r.init_pid());
        let gate = r.exec_gate();
        let held = gate.lock().await;
        let ((), control) = written_by(async move {
            tokio::task::spawn_blocking(move || {
                let f = std::fs::OpenOptions::new()
                    .write(true)
                    .open(&in_view)
                    .unwrap();
                f.set_len(0).unwrap();
            })
            .await
            .unwrap();
        })
        .await;
        drop(held);
        assert!(
            control >= LOWER / 2,
            "control: the probe sees a copy-up ({control} bytes written; a state directory on \
             tmpfs or a reflink filesystem copies up without counted writes)"
        );
        let (out, wrote) = written_by(s.call(
            "fs_write",
            json!({"path": "/workspace/o/big", "content_b64": "eA=="}),
        ))
        .await;
        assert!(!out.is_error, "{}", out.text);
        eprintln!("bytes written: {control} (control), {wrote} (the write)");
        assert!(wrote <= COPY_BOUND, "the write copied {wrote} bytes up");
        let (_, seen) = exec_in(r.container(), &["cat", "/workspace/o/big"]);
        assert_eq!(seen, "x");
        assert!(lower_intact(&st.join("big")), "the host's lower file");
        assert!(lower_intact(&st.join("sibling")));
        assert!(exists(r.container()));
        x.stop(r).await;
    });
}

/// Ruling Q29: a staged write lands in the session's upper directory, the host folder is
/// byte-identical, and the change is listed; an `rw` write lands in the host folder through the
/// workspace's view. After the session, nothing resolves (the init is gone).
#[test]
fn file_tools_write_where_the_workspace_writes() {
    rt().block_on(async {
        let x = Lx::new();
        let st = x.f.root.join("home/code/other");
        let rw = x.f.root.join("home/code/myproject");
        std::fs::create_dir_all(&st).unwrap();
        std::fs::create_dir_all(&rw).unwrap();
        std::fs::write(st.join("keep.txt"), b"host\n").unwrap();
        let before = tree_state(&st);
        let v = manifest(
            &x,
            &mounts(&[
                mount("~/code/other", "/workspace/o", "staged"),
                mount("~/code/myproject", "/workspace/p", "rw"),
            ]),
            "deny",
        );
        let r = x.launch(&v, "files").await.unwrap();
        let s = session(&x, &v, &r, Duration::from_secs(30));
        for (path, b64) in [
            ("/workspace/o/keep.txt", "c2FuZGJveAo="),
            ("/workspace/o/new.txt", "eAo="),
        ] {
            let out = s
                .call("fs_write", json!({"path": path, "content_b64": b64}))
                .await;
            assert!(!out.is_error, "{path}: {}", out.text);
        }
        assert_eq!(tree_state(&st), before, "the host folder of a staged mount");
        let (_, seen) = exec_in(
            r.container(),
            &["cat", "/workspace/o/keep.txt", "/workspace/o/new.txt"],
        );
        assert_eq!(seen, "sandbox\nx\n");
        let out = s
            .call("fs_read", json!({"path": "/workspace/o/keep.txt"}))
            .await;
        assert_eq!(
            serde_json::from_str::<Value>(&out.text).unwrap()["content"],
            "sandbox\n"
        );
        let out = s
            .call("fs_delete", json!({"path": "/workspace/o/keep.txt"}))
            .await;
        assert!(!out.is_error, "{}", out.text);
        assert_eq!(tree_state(&st), before);
        let changes: Vec<String> = common::changes(&x.paths("files"))
            .unwrap()
            .into_iter()
            .map(|c| format!("{} {:?}", c.path.display(), c.kind))
            .collect();
        assert_eq!(changes, ["keep.txt Deleted", "new.txt Written"]);
        assert_eq!(x.events.args("tool.run").unwrap()["mode"], "staged");
        // rw: the host folder, through the workspace's view.
        let out = s
            .call(
                "fs_write",
                json!({"path": "/workspace/p/a.txt", "content_b64": "aGkK"}),
            )
            .await;
        assert!(!out.is_error, "{}", out.text);
        assert_eq!(std::fs::read(rw.join("a.txt")).unwrap(), b"hi\n");
        // The ro bind of a brokered mount is the sandbox's own wall (RT-AG-05); covered below.
        x.stop(r).await;
        let out = s
            .call(
                "fs_write",
                json!({"path": "/workspace/p/b.txt", "content_b64": "aGkK"}),
            )
            .await;
        assert_eq!(out.text, "denied: container-gone");
        assert!(!rw.join("b.txt").exists());
    });
}

/// RT-AG-05, the sandbox's half: in a brokered mount the sandbox's own write fails (read-only);
/// only the broker's approved `fs_write` reaches the folder.
#[test]
fn rt_ag_05_the_sandbox_cannot_write_a_brokered_mount_itself() {
    rt().block_on(async {
        let x = Lx::new();
        let notes = x.f.root.join("home/code/notes");
        std::fs::create_dir_all(&notes).unwrap();
        let v = manifest(
            &x,
            &mounts(&[mount("~/code/notes", "/workspace/notes", "brokered")]),
            "deny",
        );
        let r = x.launch(&v, "ag05").await.unwrap();
        let (code, out) = exec(&r, "echo x > /workspace/notes/c").await;
        assert_ne!(code, 0);
        assert!(out.contains("Read-only file system"), "{out}");
        assert!(!notes.join("c").exists());
        let s = Arc::new(session(&x, &v, &r, Duration::from_secs(30)));
        let s2 = Arc::clone(&s);
        let h = tokio::spawn(async move {
            s2.call(
                "fs_write",
                json!({"path": "/workspace/notes/c", "content_b64": "eAo="}),
            )
            .await
        });
        let p = s.shown(1).await;
        assert!(!notes.join("c").exists(), "written before approval");
        s.desk
            .decide(&p.id, Decision::Approve, ME, seen(&p))
            .await
            .unwrap();
        assert!(!h.await.unwrap().is_error);
        assert_eq!(std::fs::read(notes.join("c")).unwrap(), b"x\n");
        let (_, seen) = exec_in(r.container(), &["cat", "/workspace/notes/c"]);
        assert_eq!(seen, "x\n");
        x.stop(r).await;
    });
}
