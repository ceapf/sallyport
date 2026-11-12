//! RT-AG-09, the free-space floor and `runtime.stage_size` with real containers (#14,
//! maintainer design after the 6c-1 reviews).
//!
//! The floor is a launcher setting (`DiskFloor`), the same one `sallyd`'s configuration sets, so
//! these tests run on whatever filesystem holds the target directory. They place the floor a few
//! hundred MiB below its current free space, so a full-speed writer crosses it quickly. There is
//! no test-only path in the launcher. The fixture is `common::container`; these tests never skip.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::{Duration, Instant};

use sallyd::sandbox::{DiskFloor, LaunchError, Running};

mod common;
use common::container::*;
use common::*;

const MIB: u64 = 1 << 20;

/// These tests write hundreds of MiB at full speed against a floor relative to the free space
/// they saw. They hold the I/O lock exclusively: two at once would eat each other's margin, and
/// their disk saturation must not stall other tests' containers.
fn serial() -> std::fs::File {
    io_lock(true)
}

/// The floor writer tests: the disk-free lock first (a mutation run in either lane frees and
/// takes gigabytes and so moves their margin; architect ruling D1), then [`serial`].
fn floor_serial() -> (std::fs::File, std::fs::File) {
    let disk = disk_free_lock();
    (disk, serial())
}

/// Bytes available to unprivileged users on the filesystem of the test fixtures.
fn free_now() -> u64 {
    let s = rustix::fs::statvfs(env!("CARGO_TARGET_TMPDIR")).unwrap();
    s.f_bavail * s.f_frsize
}

/// A launcher whose floor sits `margin` bytes below the current free space. Fails (never skips)
/// unless 8 GiB more than the margin is free, so a broken watchdog cannot fill a nearly full disk
/// (re-review L6).
fn floor_below_free(margin: u64) -> Lx {
    let free = free_now();
    assert!(
        free >= margin + 8192 * MIB,
        "the floor tests need {} MiB free, have {} MiB",
        (margin + 8192 * MIB) / MIB,
        free / MIB
    );
    Lx::with_floor(DiskFloor {
        min_bytes: free - margin,
        percent: 0,
    })
}

/// Removes a host file the test made, even when the test fails.
struct RemoveFile(std::path::PathBuf);

impl Drop for RemoveFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

async fn gone_within(container: &str, limit: Duration) -> bool {
    let until = Instant::now() + limit;
    while Instant::now() < until {
        if !exists(container) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    false
}

/// `sh -c <script>` in the container, on the blocking pool: the watchdog runs on this test's
/// runtime and must keep running while the exec blocks.
async fn sh(container: &str, script: String) -> (i32, String) {
    let c = container.to_owned();
    tokio::task::spawn_blocking(move || exec_in(&c, &["sh", "-c", &script]))
        .await
        .unwrap()
}

/// Writes zeros at full speed until the session is killed (the exec then returns). Capped at
/// twice the room above the floor, so a broken watchdog fails the test instead of filling the
/// disk.
async fn write_until_killed(r: &Running, path: &str, room: u64) {
    let count = 2 * room / MIB;
    let script = format!("dd if=/dev/zero of={path} bs=1M count={count} 2>/dev/null; sleep 30");
    let _ = sh(r.container(), script).await;
}

/// The floor kills an `rw` writer: mounts that had no limit at all before.
#[test]
fn rt_ag_09_a_full_speed_writer_in_an_rw_mount_is_stopped_by_the_floor() {
    let _serial = floor_serial();
    rt().block_on(async {
        let x = floor_below_free(512 * MIB);
        let v =
            x.f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", "rw")]));
        let r = x.launch(&v, "rw-fill").await.unwrap();
        write_until_killed(&r, "/workspace/p/fill", 512 * MIB).await;
        assert!(gone_within(r.container(), Duration::from_secs(20)).await);
        let a = x.events.args("session.resource_limit").expect("audited");
        assert_eq!(a["reason"], "disk_floor", "{a}");
        assert_eq!(a["filesystem"], "filesystem.mounts[0]", "{a}");
        assert!(
            a["free"].as_u64().unwrap() < a["floor"].as_u64().unwrap(),
            "{a}"
        );
        x.stop(r).await;
    });
}

/// The floor kills a staged writer before its `stage_size` is reached: the host filled most of
/// the margin after the launch (the floor reads the filesystem's own accounting).
#[test]
fn rt_ag_09_a_full_speed_writer_in_a_staged_mount_is_stopped_by_the_floor() {
    let _serial = floor_serial();
    rt().block_on(async {
        let x = floor_below_free(2048 * MIB);
        let v = x.f.load(&format!(
            "{}runtime:\n  stage_size: 1GiB\n",
            mounts(&[mount("~/code/other", "/workspace/o", "staged")])
        ));
        let r = x.launch(&v, "staged-fill").await.unwrap();
        let _hog_guard = RemoveFile(x.f.root.join("hog"));
        let hog = std::fs::File::create(x.f.root.join("hog")).unwrap();
        rustix::fs::fallocate(&hog, rustix::fs::FallocateFlags::empty(), 0, 1536 * MIB).unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(
            exists(r.container()),
            "the host's own write is not the session's"
        );
        write_until_killed(&r, "/workspace/o/fill", 512 * MIB).await;
        assert!(gone_within(r.container(), Duration::from_secs(20)).await);
        let a = x.events.args("session.resource_limit").expect("audited");
        assert_eq!(a["reason"], "disk_floor", "{a}");
        assert_eq!(a["filesystem"], "state", "{a}");
        x.stop(r).await;
    });
}

/// A launch is refused when the floor plus `stage_size` is not free. `stage_size` is the
/// maximum, so no other process's freed space can admit this launch (architect ruling D1: with
/// 1 GiB, 512 MiB freed elsewhere between the floor's reading and the launch admitted it, as a
/// mutation run in the other lane deleting its tree copy did).
#[test]
fn a_launch_without_room_for_stage_size_above_the_floor_is_refused() {
    let _serial = serial();
    rt().block_on(async {
        let x = floor_below_free(512 * MIB);
        let v = x.f.load(&format!(
            "{}runtime:\n  stage_size: 1TiB\n",
            mounts(&[mount("~/code/other", "/workspace/o", "staged")])
        ));
        let e = x.launch(&v, "no-room").await.unwrap_err();
        assert!(matches!(e, LaunchError::DiskSpace(_)), "{e}");
        assert_eq!(x.events.list(), ["sandbox.refuse"]);
        assert_eq!(
            x.events.args("sandbox.refuse").unwrap()["reason"],
            "disk-floor"
        );
    });
}

/// The re-review's HIGH: renaming files in a loop, within a directory and across directories,
/// does not hide data from `stage_size`. The walk runs on the frozen container.
#[test]
fn rt_ag_09_rename_churn_does_not_evade_stage_size() {
    let _serial = serial();
    rt().block_on(async {
        let x = Lx::with_floor(DiskFloor::default());
        let v = x.f.load(&format!(
            "{}runtime:\n  stage_size: 64MiB\n",
            mounts(&[mount("~/code/other", "/workspace/o", "staged")])
        ));
        let r = x.launch(&v, "churn").await.unwrap();
        // The renamer starts first, so every file is moving (within d1, and between d1 and
        // d2) for the whole time the data grows past the limit. The writer opens all four
        // files before the renamer starts and writes through those fds: `dd of=<name>` would
        // re-create a name the renamer had just moved away, and the renamer's next `mv` would
        // then replace that new file, so as little as 24 of the 96 MiB was kept (6c-2: a run
        // ended at 48 MiB, under the limit, and was rightly not killed).
        let script = "cd /workspace/o; mkdir -p d1 d2; \
             exec 3>>d1/f1 4>>d1/f2 5>>d1/f3 6>>d1/f4; \
             (while :; do for i in 1 2 3 4; do mv d1/f$i d1/g$i; mv d1/g$i d2/f$i; \
             mv d2/f$i d1/f$i; done; done) & \
             for fd in 3 4 5 6; do dd if=/dev/zero bs=1M count=24 2>/dev/null >&$fd; done; \
             sleep 30";
        let (_, out) = sh(r.container(), script.to_owned()).await;
        let du = sh(r.container(), "du -sk /workspace/o".to_owned()).await;
        assert!(
            gone_within(r.container(), Duration::from_secs(20)).await,
            "not killed: exec {out:?}, du {du:?}, events {:?}, args {:?}",
            x.events.list(),
            x.events.args("session.resource_limit")
        );
        let a = x.events.args("session.resource_limit").expect("audited");
        assert_eq!(a["resource"], "stage_size", "{a}");
        assert!(
            a["reason"] == "stage_size" || a["reason"] == "unmeasurable",
            "{a}"
        );
        x.stop(r).await;
    });
}

/// One session busy with walks of a large tree does not delay another session's floor check:
/// the floor task never waits for the walk permit, the exec gate or a walk. Here the writer's
/// own growth keeps waking the other session's stage task, whose walks run alongside.
#[test]
fn rt_ag_09_a_busy_walk_does_not_delay_another_sessions_floor() {
    let _serial = floor_serial();
    rt().block_on(async {
        let x = floor_below_free(768 * MIB);
        let tree = x.f.load(&format!(
            "{}runtime:\n  stage_size: 32MiB\n",
            mounts(&[mount("~/code/other", "/workspace/o", "staged")])
        ));
        let busy = x.launch(&tree, "busy").await.unwrap();
        let script = "cd /workspace/o; for d in $(seq 1 100); do mkdir t$d; \
             (cd t$d; seq 1 2000 | xargs touch); done";
        let (code, out) = sh(busy.container(), script.to_owned()).await;
        assert_eq!(code, 0, "{out}");
        let rw =
            x.f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", "rw")]));
        let writer = x.launch(&rw, "writer").await.unwrap();
        let started = Instant::now();
        write_until_killed(&writer, "/workspace/p/fill", 768 * MIB).await;
        assert!(gone_within(writer.container(), Duration::from_secs(20)).await);
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "the floor reacted within its poll"
        );
        let a = x.events.args("session.resource_limit").expect("audited");
        assert_eq!(a["reason"], "disk_floor", "{a}");
        x.stop(writer).await;
        x.stop(busy).await;
    });
}
