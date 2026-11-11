//! RT-SEC-14: no broker file descriptor reaches Podman or a container. The broker holds its
//! long-lived descriptors (the audit log and its lock, the secrets store), launches through the
//! normal path (which holds its own while it runs podman), and then:
//! - on the Podman side, conmon (which outlives `podman start`) and a process Podman runs
//!   through the launcher's own hermetic command (`podman unshare`) hold no descriptor that
//!   refers to a broker object. Podman's own descriptors are expected: conmon's pipes and
//!   `userdata` files, and the pipe `podman unshare` passes its child as fd 3 (also from a plain
//!   shell);
//! - in the container, the entry process holds only fds 0, 1 and 2, and PID 1 (the init,
//!   catatonit) adds only its own signalfd.
//!
//! The broker objects are not a hand-written list: the launcher runs podman through a wrapper
//! that, during the launch, records every descriptor the broker process holds at the moment it
//! runs podman (`/proc/<parent>/fd`), so a descriptor nobody thought of is still compared. Only
//! what the test harness held before the broker started, and `/dev/null` (a shared device every
//! process opens), are left out.
//!
//! Identity is `st_dev:st_ino`; anonymous-inode descriptors (eventfd, epoll, signalfd) share one
//! inode and are not compared. A planted inheritable descriptor (a `dup` without `O_CLOEXEC`)
//! shows that both Podman-side observation points see a leak when there is one. The control is
//! `sally_core::fd`, which opens every `rustix` descriptor with `O_CLOEXEC` (`std` does the same
//! for its own). The container never sees the planted descriptor: the OCI runtime closes
//! descriptors above 2, a second layer.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use rustix::fs::{Mode, OFlags};
use sally_core::audit::{Actor, AuditWriter, NewEntry, SystemClock};
use sally_core::manifest::AuditLevel;
use sallyd::sandbox::Running;

mod common;
use common::container::*;
use common::*;

type Id = (u64, u64);

fn id_of(p: &Path) -> Option<Id> {
    std::fs::metadata(p).ok().map(|m| (m.dev(), m.ino()))
}

/// One open descriptor: its number, its link target and the identity it refers to (`None` for
/// an anonymous inode, which every eventfd, epoll and signalfd shares).
#[derive(Debug, Clone)]
struct Fd {
    fd: String,
    target: String,
    id: Option<Id>,
}

/// The descriptors of host process `pid` (`self` for this one).
fn host_fds(pid: &str) -> Vec<Fd> {
    std::fs::read_dir(format!("/proc/{pid}/fd"))
        .unwrap()
        .flatten()
        .filter_map(|e| {
            let p = e.path();
            let target = std::fs::read_link(&p).ok()?.display().to_string();
            let id = id_of(&p).filter(|_| !target.starts_with("anon_inode:"));
            Some(Fd {
                fd: e.file_name().to_string_lossy().into_owned(),
                target,
                id,
            })
        })
        .collect()
}

/// `pid fd dev:ino target` for each descriptor of each process in `$PIDS`, as seen from
/// wherever the script runs.
const LIST_FDS: &str = r#"for p in $PIDS; do for f in /proc/$p/fd/*; do t=$(readlink "$f") && i=$(stat -L -c %d:%i "$f" 2>/dev/null || echo -) && echo "$p ${f##*/} $i $t"; done; done"#;

/// `(pid, Fd)` from [`LIST_FDS`] output; other lines are ignored.
fn parse_fds(out: &str) -> Vec<(String, Fd)> {
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    out.lines()
        .filter_map(|l| {
            let mut w = l.splitn(4, ' ');
            let (p, fd, i, target) = (w.next()?, w.next()?, w.next()?, w.next()?);
            if !digits(p) || !digits(fd) {
                return None;
            }
            let id = i
                .split_once(':')
                .and_then(|(d, n)| Some((d.parse().ok()?, n.parse().ok()?)))
                .filter(|_| !target.starts_with("anon_inode:"));
            let (fd, target) = (fd.to_owned(), target.to_owned());
            Some((p.to_owned(), Fd { fd, target, id }))
        })
        .collect()
}

/// The descriptors in `fds` that refer to a broker object.
fn broker_refs<'a>(fds: impl IntoIterator<Item = &'a Fd>, broker: &BTreeSet<Id>) -> Vec<Fd> {
    fds.into_iter()
        .filter(|f| f.id.is_some_and(|i| broker.contains(&i)))
        .cloned()
        .collect()
}

/// A podman wrapper that, while recording is on, appends the descriptors of its parent (the
/// broker, at the moment it runs podman) to a file, then runs the real podman. The listing
/// runs in a subshell, so podman's environment is unchanged.
struct Recorder {
    dir: PathBuf,
}

impl Recorder {
    fn new() -> Self {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("rt-sec-14-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        Self { dir }
    }

    fn wrap(&self, real: &Path) -> PathBuf {
        let (dir, real) = (self.dir.display(), real.display());
        let script = format!(
            "#!/bin/sh\nif [ -e '{dir}/on' ]; then\n  (PATH=/usr/bin:/bin; PIDS=$PPID; {LIST_FDS}) >>'{dir}/fds'\nfi\nexec '{real}' \"$@\"\n"
        );
        let bin = self.dir.join("podman");
        executable(&bin, script.as_bytes());
        bin
    }

    fn recording(&self, on: bool) {
        let flag = self.dir.join("on");
        if on {
            std::fs::write(flag, "").unwrap();
        } else {
            std::fs::remove_file(flag).unwrap();
        }
    }

    /// Every descriptor recorded, each checked to be the broker's own.
    fn broker_fds(&self) -> Vec<Fd> {
        let text = std::fs::read_to_string(self.dir.join("fds")).expect("podman ran recorded");
        let me = std::process::id().to_string();
        parse_fds(&text)
            .into_iter()
            .map(|(pid, f)| {
                assert_eq!(pid, me, "the wrapper's parent is not the broker");
                f
            })
            .collect()
    }
}

impl Drop for Recorder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// PID 1 (the init) and its children (the image's entry), from inside the container. A `podman
/// exec` process has no parent in the container's PID namespace, so it is not one of them.
async fn container_fds(r: &Running) -> Vec<(String, Fd)> {
    let pids = r#"PIDS="1 $(cd /proc && for s in [0-9]*/stat; do read -r pid comm st ppid rest 2>/dev/null <"$s" && [ "$ppid" = 1 ] && echo "$pid"; done)""#;
    let (code, out) = exec(r, &format!("{pids}; {LIST_FDS}")).await;
    assert_eq!(code, 0, "{out}");
    parse_fds(&out)
}

/// What a process Podman starts inherits: `podman unshare` through the launcher's hermetic
/// command lists its shell's own descriptors.
async fn podman_child_fds(x: &Lx) -> Vec<Fd> {
    let script = format!("PIDS=$$; {LIST_FDS}");
    let out = x
        .hermetic(&["unshare".into(), "sh".into(), "-c".into(), script])
        .await;
    let fds: Vec<Fd> = parse_fds(&out).into_iter().map(|(_, f)| f).collect();
    assert!(
        fds.iter().any(|f| f.fd == "0"),
        "the podman child listed nothing: {out}"
    );
    fds
}

async fn conmon_pid(x: &Lx, r: &Running) -> String {
    x.hermetic(&[
        "inspect".into(),
        "--format".into(),
        "{{.State.ConmonPid}}".into(),
        r.container().into(),
    ])
    .await
}

struct Held {
    _audit: AuditWriter,
    store: OwnedFd,
    store_id: Id,
    audit_log: Id,
}

/// Opens what the broker holds for its lifetime, through the production code paths.
fn hold(x: &Lx) -> Held {
    let audit_dir = x.f.root.join("audit");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&audit_dir)
        .unwrap();
    let mut audit = AuditWriter::open(&audit_dir, Box::new(SystemClock)).unwrap();
    // The log file is created by the first entry.
    audit
        .append(
            NewEntry::new(Actor::Sallyd, "test.start"),
            AuditLevel::Actions,
        )
        .unwrap();
    let secrets = x.f.root.join("secrets");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&secrets)
        .unwrap();
    let store_path = secrets.join("secrets.toml");
    std::fs::write(&store_path, "").unwrap();
    std::fs::set_permissions(&store_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let store = sally_core::fd::open(
        &store_path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .unwrap();
    let log = std::fs::read_dir(&audit_dir)
        .unwrap()
        .flatten()
        .find(|e| e.file_name().to_string_lossy().ends_with(".jsonl"))
        .expect("the audit writer created its log");
    Held {
        _audit: audit,
        store,
        store_id: id_of(&store_path).unwrap(),
        audit_log: id_of(&log.path()).unwrap(),
    }
}

/// The descriptors of the session's conmon.
async fn conmon_fds(x: &Lx, r: &Running) -> Vec<Fd> {
    let fds = host_fds(&conmon_pid(x, r).await);
    assert!(!fds.is_empty(), "conmon shows no descriptors");
    fds
}

/// The broker objects: what the broker held at each podman run during the launch, and what it
/// holds after it, less what the harness held before (`baseline`) and `/dev/null`.
fn broker_set(rec: &Recorder, baseline: &BTreeSet<Id>) -> BTreeSet<Id> {
    let null = id_of(Path::new("/dev/null"));
    rec.broker_fds()
        .into_iter()
        .chain(host_fds("self"))
        .filter_map(|f| f.id)
        .filter(|i| !baseline.contains(i) && Some(*i) != null)
        .collect()
}

#[test]
fn rt_sec_14_no_broker_descriptor_reaches_podman_or_a_container() {
    rt().block_on(async {
        let baseline: BTreeSet<Id> = host_fds("self").into_iter().filter_map(|f| f.id).collect();
        let rec = Recorder::new();
        let x = Lx::with_podman(|real| rec.wrap(real));
        let staged = x.f.root.join("home/code/staged");
        let ro = x.f.root.join("home/code/ro");
        for d in [&staged, &ro] {
            std::fs::create_dir_all(d).unwrap();
            std::fs::write(d.join("f.txt"), "x\n").unwrap();
        }
        let v = x.f.load(&mounts(&[
            mount("~/code/staged", "/workspace/s", "staged"),
            mount("~/code/ro", "/workspace/r", "ro"),
        ]));
        let held = hold(&x);
        rec.recording(true);
        let r = x.launch(&v, "sec14").await.unwrap();
        rec.recording(false);
        let broker = broker_set(&rec, &baseline);
        // The recording ran while the broker held its long-lived descriptors.
        for (what, id) in [
            ("the audit log", held.audit_log),
            ("the secrets store", held.store_id),
        ] {
            assert!(
                broker.contains(&id),
                "the broker set misses {what}: {:#?}",
                rec.broker_fds()
            );
        }

        let conmon = conmon_fds(&x, &r).await;
        assert_eq!(
            broker_refs(&conmon, &broker).len(),
            0,
            "conmon: {conmon:#?}"
        );
        let child = podman_child_fds(&x).await;
        assert_eq!(
            broker_refs(&child, &broker).len(),
            0,
            "podman child: {child:#?}"
        );

        let inside = container_fds(&r).await;
        assert!(
            inside.iter().any(|(p, _)| p != "1"),
            "no entry process: {inside:#?}"
        );
        for (pid, f) in &inside {
            let own = pid == "1" && f.target == "anon_inode:[signalfd]";
            assert!(
                own || ["0", "1", "2"].contains(&f.fd.as_str()),
                "container pid {pid}: {f:?}"
            );
        }
        x.stop(r).await;

        // Each Podman-side observation point sees a leak when there is one.
        let leak = rustix::io::dup(&held.store).unwrap();
        let planted = |fds: &[Fd]| fds.iter().any(|f| f.id == Some(held.store_id));
        assert!(
            planted(&podman_child_fds(&x).await),
            "podman child misses the plant"
        );
        let r = x.launch(&v, "sec14l").await.unwrap();
        assert!(
            planted(&conmon_fds(&x, &r).await),
            "conmon misses the plant"
        );
        x.stop(r).await;
        drop(leak);
    });
}
