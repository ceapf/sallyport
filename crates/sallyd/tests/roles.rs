//! Task 6c red-team rows that hold in every role, with real containers (rootless Podman):
//! RT-NET-01 (no route out), RT-NET-08 (raw sockets and ICMP), RT-NET-12 (socket families) and
//! RT-FS-17 (no new namespaces).
//!
//! The workspace comes from the launcher; the harness and inference containers from their argv
//! builders, created and started with hermetic podman exactly as the argv says (their launchers
//! arrive in Tasks 12 and M3). The probe is `tests/redteam/probe/probe.c`. Every refusal must be
//! `ENOSYS` (38), the seccomp profiles' default action: the kernel never returns it for `socket`,
//! `unshare`, `clone` or `clone3` itself, so the profile is what refused. That holds for
//! `clone3` only from kernel 5.3 on, where the syscall exists; [`kernel_has_clone3`] checks it.
//! The fixture is `common::container`; these tests never skip.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::fs::PermissionsExt;

use sally_core::manifest::Cpus;
use sallyd::sandbox::{
    InferenceSpec, Running, SessionDirs, SessionId, VerifiedModel, harness_argv, inference_argv,
};

mod common;
use common::container::*;
use common::*;

/// The seccomp profiles' default errno (ENOSYS).
const SECCOMP: &str = "errno=38";

/// The host kernel is 5.3 or later, so `clone3` exists and only seccomp can answer ENOSYS.
fn kernel_has_clone3() -> bool {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap();
    let mut parts = release.trim().split(['.', '-']);
    let mut next = || {
        parts
            .next()
            .and_then(|p| p.parse::<u32>().ok())
            .unwrap_or(0)
    };
    (next(), next()) >= (5, 3)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    Workspace,
    Harness,
    Inference,
}

const ROLES: [Role; 3] = [Role::Workspace, Role::Harness, Role::Inference];

/// One started container of a role.
struct Boxed {
    role: Role,
    container: String,
    /// The workspace's launcher handle; the other roles are removed by the fixture.
    running: Option<Running>,
}

async fn start(x: &Lx, role: Role) -> Boxed {
    let tag = format!("{role:?}").to_lowercase();
    let v = x.f.load("");
    let paths = x.paths(&tag);
    let (container, running) = match role {
        Role::Workspace => {
            let v =
                x.f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", "rw")]));
            let r = x.launch(&v, &tag).await.unwrap();
            (r.container().to_owned(), Some(r))
        }
        Role::Harness => {
            let dirs = SessionDirs::create(&paths, &x.xdg, &[], 0).unwrap();
            let argv = harness_argv(&x.common_args(&dirs), &paths, &v, &test_image()).unwrap();
            (x.create_and_start(argv).await, None)
        }
        Role::Inference => {
            let dirs = SessionDirs::create(&paths, &x.xdg, &[], 0).unwrap();
            let blobs = x.f.root.join("blobs");
            let blob = blobs.join("sha256").join(D1);
            std::fs::create_dir_all(blob.parent().unwrap()).unwrap();
            std::fs::write(&blob, b"GGUF").unwrap();
            std::fs::set_permissions(&blob, std::fs::Permissions::from_mode(0o444)).unwrap();
            let socket_dir = paths.socket_root().join("infer");
            std::fs::create_dir(&socket_dir).unwrap();
            std::fs::set_permissions(&socket_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            let spec = InferenceSpec {
                instance: SessionId::parse(&format!("{}-{tag}", x.scope)).unwrap(),
                socket_dir,
                model: VerifiedModel::pin(&blobs, D1).unwrap(),
                image: test_image(),
                gpu: false,
                gpu_layers: 0,
                context: 512,
                cpus: Cpus::from_millis(1000),
                memory: None,
            };
            let argv = inference_argv(&x.common_args(&dirs), &spec).unwrap();
            (x.create_and_start(argv).await, None)
        }
    };
    Boxed {
        role,
        container,
        running,
    }
}

/// Runs each probe call in the container; returns `(call, result)` in order.
fn probe(b: &Boxed, calls: &[&str]) -> Vec<(String, String)> {
    let script: String = calls
        .iter()
        .map(|c| format!("echo \"{c} => $({PROBE} {c})\"; "))
        .collect();
    let (code, out) = exec_in(&b.container, &["sh", "-c", &script]);
    assert_eq!(code, 0, "{:?}: {out}", b.role);
    let got: Vec<(String, String)> = out
        .lines()
        .filter_map(|l| l.split_once(" => "))
        .map(|(c, r)| (c.to_owned(), r.to_owned()))
        .collect();
    assert_eq!(got.len(), calls.len(), "{:?}: {out}", b.role);
    got
}

fn check(b: &Boxed, expected: &[(&str, &str)]) {
    let calls: Vec<&str> = expected.iter().map(|(c, _)| *c).collect();
    for ((call, got), (_, want)) in probe(b, &calls).iter().zip(expected) {
        assert_eq!(got, want, "{:?}: probe {call}", b.role);
    }
}

async fn finish(x: &Lx, boxes: Vec<Boxed>) {
    for b in boxes {
        if let Some(r) = b.running {
            x.stop(r).await;
        }
    }
}

/// RT-NET-12: socket families outside each role's list fail with the profile's ENOSYS, from
/// every role, including families a network namespace does not isolate (`AF_VSOCK` reaches the
/// hypervisor host) and netlink protocols other than `NETLINK_ROUTE`. Inference allows `AF_UNIX`
/// only; workspace and harness add `AF_INET`, `AF_INET6` and `NETLINK_ROUTE` (loopback only:
/// `--network=none`). Raw IP sockets pass the family filter but need `CAP_NET_RAW`, which no
/// role has.
#[test]
fn rt_net_12_socket_families_outside_the_role_list_fail() {
    rt().block_on(async {
        let x = Lx::new();
        let mut boxes = Vec::new();
        for role in ROLES {
            boxes.push(start(&x, role).await);
        }
        let denied_everywhere = [
            ("socket 40 1 0", SECCOMP),  // AF_VSOCK
            ("socket 40 2 0", SECCOMP),  // AF_VSOCK, datagram
            ("socket 17 3 0", SECCOMP),  // AF_PACKET
            ("socket 17 2 0", SECCOMP),  // AF_PACKET, cooked
            ("socket 16 3 9", SECCOMP),  // NETLINK_AUDIT
            ("socket 16 3 15", SECCOMP), // NETLINK_KOBJECT_UEVENT
            ("socket 16 3 12", SECCOMP), // NETLINK_NETFILTER
            ("socket 38 5 0", SECCOMP),  // AF_ALG
            ("socket 44 3 0", SECCOMP),  // AF_XDP
            ("socket 15 3 2", SECCOMP),  // AF_KEY
            ("socket 31 3 0", SECCOMP),  // AF_BLUETOOTH
            ("socket 21 5 0", SECCOMP),  // AF_RDS
            ("socket 30 4 0", SECCOMP),  // AF_TIPC
        ];
        for b in &boxes {
            check(b, &[("socket 1 1 0", "ok"), ("socket 1 2 0", "ok")]);
            check(b, &denied_everywhere);
            let ip = match b.role {
                Role::Inference => [
                    ("socket 2 1 0", SECCOMP),
                    ("socket 10 1 0", SECCOMP),
                    ("socket 16 3 0", SECCOMP),
                    ("socket 2 3 1", SECCOMP),
                ],
                Role::Workspace | Role::Harness => [
                    ("socket 2 1 0", "ok"),
                    ("socket 10 1 0", "ok"),
                    ("socket 16 3 0", "ok"),
                    ("socket 2 3 1", "errno=1"), // raw ICMP: EPERM, no CAP_NET_RAW
                ],
            };
            check(b, &ip);
        }
        finish(&x, boxes).await;
    });
}

/// ENETUNREACH: `--network=none` leaves only `lo`, so there is no route.
const UNREACH: &str = "errno=101";

/// Every role's only interface is `lo`.
fn only_loopback(b: &Boxed) {
    let (code, out) = exec_in(&b.container, &["ls", "/sys/class/net"]);
    assert_eq!((code, out.trim()), (0, "lo"), "{:?}", b.role);
}

/// RT-NET-01: direct TCP and UDP to the internet fail in every role. Workspace and harness may
/// open IP sockets (loopback only), so `connect` finds no route; inference may not open them.
#[test]
fn rt_net_01_direct_tcp_and_udp_find_no_route() {
    rt().block_on(async {
        let x = Lx::new();
        let mut boxes = Vec::new();
        for role in ROLES {
            boxes.push(start(&x, role).await);
        }
        for b in &boxes {
            only_loopback(b);
            let want = match b.role {
                Role::Inference => SECCOMP,
                Role::Workspace | Role::Harness => UNREACH,
            };
            check(
                b,
                &[
                    ("connect 2 1 0 1.1.1.1 443", want),
                    ("connect 2 2 0 8.8.8.8 53", want),
                    ("connect 10 1 0 2606:4700:4700::1111 443", want),
                    ("connect 10 2 0 2001:4860:4860::8888 53", want),
                ],
            );
            let (code, out) = exec_in(&b.container, &["nc", "-w", "3", "1.1.1.1", "443"]);
            assert_ne!(code, 0, "{:?}: busybox nc: {out}", b.role);
        }
        finish(&x, boxes).await;
    });
}

/// RT-NET-08: no raw sockets (no role has `CAP_NET_RAW`) and no ICMP out: `ping` fails in every
/// role, and an unprivileged ICMP ("ping") socket is refused with EACCES: the container's
/// `net.ipv4.ping_group_range` does not include the sandbox's group. Each probe sends one echo
/// request; the error code alone does not pass: if a socket is ever created, its send must fail
/// with ENETUNREACH (no packet leaves).
#[test]
fn rt_net_08_raw_sockets_and_icmp_fail() {
    rt().block_on(async {
        let x = Lx::new();
        let mut boxes = Vec::new();
        for role in ROLES {
            boxes.push(start(&x, role).await);
        }
        for b in &boxes {
            let (raw, icmp) = match b.role {
                Role::Inference => ("socket errno=38", "socket errno=38"),
                Role::Workspace | Role::Harness => ("socket errno=1", "socket errno=13"),
            };
            // Raw sockets must be refused at creation (the capability drop, not only
            // `--network=none`); a ping socket may instead be created and fail to send.
            let cases = [
                ("send 2 3 1 1.1.1.1 0", raw, false),   // SOCK_RAW, IPPROTO_ICMP
                ("send 2 3 255 1.1.1.1 0", raw, false), // SOCK_RAW, IPPROTO_RAW
                ("send 10 3 58 2606:4700::1111 0", raw, false), // SOCK_RAW, ICMPv6
                ("send 2 2 1 1.1.1.1 0", icmp, true),   // SOCK_DGRAM, IPPROTO_ICMP
                ("send 10 2 58 2606:4700::1111 0", icmp, true), // SOCK_DGRAM, ICMPv6
            ];
            let calls: Vec<&str> = cases.iter().map(|(c, _, _)| *c).collect();
            for ((call, got), (_, refused, may_send)) in probe(b, &calls).iter().zip(&cases) {
                let failed_send = *may_send && got == "sendto errno=101";
                assert!(
                    got == refused || failed_send,
                    "{:?}: probe {call}: {got} (want {refused}{})",
                    b.role,
                    if *may_send {
                        ", or a send that fails"
                    } else {
                        ""
                    }
                );
            }
            let (code, out) = exec_in(&b.container, &["ping", "-c", "1", "-W", "2", "1.1.1.1"]);
            assert_ne!(code, 0, "{:?}: ping: {out}", b.role);
        }
        finish(&x, boxes).await;
    });
}

/// RT-FS-17: no role can create a user, mount or network namespace through `unshare`, `clone`
/// or `clone3` (the profile's clone mask and the `clone3` refusal). A plain fork-like `clone`
/// still works.
#[test]
fn rt_fs_17_no_role_creates_a_namespace() {
    assert!(
        kernel_has_clone3(),
        "clone3 needs kernel >= 5.3, or its ENOSYS proves nothing"
    );
    rt().block_on(async {
        let x = Lx::new();
        let mut boxes = Vec::new();
        for role in ROLES {
            boxes.push(start(&x, role).await);
        }
        for b in &boxes {
            check(
                b,
                &[
                    ("clone 0", "ok"),
                    ("unshare 0x10000000", SECCOMP), // CLONE_NEWUSER
                    ("unshare 0x20000", SECCOMP),    // CLONE_NEWNS
                    ("unshare 0x40000000", SECCOMP), // CLONE_NEWNET
                    ("unshare 0x30020000", SECCOMP), // NEWUSER | NEWNS | NEWPID
                    ("clone 0x10000000", SECCOMP),
                    ("clone 0x20000", SECCOMP),
                    ("clone 0x10020000", SECCOMP),
                    ("clone 0x2000000", SECCOMP), // CLONE_NEWCGROUP
                    ("clone3 0", SECCOMP),
                    ("clone3 0x10000000", SECCOMP),
                ],
            );
            // The same through busybox, as an agent would try it.
            let (code, out) = exec_in(&b.container, &["unshare", "-U", "-r", "true"]);
            assert_ne!(code, 0, "{:?}: {out}", b.role);
            assert!(
                out.contains("Function not implemented"),
                "{:?}: refused by the profile (ENOSYS): {out}",
                b.role
            );
        }
        finish(&x, boxes).await;
    });
}
