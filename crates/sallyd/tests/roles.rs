//! Task 6c red-team rows that hold in every role, with real containers (rootless Podman):
//! RT-NET-01 (no route out), RT-NET-08 (raw sockets and ICMP), RT-NET-12 (socket families),
//! RT-FS-17 (no new namespaces) and RT-FS-24 (removed system calls), and the ENOENT half of
//! RT-FS-10 (broker state out of reach).
//!
//! The workspace comes from the launcher; the harness and inference containers from their argv
//! builders, created and started with hermetic podman exactly as the argv says (their launchers,
//! #123, are tested in `tests/oci.rs` and `tests/role_launch.rs`). The probe is
//! `tests/redteam/probe/probe.c`. Every refusal of RT-NET-12 and RT-FS-17 must be `ENOSYS` (38),
//! the seccomp profiles' default action: the kernel never returns it for `socket`,
//! `socketpair`, `unshare`, `clone` or `clone3` itself (an unsupported family or protocol is
//! `EAFNOSUPPORT`, `EPROTONOSUPPORT` or `EOPNOTSUPP`), so the profile is what refused. That holds
//! for `clone3` only from kernel 5.3 on, where the syscall exists; [`kernel_has_clone3`] checks
//! it. RT-FS-24's calls answer as the profile says (see its test).
//! The fixture is `common::container`; these tests never skip.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

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
    /// The host directory mounted at `/run/sallyport` in this role.
    sockets: PathBuf,
}

async fn start(x: &Lx, role: Role) -> Boxed {
    let tag = format!("{role:?}").to_lowercase();
    let v = x.f.load("");
    let paths = x.paths(&tag);
    let (container, running, sockets) = match role {
        Role::Workspace => {
            let v =
                x.f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", "rw")]));
            let r = x.launch(&v, &tag).await.unwrap();
            let sockets = r.paths().workspace_sockets();
            (r.container().to_owned(), Some(r), sockets)
        }
        Role::Harness => {
            let dirs = SessionDirs::create(&paths, &x.xdg, &[], 0).unwrap();
            let argv = harness_argv(&x.common_args(&dirs), &paths, &v, &test_image()).unwrap();
            (
                x.create_and_start(argv).await,
                None,
                paths.harness_sockets(),
            )
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
                socket_dir: socket_dir.clone(),
                model: VerifiedModel::pin(&blobs, D1).unwrap(),
                image: test_image(),
                gpu: false,
                gpu_layers: 0,
                context: 512,
                cpus: Cpus::from_millis(1000),
                memory: None,
            };
            let argv = inference_argv(&x.common_args(&dirs), &spec).unwrap();
            (x.create_and_start(argv).await, None, socket_dir)
        }
    };
    Boxed {
        role,
        container,
        running,
        sockets,
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
/// role has. `socketpair` is allowed for `AF_UNIX` only, in every role: its control makes
/// `AF_UNIX` stream and datagram pairs, and every other family (the denied ones, `AF_INET`,
/// `AF_INET6`, `AF_NETLINK`) must fail with `ENOSYS`. The kernel answers a `socketpair` it
/// refuses with its own errno (`EOPNOTSUPP`, `EAFNOSUPPORT`, `EPERM` and the like), never
/// `ENOSYS`, so that errno can only come from the profile.
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
            // Security review: `socketpair` follows the list too, AF_UNIX only in every role.
            // Control: AF_UNIX pairs are made. Every other family is the profile's ENOSYS, never
            // the kernel's own answer.
            check(b, &[("socketpair 1 1 0", "ok"), ("socketpair 1 2 0", "ok")]);
            let calls: Vec<String> = denied_everywhere
                .iter()
                .map(|(call, _)| call.replacen("socket ", "socketpair ", 1))
                .chain(
                    ["socketpair 2 1 0", "socketpair 10 1 0", "socketpair 16 3 0"]
                        .map(String::from),
                )
                .collect();
            let refused: Vec<(&str, &str)> = calls.iter().map(|c| (c.as_str(), SECCOMP)).collect();
            check(b, &refused);
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

/// RT-NET-01's busybox `nc` connect to `host` port `port`; exits 0 once connected.
fn nc_connect(host: &str, port: u16) -> String {
    format!("nc -w 3 {host} {port} </dev/null")
}

/// RT-NET-01's control (analogue, architect Q154): in workspace and harness, the same probe
/// `connect` and the same `nc` form reach a listener on the container's own loopback (its own
/// network namespace: nothing is bound on the host); in inference, which may open no IP socket,
/// an `AF_UNIX` socket is created. Leaving `--network=none` out is forbidden by a hard rule.
fn net01_control(b: &Boxed) {
    if b.role == Role::Inference {
        check(b, &[("socket 1 1 0", "ok")]);
        return;
    }
    let script = format!(
        "nc -l -p 4000 >/dev/null 2>&1 & nc -l -p 4001 >/dev/null 2>&1 & sleep 1; \
         echo \"probe => $({PROBE} connect 2 1 0 127.0.0.1 4000)\"; \
         {} && echo 'nc => ok'",
        nc_connect("127.0.0.1", 4001)
    );
    let (_, out) = exec_in(&b.container, &["sh", "-c", &script]);
    assert!(out.contains("probe => ok"), "control: {:?}: {out}", b.role);
    assert!(out.contains("nc => ok"), "control: {:?}: {out}", b.role);
}

/// RT-NET-01: direct TCP and UDP to the internet fail in every role. Workspace and harness may
/// open IP sockets (loopback only), so `connect` finds no route; inference may not open them.
/// Control (analogue), asserted first: [`net01_control`].
#[test]
fn rt_net_01_direct_tcp_and_udp_find_no_route() {
    rt().block_on(async {
        let x = Lx::new();
        let mut boxes = Vec::new();
        for role in ROLES {
            boxes.push(start(&x, role).await);
        }
        for b in &boxes {
            net01_control(b);
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
            let (code, out) = exec_in(&b.container, &["sh", "-c", &nc_connect("1.1.1.1", 443)]);
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

/// The errno of the profiles' explicit `SCMP_ACT_ERRNO` rules that come before their default
/// (`bpf`, `userfaultfd`, `open_by_handle_at`, among others): EPERM.
const PROFILE_EPERM: &str = "errno=1";

/// RT-FS-24: one system call of each class the profiles remove (mount, ptrace, bpf, io_uring,
/// keyring, userfaultfd, handle-based open) answers as the profile says, in every role: the
/// default's ENOSYS, or EPERM where an explicit rule names the call. Each runs with every
/// argument 0, except `userfaultfd` with `UFFD_USER_MODE_ONLY` (1), which an unprivileged process
/// may use. Unfiltered, the kernel runs `ptrace` and that `userfaultfd`, and answers the others
/// EFAULT or EINVAL: never ENOSYS, and never EPERM for the three EPERM calls, so the profile is
/// what refused. Control, first in each role: an allowed call (`getpid`) through the same probe
/// answers `ok`.
#[test]
fn rt_fs_24_removed_system_calls_answer_as_the_profile_says() {
    rt().block_on(async {
        let x = Lx::new();
        let mut boxes = Vec::new();
        for role in ROLES {
            boxes.push(start(&x, role).await);
        }
        for b in &boxes {
            let control = probe(b, &["syscall getpid"]);
            assert_eq!(control[0].1, "ok", "control: {:?}: getpid", b.role);
            check(
                b,
                &[
                    ("syscall mount", SECCOMP),
                    ("syscall ptrace", SECCOMP),
                    ("syscall bpf", PROFILE_EPERM),
                    ("syscall io_uring_setup", SECCOMP),
                    ("syscall keyctl", SECCOMP),
                    ("syscall userfaultfd 1", PROFILE_EPERM),
                    ("syscall open_by_handle_at", PROFILE_EPERM),
                ],
            );
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

/// The broker's state on the host, made to exist first so that ENOENT from a role proves the path
/// is out of its reach rather than absent: `control.sock` (bound), the audit directory, the
/// secrets file, the library blobs directory, and the blobs directory the inference model came
/// from. Absolute host paths (ARCHITECTURE §3.1).
fn broker_state(x: &Lx) -> (Vec<PathBuf>, std::os::unix::net::UnixListener) {
    let home = x.f.root.join("home");
    let data = home.join(".local/share/sallyport");
    let sockets = x.xdg.join("sallyport");
    std::fs::create_dir_all(&sockets).unwrap();
    let control = sockets.join("control.sock");
    let listener = std::os::unix::net::UnixListener::bind(&control).unwrap();
    let audit = data.join("audit");
    std::fs::create_dir_all(&audit).unwrap();
    std::fs::write(audit.join("audit-202611.jsonl"), b"{}\n").unwrap();
    let config = home.join(".config/sallyport");
    std::fs::create_dir_all(&config).unwrap();
    let secrets = config.join("secrets.toml");
    std::fs::write(&secrets, b"").unwrap();
    std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o600)).unwrap();
    let blobs = data.join("library/blobs/sha256");
    std::fs::create_dir_all(&blobs).unwrap();
    let paths = vec![control, audit, secrets, blobs, x.f.root.join("blobs")];
    for p in &paths {
        assert!(p.exists(), "{} must exist on the host", p.display());
    }
    (paths, listener)
}

/// The broker's `control.sock` as a role would find it beside its own sockets (form D).
const CONTROL_SOCK: &str = "/run/sallyport/control.sock";

/// RT-FS-10's probe strings for a role whose host socket directory is `sockets`, for each
/// broker path in `host`: its absolute path (form A), under `/run/sallyport/../..` (B), and
/// the `..` chain from `sockets` (C). On the host, each climb reaches its path.
fn fs10_tried(sockets: &Path, host: &[PathBuf]) -> Vec<String> {
    let mut tried: Vec<String> = host.iter().map(|p| p.display().to_string()).collect();
    tried.extend(
        host.iter()
            .map(|p| format!("/run/sallyport/../..{}", p.display())),
    );
    for p in host {
        let up = sockets.join(climb(sockets, p));
        assert_eq!(up.canonicalize().unwrap(), p.canonicalize().unwrap());
    }
    tried.extend(
        host.iter()
            .map(|p| format!("/run/sallyport/{}", climb(sockets, p))),
    );
    tried
}

/// `ls -d` of `/run/sallyport`, then of each path, in `container`: one line per path, `found`
/// or the error. `/run/sallyport` must be found, so the probe tells present from absent.
fn fs10_probe(container: &str, tried: &[String]) -> Vec<String> {
    let script: String = std::iter::once("/run/sallyport")
        .chain(tried.iter().map(String::as_str))
        .map(|p| format!("r=$(ls -d -- '{p}' 2>&1 >/dev/null) && echo 'found' || echo \"$r\"; "))
        .collect();
    let (code, out) = exec_in(container, &["sh", "-c", &script]);
    assert_eq!(code, 0, "{container}: {out}");
    let lines: Vec<String> = out.lines().map(str::to_owned).collect();
    assert_eq!(lines.len(), tried.len() + 1, "{container}: {out}");
    assert_eq!(lines[0], "found", "{container}: /run/sallyport");
    lines
}

/// A harness container for session `tag` from the product argv, with `leave_out`.
async fn harness_control(x: &Lx, tag: &str, leave_out: LeaveOut<'_>) -> String {
    let paths = x.paths(tag);
    let dirs = SessionDirs::create(&paths, &x.xdg, &[], 0).unwrap();
    let argv = harness_argv(&x.common_args(&dirs), &paths, &x.f.load(""), &test_image()).unwrap();
    x.control(argv, leave_out).await
}

/// RT-FS-10's controls (#122, architect Q167), harness role only: every role's probe strings
/// (`tried`) print `found` in a container with each broker path bound in at its host path and at
/// the guest path its climb reaches; `control.sock` is found beside the role's sockets when the
/// broker's socket directory is the source of `/run/sallyport`.
async fn fs10_controls(x: &Lx, boxes: &[Boxed], host: &[PathBuf], tried: &[Vec<String>]) {
    let mut guests: Vec<(PathBuf, String)> = Vec::new();
    for p in host {
        guests.push((p.clone(), p.display().to_string()));
        for b in boxes {
            let at = (p.clone(), inside(&climb(&b.sockets, p)));
            if !guests.contains(&at) {
                guests.push(at);
            }
        }
    }
    assert_eq!(
        guests.len(),
        2 * host.len(),
        "control: one climb target per path: {guests:?}"
    );
    let binds: Vec<(&Path, &str)> = guests
        .iter()
        .map(|(h, g)| (h.as_path(), g.as_str()))
        .collect();
    let id = harness_control(x, "fs10x", LeaveOut::Binds(&binds)).await;
    for (b, tried) in boxes.iter().zip(tried) {
        for (p, line) in tried.iter().zip(&fs10_probe(&id, tried)[1..]) {
            assert_eq!(line, "found", "control: {:?}: {p}", b.role);
        }
    }
    let sockets = host[0].parent().unwrap();
    let source = LeaveOut::Source {
        guest: "/run/sallyport",
        host: sockets,
    };
    let id = harness_control(x, "fs10y", source).await;
    let line = &fs10_probe(&id, &[CONTROL_SOCK.to_owned()])[1];
    assert_eq!(line, "found", "control: {CONTROL_SOCK}");
}

/// RT-FS-10, the ENOENT half (#61 item 1; architect Q82): from every role, the broker's state is
/// out of reach. Each host path by its absolute path, under `/run/sallyport/../..`, and by the
/// `..` chain that climbs from the role's host socket directory (mounted at `/run/sallyport`) to
/// it, and `control.sock` beside the role's own sockets: all ENOENT. `/run/sallyport` itself is
/// found in every role, so the probe tells present from absent. Control: the role's mount set
/// (`argv.rs`): mounting any of these host directories into a role makes its path resolve.
#[test]
fn rt_fs_10_broker_state_is_enoent_from_every_role() {
    rt().block_on(async {
        let x = Lx::new();
        let mut boxes = Vec::new();
        for role in ROLES {
            boxes.push(start(&x, role).await);
        }
        // After the starts: the inference role's blobs directory exists only from then.
        let (host, _control) = broker_state(&x);
        let tried: Vec<Vec<String>> = boxes
            .iter()
            .map(|b| fs10_tried(&b.sockets, &host))
            .collect();
        fs10_controls(&x, &boxes, &host, &tried).await;
        for (b, tried) in boxes.iter().zip(&tried) {
            let mut tried = tried.clone();
            tried.push(CONTROL_SOCK.into());
            let lines = fs10_probe(&b.container, &tried);
            for (p, line) in tried.iter().zip(&lines[1..]) {
                assert!(
                    line.ends_with("No such file or directory"),
                    "{:?}: {p}: {line}",
                    b.role
                );
            }
        }
        finish(&x, boxes).await;
    });
}
