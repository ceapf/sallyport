//! RT-SUP-01 (remainder) and RT-SUP-02: a pinned image that is not in local storage is refused
//! before anything is created, and nothing on that path makes an outbound connection.
//!
//! The launcher's check (`sandbox::images`) is there for the clear refusal reason only; the
//! enforcement is the digest reference plus `--pull=never` at `podman create`, which the strace
//! case covers as well. The fixture is `common::container`; these tests never skip.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;

use sallyd::sandbox::LaunchError;

mod common;
use common::container::*;
use common::*;

/// The base image's name with a digest nothing in local storage carries.
fn absent_image() -> String {
    let name = BASE.split_once('@').unwrap().0;
    format!("{name}@sha256:{D1}")
}

/// A manifest whose workspace image is `image`.
fn with_image(x: &Lx, image: &str) -> sally_core::manifest::ValidatedManifest {
    x.f.load(&format!(
        "{}runtime:\n  image: \"{image}\"\n",
        mounts(&[mount("~/code/myproject", "/workspace/p", "ro")])
    ))
}

fn refused_as_digest_mismatch(x: &Lx, e: &LaunchError) {
    assert!(matches!(e, LaunchError::ImageMissing(_)), "{e}");
    assert_eq!(x.events.list(), ["sandbox.refuse"]);
    assert_eq!(
        x.events.args("sandbox.refuse").unwrap()["reason"],
        "digest-mismatch"
    );
}

/// The base image is present under its name; the same name with another digest is refused,
/// and so is the base image's own digest under another name.
#[test]
fn rt_sup_01_a_pinned_digest_not_in_local_storage_is_refused() {
    rt().block_on(async {
        let digest = BASE.split_once('@').unwrap().1;
        for image in [absent_image(), format!("localhost/other@{digest}")] {
            let x = Lx::new();
            let v = with_image(&x, &image);
            let e = x.launch(&v, "sup01").await.unwrap_err();
            refused_as_digest_mismatch(&x, &e);
            let names = podman(&["ps", "--all", "--format", "{{.Names}}"]);
            assert!(
                !String::from_utf8_lossy(&names.stdout).contains(&x.scope),
                "nothing was created for {image}"
            );
        }
    });
}

/// Hermetic podman, untraced.
fn hermetic(x: &Lx, args: &[&str]) -> std::process::Output {
    let out = Command::new(x.podman.bin())
        .args(args)
        .env_clear()
        .envs(x.podman.environment().iter().map(|(k, v)| (k, v)))
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "podman {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

/// The image store's `images.json`, under the graph root hermetic podman reports.
fn images_json(x: &Lx) -> String {
    let info = hermetic(
        x,
        &[
            "info",
            "--format",
            "{{.Store.GraphRoot}}\t{{.Store.GraphDriverName}}",
        ],
    );
    let info = String::from_utf8(info.stdout).unwrap();
    let (root, driver) = info.trim().split_once('\t').unwrap();
    assert!(root.starts_with('/') && !driver.is_empty(), "{info:?}");
    format!("{root}/{driver}-images/images.json")
}

/// The sockets syscalls that can carry an address, and the ones that prove the lookup ran.
const TRACE: &str = "trace=connect,sendto,sendmsg,sendmmsg,openat,execve";

/// `strace -f` of hermetic podman `args`. Asserts its exit code and stderr, that podman ran and
/// opened the image store (`store`), and that no `connect`/`send*` names an `AF_INET` or
/// `AF_INET6` address, loopback included (`AF_UNIX` and netlink are local).
fn traced(x: &Lx, args: &[&str], store: &str, code: i32, stderr: &str) {
    let log = x.f.root.join("strace.log");
    let out = Command::new("strace")
        .args(["-f", "-qq", "-e", TRACE, "-o"])
        .arg(&log)
        .arg(x.podman.bin())
        .args(args)
        .env_clear()
        .envs(x.podman.environment().iter().map(|(k, v)| (k, v)))
        .stdin(std::process::Stdio::null())
        .output()
        .expect("strace must be installed (CI: container test prerequisites)");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(code), "podman {args:?}: {err}");
    assert!(err.contains(stderr), "podman {args:?}: {err}");
    let text = std::fs::read_to_string(&log).unwrap();
    let bin = x.podman.bin().to_string_lossy();
    assert!(
        text.lines()
            .any(|l| l.contains("execve(") && l.contains(&*bin)),
        "the trace saw podman run: {text}"
    );
    assert!(
        text.lines()
            .any(|l| l.contains("openat(") && l.contains(&format!("\"{store}\""))),
        "podman {args:?} looked the image up in {store}: {text}"
    );
    let sends = ["connect(", "sendto(", "sendmsg(", "sendmmsg("];
    for line in text.lines().filter(|l| sends.iter().any(|s| l.contains(s))) {
        let inet =
            line.contains("AF_INET") || line.contains("inet_addr(") || line.contains("inet_pton(");
        assert!(!inet, "podman {args:?} addressed an IP: {line}");
    }
}

/// A missing digest is refused as not found (not as a podman error), and neither the launcher's
/// check (`podman image exists`) nor the enforcement (`podman create --pull=never`) sends to any
/// IP address, loopback included.
#[test]
fn rt_sup_02_a_missing_digest_is_refused_without_an_outbound_connection() {
    rt().block_on(async {
        let x = Lx::new();
        let image = absent_image();
        let v = with_image(&x, &image);
        let e = x.launch(&v, "sup02").await.unwrap_err();
        refused_as_digest_mismatch(&x, &e);
        assert!(e.to_string().contains("not in local storage"), "{e}");
        // A traced podman cannot start the setuid uid-map helpers, so the rootless namespace
        // must already exist: an untraced hermetic call creates it whatever ran before.
        hermetic(&x, &["unshare", "true"]);
        let store = images_json(&x);
        traced(&x, &["image", "exists", &image], &store, 1, "");
        let create = ["create", "--pull=never", "--network=none", &image, "true"];
        traced(&x, &create, &store, 125, "image not known");
    });
}
