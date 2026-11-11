//! RT-SUP-01 (remainder) and RT-SUP-02: a pinned image that is not in local storage is refused
//! before anything is created, and nothing on that path makes an outbound connection.
//!
//! The launcher's check (`sandbox::images`) is there for the clear refusal reason only; the
//! enforcement is the digest reference plus `--pull=never` at `podman create`, which the strace
//! case covers as well. The fixture is `common::container`; these tests never skip.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
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

/// `strace -f` of hermetic podman: every `connect` it makes is local (`AF_UNIX`, netlink, or
/// loopback). Returns the log, so a caller can check the trace is not vacuous.
fn traced(x: &Lx, args: &[&str], log: &Path) -> String {
    let status = Command::new("strace")
        .args(["-f", "-qq", "-e", "trace=connect,execve", "-o"])
        .arg(log)
        .arg(x.podman.bin())
        .args(args)
        .env_clear()
        .envs(x.podman.environment().iter().map(|(k, v)| (k, v)))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("strace must be installed (CI: container test prerequisites)");
    assert!(
        !status.success(),
        "podman {args:?} must fail for an absent image"
    );
    let text = std::fs::read_to_string(log).unwrap();
    assert!(
        text.contains("execve(") && text.contains(&*x.podman.bin().to_string_lossy()),
        "the trace saw podman run: {text}"
    );
    for line in text.lines().filter(|l| l.contains("connect(")) {
        let local = line.contains("sa_family=AF_UNIX")
            || line.contains("sa_family=AF_NETLINK")
            || line.contains("inet_addr(\"127.")
            || line.contains("inet_pton(AF_INET6, \"::1\"");
        assert!(local, "outbound connect: {line}");
    }
    text
}

/// A missing digest is refused, and neither the launcher's check (`podman image exists`) nor
/// the enforcement (`podman create --pull=never`) connects anywhere but locally.
#[test]
fn rt_sup_02_a_missing_digest_is_refused_without_an_outbound_connection() {
    rt().block_on(async {
        let x = Lx::new();
        let image = absent_image();
        let v = with_image(&x, &image);
        let e = x.launch(&v, "sup02").await.unwrap_err();
        refused_as_digest_mismatch(&x, &e);
        let log = x.f.root.join("strace.log");
        traced(&x, &["image", "exists", &image], &log);
        traced(
            &x,
            &["create", "--pull=never", "--network=none", &image, "true"],
            &log,
        );
    });
}
