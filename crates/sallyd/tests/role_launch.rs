//! The harness and inference launches through the one launch path (#123; architect Q130,
//! Q131, Q139–Q143): the refusals before anything is made, the harness's claim on its session,
//! the image check of every role, and what `stop_role` removes and keeps. The per-role
//! RT-SUP-04 tests (private `HOME`, empty mounts file, verifier) are in `tests/oci.rs`.
//!
//! The fixture is `common::container`; these tests never skip.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use sallyd::sandbox::{ImageRef, LaunchError};

mod common;
use common::container::*;

/// A digest-pinned image that is not in local storage.
fn absent_image() -> ImageRef {
    ImageRef::parse(&format!(
        "localhost/sallyport-absent@sha256:{}",
        "0".repeat(64)
    ))
    .unwrap()
}

/// A podman wrapper that appends each call's argv to `<at>/argv`, then runs the real podman.
/// Armed (`<at>/when` holds `create` or `init`, `<at>/sock` a path), it swaps that path once:
/// a directory for a new empty one, a file for a copy of itself (same bytes, another inode).
/// The swap happens after a successful `create`, or before `init` runs (after the host
/// re-check). Armed with `rm`, it fails every `rm` until disarmed instead. The verb is the
/// first word after the global `--flag value` pairs.
fn logging_podman(at: &Path, real: &Path) -> PathBuf {
    let (at, real) = (at.display(), real.display());
    let script = format!(
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >>'{at}/argv'\n\
         v=; skip=\nfor a; do\n\
         if [ -n \"$skip\" ]; then skip=; continue; fi\n\
         case \"$a\" in --*) [ -z \"$v\" ] && skip=1 ;; *) [ -z \"$v\" ] && v=$a ;; esac\n\
         done\n\
         when=$(cat '{at}/when' 2>/dev/null); sock=$(cat '{at}/sock' 2>/dev/null)\n\
         swap() {{ rm -f '{at}/when'; mv \"$sock\" \"$sock.old\" && \
         if [ -d \"$sock.old\" ]; then mkdir -m 700 \"$sock\"; \
         else cp -p \"$sock.old\" \"$sock\"; fi; }}\n\
         if [ \"$v\" = init ] && [ \"$when\" = init ]; then swap; fi\n\
         if [ \"$v\" = rm ] && [ \"$when\" = rm ]; then exit 125; fi\n\
         '{real}' \"$@\"\nrc=$?\n\
         if [ $rc -eq 0 ] && [ \"$v\" = create ] && [ \"$when\" = create ]; then swap; fi\n\
         exit $rc\n"
    );
    let bin = PathBuf::from(at.to_string()).join("podman");
    executable(&bin, script.as_bytes());
    bin
}

/// Arms [`logging_podman`] in `dir` to swap `sock` at `when`.
fn arm(dir: &Path, when: &str, sock: &Path) {
    std::fs::write(dir.join("sock"), sock.display().to_string()).unwrap();
    std::fs::write(dir.join("when"), when).unwrap();
}

struct RemoveOnDrop(PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn scratch(tag: &str) -> (PathBuf, RemoveOnDrop) {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("roles-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    (dir.clone(), RemoveOnDrop(dir))
}

fn logged(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("argv")).unwrap_or_default()
}

/// The last entry: its event and args, and whether it named a session.
fn last(x: &Lx) -> (String, serde_json::Value, String) {
    let (event, args) = x.events.all().last().cloned().unwrap();
    (event, args, x.events.debug().last().cloned().unwrap())
}

/// Q130, Q142: a harness needs an image first, then a live session; refused, it creates
/// nothing and runs no podman command.
#[test]
fn a_harness_outside_a_live_session_or_without_an_image_is_refused_first() {
    let (dir, _cleanup) = scratch("h-none");
    rt().block_on(async {
        let x = Lx::with_podman(|real| logging_podman(&dir, real));
        let v = x.f.load("");
        let mut no_image = x.harness(&v, "h-none");
        no_image.default_image = None;
        let e = x.launcher.launch_harness(no_image).await.unwrap_err();
        assert!(matches!(e, LaunchError::NoHarnessImage), "{e:?}");
        let (event, args, _) = last(&x);
        assert_eq!(event, "sandbox.refuse");
        assert_eq!(args["role"], "harness");
        assert_eq!(args["reason"], "no-default-image");
        let e = x
            .launcher
            .launch_harness(x.harness(&v, "h-none"))
            .await
            .unwrap_err();
        assert!(matches!(e, LaunchError::Harness(_)), "{e:?}");
        let (_, args, debug) = last(&x);
        assert_eq!(args["reason"], "no-session");
        assert_eq!(args["cleanup"], "nothing to clean up");
        let sid = x.paths("h-none").id().as_str().to_owned();
        assert!(debug.contains(&format!("Some(\"{sid}\")")), "{debug}");
        assert!(!x.paths("h-none").socket_root().exists());
        assert_eq!(logged(&dir), "", "no podman command ran");
    });
}

/// Security and Rust reviews H1/M1: a stop whose entry failed hands the handle back, the
/// container already gone and the claim freed; a retry after the session's next harness
/// launched writes the entry and never touches that harness (removal is by id, once).
#[test]
fn a_retried_harness_stop_never_touches_the_next_harness() {
    rt().block_on(async {
        let x = Lx::new();
        let v = x.f.load("");
        let ws = x.launch(&v, "h-retry").await.unwrap();
        let first = x
            .launcher
            .launch_harness(x.harness(&v, "h-retry"))
            .await
            .unwrap();
        x.events.fail(&["sandbox.stop"]);
        let e = x.launcher.stop_role(first).await.unwrap_err();
        x.events.fail(&[]);
        assert!(!exists(e.running.name()), "removed before the entry failed");
        let second = x
            .launcher
            .launch_harness(x.harness(&v, "h-retry"))
            .await
            .unwrap();
        x.launcher.stop_role(e.running).await.unwrap();
        assert_eq!(last(&x).0, "sandbox.stop");
        let id = podman(&["inspect", "--format", "{{.Id}}", second.name()]);
        assert_eq!(
            String::from_utf8_lossy(&id.stdout).trim(),
            second.container()
        );
        // The second's claim is still held: a third launch is refused.
        let third = x.launcher.launch_harness(x.harness(&v, "h-retry")).await;
        assert!(matches!(third, Err(LaunchError::Harness(_))), "{third:?}");
        x.launcher.stop_role(second).await.unwrap();
        x.stop(ws).await;
    });
}

/// Security review M2 (B4 for the harness and inference): the socket directory swapped after
/// `create` is caught by the host re-check (`mount-changed`), swapped after that re-check but
/// before `init` by the in-container check (`sandbox.mount_mismatch`). Each refusal frees the
/// harness claim, and so does a directory check that fails (Rust review M3): the harness
/// launches afterwards.
#[test]
fn a_swapped_socket_directory_is_refused_for_the_harness_and_inference() {
    let (dir, _cleanup) = scratch("swap");
    rt().block_on(async {
        let x = Lx::with_podman(|real| logging_podman(&dir, real));
        let v = x.f.load("");
        let ws = x.launch(&v, "swap").await.unwrap();
        let sock = ws.paths().harness_sockets();
        let cases = [
            ("create", "sandbox.refuse", "mount-changed"),
            ("init", "sandbox.mount_mismatch", "mount-mismatch"),
        ];
        for (when, event, reason) in cases {
            arm(&dir, when, &sock);
            let e = x.launcher.launch_harness(x.harness(&v, "swap")).await;
            let (got, args, _) = last(&x);
            assert_eq!(
                (got.as_str(), &args["reason"]),
                (event, &reason.into()),
                "{e:?}"
            );
            assert_eq!(args["role"], "harness");
            assert!(!exists(&format!("sp-h-{}", ws.paths().id().as_str())));
        }
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o750)).unwrap();
        let e = x.launcher.launch_harness(x.harness(&v, "swap")).await;
        assert!(matches!(e, Err(LaunchError::NoSession(_))), "{e:?}");
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o700)).unwrap();
        let h = x
            .launcher
            .launch_harness(x.harness(&v, "swap"))
            .await
            .unwrap();
        x.launcher.stop_role(h).await.unwrap();
        x.stop(ws).await;
        for (n, (when, event, reason)) in cases.into_iter().enumerate() {
            let tag = format!("swap-i{n}");
            arm(&dir, when, x.instance_paths(&tag).socket_dir());
            let e = x
                .launcher
                .launch_inference(x.inference(x.model(), &tag))
                .await;
            let (got, args, _) = last(&x);
            assert_eq!(
                (got.as_str(), &args["reason"]),
                (event, &reason.into()),
                "{e:?}"
            );
            assert_eq!(args["role"], "inference");
            assert!(!x.instance_paths(&tag).data_dir().exists());
        }
    });
}

/// Re-review L3: a stop whose entry was written but whose removal failed hands the handle back
/// with the container and the claim kept; the retry removes it without a second
/// `sandbox.stop`.
#[test]
fn a_retried_stop_after_a_failed_removal_writes_one_entry() {
    let (dir, _cleanup) = scratch("rmfail");
    rt().block_on(async {
        let x = Lx::with_podman(|real| logging_podman(&dir, real));
        let v = x.f.load("");
        let ws = x.launch(&v, "rmfail").await.unwrap();
        let h = x
            .launcher
            .launch_harness(x.harness(&v, "rmfail"))
            .await
            .unwrap();
        let stops = || {
            x.events
                .all()
                .iter()
                .filter(|(e, a)| e == "sandbox.stop" && a["role"] == "harness")
                .count()
        };
        std::fs::write(dir.join("when"), "rm").unwrap();
        let e = x.launcher.stop_role(h).await.unwrap_err();
        std::fs::remove_file(dir.join("when")).unwrap();
        assert!(exists(e.running.name()), "the container is kept");
        assert_eq!(stops(), 1);
        let again = x.launcher.launch_harness(x.harness(&v, "rmfail")).await;
        assert!(matches!(again, Err(LaunchError::Harness(_))), "{again:?}");
        x.launcher.stop_role(e.running).await.unwrap();
        assert_eq!(stops(), 1);
        assert!(!exists(&format!("sp-h-{}", ws.paths().id().as_str())));
        x.stop(ws).await;
    });
}

/// Re-review M1 (SI-6, B4 for the model): the model blob replaced by a copy of itself (same
/// bytes, another inode) after `create` is caught by the host re-check (`mount-changed`), and
/// after that re-check but before `init` by the in-container check (`sandbox.mount_mismatch`).
/// Either way the instance's directories are gone.
#[test]
fn a_swapped_model_blob_is_refused_for_inference() {
    let (dir, _cleanup) = scratch("blob");
    rt().block_on(async {
        let x = Lx::with_podman(|real| logging_podman(&dir, real));
        let cases = [
            ("create", "sandbox.refuse", "mount-changed"),
            ("init", "sandbox.mount_mismatch", "mount-mismatch"),
        ];
        for (n, (when, event, reason)) in cases.into_iter().enumerate() {
            let tag = format!("blob-i{n}");
            // Pinned anew each time: the previous case left the copy in place.
            let model = x.model();
            arm(&dir, when, model.path());
            let e = x.launcher.launch_inference(x.inference(model, &tag)).await;
            let (got, args, _) = last(&x);
            assert_eq!(
                (got.as_str(), &args["reason"]),
                (event, &reason.into()),
                "{e:?}"
            );
            assert_eq!(args["role"], "inference");
            assert!(!std::fs::exists(dir.join("when")).unwrap(), "not swapped");
            assert!(!x.instance_paths(&tag).data_dir().exists());
        }
    });
}

/// Q139, Q143 (h): a second harness for the same session is refused `overlap` before it can
/// create or remove anything: the first keeps running, with the same id, and no `rm` named it.
#[test]
fn a_second_harness_is_refused_and_the_first_keeps_running() {
    let (dir, _cleanup) = scratch("h-twice");
    rt().block_on(async {
        let x = Lx::with_podman(|real| logging_podman(&dir, real));
        let v = x.f.load("");
        let ws = x.launch(&v, "h-twice").await.unwrap();
        let first = x
            .launcher
            .launch_harness(x.harness(&v, "h-twice"))
            .await
            .unwrap();
        let before = logged(&dir).lines().count();
        let e = x
            .launcher
            .launch_harness(x.harness(&v, "h-twice"))
            .await
            .unwrap_err();
        assert!(matches!(e, LaunchError::Harness(_)), "{e:?}");
        let (_, args, _) = last(&x);
        assert_eq!(args["reason"], "overlap");
        assert!(
            args["detail"].as_str().unwrap().contains(first.name()),
            "{args}"
        );
        let after = logged(&dir);
        let calls: Vec<&str> = after.lines().skip(before).collect();
        assert!(calls.is_empty(), "the refusal ran podman: {calls:?}");
        let id = podman(&["inspect", "--format", "{{.Id}}", first.name()]);
        assert_eq!(
            String::from_utf8_lossy(&id.stdout).trim(),
            first.container()
        );
        x.launcher.stop_role(first).await.unwrap();
        x.stop(ws).await;
    });
}

/// Q130, Q143 (h): `stop_role` removes the harness container only: both session roots and the
/// harness socket directory stay, the session stays live and its harness can launch again.
#[test]
fn stopping_the_harness_keeps_the_session_and_frees_its_claim() {
    rt().block_on(async {
        let x = Lx::new();
        let v = x.f.load("");
        let ws = x.launch(&v, "h-stop").await.unwrap();
        let h = x
            .launcher
            .launch_harness(x.harness(&v, "h-stop"))
            .await
            .unwrap();
        let name = h.name().to_owned();
        x.launcher.stop_role(h).await.unwrap();
        let (event, args, _) = last(&x);
        assert_eq!(event, "sandbox.stop");
        assert_eq!(args, serde_json::json!({"role": "harness"}));
        assert!(!exists(&name));
        let paths = ws.paths().clone();
        for d in [
            paths.socket_root().to_owned(),
            paths.data_root().to_owned(),
            paths.harness_sockets(),
        ] {
            assert!(d.is_dir(), "{}", d.display());
        }
        let again = x
            .launcher
            .launch_harness(x.harness(&v, "h-stop"))
            .await
            .unwrap();
        x.launcher.stop_role(again).await.unwrap();
        x.stop(ws).await;
        // The workspace's stop released the session: no harness launches into it now.
        let e = x
            .launcher
            .launch_harness(x.harness(&v, "h-stop"))
            .await
            .unwrap_err();
        assert_eq!(last(&x).1["reason"], "no-session", "{e:?}");
    });
}

/// Q131, Q143 (h): GPU inference is refused first, audited with no session and the instance
/// in its args, and nothing is made.
#[test]
fn gpu_inference_is_refused_first_and_names_the_instance() {
    let (dir, _cleanup) = scratch("i-gpu");
    rt().block_on(async {
        let x = Lx::with_podman(|real| logging_podman(&dir, real));
        let mut req = x.inference(x.model(), "i-gpu");
        req.gpu = true;
        let instance = req.instance.as_str().to_owned();
        let e = x.launcher.launch_inference(req).await.unwrap_err();
        assert!(matches!(e, LaunchError::GpuUnsupported), "{e:?}");
        let (event, args, debug) = last(&x);
        assert_eq!(event, "sandbox.refuse");
        assert_eq!(args["role"], "inference");
        assert_eq!(args["instance"], instance.as_str());
        assert_eq!(args["reason"], "gpu-unsupported");
        assert!(debug.contains("session: None"), "{debug}");
        let p = x.instance_paths("i-gpu");
        assert!(!p.socket_dir().exists() && !p.data_dir().exists());
        assert_eq!(logged(&dir), "", "no podman command ran");
    });
}

/// Q131: an inference instance's stop is audited with the instance and removes its container
/// and both of its directories; its id is never reused.
#[test]
fn stopping_inference_removes_its_container_and_directories() {
    rt().block_on(async {
        let x = Lx::new();
        let i = x
            .launcher
            .launch_inference(x.inference(x.model(), "i-stop"))
            .await
            .unwrap();
        let p = x.instance_paths("i-stop");
        assert!(p.socket_dir().is_dir() && p.profiles().is_dir());
        let (launch, args, debug) = last(&x);
        assert_eq!(launch, "sandbox.launch");
        assert_eq!(args["role"], "inference");
        assert!(debug.contains("session: None"), "{debug}");
        let name = i.name().to_owned();
        x.launcher.stop_role(i).await.unwrap();
        let (event, args, _) = last(&x);
        assert_eq!(event, "sandbox.stop");
        assert_eq!(args["instance"], p.id().as_str());
        assert!(!exists(&name));
        assert!(!p.socket_dir().exists() && !p.data_dir().exists());
    });
}

/// Q143 (g): every role checks its image before it makes anything: absent, it is refused
/// `digest-mismatch`, no directory of that launch exists and no `create` ran.
#[test]
fn an_absent_image_is_refused_for_every_role_before_anything_is_made() {
    let (dir, _cleanup) = scratch("absent");
    rt().block_on(async {
        let x = Lx::with_podman(|real| logging_podman(&dir, real));
        let creates = || {
            logged(&dir)
                .lines()
                .filter(|l| l.split(' ').any(|w| w == "create"))
                .count()
        };
        let mut ws = x.request(&x.f.load(""), "absent-ws");
        ws.default_image = Some(absent_image());
        let e = x.launcher.launch_workspace(ws).await.unwrap_err();
        assert!(matches!(e, LaunchError::ImageMissing(_)), "{e:?}");
        assert_eq!(last(&x).1["reason"], "digest-mismatch");
        assert!(!x.paths("absent-ws").socket_root().exists());
        assert_eq!(creates(), 0);

        let v = x.f.load("");
        let live = x.launch(&v, "absent-h").await.unwrap();
        let before = creates();
        let mut h = x.harness(&v, "absent-h");
        h.default_image = Some(absent_image());
        let e = x.launcher.launch_harness(h).await.unwrap_err();
        assert!(matches!(e, LaunchError::ImageMissing(_)), "{e:?}");
        assert_eq!(last(&x).1["reason"], "digest-mismatch");
        assert_eq!(last(&x).1["role"], "harness");
        assert_eq!(creates(), before);
        // The refusal freed the claim (Rust review M3): the harness launches with its image.
        let ok = x
            .launcher
            .launch_harness(x.harness(&v, "absent-h"))
            .await
            .unwrap();
        x.launcher.stop_role(ok).await.unwrap();
        x.stop(live).await;

        let before = creates();
        let mut i = x.inference(x.model(), "absent-i");
        i.image = absent_image();
        let e = x.launcher.launch_inference(i).await.unwrap_err();
        assert!(matches!(e, LaunchError::ImageMissing(_)), "{e:?}");
        assert_eq!(last(&x).1["reason"], "digest-mismatch");
        assert_eq!(last(&x).1["role"], "inference");
        let p = x.instance_paths("absent-i");
        assert!(!p.socket_dir().exists() && !p.data_dir().exists());
        assert_eq!(creates(), before);
    });
}
