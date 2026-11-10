//! Task 6a: the pure `podman run` argv builder for every role (AMENDMENTS-01 §2, §6.1, §6.2) and
//! every mount mode, including `staged` and the `.git` overlay (AMENDMENTS-02 B2), plus the
//! forbidden-flag checker the red-team harness relies on (CLAUDE.md hard rules).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use proptest::prelude::*;
use sally_core::manifest::{ByteSize, Cpus, HostEnv, ValidatedManifest, load};
use sallyd::sandbox::{
    ArgvError, CheckedRuntime, CommonArgs, GitScan, ImageRef, InferenceSpec, SessionId,
    SessionPaths, UserIds, check_argv, harness_argv, inference_argv, workspace_argv,
};

const D0: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const D1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const D2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const HEADER: &str = "apiVersion: sallyport/v1\nkind: Manifest\nname: t\nmodel:\n  ref: any\n";

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A throwaway `$HOME`, runtime and state directories, removed on drop.
struct Fx {
    root: PathBuf,
    env: HostEnv,
    common: CommonArgs,
    paths: SessionPaths,
}

impl Fx {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("sallyd-argv-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let home = root.join("home");
        for d in [
            "code/myproject",
            "code/other",
            "Documents/research",
            ".config/sallyport",
            ".local/share/sallyport",
        ] {
            std::fs::create_dir_all(home.join(d)).unwrap();
        }
        for d in ["run", "bin", "profiles"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        let root = std::fs::canonicalize(&root).unwrap();
        let crun = root.join("bin/crun");
        std::fs::write(&crun, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&crun, std::fs::Permissions::from_mode(0o755)).unwrap();
        let home = root.join("home");
        let env = HostEnv {
            home: home.clone(),
            other_homes: Vec::new(),
            xdg_config_home: None,
            xdg_data_home: None,
            xdg_runtime_dir: Some(root.join("run")),
            podman_storage: vec![home.join(".local/share/containers/storage")],
            nproc: 8,
            mem_bytes: 16 << 30,
        };
        let common = CommonArgs {
            runtime: CheckedRuntime::check(&crun).unwrap(),
            ids: UserIds {
                uid: 1000,
                gid: 1000,
            },
            profiles: root.join("profiles"),
        };
        let paths = SessionPaths::new(
            SessionId::parse("s-0001").unwrap(),
            &root.join("run/sallyport"),
            &home.join(".local/share/sallyport"),
        )
        .unwrap();
        Self {
            root,
            env,
            common,
            paths,
        }
    }

    fn load(&self, body: &str) -> ValidatedManifest {
        let secrets: BTreeSet<String> = ["GITHUB_TOKEN".to_owned()].into_iter().collect();
        match load(&format!("{HEADER}{body}"), &self.env, &secrets) {
            Ok(v) => v.manifest,
            Err(e) => panic!("{e:#?}"),
        }
    }

    fn redact(&self, args: &[String]) -> String {
        let root = self.root.display().to_string();
        args.iter()
            .map(|a| a.replace(&root, "$ROOT"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn image(name: &str, digest: &str) -> ImageRef {
    ImageRef::parse(&format!("ghcr.io/sallyport/{name}@sha256:{digest}")).unwrap()
}

fn ws_image() -> ImageRef {
    image("workspace", D1)
}

fn mount(host: &str, guest: &str, mode: &str) -> String {
    format!("    - host: \"{host}\"\n      guest: {guest}\n      mode: {mode}\n")
}

fn mounts(list: &[String]) -> String {
    format!("filesystem:\n  mounts:\n{}", list.concat())
}

const PROXY: &str = "network:\n  mode: proxy\n  allow:\n    - host: pypi.org\n";

// ---- snapshots: workspace, every mount mode -------------------------------------------------

#[test]
fn snapshot_workspace_ro_no_network() {
    let f = Fx::new();
    let v = f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", "ro")]));
    let a = workspace_argv(&f.common, &f.paths, &v, &[], &ws_image()).unwrap();
    insta::assert_snapshot!("workspace-ro", f.redact(&a));
}

#[test]
fn snapshot_workspace_rw_with_git_overlays_and_pointer_files() {
    let f = Fx::new();
    let v = f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", "rw")]));
    let scan = GitScan {
        mount: 0,
        dirs: vec![PathBuf::from(".git"), PathBuf::from("vendor/lib/.git")],
        files: vec![PathBuf::from("sub/module/.git")],
    };
    let a = workspace_argv(&f.common, &f.paths, &v, &[scan], &ws_image()).unwrap();
    insta::assert_snapshot!("workspace-rw-git", f.redact(&a));
}

#[test]
fn snapshot_workspace_brokered_is_a_read_only_bind() {
    let f = Fx::new();
    let v = f.load(&mounts(&[mount(
        "~/Documents/research",
        "/workspace/r",
        "brokered",
    )]));
    let a = workspace_argv(&f.common, &f.paths, &v, &[], &ws_image()).unwrap();
    insta::assert_snapshot!("workspace-brokered", f.redact(&a));
}

#[test]
fn snapshot_workspace_staged_mounts_and_proxy() {
    let f = Fx::new();
    let v = f.load(&format!(
        "{}{PROXY}",
        mounts(&[
            mount("~/code/myproject", "/workspace/p", "staged"),
            mount("~/code/other", "/workspace/o", "staged"),
        ])
    ));
    let a = workspace_argv(&f.common, &f.paths, &v, &[], &ws_image()).unwrap();
    insta::assert_snapshot!("workspace-staged-proxy", f.redact(&a));
}

#[test]
fn snapshot_workspace_all_modes_secrets_and_custom_image() {
    let f = Fx::new();
    let v = f.load(&format!(
        "runtime:\n  image: ghcr.io/x/tools@sha256:{D2}\n  cpus: 2.5\n  memory: 3GiB\n  pids: 256\n  tmp_size: 512MiB\n  tmp_exec: true\n{}network:\n  mode: proxy\n  allow:\n    - host: api.github.com\nsecrets:\n  - name: GITHUB_TOKEN\n    inject: {{host: api.github.com, header: Authorization, format: \"Bearer {{value}}\"}}\n    expose_env: GH_TOKEN\n",
        mounts(&[
            mount("~/code/myproject", "/workspace/p", "rw"),
            mount("~/code/other", "/workspace/o", "ro"),
            mount("~/Documents/research", "/workspace/r", "staged"),
        ])
    ));
    let scan = GitScan {
        mount: 0,
        dirs: vec![PathBuf::from(".git")],
        files: Vec::new(),
    };
    let a = workspace_argv(&f.common, &f.paths, &v, &[scan], &ws_image()).unwrap();
    insta::assert_snapshot!("workspace-all-modes-secrets", f.redact(&a));
}

// ---- snapshots: harness and inference -------------------------------------------------------

#[test]
fn snapshot_harness_default_and_custom_image() {
    let f = Fx::new();
    let v = f.load("");
    let a = harness_argv(&f.common, &f.paths, &v, &image("harness", D0)).unwrap();
    insta::assert_snapshot!("harness-default", f.redact(&a));
    let v = f.load(&format!("harness:\n  image: ghcr.io/x/h@sha256:{D2}\n"));
    let a = harness_argv(&f.common, &f.paths, &v, &image("harness", D0)).unwrap();
    assert!(a.contains(&format!("ghcr.io/x/h@sha256:{D2}")), "{a:?}");
}

fn inference(f: &Fx, gpu: bool, memory: Option<ByteSize>) -> InferenceSpec {
    let blob = f
        .root
        .join("home/.local/share/sallyport/library/blobs/sha256")
        .join(D0);
    std::fs::create_dir_all(blob.parent().unwrap()).unwrap();
    std::fs::write(&blob, b"GGUF").unwrap();
    InferenceSpec {
        instance: SessionId::parse("i-0001").unwrap(),
        socket_dir: f.root.join("run/sallyport/infer/i-0001"),
        model: blob,
        image: image("inference", D0),
        gpu,
        gpu_layers: 99,
        context: 8192,
        cpus: Cpus::from_millis(4000),
        memory,
    }
}

#[test]
fn snapshot_inference_gpu_and_cpu() {
    let f = Fx::new();
    let a = inference_argv(
        &f.common,
        &inference(&f, true, Some(ByteSize::from_bytes(8 << 30))),
    )
    .unwrap();
    insta::assert_snapshot!("inference-gpu", f.redact(&a));
    let a = inference_argv(&f.common, &inference(&f, false, None)).unwrap();
    insta::assert_snapshot!("inference-cpu", f.redact(&a));
    assert!(!a.iter().any(|x| x.starts_with("--device")), "{a:?}");
}

// ---- invariants of every argv ---------------------------------------------------------------

fn every_argv(f: &Fx) -> Vec<Vec<String>> {
    let v = f.load(&format!(
        "{}{PROXY}",
        mounts(&[
            mount("~/code/myproject", "/workspace/p", "rw"),
            mount("~/code/other", "/workspace/o", "staged"),
            mount("~/Documents/research", "/workspace/r", "brokered"),
        ])
    ));
    let scan = GitScan {
        mount: 0,
        dirs: vec![PathBuf::from(".git")],
        files: Vec::new(),
    };
    vec![
        workspace_argv(&f.common, &f.paths, &v, &[scan], &ws_image()).unwrap(),
        harness_argv(&f.common, &f.paths, &v, &image("harness", D0)).unwrap(),
        inference_argv(&f.common, &inference(f, true, None)).unwrap(),
    ]
}

#[test]
fn every_role_starts_with_the_checked_runtime_and_has_the_section_6_1_flags() {
    let f = Fx::new();
    for a in every_argv(&f) {
        assert_eq!(a[0], "--runtime", "{a:?}");
        assert_eq!(a[1], f.root.join("bin/crun").display().to_string());
        assert_eq!(a[2], "run");
        for flag in [
            "--rm",
            "--pull=never",
            "--http-proxy=false",
            "--log-driver=none",
            "--network=none",
            "--no-hosts",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--userns=keep-id",
            "--init",
            "--env-host=false",
        ] {
            assert_eq!(
                a.iter().filter(|x| *x == flag).count(),
                1,
                "{flag} in {a:?}"
            );
        }
        let core = a.windows(2).any(|w| w[0] == "--ulimit" && w[1] == "core=0");
        assert!(core, "{a:?}");
    }
}

#[test]
fn roles_never_share_a_socket_directory() {
    let f = Fx::new();
    let all = every_argv(&f);
    let sock_src = |a: &[String]| {
        a.iter()
            .filter_map(|x| x.strip_suffix(":/run/sallyport:rw,nosuid,nodev,bind"))
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    let (ws, h, inf) = (sock_src(&all[0]), sock_src(&all[1]), sock_src(&all[2]));
    assert_eq!((ws.len(), h.len(), inf.len()), (1, 1, 1));
    assert_ne!(ws, h);
    assert_ne!(ws, inf);
    assert_ne!(h, inf);
    // The harness gets no mounts besides its sockets, and no proxy.
    assert_eq!(all[1].iter().filter(|x| *x == "-v").count(), 1);
    assert!(!all[1].iter().any(|x| x.contains("PROXY")), "{:?}", all[1]);
    // Only inference gets the GPU.
    assert!(!all[0].iter().any(|x| x.contains("nvidia")));
    assert!(!all[1].iter().any(|x| x.contains("nvidia")));
}

#[test]
fn git_overlays_land_in_session_scratch_and_never_touch_the_host_git() {
    let f = Fx::new();
    let v = f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", "rw")]));
    let scan = GitScan {
        mount: 0,
        dirs: vec![PathBuf::from(".git")],
        files: Vec::new(),
    };
    let a = workspace_argv(&f.common, &f.paths, &v, &[scan], &ws_image()).unwrap();
    let host_git = f
        .root
        .join("home/code/myproject/.git")
        .display()
        .to_string();
    let overlay = a
        .iter()
        .find(|x| x.starts_with(&format!("{host_git}:")))
        .expect("an overlay for the .git directory");
    assert!(
        overlay.contains(":/workspace/p/.git:O,upperdir="),
        "{overlay}"
    );
    let scratch = f
        .root
        .join("home/.local/share/sallyport/sessions/s-0001/git/0")
        .display()
        .to_string();
    assert!(
        overlay.contains(&format!("upperdir={scratch}/upper,workdir={scratch}/work")),
        "{overlay}"
    );
    // The overlay comes after the mount it shadows, or it would be hidden by it.
    let pos = |needle: &str| a.iter().position(|x| x.starts_with(needle)).unwrap();
    assert!(pos(&host_git) > pos(&f.root.join("home/code/myproject:").display().to_string()));
}

// ---- builder refuses bad input ------------------------------------------------------------------

#[test]
fn git_scan_entries_are_validated() {
    let f = Fx::new();
    let v = f.load(&mounts(&[
        mount("~/code/myproject", "/workspace/p", "rw"),
        mount("~/code/other", "/workspace/o", "staged"),
    ]));
    let bad = [
        GitScan {
            mount: 0,
            dirs: vec![PathBuf::from("../x/.git")],
            files: Vec::new(),
        },
        GitScan {
            mount: 0,
            dirs: vec![PathBuf::from("/abs/.git")],
            files: Vec::new(),
        },
        GitScan {
            mount: 0,
            dirs: vec![PathBuf::from("a:b/.git")],
            files: Vec::new(),
        },
        GitScan {
            mount: 0,
            dirs: vec![PathBuf::from("a,ro/.git")],
            files: Vec::new(),
        },
        GitScan {
            mount: 0,
            dirs: vec![PathBuf::from("not-git")],
            files: Vec::new(),
        },
        GitScan {
            mount: 0,
            dirs: Vec::new(),
            files: vec![PathBuf::from("x/./.git")],
        },
        GitScan {
            mount: 1,
            dirs: vec![PathBuf::from(".git")],
            files: Vec::new(),
        },
        GitScan {
            mount: 7,
            dirs: vec![PathBuf::from(".git")],
            files: Vec::new(),
        },
    ];
    for scan in bad {
        let r = workspace_argv(
            &f.common,
            &f.paths,
            &v,
            std::slice::from_ref(&scan),
            &ws_image(),
        );
        assert!(matches!(r, Err(ArgvError::Input(_))), "{scan:?}: {r:?}");
    }
}

#[test]
fn identifiers_and_images_are_validated() {
    for bad in ["", "S-1", "a_b", "-x", &"a".repeat(65), "a/b", "a:b"] {
        assert!(SessionId::parse(bad).is_err(), "{bad:?}");
    }
    for ok in ["s-1", "0", &"a".repeat(64)] {
        assert!(SessionId::parse(ok).is_ok(), "{ok:?}");
    }
    for bad in [
        "ghcr.io/x/y:latest".to_owned(),
        format!("ghcr.io/x/y@sha256:{}", &D0[1..]),
        format!("ghcr.io/x/y@sha256:{}", D0.to_uppercase().replace('0', "A")),
        format!("ghcr.io/x y@sha256:{D0}"),
        format!("-ghcr.io/x@sha256:{D0}"),
        format!("@sha256:{D0}"),
    ] {
        assert!(ImageRef::parse(&bad).is_err(), "{bad}");
    }
}

#[test]
fn inference_refuses_a_model_or_socket_path_that_would_break_the_mount_syntax() {
    let f = Fx::new();
    let mut spec = inference(&f, false, None);
    spec.model = f.root.join("a:b");
    assert!(matches!(
        inference_argv(&f.common, &spec),
        Err(ArgvError::Input(_))
    ));
    let mut spec = inference(&f, false, None);
    spec.socket_dir = PathBuf::from("relative/dir");
    assert!(matches!(
        inference_argv(&f.common, &spec),
        Err(ArgvError::Input(_))
    ));
}

// ---- the forbidden-flag checker (deny + allow) ----------------------------------------------

fn base(f: &Fx) -> (Vec<String>, Vec<PathBuf>) {
    let v = f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", "ro")]));
    let a = workspace_argv(&f.common, &f.paths, &v, &[], &ws_image()).unwrap();
    let roots = vec![
        f.root.join("home/code/myproject"),
        f.root.join("run/sallyport/sessions/s-0001"),
    ];
    (a, roots)
}

fn with(a: &[String], extra: &[&str]) -> Vec<String> {
    // Insert just after `run`, where podman reads options.
    let mut out = a[..3].to_vec();
    out.extend(extra.iter().map(|s| (*s).to_owned()));
    out.extend_from_slice(&a[3..]);
    out
}

#[test]
fn checker_accepts_the_builders_output() {
    let f = Fx::new();
    let (a, roots) = base(&f);
    let roots: Vec<&Path> = roots.iter().map(PathBuf::as_path).collect();
    check_argv(&a, &roots).unwrap();
}

#[test]
fn checker_refuses_every_forbidden_flag() {
    let f = Fx::new();
    let (a, roots) = base(&f);
    let roots: Vec<&Path> = roots.iter().map(PathBuf::as_path).collect();
    let forbidden: &[&[&str]] = &[
        &["--privileged"],
        &["--privileged=true"],
        &["--cap-add=NET_ADMIN"],
        &["--cap-add", "SYS_ADMIN"],
        &["--network=host"],
        &["--network", "bridge"],
        &["--net=slirp4netns"],
        &["--network=pasta"],
        &["--network=container:other"],
        &["--security-opt", "seccomp=unconfined"],
        &["--security-opt=seccomp=unconfined"],
        &["--security-opt", "apparmor=unconfined"],
        &["--userns=host"],
        &["--userns", "host"],
        &["--pid=host"],
        &["--ipc=host"],
        &["--uts=host"],
        &["--device", "/dev/kvm"],
        &["--device=/dev/fuse"],
        &["-v", "/etc:/x:ro,nosuid,nodev,bind"],
        &["--volume=/etc:/x:ro,nosuid,nodev,bind"],
        &["--mount", "type=bind,src=/etc,dst=/x"],
        &["--volumes-from", "other"],
        &["--env-host"],
        &["--env-host=true"],
    ];
    for extra in forbidden {
        let r = check_argv(&with(&a, extra), &roots);
        assert!(
            matches!(r, Err(ArgvError::Forbidden(_))),
            "{extra:?}: {r:?}"
        );
    }
    // The GPU device is the one allowed `--device`.
    check_argv(&with(&a, &["--device", "nvidia.com/gpu=all"]), &roots).unwrap();
}

#[test]
fn checker_requires_the_hardening_flags_and_mount_options() {
    let f = Fx::new();
    let (a, roots) = base(&f);
    let roots: Vec<&Path> = roots.iter().map(PathBuf::as_path).collect();
    for drop in [
        "--network=none",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--read-only",
        "--pull=never",
        "--rm",
        "--userns=keep-id",
    ] {
        let without: Vec<String> = a.iter().filter(|x| *x != drop).cloned().collect();
        assert!(
            matches!(check_argv(&without, &roots), Err(ArgvError::Forbidden(_))),
            "{drop} removed"
        );
    }
    let mount = a
        .iter()
        .position(|x| x.ends_with(":/workspace/p:ro,nosuid,nodev,bind"))
        .unwrap();
    for weak in [
        ":/workspace/p:ro",
        ":/workspace/p:ro,nodev,bind",
        ":/workspace/p:rw,suid,nodev,bind",
    ] {
        let mut b = a.clone();
        b[mount] = format!("{}{weak}", f.root.join("home/code/myproject").display());
        assert!(
            matches!(check_argv(&b, &roots), Err(ArgvError::Forbidden(_))),
            "{weak}"
        );
    }
    // An overlay may carry only O, upperdir and workdir.
    let mut b = a.clone();
    b[mount] = format!(
        "{}:/workspace/p:O,upperdir={0}/u,workdir={0}/w,exec",
        f.root.join("home/code/myproject").display()
    );
    assert!(matches!(
        check_argv(&b, &roots),
        Err(ArgvError::Forbidden(_))
    ));
}

// ---- property: any valid manifest yields an argv the checker accepts -------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn any_mount_mix_passes_the_checker(
        modes in proptest::collection::vec(prop_oneof![Just("ro"), Just("rw"), Just("brokered"), Just("staged")], 0..3),
        proxy in any::<bool>(),
        git in any::<bool>(),
    ) {
        let f = Fx::new();
        let hosts = ["~/code/myproject", "~/code/other", "~/Documents/research"];
        let list: Vec<String> = modes.iter().enumerate()
            .map(|(i, m)| mount(hosts[i], &format!("/workspace/m{i}"), m)).collect();
        let body = if list.is_empty() { String::new() } else { mounts(&list) };
        let body = if proxy { format!("{body}{PROXY}") } else { body };
        let v = f.load(&body);
        let scans: Vec<GitScan> = modes.iter().enumerate()
            .filter(|(_, m)| git && **m == "rw")
            .map(|(i, _)| GitScan { mount: i, dirs: vec![PathBuf::from(".git")], files: vec![PathBuf::from("s/.git")] })
            .collect();
        let a = workspace_argv(&f.common, &f.paths, &v, &scans, &ws_image()).unwrap();
        let overlays = scans.len() * 2;
        prop_assert_eq!(a.iter().filter(|x| *x == "-v").count(), modes.len() + overlays + 1);
        prop_assert_eq!(a.iter().filter(|x| x.starts_with("--network")).count(), 1);
        prop_assert_eq!(a.iter().any(|x| x.starts_with("--env=HTTP_PROXY=") || x == "HTTP_PROXY=http://127.0.0.1:3128"), proxy);
    }
}
