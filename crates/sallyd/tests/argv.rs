//! Task 6a: the pure `podman run` argv builder for every role (AMENDMENTS-01 §2, §6.1, §6.2) and
//! every mount mode, including `staged` and the `.git` overlay (AMENDMENTS-02 B2), plus the
//! forbidden-flag checker the red-team harness relies on (CLAUDE.md hard rules).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use proptest::prelude::*;
use sally_core::manifest::{ByteSize, Cpus, HostEnv, ValidatedManifest, load};
use sallyd::sandbox::{
    Allowed, ArgvError, CheckedRuntime, CommonArgs, GitScan, Grant, ImageRef, InferenceSpec, Role,
    SessionId, SessionPaths, Source, UserIds, check_argv, harness_argv, inference_argv,
    workspace_argv,
};

const D0: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const D1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const D2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const HEADER: &str = "apiVersion: sallyport/v1\nkind: Manifest\nname: t\nmodel:\n  ref: any\n";

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A throwaway `$HOME`, runtime and state directories, removed on drop. Lives under
/// `CARGO_TARGET_TMPDIR`: a target directory under `/tmp` cannot host it, because the runtime
/// check refuses a world-writable ancestor and the manifest denylist refuses `/tmp` mounts.
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

fn scan(mount: usize, dirs: &[&str], files: &[&str]) -> GitScan {
    GitScan {
        mount,
        dirs: dirs.iter().map(PathBuf::from).collect(),
        files: files.iter().map(PathBuf::from).collect(),
    }
}

fn every_argv(f: &Fx) -> Vec<Vec<String>> {
    let v = f.load(&format!(
        "{}{PROXY}",
        mounts(&[
            mount("~/code/myproject", "/workspace/p", "rw"),
            mount("~/code/other", "/workspace/o", "staged"),
            mount("~/Documents/research", "/workspace/r", "brokered"),
        ])
    ));
    vec![
        workspace_argv(
            &f.common,
            &f.paths,
            &v,
            &[scan(0, &[".git"], &[])],
            &ws_image(),
        )
        .unwrap(),
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
            .filter_map(|x| x.split_once(":/run/sallyport:").map(|(s, _)| s.to_owned()))
            .collect::<Vec<_>>()
    };
    let (ws, h, inf) = (sock_src(&all[0]), sock_src(&all[1]), sock_src(&all[2]));
    assert_eq!((ws.len(), h.len(), inf.len()), (1, 1, 1));
    assert_ne!(ws, h);
    assert_ne!(ws, inf);
    assert_ne!(h, inf);
    // Workspace and harness only connect, so their socket directories are read-only; inference
    // creates its socket.
    assert!(
        all[0]
            .iter()
            .any(|x| x.ends_with(":/run/sallyport:ro,nosuid,nodev,bind"))
    );
    assert!(
        all[1]
            .iter()
            .any(|x| x.ends_with(":/run/sallyport:ro,nosuid,nodev,bind"))
    );
    assert!(
        all[2]
            .iter()
            .any(|x| x.ends_with(":/run/sallyport:rw,nosuid,nodev,bind"))
    );
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
    let a = workspace_argv(
        &f.common,
        &f.paths,
        &v,
        &[scan(0, &[".git"], &[])],
        &ws_image(),
    )
    .unwrap();
    let host_git = f
        .root
        .join("home/code/myproject/.git")
        .display()
        .to_string();
    let overlay = a
        .iter()
        .find(|x| x.starts_with(&format!("{host_git}:")))
        .expect("an overlay for the .git directory");
    let scratch = f
        .root
        .join("home/.local/share/sallyport/sessions/s-0001/git/0")
        .display()
        .to_string();
    assert_eq!(
        overlay,
        &format!("{host_git}:/workspace/p/.git:O,upperdir={scratch}/upper,workdir={scratch}/work")
    );
}

/// Security review of 6a: a directory that merely contains a mount point can be renamed, so
/// `mv sub sub2 && mkdir -p sub/.git` replaced a nested `.git` shield. Every directory between
/// the mount root and a `.git` entry is bound onto itself, which makes the rename fail (EBUSY).
#[test]
fn nested_git_parents_are_pinned_by_self_binds() {
    let f = Fx::new();
    let v = f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", "rw")]));
    let a = workspace_argv(
        &f.common,
        &f.paths,
        &v,
        &[scan(
            0,
            &["vendor/lib/.git", "vendor/x/.git"],
            &["sub/module/.git"],
        )],
        &ws_image(),
    )
    .unwrap();
    let host = f.root.join("home/code/myproject").display().to_string();
    let self_binds: Vec<&str> = a
        .iter()
        .filter_map(|x| x.strip_suffix(",nosuid,nodev,bind"))
        .filter_map(|x| x.strip_prefix(&format!("{host}/")))
        .collect();
    assert_eq!(
        self_binds,
        vec![
            "sub:/workspace/p/sub:rw",
            "sub/module:/workspace/p/sub/module:rw",
            "vendor:/workspace/p/vendor:rw",
            "vendor/lib:/workspace/p/vendor/lib:rw",
            "vendor/x:/workspace/p/vendor/x:rw",
            "sub/module/.git:/workspace/p/sub/module/.git:ro",
        ]
    );
}

#[test]
fn rw_mounts_need_a_git_scan_even_if_empty() {
    let f = Fx::new();
    let v = f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", "rw")]));
    let r = workspace_argv(&f.common, &f.paths, &v, &[], &ws_image());
    assert!(
        matches!(&r, Err(ArgvError::Input(m)) if m.contains("filesystem.mounts[0]")),
        "{r:?}"
    );
    workspace_argv(&f.common, &f.paths, &v, &[scan(0, &[], &[])], &ws_image()).unwrap();
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
        vec![scan(0, &["../x/.git"], &[])],
        vec![scan(0, &["/abs/.git"], &[])],
        vec![scan(0, &["a:b/.git"], &[])],
        vec![scan(0, &["a,ro/.git"], &[])],
        vec![scan(0, &["not-git"], &[])],
        vec![scan(0, &["a//.git"], &[])],
        vec![scan(0, &[".git/modules/x/.git"], &[])],
        vec![scan(0, &[], &["x/./.git"])],
        vec![scan(0, &[".git"], &[".git"])],
        vec![scan(0, &[], &[]), scan(0, &[], &[])],
        vec![scan(0, &[], &[]), scan(1, &[".git"], &[])],
        vec![scan(0, &[], &[]), scan(7, &[".git"], &[])],
    ];
    for scans in bad {
        let r = workspace_argv(&f.common, &f.paths, &v, &scans, &ws_image());
        assert!(
            matches!(&r, Err(ArgvError::Input(m)) if m.contains("filesystem.mounts[")),
            "{scans:?}: {r:?}"
        );
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
        // SI-11: Podman transports load from a host path or another daemon.
        format!("dir:/home/u/img@sha256:{D0}"),
        format!("dir:5000/rel@sha256:{D0}"),
        format!("oci:foo@sha256:{D0}"),
        format!("oci-archive:/x.tar@sha256:{D0}"),
        format!("docker-archive:/x.tar@sha256:{D0}"),
        format!("docker-daemon:x@sha256:{D0}"),
        format!("containers-storage:x@sha256:{D0}"),
        format!("docker://ghcr.io/x@sha256:{D0}"),
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

// ---- the checker (deny + allow, per predicate) ----------------------------------------------

/// A workspace argv with one `ro` mount and the policy a hand-written caller would give it.
fn base(f: &Fx) -> (Vec<String>, Allowed) {
    let v = f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", "ro")]));
    let a = workspace_argv(&f.common, &f.paths, &v, &[], &ws_image()).unwrap();
    (a, allowed(f, Role::Workspace, Grant::Ro))
}

fn allowed(f: &Fx, role: Role, project: Grant) -> Allowed {
    let src = |p: PathBuf, guest: &str, grant| Source {
        path: p,
        guest: guest.to_owned(),
        grant,
    };
    Allowed {
        role,
        ids: f.common.ids,
        profiles: f.common.profiles.clone(),
        sources: vec![
            src(f.root.join("home/code/myproject"), "/workspace/p", project),
            src(f.paths.workspace_sockets(), "/run/sallyport", Grant::Ro),
        ],
        scratch: Some(f.paths.data_root().to_owned()),
    }
}

fn with(a: &[String], extra: &[&str]) -> Vec<String> {
    // Insert just after `run`, where podman reads options.
    let mut out = a[..3].to_vec();
    out.extend(extra.iter().map(|s| (*s).to_owned()));
    out.extend_from_slice(&a[3..]);
    out
}

/// Replaces the option token `old` (and its separate value, if `old` takes one) with `new`.
fn replacing(a: &[String], old: &str, new: &[&str]) -> Vec<String> {
    let i = a
        .iter()
        .position(|x| x == old)
        .unwrap_or_else(|| panic!("{old} in {a:?}"));
    let separate = !old.contains('=') && a.get(i + 1).is_some_and(|v| !v.starts_with('-'));
    let end = if separate { i + 2 } else { i + 1 };
    let mut out = a[..i].to_vec();
    out.extend(new.iter().map(|s| (*s).to_owned()));
    out.extend_from_slice(&a[end..]);
    out
}

fn assert_forbidden(a: &[String], allowed: &Allowed, what: &str) {
    let r = check_argv(a, allowed);
    assert!(matches!(r, Err(ArgvError::Forbidden(_))), "{what}: {r:?}");
}

#[test]
fn checker_accepts_the_builders_output() {
    let f = Fx::new();
    let (a, allowed) = base(&f);
    check_argv(&a, &allowed).unwrap();
}

#[test]
fn checker_refuses_every_forbidden_flag() {
    let f = Fx::new();
    let (a, allowed) = base(&f);
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
        &["--device", "nvidia.com/gpu=all"],
        &["-v", "/etc:/x:ro,nosuid,nodev,bind"],
        &["--volume=/etc:/x:ro,nosuid,nodev,bind"],
        &["--mount", "type=bind,src=/etc,dst=/x"],
        &["--volumes-from", "other"],
        &["--env-host"],
        &["--env-host=true"],
        &["--hooks-dir=/x"],
    ];
    for extra in forbidden {
        assert_forbidden(&with(&a, extra), &allowed, &format!("{extra:?}"));
    }
}

#[test]
fn checker_refuses_wrong_values_of_allowed_options() {
    let f = Fx::new();
    let (a, allowed) = base(&f);
    let profile = f
        .root
        .join("profiles/seccomp-workspace.json")
        .display()
        .to_string();
    let other_profile = f
        .root
        .join("home/code/myproject/allow.json")
        .display()
        .to_string();
    let cases: &[(&str, &[&str])] = &[
        ("--user", &["--user", "0:0"]),
        ("--user", &["--user", "1000"]),
        ("--name", &["--name", "sp-h-s-0001"]),
        ("--name", &["--name", "other"]),
        ("--name", &["--name", "sp-ws-"]),
        ("--hostname", &["--hostname", "host"]),
        ("--pids-limit", &["--pids-limit", "0"]),
        ("--pids-limit", &["--pids-limit", "-1"]),
        ("--cpus", &["--cpus", "x"]),
        ("--cpus", &["--cpus", "0.0"]),
        ("--memory", &["--memory", "1g"]),
        ("--memory", &["--memory", "0b"]),
        ("--ulimit", &["--ulimit", "core=1"]),
        ("--log-driver=none", &["--log-driver=json-file"]),
        ("--http-proxy=false", &["--http-proxy=true"]),
        ("--read-only-tmpfs=false", &["--read-only-tmpfs=true"]),
        ("--tmpfs", &["--tmpfs", "/tmp:rw,noexec,nodev,size=1"]),
        (
            "--tmpfs",
            &["--tmpfs", "/tmp:rw,noexec,nosuid,nodev,suid,size=1"],
        ),
        (
            "--tmpfs",
            &["--tmpfs", "/var:rw,noexec,nosuid,nodev,size=1"],
        ),
        (
            "--tmpfs",
            &["--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=0"],
        ),
        ("--tmpfs", &["--tmpfs", "/tmp:rw,noexec,suid,nodev,size=1"]),
        ("label=disable", &["label=type:spc_t"]),
        ("--pull=never", &["--pull=always"]),
        ("--network=none", &["--network=none,x"]),
        ("--cap-drop=ALL", &["--cap-drop=NET_RAW"]),
        ("--userns=keep-id", &["--userns=auto"]),
        ("--env-host=false", &["--env-host=true"]),
    ];
    for (old, new) in cases {
        assert_forbidden(
            &replacing(&a, old, new),
            &allowed,
            &format!("{old} -> {new:?}"),
        );
    }
    let seccomp = format!("seccomp={profile}");
    for bad in [
        format!("seccomp={other_profile}"),
        format!(
            "seccomp={}",
            f.root.join("profiles/seccomp-harness.json").display()
        ),
    ] {
        assert_forbidden(&replacing(&a, &seccomp, &[&bad]), &allowed, &bad);
        // A second profile is refused even though the first one is right.
        assert_forbidden(&with(&a, &["--security-opt", &bad]), &allowed, &bad);
    }
}

#[test]
fn checker_allows_only_each_roles_environment() {
    let f = Fx::new();
    let (a, allowed) = base(&f);
    for env in [
        "PATH=/x",
        "LD_PRELOAD=sallyport-placeholder",
        "SALLY_X=sallyport-placeholder",
        "lower=sallyport-placeholder",
        "GH_TOKEN=ghp-real-value",
        "HTTP_PROXY=http://evil.example:3128",
        "NO_PROXY=*",
        "SSL_CERT_FILE=/tmp/ca.pem",
        "OPENAI_API_KEY=sallyport",
        "NOEQUALS",
    ] {
        assert_forbidden(&with(&a, &["--env", env]), &allowed, env);
    }
    check_argv(
        &with(&a, &["--env", "GH_TOKEN=sallyport-placeholder"]),
        &allowed,
    )
    .unwrap();
    // A name may be set once.
    let twice = with(
        &a,
        &[
            "--env",
            "GH_TOKEN=sallyport-placeholder",
            "--env",
            "GH_TOKEN=sallyport-placeholder",
        ],
    );
    assert_forbidden(&twice, &allowed, "duplicate env");
    // Harness: exactly its two pairs.
    let h = harness_argv(&f.common, &f.paths, &f.load(""), &image("harness", D0)).unwrap();
    let ha = Allowed {
        role: Role::Harness,
        sources: vec![Source {
            path: f.paths.harness_sockets(),
            guest: "/run/sallyport".into(),
            grant: Grant::Ro,
        }],
        scratch: None,
        ..allowed.clone()
    };
    check_argv(&h, &ha).unwrap();
    assert_forbidden(
        &with(&h, &["--env", "GH_TOKEN=sallyport-placeholder"]),
        &ha,
        "harness env",
    );
    assert_forbidden(
        &replacing(
            &h,
            "OPENAI_BASE_URL=http://127.0.0.1:8080/v1",
            &["OPENAI_BASE_URL=http://evil/v1"],
        ),
        &ha,
        "harness base url",
    );
}

#[test]
fn checker_holds_every_mount_to_its_grant() {
    let f = Fx::new();
    let (a, ro) = base(&f);
    let p = f.root.join("home/code/myproject").display().to_string();
    let data = f.paths.data_root().display().to_string();
    let hsock = f.paths.harness_sockets().display().to_string();
    let bad = [
        // Prefix siblings and traversal.
        format!("{p}-evil:/workspace/q:ro,nosuid,nodev,bind"),
        format!("{p}/../../etc:/workspace/q:ro,nosuid,nodev,bind"),
        format!("{p}/./x:/workspace/p/x:ro,nosuid,nodev,bind"),
        // Destinations: traversal, root, trailing slash, twice.
        format!("{p}:/workspace/../etc:ro,nosuid,nodev,bind"),
        format!("{p}:/:ro,nosuid,nodev,bind"),
        format!("{p}:/workspace/p/:ro,nosuid,nodev,bind"),
        format!("{p}:/workspace/p:ro,nosuid,nodev,bind"),
        format!("{p}:/workspace/other:ro,nosuid,nodev,bind"),
        // A ro grant is neither writable nor an overlay, nor covers paths inside it.
        format!("{p}:/workspace/w:rw,nosuid,nodev,bind"),
        format!("{p}/sub:/workspace/p/sub:ro,nosuid,nodev,bind"),
        format!("{p}:/workspace/o:O,upperdir={data}/u,workdir={data}/w"),
        // Another role's sockets (SI-2).
        format!("{hsock}:/run/h:ro,nosuid,nodev,bind"),
        // Options.
        format!("{p}:/workspace/q:ro"),
        format!("{p}:/workspace/q:ro,nodev,bind"),
        format!("{p}:/workspace/q:rw,suid,nodev,bind"),
        format!("{p}:/workspace/q:ro,nosuid,nodev,bind:extra"),
    ];
    for v in &bad {
        assert_forbidden(&with(&a, &["-v", v]), &ro, v);
    }
    // Overlays: only on an overlay grant or inside an rw grant, scratch only in session data.
    let ov = allowed(&f, Role::Workspace, Grant::Overlay);
    let staged = |upper: &str, work: &str| {
        let mut b = a.clone();
        let i = b
            .iter()
            .position(|x| x.ends_with(":/workspace/p:ro,nosuid,nodev,bind"))
            .unwrap();
        b[i] = format!("{p}:/workspace/p:O,upperdir={upper},workdir={work}");
        b
    };
    check_argv(
        &staged(
            &format!("{data}/stage/0/upper"),
            &format!("{data}/stage/0/work"),
        ),
        &ov,
    )
    .unwrap();
    for (u, w) in [
        (format!("{p}/u"), format!("{data}/w")),
        (format!("{data}/u"), format!("{p}/w")),
        (format!("{data}/same"), format!("{data}/same")),
        (data.clone(), format!("{data}/w")),
        (format!("{data}/../u"), format!("{data}/w")),
    ] {
        assert_forbidden(&staged(&u, &w), &ov, &format!("{u} {w}"));
    }
    assert_forbidden(
        &staged(
            &format!("{data}/stage/0/upper"),
            &format!("{data}/stage/0/work"),
        ),
        &ro,
        "overlay of a ro grant",
    );
    let mut extra_opt = staged(&format!("{data}/u"), &format!("{data}/w"));
    let i = extra_opt.iter().position(|x| x.contains(":O,")).unwrap();
    extra_opt[i].push_str(",exec");
    assert_forbidden(&extra_opt, &ov, "overlay with an extra option");
    // Inside an rw grant: binds and overlays at the matching guest path only.
    let rw = allowed(&f, Role::Workspace, Grant::Rw);
    let rw_base = replacing(
        &a,
        &format!("{p}:/workspace/p:ro,nosuid,nodev,bind"),
        &[&format!("{p}:/workspace/p:rw,nosuid,nodev,bind")],
    );
    check_argv(&rw_base, &rw).unwrap();
    for ok in [
        format!("{p}/sub:/workspace/p/sub:rw,nosuid,nodev,bind"),
        format!("{p}/sub/.git:/workspace/p/sub/.git:ro,nosuid,nodev,bind"),
        format!(
            "{p}/.git:/workspace/p/.git:O,upperdir={data}/git/0/upper,workdir={data}/git/0/work"
        ),
    ] {
        check_argv(&with(&rw_base, &["-v", &ok]), &rw).unwrap();
    }
    for bad in [
        format!("{p}/sub:/workspace/elsewhere:rw,nosuid,nodev,bind"),
        format!("{p}/.git:/workspace/p/.git:O,upperdir={p}/u,workdir={data}/w"),
    ] {
        assert_forbidden(&with(&rw_base, &["-v", &bad]), &rw, &bad);
    }
}

#[test]
fn checker_requires_every_hardening_option_exactly_once() {
    let f = Fx::new();
    let (a, allowed) = base(&f);
    // Removing any option other than a mount or a variable fails; duplicating any option fails.
    let image_at = a.iter().position(|x| x.starts_with("ghcr.io/")).unwrap();
    let mut i = 3;
    while i < image_at {
        let tok = &a[i];
        let takes_value = !tok.contains('=') && !a[i + 1].starts_with('-') && i + 1 < image_at;
        let end = if takes_value { i + 2 } else { i + 1 };
        let opt: Vec<&str> = a[i..end].iter().map(String::as_str).collect();
        if tok != "-v" && tok != "--env" {
            let mut without = a[..i].to_vec();
            without.extend_from_slice(&a[end..]);
            assert_forbidden(&without, &allowed, &format!("without {opt:?}"));
        }
        assert_forbidden(&with(&a, &opt), &allowed, &format!("twice {opt:?}"));
        i = end;
    }
}

#[test]
fn checker_requires_each_roles_fixed_command_and_a_pinned_image() {
    let f = Fx::new();
    let (a, allowed) = base(&f);
    let n = a.len();
    let image_at = n - 3;
    for tail in [
        vec!["ghcr.io/x/y:latest", "/opt/sallyport/entry", "--idle"],
        vec![
            "dir:/x@sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "/opt/sallyport/entry",
            "--idle",
        ],
        vec![a[image_at].as_str(), "/opt/sallyport/entry"],
        vec![a[image_at].as_str(), "/bin/sh", "-c", "x"],
        vec![a[image_at].as_str(), "/opt/sallyport/entry", "--idle", "x"],
    ] {
        let mut b = a[..image_at].to_vec();
        b.extend(tail.iter().map(|s| (*s).to_owned()));
        assert_forbidden(&b, &allowed, &format!("{tail:?}"));
    }
    // Inference: exactly the llama-server command, numbers aside.
    let spec = inference(&f, true, None);
    let inf = inference_argv(&f.common, &spec).unwrap();
    let ia = Allowed {
        role: Role::Inference,
        sources: vec![
            Source {
                path: spec.model.clone(),
                guest: "/models/model.gguf".into(),
                grant: Grant::Ro,
            },
            Source {
                path: spec.socket_dir.clone(),
                guest: "/run/sallyport".into(),
                grant: Grant::Rw,
            },
        ],
        scratch: None,
        ..allowed.clone()
    };
    check_argv(&inf, &ia).unwrap();
    let cmd_at = inf.iter().position(|x| x == "llama-server").unwrap();
    let mutated: Vec<Vec<String>> = vec![
        [inf.clone(), vec!["--path".into(), "/".into()]].concat(),
        [inf.clone(), vec!["--lora".into(), "/x".into()]].concat(),
        inf.iter().filter(|x| *x != "--no-webui").cloned().collect(),
        // `-m` pointing elsewhere (the bind destination stays /models/model.gguf).
        inf.iter()
            .enumerate()
            .map(|(k, x)| {
                if k > cmd_at && x == "/models/model.gguf" {
                    "/models/other.gguf".into()
                } else {
                    x.clone()
                }
            })
            .collect(),
        inf.iter()
            .map(|x| if x == "99" { "-1".into() } else { x.clone() })
            .collect(),
    ];
    for m in &mutated {
        assert_forbidden(m, &ia, &format!("{:?}", &m[cmd_at..]));
    }
    // Optional options are still single: a second GPU device or memory limit is refused.
    assert_forbidden(
        &with(&inf, &["--device", "nvidia.com/gpu=all"]),
        &ia,
        "device twice",
    );
    assert_forbidden(
        &with(&with(&inf, &["--memory", "1b"]), &["--memory", "2b"]),
        &ia,
        "memory twice",
    );
    // The GPU device: inference only, exact value.
    assert_forbidden(
        &replacing(&inf, "nvidia.com/gpu=all", &["nvidia.com/gpu=all:/dev/mem"]),
        &ia,
        "device with a path",
    );
}

#[test]
fn checker_refuses_relative_or_empty_policy_paths() {
    let f = Fx::new();
    let (a, allowed) = base(&f);
    for bad in [
        PathBuf::new(),
        PathBuf::from("rel"),
        PathBuf::from("/a/../b"),
    ] {
        let mut p = allowed.clone();
        p.sources.push(Source {
            path: bad.clone(),
            guest: "/workspace/z".into(),
            grant: Grant::Rw,
        });
        assert_forbidden(&a, &p, &format!("{bad:?}"));
    }
}

// ---- every manifest mount mix (exhaustive) and random extra options (property) -------------

#[test]
fn every_mount_mix_builds_and_passes_the_checker() {
    let f = Fx::new();
    let hosts = ["~/code/myproject", "~/code/other", "~/Documents/research"];
    let modes = ["ro", "rw", "brokered", "staged"];
    let mut mixes: Vec<Vec<&str>> = vec![Vec::new()];
    for len in 1..=3 {
        let mut next = Vec::new();
        for mix in mixes.iter().filter(|m| m.len() == len - 1) {
            for m in modes {
                next.push([mix.clone(), vec![m]].concat());
            }
        }
        mixes.extend(next);
    }
    assert_eq!(mixes.len(), 1 + 4 + 16 + 64);
    for mix in &mixes {
        for proxy in [false, true] {
            let list: Vec<String> = mix
                .iter()
                .enumerate()
                .map(|(i, m)| mount(hosts[i], &format!("/workspace/m{i}"), m))
                .collect();
            let body = if list.is_empty() {
                String::new()
            } else {
                mounts(&list)
            };
            let body = if proxy {
                format!("{body}{PROXY}")
            } else {
                body
            };
            let v = f.load(&body);
            let scans: Vec<GitScan> = mix
                .iter()
                .enumerate()
                .filter(|(_, m)| **m == "rw")
                .map(|(i, _)| scan(i, &[".git"], &["s/.git"]))
                .collect();
            let a = workspace_argv(&f.common, &f.paths, &v, &scans, &ws_image()).unwrap();
            // mounts + per rw scan (overlay, parent self-bind, pointer file) + sockets
            assert_eq!(
                a.iter().filter(|x| *x == "-v").count(),
                mix.len() + scans.len() * 3 + 1
            );
            let has_proxy = a.iter().any(|x| x == "HTTP_PROXY=http://127.0.0.1:3128");
            assert_eq!(has_proxy, proxy, "{mix:?}");
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// No option podman might accept slips through: any extra `--name[=value]` is refused.
    #[test]
    fn any_extra_option_is_refused(
        name in "[a-z][a-z-]{0,15}",
        value in proptest::option::of("[ -~]{0,24}"),
        at in 0usize..40,
    ) {
        prop_assume!(name != "env" && name != "security-opt");
        let f = Fx::new();
        let (a, allowed) = base(&f);
        let image_at = a.iter().position(|x| x.starts_with("ghcr.io/")).unwrap();
        let tok = match &value { Some(v) => format!("--{name}={v}"), None => format!("--{name}") };
        // Insert at an option boundary (never between an option and its separate value).
        let bounds: Vec<usize> = (3..=image_at)
            .filter(|&i| a[i].starts_with('-') || i == image_at)
            .collect();
        let i = bounds[at % bounds.len()];
        let mut b = a[..i].to_vec();
        b.push(tok.clone());
        b.extend_from_slice(&a[i..]);
        prop_assert!(check_argv(&b, &allowed).is_err(), "{tok} accepted");
    }
}
