//! RT-SUP-04 and the OCI config verifier on real containers (Task 14, #15; architect Q111,
//! Q113, Q114): the config Podman 4.9.3 generates for each in-scope role passes, a config
//! altered after `podman init` is refused before `start`, and hostile podman configuration in
//! every location podman consults never reaches a container.
//!
//! The fixture is `common::container`; these tests never skip.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use sally_core::manifest::Cpus;
use sallyd::sandbox::oci::intent::Built;
use sallyd::sandbox::{
    ImageRef, InferenceSpec, LaunchError, ScanLimits, SessionDirs, SessionId, VerifiedModel,
    harness_build, inference_build, scan_mounts, workspace_build,
};

mod common;
use common::container::*;
use common::*;

/// The test paths go into shell scripts, TOML and JSON unescaped, and the argv log is split on
/// spaces: none may hold a quote, a backslash or a space.
fn assert_plain(p: &str) {
    assert!(
        !p.contains(['\'', '"', '\\', ' ']),
        "the test writes {p:?} into scripts and configs unescaped"
    );
}

fn scratch(tag: &str) -> (PathBuf, RemoveOnDrop) {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("oci-{tag}-{}", std::process::id()));
    assert_plain(&dir.display().to_string());
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    (dir.clone(), RemoveOnDrop(dir))
}

/// The config file of `id`, as the user sees it (the userdata directory is the subordinate
/// root's: edits go through `podman unshare`).
fn config_path(id: &str) -> String {
    let out = podman(&["inspect", "--format", "{{.OCIConfigPath}}", id]);
    assert!(out.status.success());
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

/// Rewrites the config of `id` with `sed -e expr`; panics unless it changed.
fn tamper(id: &str, expr: &str) {
    let path = config_path(id);
    let before = podman(&["unshare", "cat", &path]).stdout;
    assert!(
        podman(&["unshare", "sed", "-i", "-e", expr, &path])
            .status
            .success()
    );
    assert_ne!(podman(&["unshare", "cat", &path]).stdout, before, "{expr}");
}

fn mismatch_field(r: Result<(), LaunchError>) -> String {
    match r {
        Err(LaunchError::ConfigMismatch(m)) => m.field,
        other => panic!("{other:?}"),
    }
}

/// Creates and initialises `argv` with hermetic podman, `init` as the launcher runs it
/// (`Podman::spec_args`); the container id.
async fn create_and_init(x: &Lx, argv: Vec<String>) -> String {
    let out = x.hermetic(&argv).await;
    let id = out.lines().last().unwrap().to_owned();
    let init: Vec<String> = x
        .podman
        .spec_args("init", &id)
        .iter()
        .map(|a| a.to_str().unwrap().to_owned())
        .collect();
    x.hermetic(&init).await;
    id
}

/// Harness: the real config passes; with a capability added after `init` it is refused.
#[test]
fn rt_sup_04_the_harness_config_passes_and_a_tampered_one_is_refused() {
    rt().block_on(async {
        let x = Lx::new();
        let v = x.f.load("");
        let paths = x.paths("h-oci");
        let dirs = SessionDirs::create(&paths, &x.xdg, &[], 0).unwrap();
        let built = harness_build(&x.common_args(&dirs), &paths, &v, &test_image()).unwrap();
        let id = create_and_init(&x, built.argv).await;
        x.launcher.verify_config(&id, &built.intent).await.unwrap();
        tamper(
            &id,
            r#"s/"capabilities":{}/"capabilities":{"bounding":["CAP_NET_RAW"]}/"#,
        );
        assert_eq!(
            mismatch_field(x.launcher.verify_config(&id, &built.intent).await),
            "process.capabilities.bounding"
        );
        let _ = podman(&["rm", "--force", &id]);
    });
}

/// CPU inference: the real config passes (no hostname, no memory limit); `no_new_privs`
/// dropped is refused, and so is a GPU intent.
#[test]
fn rt_sup_04_the_cpu_inference_config_passes_and_a_tampered_one_is_refused() {
    rt().block_on(async {
        let x = Lx::new();
        let (dir, _cleanup) = scratch("infer");
        let paths = x.paths("i-oci");
        let dirs = SessionDirs::create(&paths, &x.xdg, &[], 0).unwrap();
        let digest = "a".repeat(64);
        let blob = dir.join("blobs/sha256").join(&digest);
        std::fs::create_dir_all(blob.parent().unwrap()).unwrap();
        std::fs::write(&blob, b"GGUF").unwrap();
        std::fs::set_permissions(&blob, std::fs::Permissions::from_mode(0o444)).unwrap();
        let socket_dir = dir.join("sock");
        std::fs::create_dir_all(&socket_dir).unwrap();
        let spec = InferenceSpec {
            instance: SessionId::parse(&format!("{}-i", x.scope)).unwrap(),
            socket_dir,
            model: VerifiedModel::pin(&dir.join("blobs"), &digest).unwrap(),
            image: test_image(),
            gpu: false,
            gpu_layers: 0,
            context: 512,
            cpus: Cpus::from_millis(1000),
            memory: None,
        };
        let built = inference_build(&x.common_args(&dirs), &spec).unwrap();
        let id = create_and_init(&x, built.argv.clone()).await;
        x.launcher.verify_config(&id, &built.intent).await.unwrap();
        tamper(&id, r#"s/"noNewPrivileges":true/"noNewPrivileges":false/"#);
        assert_eq!(
            mismatch_field(x.launcher.verify_config(&id, &built.intent).await),
            "process.noNewPrivileges"
        );
        // The same name is created again next.
        assert!(podman(&["rm", "--force", &id]).status.success());
        // A GPU intent is refused before the config is compared (M3, #116).
        let mut gpu = built.intent;
        gpu.gpu = true;
        let id = create_and_init(&x, built.argv).await;
        assert_eq!(
            mismatch_field(x.launcher.verify_config(&id, &gpu).await),
            "linux.devices"
        );
        let _ = podman(&["rm", "--force", &id]);
    });
}

/// A podman wrapper that appends its whole argv (`$*`) to `<at>/argv` and its `$HOME` to
/// `<at>/home` (one line each per call), runs the real podman, then runs `after` (shell, with
/// `$rc`, `$v` the verb and `$id` the word after it) and exits with podman's status. The verb is
/// the first word after the global `--flag value` pairs.
fn wrapper(at: &Path, real: &Path, after: &str) -> PathBuf {
    wrap_podman(at, real, |dir, real| {
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >>'{dir}/argv'\nprintf '%s\\n' \"$HOME\" >>'{dir}/home'\n\
             '{real}' \"$@\"\nrc=$?\n\
             v=; id=; skip=\nfor a; do\n\
             if [ -n \"$skip\" ]; then skip=; continue; fi\n\
             case \"$a\" in --*) [ -z \"$v\" ] && skip=1 ;; \
             *) if [ -z \"$v\" ]; then v=$a; elif [ -z \"$id\" ]; then id=$a; fi ;; esac\n\
             done\n{after}\nexit $rc\n"
        )
    })
}

/// The verb of one `argv` line [`wrapper`] logged.
fn verb_of(line: &str) -> &str {
    let mut words = line.split(' ');
    while let Some(w) = words.next() {
        if !w.starts_with("--") {
            return w;
        }
        words.next();
    }
    ""
}

/// [`wrapper`] that, after a successful `init` of a container whose name starts with `prefix`,
/// adds a capability to the config podman generated: the window between create and start
/// (architect Q114; Q132: the harness case alters only the harness).
fn altering_podman(at: &Path, real: &Path, prefix: &str) -> PathBuf {
    let r = real.display();
    wrapper(
        at,
        real,
        &format!(
            "if [ $rc -eq 0 ] && [ \"$v\" = init ]; then\n\
             name=$('{r}' inspect --format '{{{{.Name}}}}' \"$id\")\n\
             case \"$name\" in {prefix}*)\n\
             cfg=$('{r}' inspect --format '{{{{.OCIConfigPath}}}}' \"$id\")\n\
             '{r}' unshare sed -i -e 's/\"capabilities\":{{}}/\"capabilities\":{{\"bounding\":[\"CAP_SYS_ADMIN\"]}}/' \"$cfg\" ;;\n\
             esac\n\
             fi"
        ),
    )
}

/// Q132, one helper for every role: the podman calls logged from line `from` on (one launch of
/// `container`) all ran with the private `HOME`; the mount-link probe was created and inited
/// once (its `init` with exactly the empty mounts file), never started, and removed before the
/// real `create`; the container had exactly one `create`, one `init` and one `start`; its `init`
/// and `start` carried exactly the empty mounts file; and the verifier read the config between
/// them.
fn assert_one_start_path(x: &Lx, dir: &Path, from: usize, container: &str) {
    let argv = std::fs::read_to_string(dir.join("argv")).unwrap();
    let homes = std::fs::read_to_string(dir.join("home")).unwrap();
    let lines: Vec<&str> = argv.lines().skip(from).collect();
    let homes: Vec<&str> = homes.lines().skip(from).collect();
    assert_eq!(lines.len(), homes.len(), "{argv}");
    // The fixture's state directory (`Lx::build`): the private HOME is `<state>/podman/home`.
    let home = x.f.root.join("home/.local/share/sallyport/podman/home");
    for (line, h) in lines.iter().zip(&homes) {
        assert_eq!(Path::new(h), home, "{line}");
    }
    let file = x.podman.mounts_file();
    // The mount-link probe ran first: one `create` and one `init` with the empty mounts file,
    // never started, and removed before the real `create`.
    let probe: Vec<&str> = lines.iter().copied().filter(|l| is_probe(l)).collect();
    let name = probe
        .iter()
        .find(|l| verb_of(l) == "init")
        .and_then(|l| l.rsplit(' ').next())
        .unwrap_or_else(|| panic!("no probe init: {argv}"));
    assert!(name.starts_with("sp-probe-"), "{argv}");
    for (verb, n) in [("create", 1), ("init", 1), ("start", 0)] {
        let got = probe.iter().filter(|l| verb_of(l) == verb).count();
        assert_eq!(got, n, "probe {verb}: {argv}");
    }
    assert!(
        probe.contains(&format!("--default-mounts-file {} init {name}", file.display()).as_str()),
        "{argv}"
    );
    let removed = lines
        .iter()
        .rposition(|l| verb_of(l) == "rm" && is_probe(l))
        .unwrap_or_else(|| panic!("the probe was not removed: {argv}"));
    let lines: Vec<&str> = lines.iter().copied().filter(|l| !is_probe(l)).collect();
    let real_create = argv
        .lines()
        .skip(from)
        .position(|l| verb_of(l) == "create" && !is_probe(l))
        .unwrap();
    assert!(removed < real_create, "{argv}");
    for verb in ["create", "init", "start"] {
        let n = lines.iter().filter(|l| verb_of(l) == verb).count();
        assert_eq!(n, 1, "{verb}: {argv}");
    }
    for verb in ["init", "start"] {
        let line = lines.iter().find(|l| verb_of(l) == verb).unwrap();
        assert_eq!(
            *line,
            format!(
                "--default-mounts-file {} {verb} {container}",
                file.display()
            ),
            "{argv}"
        );
    }
    let at = |verb: &str| lines.iter().position(|l| verb_of(l) == verb).unwrap();
    let read = lines
        .iter()
        .position(|l| l.starts_with("unshare cat -- ") && l.ends_with("/config.json"))
        .unwrap_or_else(|| panic!("no config read: {argv}"));
    assert!(at("init") < read && read < at("start"), "{argv}");
}

/// The start-path tests' control, in-test (before their assertion): [`assert_one_start_path`]
/// over copies of the same launch's log, each with one defence taken out, fails: the config
/// read removed, `init` without the mounts file, the last call under another `HOME`.
fn the_check_fails_without_each_defence(x: &Lx, dir: &Path, from: usize, container: &str) {
    let argv = std::fs::read_to_string(dir.join("argv")).unwrap();
    let homes = std::fs::read_to_string(dir.join("home")).unwrap();
    let calls: Vec<(String, String)> = argv
        .lines()
        .zip(homes.lines())
        .map(|(a, h)| (a.to_owned(), h.to_owned()))
        .collect();
    let init = format!(
        "--default-mounts-file {} init {container}",
        x.podman.mounts_file().display()
    );
    let no_read: Vec<_> = calls
        .iter()
        .filter(|(a, _)| !(a.starts_with("unshare cat -- ") && a.ends_with("/config.json")))
        .cloned()
        .collect();
    let plain_init: Vec<_> = calls
        .iter()
        .map(|(a, h)| {
            let a = if *a == init {
                format!("init {container}")
            } else {
                a.clone()
            };
            (a, h.clone())
        })
        .collect();
    let mut other_home = calls.clone();
    if let Some(last) = other_home.last_mut() {
        last.1 = "/elsewhere".to_owned();
    }
    for (what, log) in [
        ("no config read", no_read),
        ("plain init", plain_init),
        ("another HOME", other_home),
    ] {
        assert_ne!(log, calls, "control: {what} changed nothing");
        let copy = dir.join(format!("control-{}", what.replace(' ', "-")));
        std::fs::create_dir_all(&copy).unwrap();
        let lines = |f: fn(&(String, String)) -> &String| {
            log.iter()
                .map(|c| format!("{}\n", f(c)))
                .collect::<String>()
        };
        std::fs::write(copy.join("argv"), lines(|c| &c.0)).unwrap();
        std::fs::write(copy.join("home"), lines(|c| &c.1)).unwrap();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_one_start_path(x, &copy, from, container);
        }));
        assert!(r.is_err(), "control: the check passes with {what}");
    }
}

/// A logged call of the mount-link probe (it names `sp-probe-…`).
fn is_probe(line: &str) -> bool {
    line.contains(" sp-probe-")
}

/// How many podman calls the wrapper in `dir` logged so far.
fn logged(dir: &Path) -> usize {
    std::fs::read_to_string(dir.join("argv"))
        .map(|a| a.lines().count())
        .unwrap_or(0)
}

/// RT-SUP-04, #123: the workspace launch runs the one start path.
#[test]
fn rt_sup_04_the_workspace_launch_runs_the_one_start_path() {
    let (dir, _cleanup) = scratch("ws-path");
    rt().block_on(async {
        let x = Lx::with_podman(|real| wrapper(&dir, real, ""));
        let v = x.f.load("");
        let r = x.launch(&v, "ws-path").await.unwrap();
        the_check_fails_without_each_defence(&x, &dir, 0, r.container());
        assert_one_start_path(&x, &dir, 0, r.container());
        x.stop(r).await;
    });
}

/// RT-SUP-04, #123: the harness launch, into the live session, runs the one start path.
#[test]
fn rt_sup_04_the_harness_launch_runs_the_one_start_path() {
    let (dir, _cleanup) = scratch("h-path");
    rt().block_on(async {
        let x = Lx::with_podman(|real| wrapper(&dir, real, ""));
        let v = x.f.load("");
        let ws = x.launch(&v, "h-path").await.unwrap();
        let from = logged(&dir);
        let h = x
            .launcher
            .launch_harness(x.harness(&v, "h-path"))
            .await
            .unwrap();
        assert_eq!(h.name(), format!("sp-h-{}", ws.paths().id().as_str()));
        the_check_fails_without_each_defence(&x, &dir, from, h.container());
        assert_one_start_path(&x, &dir, from, h.container());
        x.launcher.stop_role(h).await.unwrap();
        x.stop(ws).await;
    });
}

/// RT-SUP-04, #123: the CPU inference launch runs the one start path.
#[test]
fn rt_sup_04_the_cpu_inference_launch_runs_the_one_start_path() {
    let (dir, _cleanup) = scratch("i-path");
    rt().block_on(async {
        let x = Lx::with_podman(|real| wrapper(&dir, real, ""));
        let i = x
            .launcher
            .launch_inference(x.inference(x.model(), "i-path"))
            .await
            .unwrap();
        assert!(i.name().starts_with("sp-infer-"), "{}", i.name());
        the_check_fails_without_each_defence(&x, &dir, 0, i.container());
        assert_one_start_path(&x, &dir, 0, i.container());
        x.launcher.stop_role(i).await.unwrap();
    });
}

/// Where the image-metadata image's health check leaves its marker.
const MARKER: &str = "/tmp/sp-health-marker";

/// The test image, in Docker format, declaring a health check that makes [`MARKER`] every second
/// and one volume at a path no mount uses.
fn metadata_image() -> ImageRef {
    docker_image_with(&format!(
        "HEALTHCHECK --interval=1s --timeout=5s CMD touch {MARKER}\nVOLUME /sp-image-volume\n"
    ))
}

/// `podman inspect` of `id` with the Go template `format`, trimmed.
fn inspect(id: &str, format: &str) -> String {
    let out = podman(&["inspect", "--format", format, id]);
    assert!(
        out.status.success(),
        "inspect: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// The health check podman recorded for container `id`, as JSON.
fn health_of(id: &str) -> String {
    inspect(id, "{{json .Config.Healthcheck}}")
}

/// The names of the volumes mounted in container `id`.
fn volumes_of(id: &str) -> Vec<String> {
    let t = "{{range .Mounts}}{{if eq .Type \"volume\"}}{{.Name}} {{end}}{{end}}";
    inspect(id, t)
        .split_whitespace()
        .map(str::to_owned)
        .collect()
}

fn volume_exists(name: &str) -> bool {
    podman(&["volume", "exists", name]).status.success()
}

/// Whether a unit of the user's service manager has a name that starts with container `id`. A
/// failed listing panics, so it never reads as "none".
fn a_unit_is_named_after(id: &str) -> bool {
    let out = std::process::Command::new("systemctl")
        .args(["--user", "list-units", "--all", "--no-legend", "--plain"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "systemctl --user: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .any(|l| l.starts_with(id))
}

/// How long it took [`MARKER`] to appear in container `id`, polled until `limit`; `None` if it
/// did not.
async fn marker_within(id: &str, limit: Duration) -> Option<Duration> {
    let begun = Instant::now();
    while begun.elapsed() < limit {
        if exec_in(id, &["test", "-e", MARKER]).0 == 0 {
            return Some(begun.elapsed());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    None
}

/// Whether hermetic `podman healthcheck run` on `id` succeeded.
async fn health_run(x: &Lx, id: &str) -> bool {
    let out = x
        .podman
        .command()
        .args(["healthcheck", "run", id])
        .output()
        .await
        .unwrap();
    out.status.success()
}

/// The longest the controls wait for the image's health check to act on its own.
const CONTROL_LIMIT: Duration = Duration::from_secs(30);

/// The controls of the image-metadata rows, from the product-built `built` of one role from
/// [`metadata_image`]; how long the image's health check took to act on its own.
///
/// Health checks: the argv without `--no-healthcheck` gives a container that carries the image's
/// health check, which the verifier refuses on `healthcheck`; started, the check runs by itself
/// (the marker appears, and a unit is named after the container). Volumes: the argv without
/// `--image-volume=ignore` gives a container with the image's volume. Nothing of either control
/// is left behind.
async fn metadata_controls(x: &Lx, built: &Built) -> Duration {
    let declared = podman(&[
        "image",
        "inspect",
        "--format",
        "{{json .Config.Healthcheck}}",
        metadata_image().as_str(),
    ]);
    assert!(
        String::from_utf8_lossy(&declared.stdout).contains(MARKER),
        "the fixture image declares its health check"
    );
    let argv = x.left_out(built.argv.clone(), LeaveOut::Healthcheck);
    let id = create_and_init(x, argv).await;
    assert!(
        health_of(&id).contains(MARKER),
        "control: {}",
        health_of(&id)
    );
    assert_eq!(
        mismatch_field(x.launcher.verify_config(&id, &built.intent).await),
        "healthcheck"
    );
    x.hermetic(&["start".to_owned(), id.clone()]).await;
    let took = marker_within(&id, CONTROL_LIMIT)
        .await
        .expect("control: the image's health check made its marker by itself");
    assert!(
        a_unit_is_named_after(&id),
        "control: a unit is named after the container"
    );
    assert!(health_run(x, &id).await, "control: the health check runs");
    assert!(
        podman(&["rm", "--force", "--volumes", "--time", "0", &id])
            .status
            .success()
    );
    let begun = Instant::now();
    while a_unit_is_named_after(&id) && begun.elapsed() < CONTROL_LIMIT {
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(
        !a_unit_is_named_after(&id),
        "control: removed, no unit is named after it"
    );

    let argv = x.left_out(built.argv.clone(), LeaveOut::ImageVolume);
    let id = x.hermetic(&argv).await.lines().last().unwrap().to_owned();
    let made = volumes_of(&id);
    assert_eq!(made.len(), 1, "control: the image's volume is made");
    assert!(volume_exists(&made[0]));
    assert!(
        podman(&["rm", "--force", "--volumes", "--time", "0", &id])
            .status
            .success()
    );
    assert!(
        !volume_exists(&made[0]),
        "control: removed with its container"
    );
    took
}

/// Container `id`, launched from [`metadata_image`], carries no health check and no image
/// volume: podman records the disabled form, the marker never appears in twice the time the
/// control's check took (and a second more), no unit is named after the container, and a health
/// check run fails.
async fn assert_metadata_off(x: &Lx, id: &str, took: Duration) {
    assert_eq!(health_of(id), r#"{"Test":["NONE"]}"#);
    assert!(volumes_of(id).is_empty(), "{:?}", volumes_of(id));
    let wait = took * 2 + Duration::from_secs(1);
    assert_eq!(marker_within(id, wait).await, None, "the marker appeared");
    assert!(
        !a_unit_is_named_after(id),
        "a unit is named after the container"
    );
    assert!(!health_run(x, id).await, "a health check ran");
    assert_eq!(
        exec_in(id, &["test", "-e", MARKER]).0,
        1,
        "the marker appeared"
    );
}

/// Security review: a workspace launched from an image that declares a health check and a
/// volume carries neither. Controls first ([`metadata_controls`]).
#[test]
fn rt_sup_05_the_workspace_image_health_check_and_volume_are_off() {
    rt().block_on(async {
        let x = Lx::new();
        let v = x.f.load("");
        let image = metadata_image();
        let paths = x.paths("md-ws-c");
        let dirs = SessionDirs::create(&paths, &x.xdg, &[], 0).unwrap();
        let scan = scan_mounts(&v, &ScanLimits::default()).unwrap();
        let built = workspace_build(&x.common_args(&dirs), &paths, &v, &scan, Some(&image));
        let took = metadata_controls(&x, &built.unwrap()).await;
        let mut req = x.request(&v, "md-ws");
        req.default_image = Some(image);
        let r = x.launcher.launch_workspace(req).await.unwrap();
        assert_metadata_off(&x, r.container(), took).await;
        x.stop(r).await;
    });
}

/// Security review: as the workspace row, for the harness.
#[test]
fn rt_sup_05_the_harness_image_health_check_and_volume_are_off() {
    rt().block_on(async {
        let x = Lx::new();
        let v = x.f.load("");
        let image = metadata_image();
        let paths = x.paths("md-h-c");
        let dirs = SessionDirs::create(&paths, &x.xdg, &[], 0).unwrap();
        let built = harness_build(&x.common_args(&dirs), &paths, &v, &image).unwrap();
        let took = metadata_controls(&x, &built).await;
        let ws = x.launch(&v, "md-h").await.unwrap();
        let mut req = x.harness(&v, "md-h");
        req.default_image = Some(image);
        let h = x.launcher.launch_harness(req).await.unwrap();
        assert_metadata_off(&x, h.container(), took).await;
        x.launcher.stop_role(h).await.unwrap();
        x.stop(ws).await;
    });
}

/// Security review: as the workspace row, for CPU inference.
#[test]
fn rt_sup_05_the_inference_image_health_check_and_volume_are_off() {
    let (dir, _cleanup) = scratch("md-infer");
    rt().block_on(async {
        let x = Lx::new();
        let image = metadata_image();
        let paths = x.paths("md-i-c");
        let dirs = SessionDirs::create(&paths, &x.xdg, &[], 0).unwrap();
        let socket_dir = dir.join("sock");
        std::fs::create_dir_all(&socket_dir).unwrap();
        let spec = InferenceSpec {
            instance: SessionId::parse(&format!("{}-md-i-c", x.scope)).unwrap(),
            socket_dir,
            model: x.model(),
            image: image.clone(),
            gpu: false,
            gpu_layers: 0,
            context: 512,
            cpus: Cpus::from_millis(1000),
            memory: None,
        };
        let built = inference_build(&x.common_args(&dirs), &spec).unwrap();
        let took = metadata_controls(&x, &built).await;
        let mut req = x.inference(x.model(), "md-i");
        req.image = image;
        let i = x.launcher.launch_inference(req).await.unwrap();
        assert_metadata_off(&x, i.container(), took).await;
        x.launcher.stop_role(i).await.unwrap();
    });
}

/// RT-SUP-04, #123, Q132 phase 2: a harness whose config is altered between `init` and
/// `start` is refused `config-mismatch` and never started; the workspace beside it was not
/// altered and still runs.
#[test]
fn rt_sup_04_a_harness_config_altered_between_create_and_start_is_refused() {
    let (dir, _cleanup) = scratch("h-altered");
    rt().block_on(async {
        let x = Lx::with_podman(|real| altering_podman(&dir, real, "sp-h-"));
        let v = x.f.load("");
        let ws = x.launch(&v, "h-altered").await.unwrap();
        let from = logged(&dir);
        let e = x
            .launcher
            .launch_harness(x.harness(&v, "h-altered"))
            .await
            .unwrap_err();
        assert!(matches!(&e, LaunchError::ConfigMismatch(_)), "{e:?}");
        let args = x.events.args("sandbox.config_mismatch").unwrap();
        assert_eq!(args["role"], "harness");
        assert_eq!(args["reason"], "config-mismatch");
        assert!(
            args["detail"]
                .as_str()
                .unwrap()
                .contains("process.capabilities"),
            "{args}"
        );
        let sid = ws.paths().id().as_str().to_owned();
        assert!(!exists(&format!("sp-h-{sid}")));
        let argv = std::fs::read_to_string(dir.join("argv")).unwrap();
        let after: Vec<&str> = argv.lines().skip(from).collect();
        assert!(
            after.iter().any(|l| verb_of(l) == "init" && !is_probe(l)),
            "{argv}"
        );
        assert!(!after.iter().any(|l| verb_of(l) == "start"), "{argv}");
        let (_, caps) = exec(&ws, "grep CapEff /proc/self/status").await;
        assert!(caps.contains("CapEff:\t0000000000000000"), "{caps}");
        assert!(exists(ws.name()), "the workspace still runs");
        x.stop(ws).await;
    });
}

/// RT-SUP-04, #123, Q132 phase 2: an inference config altered between `init` and `start` is
/// refused `config-mismatch`, never started, and the instance's directories are gone.
#[test]
fn rt_sup_04_an_inference_config_altered_between_create_and_start_is_refused() {
    let (dir, _cleanup) = scratch("i-altered");
    rt().block_on(async {
        let x = Lx::with_podman(|real| altering_podman(&dir, real, "sp-infer-"));
        let req = x.inference(x.model(), "i-altered");
        let name = format!("sp-infer-{}", req.instance.as_str());
        let e = x.launcher.launch_inference(req).await.unwrap_err();
        assert!(matches!(&e, LaunchError::ConfigMismatch(_)), "{e:?}");
        let args = x.events.args("sandbox.config_mismatch").unwrap();
        assert_eq!(args["role"], "inference");
        assert!(
            args["instance"].as_str().unwrap().ends_with("-i-altered"),
            "{args}"
        );
        assert!(!exists(&name));
        let argv = std::fs::read_to_string(dir.join("argv")).unwrap();
        assert!(
            argv.lines().any(|l| verb_of(l) == "init" && !is_probe(l)),
            "{argv}"
        );
        assert!(!argv.lines().any(|l| verb_of(l) == "start"), "{argv}");
        let p = x.instance_paths("i-altered");
        assert!(!p.socket_dir().exists() && !p.data_dir().exists());
    });
}

#[test]
fn rt_sup_04_a_config_altered_between_create_and_start_is_refused() {
    let (dir, _cleanup) = scratch("altered");
    rt().block_on(async {
        let x = Lx::with_podman(|real| altering_podman(&dir, real, "sp-"));
        let v =
            x.f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", "ro")]));
        let paths = x.paths("altered");
        let e = x.launch(&v, "altered").await.unwrap_err();
        assert!(matches!(&e, LaunchError::ConfigMismatch(_)), "{e:?}");
        assert_eq!(
            x.events.list().last().map(String::as_str),
            Some("sandbox.config_mismatch")
        );
        let args = x.events.args("sandbox.config_mismatch").unwrap();
        assert_eq!(args["reason"], "config-mismatch");
        let detail = args["detail"].as_str().unwrap();
        assert!(detail.contains("process.capabilities"), "{detail}");
        assert!(
            !detail.contains("ociVersion") && !detail.contains("CAP_SYS_ADMIN"),
            "{detail}"
        );
        assert!(!exists(&format!("sp-ws-{}", paths.id().as_str())));
        let argv = std::fs::read_to_string(dir.join("argv")).unwrap();
        assert!(
            argv.lines().any(|l| verb_of(l) == "init" && !is_probe(l)),
            "{argv}"
        );
        assert!(!argv.lines().any(|l| verb_of(l) == "start"), "{argv}");
    });
}

/// A podman wrapper that drops `--image-volume=ignore` from every call (so the image's volumes
/// are made) and, when `keep_volumes`, `--volumes` too (so `rm` leaves them). Before each `rm`
/// it appends the names of the removed container's volumes to `<at>/volumes`.
fn volume_podman(at: &Path, real: &Path, keep_volumes: bool) -> PathBuf {
    let drop = if keep_volumes { "--volumes) ;;" } else { "" };
    wrap_podman(at, real, |dir, real| {
        "#!/bin/sh\nn=$#\nv=; skip=; last=\nfor a; do\n\
         if [ -z \"$v\" ]; then\n\
         if [ -n \"$skip\" ]; then skip=; else case \"$a\" in --*) skip=1 ;; *) v=$a ;; esac; fi\n\
         fi\nlast=$a\n\
         case \"$a\" in --image-volume=ignore) ;; DROP *) set -- \"$@\" \"$a\" ;; esac\n\
         done\nshift $n\n\
         if [ \"$v\" = rm ]; then\n\
         'REAL' inspect --format '{{range .Mounts}}{{if eq .Type \"volume\"}}{{.Name}} \
         {{end}}{{end}}' \"$last\" >>'DIR/volumes' 2>/dev/null\nfi\n\
         exec 'REAL' \"$@\"\n"
            .replace("DROP", drop)
            .replace("REAL", real)
            .replace("DIR", dir)
    })
}

/// The volume names [`volume_podman`] in `dir` recorded.
fn recorded_volumes(dir: &Path) -> Vec<String> {
    std::fs::read_to_string(dir.join("volumes"))
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_owned)
        .collect()
}

/// One workspace launch of an image declaring a volume, through [`volume_podman`] in `dir`:
/// the launch is refused; the volumes of the containers it removed.
async fn refused_with_image_volume(dir: &Path, keep_volumes: bool) -> Vec<String> {
    let x = Lx::with_podman(|real| volume_podman(dir, real, keep_volumes));
    let v = x.f.load("");
    let mut req = x.request(&v, "vol");
    req.default_image = Some(image_with("VOLUME /sp-image-volume\n"));
    let e = x.launcher.launch_workspace(req).await.unwrap_err();
    assert!(matches!(&e, LaunchError::ConfigMismatch(_)), "{e:?}");
    let made = recorded_volumes(dir);
    assert!(!made.is_empty(), "the image's volume was made");
    made
}

/// Security review: removing a container also removes its anonymous volumes. A workspace
/// launch whose podman calls make the image's volume (the argv's `--image-volume=ignore`
/// dropped) is refused, and the containers it removed leave no volume behind. Control, first:
/// with `--volumes` also dropped from `rm`, the volumes stay.
#[test]
fn rt_sup_05_a_removed_container_leaves_no_image_volume() {
    let (control, _c) = scratch("vol-control");
    let (dir, _d) = scratch("vol");
    rt().block_on(async {
        let kept = refused_with_image_volume(&control, true).await;
        for name in &kept {
            assert!(volume_exists(name), "control: {name} stays");
            assert!(podman(&["volume", "rm", name]).status.success());
        }
        let made = refused_with_image_volume(&dir, false).await;
        let stayed: Vec<&String> = made.iter().filter(|n| volume_exists(n)).collect();
        for name in &stayed {
            let _ = podman(&["volume", "rm", name]);
        }
        assert!(stayed.is_empty(), "stayed behind: {stayed:?}");
    });
}

/// Every location podman consults for configuration, under a test `HOME` given to hermetic
/// podman (architect Q113: never the maintainer's real directory, which the other lane's and
/// the user's own podman read too). Returns the paths a leak would show.
struct Hostile {
    home: PathBuf,
    /// A host file a hook would create.
    hook_canary: PathBuf,
    _cleanup: RemoveOnDrop,
}

/// One `HOME` per call: the tests of this binary run in parallel in one process.
static HOMES: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

fn hostile_home() -> Hostile {
    let home = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "hostile-home-{}-{}",
        std::process::id(),
        HOMES.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    assert_plain(&home.display().to_string());
    let _ = std::fs::remove_dir_all(&home);
    let conf = home.join(".config/containers");
    std::fs::create_dir_all(conf.join("oci/hooks.d")).unwrap();
    std::fs::create_dir_all(conf.join("containers.conf.d")).unwrap();
    let leak = home.join("leak");
    std::fs::create_dir_all(&leak).unwrap();
    std::fs::write(leak.join("canary"), "HOSTILE").unwrap();
    let leak = leak.display();
    let hook_canary = home.join("hook-ran");
    let hooks = conf.join("oci/hooks.d");
    std::fs::write(
        conf.join("containers.conf"),
        format!(
            "[containers]\nvolumes = [\"{leak}:/hostile:rw\"]\n\
             default_capabilities = [\"SYS_ADMIN\", \"NET_RAW\"]\nenv = [\"HOSTILE=1\"]\n\
             netns = \"host\"\nannotations = [\"hostile=1\"]\n\
             default_ulimits = [\"nofile=1:1\"]\n[engine]\nhooks_dir = [\"{}\"]\n",
            hooks.display()
        ),
    )
    .unwrap();
    std::fs::write(
        conf.join("containers.conf.d/99-hostile.conf"),
        format!("[containers]\nvolumes = [\"{leak}:/hostile2:rw\"]\nenv = [\"HOSTILE2=1\"]\n"),
    )
    .unwrap();
    std::fs::write(
        conf.join("mounts.conf"),
        format!("{leak}:/run/secrets/hostile\n"),
    )
    .unwrap();
    // Read only if podman saw the user's config directory: an empty image store, so the launch
    // would fail with the image unknown.
    std::fs::write(
        conf.join("storage.conf"),
        format!(
            "[storage]\ndriver = \"vfs\"\ngraphroot = \"{0}/store\"\nrunroot = \"{0}/run\"\n",
            home.display()
        ),
    )
    .unwrap();
    std::fs::write(
        conf.join("registries.conf"),
        "unqualified-search-registries = [\"hostile.invalid\"]\n",
    )
    .unwrap();
    std::fs::write(
        hooks.join("hostile.json"),
        format!(
            "{{\"version\":\"1.0.0\",\"hook\":{{\"path\":\"/bin/sh\",\
             \"args\":[\"sh\",\"-c\",\"touch {}\"]}},\"when\":{{\"always\":true}},\
             \"stages\":[\"prestart\",\"createRuntime\",\"poststart\"]}}",
            hook_canary.display()
        ),
    )
    .unwrap();
    Hostile {
        _cleanup: RemoveOnDrop(home.clone()),
        home,
        hook_canary,
    }
}

/// #11 and RT-SUP-04: with hostile `containers.conf`, a drop-in, `mounts.conf`,
/// `storage.conf`, `registries.conf` and an OCI hook under the `$HOME` podman is given, the
/// launch passes the OCI config verifier (so the config is exactly what the argv intended), and
/// inside there is no extra mount, no hostile variable, no capability and only `lo`; the hook
/// never ran. `CONTAINERS_CONF` replaces the user's files, `XDG_CONFIG_HOME` is Sallyport's own
/// empty directory, and podman's environment is an allowlist (`env_clear`;
/// `podman.rs::the_environment_is_an_allowlist`), so the same variables in `sallyd`'s own
/// environment cannot point podman at these files either (architect Q113: no `set_var`).
///
/// This test is defence in depth, not the control of each defence: with any one of the private
/// `HOME`, `CONTAINERS_CONF`, `XDG_CONFIG_HOME`, `env_clear` or the verifier removed it still
/// passes, the others keeping the files out; only the exact `init`/`start` argv lines fail it.
/// Each defence's own failing test (architect Q121): the flag,
/// `rt_sup_04_the_empty_mounts_file_on_init_keeps_every_mounts_conf_out`; the private `HOME`,
/// `rt_sup_04_the_private_home_keeps_the_user_mounts_conf_out`; the environment, the daemon
/// test's exact envp; the verifier, (i) and the altered-config test. The probe's control is
/// `rt_sup_04_the_probe_finds_the_canary_when_init_reads_a_hostile_home`.
#[test]
fn rt_sup_04_hostile_podman_configuration_never_reaches_a_container() {
    let h = hostile_home();
    let (dir, _cleanup) = scratch("hostile");
    rt().block_on(async {
        let x = Lx::with_home_and_podman(Some(h.home.clone()), |real| wrapper(&dir, real, ""));
        let v =
            x.f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", "ro")]));
        let r = x.launch(&v, "hostile").await.unwrap();
        let (_, out) = exec(&r, PROBE).await;
        assert_probe_clean(&out);
        assert!(!out.contains("HOSTILE"), "{out}");
        assert!(out.contains("CapEff:\t0000000000000000"), "{out}");
        assert_eq!(
            out.lines().last(),
            Some("lo"),
            "own network namespace: {out}"
        );
        // The two calls that build the container's spec carry Sallyport's empty mounts file,
        // exactly (the mount-link probe's are held by `assert_one_start_path`'s tests).
        let all = std::fs::read_to_string(dir.join("argv")).unwrap();
        let argv: String = all
            .lines()
            .filter(|l| !is_probe(l))
            .map(|l| format!("{l}\n"))
            .collect();
        let file = x.podman.mounts_file();
        for verb in ["init", "start"] {
            let lines: Vec<&str> = argv.lines().filter(|l| verb_of(l) == verb).collect();
            assert_eq!(
                lines,
                [format!(
                    "--default-mounts-file {} {verb} {}",
                    file.display(),
                    r.container()
                )],
                "{argv}"
            );
        }
        // The verifier read the config between them (security review: its removal fails this).
        let at = |verb: &str| argv.lines().position(|l| verb_of(l) == verb).unwrap();
        let read = argv
            .lines()
            .position(|l| l.starts_with("unshare cat -- ") && l.ends_with("/config.json"))
            .unwrap_or_else(|| panic!("no config read: {argv}"));
        assert!(at("init") < read && read < at("start"), "{argv}");
        x.stop(r).await;
    });
    assert!(!h.hook_canary.exists(), "a hostile hook ran");
}

/// The probe every hostile-configuration case runs inside. `-R`: a copied subscription
/// directory shows only its name at the top (why the #11 test passed while the leak was
/// there), its files one level down.
const PROBE: &str = "for p in /hostile /hostile2 /run/secrets/hostile; do [ -e $p ] && echo LEAK $p; done; \
     ls -R /hostile /hostile2 /run/secrets 2>&1; env | grep HOSTILE; \
     grep CapEff /proc/self/status; ls /sys/class/net";

fn assert_probe_clean(out: &str) {
    assert!(!out.contains("LEAK") && !out.contains("canary"), "{out}");
}

/// One raw case (architect Q121): the product-built harness argv created by hermetic podman,
/// then `init` and `start` by raw podman with the hermetic environment, differing only in
/// `HOME` (`home`) and in the empty mounts file on both calls (`flag`). `init` runs under
/// strace (file syscalls; `-b execve` lets conmon go). The container id, the probe's output,
/// the strace text and the built intent.
struct Raw {
    id: String,
    out: String,
    trace: String,
    intent: sallyd::sandbox::oci::intent::Intent,
}

async fn raw_case(x: &Lx, dir: &Path, tag: &str, home: Option<&Path>, flag: bool) -> Raw {
    let v = x.f.load("");
    let paths = x.paths(tag);
    let dirs = SessionDirs::create(&paths, &x.xdg, &[], 0).unwrap();
    let built = harness_build(&x.common_args(&dirs), &paths, &v, &test_image()).unwrap();
    let id = x
        .hermetic(&built.argv)
        .await
        .lines()
        .last()
        .unwrap()
        .to_owned();
    let trace = dir.join(format!("{tag}.strace"));
    let args = |verb: &str| -> Vec<std::ffi::OsString> {
        if flag {
            x.podman.spec_args(verb, &id).to_vec()
        } else {
            vec![verb.into(), id.clone().into()]
        }
    };
    let run = |prefix: Vec<std::ffi::OsString>, verb: &str| {
        let mut c = tokio::process::Command::new(prefix.first().unwrap());
        c.args(prefix.get(1..).unwrap())
            .args(args(verb))
            .env_clear()
            .envs(x.podman.environment().iter().map(|(k, v)| (k, v)))
            .current_dir(dir)
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true);
        if let Some(h) = home {
            c.env("HOME", h);
        }
        c
    };
    let strace: Vec<std::ffi::OsString> = ["strace", "-f", "-b", "execve", "-qq", "-e"]
        .into_iter()
        .map(Into::into)
        .chain([
            "trace=%file".into(),
            "-o".into(),
            trace.clone().into_os_string(),
            x.podman.bin().into(),
        ])
        .collect();
    for (prefix, verb) in [(strace, "init"), (vec![x.podman.bin().into()], "start")] {
        let out = tokio::time::timeout(
            std::time::Duration::from_secs(120),
            run(prefix, verb).output(),
        )
        .await
        .expect("podman within 120 s")
        .unwrap();
        assert!(
            out.status.success(),
            "{verb}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let (_, out) = exec_in(&id, &["sh", "-c", PROBE]);
    Raw {
        id,
        out,
        trace: std::fs::read_to_string(&trace).unwrap(),
        intent: built.intent,
    }
}

/// Every `mounts.conf` path in a strace text.
fn mounts_conf_paths(trace: &str) -> Vec<&str> {
    trace
        .split('"')
        .filter(|s| s.ends_with("/mounts.conf"))
        .collect()
}

/// (i) The control (maintainer ruling 5): with the defences off (a hostile `HOME`, no flag on
/// `init`), the same probe finds the canary, and the verifier refuses the config podman wrote.
#[test]
fn rt_sup_04_the_probe_finds_the_canary_when_init_reads_a_hostile_home() {
    let h = hostile_home();
    let (dir, _cleanup) = scratch("raw-i");
    rt().block_on(async {
        let x = Lx::new();
        let r = raw_case(&x, &dir, "raw-i", Some(&h.home), false).await;
        assert!(r.out.contains("LEAK /run/secrets/hostile"), "{}", r.out);
        assert!(r.out.contains("canary"), "{}", r.out);
        assert_eq!(
            mismatch_field(x.launcher.verify_config(&r.id, &r.intent).await),
            "mounts[/run/secrets/hostile]"
        );
    });
}

/// (ii) The flag alone: a hostile `HOME`, the empty mounts file on `init`. Podman reads one
/// list (the user's file, `/etc/containers`, `/usr/share/containers`), so no `mounts.conf` but
/// Sallyport's is touched.
#[test]
fn rt_sup_04_the_empty_mounts_file_on_init_keeps_every_mounts_conf_out() {
    let h = hostile_home();
    let (dir, _cleanup) = scratch("raw-ii");
    rt().block_on(async {
        let x = Lx::new();
        let r = raw_case(&x, &dir, "raw-ii", Some(&h.home), true).await;
        assert_probe_clean(&r.out);
        let own = x.podman.mounts_file();
        let seen = mounts_conf_paths(&r.trace);
        assert!(seen.iter().any(|p| Path::new(p) == own), "{seen:?}");
        assert!(seen.iter().all(|p| Path::new(p) == own), "{seen:?}");
    });
}

/// (iii) The private `HOME` alone: no flag on `init`, and hermetic podman set up from a host
/// `HOME` that holds the hostile `mounts.conf`, so podman given that `HOME` (the redirect
/// removed) would mount the canary and stop there. The user's file is not read (only the
/// canary is asserted: a host with a system `mounts.conf` adds its own, #121). The control of
/// (ii)'s scan: without the flag, strace shows `init` looking for the system files.
#[test]
fn rt_sup_04_the_private_home_keeps_the_user_mounts_conf_out() {
    let h = hostile_home();
    let (dir, _cleanup) = scratch("raw-iii");
    rt().block_on(async {
        let x = Lx::with_home_and_podman(Some(h.home.clone()), Path::to_path_buf);
        let r = raw_case(&x, &dir, "raw-iii", None, false).await;
        assert_probe_clean(&r.out);
        let seen = mounts_conf_paths(&r.trace);
        let home = h.home.display().to_string();
        assert!(!seen.iter().any(|p| p.starts_with(&home)), "{seen:?}");
        let etc = "/etc/containers/mounts.conf";
        assert!(seen.contains(&etc), "{seen:?}");
        // Podman stops at the first file that exists.
        if !Path::new(etc).exists() {
            assert!(
                seen.contains(&"/usr/share/containers/mounts.conf"),
                "{seen:?}"
            );
        }
    });
}
