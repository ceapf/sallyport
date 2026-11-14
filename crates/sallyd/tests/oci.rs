//! RT-SUP-04 and the OCI config verifier on real containers (Task 14, #15; architect Q111,
//! Q113, Q114): the config Podman 4.9.3 generates for each in-scope role passes, a config
//! altered after `podman init` is refused before `start`, and hostile podman configuration in
//! every location podman consults never reaches a container.
//!
//! The fixture is `common::container`; these tests never skip.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use sally_core::manifest::Cpus;
use sallyd::sandbox::{
    InferenceSpec, LaunchError, SessionDirs, SessionId, VerifiedModel, harness_build,
    inference_build,
};

mod common;
use common::container::*;
use common::*;

struct RemoveOnDrop(PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

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

/// A podman wrapper that appends its whole argv (`$*`) to `<at>/argv`, runs the real podman,
/// then runs `after` (shell, with `$rc`, `$v` the verb and `$id` the word after it) and exits
/// with podman's status. The verb is the first word after the global `--flag value` pairs.
fn wrapper(at: &Path, real: &Path, after: &str) -> PathBuf {
    let (dir, real) = (at.display(), real.display());
    for p in [dir.to_string(), real.to_string()] {
        assert_plain(&p);
    }
    let script = format!(
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >>'{dir}/argv'\n'{real}' \"$@\"\nrc=$?\n\
         v=; id=; skip=\nfor a; do\n\
         if [ -n \"$skip\" ]; then skip=; continue; fi\n\
         case \"$a\" in --*) [ -z \"$v\" ] && skip=1 ;; \
         *) if [ -z \"$v\" ]; then v=$a; elif [ -z \"$id\" ]; then id=$a; fi ;; esac\n\
         done\n{after}\nexit $rc\n"
    );
    let bin = at.join("podman");
    executable(&bin, script.as_bytes());
    bin
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

/// [`wrapper`] that, after a successful `init`, adds a capability to the config podman
/// generated: the window between create and start (architect Q114).
fn altering_podman(at: &Path, real: &Path) -> PathBuf {
    let r = real.display();
    wrapper(
        at,
        real,
        &format!(
            "if [ $rc -eq 0 ] && [ \"$v\" = init ]; then\n\
             cfg=$('{r}' inspect --format '{{{{.OCIConfigPath}}}}' \"$id\")\n\
             '{r}' unshare sed -i -e 's/\"capabilities\":{{}}/\"capabilities\":{{\"bounding\":[\"CAP_SYS_ADMIN\"]}}/' \"$cfg\"\n\
             fi"
        ),
    )
}

#[test]
fn rt_sup_04_a_config_altered_between_create_and_start_is_refused() {
    let (dir, _cleanup) = scratch("altered");
    rt().block_on(async {
        let x = Lx::with_podman(|real| altering_podman(&dir, real));
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
        assert!(argv.lines().any(|l| verb_of(l) == "init"), "{argv}");
        assert!(!argv.lines().any(|l| verb_of(l) == "start"), "{argv}");
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
        // The two calls that build the spec carry Sallyport's empty mounts file, exactly.
        let argv = std::fs::read_to_string(dir.join("argv")).unwrap();
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
