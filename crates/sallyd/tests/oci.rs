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

fn scratch(tag: &str) -> (PathBuf, RemoveOnDrop) {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("oci-{tag}-{}", std::process::id()));
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

/// Creates and initialises `argv` with hermetic podman; the container id.
async fn create_and_init(x: &Lx, argv: Vec<String>) -> String {
    let out = x.hermetic(&argv).await;
    let id = out.lines().last().unwrap().to_owned();
    x.hermetic(&["init".to_owned(), id.clone()]).await;
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

/// CPU inference: the real config passes (no hostname, no memory limit); a socket directory
/// turned read-only-less and `no_new_privs` dropped are each refused.
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
        let _ = podman(&["rm", "--force", &id]);
        // A GPU intent is refused before anything is read (M3, #116).
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

/// A podman wrapper that logs each verb and, after a successful `init`, adds a capability to
/// the config podman generated: the window between create and start (architect Q114).
fn altering_podman(at: &Path, real: &Path) -> PathBuf {
    let (dir, real) = (at.display(), real.display());
    for p in [dir.to_string(), real.to_string()] {
        assert!(!p.contains('\''), "the wrapper single-quotes {p}");
    }
    let script = format!(
        "#!/bin/sh\necho \"$1\" >>'{dir}/verbs'\n'{real}' \"$@\"\nrc=$?\n\
         if [ $rc -eq 0 ] && [ \"$1\" = init ]; then\n\
         cfg=$('{real}' inspect --format '{{{{.OCIConfigPath}}}}' \"$2\")\n\
         '{real}' unshare sed -i -e 's/\"capabilities\":{{}}/\"capabilities\":{{\"bounding\":[\"CAP_SYS_ADMIN\"]}}/' \"$cfg\"\n\
         fi\nexit $rc\n"
    );
    let bin = at.join("podman");
    executable(&bin, script.as_bytes());
    bin
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
        let verbs = std::fs::read_to_string(dir.join("verbs")).unwrap();
        assert!(verbs.lines().any(|l| l == "init"), "{verbs}");
        assert!(!verbs.lines().any(|l| l == "start"), "{verbs}");
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

fn hostile_home() -> Hostile {
    let home = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("hostile-home-{}", std::process::id()));
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
#[test]
fn rt_sup_04_hostile_podman_configuration_never_reaches_a_container() {
    let h = hostile_home();
    rt().block_on(async {
        let x = Lx::with_home(Some(h.home.clone()));
        let v =
            x.f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", "ro")]));
        let r = x.launch(&v, "hostile").await.unwrap();
        let (_, out) = exec(
            &r,
            // -R: a copied subscription directory shows only its name at the top (the gap the
            // verifier found in Task 14), its files one level down.
            "for p in /hostile /hostile2 /run/secrets/hostile; do [ -e $p ] && echo LEAK $p; done; \
             ls -R /hostile /hostile2 /run/secrets 2>&1; env | grep HOSTILE; \
             grep CapEff /proc/self/status; ls /sys/class/net",
        )
        .await;
        assert!(
            !out.contains("LEAK") && !out.contains("canary") && !out.contains("HOSTILE"),
            "{out}"
        );
        assert!(out.contains("CapEff:\t0000000000000000"), "{out}");
        assert_eq!(
            out.lines().last(),
            Some("lo"),
            "own network namespace: {out}"
        );
        x.stop(r).await;
    });
    assert!(!h.hook_canary.exists(), "a hostile hook ran");
}
