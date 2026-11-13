//! Red-team rows RT-SEC-01 and RT-SEC-02 (Task 9b, architect ruling A6): no form of any secret
//! the session holds reaches a container, in a process environment or command line (01) or in a
//! file (02).
//!
//! Each test launches a workspace session whose grants include an `expose_env` grant and a
//! `{basic}` grant (credentials from the production secrets store file over a temporary 0600
//! store, as in `intercept.rs`), and a harness of the same session, then runs the shared search
//! (`common::search`, RT-SEC-10's) in both. The patterns are the `SALLY_CANARY` marker and every
//! independently computed form of every canary (`common::forms`): the raw values, their
//! percent spellings and base64 cores, the rendered `Bearer` value, and the `{basic}` rendered
//! value and blobs. A planted throwaway value (`SALLY_CANARY_PLANTED_…`, never a store value) is
//! found in each place searched: the positive control. A search that outlives its bound fails,
//! naming the bound.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::container::{Lx, SHIM_LOG, exec, exec_in, ids, net_image, rt, test_image};
use common::egress::canary;
use common::forms::{basic_blob, basic_forms, forms_of};
use common::search::{Plants, Scope, fixed_patterns, found, search_script, unreadable_script};
use sallyd::sandbox::{CommonArgs, Running, WorkspaceRequest, harness_argv};

/// A `Bearer` grant exposed to the workspace as a placeholder (`GH_TOKEN`), and a `{basic}`
/// grant.
const MANIFEST: &str = "network:\n  mode: proxy\n  allow:\n    - host: mock.test\n    \
                        - host: b1.mock.test\n\
                        secrets:\n  - name: GITHUB_TOKEN\n    inject: {host: mock.test, \
                        header: Authorization, format: \"Bearer {value}\"}\n    \
                        expose_env: GH_TOKEN\n  \
                        - name: GIT_TOKEN\n    inject: {host: b1.mock.test, \
                        header: Authorization, format: \"Basic {basic}\", basic_user: x}\n";

/// Carried in the argv of the search's own processes; a command line carrying it is skipped.
const SEARCH_MARK: &str = "sp-rt-sec-01-02-search";

/// The longest both searches (workspace, then harness) may take together. Measured locally:
/// 2.8 s for the processes and 4.1 s for the files of both containers; thirty times that leaves
/// room for a loaded CI runner, and a search that is stuck still fails, naming the bound.
const SEARCH_BOUND: Duration = Duration::from_secs(120);

/// The planted throwaway value that holds the marker, so the marker pattern finds it; never a
/// value of the store.
fn planted() -> String {
    format!("SALLY_CANARY_PLANTED_{}", std::process::id())
}

/// A planted throwaway `{basic}` blob, without the marker: only its own pattern (an encoded
/// form, with `+`, `/` or `=` in it) can find it, so the encoded patterns are proven to match in
/// the container on every run (9b security review L2).
fn planted_blob() -> String {
    basic_blob("planted", &format!("{}/+?&= {}", planted(), "p".repeat(7)))
}

/// The marker, the search's own mark, the planted blob, and every form of every canary the
/// session holds.
fn patterns() -> Vec<String> {
    let mut p = vec![
        SEARCH_MARK.to_owned(),
        "SALLY_CANARY".to_owned(),
        planted_blob(),
    ];
    for name in ["GITHUB_TOKEN", "GIT_TOKEN"] {
        p.extend(forms_of(&canary(name)));
    }
    p.push(format!("Bearer {}", canary("GITHUB_TOKEN")));
    p.extend(basic_forms("x", &canary("GIT_TOKEN")));
    p
}

/// Plants the marker in `/tmp/planted.txt`, and the blob in `/tmp/planted-blob.txt`, a process
/// environment and a process command line.
fn script(scope: Scope) -> String {
    let files = format!(
        "printf '%s' '{}' > /tmp/planted.txt\nprintf '%s' '{}' > /tmp/planted-blob.txt\n",
        planted(),
        planted_blob()
    );
    let plants = Plants {
        files: &files,
        shm: &planted(),
        process: &planted_blob(),
    };
    search_script(SEARCH_MARK, &plants, &fixed_patterns(&patterns()), scope)
}

async fn session(lx: &Lx, tag: &str) -> Running {
    let req = WorkspaceRequest {
        paths: lx.paths(tag),
        manifest: Arc::new(lx.f.load(MANIFEST)),
        default_image: Some(net_image()),
        crash: sallyd::daemon::crash::CrashReporter::channel().0,
    };
    let r = lx.launcher.launch_workspace(req).await.expect("launch");
    for _ in 0..100 {
        let (_, log) = exec(&r, &format!("cat {SHIM_LOG} 2>/dev/null")).await;
        if log.contains("sally-shim: listening on 127.0.0.1:3128") {
            return r;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the shim never became ready");
}

/// A harness of the session `tag`, started: its container name.
async fn harness(lx: &Lx, tag: &str) -> String {
    let paths = lx.paths(tag);
    let v = lx.f.load(MANIFEST);
    let common = CommonArgs {
        runtime: lx.runtime.clone(),
        ids: ids(),
        profiles: paths.data_root().join("profiles"),
        hooks_dir: lx.podman.hooks_dir(),
        mounts_file: lx.podman.mounts_file(),
        installation: lx.installation.clone(),
    };
    let argv = harness_argv(&common, &paths, &v, &test_image()).unwrap();
    let id = lx.hermetic(&argv).await;
    let id = id.lines().last().unwrap().to_owned();
    lx.hermetic(&["start".to_owned(), id.clone()]).await;
    id
}

/// Runs `script` in the workspace `r` and in the harness `h`, both within [`SEARCH_BOUND`]:
/// what each found. On expiry the test panics naming the bound; the blocking `podman exec`
/// threads cannot be cancelled, so the run ends when the unwind drops `Lx`, whose `podman rm
/// --force` ends both execs (a hung `podman` itself is left to nextest's own timeout).
async fn search(r: &Running, h: &str, script: &str) -> [Vec<String>; 2] {
    let started = Instant::now();
    let (code, ws) = tokio::time::timeout(SEARCH_BOUND, exec(r, script))
        .await
        .unwrap_or_else(|_| panic!("workspace search exceeded {SEARCH_BOUND:?}"));
    assert_eq!(code, 0, "{ws}");
    let (h, script) = (h.to_owned(), script.to_owned());
    let left = SEARCH_BOUND.saturating_sub(started.elapsed());
    let (code, hs) = tokio::time::timeout(
        left,
        tokio::task::spawn_blocking(move || exec_in(&h, &["sh", "-c", &script])),
    )
    .await
    .unwrap_or_else(|_| panic!("the searches exceeded {SEARCH_BOUND:?}"))
    .unwrap();
    assert_eq!(code, 0, "{hs}");
    eprintln!("searches took {:?}", started.elapsed());
    [found(&ws), found(&hs)]
}

/// RT-SEC-01: no process of either container holds a secret form in its environment or
/// command line. Controls: the placeholder in `argv::PLACEHOLDER` is the only value `--env`
/// carries (`expose_env`), and secret values live only in `sallyd` (`inject::Credentials`,
/// read by `StoreFile` before the container exists): putting a value or a form of it in the
/// workspace or harness argv or environment fails the test. The blob planted in an environment
/// and a command line is found in both (positive control, through an encoded pattern).
#[test]
fn rt_sec_01_no_process_environment_or_command_line_holds_a_secret() {
    rt().block_on(async {
        let lx = Lx::new();
        let r = session(&lx, "sec01").await;
        let h = harness(&lx, "sec01").await;
        let (_, env) = exec(&r, "env").await;
        assert!(env.contains("GH_TOKEN=sallyport-placeholder"), "{env}");
        let [ws, hs] = search(&r, &h, &script(Scope::Procs)).await;
        let want = ["/proc/<planted>/cmdline", "/proc/<planted>/environ"];
        assert_eq!(ws, want, "workspace");
        assert_eq!(hs, want, "harness");
        lx.stop(r).await;
    });
}

/// RT-SEC-02: no file either container can read holds a secret form. Controls: the store
/// directory is on the built-in mount denylist (RT-MAN-02 holds that half), and nothing `sallyd`
/// writes into a sandbox (the CA files, the socket directories, the shim) carries a value:
/// writing a value or a form of it anywhere a container can read fails the test. The planted
/// files (the marker, and a blob only an encoded pattern matches) are found in both (positive
/// control); `/dev/shm` keeps RT-SEC-10's tripwire. Where `sallyd` and the sandbox write
/// (`/run`, `/tmp`), nothing is unreadable to the container's user, so the search skips nothing
/// there (9b security review L3).
#[test]
fn rt_sec_02_no_file_in_either_container_holds_a_secret() {
    rt().block_on(async {
        let lx = Lx::new();
        let r = session(&lx, "sec02").await;
        let h = harness(&lx, "sec02").await;
        let [ws, hs] = search(&r, &h, &script(Scope::Files)).await;
        let want = ["/tmp/planted-blob.txt", "/tmp/planted.txt"];
        assert_eq!(ws, want, "workspace");
        assert_eq!(hs, want, "harness");
        let [ws, hs] = search(&r, &h, &unreadable_script(&["/run", "/tmp"])).await;
        assert!(ws.is_empty(), "workspace: {ws:?}");
        assert!(hs.is_empty(), "harness: {hs:?}");
        lx.stop(r).await;
    });
}
