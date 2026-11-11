//! RT-FS-12, host parts: in an `rw` and in a `staged` mount of a real git repository, the sandbox
//! plants three host-execution vectors: a `.git/hooks/pre-commit`, a `core.fsmonitor` line in
//! `.git/config`, and a `.git/commondir` that points git at a directory the sandbox wrote (with
//! its own fsmonitor config and hook). Each vector touches its own canary outside the mount.
//! PASS: the host's `git status` and `git hook run pre-commit` run none of them, during the
//! session and after it, and the host `.git` tree is unchanged. A host-side control plants each
//! vector in a throwaway repository first and proves it fires, so the pass is not vacuous.
//! (`fs_write` to `.git` paths is #19, Task 11; the in-container shields are in `launch.rs`.)
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::Command;

mod common;
use common::container::*;
use common::*;

#[derive(Clone, Copy, Debug)]
enum Vector {
    Hook,
    Fsmonitor,
    Commondir,
}

const VECTORS: [Vector; 3] = [Vector::Hook, Vector::Fsmonitor, Vector::Commondir];

/// Shell, run from a repository's work tree, that plants `v` with canary `c`.
fn plant(v: Vector, c: &Path) -> String {
    let c = c.display();
    match v {
        Vector::Hook => format!(
            "printf '#!/bin/sh\\ntouch {c}\\n' > .git/hooks/pre-commit \
             && chmod +x .git/hooks/pre-commit"
        ),
        Vector::Fsmonitor => {
            format!("printf '[core]\\n\\tfsmonitor = touch {c} #\\n' >> .git/config")
        }
        Vector::Commondir => format!(
            "mkdir -p evil/objects evil/refs/heads evil/hooks \
             && printf '[core]\\n\\trepositoryformatversion = 0\\n\\tfsmonitor = touch {c} #\\n' \
                > evil/config \
             && printf '#!/bin/sh\\ntouch {c}\\n' > evil/hooks/pre-commit \
             && chmod +x evil/hooks/pre-commit && echo ../evil > .git/commondir"
        ),
    }
}

/// Host git with no user or system configuration, never taking optional locks (so `status`
/// does not rewrite the index).
fn git(repo: &Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .args(args)
        .current_dir(repo)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", repo)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .output()
        .expect("git must be installed")
}

/// A repository with one commit at `dir`.
fn repo(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("a.txt"), "a\n").unwrap();
    for args in [
        &["init", "-q"][..],
        &["add", "a.txt"],
        &[
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.invalid",
            "commit",
            "-qm",
            "a",
        ],
    ] {
        let out = git(dir, args);
        assert!(out.status.success(), "git {args:?}: {out:?}");
    }
}

/// What the host runs in a repository: `git status` and the pre-commit hook. Their output, for
/// messages.
fn host_runs(dir: &Path) -> String {
    let s = git(dir, &["status", "--porcelain"]);
    let h = git(dir, &["hook", "run", "--ignore-missing", "pre-commit"]);
    format!("status: {s:?}\nhook: {h:?}")
}

fn canary(x: &Lx, tag: &str, v: Vector) -> PathBuf {
    x.f.root.join(format!("canary-{tag}-{v:?}"))
}

/// The control: each vector, planted on the host in its own repository, fires.
fn control(x: &Lx) {
    for v in VECTORS {
        let dir = x.f.root.join(format!("control-{v:?}"));
        repo(&dir);
        let c = canary(x, "control", v);
        let st = Command::new("sh")
            .args(["-c", &plant(v, &c)])
            .current_dir(&dir)
            .status()
            .unwrap();
        assert!(st.success(), "control plant {v:?}");
        let ran = host_runs(&dir);
        assert!(c.exists(), "control: {v:?} must fire on the host\n{ran}");
        std::fs::remove_file(&c).unwrap();
    }
}

async fn vectors_stay_in_the_sandbox(mode: &str) {
    let x = Lx::new();
    control(&x);
    let p = x.f.root.join("home/code/myproject");
    repo(&p);
    host_runs(&p);
    let before = tree_state(&p.join(".git"));
    let v =
        x.f.load(&mounts(&[mount("~/code/myproject", "/workspace/p", mode)]));
    let r = x.launch(&v, mode).await.unwrap();
    let script: Vec<String> = VECTORS
        .iter()
        .map(|&vec| plant(vec, &canary(&x, mode, vec)))
        .collect();
    let (code, out) = exec(&r, &format!("cd /workspace/p && {}", script.join(" && "))).await;
    assert_eq!(code, 0, "{mode}: the sandbox plants every vector: {out}");
    let check = |when: &str| {
        let ran = host_runs(&p);
        for vec in VECTORS {
            let c = canary(&x, mode, vec);
            assert!(
                !c.exists(),
                "{mode}, {when}: {vec:?} ran on the host\n{ran}"
            );
        }
        assert_eq!(
            tree_state(&p.join(".git")),
            before,
            "{mode}, {when}: the host .git changed"
        );
    };
    check("during the session");
    x.stop(r).await;
    check("after the session");
}

#[test]
fn rt_fs_12_git_vectors_in_an_rw_mount_never_run_on_the_host() {
    rt().block_on(vectors_stay_in_the_sandbox("rw"));
}

#[test]
fn rt_fs_12_git_vectors_in_a_staged_mount_never_run_on_the_host() {
    rt().block_on(vectors_stay_in_the_sandbox("staged"));
}
