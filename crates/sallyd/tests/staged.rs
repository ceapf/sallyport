//! RT-FS-15: in a `staged` mount the sandbox creates, modifies and deletes files, including
//! `.vscode/settings.json` and a nested `sub/.git/config`. The host tree is identical during and
//! after the session, and `session_changes` lists exactly those paths, from the session id
//! alone (architect Q81). Control (#122, architect Q182): each test first runs the same exec in
//! a sibling directory mounted `rw` and shows `tree_state` sees the host change. The fixture is
//! `common::container`; these tests never skip.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;

use sallyd::sandbox::ChangeKind;

mod common;
use common::container::*;
use common::*;

/// The control of a "the host tree is identical" check (#122): a sibling directory `rel` under
/// `~/code`, filled by the same `fill`, mounted `rw` at the same guest path, and the same
/// `script` run in it. During that session the host tree has changed, seen by the same
/// `tree_state`: read from its value before and after, `absent` is there before and gone after,
/// and `present` the other way round (architect Q190). The session is stopped after.
async fn rw_control(x: &Lx, rel: &str, fill: fn(&Path), script: &str, present: &str, absent: &str) {
    let c = x.f.root.join("home/code").join(rel);
    fill(&c);
    // A `tree_state` line is `"{rel} {mode} …"`: the trailing space makes the prefix exact.
    let has = |state: &[String], name: &str| {
        let prefix = format!("{name} ");
        state.iter().any(|l| l.starts_with(&prefix))
    };
    let before = tree_state(&c);
    assert!(
        has(&before, absent) && !has(&before, present),
        "control: the fill does not hold {absent} without {present}: {before:#?}"
    );
    let v = x.f.load(&mounts(&[mount(
        &format!("~/code/{rel}"),
        "/workspace/p",
        "rw",
    )]));
    let r = x.launch(&v, rel).await.expect("control: the rw launch");
    let (code, out) = exec(&r, script).await;
    assert_eq!(code, 0, "control: {out}");
    let after = tree_state(&c);
    assert_ne!(after, before, "control: the rw host tree did not change");
    assert!(
        has(&after, present),
        "control: {present} is not on the host: {after:#?}"
    );
    assert!(
        !has(&after, absent),
        "control: {absent} is still on the host: {after:#?}"
    );
    x.stop(r).await;
}

/// The first test's tree.
fn fill_fs15(p: &Path) {
    std::fs::create_dir_all(p.join("sub/.git")).unwrap();
    for (rel, body) in [
        ("keep.txt", "old\n"),
        ("old.txt", "bye\n"),
        ("same.txt", "untouched\n"),
        ("sub/.git/config", "[core]\n"),
    ] {
        std::fs::write(p.join(rel), body).unwrap();
    }
}

/// The first test's writes.
const FS15_SCRIPT: &str = "cd /workspace/p && echo new > new.txt && echo changed > keep.txt \
    && rm old.txt && mkdir .vscode && echo '{}' > .vscode/settings.json \
    && printf '\\tfsmonitor = /tmp/x\\n' >> sub/.git/config && cat sub/.git/config";

#[test]
fn rt_fs_15_staged_changes_leave_the_host_untouched_and_are_listed() {
    rt().block_on(async {
        let x = Lx::new();
        rw_control(&x, "fs15-rw", fill_fs15, FS15_SCRIPT, "new.txt", "old.txt").await;
        let p = x.f.root.join("home/code/myproject");
        fill_fs15(&p);
        let before = tree_state(&p);
        let v = x.f.load(&mounts(&[mount(
            "~/code/myproject",
            "/workspace/p",
            "staged",
        )]));
        let r = x.launch(&v, "fs15").await.unwrap();
        let (code, out) = exec(&r, FS15_SCRIPT).await;
        assert_eq!(code, 0, "{out}");
        assert!(
            out.contains("fsmonitor"),
            "the sandbox sees its write: {out}"
        );
        assert_eq!(tree_state(&p), before, "the host tree, during the session");
        let w = ChangeKind::Written;
        let want = [
            (".vscode/settings.json", w),
            ("keep.txt", w),
            ("new.txt", w),
            ("old.txt", ChangeKind::Deleted),
            ("sub/.git/config", w),
        ];
        let listed = || {
            changes(&x.paths("fs15"))
                .unwrap()
                .into_iter()
                .map(|c| {
                    assert_eq!(c.mount, 0);
                    (c.path.display().to_string(), c.kind)
                })
                .collect::<Vec<_>>()
        };
        let want: Vec<_> = want.iter().map(|(p, k)| ((*p).to_owned(), *k)).collect();
        assert_eq!(listed(), want, "during the session");
        x.stop(r).await;
        assert_eq!(tree_state(&p), before, "the host tree, after the session");
        assert_eq!(listed(), want, "after the session (the stage is kept)");
    });
}

/// The second test's tree.
fn fill_fs15d(p: &Path) {
    for rel in ["gone/a.txt", "moved/b.txt"] {
        std::fs::create_dir_all(p.join(rel).parent().unwrap()).unwrap();
        std::fs::write(p.join(rel), "x\n").unwrap();
    }
}

/// The second test's writes.
const FS15D_SCRIPT: &str = "cd /workspace/p && rm -rf gone && mkdir gone && echo n > gone/n.txt \
    && mv moved moved2 && ls gone moved2";

/// The kernel overlay's own markers, not ones a unit test sets: a host directory removed and
/// re-created is opaque (`Replaced`), and a host directory renamed is a copy plus a whiteout.
#[test]
fn rt_fs_15_replaced_and_renamed_directories_are_listed() {
    rt().block_on(async {
        let x = Lx::new();
        rw_control(
            &x,
            "fs15d-rw",
            fill_fs15d,
            FS15D_SCRIPT,
            "gone/n.txt",
            "moved",
        )
        .await;
        let p = x.f.root.join("home/code/myproject");
        fill_fs15d(&p);
        let before = tree_state(&p);
        let v = x.f.load(&mounts(&[mount(
            "~/code/myproject",
            "/workspace/p",
            "staged",
        )]));
        let r = x.launch(&v, "fs15d").await.unwrap();
        let (code, out) = exec(&r, FS15D_SCRIPT).await;
        assert_eq!(code, 0, "{out}");
        x.stop(r).await;
        assert_eq!(tree_state(&p), before, "the host tree");
        let listed: Vec<_> = changes(&x.paths("fs15d"))
            .unwrap()
            .into_iter()
            .map(|c| (c.path.display().to_string(), c.kind))
            .collect();
        let want = [
            ("gone", ChangeKind::Replaced),
            ("gone/n.txt", ChangeKind::Written),
            ("moved", ChangeKind::Deleted),
            ("moved2/b.txt", ChangeKind::Written),
        ];
        let want: Vec<_> = want.iter().map(|(p, k)| ((*p).to_owned(), *k)).collect();
        assert_eq!(listed, want);
    });
}
