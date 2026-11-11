//! RT-FS-15: in a `staged` mount the sandbox creates, modifies and deletes files, including
//! `.vscode/settings.json` and a nested `sub/.git/config`. The host tree is identical during and
//! after the session, and `staged_changes` lists exactly those paths. (The CLI wiring,
//! `sally session changes`, is #20, Task 12.) The fixture is `common::container`; these tests
//! never skip.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use sallyd::sandbox::{ChangeKind, staged_changes};

mod common;
use common::container::*;
use common::*;

#[test]
fn rt_fs_15_staged_changes_leave_the_host_untouched_and_are_listed() {
    rt().block_on(async {
        let x = Lx::new();
        let p = x.f.root.join("home/code/myproject");
        std::fs::create_dir_all(p.join("sub/.git")).unwrap();
        for (rel, body) in [
            ("keep.txt", "old\n"),
            ("old.txt", "bye\n"),
            ("same.txt", "untouched\n"),
            ("sub/.git/config", "[core]\n"),
        ] {
            std::fs::write(p.join(rel), body).unwrap();
        }
        let before = tree_state(&p);
        let v = x.f.load(&mounts(&[mount(
            "~/code/myproject",
            "/workspace/p",
            "staged",
        )]));
        let r = x.launch(&v, "fs15").await.unwrap();
        let (code, out) = exec(
            &r,
            "cd /workspace/p && echo new > new.txt && echo changed > keep.txt && rm old.txt \
             && mkdir .vscode && echo '{}' > .vscode/settings.json \
             && printf '\\tfsmonitor = /tmp/x\\n' >> sub/.git/config && cat sub/.git/config",
        )
        .await;
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
            staged_changes(&v, &x.paths("fs15"))
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
