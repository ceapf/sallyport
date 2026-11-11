//! RT-FS-14: a bind-mount alias of a protected folder is refused at validation, by
//! `st_dev`/`st_ino` identity: the alias's path and realpath are ordinary, only its identity is
//! the protected folder's (or an ancestor's).
//!
//! The validator must see the alias, and an unprivileged user cannot bind-mount on the host. The
//! test therefore re-runs itself in a private mount namespace inside podman's rootless user
//! namespace (`podman unshare unshare -m`). Its mounts die with that namespace, so none reaches
//! the pause namespace that later podman calls share (CLAUDE.md); the outer run checks that.
//! Aliases of directories *inside* a protected folder are not detected: the same ancestry gap as
//! the overlap rule's re-review M-2 (#17, Task 14).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

use sally_core::manifest::{Code, HostEnv, load};

mod common;
use common::container::podman;
use common::*;

const INNER: &str = "SP_RT_FS_14_INNER";
const NAME: &str = "rt_fs_14_a_bind_alias_of_a_protected_folder_is_refused";
const DONE: &str = "RT-FS-14 inner: 3 cases checked";
const PREFIX: &str = "sallyd-argv-fs14-";

/// The inner run's directory, removed on drop (also when an assertion fails; the mounts die
/// with the namespace).
struct Root(std::path::PathBuf);

impl Drop for Root {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn rt_fs_14_a_bind_alias_of_a_protected_folder_is_refused() {
    if std::env::var_os(INNER).is_some() {
        return inner();
    }
    let exe = std::env::current_exe().unwrap();
    let flag = format!("{INNER}=1");
    let out = podman(&[
        "unshare",
        "unshare",
        "-m",
        "--propagation",
        "private",
        "env",
        &flag,
        exe.to_str().unwrap(),
        "--exact",
        NAME,
        "--nocapture",
        "--test-threads=1",
    ]);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "{text}");
    assert!(text.contains(DONE), "the inner run happened: {text}");
    let info = podman(&["unshare", "cat", "/proc/self/mountinfo"]);
    let info = String::from_utf8_lossy(&info.stdout);
    // Only this test's prefix: other tests' overlays live in the pause namespace meanwhile.
    assert!(
        !info.contains(PREFIX),
        "a test mount leaked into the pause namespace: {info}"
    );
}

fn bind(src: &Path, dst: &Path) {
    let st = Command::new("mount")
        .arg("--bind")
        .args([src, dst])
        .status()
        .unwrap();
    assert!(st.success(), "mount --bind {src:?} {dst:?}");
}

fn umount(dst: &Path) {
    let st = Command::new("umount").arg(dst).status().unwrap();
    assert!(st.success(), "umount {dst:?}");
}

/// Runs in the private mount namespace: binds `~/.ssh`, `~/.local` (an ancestor of protected
/// folders) and an ordinary directory under `~/code`, and validates a mount of each alias.
fn inner() {
    // Not `Fx`: its runtime check refuses the user namespace's view of host ownership, and the
    // validator needs only a `HostEnv`.
    let root = Root(
        Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("{PREFIX}{}", std::process::id())),
    );
    let _ = std::fs::remove_dir_all(&root.0);
    let home = root.0.join("home");
    for d in [".ssh", ".local/share/keyrings", "code/real"] {
        std::fs::create_dir_all(home.join(d)).unwrap();
    }
    let home = std::fs::canonicalize(home).unwrap();
    let env = HostEnv {
        home: home.clone(),
        other_homes: Vec::new(),
        xdg_config_home: None,
        xdg_data_home: None,
        xdg_runtime_dir: None,
        podman_storage: Vec::new(),
        nproc: 8,
        mem_bytes: 16 << 30,
    };
    let cases = [
        (".ssh", "alias-ssh", Some("is the same directory as")),
        (".local", "alias-local", Some("which contains")),
        ("code/real", "alias-real", None),
    ];
    for (src, alias, _) in &cases {
        let dst = home.join("code").join(alias);
        std::fs::create_dir(&dst).unwrap();
        bind(&home.join(src), &dst);
        // Control: path and realpath are ordinary, so only the identity can refuse it.
        assert_eq!(std::fs::canonicalize(&dst).unwrap(), dst);
    }
    for (_, alias, refused) in &cases {
        let body = mounts(&[mount(&format!("~/code/{alias}"), "/workspace/p", "ro")]);
        let r = load(&format!("{HEADER}{body}"), &env, &BTreeSet::new());
        match (refused, r) {
            (None, r) => assert!(r.is_ok(), "{alias}: {:#?}", r.err()),
            (Some(why), Ok(_)) => panic!("{alias}: accepted, want {why:?}"),
            (Some(why), Err(e)) => {
                let d = e.errors.first().unwrap();
                assert_eq!(e.errors.len(), 1, "{alias}: {e:#?}");
                assert_eq!(d.code, Code::Denylisted, "{alias}: {d:#?}");
                assert_eq!(d.path, "filesystem.mounts[0].host", "{alias}");
                assert!(d.message.contains(why), "{alias}: {}", d.message);
            }
        }
    }
    for (_, alias, _) in &cases {
        umount(&home.join("code").join(alias));
    }
    drop(root);
    println!("{DONE}");
}
