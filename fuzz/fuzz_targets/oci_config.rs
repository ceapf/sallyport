//! Fuzz target: arbitrary bytes → the OCI config verifier (Task 14, #15, RT-SUP-04; architect
//! Q110: parse and verify, not parse alone). The bytes stand for the `config.json` podman wrote,
//! read back from a directory the subordinate root owns.
//!
//! Invariants: never panics; input over the bound is refused; a mismatch is printable ASCII
//! within its caps (it goes to the audit log); a config the verifier accepts parses.
#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use sallyd::sandbox::oci::config::{MAX_CONFIG, parse};
use sallyd::sandbox::oci::facts::{ContainerPaths, Facts, ImageConfig};
use sallyd::sandbox::oci::intent::{Intent, Wanted};
use sallyd::sandbox::oci::verify;
use sallyd::sandbox::{Role, UserIds};

/// The intent and facts of the seed corpus's config (`fuzz/corpus/oci_config/good.json`).
fn fixture() -> (Intent, Facts) {
    let mut i = Intent::begin(Role::Workspace, UserIds { uid: 1000, gid: 1000 }, "/s/profiles".into());
    i.tmp = Some((1_073_741_824, false));
    i.pids = Some(512);
    i.cpu_millis = Some(4000);
    i.memory = Some(8 * 1024 * 1024 * 1024);
    i.hostname = Some("sandbox".into());
    i.env = vec![("HTTP_PROXY".into(), "http://127.0.0.1:3128".into())];
    i.mounts = vec![
        Wanted::Bind { host: "/h/code/p".into(), guest: "/workspace/p".into(), rw: true },
        Wanted::Overlay {
            host: "/h/code/p/.git".into(),
            guest: "/workspace/p/.git".into(),
            upper: "/d/git/0/upper".into(),
            work: "/d/git/0/work".into(),
        },
        Wanted::Bind {
            host: "/r/sessions/s/workspace".into(),
            guest: "/run/sallyport".into(),
            rw: false,
        },
    ];
    i.image = format!("localhost/ws@sha256:{}", "e".repeat(64));
    i.command = vec!["/opt/sallyport/entry".into(), "--idle".into()];
    let id = "c".repeat(64);
    let g = "/h/.local/share/containers/storage";
    let s = format!("{g}/overlay-containers/{id}/userdata");
    let r = format!("/run/user/1000/containers/overlay-containers/{id}/userdata");
    let f = Facts {
        paths: ContainerPaths {
            config: format!("{s}/config.json"),
            hostname: format!("{r}/hostname"),
            rootfs: format!("{g}/overlay/{}/merged", "d".repeat(64)),
            static_dir: s,
            run_dir: r,
            id,
        },
        image: ImageConfig {
            env: Some(vec!["PATH=/usr/bin:/bin".into()]),
            entrypoint: None,
            working_dir: Some("/".into()),
            stop_signal: None,
        },
        init: "/usr/bin/catatonit".into(),
        arch: "x86_64",
        own_nofile: 1_048_576,
        own_nproc: 224_902,
    };
    (i, f)
}

fuzz_target!(|data: &[u8]| {
    let (i, f) = fixture();
    match verify(data, &i, &f) {
        Ok(()) => {
            assert!(data.len() <= MAX_CONFIG, "over the bound");
            assert!(parse(data).is_ok(), "accepted but does not parse");
        }
        Err(m) => {
            for part in [&m.field, &m.why] {
                assert!(part.bytes().all(|b| (0x20..0x7f).contains(&b)), "not printable: {part:?}");
                assert!(part.len() <= 200, "over the cap: {}", part.len());
            }
            if data.len() > MAX_CONFIG {
                assert_eq!(m.field, "config", "over the bound, refused late");
            }
        }
    }
});
