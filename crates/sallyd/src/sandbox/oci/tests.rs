//! The verifier against a config shaped as Podman 4.9.3 writes it (Task 14 probe), and one
//! tampered config per field class (architect Q99–Q112). The real configs are checked by the
//! container tests (`tests/oci.rs`).
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::path::PathBuf;

use serde_json::{Value, json};

use super::config::MAX_CONFIG;
use super::facts::{ContainerPaths, Facts, ImageConfig};
use super::intent::{Intent, Wanted};
use super::{Mismatch, seccomp, verify};
use crate::sandbox::profile;
use crate::sandbox::types::{Role, UserIds};

const G: &str = "/h/.local/share/containers/storage";
const R: &str = "/run/user/1000/containers";
const OWN_NOFILE: u64 = 1_048_576;
const OWN_NPROC: u64 = 224_902;
const MEM: u64 = 8 * 1024 * 1024 * 1024;

fn id() -> String {
    "c".repeat(64)
}

fn facts() -> Facts {
    let s = format!("{G}/overlay-containers/{}/userdata", id());
    let r = format!("{R}/overlay-containers/{}/userdata", id());
    Facts {
        paths: ContainerPaths {
            id: id(),
            config: format!("{s}/config.json"),
            hostname: format!("{r}/hostname"),
            rootfs: format!("{G}/overlay/{}/merged", "d".repeat(64)),
            static_dir: s,
            run_dir: r,
        },
        image: ImageConfig {
            env: Some(vec!["PATH=/usr/bin:/bin".into()]),
            entrypoint: None,
            working_dir: Some("/".into()),
            stop_signal: None,
        },
        init: "/usr/bin/catatonit".into(),
        arch: "x86_64",
        own_nofile: OWN_NOFILE,
        own_nproc: OWN_NPROC,
    }
}

fn intent() -> Intent {
    let mut i = Intent::begin(
        Role::Workspace,
        UserIds {
            uid: 1000,
            gid: 1000,
        },
        PathBuf::from("/s/profiles"),
    );
    i.tmp = Some((1_073_741_824, false));
    i.pids = Some(512);
    i.cpu_millis = Some(4000);
    i.memory = Some(MEM);
    i.hostname = Some("sandbox".into());
    i.env = vec![("HTTP_PROXY".into(), "http://127.0.0.1:3128".into())];
    i.mounts = vec![
        Wanted::Bind {
            host: "/h/code/p".into(),
            guest: "/workspace/p".into(),
            rw: true,
        },
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
    i
}

fn seccomp_json(role: Role) -> Value {
    let s = seccomp::expected(profile(role), "x86_64").unwrap();
    let rules: Vec<Value> = s
        .syscalls
        .iter()
        .map(|r| {
            let mut v = json!({"names": r.names, "action": r.action});
            if let Some(e) = r.errno_ret {
                v["errnoRet"] = json!(e);
            }
            if !r.args.is_empty() {
                v["args"] = r
                    .args
                    .iter()
                    .map(|a| json!({"index": a.index, "value": a.value, "op": a.op}))
                    .collect();
            }
            v
        })
        .collect();
    json!({"defaultAction": s.default_action, "defaultErrnoRet": s.default_errno_ret,
           "architectures": s.architectures, "syscalls": rules})
}

const USERDATA: [&str; 9] = [
    "bind", "rprivate", "ro", "nosuid", "noexec", "nodev", "nosuid", "noexec", "nodev",
];

fn mounts(i: &Intent, f: &Facts) -> Vec<Value> {
    let (s, r) = (&f.paths.static_dir, &f.paths.run_dir);
    let m = |d: &str, t: &str, src: &str, o: &[&str]| json!({"destination": d, "type": t, "source": src, "options": o});
    let mut out = vec![
        m("/proc", "proc", "proc", &["nosuid", "noexec", "nodev"]),
        m(
            "/dev",
            "tmpfs",
            "tmpfs",
            &["nosuid", "strictatime", "mode=755", "size=65536k", "ro"],
        ),
        m(
            "/dev/pts",
            "devpts",
            "devpts",
            &[
                "nosuid",
                "noexec",
                "newinstance",
                "ptmxmode=0666",
                "mode=0620",
                "gid=5",
            ],
        ),
        m(
            "/dev/mqueue",
            "mqueue",
            "mqueue",
            &["nosuid", "noexec", "nodev"],
        ),
        m("/dev/shm", "bind", &format!("{s}/shm"), &USERDATA),
        m(
            "/sys",
            "sysfs",
            "sysfs",
            &["nosuid", "noexec", "nodev", "ro"],
        ),
        m(
            "/tmp",
            "tmpfs",
            "tmpfs",
            &[
                "rw",
                "noexec",
                "nosuid",
                "nodev",
                "size=1073741824",
                "rprivate",
                "tmpcopyup",
            ],
        ),
    ];
    for w in &i.mounts {
        out.push(match w {
            Wanted::Bind { host, guest, rw } => m(
                guest,
                "bind",
                host,
                &[
                    if *rw { "rw" } else { "ro" },
                    "nosuid",
                    "nodev",
                    "bind",
                    "rprivate",
                ],
            ),
            Wanted::Overlay {
                host,
                guest,
                upper,
                work,
            } => m(
                guest,
                "overlay",
                &format!("{s}/overlay/3309457846/merge"),
                &[
                    &format!("lowerdir={host}"),
                    &format!("upperdir={upper}"),
                    &format!("workdir={work}"),
                    "private",
                    "userxattr",
                ],
            ),
        });
    }
    out.extend([
        m(
            "/run/podman-init",
            "bind",
            &f.init,
            &["bind", "ro", "rprivate"],
        ),
        m(
            "/etc/passwd",
            "bind",
            &format!("{s}/passwd"),
            &USERDATA[..6],
        ),
        m("/etc/group", "bind", &format!("{s}/group"), &USERDATA[..6]),
        m(
            "/run/.containerenv",
            "bind",
            &format!("{r}/.containerenv"),
            &USERDATA[..6],
        ),
        m("/etc/hostname", "bind", &f.paths.hostname, &USERDATA[..6]),
        m(
            "/sys/fs/cgroup",
            "cgroup",
            "cgroup",
            &["rprivate", "nosuid", "noexec", "nodev", "relatime", "ro"],
        ),
    ]);
    out
}

/// What Podman 4.9.3 writes for `i` (the probe's shape).
fn good(i: &Intent, f: &Facts) -> Value {
    let mut env = vec![
        "PATH=/usr/bin:/bin".to_owned(),
        "container=podman".to_owned(),
    ];
    env.extend(i.env.iter().map(|(n, v)| format!("{n}={v}")));
    let host = i.hostname.clone().unwrap_or_else(|| id()[..12].to_owned());
    env.extend([format!("HOSTNAME={host}"), "HOME=/".to_owned()]);
    let mut args = vec!["/run/podman-init".to_owned(), "--".to_owned()];
    args.extend(i.command.iter().cloned());
    let mut resources =
        json!({"cpu": {"quota": 400_000, "period": 100_000}, "pids": {"limit": 512}});
    if let Some(m) = i.memory {
        resources["memory"] = json!({"limit": m, "swap": m});
    }
    let map = json!([
        {"containerID": 0, "hostID": 1, "size": 1000},
        {"containerID": 1000, "hostID": 0, "size": 1},
        {"containerID": 1001, "hostID": 1001, "size": 64536}
    ]);
    let namespaces: Vec<Value> = super::linux::NAMESPACES
        .iter()
        .map(|t| json!({"type": t}))
        .collect();
    json!({
        "ociVersion": "1.1.0",
        "process": {
            "user": {"uid": 1000, "gid": 1000, "umask": 18, "additionalGids": [1000]},
            "args": args,
            "env": env,
            "cwd": "/",
            "capabilities": {},
            "rlimits": [
                {"type": "RLIMIT_CORE", "hard": 0, "soft": 0},
                {"type": "RLIMIT_NOFILE", "hard": OWN_NOFILE, "soft": OWN_NOFILE},
                {"type": "RLIMIT_NPROC", "hard": OWN_NPROC, "soft": OWN_NPROC}
            ],
            "noNewPrivileges": true
        },
        "root": {"path": f.paths.rootfs, "readonly": true},
        "hostname": host,
        "mounts": mounts(i, f),
        "annotations": {
            "io.container.manager": "libpod",
            "io.podman.annotations.autoremove": "TRUE",
            "io.podman.annotations.init": "TRUE",
            "io.podman.annotations.label": "disable",
            "io.podman.annotations.seccomp": format!("/s/profiles/{}", i.role.profile()),
            "org.opencontainers.image.stopSignal": "15"
        },
        "linux": {
            "uidMappings": map.clone(),
            "gidMappings": map,
            "resources": resources,
            "cgroupsPath": format!("user.slice:libpod:{}", id()),
            "namespaces": namespaces,
            "seccomp": seccomp_json(i.role),
            "maskedPaths": super::linux::MASKED,
            "readonlyPaths": super::linux::READONLY
        }
    })
}

fn check(v: &Value, i: &Intent, f: &Facts) -> Result<(), Mismatch> {
    verify(v.to_string().as_bytes(), i, f)
}

/// `edit` of the good config is refused, on a field starting with `field`.
#[track_caller]
fn refused(field: &str, edit: impl FnOnce(&mut Value)) -> Mismatch {
    refused_with(field, &intent(), &facts(), edit)
}

#[track_caller]
fn refused_with(field: &str, i: &Intent, f: &Facts, edit: impl FnOnce(&mut Value)) -> Mismatch {
    let mut v = good(i, f);
    edit(&mut v);
    let e = check(&v, i, f).unwrap_err();
    assert!(e.field.starts_with(field), "{e}");
    e
}

fn mount_mut<'a>(v: &'a mut Value, dest: &str) -> &'a mut Value {
    v["mounts"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|m| m["destination"] == dest)
        .unwrap()
}

#[test]
fn the_config_podman_writes_for_each_role_passes() {
    let f = facts();
    check(&good(&intent(), &f), &intent(), &f).unwrap();
    let mut h = intent();
    h.role = Role::Harness;
    check(&good(&h, &f), &h, &f).unwrap();
    let mut inf = intent();
    inf.role = Role::Inference;
    inf.hostname = None;
    inf.memory = None;
    check(&good(&inf, &f), &inf, &f).unwrap();
}

#[test]
fn an_unknown_missing_or_repeated_key_anywhere_is_a_mismatch() {
    let e = refused("config", |v| v["hooks"] = json!({}));
    assert_eq!(e.why, "unknown key hooks");
    refused("process", |v| v["process"]["terminal"] = json!(false));
    refused("process", |v| v["process"]["user"]["username"] = json!("x"));
    refused("process", |v| v["process"]["capabilities"]["x"] = json!([]));
    refused("linux", |v| v["linux"]["devices"] = json!([]));
    refused("linux", |v| v["linux"]["sysctl"] = json!({}));
    refused("linux", |v| v["linux"]["resources"]["devices"] = json!([]));
    refused("linux", |v| v["linux"]["seccomp"]["flags"] = json!([]));
    refused("linux", |v| v["linux"]["namespaces"][0]["x"] = json!(1));
    refused("mounts", |v| v["mounts"][0]["uidMappings"] = json!([]));
    refused("root", |v| v["root"]["x"] = json!(1));
    let e = refused("linux", |v| {
        v["linux"].as_object_mut().unwrap().remove("seccomp");
    });
    assert_eq!(e.why, "missing key seccomp");
    refused("config", |v| {
        v.as_object_mut().unwrap().remove("linux");
    });
    // A wrong type is named without its value.
    let e = refused("process", |v| {
        v["process"]["user"]["uid"] = json!("secret-ish")
    });
    assert!(!e.to_string().contains("secret-ish"), "{e}");
    // A repeated key, even inside annotations, where a map would keep the last one.
    let (i, f) = (intent(), facts());
    let text = good(&i, &f).to_string().replacen(
        "\"io.container.manager\":\"libpod\"",
        "\"io.container.manager\":\"libpod\",\"io.container.manager\":\"other\"",
        1,
    );
    assert_eq!(verify(text.as_bytes(), &i, &f).unwrap_err().field, "config");
    assert!(verify(b"\xff", &i, &f).is_err());
    // serde would fill a struct from an array by position; a section must be an object.
    for section in ["process", "root", "linux", "annotations"] {
        let mut v = good(&i, &f);
        v[section] = json!([]);
        let e = check(&v, &i, &f).unwrap_err();
        assert_eq!(
            (e.field.as_str(), e.why.as_str()),
            (section, "not an object")
        );
    }
    assert_eq!(verify(b"[]", &i, &f).unwrap_err().why, "not an object");
    assert!(verify(format!("{} {{}}", good(&i, &f)).as_bytes(), &i, &f).is_err());
}

#[test]
fn the_size_bound_is_exactly_max_config() {
    let (i, f) = (intent(), facts());
    let base = good(&i, &f).to_string();
    let padded = format!("{base}{}", " ".repeat(MAX_CONFIG - base.len()));
    assert_eq!(padded.len(), MAX_CONFIG);
    verify(padded.as_bytes(), &i, &f).unwrap();
    let e = verify(format!("{padded} ").as_bytes(), &i, &f).unwrap_err();
    assert_eq!(
        (e.field.as_str(), e.why.as_str()),
        ("config", "over the size bound")
    );
}

#[test]
fn the_version_user_and_groups_are_exact() {
    refused("ociVersion", |v| v["ociVersion"] = json!("1.0.2"));
    refused("process.user.uid", |v| {
        v["process"]["user"]["uid"] = json!(0)
    });
    refused("process.user.gid", |v| {
        v["process"]["user"]["gid"] = json!(0)
    });
    for g in [json!([]), json!([1000, 27]), json!([27])] {
        refused("process.user.additionalGids", |v| {
            v["process"]["user"]["additionalGids"] = g;
        });
    }
    refused("process.user.umask", |v| {
        v["process"]["user"]["umask"] = json!(0)
    });
    refused("process.user.umask", |v| {
        v["process"]["user"]
            .as_object_mut()
            .unwrap()
            .remove("umask");
    });
}

#[test]
fn the_command_is_exactly_the_built_one_after_init() {
    refused("process.args", |v| {
        v["process"]["args"][3] = json!("--other")
    });
    refused("process.args", |v| {
        v["process"]["args"].as_array_mut().unwrap().remove(0);
    });
    refused("process.args", |v| {
        v["process"]["args"]
            .as_array_mut()
            .unwrap()
            .push(json!("x"));
    });
    // An image entrypoint is refused even when the args happen to match (TODO(#117)).
    let mut f = facts();
    f.image.entrypoint = Some(vec!["/e".into()]);
    let e = refused_with("process.args", &intent(), &f, |_| {});
    assert!(e.why.contains("entrypoint"), "{e}");
    f.image.entrypoint = Some(Vec::new());
    check(&good(&intent(), &f), &intent(), &f).unwrap();
}

#[test]
fn the_environment_is_exactly_image_podman_and_argv_with_values_never_shown() {
    let e = refused("process.env.EXTRA", |v| {
        v["process"]["env"]
            .as_array_mut()
            .unwrap()
            .push(json!("EXTRA=hidden-value"));
    });
    assert!(!e.to_string().contains("hidden-value"), "{e}");
    let e = refused("process.env.HTTP_PROXY", |v| {
        let env = v["process"]["env"].as_array_mut().unwrap();
        let k = env
            .iter()
            .position(|x| x.as_str().unwrap().starts_with("HTTP_PROXY"))
            .unwrap();
        env[k] = json!("HTTP_PROXY=http://evil-value");
    });
    assert!(!e.to_string().contains("evil-value"), "{e}");
    refused("process.env.HTTP_PROXY", |v| {
        let env = v["process"]["env"].as_array_mut().unwrap();
        env.retain(|x| !x.as_str().unwrap().starts_with("HTTP_PROXY"));
    });
    refused("process.env.PATH", |v| {
        v["process"]["env"]
            .as_array_mut()
            .unwrap()
            .push(json!("PATH=/x"));
    });
    refused("process.env", |v| {
        v["process"]["env"]
            .as_array_mut()
            .unwrap()
            .push(json!("NOEQUALS"));
    });
    refused("process.env", |v| {
        v["process"]["env"]
            .as_array_mut()
            .unwrap()
            .push(json!("=v"));
    });
    refused("process.env.HOME", |v| {
        let env = v["process"]["env"].as_array_mut().unwrap();
        env.retain(|x| x != "HOME=/");
        env.push(json!("HOME=/root"));
    });
    refused("process.env.HOSTNAME", |v| {
        let env = v["process"]["env"].as_array_mut().unwrap();
        env.retain(|x| x != "HOSTNAME=sandbox");
        env.push(json!("HOSTNAME=other"));
    });
    refused("process.env.container", |v| {
        let env = v["process"]["env"].as_array_mut().unwrap();
        env.retain(|x| x != "container=podman");
    });
    // The image's own HOME and variables are kept; a bad image entry is refused.
    let mut f = facts();
    f.image.env = Some(vec!["PATH=/usr/bin:/bin".into(), "HOME=/var/x".into()]);
    let mut v = good(&intent(), &f);
    let env = v["process"]["env"].as_array_mut().unwrap();
    env.retain(|x| x != "HOME=/");
    env.push(json!("HOME=/var/x"));
    check(&v, &intent(), &f).unwrap();
    f.image.env = Some(vec!["BROKEN".into()]);
    refused_with("image.Env", &intent(), &f, |_| {});
}

#[test]
fn the_working_directory_is_the_image_s() {
    refused("process.cwd", |v| v["process"]["cwd"] = json!("/tmp"));
    let mut f = facts();
    f.image.working_dir = Some("/w".into());
    refused_with("process.cwd", &intent(), &f, |_| {});
    let mut v = good(&intent(), &f);
    v["process"]["cwd"] = json!("/w");
    check(&v, &intent(), &f).unwrap();
    for wd in [None, Some(String::new())] {
        f.image.working_dir = wd;
        check(&good(&intent(), &f), &intent(), &f).unwrap();
    }
}

#[test]
fn every_capability_set_is_empty() {
    for set in [
        "bounding",
        "effective",
        "inheritable",
        "permitted",
        "ambient",
    ] {
        refused(&format!("process.capabilities.{set}"), |v| {
            v["process"]["capabilities"][set] = json!(["CAP_CHOWN"]);
        });
    }
    let mut v = good(&intent(), &facts());
    v["process"]["capabilities"]["bounding"] = json!([]);
    check(&v, &intent(), &facts()).unwrap();
}

fn rlimits(v: &mut Value) -> &mut Vec<Value> {
    v["process"]["rlimits"].as_array_mut().unwrap()
}

#[test]
fn rlimits_are_core_zero_and_podman_s_two_within_sallyd_s_own() {
    let set = |k: usize, hard: u64, soft: u64| {
        move |v: &mut Value| {
            rlimits(v)[k]["hard"] = json!(hard);
            rlimits(v)[k]["soft"] = json!(soft);
        }
    };
    refused("process.rlimits.RLIMIT_CORE", set(0, 1, 0));
    refused("process.rlimits.RLIMIT_CORE", set(0, 0, 1));
    refused("process.rlimits.RLIMIT_NOFILE", set(1, OWN_NOFILE + 1, 1));
    refused("process.rlimits.RLIMIT_NPROC", set(2, OWN_NPROC + 1, 1));
    refused("process.rlimits.RLIMIT_NOFILE", set(1, 10, 11));
    let (i, f) = (intent(), facts());
    let mut v = good(&i, &f);
    set(1, OWN_NOFILE, 10)(&mut v);
    set(2, OWN_NPROC, OWN_NPROC)(&mut v);
    check(&v, &i, &f).unwrap();
    refused("process.rlimits.RLIMIT_AS", |v| {
        rlimits(v).push(json!({"type": "RLIMIT_AS", "hard": 1, "soft": 1}));
    });
    refused("process.rlimits.RLIMIT_CORE", |v| {
        rlimits(v).push(json!({"type": "RLIMIT_CORE", "hard": 0, "soft": 0}));
    });
    for k in 0..3 {
        refused("process.rlimits", |v| {
            rlimits(v).remove(k);
        });
    }
    // Unlimited: sallyd's own RLIM_INFINITY admits podman's unlimited too.
    let mut f = facts();
    f.own_nproc = u64::MAX;
    let mut v = good(&i, &f);
    set(2, u64::MAX, u64::MAX)(&mut v);
    check(&v, &i, &f).unwrap();
}

#[test]
fn no_new_privileges_and_the_read_only_root_are_required() {
    refused("process.noNewPrivileges", |v| {
        v["process"]["noNewPrivileges"] = json!(false)
    });
    refused("process.noNewPrivileges", |v| {
        v["process"]
            .as_object_mut()
            .unwrap()
            .remove("noNewPrivileges");
    });
    refused("root.readonly", |v| v["root"]["readonly"] = json!(false));
    refused("root.path", |v| v["root"]["path"] = json!("/"));
}

#[test]
fn the_hostname_is_the_argv_s_or_the_short_id() {
    refused("hostname", |v| v["hostname"] = json!("other"));
    let mut i = intent();
    i.hostname = None;
    let f = facts();
    check(&good(&i, &f), &i, &f).unwrap();
    refused_with("hostname", &i, &f, |v| v["hostname"] = json!("sandbox"));
}

#[test]
fn annotations_are_exact() {
    refused("annotations.x", |v| v["annotations"]["x"] = json!("y"));
    refused("annotations.io.podman.annotations.label", |v| {
        v["annotations"]
            .as_object_mut()
            .unwrap()
            .remove("io.podman.annotations.label");
    });
    refused("annotations.io.podman.annotations.seccomp", |v| {
        v["annotations"]["io.podman.annotations.seccomp"] = json!("/s/profiles/other.json");
    });
    refused("annotations.io.podman.annotations.autoremove", |v| {
        v["annotations"]["io.podman.annotations.autoremove"] = json!("FALSE");
    });
    let mut v = good(&intent(), &facts());
    v.as_object_mut().unwrap().remove("annotations");
    assert!(
        check(&v, &intent(), &facts())
            .unwrap_err()
            .field
            .starts_with("annotations.")
    );
}

#[test]
fn the_stop_signal_is_15_sigterm_or_a_decimal() {
    let mut f = facts();
    for (image, annotation) in [("SIGTERM", "15"), ("9", "9"), ("1", "1"), ("64", "64")] {
        f.image.stop_signal = Some(image.into());
        let mut v = good(&intent(), &f);
        v["annotations"]["org.opencontainers.image.stopSignal"] = json!(annotation);
        check(&v, &intent(), &f).unwrap();
        if annotation != "15" {
            refused_with(
                "annotations.org.opencontainers.image.stopSignal",
                &intent(),
                &f,
                |_| {},
            );
        }
    }
    for bad in ["SIGKILL", "0", "65", "09", "+9", ""] {
        f.image.stop_signal = Some(bad.into());
        refused_with("image.StopSignal", &intent(), &f, |_| {});
    }
}

#[test]
fn every_namespace_is_its_own() {
    let ns = |v: &mut Value| v["linux"]["namespaces"].as_array_mut().unwrap().clone();
    refused("linux.namespaces", |v| {
        v["linux"]["namespaces"].as_array_mut().unwrap().remove(5);
    });
    refused("linux.namespaces.time", |v| {
        v["linux"]["namespaces"]
            .as_array_mut()
            .unwrap()
            .push(json!({"type": "time"}));
    });
    refused("linux.namespaces.pid", |v| {
        let first = ns(v)[0].clone();
        v["linux"]["namespaces"].as_array_mut().unwrap()[1] = first;
    });
    refused("linux.namespaces.network", |v| {
        v["linux"]["namespaces"][1]["path"] = json!("/proc/1/ns/net");
    });
}

#[test]
fn id_maps_have_the_keep_id_shape() {
    for field in ["uidMappings", "gidMappings"] {
        let at = format!("linux.{field}");
        let put = |maps: Value| move |v: &mut Value| v["linux"][field] = maps;
        refused(
            &at,
            put(json!([{"containerID": 0, "hostID": 0, "size": 1}])),
        );
        refused(
            &at,
            put(json!([{"containerID": 1000, "hostID": 0, "size": 2}])),
        );
        refused(
            &at,
            put(json!([{"containerID": 1000, "hostID": 0, "size": 1},
                       {"containerID": 5, "hostID": 0, "size": 1}])),
        );
        refused(
            &at,
            put(json!([{"containerID": 1000, "hostID": 0, "size": 1},
                       {"containerID": 0, "hostID": 1, "size": 1001}])),
        );
        refused(
            &at,
            put(json!([{"containerID": 1000, "hostID": 0, "size": 1},
                       {"containerID": 0, "hostID": 1, "size": 10},
                       {"containerID": 20, "hostID": 5, "size": 10}])),
        );
        refused(
            &at,
            put(json!([{"containerID": 1000, "hostID": 0, "size": 1},
                       {"containerID": 1001, "hostID": 4_294_967_295_u32, "size": 2}])),
        );
        refused(
            &at,
            put(json!([{"containerID": 1000, "hostID": 0, "size": 1},
                       {"containerID": 0, "hostID": 1, "size": 0}])),
        );
        refused(
            &at,
            put(json!([{"containerID": 0, "hostID": 1, "size": 1000}])),
        );
        refused(&at, put(json!([])));
    }
    let mut v = good(&intent(), &facts());
    v["linux"]["uidMappings"] = json!([{"containerID": 1000, "hostID": 0, "size": 1},
        {"containerID": 4_294_967_294_u32, "hostID": 1, "size": 2}]);
    check(&v, &intent(), &facts()).unwrap();
}

/// At most the 340 lines the kernel accepts in an id map, checked before the pairwise overlap
/// scan (which a 1 MiB config could otherwise make quadratic over ~25k entries).
#[test]
fn an_id_map_longer_than_the_kernel_accepts_is_refused() {
    let maps = |n: u32| {
        let mut m = vec![json!({"containerID": 1000, "hostID": 0, "size": 1})];
        m.extend((1..n).map(|k| json!({"containerID": 2000 + k, "hostID": 10 + k, "size": 1})));
        Value::Array(m)
    };
    let mut v = good(&intent(), &facts());
    v["linux"]["uidMappings"] = maps(340);
    check(&v, &intent(), &facts()).unwrap();
    let e = refused("linux.gidMappings", |v| {
        v["linux"]["gidMappings"] = maps(341)
    });
    assert_eq!(e.why, "more mappings than the kernel accepts");
}

#[test]
fn resources_are_exactly_the_argv_s_with_no_swap() {
    let r = "linux.resources";
    refused(r, |v| {
        v["linux"]["resources"]["memory"]["swap"] = json!(2 * MEM)
    });
    refused(r, |v| {
        v["linux"]["resources"]["memory"]["limit"] = json!(MEM + 1)
    });
    refused(r, |v| {
        v["linux"]["resources"]["memory"]
            .as_object_mut()
            .unwrap()
            .remove("swap");
    });
    refused(r, |v| {
        v["linux"]["resources"]
            .as_object_mut()
            .unwrap()
            .remove("memory");
    });
    refused(r, |v| {
        v["linux"]["resources"]["cpu"]["quota"] = json!(400_001)
    });
    refused(r, |v| {
        v["linux"]["resources"]["cpu"]["period"] = json!(50_000)
    });
    refused(r, |v| v["linux"]["resources"]["pids"]["limit"] = json!(513));
    refused(r, |v| {
        v["linux"]["resources"]
            .as_object_mut()
            .unwrap()
            .remove("pids");
    });
    let mut i = intent();
    i.memory = None;
    refused_with(r, &i, &facts(), |v| {
        v["linux"]["resources"]["memory"] = json!({"limit": MEM, "swap": MEM});
    });
    i.memory = Some(u64::MAX);
    assert_eq!(
        check(&good(&intent(), &facts()), &i, &facts())
            .unwrap_err()
            .why,
        "a limit does not fit"
    );
}

#[test]
fn the_cgroup_path_seccomp_and_masked_paths_are_checked() {
    refused("linux.cgroupsPath", |v| {
        v["linux"]["cgroupsPath"] = json!(format!("/libpod_parent/libpod-{}", id()));
    });
    refused("linux.seccomp", |v| {
        v["linux"]["seccomp"]["defaultAction"] = json!("SCMP_ACT_ALLOW")
    });
    refused("linux.seccomp", |v| {
        v["linux"]["seccomp"]["syscalls"][0]["action"] = json!("SCMP_ACT_ALLOW");
    });
    refused("linux.seccomp", |v| {
        v["linux"]["seccomp"]["syscalls"]
            .as_array_mut()
            .unwrap()
            .pop();
    });
    refused("linux.seccomp", |v| {
        let s = v["linux"]["seccomp"]["syscalls"].as_array_mut().unwrap();
        s.swap(0, 1);
    });
    // The harness filter in a workspace container is the wrong role's only if they differ: the
    // inference filter is.
    refused("linux.seccomp", |v| {
        v["linux"]["seccomp"] = seccomp_json(Role::Inference)
    });
    let mut f = facts();
    f.arch = "riscv64";
    refused_with("linux.seccomp", &intent(), &f, |_| {});
    refused("linux.maskedPaths", |v| {
        v["linux"]["maskedPaths"].as_array_mut().unwrap().remove(1);
    });
    refused("linux.readonlyPaths", |v| {
        v["linux"]["readonlyPaths"].as_array_mut().unwrap().pop();
    });
    let mut v = good(&intent(), &facts());
    v["linux"]["maskedPaths"]
        .as_array_mut()
        .unwrap()
        .push(json!("/proc/extra"));
    v["linux"]["readonlyPaths"]
        .as_array_mut()
        .unwrap()
        .push(json!("/proc/extra"));
    check(&v, &intent(), &facts()).unwrap();
}

#[test]
fn gpu_inference_is_refused_until_m3() {
    let mut i = intent();
    i.gpu = true;
    let f = facts();
    let e = check(&good(&i, &f), &i, &f).unwrap_err();
    assert_eq!(e.field, "linux.devices");
}

#[test]
fn mounts_are_exactly_the_intended_set() {
    refused("mounts[/hostile]", |v| {
        v["mounts"].as_array_mut().unwrap().push(json!({
            "destination": "/hostile", "type": "bind", "source": "/h", "options": ["ro"]}));
    });
    refused("mounts[/run/sallyport]", |v| {
        v["mounts"]
            .as_array_mut()
            .unwrap()
            .retain(|m| m["destination"] != "/run/sallyport");
    });
    refused("mounts[/run/secrets]", |v| {
        v["mounts"].as_array_mut().unwrap().push(json!({
            "destination": "/run/secrets", "type": "bind", "source": "/x", "options": []}));
    });
    refused("mounts[/proc]", |v| {
        let first = v["mounts"][0].clone();
        v["mounts"].as_array_mut().unwrap().push(first);
    });
    refused("mounts[/proc/../x]", |v| {
        v["mounts"][0]["destination"] = json!("/proc/../x")
    });
    refused("mounts[/workspace/p/]", |v| {
        mount_mut(v, "/workspace/p")["destination"] = json!("/workspace/p/");
    });
}

/// The `oci_config` fuzz target's seed is a config the verifier accepts for this fixture (the
/// target's fixture is the same), so the fuzzer starts from the accepting path.
#[test]
fn the_fuzz_seed_is_an_accepted_config() {
    let seed = include_bytes!("../../../../../fuzz/corpus/oci_config/good.json");
    verify(seed, &intent(), &facts()).unwrap();
}

/// A mount podman adds of its own accord is refused whatever reached it: a `mounts.conf`
/// subscription (user, `/etc/containers` or `/usr/share/containers`), in exactly the shape
/// Podman 4.9.3 writes (probed in Task 14: a copy in the run directory, bound `bind,rprivate`),
/// and a FIPS-mode host's `system-fips` file (such hosts: #121).
#[test]
fn a_subscription_mount_podman_adds_is_refused() {
    let run = facts().paths.run_dir;
    for name in ["x", "system-fips"] {
        let dest = format!("/run/secrets/{name}");
        let source = format!("{run}/run/secrets/{name}");
        let m = refused(&format!("mounts[{dest}]"), |v| {
            v["mounts"].as_array_mut().unwrap().push(json!({
                "destination": dest, "type": "bind", "source": source,
                "options": ["bind", "rprivate"]}));
        });
        assert_eq!(m.why, "not intended");
    }
}

#[test]
fn each_mount_has_exactly_its_type_source_and_options() {
    let set = |dest: &'static str, key: &'static str, val: Value| {
        move |v: &mut Value| mount_mut(v, dest)[key] = val
    };
    let field = |d: &str| format!("mounts[{d}]");
    refused(
        &field("/workspace/p"),
        set("/workspace/p", "source", json!("/h/other")),
    );
    refused(
        &field("/workspace/p"),
        set("/workspace/p", "type", json!("rbind")),
    );
    let e = refused(
        &field("/run/sallyport"),
        set(
            "/run/sallyport",
            "options",
            json!(["rw", "nosuid", "nodev", "bind", "rprivate"]),
        ),
    );
    assert_eq!(e.why, "option rw not intended");
    let e = refused(
        &field("/workspace/p"),
        set(
            "/workspace/p",
            "options",
            json!(["rw", "nodev", "bind", "rprivate"]),
        ),
    );
    assert_eq!(e.why, "option nosuid missing");
    // An option's value (a host path in `lowerdir=`) never reaches the audit detail.
    let e = refused(
        &field("/workspace/p"),
        set(
            "/workspace/p",
            "options",
            json!([
                "rw",
                "nosuid",
                "nodev",
                "bind",
                "rprivate",
                "lowerdir=/h/secret"
            ]),
        ),
    );
    assert_eq!(e.why, "option lowerdir not intended");
    refused(
        &field("/workspace/p"),
        set(
            "/workspace/p",
            "options",
            json!(["rw", "nosuid", "bind", "rprivate"]),
        ),
    );
    refused(
        &field("/workspace/p"),
        set(
            "/workspace/p",
            "options",
            json!(["rw", "nosuid", "nodev", "bind", "rprivate", "suid"]),
        ),
    );
    // Repeated options are one option (podman's /dev/shm), but ro and rw together are not.
    refused(
        &field("/run/sallyport"),
        set(
            "/run/sallyport",
            "options",
            json!(["ro", "rw", "nosuid", "nodev", "bind", "rprivate"]),
        ),
    );
    for (dest, src) in [
        ("/run/podman-init", "/usr/local/bin/catatonit"),
        ("/etc/hostname", "/run/user/1000/containers/other/hostname"),
        ("/etc/passwd", "/etc/passwd"),
        ("/dev/shm", "/dev/shm"),
        ("/proc", "/proc"),
    ] {
        refused(&field(dest), set(dest, "source", json!(src)));
    }
}

#[test]
fn an_overlay_has_exactly_its_granted_layers() {
    let d = "/workspace/p/.git";
    let s = facts().paths.static_dir;
    let opts = |lower: &str, upper: &str, work: &str| {
        json!([
            format!("lowerdir={lower}"),
            format!("upperdir={upper}"),
            format!("workdir={work}"),
            "private",
            "userxattr"
        ])
    };
    for o in [
        opts("/h/code/other/.git", "/d/git/0/upper", "/d/git/0/work"),
        opts("/h/code/p/.git", "/d/git/1/upper", "/d/git/0/work"),
        opts("/h/code/p/.git", "/d/git/0/upper", "/tmp/work"),
        json!([
            "lowerdir=/h/code/p/.git",
            "upperdir=/d/git/0/upper",
            "workdir=/d/git/0/work"
        ]),
    ] {
        refused(&format!("mounts[{d}]"), |v| mount_mut(v, d)["options"] = o);
    }
    for src in [
        format!("{s}/overlay/x1/merge"),
        format!("{s}/overlay//merge"),
        format!("{s}/overlay/1/merged"),
        "/elsewhere/overlay/1/merge".to_owned(),
        "/h/code/p/.git".to_owned(),
    ] {
        refused(&format!("mounts[{d}]"), |v| {
            mount_mut(v, d)["source"] = json!(src)
        });
    }
}

#[test]
fn a_parent_mounted_after_its_child_is_refused() {
    let e = refused("mounts[/workspace/p]", |v| {
        let ms = v["mounts"].as_array_mut().unwrap();
        let p = ms
            .iter()
            .position(|m| m["destination"] == "/workspace/p")
            .unwrap();
        let parent = ms.remove(p);
        ms.push(parent);
    });
    assert!(e.why.contains("/workspace/p/.git"), "{e}");
    refused("mounts[/dev]", |v| {
        let ms = v["mounts"].as_array_mut().unwrap();
        let dev = ms.remove(1);
        ms.push(dev);
    });
    // Siblings with a shared prefix are not parent and child.
    let mut i = intent();
    i.mounts.push(Wanted::Bind {
        host: "/h/q".into(),
        guest: "/workspace/pq".into(),
        rw: false,
    });
    let f = facts();
    let mut v = good(&i, &f);
    let ms = v["mounts"].as_array_mut().unwrap();
    let k = ms
        .iter()
        .position(|m| m["destination"] == "/workspace/pq")
        .unwrap();
    let pq = ms.remove(k);
    ms.insert(0, pq);
    check(&v, &i, &f).unwrap();
}

#[test]
fn a_mismatch_is_escaped_and_capped() {
    let e = Mismatch::new(format!("mounts[/a\u{1b}[31m{}]", "x".repeat(500)), "why\n");
    assert!(
        !e.field.contains('\u{1b}') && !e.why.contains('\n'),
        "{e:?}"
    );
    assert!(e.field.len() < 220, "{}", e.field.len());
    assert_eq!(e.to_string(), format!("{}: {}", e.field, e.why));
}
