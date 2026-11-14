//! What the verifier needs besides the intent, read through hermetic podman at launch time and
//! checked here (architect Q99, Q101, Q116: the checks are decisions, so they are pure and in the
//! mutation scope): the container's own directories from `podman inspect`, and the image's
//! `Config`.

use serde::Deserialize;

use super::Mismatch;

/// The `podman inspect --format` template whose output [`ContainerPaths::parse`] reads: one JSON
/// object, every value JSON-escaped by the template.
pub const INSPECT_FORMAT: &str = "{\"static\":{{json .StaticDir}},\"config\":{{json .OCIConfigPath}},\
     \"hostname\":{{json .HostnamePath}},\"rootfs\":{{json .GraphDriver.Data.MergedDir}}}";

/// The `podman image inspect --format` template whose output [`ImageConfig::parse`] reads.
pub const IMAGE_FORMAT: &str = "{{json .Config}}";

/// The largest `podman inspect` or `podman image inspect` output accepted.
pub const MAX_INSPECT: usize = 65_536;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inspected {
    #[serde(rename = "static")]
    static_dir: String,
    config: String,
    hostname: String,
    rootfs: String,
}

/// The container's own directories, checked against its id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerPaths {
    /// The container id (64 lowercase hex digits).
    pub id: String,
    /// `<graphroot>/overlay-containers/<id>/userdata`.
    pub static_dir: String,
    /// `<runroot>/overlay-containers/<id>/userdata`.
    pub run_dir: String,
    /// `<static_dir>/config.json`.
    pub config: String,
    /// `<run_dir>/hostname`.
    pub hostname: String,
    /// `<graphroot>/overlay/<layer>/merged`.
    pub rootfs: String,
}

fn inspect_err(why: impl AsRef<str>) -> Mismatch {
    Mismatch::new("inspect", why)
}

/// 64 lowercase hex digits.
#[must_use]
pub fn is_id(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// An absolute path of plain segments: no empty, `.` or `..` segment, no trailing `/`, no
/// control character.
#[must_use]
pub fn is_clean(p: &str) -> bool {
    p.strip_prefix('/').is_some_and(|rest| {
        !rest.is_empty()
            && !p.chars().any(char::is_control)
            && rest
                .split('/')
                .all(|s| !s.is_empty() && s != "." && s != "..")
    })
}

/// The `<root>` of `<root>/overlay-containers/<id>/userdata`, when `dir` has that form.
fn userdata_root<'a>(dir: &'a str, id: &str) -> Option<&'a str> {
    let root = dir.strip_suffix(&format!("/overlay-containers/{id}/userdata"))?;
    (is_clean(root)).then_some(root)
}

impl ContainerPaths {
    /// Checks the output of `podman inspect --format` [`INSPECT_FORMAT`] for container `id`.
    ///
    /// # Errors
    /// A [`Mismatch`] on field `inspect` naming what is wrong.
    pub fn parse(out: &[u8], id: &str) -> Result<Self, Mismatch> {
        if out.len() > MAX_INSPECT {
            return Err(inspect_err("over the size bound"));
        }
        if !is_id(id) {
            return Err(inspect_err("not a container id"));
        }
        let text = std::str::from_utf8(out).map_err(|_| inspect_err("not UTF-8"))?;
        let value = crate::rpc::json::parse(text.trim_end_matches('\n').as_bytes())
            .ok()
            .filter(serde_json::Value::is_object)
            .ok_or_else(|| inspect_err("not one strict JSON object"))?;
        let i: Inspected =
            serde_json::from_value(value).map_err(|_| inspect_err("not the expected fields"))?;
        for (name, p) in [
            ("static", &i.static_dir),
            ("config", &i.config),
            ("hostname", &i.hostname),
            ("rootfs", &i.rootfs),
        ] {
            if !is_clean(p) {
                return Err(inspect_err(format!("{name}: not a clean absolute path")));
            }
        }
        let graph = userdata_root(&i.static_dir, id)
            .ok_or_else(|| inspect_err("static: not this container's userdata directory"))?;
        if i.config != format!("{}/config.json", i.static_dir) {
            return Err(inspect_err("config: not <static>/config.json"));
        }
        let run_dir = i
            .hostname
            .strip_suffix("/hostname")
            .filter(|d| userdata_root(d, id).is_some())
            .ok_or_else(|| inspect_err("hostname: not this container's userdata directory"))?;
        let layer = i
            .rootfs
            .strip_prefix(&format!("{graph}/overlay/"))
            .and_then(|r| r.strip_suffix("/merged"))
            .ok_or_else(|| inspect_err("rootfs: not <graphroot>/overlay/<layer>/merged"))?;
        if !is_id(layer) {
            return Err(inspect_err("rootfs: not a layer id"));
        }
        Ok(Self {
            id: id.to_owned(),
            run_dir: run_dir.to_owned(),
            static_dir: i.static_dir,
            config: i.config,
            hostname: i.hostname,
            rootfs: i.rootfs,
        })
    }
}

/// The fields of an image's `Config` that reach the OCI config (architect Q101). Not
/// `deny_unknown_fields`: every effect of any other image field (a `Volumes` entry, say) shows in
/// `config.json`, where unknown keys and extra mounts are refused. A field used here with the
/// wrong type refuses.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct ImageConfig {
    /// `NAME=value` pairs.
    #[serde(rename = "Env", default)]
    pub env: Option<Vec<String>>,
    /// Podman prepends it to the command.
    #[serde(rename = "Entrypoint", default)]
    pub entrypoint: Option<Vec<String>>,
    /// The process's working directory.
    #[serde(rename = "WorkingDir", default)]
    pub working_dir: Option<String>,
    /// The stop signal, as the image names it.
    #[serde(rename = "StopSignal", default)]
    pub stop_signal: Option<String>,
}

impl ImageConfig {
    /// Parses the output of `podman image inspect --format` [`IMAGE_FORMAT`].
    ///
    /// # Errors
    /// A [`Mismatch`] on field `image`.
    pub fn parse(out: &[u8]) -> Result<Self, Mismatch> {
        let err = |why: &str| Mismatch::new("image", why);
        if out.len() > MAX_INSPECT {
            return Err(err("over the size bound"));
        }
        let text = std::str::from_utf8(out).map_err(|_| err("not UTF-8"))?;
        let value = crate::rpc::json::parse(text.trim_end_matches('\n').as_bytes())
            .ok()
            .filter(serde_json::Value::is_object)
            .ok_or_else(|| err("not one strict JSON object"))?;
        serde_json::from_value(value).map_err(|_| err("a field has the wrong type"))
    }
}

/// Everything the verifier compares besides the intent and the config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {
    /// The container's checked directories.
    pub paths: ContainerPaths,
    /// The image's `Config`.
    pub image: ImageConfig,
    /// The checked `catatonit` path (`--init`), as hermetic podman's `containers.conf` names it.
    pub init: String,
    /// `std::env::consts::ARCH`.
    pub arch: &'static str,
    /// `sallyd`'s own hard `RLIMIT_NOFILE` and `RLIMIT_NPROC` (`u64::MAX` for unlimited).
    pub own_nofile: u64,
    /// See `own_nofile`.
    pub own_nproc: u64,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const G: &str = "/h/.local/share/containers/storage";
    const R: &str = "/run/user/1/containers";

    fn id() -> String {
        "c".repeat(64)
    }

    fn inspect(static_dir: &str, config: &str, hostname: &str, rootfs: &str) -> String {
        serde_json::json!({
            "static": static_dir, "config": config, "hostname": hostname, "rootfs": rootfs,
        })
        .to_string()
    }

    fn good() -> [String; 4] {
        let s = format!("{G}/overlay-containers/{}/userdata", id());
        [
            s.clone(),
            format!("{s}/config.json"),
            format!("{R}/overlay-containers/{}/userdata/hostname", id()),
            format!("{G}/overlay/{}/merged", "d".repeat(64)),
        ]
    }

    fn parse(f: &[String; 4]) -> Result<ContainerPaths, Mismatch> {
        let [a, b, c, d] = f;
        ContainerPaths::parse(format!("{}\n", inspect(a, b, c, d)).as_bytes(), &id())
    }

    #[test]
    fn the_container_s_own_directories_are_accepted() {
        let p = parse(&good()).unwrap();
        assert_eq!(
            p.run_dir,
            format!("{R}/overlay-containers/{}/userdata", id())
        );
        assert_eq!(p.static_dir, good()[0]);
        assert_eq!(p.config, good()[1]);
        assert_eq!(p.hostname, good()[2]);
        assert_eq!(p.rootfs, good()[3]);
        assert_eq!(p.id, id());
    }

    #[test]
    fn any_other_directory_is_refused() {
        let other = "e".repeat(64);
        let mut cases = Vec::new();
        let mut set = |k: usize, v: String| {
            let mut f = good();
            if let Some(slot) = f.get_mut(k) {
                *slot = v;
            }
            cases.push(f);
        };
        set(0, format!("{G}/overlay-containers/{other}/userdata"));
        set(0, format!("{G}/overlay-containers/{}/userdata/", id()));
        set(0, format!("{G}/../x/overlay-containers/{}/userdata", id()));
        set(0, format!("overlay-containers/{}/userdata", id()));
        set(0, format!("/overlay-containers/{}/userdata", id()));
        set(
            1,
            format!("{G}/overlay-containers/{}/userdata/other.json", id()),
        );
        set(
            2,
            format!("{R}/overlay-containers/{other}/userdata/hostname"),
        );
        set(2, format!("{R}/overlay-containers/{}/userdata/hosts", id()));
        set(
            2,
            format!("{R}/overlay-containers/{}/userdata/x/hostname", id()),
        );
        set(3, format!("/elsewhere/overlay/{}/merged", "d".repeat(64)));
        set(3, format!("{G}/overlay/{}/merged", "d".repeat(63)));
        set(3, format!("{G}/overlay/{}/diff", "d".repeat(64)));
        set(3, format!("{G}/overlay/{}/merged\n", "d".repeat(64)));
        for f in cases {
            assert!(parse(&f).is_err(), "{f:?}");
        }
    }

    #[test]
    fn the_output_must_be_one_strict_bounded_object_for_a_real_id() {
        let [a, b, c, d] = good();
        let ok = inspect(&a, &b, &c, &d);
        assert!(ContainerPaths::parse(ok.as_bytes(), &id()).is_ok());
        assert!(ContainerPaths::parse(ok.as_bytes(), "C".repeat(64).as_str()).is_err());
        assert!(ContainerPaths::parse(ok.as_bytes(), &"c".repeat(63)).is_err());
        let dup = ok.replacen('{', &format!("{{\"static\":{a:?},"), 1);
        assert!(ContainerPaths::parse(dup.as_bytes(), &id()).is_err());
        let extra = ok.replacen('{', "{\"x\":1,", 1);
        assert!(ContainerPaths::parse(extra.as_bytes(), &id()).is_err());
        assert!(ContainerPaths::parse(format!("{ok}{ok}").as_bytes(), &id()).is_err());
        assert!(ContainerPaths::parse(b"\xff", &id()).is_err());
        let pad = MAX_INSPECT - ok.len();
        let big = format!("{ok}{}", " ".repeat(pad));
        assert!(ContainerPaths::parse(big.as_bytes(), &id()).is_ok());
        assert!(ContainerPaths::parse(format!("{big} ").as_bytes(), &id()).is_err());
    }

    #[test]
    fn clean_paths_are_absolute_plain_segments() {
        for ok in ["/a", "/a/b.c", "/a/..b"] {
            assert!(is_clean(ok), "{ok}");
        }
        for bad in [
            "", "/", "a", "/a/", "//a", "/a//b", "/a/./b", "/a/../b", "/a/\u{7}",
        ] {
            assert!(!is_clean(bad), "{bad:?}");
        }
    }

    #[test]
    fn the_image_config_is_typed_for_the_fields_used() {
        let c = ImageConfig::parse(
            br#"{"Env":["PATH=/bin"],"Cmd":["/bin/sh"],"WorkingDir":"/","Labels":{"a":"b"}}"#,
        )
        .unwrap();
        assert_eq!(c.env, Some(vec!["PATH=/bin".to_owned()]));
        assert_eq!(c.working_dir.as_deref(), Some("/"));
        assert_eq!(c.entrypoint, None);
        let c = ImageConfig::parse(br#"{"Entrypoint":["/e"],"StopSignal":"SIGTERM"}"#).unwrap();
        assert_eq!(c.entrypoint, Some(vec!["/e".to_owned()]));
        assert_eq!(c.stop_signal.as_deref(), Some("SIGTERM"));
        for bad in [
            &br#"{"Env":"PATH=/bin"}"#[..],
            br#"{"Env":[],"Env":[]}"#,
            br#"{"WorkingDir":1}"#,
            b"[]",
            b"{} {}",
            b"\xff",
        ] {
            assert!(ImageConfig::parse(bad).is_err(), "{bad:?}");
        }
        let full = format!("{{}}{}", " ".repeat(MAX_INSPECT - 2));
        assert_eq!(full.len(), MAX_INSPECT);
        assert!(ImageConfig::parse(full.as_bytes()).is_ok());
        assert!(ImageConfig::parse(format!("{full} ").as_bytes()).is_err());
    }
}
