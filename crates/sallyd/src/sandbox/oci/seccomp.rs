//! The seccomp filter a container must carry, derived from Sallyport's embedded profile the way
//! Podman 4.9.3 converts a profile into the OCI config (containers/common `pkg/seccomp`): keep
//! the native architecture's `archMap` entry, drop the rules whose `includes`/`excludes` do not
//! match the native architecture and an empty capability set, and carry the remaining rules in
//! order with only `names`, `action`, `errnoRet` and `args`. The verifier compares the result
//! with the config's `linux.seccomp` by content (Task 14).
//!
//! A profile condition this module cannot evaluate (`minKernel`, a singular `name`, an unknown
//! key) is an error, never a guess: the verifier then refuses the launch.

use serde::Deserialize;

/// `linux.seccomp` of an OCI config, as far as Podman writes it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OciSeccomp {
    /// The action of a syscall no rule names.
    pub default_action: String,
    /// The errno of `default_action` when it is `SCMP_ACT_ERRNO`.
    pub default_errno_ret: Option<u32>,
    /// Architectures the filter applies to.
    pub architectures: Vec<String>,
    /// The rules, in order.
    pub syscalls: Vec<OciRule>,
}

/// One rule of [`OciSeccomp`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OciRule {
    /// Syscall names.
    pub names: Vec<String>,
    /// `SCMP_ACT_*`.
    pub action: String,
    /// The errno of an `SCMP_ACT_ERRNO` rule.
    pub errno_ret: Option<u32>,
    /// Argument conditions; Podman omits an empty list.
    #[serde(default)]
    pub args: Vec<OciArg>,
}

/// One argument condition of [`OciRule`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OciArg {
    /// Argument index.
    pub index: u32,
    /// Compared value.
    pub value: u64,
    /// Second value (masked compares); Podman omits a zero.
    #[serde(default)]
    pub value_two: u64,
    /// `SCMP_CMP_*`.
    pub op: String,
}

/// The embedded profile's format (Docker/containers-common), strictly.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Profile {
    default_action: String,
    /// Known so the strict parse accepts it; Podman carries only `defaultErrnoRet`.
    #[serde(default)]
    #[expect(dead_code, reason = "parsed, never converted")]
    default_errno: Option<String>,
    #[serde(default)]
    default_errno_ret: Option<u32>,
    arch_map: Vec<ArchEntry>,
    syscalls: Vec<Rule>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ArchEntry {
    architecture: String,
    sub_architectures: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Rule {
    names: Vec<String>,
    action: String,
    #[serde(default)]
    args: Vec<OciArg>,
    /// Known so the strict parse accepts them; Podman drops both.
    #[serde(default)]
    #[expect(dead_code, reason = "parsed, never converted")]
    comment: Option<String>,
    #[serde(default)]
    #[expect(dead_code, reason = "parsed, never converted")]
    errno: Option<String>,
    #[serde(default)]
    errno_ret: Option<u32>,
    #[serde(default)]
    includes: Option<Filter>,
    #[serde(default)]
    excludes: Option<Filter>,
}

/// `includes`/`excludes`: only architectures and capabilities; a `minKernel` fails the parse.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Filter {
    #[serde(default)]
    arches: Vec<String>,
    #[serde(default)]
    caps: Vec<String>,
}

/// Why no expected filter could be derived.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SeccompError {
    /// The embedded profile does not parse strictly.
    #[error("seccomp profile: {0}")]
    Profile(String),
    /// The host architecture has no entry this module can map.
    #[error("seccomp profile: no mapping for host architecture {0:?}")]
    Arch(String),
}

/// The Go architecture name (`includes.arches`) and the libseccomp one (`archMap`) of a Rust
/// `target_arch`; `None` for one Sallyport does not ship profiles for.
fn arch_names(rust_arch: &str) -> Option<(&'static str, &'static str)> {
    match rust_arch {
        "x86_64" => Some(("amd64", "SCMP_ARCH_X86_64")),
        "aarch64" => Some(("arm64", "SCMP_ARCH_AARCH64")),
        _ => None,
    }
}

/// The filter Podman writes for `profile_json` on a host of `rust_arch` (as
/// `std::env::consts::ARCH` names it) for a container with no capabilities.
///
/// # Errors
/// [`SeccompError`] when the profile does not parse strictly or the architecture is unknown.
pub fn expected(profile_json: &str, rust_arch: &str) -> Result<OciSeccomp, SeccompError> {
    let p: Profile =
        serde_json::from_str(profile_json).map_err(|e| SeccompError::Profile(e.to_string()))?;
    let (go_arch, scmp_arch) =
        arch_names(rust_arch).ok_or_else(|| SeccompError::Arch(rust_arch.to_owned()))?;
    let mut architectures = Vec::new();
    for a in p
        .arch_map
        .into_iter()
        .filter(|a| a.architecture == scmp_arch)
    {
        architectures.push(a.architecture);
        architectures.extend(a.sub_architectures);
    }
    if architectures.is_empty() {
        return Err(SeccompError::Arch(rust_arch.to_owned()));
    }
    let syscalls = p
        .syscalls
        .into_iter()
        .filter(|r| applies(r, go_arch))
        .map(|r| OciRule {
            names: r.names,
            action: r.action,
            errno_ret: r.errno_ret,
            args: r.args,
        })
        .collect();
    Ok(OciSeccomp {
        default_action: p.default_action,
        default_errno_ret: p.default_errno_ret,
        architectures,
        syscalls,
    })
}

/// containers/common's rule filter with an empty capability set: an `excludes` match on the
/// architecture drops the rule, `excludes.caps` never match, `includes.arches` must name the
/// architecture, and any `includes.caps` cannot be met.
fn applies(r: &Rule, go_arch: &str) -> bool {
    let none = Filter::default();
    let inc = r.includes.as_ref().unwrap_or(&none);
    let exc = r.excludes.as_ref().unwrap_or(&none);
    let named = |f: &Filter| f.arches.iter().any(|a| a == go_arch);
    !named(exc) && (inc.arches.is_empty() || named(inc)) && inc.caps.is_empty()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::sandbox::profile;
    use crate::sandbox::types::Role;

    fn fixture(s: &str) -> OciSeccomp {
        serde_json::from_str(s).unwrap()
    }

    /// The filters Podman 4.9.3 wrote into real configs on x86_64 (Task 14 probe): the
    /// conversion here must reproduce them exactly, rule order included.
    #[test]
    fn the_embedded_profiles_convert_exactly_as_podman_converts_them() {
        let ws = fixture(include_str!("testdata/seccomp-workspace.amd64.json"));
        let inf = fixture(include_str!("testdata/seccomp-inference.amd64.json"));
        assert_eq!(expected(profile(Role::Workspace), "x86_64").unwrap(), ws);
        assert_eq!(expected(profile(Role::Harness), "x86_64").unwrap(), ws);
        assert_eq!(expected(profile(Role::Inference), "x86_64").unwrap(), inf);
        assert_eq!(ws.syscalls.len(), 18);
    }

    fn rule(extra: &str) -> String {
        format!(
            r#"{{"defaultAction":"SCMP_ACT_ERRNO","defaultErrnoRet":38,
                "archMap":[{{"architecture":"SCMP_ARCH_X86_64","subArchitectures":["SCMP_ARCH_X86"]}},
                           {{"architecture":"SCMP_ARCH_AARCH64","subArchitectures":[]}}],
                "syscalls":[{{"names":["read"],"action":"SCMP_ACT_ALLOW"{extra}}}]}}"#
        )
    }

    fn kept(extra: &str, arch: &str) -> bool {
        !expected(&rule(extra), arch).unwrap().syscalls.is_empty()
    }

    #[test]
    fn rules_are_filtered_by_architecture_and_an_empty_capability_set() {
        assert!(kept("", "x86_64"));
        assert!(kept(r#","includes":{},"excludes":{}"#, "x86_64"));
        assert!(kept(r#","includes":{"arches":["x32","amd64"]}"#, "x86_64"));
        assert!(!kept(r#","includes":{"arches":["arm64"]}"#, "x86_64"));
        assert!(kept(r#","includes":{"arches":["arm64"]}"#, "aarch64"));
        assert!(!kept(r#","excludes":{"arches":["amd64"]}"#, "x86_64"));
        assert!(kept(r#","excludes":{"arches":["arm64"]}"#, "x86_64"));
        assert!(!kept(r#","includes":{"caps":["CAP_SYS_ADMIN"]}"#, "x86_64"));
        assert!(kept(r#","excludes":{"caps":["CAP_SYS_ADMIN"]}"#, "x86_64"));
    }

    #[test]
    fn the_native_arch_map_entry_and_its_sub_architectures_are_kept() {
        let x = expected(&rule(""), "x86_64").unwrap();
        assert_eq!(x.architectures, ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86"]);
        assert_eq!(x.default_action, "SCMP_ACT_ERRNO");
        assert_eq!(x.default_errno_ret, Some(38));
        let a = expected(&rule(""), "aarch64").unwrap();
        assert_eq!(a.architectures, ["SCMP_ARCH_AARCH64"]);
    }

    #[test]
    fn a_rule_keeps_its_errno_and_args_and_drops_its_comments() {
        let x = expected(
            &rule(
                r#","errnoRet":1,"errno":"EPERM","comment":"c",
                   "args":[{"index":0,"value":2,"valueTwo":0,"op":"SCMP_CMP_EQ"}]"#,
            ),
            "x86_64",
        )
        .unwrap();
        let r = x.syscalls.first().unwrap();
        assert_eq!(r.errno_ret, Some(1));
        assert_eq!(
            r.args,
            [OciArg {
                index: 0,
                value: 2,
                value_two: 0,
                op: "SCMP_CMP_EQ".into()
            }]
        );
    }

    #[test]
    fn what_cannot_be_evaluated_is_an_error() {
        for (extra, arch) in [
            (r#","includes":{"minKernel":"4.8"}"#, "x86_64"),
            (r#","name":"read""#, "x86_64"),
            ("", "riscv64"),
        ] {
            assert!(expected(&rule(extra), arch).is_err(), "{extra} {arch}");
        }
        let no_entry = rule("").replace("SCMP_ARCH_AARCH64", "SCMP_ARCH_PPC64LE");
        assert_eq!(
            expected(&no_entry, "aarch64"),
            Err(SeccompError::Arch("aarch64".into()))
        );
        assert!(matches!(
            expected("{", "x86_64"),
            Err(SeccompError::Profile(_))
        ));
    }
}
