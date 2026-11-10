//! The seccomp profiles (ARCHITECTURE §3.4), embedded in the binary (#10). At launch they are
//! written into the session's 0700 directory, so no file outside Sallyport's control decides what
//! a sandbox may call. `scripts/gen_seccomp.py` derives them from containers-common's default
//! profile; the tests here check the properties independently of the generator. TODO(#17):
//! container red-team tests for the socket-family, clone and native-architecture filters.

use std::io::Write as _;
use std::os::fd::AsFd;

use rustix::fs::{Mode, OFlags};

use super::types::Role;

const WORKSPACE: &str = include_str!("../../../../profiles/seccomp-workspace.json");
const HARNESS: &str = include_str!("../../../../profiles/seccomp-harness.json");
const INFERENCE: &str = include_str!("../../../../profiles/seccomp-inference.json");

/// The embedded profile of `role`.
#[must_use]
pub fn profile(role: Role) -> &'static str {
    match role {
        Role::Workspace => WORKSPACE,
        Role::Harness => HARNESS,
        Role::Inference => INFERENCE,
    }
}

/// Writes every role's profile into `dir` (a directory Sallyport just created, 0700) as
/// `seccomp-<role>.json`, mode 0600. Refuses to replace an existing file or follow a symlink.
///
/// # Errors
/// The I/O error, e.g. `EEXIST`.
pub fn write_profiles(dir: impl AsFd) -> std::io::Result<()> {
    for role in [Role::Workspace, Role::Harness, Role::Inference] {
        let fd = rustix::fs::openat(
            &dir,
            role.profile(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )?;
        std::fs::File::from(fd).write_all(profile(role).as_bytes())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use serde_json::Value;

    use super::*;

    /// ARCHITECTURE §3.4, restated here rather than imported from the generator: a regenerated
    /// profile that allows any of these fails this test.
    const REMOVED: &[&str] = &[
        "mount",
        "umount",
        "umount2",
        "pivot_root",
        "chroot",
        "fsopen",
        "fsconfig",
        "fsmount",
        "fspick",
        "move_mount",
        "open_tree",
        "mount_setattr",
        "ptrace",
        "process_vm_readv",
        "process_vm_writev",
        "pidfd_getfd",
        "keyctl",
        "add_key",
        "request_key",
        "bpf",
        "perf_event_open",
        "userfaultfd",
        "io_uring_setup",
        "io_uring_enter",
        "io_uring_register",
        "unshare",
        "setns",
        "kexec_load",
        "kexec_file_load",
        "reboot",
        "swapon",
        "swapoff",
        "init_module",
        "finit_module",
        "delete_module",
        "acct",
        "settimeofday",
        "stime",
        "clock_settime",
        "clock_settime64",
        "clock_adjtime",
        "clock_adjtime64",
        "mknod",
        "mknodat",
        "personality",
        "uselib",
        "vhangup",
        "quotactl",
        "quotactl_fd",
        "lookup_dcookie",
        "nfsservctl",
        "open_by_handle_at",
        "name_to_handle_at",
        // 6b security review: no unfilterable socket multiplexer, no kernel log.
        "socketcall",
        "syslog",
        // Flags in memory seccomp cannot read; ENOSYS makes libc fall back to `clone`.
        "clone3",
    ];
    const ROLES: [Role; 3] = [Role::Workspace, Role::Harness, Role::Inference];

    fn rules(role: Role) -> Vec<Value> {
        let p: Value = serde_json::from_str(profile(role)).unwrap();
        assert_eq!(p["defaultAction"], "SCMP_ACT_ERRNO", "{role:?}");
        p["syscalls"].as_array().unwrap().clone()
    }

    fn allows(rule: &Value, name: &str) -> bool {
        rule["action"] != "SCMP_ACT_ERRNO"
            && rule["names"].as_array().unwrap().iter().any(|n| n == name)
    }

    #[test]
    fn no_rule_of_any_role_allows_a_removed_syscall_under_any_condition() {
        for role in ROLES {
            for rule in rules(role) {
                // Every non-errno rule is a plain allow: no trace, log or user notification.
                if rule["action"] != "SCMP_ACT_ERRNO" {
                    assert_eq!(rule["action"], "SCMP_ACT_ALLOW", "{role:?}: {rule}");
                }
                for name in REMOVED {
                    assert!(!allows(&rule, name), "{role:?} allows {name}: {rule}");
                }
            }
        }
    }

    /// The address families a role's `socket` rules allow, each as `(family, extra args)`.
    fn socket_families(role: Role) -> Vec<(u64, usize)> {
        let mut out: Vec<(u64, usize)> = rules(role)
            .into_iter()
            .filter(|r| allows(r, "socket"))
            .map(|r| {
                assert_eq!(r["names"], serde_json::json!(["socket"]), "{role:?}: {r}");
                let args = r["args"].as_array().unwrap();
                assert_eq!(args[0]["index"], 0, "{role:?}: {r}");
                assert_eq!(args[0]["op"], "SCMP_CMP_EQ", "{role:?}: {r}");
                assert!(
                    r.get("includes")
                        .is_none_or(|i| i == &serde_json::json!({}))
                );
                (args[0]["value"].as_u64().unwrap(), args.len() - 1)
            })
            .collect();
        out.sort_unstable();
        out
    }

    /// 6b security review H2: an allowlist of address families, never an unconditional
    /// `socket`. AF_VSOCK (40) ignores network namespaces and reaches the hypervisor host.
    #[test]
    fn sockets_are_an_allowlist_of_address_families() {
        for role in [Role::Workspace, Role::Harness] {
            // AF_UNIX, AF_INET, AF_INET6, AF_NETLINK (NETLINK_ROUTE only).
            assert_eq!(
                socket_families(role),
                [(1, 0), (2, 0), (10, 0), (16, 1)],
                "{role:?}"
            );
            let netlink = rules(role)
                .into_iter()
                .find(|r| allows(r, "socket") && r["args"][0]["value"] == 16)
                .unwrap();
            assert_eq!(netlink["args"][1]["index"], 2);
            assert_eq!(netlink["args"][1]["value"], 0, "NETLINK_ROUTE");
            assert_eq!(
                netlink["args"][1]["op"], "SCMP_CMP_EQ",
                "equality fails closed"
            );
        }
        assert_eq!(socket_families(Role::Inference), [(1, 0)], "AF_UNIX only");
    }

    /// 6b security review H1: `clone` may not create namespaces (no nested user or network
    /// namespace, so no CAP_NET_ADMIN over nf_tables); exactly Docker's mask.
    #[test]
    fn clone_is_allowed_only_without_namespace_flags() {
        for role in ROLES {
            let clone: Vec<Value> = rules(role)
                .into_iter()
                .filter(|r| allows(r, "clone"))
                .collect();
            assert_eq!(clone.len(), 1, "{role:?}");
            let r = &clone[0];
            assert_eq!(r["names"], serde_json::json!(["clone"]));
            assert_eq!(r["args"].as_array().unwrap().len(), 1);
            assert_eq!(r["args"][0]["index"], 0);
            assert_eq!(r["args"][0]["op"], "SCMP_CMP_MASKED_EQ");
            assert_eq!(r["args"][0]["value"], 0x7E02_0000_u64);
            assert_eq!(r["args"][0]["valueTwo"], 0);
        }
    }

    /// 6b security review H2: only native architectures, so the 32-bit ABI (`int 0x80`,
    /// `socketcall`) never matches an allow rule.
    #[test]
    fn only_native_architectures_are_listed() {
        for role in ROLES {
            let p: Value = serde_json::from_str(profile(role)).unwrap();
            let arches: Vec<&str> = p["archMap"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| {
                    assert_eq!(a["subArchitectures"], serde_json::json!([]), "{role:?}");
                    a["architecture"].as_str().unwrap()
                })
                .collect();
            assert_eq!(
                arches,
                ["SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"],
                "{role:?}"
            );
        }
    }

    #[test]
    fn profiles_are_written_once_0600_and_never_through_a_symlink() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("sallyd-profiles-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let fd = std::fs::File::open(&dir).unwrap();
        write_profiles(&fd).unwrap();
        for role in ROLES {
            let p = dir.join(role.profile());
            assert_eq!(std::fs::read_to_string(&p).unwrap(), profile(role));
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        assert!(write_profiles(&fd).is_err(), "never replaced");
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        std::os::unix::fs::symlink("/dev/null", dir.join("seccomp-workspace.json")).unwrap();
        let fd = std::fs::File::open(&dir).unwrap();
        assert!(write_profiles(&fd).is_err(), "never through a symlink");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
