#!/usr/bin/env python3
"""Derives profiles/seccomp-{workspace,harness,inference}.json (ARCHITECTURE section 3.4).

Input: containers-common's default profile (Docker format), normally
/usr/share/containers/seccomp.json. Run with `python3 -I scripts/gen_seccomp.py <default.json>`.
The output is committed; `crates/sallyd/src/sandbox/profiles.rs` embeds it and its tests check the
properties below, so a regenerated profile that drifts fails CI.

- Every rule that allows a syscall in REMOVED or REPLACED loses that name; rules left empty are
  dropped.
- `clone` is allowed only without namespace flags (Docker's rule): no nested user, network or
  mount namespace, so the kernel surface those expose (nf_tables, mount) stays out of reach.
  `clone3` is not allowed at all (its flags live in memory seccomp cannot read); it fails with
  the default ENOSYS and libc falls back to `clone`.
- `socket` is allowed per address family (AF_UNIX, AF_INET, AF_INET6, AF_NETLINK with
  NETLINK_ROUTE only; inference AF_UNIX only). Families network namespaces do not isolate (AF_VSOCK reaches the hypervisor
  host) and everything else get ENOSYS.
- Only native architectures: no 32-bit sub-architectures, so `int 0x80` (and `socketcall`,
  which cannot be argument-filtered) never reaches an allow rule.
"""

import json
import sys
from typing import Any

# ARCHITECTURE section 3.4, plus the same capability in other spellings: the new mount API
# (fsopen ... mount_setattr), umount, the 64-bit time calls, clock_adjtime and pidfd_getfd
# (ptrace-like fd theft).
REMOVED = frozenset(
    """
    mount umount umount2 pivot_root chroot fsopen fsconfig fsmount fspick move_mount open_tree
    mount_setattr ptrace process_vm_readv process_vm_writev pidfd_getfd keyctl add_key
    request_key bpf perf_event_open userfaultfd io_uring_setup io_uring_enter io_uring_register
    unshare setns kexec_load kexec_file_load reboot swapon swapoff init_module finit_module
    delete_module acct settimeofday stime clock_settime clock_settime64 clock_adjtime
    clock_adjtime64 mknod mknodat personality uselib vhangup quotactl quotactl_fd lookup_dcookie
    nfsservctl open_by_handle_at name_to_handle_at socketcall syslog
    """.split()
)
# Dropped from every rule and re-added below with argument filters.
REPLACED = frozenset({"clone", "clone3", "socket"})

AF_UNIX, AF_INET, AF_INET6, AF_NETLINK = 1, 2, 10, 16
NETLINK_ROUTE = 0
# CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID
# | CLONE_NEWNET
NAMESPACE_FLAGS = 0x7E020000

Rule = dict[str, Any]


def strip(profile: dict[str, Any]) -> dict[str, Any]:
    out = dict(profile)
    rules: list[Rule] = []
    for rule in profile["syscalls"]:
        names = [n for n in rule["names"] if n not in REPLACED]
        if rule["action"] == "SCMP_ACT_ALLOW":
            names = [n for n in names if n not in REMOVED]
        if not names:
            continue
        rules.append({**rule, "names": names})
    rules.append(
        {
            "names": ["clone"],
            "action": "SCMP_ACT_ALLOW",
            "args": [
                {"index": 0, "value": NAMESPACE_FLAGS, "valueTwo": 0, "op": "SCMP_CMP_MASKED_EQ"}
            ],
            "comment": "No namespace flags (ARCHITECTURE section 3.4).",
        }
    )
    out["syscalls"] = rules
    out["archMap"] = [
        {**a, "subArchitectures": []}
        for a in profile["archMap"]
        if a["architecture"] in ("SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64")
    ]
    return out


def with_sockets(profile: dict[str, Any], families: list[int]) -> dict[str, Any]:
    rules: list[Rule] = list(profile["syscalls"])
    for family in families:
        args = [{"index": 0, "value": family, "valueTwo": 0, "op": "SCMP_CMP_EQ"}]
        if family == AF_NETLINK:
            # NETLINK_ROUTE only, by equality (fails closed; a NE check on the 64-bit argument
            # is bypassable, the kernel truncates it to int).
            args.append({"index": 2, "value": NETLINK_ROUTE, "valueTwo": 0, "op": "SCMP_CMP_EQ"})
        rules.append(
            {
                "names": ["socket"],
                "action": "SCMP_ACT_ALLOW",
                "args": args,
                "comment": f"Address family {family} (ARCHITECTURE section 3.4).",
            }
        )
    return {**profile, "syscalls": rules}


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: gen_seccomp.py <containers-common seccomp.json>", file=sys.stderr)
        return 2
    with open(argv[1], encoding="utf-8") as f:
        base = strip(json.load(f))
    inet = [AF_UNIX, AF_INET, AF_INET6, AF_NETLINK]
    for role, profile in [
        ("workspace", with_sockets(base, inet)),
        ("harness", with_sockets(base, inet)),
        ("inference", with_sockets(base, [AF_UNIX])),
    ]:
        with open(f"profiles/seccomp-{role}.json", "w", encoding="utf-8") as f:
            json.dump(profile, f, indent=1, sort_keys=True)
            f.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
