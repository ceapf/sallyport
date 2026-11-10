#!/usr/bin/env python3
"""Derives profiles/seccomp-{workspace,harness,inference}.json (ARCHITECTURE section 3.4).

Input: containers-common's default profile (Docker format), normally
/usr/share/containers/seccomp.json. Run with `python3 -I scripts/gen_seccomp.py <default.json>`.
The output is committed; `crates/sallyd/src/sandbox/profiles.rs` embeds it and its tests check the
properties below, so a regenerated profile that drifts fails CI.

- Every rule that allows a syscall in REMOVED loses that name; rules left empty are dropped.
- Inference: every `socket` rule is replaced by one that allows only AF_UNIX, so no AF_INET or
  AF_INET6 socket exists and `connect`/`bind`/`listen` have nothing to act on.
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
    nfsservctl open_by_handle_at name_to_handle_at
    """.split()
)

AF_UNIX = 1

Rule = dict[str, Any]


def strip(profile: dict[str, Any]) -> dict[str, Any]:
    out = dict(profile)
    rules: list[Rule] = []
    for rule in profile["syscalls"]:
        if rule["action"] == "SCMP_ACT_ALLOW":
            names = [n for n in rule["names"] if n not in REMOVED]
            if not names:
                continue
            rule = {**rule, "names": names}
        rules.append(rule)
    out["syscalls"] = rules
    return out


def unix_sockets_only(profile: dict[str, Any]) -> dict[str, Any]:
    rules: list[Rule] = [r for r in profile["syscalls"] if "socket" not in r["names"]]
    rules.append(
        {
            "names": ["socket"],
            "action": "SCMP_ACT_ALLOW",
            "args": [{"index": 0, "value": AF_UNIX, "valueTwo": 0, "op": "SCMP_CMP_EQ"}],
            "comment": "Inference: AF_UNIX only (ARCHITECTURE section 3.4).",
        }
    )
    return {**profile, "syscalls": rules}


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: gen_seccomp.py <containers-common seccomp.json>", file=sys.stderr)
        return 2
    with open(argv[1], encoding="utf-8") as f:
        base = strip(json.load(f))
    for role, profile in [
        ("workspace", base),
        ("harness", base),
        ("inference", unix_sockets_only(base)),
    ]:
        with open(f"profiles/seccomp-{role}.json", "w", encoding="utf-8") as f:
            json.dump(profile, f, indent=1, sort_keys=True)
            f.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
