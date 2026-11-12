#!/usr/bin/env bash
# scripts/disk-lock.sh <command...> — runs a command (a local mutation run) under the per-user
# `disk-free` lock, held shared (architect ruling D1). A mutation run copies the tree and builds
# into it, taking and freeing gigabytes; the disk-floor writer tests set their floor against the
# free space they see, so they take this lock exclusively and wait for the run to end, in either
# lane (`disk_free_lock` in crates/sallyd/tests/common/container.rs, bounded at 20 minutes).
# Same lock directory and checks as scripts/test-run.sh. Exit: 78 on a usage error or a bad lock
# directory (not 2, which the mutants gate reads as "missed mutants"), otherwise the command's
# own status. `flock -o`: only the command's own run holds the lock, never a process it leaves.
set -euo pipefail

[ $# -ge 1 ] || { echo "usage: disk-lock.sh <command...>" >&2; exit 78; }

private_dir() {
  [ ! -L "$1" ] && [ -d "$1" ] && [ "$(stat -c %u "$1")" = "$(id -u)" ] &&
    [ $((8#$(stat -c %a "$1") & 8#077)) -eq 0 ]
}
[[ "${XDG_RUNTIME_DIR:-}" == /* ]] || { echo "disk-lock: XDG_RUNTIME_DIR must be absolute" >&2; exit 78; }
locks="$XDG_RUNTIME_DIR/sallyport-test"
private_dir "$XDG_RUNTIME_DIR" && mkdir -p -m 700 "$locks" && private_dir "$locks" || {
  echo "disk-lock: XDG_RUNTIME_DIR and $locks must be directories owned by this user, mode 0700" >&2
  exit 78
}

echo "disk-lock: taking $locks/disk-free.lock (shared; waits for a running disk-floor test); disk-floor tests in either lane then wait for this run" >&2
exec flock -o -s "$locks/disk-free.lock" "$@"
