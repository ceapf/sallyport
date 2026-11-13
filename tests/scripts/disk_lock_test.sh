#!/usr/bin/env bash
# tests/scripts/disk_lock_test.sh — scripts/disk-lock.sh runs a command under the shared
# `disk-free` lock (architect ruling D1): it refuses a lock directory others could reach, passes
# the command's exit status through, and waits while the disk-floor tests hold the lock
# exclusively. Runs via `make test-scripts`.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
lock="$root/scripts/disk-lock.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fail() { echo "disk_lock_test: $*" >&2; exit 1; }

mkdir -m 700 "$tmp/xdg"

# refused <what> <env assignment...>: exit 78 (never 2, the mutants gate's "missed"), and the
# command never runs.
refused() {
  local what="$1" rc=0
  shift
  env "$@" bash "$lock" touch "$tmp/ran" 2>/dev/null || rc=$?
  [ "$rc" -eq 78 ] && [ ! -e "$tmp/ran" ] || fail "$what: rc $rc"
}
refused "unset XDG_RUNTIME_DIR" -u XDG_RUNTIME_DIR
refused "relative XDG_RUNTIME_DIR" XDG_RUNTIME_DIR=rel
mkdir -m 755 "$tmp/open"
refused "0755 XDG_RUNTIME_DIR" XDG_RUNTIME_DIR="$tmp/open"
mkdir -m 700 "$tmp/x2" && mkdir -m 755 "$tmp/x2/sallyport-test"
refused "0755 lock directory" XDG_RUNTIME_DIR="$tmp/x2"
ln -s "$tmp/xdg" "$tmp/link"
refused "symlinked XDG_RUNTIME_DIR" XDG_RUNTIME_DIR="$tmp/link"
rc=0; bash "$lock" 2>/dev/null || rc=$?
[ "$rc" -eq 78 ] || fail "no command: rc $rc"

# The Rust side takes the same lock, and every disk-floor test that sets a floor below the free
# space takes it first, except the admission test (architect ruling D1: its stage_size is the
# maximum, so freed space cannot admit it). A new floor test without the lock fails here.
grep -qF 'lock_path("disk-free")' "$root/crates/sallyd/tests/common/locks.rs" ||
  fail "locks.rs does not take lock_path(\"disk-free\")"
unlocked="$(awk '
  /^fn / { if (name != "" && floor && !locked) print name; name = $2; sub(/\(.*/, "", name);
           floor = 0; locked = 0; next }
  /floor_below_free\(/ { floor = 1 }
  /floor_serial\(/ { locked = 1 }
  END { if (name != "" && floor && !locked) print name }
' "$root/crates/sallyd/tests/disk.rs" | grep -vx 'floor_below_free' || true)"
[ "$unlocked" = "a_launch_without_room_for_stage_size_above_the_floor_is_refused" ] ||
  fail "floor tests without the disk-free lock: ${unlocked:-<none; expected the admission test>}"

# The command's status passes through, and it runs with the lock held shared.
export XDG_RUNTIME_DIR="$tmp/xdg"
l="$tmp/xdg/sallyport-test/disk-free.lock"
rc=0; bash "$lock" sh -c 'exit 7' 2>/dev/null || rc=$?
[ "$rc" -eq 7 ] || fail "status not passed through: rc $rc"
bash "$lock" sh -c "flock -n -s '$l' true && ! flock -n -x '$l' true" 2>/dev/null ||
  fail "the command did not run under a shared lock"

# within <tenths> <command...>: polls the command every 0.1 s, at most <tenths> times.
within() {
  local n="$1"
  shift
  until "$@"; do
    n=$((n - 1))
    [ "$n" -gt 0 ] || return 1
    sleep 0.1
  done
}

# A held exclusive lock (the floor tests) makes it wait; released, it runs. No timing
# arithmetic: the holder keeps the lock until the test lets it go.
flock -x "$l" sh -c "until [ -e '$tmp/go' ]; do sleep 0.05; done" &
holder=$!
within 50 sh -c "! flock -n -s '$l' true" || fail "the exclusive holder never took the lock"
bash "$lock" touch "$tmp/ran2" 2>/dev/null &
waiter=$!
sleep 0.3
[ ! -e "$tmp/ran2" ] || fail "ran while a floor test held the lock exclusively"
touch "$tmp/go"
within 50 test -e "$tmp/ran2" || fail "did not run once the exclusive holder let go"
wait "$holder" "$waiter"

echo "disk_lock_test: ok"
