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

# No (or a relative) XDG_RUNTIME_DIR: exit 2, the command never runs.
rc=0; env -u XDG_RUNTIME_DIR bash "$lock" touch "$tmp/ran" 2>/dev/null || rc=$?
[ "$rc" -eq 2 ] && [ ! -e "$tmp/ran" ] || fail "unset XDG_RUNTIME_DIR: rc $rc"
rc=0; XDG_RUNTIME_DIR=rel bash "$lock" touch "$tmp/ran" 2>/dev/null || rc=$?
[ "$rc" -eq 2 ] && [ ! -e "$tmp/ran" ] || fail "relative XDG_RUNTIME_DIR: rc $rc"

# A lock directory open to others: exit 2, the command never runs.
mkdir -m 755 "$tmp/open"
rc=0; XDG_RUNTIME_DIR="$tmp/open" bash "$lock" touch "$tmp/ran" 2>/dev/null || rc=$?
[ "$rc" -eq 2 ] && [ ! -e "$tmp/ran" ] || fail "0755 XDG_RUNTIME_DIR: rc $rc"
mkdir -m 700 "$tmp/x2" && mkdir -m 755 "$tmp/x2/sallyport-test"
rc=0; XDG_RUNTIME_DIR="$tmp/x2" bash "$lock" touch "$tmp/ran" 2>/dev/null || rc=$?
[ "$rc" -eq 2 ] && [ ! -e "$tmp/ran" ] || fail "0755 lock directory: rc $rc"

# The command's status passes through, and it runs with the lock held shared.
export XDG_RUNTIME_DIR="$tmp/xdg"
l="$tmp/xdg/sallyport-test/disk-free.lock"
rc=0; bash "$lock" sh -c 'exit 7' 2>/dev/null || rc=$?
[ "$rc" -eq 7 ] || fail "status not passed through: rc $rc"
bash "$lock" sh -c "flock -n -s '$l' true && ! flock -n -x '$l' true" 2>/dev/null ||
  fail "the command did not run under a shared lock"

# A held exclusive lock (the floor tests) makes it wait.
flock -x "$l" sleep 2 &
holder=$!
until ! flock -n -s "$l" true; do sleep 0.05; done
start=$(date +%s%N)
bash "$lock" true 2>/dev/null
waited=$(( ($(date +%s%N) - start) / 1000000 ))
wait "$holder"
[ "$waited" -ge 1000 ] || fail "did not wait for the exclusive holder (${waited} ms)"

echo "disk_lock_test: ok"
