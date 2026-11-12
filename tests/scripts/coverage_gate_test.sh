#!/usr/bin/env bash
# tests/scripts/coverage_gate_test.sh — scripts/coverage-gate.sh sums the lines of the matching
# files only, passes at exactly the minimum, fails one line under it, and fails when nothing
# matched. Runs via `make test-scripts`.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
gate="$root/scripts/coverage-gate.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fail=0
# summary <file> <name count covered>...
summary() {
  local out="$1"
  shift
  local files="" sep=""
  while [ "$#" -gt 0 ]; do
    files="$files$sep{\"filename\":\"$1\",\"summary\":{\"lines\":{\"count\":$2,\"covered\":$3}}}"
    sep=","
    shift 3
  done
  printf '{"data":[{"files":[%s]}]}' "$files" >"$out"
}
# expect <want exit> <label> <min> <fragment>
expect() {
  local rc=0
  bash "$gate" "$3" "$tmp/s.json" "$4" >/dev/null 2>&1 || rc=$?
  if [ "$rc" -ne "$1" ]; then
    echo "FAIL: $2: exit $rc, want $1" >&2
    fail=1
  fi
}

# 85 of 100 egress lines; the 0-covered sandbox file must not count.
summary "$tmp/s.json" /r/crates/sallyd/src/egress/a.rs 60 50 /r/crates/sallyd/src/egress/b.rs 40 35 \
  /r/crates/sallyd/src/sandbox/c.rs 500 0
expect 0 "exactly the minimum passes" 85 /crates/sallyd/src/egress/
expect 1 "one point over the coverage fails" 86 /crates/sallyd/src/egress/
expect 1 "no matching file fails" 85 /crates/sallyd/src/approvals/
summary "$tmp/s.json" /r/crates/sallyd/src/egress/a.rs 100 84
expect 1 "one line under fails" 85 /crates/sallyd/src/egress/
summary "$tmp/s.json" /r/crates/sallyd/src/egress/a.rs 0 0
expect 1 "matching files without lines fail" 85 /crates/sallyd/src/egress/
rc=0
bash "$gate" 85 "$tmp/s.json" >/dev/null 2>&1 || rc=$?
if [ "$rc" -ne 2 ]; then
  echo "FAIL: a missing argument: exit $rc, want 2" >&2
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "coverage_gate_test: ok"
