#!/usr/bin/env bash
# tests/scripts/mutants_gate_test.sh — scripts/mutants-gate.sh fails on missed mutants only
# (maintainer ruling, issue #36): a timed-out mutant counts as detected and is listed in the job
# summary; any other cargo-mutants failure still fails. Runs via `make test-scripts`.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
gate="$root/scripts/mutants-gate.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fail=0
# expect <want exit> <label> <cargo-mutants exit> <missed lines> <timeout lines>
expect() {
  rm -rf "$tmp/out" "$tmp/summary"
  mkdir -p "$tmp/out"
  printf '%s' "$4" >"$tmp/out/missed.txt"
  printf '%s' "$5" >"$tmp/out/timeout.txt"
  local rc=0
  GITHUB_STEP_SUMMARY="$tmp/summary" bash "$gate" "$3" "$tmp/out" >/dev/null 2>&1 || rc=$?
  if [ "$rc" -ne "$1" ]; then
    echo "FAIL: $2: exit $rc, want $1" >&2
    fail=1
  fi
}
t1='src/a.rs:1:2: replace == with != in f'
m1='src/b.rs:3:4: replace > with >= in g'
expect 0 "all caught" 0 "" ""
expect 0 "timeouts only" 3 "" "$t1"$'\n'
expect 1 "missed" 2 "$m1"$'\n' ""
expect 1 "missed and timeouts" 2 "$m1"$'\n' "$t1"$'\n'
expect 1 "missed, reported with the timeout code" 3 "$m1"$'\n' "$t1"$'\n'
expect 1 "exit 2 but nothing listed missed" 2 "" ""
expect 1 "baseline failed" 4 "" ""
expect 1 "usage error" 1 "" ""
expect 1 "exit 0 but a mutant listed missed" 0 "$m1"$'\n' ""

# The summary lists each timed-out mutant.
expect 0 "timeouts listed" 3 "" "$t1"$'\n'
if ! grep -Fq "$t1" "$tmp/summary"; then
  echo "FAIL: the summary does not list the timed-out mutant" >&2
  fail=1
fi
# A missing output directory (cargo-mutants never ran) fails.
rc=0
GITHUB_STEP_SUMMARY="$tmp/summary" bash "$gate" 0 "$tmp/nowhere" >/dev/null 2>&1 || rc=$?
if [ "$rc" -eq 0 ]; then
  echo "FAIL: a missing mutants.out passed" >&2
  fail=1
fi

[ "$fail" -eq 0 ] && echo "mutants_gate_test: ok"
exit "$fail"
