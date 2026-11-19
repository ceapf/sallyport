#!/usr/bin/env bash
# tests/scripts/redteam_guard_test.sh — scripts/redteam-guard.sh passes when the only ignored rt_
# test is the approved WSL one and the run lists exactly the count; it fails on a second ignored
# rt_ test, on the WSL test missing from the ignored list, on a run above the count (raise it) or
# below it (tests missing), on an empty list, and on a line that is not "<binary> <test>" in either
# list; a count that is not a positive integer without a leading zero is a usage error. Runs via
# `make test-scripts`.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
guard="$root/scripts/redteam-guard.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

wsl=rt_fs_11_wsl_a_windows_executable_does_not_reach_windows
fail=0
# lines <file> <count>: <count> run lines, "<binary> rt_x_<n>_test".
lines() {
  : >"$1"
  local i
  for ((i = 1; i <= $2; i++)); do echo "sallyd::bin rt_x_${i}_test" >>"$1"; done
}
# expect <want exit> <label> <ignored text> <run count> <count> [message fragment] [absent fragment]
expect() {
  local rc=0 out
  printf '%s' "$3" >"$tmp/ignored"
  lines "$tmp/run" "$4"
  out="$(bash "$guard" "$wsl" "$5" "$tmp/ignored" "$tmp/run" 2>&1)" || rc=$?
  if [ "$rc" -ne "$1" ]; then
    echo "FAIL: $2: exit $rc, want $1: $out" >&2
    fail=1
  fi
  if [ -n "${6:-}" ] && ! grep -qF -- "$6" <<<"$out"; then
    echo "FAIL: $2: output lacks '$6': $out" >&2
    fail=1
  fi
  if [ -n "${7:-}" ] && grep -qF -- "$7" <<<"$out"; then
    echo "FAIL: $2: output has '$7': $out" >&2
    fail=1
  fi
}
# usage <label> <count>: the guard refuses <count> as a usage error (exit 2).
usage() {
  local rc=0
  bash "$guard" "$wsl" "$2" "$tmp/ignored" "$tmp/run" >/dev/null 2>&1 || rc=$?
  [ "$rc" -eq 2 ] || { echo "FAIL: $1: exit $rc, want 2" >&2; fail=1; }
}

only="sallyd::escape $wsl
"
expect 0 "only the WSL test ignored, run at the count" "$only" 5 5 \
  "5 rt_ tests run (REDTEAM_COUNT 5); the only ignored one is $wsl"
expect 1 "run one above the count" "$only" 6 5 \
  "6 rt_ tests run, REDTEAM_COUNT in the Makefile is 5: raise it to 6" "missing"
expect 1 "run one below the count" "$only" 4 5 \
  "4 rt_ tests run, REDTEAM_COUNT in the Makefile is 5: 1 missing" "raise"
expect 1 "below the count, never told to lower it" "$only" 4 5 \
  "find the lost tests. The count goes down only in a PR that removes a test" "lower"
expect 1 "above, compared as numbers" "$only" 10 9 "raise it to 10" "missing"
expect 1 "below, compared as numbers" "$only" 9 10 "1 missing" "raise"
expect 1 "a second ignored rt_ test" "${only}sallyd::launch rt_fs_13_x
" 5 5 "rt_fs_13_x"
expect 1 "the WSL test not ignored" "" 5 5 "ignored rt_ tests must be exactly $wsl"
expect 1 "another test ignored instead" "sallyd::launch rt_fs_13_x
" 5 5 "rt_fs_13_x"
expect 1 "an empty run list" "$only" 0 5 "0 rt_ tests run"
expect 1 "a malformed ignored line" "${only}garbage
" 5 5 "unexpected line in $tmp/ignored"
# A line that is not "<binary> <test>" in the run list.
printf '%s' "$only" >"$tmp/ignored"
lines "$tmp/run" 5
echo "garbage" >>"$tmp/run"
rc=0
out="$(bash "$guard" "$wsl" 5 "$tmp/ignored" "$tmp/run" 2>&1)" || rc=$?
[ "$rc" -eq 1 ] && grep -qF "unexpected line" <<<"$out" || {
  echo "FAIL: a malformed run line: exit $rc: $out" >&2
  fail=1
}
rc=0
bash "$guard" >/dev/null 2>&1 || rc=$?
[ "$rc" -eq 2 ] || { echo "FAIL: no argument: exit $rc, want 2" >&2; fail=1; }
lines "$tmp/run" 5
usage "a count that is not a number" five
usage "a count of zero" 0
usage "a count with a leading zero" 05
usage "a count with trailing text" 5x

[ "$fail" -eq 0 ] && echo "redteam_guard_test: ok"
exit "$fail"
