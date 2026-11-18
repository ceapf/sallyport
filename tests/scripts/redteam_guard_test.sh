#!/usr/bin/env bash
# tests/scripts/redteam_guard_test.sh — scripts/redteam-guard.sh passes when the only ignored rt_
# test is the approved WSL one and the run lists at least the floor; it fails on a second ignored
# rt_ test, on the WSL test missing from the ignored list, on a run below the floor, on an empty
# list, and on a line that is not "<binary> <test>" in either list. Runs via `make test-scripts`.
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
# expect <want exit> <label> <ignored text> <run count> <min> [message fragment]
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
}

only="sallyd::escape $wsl
"
expect 0 "only the WSL test ignored, run at the floor" "$only" 5 5
expect 0 "run above the floor" "$only" 6 5
expect 1 "run one below the floor" "$only" 4 5 "4 rt_ tests run, the floor is 5"
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
rc=0
bash "$guard" "$wsl" five "$tmp/ignored" "$tmp/run" >/dev/null 2>&1 || rc=$?
[ "$rc" -eq 2 ] || { echo "FAIL: a floor that is not a number: exit $rc, want 2" >&2; fail=1; }

[ "$fail" -eq 0 ] && echo "redteam_guard_test: ok"
exit "$fail"
