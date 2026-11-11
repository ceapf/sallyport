#!/usr/bin/env bash
# tests/scripts/check_trailers_test.sh — scripts/check-trailers.sh passes Signed-off-by-only
# commits and fails on each co-author or tool line, in any case. Runs in CI (doctor-syntax job)
# and via `make test-scripts`. Builds a throwaway repository with planted identities only.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
check="$root/scripts/check-trailers.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
g() { git -C "$tmp" -c user.name=Planted -c user.email=planted@example.invalid \
  -c core.hooksPath=/dev/null -c commit.gpgsign=false "$@"; }
g init -q
g commit -q --allow-empty -m "base"
base="$(g rev-parse HEAD)"

fail=0
expect() { # expect <0|1> <label> <message>
  g reset -q --hard "$base"
  g commit -q --allow-empty -m "$3"
  local rc=0
  (cd "$tmp" && bash "$check" "$base" HEAD) >/dev/null 2>&1 || rc=$?
  if [ "$rc" -ne "$1" ]; then
    echo "FAIL: $2: exit $rc, want $1" >&2
    fail=1
  fi
}
# Built from parts so this file's own text is not one of the lines it plants.
co="Co-Authored""-By"
expect 0 "sign-off only" "$(printf 'fix: x\n\nSigned-off-by: Planted <planted@example.invalid>')"
expect 0 "prose mentioning authors" "$(printf 'docs: credit co-authors in the README')"
expect 1 "co-author" "$(printf 'fix: x\n\n%s: Bot <bot@example.invalid>' "$co")"
expect 1 "co-author lowercase" "$(printf 'fix: x\n\n%s: Bot <b@example.invalid>' "${co,,}")"
expect 1 "session" "$(printf 'fix: x\n\nClaude''-Session: abc')"
expect 1 "tool footer" "$(printf 'fix: x\n\nGenerated'' with some tool')"
# A bad commit in the middle of a range is found.
g reset -q --hard "$base"
g commit -q --allow-empty -m "one"
g commit -q --allow-empty -m "$(printf 'two\n\n%s: Bot <b@example.invalid>' "$co")"
g commit -q --allow-empty -m "three"
rc=0
(cd "$tmp" && bash "$check" "$base" HEAD) >/dev/null 2>&1 || rc=$?
[ "$rc" -eq 1 ] || { echo "FAIL: middle commit: exit $rc, want 1" >&2; fail=1; }
# An unknown SHA fails instead of passing an empty range.
rc=0
(cd "$tmp" && bash "$check" 0123456789abcdef0123456789abcdef01234567 HEAD) >/dev/null 2>&1 || rc=$?
[ "$rc" -ne 0 ] || { echo "FAIL: unknown base passed" >&2; fail=1; }
[ "$fail" -eq 0 ] && echo "check_trailers_test: ok"
exit "$fail"
