#!/usr/bin/env bash
# tests/scripts/disk_check_test.sh — scripts/disk-check.sh passes at exactly what a launch needs
# (floor + 10 GiB stage_size), fails one byte under it with its message, uses 5 % of a large
# filesystem as the floor, and fails on unreadable df output. Runs via `make test-scripts`.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
check="$root/scripts/disk-check.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

GIB=$((1 << 30))
fail=0
# fake_df <size> <avail>: a df stand-in printing one header and one data line.
fake_df() {
  printf '#!/usr/bin/env bash\necho "  1B-blocks     Avail"\necho "%s %s"\n' "$1" "$2" >"$tmp/df"
  chmod +x "$tmp/df"
}
# expect <want exit> <label> <size> <avail> [message fragment]
expect() {
  local rc=0 out
  fake_df "$3" "$4"
  out="$(DISK_CHECK_DF="$tmp/df" bash "$check" /somewhere 2>&1)" || rc=$?
  if [ "$rc" -ne "$1" ]; then
    echo "FAIL: $2: exit $rc, want $1" >&2
    fail=1
  fi
  if [ -n "${5:-}" ] && ! grep -qF -- "$5" <<<"$out"; then
    echo "FAIL: $2: output lacks '$5': $out" >&2
    fail=1
  fi
}

small=$((72 * GIB)) # 5 % is 3.6 GiB: the 4 GiB minimum is the floor
need_small=$((4 * GIB + 10 * GIB))
expect 0 "exactly enough" "$small" "$need_small" "a launch needs 14 GiB"
expect 1 "one byte short" "$small" $((need_small - 1)) "free more in the 'free runner disk' step"
big=$((200 * GIB)) # 5 % is 10 GiB: above the minimum
need_big=$((10 * GIB + 10 * GIB))
expect 0 "percent floor, enough" "$big" "$need_big"
expect 1 "percent floor, one byte short" "$big" $((need_big - 1)) "disk floor $((10 * GIB))"
expect 1 "unreadable df output" "$small" "n/a" "unexpected df output"
rc=0
bash "$check" >/dev/null 2>&1 || rc=$?
[ "$rc" -eq 2 ] || { echo "FAIL: no argument: exit $rc, want 2" >&2; fail=1; }

[ "$fail" -eq 0 ] && echo "disk_check_test: ok"
exit "$fail"
