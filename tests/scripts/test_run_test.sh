#!/usr/bin/env bash
# tests/scripts/test_run_test.sh — scripts/test-run.sh gives each run a fresh id, and afterwards
# removes only that run's containers and image tags; a container left after a passing command
# is a leak and fails the run (architect Q26). Uses a stub podman. Runs via `make test-scripts`.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
run="$root/scripts/test-run.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -m 700 "$tmp/xdg"

# The stub: `ps`/`images` print the state files; `rm`/`rmi` delete a line unless it is listed
# in `stuck`; every call is logged.
cat >"$tmp/podman" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
s="$STUB"
echo "$*" >>"$s/log"
drop() { if grep -qxF "$2" "$s/stuck"; then exit 1; fi; grep -vxF "$2" "$s/$1" >"$s/$1.n" || true; mv "$s/$1.n" "$s/$1"; }
case "$1" in
  ps) [ ! -e "$s/psfail" ] || exit 125; cat "$s/containers" ;;
  images) [ ! -e "$s/imgfail" ] || exit 125; cat "$s/images" ;;
  rm) drop containers "${*: -1}" ;;
  rmi) drop images "${*: -1}" ;;
  *) exit 2 ;;
esac
EOF
chmod +x "$tmp/podman"

fail=0
check() { # <label> <condition...>
  local label="$1"; shift
  if ! "$@"; then echo "FAIL: $label" >&2; fail=1; fi
}

# go <command script>: fresh stub state with another run's names, then the wrapper. Sets rc.
other_c='sp-ws-tzzzzzzzz-1-0-a'
other_i='localhost/sallyport-test:zzzzzzzz-0123456789abcdef'
go() {
  rm -rf "$tmp/s" && mkdir "$tmp/s"
  printf '%s\n' "$other_c" 'sp-ws-tzzzzzzz-1-0-a' 'unrelated' >"$tmp/s/containers"
  printf '%s\n' "$other_i" 'docker.io/library/alpine:3.20' >"$tmp/s/images"
  : >"$tmp/s/stuck"
  rc=0
  STUB="$tmp/s" SALLYPORT_PODMAN="$tmp/podman" XDG_RUNTIME_DIR="$tmp/xdg" \
    SALLYPORT_TEST_RUN=inherit0 bash "$run" bash -c "$1" >"$tmp/out" 2>&1 || rc=$?
}
# Lines the command adds for its own run (it sees the run id in SALLYPORT_TEST_RUN).
own='echo "sp-ws-t$SALLYPORT_TEST_RUN-1-0-a" >>"$STUB/containers";'
own_img='echo "localhost/sallyport-test-net:$SALLYPORT_TEST_RUN-0123456789abcdef" >>"$STUB/images";
         echo "localhost/sallyport-test:$SALLYPORT_TEST_RUN-0123456789abcdef" >>"$STUB/images";
         echo "localhost/sallyport-test:$SALLYPORT_TEST_RUN-x" >>"$STUB/images";'
untouched() { grep -qxF "$other_c" "$tmp/s/containers" && grep -qxF "$other_i" "$tmp/s/images" &&
  grep -qxF 'sp-ws-tzzzzzzz-1-0-a' "$tmp/s/containers" && grep -qx 'docker.io/library/alpine:3.20' "$tmp/s/images"; }
no_rmi_flags() { ! grep -qE '^rmi .*(-f|--force)|prune|--filter' "$tmp/s/log"; }

# Clean success: exit 0, the run's image tags untagged, nobody else's names touched.
go "echo \"id=\$SALLYPORT_TEST_RUN\" >\"\$STUB/id\"; $own_img
    echo \"sp-ws-t\${SALLYPORT_TEST_RUN}0-1-0-a\" >>\"\$STUB/containers\"
    echo \"xsp-ws-t\${SALLYPORT_TEST_RUN}-1-0-a\" >>\"\$STUB/containers\"
    echo \"evil/localhost/sallyport-test:\${SALLYPORT_TEST_RUN}-0123456789abcdef\" >>\"\$STUB/images\"
    echo \"localhost/sallyport-test:\${SALLYPORT_TEST_RUN}-0123456789abcdef0\" >>\"\$STUB/images\""
check "clean success exits 0 (got $rc)" test "$rc" -eq 0
check "a name extending the run id is not this run's" grep -qE '^sp-ws-t[a-z0-9]{8}0-1-0-a$' "$tmp/s/containers"
check "a container name is matched from its start" grep -qE '^xsp-ws-t[a-z0-9]{8}-1-0-a$' "$tmp/s/containers"
check "an image name is matched from its start" grep -qE '^evil/localhost/' "$tmp/s/images"
check "an image tag is matched to its end" grep -qE ':[a-z0-9]{8}-0123456789abcdef0$' "$tmp/s/images"
check "a fresh 8-char run id replaces the inherited one" grep -qxE 'id=[a-z0-9]{8}' "$tmp/s/id"
check "the inherited id is not used" test "$(cat "$tmp/s/id")" != "id=inherit0"
check "own image tags removed" bash -c "! grep -qE '^localhost/sallyport-test(-net)?:$(cut -d= -f2 "$tmp/s/id")-0123456789abcdef\$' '$tmp/s/images'"
check "a tag outside the anchored shape is kept" grep -q ':.*-x$' "$tmp/s/images"
check "other runs untouched (success)" untouched
check "no forced, filtered or pruning removal" no_rmi_flags

# Leak after success: a distinct non-zero exit, the name printed, the container removed.
go "$own"
check "leak after success exits 3 (got $rc)" test "$rc" -eq 3
check "leak names the container" grep -q 'sp-ws-t[a-z0-9]\{8\}-1-0-a' "$tmp/out"
check "leaked container swept" bash -c "test \$(grep -c '^sp-ws-t' '$tmp/s/containers') -eq 2"
check "other runs untouched (leak)" untouched
check "containers removed before images" bash -c "awk '/^rmi /{i=NR} /^rm /{r=NR} END{exit !(r && (!i || r < i))}' '$tmp/s/log'"

# Command failure keeps its own status; leftovers are still swept.
go "$own exit 7"
check "command failure keeps its status (got $rc)" test "$rc" -eq 7
check "leftovers swept after a failure" bash -c "test \$(grep -c '^sp-ws-t' '$tmp/s/containers') -eq 2"
check "other runs untouched (failure)" untouched

# A container that cannot be removed fails the run even after success.
go "$own"' echo "sp-ws-t$SALLYPORT_TEST_RUN-1-0-a" >"$STUB/stuck"'
check "an unremovable container exits 4 (got $rc)" test "$rc" -eq 4

# Interrupted: the sweep still runs.
go "$own"' kill -TERM $PPID; sleep 5'
check "a terminated run exits non-zero (got $rc)" test "$rc" -ne 0
check "a terminated run still sweeps" bash -c "test \$(grep -c '^sp-ws-t' '$tmp/s/containers') -eq 2"

# Interrupted with INT: the whole command is stopped, grandchildren included, so nothing is
# created after the sweep (security review M1).
go "$own"' (sleep 2; echo late >>"$STUB/containers") & kill -INT $PPID; wait'
sleep 3
check "an interrupted run exits non-zero (got $rc)" test "$rc" -ne 0
check "an interrupted run stops its grandchildren" bash -c "! grep -qx late '$tmp/s/containers'"
check "an interrupted run still sweeps" bash -c "test \$(grep -c '^sp-ws-t' '$tmp/s/containers') -eq 2"

# A listing podman cannot give fails closed, never reads as "nothing left" (security review M2).
for f in psfail imgfail; do
  go "touch \"\$STUB/$f\""
  check "a failed podman listing ($f) exits non-zero (got $rc)" test "$rc" -ne 0
  go "$own touch \"\$STUB/$f\"; exit 7"
  check "a failed listing ($f) keeps a failed command's status (got $rc)" test "$rc" -eq 7
done

# Ruling 3 / Q65: a test that timed out on the disk-free lock has not run. It lists itself in
# $SALLYPORT_TEST_NOT_RUN/list; the wrapper re-runs each listed test once (through the cargo
# stub) and reports by the re-run. The stub cargo prints what the re-run "did", from $STUB/rerun:
# pass (one test passed), fail (exit 101), none (zero tests), notrun (lists itself again).
cat >"$tmp/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
echo "cargo $*" >>"$STUB/log"
case "$(cat "$STUB/rerun")" in
  pass) echo "test result: ok. 1 passed; 0 failed; 0 ignored" ;;
  fail) echo "test result: FAILED. 0 passed; 1 failed"; exit 101 ;;
  none) echo "test result: ok. 0 passed; 0 failed; 0 ignored" ;;
  notrun) echo "sallyd disk ${*: -1}" >>"$SALLYPORT_TEST_NOT_RUN/list"
          echo "test result: ok. 1 passed; 0 failed; 0 ignored" ;;
  # Lists itself again, but the build failed: the failure is the verdict.
  failnotrun) echo "sallyd disk ${*: -1}" >>"$SALLYPORT_TEST_NOT_RUN/list"; exit 101 ;;
  # A re-run that reads its stdin must find nothing there (not the rest of the list).
  stdin) if IFS= read -r x; then echo "ate $x" >>"$STUB/log"; fi
         echo "test result: ok. 1 passed; 0 failed; 0 ignored" ;;
  # The wrapper is terminated during the re-run, whose child would create a container late.
  # (TERM: the test starts the wrapper in the background, where INT is ignored.)
  signal) while [ ! -s "$STUB/wrapper" ]; do sleep 0.1; done
          (sleep 2; echo late >>"$STUB/containers") &
          kill -TERM "$(cat "$STUB/wrapper")"; wait ;;
esac
EOF
chmod +x "$tmp/cargo"
lists='echo "sallyd disk rt_ag_09_one" >>"$SALLYPORT_TEST_NOT_RUN/list";'
# notrun <rerun> <command script>: go with the cargo stub set to <rerun>.
notrun() {
  rm -rf "$tmp/s" && mkdir "$tmp/s"
  : >"$tmp/s/containers"; : >"$tmp/s/images"; : >"$tmp/s/stuck"
  echo "$1" >"$tmp/s/rerun"
  rc=0
  STUB="$tmp/s" SALLYPORT_PODMAN="$tmp/podman" SALLYPORT_CARGO="$tmp/cargo" \
    XDG_RUNTIME_DIR="$tmp/xdg" SALLYPORT_TEST_NOT_RUN=/inherited \
    bash "$run" bash -c "$2" >"$tmp/out" 2>&1 || rc=$?
}

notrun pass 'test -d "$SALLYPORT_TEST_NOT_RUN" && test "$SALLYPORT_TEST_NOT_RUN" != /inherited &&
  test "$(stat -c %a "$SALLYPORT_TEST_NOT_RUN")" = 700 && echo ok >"$STUB/dir"'
check "an empty list: no re-run, exit 0 (got $rc)" test "$rc" -eq 0
check "a fresh private list directory replaces an inherited one" test -f "$tmp/s/dir"
check "an empty list re-runs nothing" bash -c "! grep -q '^cargo' '$tmp/s/log' 2>/dev/null"

notrun pass "$lists"
check "listed, re-run passes: exit 0 (got $rc)" test "$rc" -eq 0
check "the re-run names the exact test" grep -qx 'cargo test -p sallyd --test disk -- --exact rt_ag_09_one' "$tmp/s/log"
check "NOT RUN is printed on stderr" grep -q 'NOT RUN.*rt_ag_09_one' "$tmp/out"

notrun pass "$lists $lists"
check "a test listed twice is re-run once" test "$(grep -c '^cargo' "$tmp/s/log")" -eq 1

notrun fail "$lists"
check "listed, re-run fails: its status (got $rc)" test "$rc" -eq 101

notrun notrun "$lists"
check "listed and still not run: exit 6 (got $rc)" test "$rc" -eq 6
check "still not run names the test and the lock" grep -q 'did not run.*rt_ag_09_one.*disk-free' "$tmp/out"

notrun none "$lists"
check "a re-run that ran no test: exit 6 (got $rc)" test "$rc" -eq 6

# Review fixes (PS-L1, PS-L2/PR-M3, PR-M2, rc first).
notrun failnotrun "$lists"
check "a failed re-run that listed itself keeps its status (got $rc)" test "$rc" -eq 101

two='echo "sallyd disk rt_ag_09_one" >>"$SALLYPORT_TEST_NOT_RUN/list";
     echo "sallyd disk rt_ag_09_two" >>"$SALLYPORT_TEST_NOT_RUN/list";'
notrun stdin "$two"
check "a re-run reading stdin: exit 0 (got $rc)" test "$rc" -eq 0
check "every listed test is re-run though one reads stdin" test "$(grep -c '^cargo' "$tmp/s/log")" -eq 2
check "a re-run's stdin is empty" bash -c "! grep -q '^ate' '$tmp/s/log'"

notrun pass "printf '%s' 'sallyd disk rt_ag_09_one' >>\"\$SALLYPORT_TEST_NOT_RUN/list\""
check "a last line without a newline: exit 0 (got $rc)" test "$rc" -eq 0
check "a last line without a newline is re-run" grep -qx 'cargo test -p sallyd --test disk -- --exact rt_ag_09_one' "$tmp/s/log"

for bad in 'sallyd disk -x' 'sallyd --test a' '-p disk a' 'sallyd disk rt_ag_09_one

'; do
  notrun pass "printf '%s' '$bad' >>\"\$SALLYPORT_TEST_NOT_RUN/list\""
  check "a field starting with a dash, or a blank line, exits 6: '$bad' (got $rc)" test "$rc" -eq 6
  check "and re-runs nothing: '$bad'" bash -c "! grep -q '^cargo' '$tmp/s/log' 2>/dev/null"
done

rm -rf "$tmp/s" && mkdir "$tmp/s"
: >"$tmp/s/containers"; : >"$tmp/s/images"; : >"$tmp/s/stuck"
echo signal >"$tmp/s/rerun"
rc=0
STUB="$tmp/s" SALLYPORT_PODMAN="$tmp/podman" SALLYPORT_CARGO="$tmp/cargo" \
  XDG_RUNTIME_DIR="$tmp/xdg" bash "$run" bash -c "$lists" >"$tmp/out" 2>&1 &
echo $! >"$tmp/s/wrapper"
wait $! || rc=$?
sleep 3
check "a run interrupted in its re-run exits non-zero (got $rc)" test "$rc" -ne 0
check "an interrupted re-run stops its children" bash -c "! grep -qx late '$tmp/s/containers'"
check "an interrupted re-run leaves no list directory" bash -c "! ls -d '$tmp/xdg/sallyport-test/not-run.'* 2>/dev/null"

for bad in 'sallyd disk' 'sallyd disk a b' 'sallyd disk a;b' 'sallyd ../x a' 'sallyd disk $(id)'; do
  notrun pass "printf '%s\n' '$bad' >>\"\$SALLYPORT_TEST_NOT_RUN/list\""
  check "a malformed line exits 6: '$bad' (got $rc)" test "$rc" -eq 6
  check "a malformed line re-runs nothing: '$bad'" bash -c "! grep -q '^cargo' '$tmp/s/log' 2>/dev/null"
done

notrun pass "$lists exit 7"
check "a failed command keeps its status though a list exists (got $rc)" test "$rc" -eq 7
check "NOT RUN is printed even when the command failed" grep -q 'NOT RUN.*rt_ag_09_one' "$tmp/out"
check "a failed command re-runs nothing" bash -c "! grep -q '^cargo' '$tmp/s/log' 2>/dev/null"
check "the list directory is removed" bash -c "! ls -d '$tmp/xdg/sallyport-test/not-run.'* 2>/dev/null"

# The lock directory and XDG_RUNTIME_DIR itself must be private.
chmod 755 "$tmp/xdg"
go "$own_img"
check "a group/other-accessible XDG_RUNTIME_DIR is refused (got $rc)" test "$rc" -ne 0
chmod 700 "$tmp/xdg"
chmod 755 "$tmp/xdg/sallyport-test" 2>/dev/null || mkdir -m 755 "$tmp/xdg/sallyport-test"
go "$own_img"
check "a group/other-accessible lock directory is refused (got $rc)" test "$rc" -ne 0
chmod 700 "$tmp/xdg/sallyport-test"

exit "$fail"
