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
  ps) cat "$s/containers" ;;
  images) cat "$s/images" ;;
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
    echo \"sp-ws-t\${SALLYPORT_TEST_RUN}0-1-0-a\" >>\"\$STUB/containers\""
check "clean success exits 0 (got $rc)" test "$rc" -eq 0
check "a name extending the run id is not this run's" grep -qE '^sp-ws-t[a-z0-9]{8}0-1-0-a$' "$tmp/s/containers"
check "a fresh 8-char run id replaces the inherited one" grep -qxE 'id=[a-z0-9]{8}' "$tmp/s/id"
check "the inherited id is not used" test "$(cat "$tmp/s/id")" != "id=inherit0"
check "own image tags removed" bash -c "! grep -q 'sallyport-test.*:$(cut -d= -f2 "$tmp/s/id")-0123' '$tmp/s/images'"
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

# The lock directory must be private.
chmod 755 "$tmp/xdg/sallyport-test" 2>/dev/null || mkdir -m 755 "$tmp/xdg/sallyport-test"
go "$own_img"
check "a group/other-accessible lock directory is refused (got $rc)" test "$rc" -ne 0
chmod 700 "$tmp/xdg/sallyport-test"

exit "$fail"
