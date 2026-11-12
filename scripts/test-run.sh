#!/usr/bin/env bash
# scripts/test-run.sh <command...> — runs a test command as one run, so two worktrees can test
# at the same time (Task 8 PR C, architect Q24–Q26).
#
# - Gives the run a fresh id: SALLYPORT_TEST_RUN, 8 characters of [a-z0-9], always generated
#   here (an inherited value is overwritten, so two runs started from one shell never share it).
#   The fixture names its containers `sp-{ws,h,infer}-t<run>-…` and its images
#   `localhost/sallyport-test{,-net,-exit}:<run>-<hash>`.
# - Afterwards, also on INT/TERM, removes only this run's containers (anchored names, then
#   `podman rm`), then only this run's image tags (anchored names, plain `podman rmi` under the
#   test-image lock, which only untags while another tag remains). Never a filter, an ID, a
#   forced removal or a prune; never another run's names or the base image.
# - Exit: a failed command keeps its status. A container left after a passing command is a
#   leak: exit 3, names printed. A container still present after the sweep: exit 4 (or the
#   command's own non-zero status).
# SALLYPORT_PODMAN overrides the podman binary (tests/scripts/test_run_test.sh uses a stub).
set -euo pipefail

[ $# -ge 1 ] || { echo "usage: test-run.sh <command...>" >&2; exit 2; }
podman="${SALLYPORT_PODMAN:-podman}"

# The machine-wide lock directory the fixture uses too (architect Q23): private, ours, real.
[[ "${XDG_RUNTIME_DIR:-}" == /* ]] || { echo "test-run: XDG_RUNTIME_DIR must be absolute" >&2; exit 2; }
locks="$XDG_RUNTIME_DIR/sallyport-test"
mkdir -p -m 700 "$locks"
if [ -L "$locks" ] || [ "$(stat -c '%u %a' "$locks")" != "$(id -u) 700" ]; then
  echo "test-run: $locks must be a directory owned by this user with mode 0700" >&2
  exit 2
fi

alphabet=abcdefghijklmnopqrstuvwxyz0123456789
id=
for b in $(od -An -N8 -tu1 /dev/urandom); do id+="${alphabet:b%36:1}"; done
[[ "$id" =~ ^[a-z0-9]{8}$ ]] || { echo "test-run: no run id" >&2; exit 2; }
export SALLYPORT_TEST_RUN="$id"
echo "test-run: run $id"

own_containers() {
  "$podman" ps --all --format '{{.Names}}' | grep -E "^sp-(ws|h|infer)-t${id}-" || true
}
own_images() {
  "$podman" images --format '{{.Repository}}:{{.Tag}}' |
    grep -E "^localhost/sallyport-test(-net|-exit)?:${id}-[0-9a-f]{16}\$" || true
}

swept=0
sweep() { # <command status>; prints nothing on a clean run
  [ "$swept" -eq 0 ] || return 0
  swept=1
  local status="$1" left names
  left="$(own_containers)"
  for names in $left; do
    "$podman" rm --force --time 0 "$names" >/dev/null 2>&1 || true
  done
  (
    flock 9
    for names in $(own_images); do
      "$podman" rmi "$names" >/dev/null 2>&1 || echo "test-run: could not untag $names" >&2
    done
  ) 9>>"$locks/test-image.lock"
  if [ -n "$(own_containers)" ]; then
    echo "test-run: containers still present after the sweep:" >&2
    own_containers >&2
    [ "$status" -ne 0 ] && return "$status"
    return 4
  fi
  if [ -n "$left" ]; then
    echo "test-run: containers left behind (removed):" >&2
    printf '%s\n' "$left" >&2
    [ "$status" -ne 0 ] && return "$status"
    return 3
  fi
  return "$status"
}

child=
finish() {
  local rc=$?
  trap - EXIT INT TERM
  sweep "$rc" || rc=$?
  exit "$rc"
}
on_signal() { # stop the command first, so it creates nothing after the sweep
  [ -z "$child" ] || { kill -TERM "$child" 2>/dev/null || true; wait "$child" 2>/dev/null || true; }
  exit "$1"
}
trap finish EXIT
trap 'on_signal 130' INT
trap 'on_signal 143' TERM

"$@" &
child=$!
status=0
wait "$child" || status=$?
child=
exit "$status"
