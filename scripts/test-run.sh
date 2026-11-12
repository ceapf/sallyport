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

# The per-user lock directory the fixture uses too (architect Q23): it and XDG_RUNTIME_DIR are
# real directories owned by this user with no group or other access, so nobody else can plant
# a file or link at the lock path (the `9>>` below follows a link; only this user could make one).
private_dir() {
  [ ! -L "$1" ] && [ -d "$1" ] && [ "$(stat -c %u "$1")" = "$(id -u)" ] &&
    [ $((8#$(stat -c %a "$1") & 8#077)) -eq 0 ]
}
[[ "${XDG_RUNTIME_DIR:-}" == /* ]] || { echo "test-run: XDG_RUNTIME_DIR must be absolute" >&2; exit 2; }
locks="$XDG_RUNTIME_DIR/sallyport-test"
private_dir "$XDG_RUNTIME_DIR" && mkdir -p -m 700 "$locks" && private_dir "$locks" || {
  echo "test-run: XDG_RUNTIME_DIR and $locks must be directories owned by this user, mode 0700" >&2
  exit 2
}

alphabet=abcdefghijklmnopqrstuvwxyz0123456789
id=
for b in $(od -An -N8 -tu1 /dev/urandom); do id+="${alphabet:b%36:1}"; done
[[ "$id" =~ ^[a-z0-9]{8}$ ]] || { echo "test-run: no run id" >&2; exit 2; }
export SALLYPORT_TEST_RUN="$id"
echo "test-run: run $id"

# mine <regex> <podman args...>: the matching lines of a podman listing. A failed listing fails
# (exit 5): it never reads as "nothing left" (security review M2). grep's "no match" is empty.
mine() {
  local re="$1" out
  shift
  out="$("$podman" "$@")" || { echo "test-run: podman $1 failed" >&2; return 5; }
  printf '%s\n' "$out" | grep -E "$re" || [ $? -eq 1 ]
}
own_containers() { mine "^sp-(ws|h|infer)-t${id}-" ps --all --format '{{.Names}}'; }
own_images() {
  mine "^localhost/sallyport-test(-net|-exit)?:${id}-[0-9a-f]{16}\$" \
    images --format '{{.Repository}}:{{.Tag}}'
}

# worse <status> <rc>: the command's own failure wins; otherwise rc. Callers write `return $?`:
# sweep runs in the EXIT trap, where a bare `return` gives the status from before the trap.
worse() { if [ "$1" -ne 0 ]; then return "$1"; fi; return "$2"; }

swept=0
sweep() { # <command status>; prints nothing on a clean run
  [ "$swept" -eq 0 ] || return 0
  swept=1
  local status="$1" left still n
  left="$(own_containers)" || { worse "$status" 5; return $?; }
  while IFS= read -r n; do
    [ -z "$n" ] || "$podman" rm --force --time 0 "$n" >/dev/null 2>&1 || true
  done <<<"$left"
  # Untag under the image lock, so it never interleaves with another run's build.
  if ! (
    flock 9
    imgs="$(own_images)" || exit 5
    while IFS= read -r n; do
      [ -z "$n" ] || "$podman" rmi "$n" >/dev/null 2>&1 || echo "test-run: could not untag $n" >&2
    done <<<"$imgs"
  ) 9>>"$locks/test-image.lock"; then
    worse "$status" 5
    return $?
  fi
  still="$(own_containers)" || { worse "$status" 5; return $?; }
  if [ -n "$still" ]; then
    printf 'test-run: containers still present after the sweep:\n%s\n' "$still" >&2
    worse "$status" 4
    return $?
  fi
  if [ -n "$left" ]; then
    printf 'test-run: containers left behind (removed):\n%s\n' "$left" >&2
    worse "$status" 3
    return $?
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
# Stop the whole command first (its process group: cargo, the test binaries, their children), so
# nothing is created after the sweep (security review M1).
on_signal() {
  [ -z "$child" ] || { kill -TERM -- "-$child" 2>/dev/null || true; wait "$child" 2>/dev/null || true; }
  exit "$1"
}
trap finish EXIT
trap 'on_signal 130' INT
trap 'on_signal 143' TERM

# Job control: the command gets its own process group, with SIGINT not ignored (a non-interactive
# shell starts background jobs with INT and QUIT ignored).
set -m
"$@" &
child=$!
set +m
status=0
wait "$child" || status=$?
child=
exit "$status"
