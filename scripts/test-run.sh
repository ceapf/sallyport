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
# - A disk-floor test that timed out waiting for the disk-free lock has not run (ruling 3,
#   architect Q65): it lists itself in $SALLYPORT_TEST_NOT_RUN (a fresh private directory made
#   here) and returns, so its first-pass PASS line is not a verdict; this script's exit is.
#   After a passing command each listed test is re-run once, alone, under the same run id; the
#   names are printed (NOT RUN) whatever the outcome.
# - Exit: a failed command keeps its status. A container left after a passing command is a
#   leak: exit 3, names printed. A container still present after the sweep: exit 4 (or the
#   command's own non-zero status). A listed test still not run on its re-run, a re-run that ran
#   other than exactly one test, or a malformed list line: exit 6; a re-run that fails keeps its
#   status.
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

# Ruling 3 / Q65: a disk-floor test that timed out waiting for the disk-free lock has not run.
# It lists itself (`<package> <test binary> <test name>`) in this fresh private directory and
# returns; an inherited value is overwritten. Removed when the run ends.
notrun="$(mktemp -d "$locks/not-run.XXXXXXXX")"
export SALLYPORT_TEST_NOT_RUN="$notrun"
cargo_bin="${SALLYPORT_CARGO:-cargo}"

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
  rm -rf -- "$notrun"
  exit "$rc"
}

# The tests listed in <dir>/list, one `<package> <binary> <test>` per line, deduplicated. The
# deduplicated text is what is checked and returned, last line included with or without its
# newline. A malformed line (a field not of [A-Za-z0-9_-] or starting with `-`, a blank line)
# fails (exit 6): it is never skipped.
listed() {
  local f="$1/list" line out
  [ -s "$f" ] || return 0
  out="$(sort -u "$f")"
  while IFS= read -r line || [ -n "$line" ]; do
    [[ "$line" =~ ^[A-Za-z0-9_][A-Za-z0-9_-]*\ [A-Za-z0-9_][A-Za-z0-9_-]*\ [A-Za-z0-9_][A-Za-z0-9_-]*$ ]] || {
      echo "test-run: malformed not-run line: $line" >&2
      return 6
    }
  done <<<"$out"
  printf '%s\n' "$out"
}

# rerun <package> <binary> <test>: runs that one test with a fresh list (inside $notrun, so the
# run's end removes it). Like the command: its own process group, which a signal stops, and
# stdin from /dev/null (it never reads the rest of the list). A failure keeps its status;
# otherwise 0 only when exactly one test ran and passed and it did not list itself again (6).
rerun() {
  local again rc=0
  again="$(mktemp -d "$notrun/again.XXXXXXXX")"
  set -m
  SALLYPORT_TEST_NOT_RUN="$again" "$cargo_bin" test -p "$1" --test "$2" -- --exact "$3" \
    >"$again/out" 2>&1 </dev/null &
  child=$!
  set +m
  wait "$child" || rc=$?
  child=
  cat -- "$again/out"
  if [ "$rc" -ne 0 ]; then
    return "$rc"
  fi
  if [ -s "$again/list" ]; then
    return 6
  fi
  grep -qE '^test result: ok\. 1 passed;' "$again/out" || {
    echo "test-run: the re-run of $3 did not run exactly one test" >&2
    return 6
  }
}

# not_run <command status>: reports the listed tests and, after a passing command, re-runs each
# once. The command's own failure wins. Exit 6: a test still not run, or a malformed list.
not_run() {
  local status="$1" tests pkg bin name rc still=()
  tests="$(listed "$notrun")" || { worse "$status" 6; return $?; }
  [ -n "$tests" ] || return "$status"
  echo "test-run: NOT RUN (the disk-free lock was not free): $(cut -d' ' -f3 <<<"$tests" | tr '\n' ' ')" >&2
  [ "$status" -eq 0 ] || return "$status"
  while read -r pkg bin name; do
    rc=0
    rerun "$pkg" "$bin" "$name" || rc=$?
    if [ "$rc" -eq 6 ]; then
      still+=("$name")
    elif [ "$rc" -ne 0 ]; then
      return "$rc"
    fi
  done <<<"$tests"
  if [ "${#still[@]}" -gt 0 ]; then
    echo "test-run: did not run: ${still[*]} (the lock $locks/disk-free.lock was not free)" >&2
    return 6
  fi
  return 0
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
not_run "$status" || status=$?
exit "$status"
