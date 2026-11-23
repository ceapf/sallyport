#!/usr/bin/env bash
# tests/scripts/loaded_repeat_test.sh — scripts/loaded-repeat.sh's verdicts, with stub commands
# for the pre-build, the load and the repeat (no cargo, no podman). A repeat passes only on exit
# 0 with "4 passed" and the fork-bomb test's diagnostic line; one red still runs every repeat and
# fails the run; a repeat without the load at its start and end is not counted; a time-out is red;
# a load pass that failed in the fork-bomb test fails the run; the load is stopped at the end.
# Runs via `make test-scripts`.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
script="$root/scripts/loaded-repeat.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# The repeat stub: bash run.sh <counter file> <mode,mode,...> prints the log of the mode at the
# position of this call (the last mode repeats).
cat >"$tmp/run.sh" <<'EOF'
n=$(($(cat "$1" 2>/dev/null || echo 0) + 1))
echo "$n" >"$1"
IFS=, read -ra modes <<<"$2"
i=$((n - 1))
[ "$i" -lt "${#modes[@]}" ] || i=$((${#modes[@]} - 1))
fork=rt_ag_09_a_fork_bomb_is_held_by_the_pids_limit
figures="rt_ag_09 fork-bomb figures: memory.peak=$((1000 + n)) max=0 oom=0 oom_kill=0 oom_group_kill=0 pids.peak=64 pids.events.max=3"
case "${modes[$i]}" in
  pass) printf 'test %s ... ok\n%s\ntest result: ok. 4 passed; 0 failed\n' "$fork" "$figures" ;;
  red) printf 'test %s ... FAILED\n%s\ntest result: FAILED. 3 passed; 1 failed\n' "$fork" "$figures"; exit 101 ;;
  nodiag) printf 'test %s ... ok\ntest result: ok. 4 passed; 0 failed\n' "$fork" ;;
  leak) printf 'test %s ... ok\n%s\ntest result: ok. 4 passed; 0 failed\n' "$fork" "$figures"; exit 3 ;;
  three) printf 'test %s ... ok\n%s\ntest result: ok. 3 passed; 0 failed\n' "$fork" "$figures" ;;
  slow) sleep 2; printf 'test %s ... ok\n%s\ntest result: ok. 4 passed; 0 failed\n' "$fork" "$figures" ;;
  hang) sleep 30 ;;
esac
EOF

fail=0
case_n=0
# run <name> <count> <want exit> <modes> [VAR=value...]: runs the script with the stubs; the load
# defaults to a long sleep. Leaves the results in $tmp/<name>/results.txt.
run() {
  local name="$1" n="$2" want="$3" modes="$4" got=0
  shift 4
  case_n=$((case_n + 1))
  # Bounded: a script that never stops fails its case (124) instead of hanging the suite.
  timeout 60 env LOADED_REPEAT_PREBUILD=true LOADED_REPEAT_LOAD="sleep 30" \
    LOADED_REPEAT_RUN="bash $tmp/run.sh $tmp/$name.count $modes" "$@" \
    bash "$script" "$n" "$tmp/$name" >"$tmp/$name.out" 2>&1 || got=$?
  if [ "$got" != "$want" ]; then
    echo "FAIL $name: exit $got, want $want"
    cat "$tmp/$name.out" "$tmp/$name/results.txt" 2>/dev/null
    fail=1
  fi
}
# has <name> <fixed string>: the case's results file holds that text.
has() {
  if ! grep -qF -- "$2" "$tmp/$1/results.txt"; then
    echo "FAIL $1: no '$2' in its results"
    cat "$tmp/$1/results.txt"
    fail=1
  fi
}
# lines <name> <want>: the case's results hold exactly that many run lines.
lines() {
  local got
  got=$(grep -c ' run=' "$tmp/$1/results.txt" || true)
  if [ "$got" != "$2" ]; then
    echo "FAIL $1: $got run lines, want $2"
    fail=1
  fi
}

started=$(date +%s)
run all 3 0 pass
lines all 3
has all "run=2 loaded pass fork-bomb=ok memory.peak=1002 oom_kill=0 pids.peak=64"
has all "load pass 1: stopped (TERM)"
has all "planned 3, loaded 3, unloaded 0, passed 3, red 0, load passes 1, verdict pass"
# The 30 s load was stopped, not waited out.
[ $(($(date +%s) - started)) -lt 20 ] || { echo "FAIL all: the load was not stopped"; fail=1; }

run one-red 3 1 pass,red,pass
lines one-red 3
has one-red "run=2 loaded red fork-bomb=FAILED"
has one-red "run=3 loaded pass"
has one-red "passed 2, red 1, load passes 1, verdict red"

run no-figures 2 1 pass,nodiag
has no-figures "run=2 loaded red fork-bomb=ok memory.peak= oom_kill= pids.peak= secs="
has no-figures "verdict red"

# test-run.sh's own failures (a leaked container, 3) after a passing test binary are red.
run leaked 1 1 leak
has leaked "run=1 loaded red fork-bomb=ok memory.peak=1001 oom_kill=0 pids.peak=64"
has leaked "exit=3"

run wrong-count 1 1 three
has wrong-count "run=1 loaded red"

run unloaded 1 1 slow LOADED_REPEAT_LOAD="sleep 1" LOADED_REPEAT_RESTART=0
lines unloaded 1
has unloaded "run=1 unloaded pass"
has unloaded "load pass 1: exit 0, fork-bomb test failed: no"
has unloaded "planned 1, loaded 0, unloaded 1, passed 1, red 0, load passes 1, verdict incomplete"

# A 1 s load under 0.4 s repeats ends mid-run: it is started again until 5 loaded repeats ran.
run restarted 5 0 pass LOADED_REPEAT_LOAD="sleep 1" \
  LOADED_REPEAT_RUN="sleep 0.4; bash $tmp/run.sh $tmp/restarted.count pass"
has restarted "load pass 1: exit 0"
has restarted "load pass 2"
has restarted "planned 5, loaded 5,"

run time-out 1 1 hang LOADED_REPEAT_LIMIT=1
has time-out "run=1 loaded red fork-bomb=unknown"
has time-out "exit=124"

# A load that fails within a repeat's time: the fork-bomb failure in its log is red, and after
# two passes with no loaded repeat the load is not started again.
run load-red 1 1 slow \
  LOADED_REPEAT_LOAD="sleep 1; echo '---- rt_ag_09_a_fork_bomb_is_held_by_the_pids_limit stdout ----'; exit 101"
has load-red "load pass 1: exit 101, fork-bomb test failed: yes"
has load-red "loaded 0, unloaded 2, passed 2, red 0, load passes 2, verdict red"

run idle-load 1 1 slow LOADED_REPEAT_LOAD="sleep 1; exit 2"
has idle-load "load pass 2: exit 2, fork-bomb test failed: no"
has idle-load "loaded 0, unloaded 2, passed 2, red 0, load passes 2, verdict incomplete"

run start-limit 5 1 slow LOADED_REPEAT_START_LIMIT=1
lines start-limit 1
has start-limit "loaded 1, unloaded 0, passed 1, red 0, load passes 1, verdict incomplete"

for args in "0 $tmp/u" "x $tmp/u" "1"; do
  got=0
  # shellcheck disable=SC2086 # the cases are word lists
  bash "$script" $args >/dev/null 2>&1 || got=$?
  [ "$got" = 2 ] || { echo "FAIL usage '$args': exit $got, want 2"; fail=1; }
done
got=0
LOADED_REPEAT_RESTART=2 bash "$script" 1 "$tmp/u" >/dev/null 2>&1 || got=$?
[ "$got" = 2 ] || { echo "FAIL restart 2: exit $got, want 2"; fail=1; }

if [ "$fail" -eq 0 ]; then
  echo "loaded_repeat_test: ok ($case_n cases and the usage errors)"
fi
exit "$fail"
