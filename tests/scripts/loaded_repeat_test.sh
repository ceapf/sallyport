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
  hit) printf 'test %s ... ok\n%s\ntest result: ok. 4 passed; 0 failed\n' "$fork" \
    "rt_ag_09 fork-bomb figures: memory.peak=67108864 max=4 oom=0 oom_kill=0 oom_group_kill=0 pids.peak=64 pids.events.max=3" ;;
  nopeak) printf 'test %s ... ok\n%s\ntest result: ok. 4 passed; 0 failed\n' "$fork" \
    "rt_ag_09 fork-bomb figures: memory.peak=absent max=0 oom=0 oom_kill=0 oom_group_kill=0 pids.peak=absent pids.events.max=3" ;;
  nomax) printf 'test %s ... ok\n%s\ntest result: ok. 4 passed; 0 failed\n' "$fork" \
    "rt_ag_09 fork-bomb figures: memory.peak=$((1000 + n)) oom_kill=0 pids.peak=64 pids.events.max=7" ;;
  kill) printf 'test %s ... FAILED\n%s\ntest result: FAILED. 3 passed; 1 failed\n' "$fork" \
    "rt_ag_09 fork-bomb figures: memory.peak=67108864 max=9 oom=1 oom_kill=1 oom_group_kill=0 pids.peak=64 pids.events.max=3"; exit 101 ;;
  leak) printf 'test %s ... ok\n%s\ntest result: ok. 4 passed; 0 failed\n' "$fork" "$figures"; exit 3 ;;
  three) printf 'test %s ... ok\n%s\ntest result: ok. 3 passed; 0 failed\n' "$fork" "$figures" ;;
  slow) sleep 2; printf 'test %s ... ok\n%s\ntest result: ok. 4 passed; 0 failed\n' "$fork" "$figures" ;;
  hang) sleep 30 ;;
  # Records the TERM it gets (as test-run.sh would sweep on it) in <counter file>.term.
  trapped) sleep 30 & trap 'kill $!; echo term >"$1.term"; exit 143' TERM; wait ;;
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
has all "run=2 loaded pass fork-bomb=ok memory.peak=1002 max=0 oom_kill=0 pids.peak=64"
has all "load pass 1: stopped (TERM)"
has all "planned 3, loaded 3, unloaded 0, passed 3, red 0, load passes 1, memory limit hit (max above 0) 0, OOM kills (oom_kill above 0) 0, highest memory.peak 1003, verdict pass"
# The 30 s load was stopped, not waited out.
[ $(($(date +%s) - started)) -lt 20 ] || { echo "FAIL all: the load was not stopped"; fail=1; }

run one-red 3 1 pass,red,pass
lines one-red 3
has one-red "run=2 loaded red fork-bomb=FAILED"
has one-red "run=3 loaded pass"
has one-red "passed 2, red 1, load passes 1,"
has one-red "verdict red"

run no-figures 2 1 pass,nodiag
has no-figures "run=2 loaded red fork-bomb=ok memory.peak= max= oom_kill= pids.peak= secs="
has no-figures "verdict red"

# test-run.sh's own failures (a leaked container, 3) after a passing test binary are red.
run leaked 1 1 leak
has leaked "run=1 loaded red fork-bomb=ok memory.peak=1001 max=0 oom_kill=0 pids.peak=64"
has leaked "exit=3"

run wrong-count 1 1 three
has wrong-count "run=1 loaded red"

run unloaded 1 1 slow LOADED_REPEAT_LOAD="sleep 1" LOADED_REPEAT_RESTART=0
lines unloaded 1
has unloaded "run=1 unloaded pass"
has unloaded "load pass 1: exit 0, fork-bomb test failed: no"
has unloaded "planned 1, loaded 0, unloaded 1, passed 1, red 0, load passes 1,"
has unloaded "verdict incomplete"

# A 2 s load under 0.3 s repeats ends mid-run: it is started again until 10 loaded repeats ran.
run restarted 10 0 pass LOADED_REPEAT_LOAD="sleep 2" \
  LOADED_REPEAT_RUN="sleep 0.3; bash $tmp/run.sh $tmp/restarted.count pass"
has restarted "load pass 1: exit 0"
has restarted "load pass 2"
has restarted "planned 10, loaded 10,"

run time-out 1 1 hang LOADED_REPEAT_LIMIT=1 LOADED_REPEAT_KILL_AFTER=5
has time-out "run=1 loaded red fork-bomb=unknown"
has time-out "exit=124"

# A load that fails within a repeat's time: the fork-bomb failure in its log is red, and after
# two passes with no loaded repeat the load is not started again.
run load-red 1 1 slow \
  LOADED_REPEAT_LOAD="sleep 1; echo '---- rt_ag_09_a_fork_bomb_is_held_by_the_pids_limit stdout ----'; exit 101"
has load-red "load pass 1: exit 101, fork-bomb test failed: yes"
has load-red "loaded 0, unloaded 2, passed 2, red 0, load passes 2,"
has load-red "verdict red"

run idle-load 1 1 slow LOADED_REPEAT_LOAD="sleep 1; exit 2"
has idle-load "load pass 2: exit 2, fork-bomb test failed: no"
has idle-load "loaded 0, unloaded 2, passed 2, red 0, load passes 2,"
has idle-load "verdict incomplete"

run start-limit 5 1 slow LOADED_REPEAT_START_LIMIT=1
lines start-limit 1
has start-limit "loaded 1, unloaded 0, passed 1, red 0, load passes 1,"
has start-limit "verdict incomplete"

# A pass that hit the memory limit stays a pass; the hit, the kill count and the highest peak are
# reported. A figures line without a memory.events max reads max empty, never pids.events.max.
run limit-hit 3 0 pass,hit,nomax
has limit-hit "run=2 loaded pass fork-bomb=ok memory.peak=67108864 max=4 oom_kill=0 pids.peak=64"
has limit-hit "run=3 loaded pass fork-bomb=ok memory.peak=1003 max= oom_kill=0 pids.peak=64"
has limit-hit "memory limit hit (max above 0) 1, OOM kills (oom_kill above 0) 0, highest memory.peak 67108864, verdict pass"
# A kernel without memory.peak prints absent: never the highest peak.
run no-peak 2 0 nopeak,pass
has no-peak "run=1 loaded pass fork-bomb=ok memory.peak=absent max=0"
has no-peak "highest memory.peak 1002, verdict pass"
run killed 1 1 kill
has killed "OOM kills (oom_kill above 0) 1,"

# The load and the repeat start with INT and QUIT at their defaults, not ignored as bash leaves
# them for a background command (test-run.sh's own INT test fails under an ignored INT).
run signals 1 0 pass LOADED_REPEAT_LOAD="trap -p INT QUIT >$tmp/signals.load; sleep 30" \
  LOADED_REPEAT_RUN="trap -p INT QUIT >$tmp/signals.run; bash $tmp/run.sh $tmp/signals.count pass"
for f in load run; do
  if [ ! -e "$tmp/signals.$f" ] || [ -s "$tmp/signals.$f" ]; then
    echo "FAIL signals: the $f's INT/QUIT dispositions: $(cat "$tmp/signals.$f" 2>/dev/null || echo none)"
    fail=1
  fi
done

# TERM to the script mid-repeat: the repeat and the load each get TERM at once (each would
# sweep its containers) and the script exits 143, well before the repeat's 600 s limit.
case_n=$((case_n + 1))
began=$(date +%s)
LOADED_REPEAT_PREBUILD=true \
  LOADED_REPEAT_LOAD="sleep 30 & trap 'kill \$!; echo term >$tmp/stopped.load; exit 143' TERM; wait" \
  LOADED_REPEAT_RUN="bash $tmp/run.sh $tmp/stopped.count trapped" \
  bash "$script" 1 "$tmp/stopped" >"$tmp/stopped.out" 2>&1 &
pid=$!
for _ in $(seq 50); do
  [ -e "$tmp/stopped.count" ] && break
  sleep 0.1
done
sleep 0.5
kill -TERM "$pid"
got=0
wait "$pid" || got=$?
[ "$got" = 143 ] || { echo "FAIL stopped: exit $got, want 143"; cat "$tmp/stopped.out"; fail=1; }
[ -e "$tmp/stopped.count.term" ] || { echo "FAIL stopped: the repeat got no TERM"; fail=1; }
[ -e "$tmp/stopped.load" ] || { echo "FAIL stopped: the load got no TERM"; fail=1; }
[ $(($(date +%s) - began)) -lt 20 ] || { echo "FAIL stopped: the script did not stop at once"; fail=1; }

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
