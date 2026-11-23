#!/usr/bin/env bash
# scripts/loaded-repeat.sh <count> <results dir> — repeats RT-AG-09's bombs binary under load
# (#141: its fork-bomb test once saw a memory entry in a full `make test`).
#
# - First builds both commands' tests and the load's shim, so neither side waits on cargo's build
#   lock. Then starts the load, `make test`, in its own session, and runs the repeat command
#   <count> times while the load is alive. Each repeat is one scripts/test-run.sh invocation of the whole
#   bombs binary, so the fork-bomb test keeps its in-process neighbours of a suite run.
# - A repeat passes only when the command exits 0, its log says "test result: ok. 4 passed" and
#   holds the fork-bomb test's diagnostic line. Anything else, a time-out included, is red. A red
#   is never re-run or dropped: every repeat is a line in <results dir>/results.txt. Each line
#   also gives the test's memory.peak, memory.events max (the memory limit was hit) and oom_kill;
#   the totals count the runs that hit the limit and the runs with an OOM kill, and give the
#   highest peak. None of these gates: a pass that hit the limit is reported, not failed.
# - A repeat counts toward <count> only when the load was alive at its start and its end; the
#   others are kept and marked unloaded (a red in one is still red). When the load ends, it is
#   started again if LOADED_REPEAT_RESTART=1 (but not after two passes in a row during which no
#   repeat counted: such a load cannot carry one); otherwise no further repeat starts. With
#   LOADED_REPEAT_START_LIMIT=<s> (0: none) no repeat starts later than s seconds after the first.
#   Each load pass keeps its log (load-<k>.log): it ran bombs.rs too, an in-suite sample.
# - The load and each repeat run in the background, where bash (without job control) ignores
#   INT and QUIT and the ignore survives exec; both start with those signals reset to default,
#   so test-run.sh and its own tests (an interrupted run, test_run_test.sh) see a normal process.
# - When the repeats end, the load gets TERM (its test-run.sh sweeps its own containers) and is
#   waited for. A load pass starts only once it leads its own process group (at most 5 s, else
#   exit 1 with no repeat), and the stop falls back to the load's own pid if the group is gone.
#   Exit 0 only when every repeat passed, <count> loaded repeats ran and no load pass failed in
#   the fork-bomb test; otherwise 1, with the verdict (red or incomplete) on the totals line.
#   Usage errors exit 2.
# Environment (defaults in brackets): LOADED_REPEAT_LIMIT, seconds per repeat [600];
# LOADED_REPEAT_KILL_AFTER, seconds from a repeat's TERM to its KILL [180];
# LOADED_REPEAT_RESTART [1]; LOADED_REPEAT_START_LIMIT [0]; LOADED_REPEAT_PREBUILD,
# LOADED_REPEAT_LOAD and LOADED_REPEAT_RUN, the three commands (tests/scripts/loaded_repeat_test.sh
# replaces them with stubs). Tested by that file, via `make test-scripts`.
set -euo pipefail

if [ "$#" -ne 2 ] || [[ ! "$1" =~ ^[1-9][0-9]*$ ]]; then
  echo "usage: loaded-repeat.sh <count> <results dir>" >&2
  exit 2
fi
count="$1" out="$2"
limit="${LOADED_REPEAT_LIMIT:-600}"
kill_after="${LOADED_REPEAT_KILL_AFTER:-180}"
restart="${LOADED_REPEAT_RESTART:-1}"
start_limit="${LOADED_REPEAT_START_LIMIT:-0}"
# The load's own builds too (its shim-check builds the release shim), so no repeat waits on
# cargo's build lock while the load builds.
prebuild="${LOADED_REPEAT_PREBUILD:-cargo test -q --workspace --no-run && cargo test -q -p sallyd --test bombs --no-run && make -s shim}"
load_cmd="${LOADED_REPEAT_LOAD:-make test}"
run_cmd="${LOADED_REPEAT_RUN:-bash scripts/test-run.sh cargo test -p sallyd --test bombs -- --nocapture}"
fork=rt_ag_09_a_fork_bomb_is_held_by_the_pids_limit
prefix='rt_ag_09 fork-bomb figures:'
for v in "$limit" "$start_limit" "$kill_after"; do
  [[ "$v" =~ ^[0-9]+$ ]] || { echo "loaded-repeat: a limit is not a number: $v" >&2; exit 2; }
done
[ "$restart" = 0 ] || [ "$restart" = 1 ] || { echo "loaded-repeat: LOADED_REPEAT_RESTART is 0 or 1" >&2; exit 2; }
mkdir -p "$out"
results="$out/results.txt"

# Test containers present that are not this script's: another worktree testing beside it.
others() {
  podman ps --format '{{.Names}}' 2>/dev/null | grep -c '^sp-' || true
}
{
  echo "commit: $(git rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "nproc: $(nproc)"
  free -m
  echo "test containers before the run (another worktree): $(others)"
  echo "planned loaded repeats: $count; per-repeat limit ${limit}s; restart $restart; start limit ${start_limit}s"
} >"$results"

bash -c "$prebuild" >"$out/prebuild.log" 2>&1 || {
  echo "loaded-repeat: the pre-build failed; see $out/prebuild.log" >&2
  exit 1
}

# load_start checks for the load's process group every 0.05 s, at most GROUP_TRIES times (5 s).
GROUP_TRIES=100
load_pid="" passes=0 load_red=0 idle=0 loaded=0 at_load=0
load_start() {
  passes=$((passes + 1))
  at_load="$loaded"
  # TODO(#321): a signal between this fork and the next line leaves the load running.
  setsid env --default-signal=INT,QUIT bash -c "$load_cmd" >"$out/load-$passes.log" 2>&1 &
  load_pid=$!
  # The load's process group exists only once the child has called setsid(); a stop before that
  # would miss it. Wait for it (a load that already ended needs none).
  local tries=0
  until kill -0 -- "-$load_pid" 2>/dev/null; do
    kill -0 "$load_pid" 2>/dev/null || return 0
    if [ "$tries" -ge "$GROUP_TRIES" ]; then
      echo "loaded-repeat: the load did not get its own process group within $((GROUP_TRIES / 20)) s" >&2
      exit 1
    fi
    tries=$((tries + 1))
    sleep 0.05
  done
}
# Records a finished load pass: its exit status, and whether the fork-bomb test failed in it.
load_end() {
  local s=0
  wait "$load_pid" || s=$?
  local f=no
  if grep -qE "^(---- )?$fork( |$)" "$out/load-$passes.log"; then
    f=yes
    load_red=1
  fi
  echo "load pass $passes: exit $s, fork-bomb test failed: $f" >>"$results"
  load_pid=""
  # A pass that ended before any repeat beside it counted (a load that fails at once).
  if [ "$loaded" -eq "$at_load" ]; then idle=$((idle + 1)); else idle=0; fi
}
alive() {
  [ -n "$load_pid" ] && kill -0 "$load_pid" 2>/dev/null
}
# TERM to the load's process group, or to the load itself when there is no such group.
stop_load() {
  kill -TERM -- "-$load_pid" 2>/dev/null || kill -TERM "$load_pid" 2>/dev/null || true
}
# A repeat or load still running when this script ends early (an error, INT, TERM) gets TERM
# and is waited for, so each test-run.sh sweeps its own containers. Neither is in this script's
# process group (timeout makes its own; the load runs in its own session), so a Ctrl-C reaches
# neither directly. The repeat runs in the background and is waited for, so a trapped signal
# interrupts the wait at once instead of after the repeat's limit.
rep_pid=""
stop_all() {
  if [ -n "$rep_pid" ] && kill -0 "$rep_pid" 2>/dev/null; then
    kill -TERM "$rep_pid" 2>/dev/null || true
    wait "$rep_pid" 2>/dev/null || true
  fi
  if alive; then
    stop_load
    wait "$load_pid" 2>/dev/null || true
  fi
}
trap stop_all EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
field() {
  grep -oE "(^| )$1=[^ ]+" <<<"$2" | head -n1 | cut -d= -f2 || true
}

load_start
i=0 passed=0 red=0 unloaded=0 first="" hit_max=0 hit_oom=0 top=""
while [ "$loaded" -lt "$count" ]; do
  if ! alive; then
    [ -z "$load_pid" ] || load_end
    [ "$restart" = 1 ] || break
    # Two passes in a row with no loaded repeat: the load cannot carry a repeat; stop.
    [ "$idle" -lt 2 ] || break
    load_start
  fi
  now=$(date +%s)
  first="${first:-$now}"
  if [ "$start_limit" -gt 0 ] && [ $((now - first)) -gt "$start_limit" ]; then
    break
  fi
  i=$((i + 1))
  log="$out/run-$i.log"
  at_start=no
  alive && at_start=yes
  s=0
  # TERM at the limit; KILL only kill_after seconds later, so test-run.sh has time to stop the
  # test binary and sweep its containers (a KILL before that leaves them behind).
  timeout --signal=TERM --kill-after="$kill_after" "$limit" \
    env --default-signal=INT,QUIT bash -c "$run_cmd" >"$log" 2>&1 &
  rep_pid=$!
  wait "$rep_pid" || s=$?
  rep_pid=""
  at_end=no
  alive && at_end=yes
  secs=$(($(date +%s) - now))
  line=$(grep -F "$prefix" "$log" | head -n1 || true)
  verdict=red
  if [ "$s" -eq 0 ] && grep -qF "test result: ok. 4 passed" "$log" && [ -n "$line" ]; then
    verdict=pass
  fi
  own=unknown
  if grep -qE "^test $fork \.\.\. ok" "$log"; then
    own=ok
  elif grep -qE "$fork.*FAILED|^---- $fork " "$log"; then
    own=FAILED
  fi
  if [ "$at_start" = yes ] && [ "$at_end" = yes ]; then
    state=loaded
    loaded=$((loaded + 1))
  else
    state=unloaded
    unloaded=$((unloaded + 1))
  fi
  if [ "$verdict" = pass ]; then passed=$((passed + 1)); else red=$((red + 1)); fi
  # Reported, never gating: memory.events max (the limit was hit, reclaim ran), the OOM kills,
  # and memory.peak. A pass that hit the memory limit is the early sign of #141.
  mpeak=$(field memory.peak "$line") mmax=$(field max "$line") kills=$(field oom_kill "$line")
  if [[ "$mmax" =~ ^[0-9]+$ ]] && [ "$mmax" -gt 0 ]; then hit_max=$((hit_max + 1)); fi
  if [[ "$kills" =~ ^[0-9]+$ ]] && [ "$kills" -gt 0 ]; then hit_oom=$((hit_oom + 1)); fi
  if [[ "$mpeak" =~ ^[0-9]+$ ]] && { [ -z "$top" ] || [ "$mpeak" -gt "$top" ]; }; then top="$mpeak"; fi
  printf '%s run=%d %s %s fork-bomb=%s memory.peak=%s max=%s oom_kill=%s pids.peak=%s secs=%d exit=%d\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$i" "$state" "$verdict" "$own" \
    "$mpeak" "$mmax" "$kills" "$(field pids.peak "$line")" "$secs" "$s" >>"$results"
done

if alive; then
  stop_load
  s=0
  wait "$load_pid" || s=$?
  echo "load pass $passes: stopped (TERM), exit $s" >>"$results"
  load_pid=""
elif [ -n "$load_pid" ]; then
  load_end
fi
echo "test containers after the run (another worktree's, or left by this run): $(others)" >>"$results"

verdict=pass
if [ "$red" -gt 0 ] || [ "$load_red" -eq 1 ]; then
  verdict=red
elif [ "$loaded" -lt "$count" ]; then
  verdict=incomplete
fi
echo "totals: planned $count, loaded $loaded, unloaded $unloaded, passed $passed, red $red, load passes $passes, memory limit hit (max above 0) $hit_max, OOM kills (oom_kill above 0) $hit_oom, highest memory.peak ${top:-none}, verdict $verdict" >>"$results"
tail -n1 "$results"
[ "$verdict" = pass ]
