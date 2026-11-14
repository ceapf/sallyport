#!/usr/bin/env bash
# scripts/mutants-gate.sh <cargo-mutants exit code> <mutants.out dir> — the mutation gate
# (maintainer ruling, issue #36): it fails on missed mutants. A mutant that hangs a test counts
# as detected. The job summary ($GITHUB_STEP_SUMMARY, else stdout) lists the timed-out mutants,
# those caught by nextest's per-test limit, and those caught by the test memory cap (#82). Any
# other cargo-mutants failure (usage, baseline, internal error) still fails, and so does an
# unmutated baseline in which a test ran past nextest's slow period: that breaks the per-test
# limit's margin (architect ruling R1, #82).
# Tested by tests/scripts/mutants_gate_test.sh.
set -euo pipefail

code="${1:?usage: mutants-gate.sh <exit code> <mutants.out dir>}"
out="${2:?usage: mutants-gate.sh <exit code> <mutants.out dir>}"

# cargo-mutants exit codes: 0 all caught, 2 missed mutants, 3 timeouts (which outrank missed
# mutants, so 3 can hide them: missed.txt decides); anything else failed.
case "$code" in
  0 | 2 | 3) ;;
  *)
    echo "mutants-gate: cargo-mutants failed with exit $code" >&2
    exit 1
    ;;
esac
if [ ! -d "$out" ]; then
  echo "mutants-gate: $out does not exist" >&2
  exit 1
fi
# cargo-mutants creates both lists at the start of a run; a missing one means the run, or a new
# cargo-mutants version, did not produce what this gate reads.
for f in missed.txt timeout.txt; do
  if [ ! -f "$out/$f" ] || [ ! -r "$out/$f" ]; then
    echo "mutants-gate: $out/$f is missing or unreadable" >&2
    exit 1
  fi
done
missed="$(cat "$out/missed.txt")"
timeouts="$(cat "$out/timeout.txt")"
# Every mutant tested lands in one of these lists.
tested="$(cat "$out"/caught.txt "$out"/missed.txt "$out"/timeout.txt "$out"/unviable.txt \
  2>/dev/null || true)"

# The mutants whose log matches an extended regex, colour codes stripped. A log's first "*** "
# line names its mutant (the log opens with a blank line); the baseline is not a mutant.
logs_matching() {
  [ -d "$out/log" ] || return 0
  local f
  for f in "$out"/log/*.log; do
    [ -f "$f" ] || continue
    [ "$(basename "$f")" = baseline.log ] && continue
    # grep without -q reads to the end, so sed never takes a SIGPIPE that pipefail would report.
    if sed 's/\x1b\[[0-9;]*m//g' "$f" | grep -E "$1" >/dev/null; then
      grep -m 1 '^\*\*\* ' "$f" | sed 's/^\*\*\* //'
    fi
  done
}
# Caught, so in neither timeout.txt nor missed.txt, but worth seeing: a test nextest terminated at
# the per-test limit (.config/nextest.toml) hangs; an allocation refused by the data cap (Makefile
# MUTANTS_DATA_CAP) means the mutant allocates without end.
hung="$(logs_matching '^ *TIMEOUT \[' 2>/dev/null || true)"
oom="$(logs_matching 'memory allocation of [0-9]+ bytes failed' 2>/dev/null || true)"

section() {
  [ -n "$2" ] || return 0
  echo "### $1"
  echo
  echo '```'
  echo "$2"
  echo '```'
}
report() {
  section "Timed-out mutants (detected: each hangs a test)" "$timeouts"
  section "Mutants caught by the per-test limit (each hangs a test)" "$hung"
  section "Mutants caught by the test memory cap (each allocates without end)" "$oom"
}
# The lists are information: failing to write them (no summary file, a closed stdout) never
# changes the verdict.
if [ -n "$timeouts$hung$oom" ]; then
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    report >>"$GITHUB_STEP_SUMMARY" || true
  else
    report 2>/dev/null || true
  fi
fi

fail=0
if [ -n "$missed" ]; then
  echo "mutants-gate: missed mutants:" >&2
  echo "$missed" >&2
  fail=1
fi
if [ "$code" -eq 2 ] && [ -z "$missed" ]; then
  echo "mutants-gate: cargo-mutants reported missed mutants but $out/missed.txt is empty" >&2
  fail=1
fi
if [ "$code" -eq 3 ] && [ -z "$timeouts" ]; then
  echo "mutants-gate: cargo-mutants reported timeouts but $out/timeout.txt is empty" >&2
  fail=1
fi
# The per-test limit's margin (.config/nextest.toml): a test that runs past the slow period in the
# unmutated baseline, on this machine under this profile, is too slow for the limit. Without the
# baseline's log the margin is unknown, so a run that tested any mutant fails.
baseline="$out/log/baseline.log"
if [ -n "$tested" ]; then
  if [ ! -f "$baseline" ] || [ ! -r "$baseline" ]; then
    echo "mutants-gate: $baseline is missing or unreadable" >&2
    fail=1
  elif slow="$(sed 's/\x1b\[[0-9;]*m//g' "$baseline" | grep -E '^ *SLOW \[')"; then
    echo "mutants-gate: a test in the unmutated baseline ran past nextest's slow period;" \
      "split or speed it up, never raise the limit (.config/nextest.toml):" >&2
    echo "$slow" >&2
    fail=1
  fi
fi
exit "$fail"
