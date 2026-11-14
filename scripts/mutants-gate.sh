#!/usr/bin/env bash
# scripts/mutants-gate.sh <cargo-mutants exit code> <mutants.out dir> — the mutation gate
# (maintainer ruling, issue #36): it fails on missed mutants only. A mutant that hangs a test
# counts as detected; the timed-out ones, and those caught by nextest's per-test limit, are listed
# in the job summary ($GITHUB_STEP_SUMMARY, else stdout). Any other cargo-mutants failure (usage, baseline, internal error) still fails.
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

# Mutants whose tests nextest terminated at the per-test limit (.config/nextest.toml, #82): they
# are caught, so they are not in timeout.txt, but each still hangs a test. A log's first "*** "
# line names its mutant (the log opens with a blank line); nextest marks a terminated test
# "TIMEOUT [", maybe in colour.
hung_tests() {
  [ -d "$out/log" ] || return 0
  local f
  for f in "$out"/log/*.log; do
    [ -f "$f" ] || continue
    # grep without -q reads to the end, so sed never takes a SIGPIPE that pipefail would report.
    if sed 's/\x1b\[[0-9;]*m//g' "$f" | grep -E '^ *TIMEOUT \[' >/dev/null; then
      grep -m 1 '^\*\*\* ' "$f" | sed 's/^\*\*\* //'
    fi
  done
}
hung="$(hung_tests || true)"

report() {
  if [ -n "$timeouts" ]; then
    echo "### Timed-out mutants (detected: each hangs a test)"
    echo
    echo '```'
    echo "$timeouts"
    echo '```'
  fi
  if [ -n "$hung" ]; then
    echo "### Mutants caught by the per-test limit (each hangs a test)"
    echo
    echo '```'
    echo "$hung"
    echo '```'
  fi
}
# The lists are information: failing to write them (no summary file, a closed stdout) never
# changes the verdict.
if [ -n "$timeouts" ] || [ -n "$hung" ]; then
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    report >>"$GITHUB_STEP_SUMMARY" || true
  else
    report 2>/dev/null || true
  fi
fi
if [ -n "$missed" ]; then
  echo "mutants-gate: missed mutants:" >&2
  echo "$missed" >&2
  exit 1
fi
if [ "$code" -eq 2 ]; then
  echo "mutants-gate: cargo-mutants reported missed mutants but $out/missed.txt is empty" >&2
  exit 1
fi
if [ "$code" -eq 3 ] && [ -z "$timeouts" ]; then
  echo "mutants-gate: cargo-mutants reported timeouts but $out/timeout.txt is empty" >&2
  exit 1
fi
exit 0
