#!/usr/bin/env bash
# scripts/mutants-gate.sh <cargo-mutants exit code> <mutants.out dir> — the mutation gate
# (maintainer ruling, issue #36): it fails on missed mutants only. A mutant that hangs a test
# counts as detected; the timed-out ones are listed in the job summary ($GITHUB_STEP_SUMMARY,
# else stdout). Any other cargo-mutants failure (usage, baseline, internal error) still fails.
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

report() {
  echo "### Timed-out mutants (detected: each hangs a test)"
  echo
  echo '```'
  echo "$timeouts"
  echo '```'
}
# The list is information: failing to write it (no summary file, a closed stdout) never changes
# the verdict.
if [ -n "$timeouts" ]; then
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
