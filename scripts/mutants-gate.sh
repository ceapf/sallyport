#!/usr/bin/env bash
# scripts/mutants-gate.sh <cargo-mutants exit code> <mutants.out dir> — the mutation gate
# (maintainer ruling, issue #36): it fails on missed mutants only. A mutant that hangs a test
# counts as detected; the timed-out ones are listed in the job summary ($GITHUB_STEP_SUMMARY,
# else stdout). Any other cargo-mutants failure (usage, baseline, internal error) still fails.
# Tested by tests/scripts/mutants_gate_test.sh.
set -euo pipefail

code="${1:?usage: mutants-gate.sh <exit code> <mutants.out dir>}"
out="${2:?usage: mutants-gate.sh <exit code> <mutants.out dir>}"
summary="${GITHUB_STEP_SUMMARY:-/dev/stdout}"

# cargo-mutants exit codes: 0 all caught, 2 missed mutants, 3 timeouts; anything else failed.
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
missed="$(cat "$out/missed.txt" 2>/dev/null || true)"
timeouts="$(cat "$out/timeout.txt" 2>/dev/null || true)"

if [ -n "$timeouts" ]; then
  {
    echo "### Timed-out mutants (detected: each hangs a test)"
    echo
    echo '```'
    echo "$timeouts"
    echo '```'
  } >>"$summary"
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
exit 0
