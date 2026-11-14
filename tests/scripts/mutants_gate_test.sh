#!/usr/bin/env bash
# tests/scripts/mutants_gate_test.sh — scripts/mutants-gate.sh fails on missed mutants only
# (maintainer ruling, issue #36): a timed-out mutant counts as detected and is listed in the job
# summary; any other cargo-mutants failure still fails. Runs via `make test-scripts`.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
gate="$root/scripts/mutants-gate.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fail=0
# A clean unmutated baseline: nextest's summary, no SLOW line.
clean_baseline='
*** baseline
     Summary [   2.966s] 909 tests run: 909 passed, 0 skipped
'
# fresh_out: an output directory with one caught mutant and a clean baseline log.
fresh_out() {
  rm -rf "$tmp/out" "$tmp/summary"
  mkdir -p "$tmp/out/log"
  printf '%s\n' 'src/z.rs:1:1: replace z -> bool with true' >"$tmp/out/caught.txt"
  : >"$tmp/out/missed.txt"
  : >"$tmp/out/timeout.txt"
  : >"$tmp/out/unviable.txt"
  printf '%s' "$clean_baseline" >"$tmp/out/log/baseline.log"
}
# gate_rc <cargo-mutants exit>: the gate's exit code on $tmp/out.
gate_rc() {
  local rc=0
  GITHUB_STEP_SUMMARY="$tmp/summary" bash "$gate" "$1" "$tmp/out" >/dev/null 2>&1 || rc=$?
  echo "$rc"
}
# expect <want exit> <label> <cargo-mutants exit> <missed lines> <timeout lines>
expect() {
  fresh_out
  printf '%s' "$4" >"$tmp/out/missed.txt"
  printf '%s' "$5" >"$tmp/out/timeout.txt"
  local rc
  rc="$(gate_rc "$3")"
  if [ "$rc" -ne "$1" ]; then
    echo "FAIL: $2: exit $rc, want $1" >&2
    fail=1
  fi
}
t1='src/a.rs:1:2: replace == with != in f'
m1='src/b.rs:3:4: replace > with >= in g'
expect 0 "all caught" 0 "" ""
expect 0 "timeouts only" 3 "" "$t1"$'\n'
expect 1 "missed" 2 "$m1"$'\n' ""
expect 1 "missed and timeouts" 2 "$m1"$'\n' "$t1"$'\n'
expect 1 "missed, reported with the timeout code" 3 "$m1"$'\n' "$t1"$'\n'
expect 1 "exit 2 but nothing listed missed" 2 "" ""
expect 1 "baseline failed" 4 "" ""
expect 1 "usage error" 1 "" ""
expect 1 "exit 0 but a mutant listed missed" 0 "$m1"$'\n' ""
expect 1 "exit 3 but nothing listed timed out" 3 "" ""

# Without GITHUB_STEP_SUMMARY the list goes to stdout, and a closed stdout does not fail a
# timeouts-only run.
fresh_out
printf '%s\n' "$t1" >"$tmp/out/timeout.txt"
if ! (unset GITHUB_STEP_SUMMARY; bash "$gate" 3 "$tmp/out" 2>/dev/null) | grep -Fq "$t1"; then
  echo "FAIL: without a summary file the timed-out mutant is not printed" >&2
  fail=1
fi
rc=0
(unset GITHUB_STEP_SUMMARY; bash "$gate" 3 "$tmp/out" >&- 2>/dev/null) || rc=$?
if [ "$rc" -ne 0 ]; then
  echo "FAIL: a timeouts-only run with stdout closed: exit $rc, want 0" >&2
  fail=1
fi

# The summary lists each timed-out mutant.
expect 0 "timeouts listed" 3 "" "$t1"$'\n'
if ! grep -Fq "$t1" "$tmp/summary"; then
  echo "FAIL: the summary does not list the timed-out mutant" >&2
  fail=1
fi
# A mutant whose log shows a test terminated by nextest's per-test limit (#82), plain or in
# colour, is listed in the summary; the verdict stays "caught". A log without one is not listed.
h1='src/c.rs:5:6: replace step -> u64 with 0'
h2='src/d.rs:7:8: replace h -> bool with true'
c1='src/e.rs:9:10: replace k -> bool with false'
fresh_out
# cargo-mutants opens each log with a blank line.
printf '\n*** %s\n*** mutation diff:\n     TIMEOUT [   4.004s] (2/2) runaway tests::t\n' "$h1" \
  >"$tmp/out/log/h1.log"
printf '*** %s\n\033[1;31m     TIMEOUT\033[0m [  30.002s] (1/2) x tests::u\n' "$h2" \
  >"$tmp/out/log/h2.log"
printf '*** %s\n        PASS [   0.004s] (1/1) x tests::v\n' "$c1" >"$tmp/out/log/c1.log"
rc=0
GITHUB_STEP_SUMMARY="$tmp/summary" bash "$gate" 0 "$tmp/out" >/dev/null 2>&1 || rc=$?
if [ "$rc" -ne 0 ]; then
  echo "FAIL: mutants caught by the per-test limit: exit $rc, want 0" >&2
  fail=1
fi
for m in "$h1" "$h2"; do
  if ! grep -Fq "$m" "$tmp/summary" 2>/dev/null; then
    echo "FAIL: the summary does not list the per-test-limit mutant $m" >&2
    fail=1
  fi
done
if grep -Fq "$c1" "$tmp/summary" 2>/dev/null; then
  echo "FAIL: the summary lists a mutant no test hung for" >&2
  fail=1
fi
# Missed mutants still fail when some were caught by the per-test limit.
printf '%s\n' "$m1" >"$tmp/out/missed.txt"
rc=0
GITHUB_STEP_SUMMARY="$tmp/summary" bash "$gate" 2 "$tmp/out" >/dev/null 2>&1 || rc=$?
if [ "$rc" -ne 1 ]; then
  echo "FAIL: missed mutants beside per-test-limit ones: exit $rc, want 1" >&2
  fail=1
fi

# A mutant whose test was refused memory by the data cap (#82) is listed apart; the verdict stays
# "caught". The baseline itself is never listed.
o1='src/f.rs:11:12: replace step -> usize with 0'
fresh_out
printf '\n*** %s\nmemory allocation of 2147483648 bytes failed\n' "$o1" >"$tmp/out/log/o1.log"
printf '\n*** baseline\nmemory allocation of 8 bytes failed\n     TIMEOUT [ 1s] x\n' \
  >"$tmp/out/log/baseline.log"
if [ "$(gate_rc 0)" -ne 0 ]; then
  echo "FAIL: a mutant caught by the memory cap failed the gate" >&2
  fail=1
fi
if ! grep -A3 'memory cap' "$tmp/summary" 2>/dev/null | grep -Fq "$o1"; then
  echo "FAIL: the summary does not list the memory-cap mutant under its heading" >&2
  fail=1
fi
if grep -A3 'per-test limit' "$tmp/summary" 2>/dev/null | grep -Fq "$o1"; then
  echo "FAIL: the memory-cap mutant is listed as hung" >&2
  fail=1
fi
if grep -Fxq 'baseline' "$tmp/summary" 2>/dev/null; then
  echo "FAIL: the summary lists the baseline as a mutant" >&2
  fail=1
fi

# The per-test limit's margin (architect ruling R1): a SLOW line in the unmutated baseline, plain
# or in colour, fails the gate; so does a missing baseline log once any mutant was tested. A run
# that tested no mutant passes without one, and a clean baseline passes.
slow_plain='        SLOW [>  7.500s] (───) sallyd llm::server::tests::t'
slow_colour=$'\033[1;33m        SLOW\033[0m [>  7.500s] (───) sallyd x::y'
for line in "$slow_plain" "$slow_colour"; do
  fresh_out
  printf '%s\n%s\n' "$clean_baseline" "$line" >"$tmp/out/log/baseline.log"
  if [ "$(gate_rc 0)" -ne 1 ]; then
    echo "FAIL: a SLOW line in the baseline passed: $line" >&2
    fail=1
  fi
done
fresh_out
printf '%s\n%s\n' "$clean_baseline" "$slow_plain" >"$tmp/out/log/baseline.log"
printf '%s\n' "$m1" >"$tmp/out/missed.txt"
err="$(GITHUB_STEP_SUMMARY="$tmp/summary" bash "$gate" 2 "$tmp/out" 2>&1 >/dev/null || true)"
if ! grep -Fq "$m1" <<<"$err"; then
  echo "FAIL: a slow baseline hides the missed mutants from the report" >&2
  fail=1
fi
fresh_out
rm "$tmp/out/log/baseline.log"
if [ "$(gate_rc 0)" -ne 1 ]; then
  echo "FAIL: a run that tested mutants passed without a baseline log" >&2
  fail=1
fi
fresh_out
rm "$tmp/out/log/baseline.log"
: >"$tmp/out/caught.txt"
if [ "$(gate_rc 0)" -ne 0 ]; then
  echo "FAIL: a run that tested no mutant failed for want of a baseline log" >&2
  fail=1
fi
fresh_out
printf '\n*** src/z.rs\n        SLOW [>  7.500s] (───) x tests::slow_under_a_mutant\n' \
  >"$tmp/out/log/z.log"
if [ "$(gate_rc 0)" -ne 0 ]; then
  echo "FAIL: a SLOW line in a mutant's log (not the baseline) failed the gate" >&2
  fail=1
fi

# Exit 3 can hide missed mutants (timeouts outrank them): without missed.txt, or without
# timeout.txt, the gate fails rather than trusting the exit code.
for gone in missed.txt timeout.txt; do
  rm -rf "$tmp/out" && mkdir -p "$tmp/out"
  : >"$tmp/out/missed.txt"
  : >"$tmp/out/timeout.txt"
  rm "$tmp/out/$gone"
  rc=0
  GITHUB_STEP_SUMMARY="$tmp/summary" bash "$gate" 3 "$tmp/out" >/dev/null 2>&1 || rc=$?
  if [ "$rc" -eq 0 ]; then
    echo "FAIL: exit 3 without $gone passed" >&2
    fail=1
  fi
done
# A missing output directory (cargo-mutants never ran) fails.
rc=0
GITHUB_STEP_SUMMARY="$tmp/summary" bash "$gate" 0 "$tmp/nowhere" >/dev/null 2>&1 || rc=$?
if [ "$rc" -eq 0 ]; then
  echo "FAIL: a missing mutants.out passed" >&2
  fail=1
fi

[ "$fail" -eq 0 ] && echo "mutants_gate_test: ok"
exit "$fail"
