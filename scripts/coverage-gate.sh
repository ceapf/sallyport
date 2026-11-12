#!/usr/bin/env bash
# scripts/coverage-gate.sh <min-percent> <llvm-cov-json> <path-fragment>
#
# Line coverage of every file whose path contains <path-fragment>, summed from the JSON summary
# of `cargo llvm-cov --json --summary-only`; test files (`*_tests.rs`) never count. Fails under
# <min-percent>, and fails when no file
# matched (a moved module must not pass the gate by vanishing). Architect ruling Q16 (Task 8):
# the egress module is gated as a whole, files are selected by directory, not by a deny-list.
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: coverage-gate.sh <min-percent> <llvm-cov-json> <path-fragment>" >&2
  exit 2
fi
min="$1" json="$2" frag="$3"
# A whole percent, 0..100: anything else would let bash arithmetic pass the gate by accident.
if ! [[ "$min" =~ ^(100|[1-9]?[0-9])$ ]]; then
  echo "coverage-gate: <min-percent> must be a whole number 0..100, got '$min'" >&2
  exit 2
fi
command -v jq >/dev/null || { echo "coverage-gate: jq not found" >&2; exit 2; }

read -r files count covered < <(jq -r --arg f "$frag" '
  [.data[].files[] | select((.filename | contains($f)) and (.filename | endswith("_tests.rs") | not))
   | .summary.lines]
  | "\(length) \(map(.count) | add // 0) \(map(.covered) | add // 0)"' "$json")

if [ "$files" -eq 0 ] || [ "$count" -eq 0 ]; then
  echo "coverage-gate: no lines under '$frag'" >&2
  exit 1
fi
# Integer arithmetic: covered/count >= min/100.
if [ $((covered * 100)) -lt $((min * count)) ]; then
  echo "coverage-gate: '$frag' $covered/$count lines, under $min%" >&2
  exit 1
fi
echo "coverage-gate: '$frag' $covered/$count lines in $files files (>= $min%)"
