#!/usr/bin/env bash
# scripts/redteam-guard.sh <wsl test> <floor> <ignored list> <run list> — the red-team selection
# guard of `make redteam`. Both lists are `cargo nextest list --message-format oneline` output
# ("<binary> <test>" per line) for the rt_ filter: <ignored list> with `--run-ignored only`,
# <run list> with the default. It fails unless the only ignored rt_ test is <wsl test> (CLAUDE.md:
# the one approved #[ignore]) and at least <floor> rt_ tests run, so neither an added #[ignore] nor
# a lost test file turns into a green run that skipped rows. Tested by
# tests/scripts/redteam_guard_test.sh.
set -euo pipefail

if [ "$#" -ne 4 ] || ! [[ "$2" =~ ^[0-9]+$ ]]; then
  echo "usage: redteam-guard.sh <wsl test> <floor> <ignored list> <run list>" >&2
  exit 2
fi
wsl="$1" floor="$2" ignored="$3" run="$4"

# names <file>: the test name of each "<binary> <test>" line; any other line fails.
names() {
  local line
  while IFS= read -r line || [ -n "$line" ]; do
    if ! [[ "$line" =~ ^[^[:space:]]+\ ([^[:space:]]+)$ ]]; then
      echo "redteam-guard: unexpected line in $1: $line" >&2
      return 1
    fi
    echo "${BASH_REMATCH[1]}"
  done <"$1"
}

got="$(names "$ignored")" || exit 1
if [ "$got" != "$wsl" ]; then
  echo "redteam-guard: ignored rt_ tests must be exactly $wsl; nextest lists: ${got:-none}" >&2
  exit 1
fi
listed="$(names "$run")" || exit 1
count="$(grep -c . <<<"$listed")" || count=0
if [ "$count" -lt "$floor" ]; then
  echo "redteam-guard: $count rt_ tests run, the floor is $floor (REDTEAM_FLOOR in the Makefile)" >&2
  exit 1
fi
echo "redteam-guard: $count rt_ tests run (floor $floor); the only ignored one is $wsl"
