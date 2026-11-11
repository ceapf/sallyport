#!/usr/bin/env bash
# scripts/check-trailers.sh <base> <head> — fails if any commit in <base>..<head> has a co-author
# or tool line in its message. Commits carry Signed-off-by only (CLAUDE.md, Conventions).
# Runs in CI (doctor-syntax job) on every pull request; tested by tests/scripts/check_trailers_test.sh.
set -euo pipefail

base="${1:?usage: check-trailers.sh <base> <head>}"
head="${2:?usage: check-trailers.sh <base> <head>}"
# The footer form only: a line that starts with "Generated with", after an optional emoji
# (non-ASCII bytes under LC_ALL=C). Prose that mentions the phrase mid-line passes.
re='^[[:space:]]*(co-authored-by|claude-session)[[:space:]]*:|^[[:space:]]*([^[:print:][:space:]]+[[:space:]]*)?generated with'
export LC_ALL=C

# A plain assignment, so an unknown or unfetched SHA fails here (set -e) instead of passing empty.
commits="$(git rev-list "$base..$head")"
bad=0
for c in $commits; do
  msg="$(git show -s --format=%B "$c")"
  if grep -Eiq "$re" <<<"$msg"; then
    echo "commit $c has a co-author or tool line:" >&2
    grep -Ein "$re" <<<"$msg" >&2
    bad=1
  fi
done
exit "$bad"
