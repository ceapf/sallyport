#!/usr/bin/env bash
# tests/scripts/nightly_shards_test.sh — scripts/nightly-shards.sh fails when the nightly's matrix
# does not run every mutation set's shards exactly once. A row of job J reads `- { shard: k/n }`
# (make target J) or `- { set: S, shard: k/n }` (make target J-S). Each target's rows agree on n
# and list every k in 0..n-1 once; every `mutants` and `mutants-wide-<set>` target of the Makefile
# has rows, and every row names a target; each sharded job passes `MUTANTS_SHARD="$SHARD"` with
# `SHARD` from `matrix.shard`. A shard left out of the matrix drops its mutants without any job
# failing, so the check guards "more shards, never fewer mutants". The real nightly.yml and
# Makefile are checked at the end. Runs via `make test-scripts`.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
script="$root/scripts/nightly-shards.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fail=0
# makefile <name> <target>...: a Makefile with these targets plus one the check must ignore.
makefile() {
  local f="$tmp/$1.mk" t
  shift
  {
    for t in "$@"; do
      printf '%s:\n\techo %s\n' "$t" "$t"
    done
    printf 'mutants-paths:\n\techo paths\n'
  } >"$f"
  echo "$f"
}
# job <name> <row>...: one sharded job's lines, wired as the nightly wires its jobs.
job() {
  local name="$1" row
  shift
  echo "  $name:"
  echo "    strategy:"
  echo "      fail-fast: false"
  echo "      matrix:"
  echo "        include:"
  for row in "$@"; do
    echo "          $row"
  done
  echo "    steps:"
  echo "      - env:"
  echo "          SHARD: \${{ matrix.shard }}"
  echo "        run: make $name MUTANTS_SHARD=\"\$SHARD\""
}
# workflow <name> <text>: a workflow file holding `jobs:` and then the text.
workflow() {
  local f="$tmp/$1.yml"
  printf 'jobs:\n%s\n' "$2" >"$f"
  echo "$f"
}
# expect <want exit> <label> <args>...: the exit code matches; stderr is kept in $last and stdout
# in $out.
expect() {
  local want="$1" label="$2" rc=0
  shift 2
  out="$(bash "$script" "$@" 2>"$tmp/err")" || rc=$?
  last="$(cat "$tmp/err")"
  if [ "$rc" -ne "$want" ]; then
    echo "FAIL: $label: exit $rc, want $want ($last)" >&2
    fail=1
  fi
}
# names <label> <text>...: the last run's stderr holds each text.
names() {
  local label="$1"
  shift
  local t
  for t in "$@"; do
    if ! grep -Fq -- "$t" <<<"$last"; then
      echo "FAIL: $label: the script does not name '$t' ($last)" >&2
      fail=1
    fi
  done
}

mk="$(makefile mk mutants mutants-wide-a mutants-wide-b)"
deny="$(job mutants '- { shard: 0/2 }' '- { shard: 1/2 }')"
wide="$(job mutants-wide '- { set: a, shard: 0/3 }' '- { set: b, shard: 0/1 }' \
  '- { set: a, shard: 2/3 }' '- { set: a, shard: 1/3 }')"
good="$(workflow good "$deny"$'\n'"$wide")"
expect 0 "every shard of every target once" "$good" "$mk"
for t in "mutants: 2 shards" "mutants-wide-a: 3 shards" "mutants-wide-b: 1 shard"; do
  if ! grep -Fxq "nightly-shards: $t" <<<"$out"; then
    echo "FAIL: every shard of every target once: no line '$t' ($out)" >&2
    fail=1
  fi
done

expect 1 "a wide target with no rows" "$good" "$(makefile more mutants mutants-wide-a mutants-wide-b \
  mutants-wide-c)"
names "a wide target with no rows" "$good" "mutants-wide-c has no shard rows"
expect 1 "the deny-path job with no rows" "$(workflow nodeny "$wide")" "$mk"
names "the deny-path job with no rows" "mutants has no shard rows"
expect 1 "a row naming no make target" "$(workflow stray "$deny"$'\n'"$wide"$'\n'"$(job mutants-wide \
  '- { set: z, shard: 0/1 }')")" "$mk"
names "a row naming no make target" "mutants-wide-z is not a make target"
expect 1 "a job whose rows name no make target" "$(workflow strayjob "$deny"$'\n'"$wide"$'\n'"$(job \
  other '- { shard: 0/1 }')")" "$mk"
names "a job whose rows name no make target" "other is not a make target"

# rows <label> <want text> <deny-path row>...: the deny-path job with these rows fails, naming it.
rows() {
  local label="$1" want="$2"
  shift 2
  expect 1 "$label" "$(workflow rows "$(job mutants "$@")"$'\n'"$wide")" "$mk"
  names "$label" "$tmp/rows.yml" "$want"
}
rows "a shard left out" "mutants: shard 1/3 is missing" '- { shard: 0/3 }' '- { shard: 2/3 }'
rows "a shard listed twice" "mutants: shard 1/2 is listed 2 times" '- { shard: 0/2 }' \
  '- { shard: 1/2 }' '- { shard: 1/2 }'
rows "two shard counts in one target" "mutants: rows disagree on the shard count" \
  '- { shard: 0/2 }' '- { shard: 1/3 }' '- { shard: 2/3 }'
rows "a shard index not below the count" "mutants: shard 2/2 is out of range" '- { shard: 0/2 }' \
  '- { shard: 1/2 }' '- { shard: 2/2 }'
rows "a shard count of zero" "mutants: shard 0/0 is out of range" '- { shard: 0/0 }'
rows "a shard number with a leading zero" "01/2" '- { shard: 0/2 }' '- { shard: 01/2 }'
rows "a row in another form" "shard: 0-1" '- { shard: 0/1 }' '- { shard: 0-1 }'
rows "a row with its fields swapped" "{ shard: 0/1, set: a }" '- { shard: 0/1 }' \
  '- { shard: 0/1, set: a }'
rows "a row commented out" "# - { shard: 1/2 }" '- { shard: 0/2 }' '# - { shard: 1/2 }'

# wiring <label> <want text> <sed expression>: the good workflow with one line changed fails.
wiring() {
  local label="$1" want="$2" f="$tmp/wiring.yml"
  sed "$3" "$good" >"$f"
  if cmp -s "$f" "$good"; then
    echo "FAIL: $label: the fixture did not change" >&2
    fail=1
  fi
  expect 1 "$label" "$f" "$mk"
  names "$label" "$f" "$want"
}
wiring "MUTANTS_SHARD not from SHARD" 'MUTANTS_SHARD=0/2' '0,/MUTANTS_SHARD="\$SHARD"/s//MUTANTS_SHARD=0\/2/'
wiring "MUTANTS_SHARD unquoted" 'MUTANTS_SHARD=$SHARD' '0,/MUTANTS_SHARD="\$SHARD"/s//MUTANTS_SHARD=$SHARD/'
wiring "SHARD not from matrix.shard" 'SHARD: ${{ matrix.set }}' '0,/matrix\.shard/s//matrix.set/'
wiring "a sharded job that passes no shard" "mutants passes no" '0,/ MUTANTS_SHARD="\$SHARD"/s///'
wiring "a sharded job with no SHARD env" "mutants sets no" '0,/^ *SHARD: .*$/{/^ *SHARD: .*$/d}'
wiring "the wide job's MUTANTS_SHARD not from SHARD" 'mutants-wide: MUTANTS_SHARD=1/3' \
  '$s/MUTANTS_SHARD="\$SHARD"/MUTANTS_SHARD=1\/3/'
wiring "a SHARD env outside any job" "'SHARD: \${{ matrix.shard }}' is outside any job" \
  '1i\  SHARD: ${{ matrix.shard }}'
wiring "a MUTANTS_SHARD outside any job" 'MUTANTS_SHARD="$SHARD" is outside any job' \
  '1i\# make mutants MUTANTS_SHARD="$SHARD"'

# The loaded repeat (#141) reports and does not gate: only its job carries continue-on-error, at
# job level and true, and no job needs it.
# repeatjob [extra job-level line]: the repeat job as the nightly wires it.
repeatjob() {
  echo "  loaded-repeat:"
  echo "    runs-on: ubuntu-24.04"
  echo "    continue-on-error: true"
  [ -z "${1:-}" ] || echo "    $1"
  echo "    steps:"
  echo "      - run: make loaded-repeat"
}
# lenient <label> <want exit> <want text or ""> <workflow text>: the deny-path and wide jobs plus
# the text.
lenient() {
  expect "$2" "$1" "$(workflow lenient "$deny"$'\n'"$wide"$'\n'"$4")" "$mk"
  [ -z "$3" ] || names "$1" "$3"
}
lenient "the repeat job with its continue-on-error" 0 "" "$(repeatjob)"
lenient "the repeat job may need a mutation job" 0 "" "$(repeatjob 'needs: [mutants]')"
lenient "the repeat job without continue-on-error" 1 \
  "loaded-repeat: the job must carry 'continue-on-error: true'" "$(repeatjob | grep -v continue-on-error)"
lenient "the repeat job's continue-on-error false" 1 \
  "'continue-on-error: false' is not the job-level 'continue-on-error: true'" \
  "$(repeatjob | sed 's/continue-on-error: true/continue-on-error: false/')"
lenient "a step-level continue-on-error in the repeat job" 1 "is not the job-level" \
  "$(repeatjob)"$'\n'"        continue-on-error: true"
lenient "continue-on-error on a mutation job" 1 \
  "mutants-wide: continue-on-error is allowed only on the loaded-repeat job" \
  "$(repeatjob)"$'\n'"$(job mutants-wide | sed '1a\    continue-on-error: true' | head -n 2)"
lenient "a job that needs the repeat job" 1 "late: no job may need the loaded-repeat job" \
  "$(repeatjob)"$'\n'"  late:"$'\n'"    needs: [mutants, loaded-repeat]"
lenient "a job that needs the repeat job in a list" 1 "late: no job may need the loaded-repeat job" \
  "$(repeatjob)"$'\n'"  late:"$'\n'"    needs:"$'\n'"      - mutants"$'\n'"      - loaded-repeat"
lenient "a step's continue-on-error on a mutation job" 1 \
  "mutants-wide: continue-on-error is allowed only on the loaded-repeat job" \
  "$(repeatjob)"$'\n'"$(job mutants-wide | sed 's/^      - env:$/      - continue-on-error: true\n        env:/' | sed -n '1p;/continue-on-error/p')"
lenient "a quoted continue-on-error on a mutation job" 1 "mutants-wide: continue-on-error is allowed" \
  "$(repeatjob)"$'\n'"  mutants-wide:"$'\n'"    \"continue-on-error\": true"
lenient "a continue-on-error in a flow map on a mutation job" 1 "mutants-wide: continue-on-error is allowed" \
  "$(repeatjob)"$'\n'"  mutants-wide:"$'\n'"    steps:"$'\n'"      - { run: make mutants, continue-on-error: true }"
lenient "a SHARD env in the repeat job" 1 "loaded-repeat: no shard settings in the repeat job" \
  "$(repeatjob)"$'\n'"      - env:"$'\n'"          SHARD: \${{ matrix.shard }}"
lenient "a MUTANTS_SHARD in the repeat job" 1 "loaded-repeat: no shard settings in the repeat job" \
  "$(repeatjob)"$'\n'"      - run: make loaded-repeat MUTANTS_SHARD=\"\$SHARD\""
lenient "a job that needs the repeat job as a scalar" 1 "late: no job may need the loaded-repeat job" \
  "$(repeatjob)"$'\n'"  late:"$'\n'"    needs: loaded-repeat"
lenient "a needs list with a blank line and a comment" 1 "late: no job may need the loaded-repeat job" \
  "$(repeatjob)"$'\n'"  late:"$'\n'"    needs:"$'\n'"      - mutants"$'\n'$'\n'"      # the repeat"$'\n'"      - loaded-repeat"
lenient "a needs flow list over two lines" 1 "late: no job may need the loaded-repeat job" \
  "$(repeatjob)"$'\n'"  late:"$'\n'"    needs: [mutants,"$'\n'"      loaded-repeat]"
lenient "a job may need jobs whose names only contain the repeat's" 0 "" \
  "$(repeatjob)"$'\n'"  loaded-repeat-2:"$'\n'"    runs-on: ubuntu-24.04"$'\n'"  late:"$'\n'"    needs: [loaded-repeat-2, xloaded-repeat]"$'\n'"    runs-on: ubuntu-24.04"
lenient "a needs entry ends at the next job-level key" 0 "" \
  "$(repeatjob)"$'\n'"  late:"$'\n'"    needs: [mutants]"$'\n'"    runs-on: ubuntu-24.04"$'\n'"    steps:"$'\n'"      - run: echo loaded-repeat"
f="$tmp/lenient-top.yml"
printf 'continue-on-error: true\n' >"$f"
cat "$(workflow lenient-body "$deny"$'\n'"$wide")" >>"$f"
expect 1 "continue-on-error outside any job" "$f" "$mk"
names "continue-on-error outside any job" "(outside any job): continue-on-error is allowed only"

expect 1 "no Makefile" "$good"
names "no Makefile" usage
expect 1 "no arguments"
names "no arguments" usage
expect 1 "a missing workflow file" "$tmp/gone.yml" "$mk"
names "a missing workflow file" "$tmp/gone.yml is missing or unreadable"
expect 1 "a missing Makefile" "$good" "$tmp/gone.mk"
names "a missing Makefile" "$tmp/gone.mk is missing or unreadable"
# With no target to expect and no row to check, only this check can fail the run.
expect 1 "a Makefile with no mutation target" "$(workflow empty "")" "$(makefile none lint)"
names "a Makefile with no mutation target" "no mutants targets"
# Keys ahead of `jobs:` are no jobs: an indented `workflow_dispatch:` under `on:` must not take a
# SHARD env as its own.
f="$tmp/before-jobs.yml"
printf 'on:\n  workflow_dispatch:\nenv:\n  SHARD: ${{ matrix.shard }}\n' >"$f"
cat "$good" >>"$f"
expect 1 "a SHARD env ahead of jobs:" "$f" "$mk"
names "a SHARD env ahead of jobs:" "'SHARD: \${{ matrix.shard }}' is outside any job"
outside="$(workflow outside "$deny"$'\n'"$wide")"
sed -i '1i - { shard: 0/1 }' "$outside"
expect 1 "a row outside any job" "$outside" "$mk"
names "a row outside any job" "$outside:  is not a make target"

# The real workflow against the real Makefile: every mutation target has a line (n not pinned).
expect 0 "the nightly's own matrix" "$root/.github/workflows/nightly.yml" "$root/Makefile"
targets="$(grep -oE '^mutants(-wide-[a-z0-9]+)?:' "$root/Makefile" | tr -d :)"
if [ "$(grep -c '' <<<"$targets")" -lt 5 ]; then
  echo "FAIL: the real Makefile lists fewer than five mutation targets: $targets" >&2
  fail=1
fi
for t in $targets; do
  if ! grep -Eq "^nightly-shards: $t: [0-9]+ shards?$" <<<"$out"; then
    echo "FAIL: the nightly's own matrix: no line for $t ($out)" >&2
    fail=1
  fi
done

[ "$fail" -eq 0 ] && echo "nightly_shards_test: ok"
exit "$fail"
