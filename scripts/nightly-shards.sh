#!/usr/bin/env bash
# scripts/nightly-shards.sh <workflow file> <Makefile> — the nightly runs every mutation set's
# shards exactly once. A matrix row of job J reads `- { shard: <k>/<n> }`, which runs make target
# J, or `- { set: <s>, shard: <k>/<n> }`, which runs J-<s>. For each target, its rows agree on n
# (at least 1) and list every k in 0..n-1 once. Every `mutants` and `mutants-wide-<set>` target in
# the Makefile has rows, and every row names a target there. Every line holding `shard:` must be
# such a row. A job with rows passes `MUTANTS_SHARD="$SHARD"` and sets `SHARD: ${{ matrix.shard }}`,
# and no other value of either appears. A shard left out of the matrix drops its mutants without
# any job failing, so this guards "more shards, never fewer mutants". Prints one line per target;
# names every problem with the workflow file, then exits 1. Tested by
# tests/scripts/nightly_shards_test.sh, which also checks the real nightly.yml and Makefile.
set -euo pipefail

usage="usage: nightly-shards.sh <workflow file> <Makefile>"
if [ "$#" -ne 2 ]; then
  echo "nightly-shards: $usage" >&2
  exit 1
fi
file="$1" makefile="$2"
for f in "$file" "$makefile"; do
  if [ ! -f "$f" ] || [ ! -r "$f" ]; then
    echo "nightly-shards: $f is missing or unreadable" >&2
    exit 1
  fi
done

fail=0
bad() {
  echo "nightly-shards: $file: $1" >&2
  fail=1
}
declare -A target=() count=() seen=() passes=() sets=() rowjob=()
mapfile -t targets < <(grep -oE '^mutants(-wide-[a-z0-9]+)?:' "$makefile" | tr -d : | sort -u)
if [ "${#targets[@]}" -eq 0 ]; then
  echo "nightly-shards: $makefile has no mutants targets" >&2
  exit 1
fi
for t in "${targets[@]}"; do
  target[$t]=1
done

row='^[[:space:]]*- \{ (set: ([a-z][a-z0-9]*), )?shard: (0|[1-9][0-9]*)/(0|[1-9][0-9]*) \}[[:space:]]*$'
job_line='^  ([A-Za-z0-9_-]+):[[:space:]]*$'
shard_env='SHARD: ${{ matrix.shard }}'
in_jobs=0 job=""
while IFS= read -r line || [ -n "$line" ]; do
  trimmed="${line#"${line%%[![:space:]]*}"}"
  if [[ "$line" == jobs:* ]]; then
    in_jobs=1
    continue
  fi
  if [ "$in_jobs" -eq 1 ] && [[ "$line" =~ $job_line ]]; then
    job="${BASH_REMATCH[1]}"
    continue
  fi
  # Every MUTANTS_SHARD value, wherever it appears, is the step's SHARD variable, quoted, inside a
  # job (an empty job name is no array key).
  while read -r v; do
    if [ -z "$job" ]; then
      bad "$v is outside any job"
    elif [ "$v" = 'MUTANTS_SHARD="$SHARD"' ]; then
      passes[$job]=1
    else
      bad "$job: $v is not MUTANTS_SHARD=\"\$SHARD\""
    fi
  done < <(grep -oE 'MUTANTS_SHARD=("[^"]*"|[^[:space:]]*)' <<<"$line" || true)
  if [[ "$trimmed" == SHARD:* ]]; then
    if [ -z "$job" ]; then
      bad "'$trimmed' is outside any job"
    elif [ "$trimmed" = "$shard_env" ]; then
      sets[$job]=1
    else
      bad "$job: '$trimmed' is not '$shard_env'"
    fi
  fi
  case "$line" in
    *shard:*) ;;
    *) continue ;;
  esac
  # A row outside any job runs target "" or "-<set>", which the target check below refuses.
  if [[ ! "$line" =~ $row ]]; then
    bad "not a matrix row of the form '- { [set: <name>, ]shard: <k>/<n> }': $trimmed"
    continue
  fi
  t="$job${BASH_REMATCH[2]:+-${BASH_REMATCH[2]}}" k="${BASH_REMATCH[3]}" n="${BASH_REMATCH[4]}"
  # An empty target (a row outside any job) is no array key: test it before the lookup.
  if [ -z "$t" ] || [ -z "${target[$t]:-}" ]; then
    bad "$t is not a make target with mutants in its name in $makefile"
    continue
  fi
  rowjob[$t]="$job"
  # k is at least 0, so this also refuses n = 0.
  if [ "$k" -ge "$n" ]; then
    bad "$t: shard $k/$n is out of range"
    continue
  fi
  if [ -z "${count[$t]:-}" ]; then
    count[$t]="$n"
  elif [ "${count[$t]}" != "$n" ]; then
    count[$t]=mixed
  fi
  seen[$t/$k/$n]=$((${seen[$t/$k/$n]:-0} + 1))
done <"$file"

declare -A checked=()
for t in "${targets[@]}"; do
  n="${count[$t]:-}"
  if [ -z "$n" ]; then
    bad "$t has no shard rows"
    continue
  fi
  j="${rowjob[$t]}"
  if [ -z "${checked[$j]:-}" ]; then
    checked[$j]=1
    [ -n "${passes[$j]:-}" ] || bad "job $j passes no MUTANTS_SHARD=\"\$SHARD\""
    [ -n "${sets[$j]:-}" ] || bad "job $j sets no '$shard_env'"
  fi
  if [ "$n" = mixed ]; then
    bad "$t: rows disagree on the shard count"
    continue
  fi
  ok=1
  for ((k = 0; k < n; k++)); do
    times="${seen[$t/$k/$n]:-0}"
    if [ "$times" -eq 0 ]; then
      bad "$t: shard $k/$n is missing"
      ok=0
    elif [ "$times" -gt 1 ]; then
      bad "$t: shard $k/$n is listed $times times"
      ok=0
    fi
  done
  if [ "$ok" -eq 1 ]; then
    echo "nightly-shards: $t: $n shard$([ "$n" -eq 1 ] || echo s)"
  fi
done
exit "$fail"
