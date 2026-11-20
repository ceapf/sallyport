#!/usr/bin/env bash
# tests/scripts/mutants_paths_test.sh — scripts/mutants-paths.sh fails when a mutation list entry
# matches no Rust file: a plain entry must be an existing regular `.rs` file, a glob entry must
# match at least one, and an empty list fails. `make mutants-paths` checks every list in the
# Makefile, quoted, so the script sees each glob as written. Runs via `make test-scripts`.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
script="$root/scripts/mutants-paths.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fail=0
mkdir -p "$tmp/tree/src/dir" "$tmp/tree/src/empty" "$tmp/tree/src/d.rs"
: >"$tmp/tree/src/a.rs"
: >"$tmp/tree/src/dir/b.rs"
: >"$tmp/tree/src/dir/c.rs"
: >"$tmp/tree/src/notes.txt"
: >"$tmp/tree/src/empty/readme.md"

# run <list name> <entry>...: the script's exit code, then its stderr, run from the tree's root.
run() {
  local rc=0 err
  err="$(cd "$tmp/tree" && bash "$script" "$@" 2>&1 >/dev/null)" || rc=$?
  printf '%s\n%s' "$rc" "$err"
}
# expect <want exit> <label> <list name> <entry>...: the exit code matches.
expect() {
  local want="$1" label="$2" out rc
  shift 2
  out="$(run "$@")"
  rc="${out%%$'\n'*}"
  if [ "$rc" -ne "$want" ]; then
    echo "FAIL: $label: exit $rc, want $want" >&2
    fail=1
  fi
  last="$out"
}
# names <label> <text>...: the last run's stderr holds each text.
names() {
  local label="$1"
  shift
  local t
  for t in "$@"; do
    if ! grep -Fq -- "$t" <<<"$last"; then
      echo "FAIL: $label: the script does not name '$t'" >&2
      fail=1
    fi
  done
}

expect 0 "an existing file" LIST src/a.rs
expect 0 "a glob with matches" LIST 'src/dir/*.rs'
expect 0 "files and globs together" LIST src/a.rs 'src/dir/*.rs' 'src/d?r/b.rs' 'src/[d]ir/c.rs'
expect 1 "a missing file" LIST src/a.rs src/gone.rs
names "a missing file" src/gone.rs LIST
expect 1 "a glob with no match" LIST 'src/empty/*.rs'
names "a glob with no match" 'src/empty/*.rs matches no file'
expect 1 "a glob whose directory is missing" LIST 'src/none/*.rs'
names "a glob whose directory is missing" 'src/none/*.rs matches no file'
expect 1 "a file that is not Rust" LIST src/notes.txt
names "a file that is not Rust" src/notes.txt
expect 1 "a glob matching a file that is not Rust" LIST 'src/*'
names "a glob matching a file that is not Rust" src/notes.txt
expect 1 "a directory" LIST src/dir
names "a directory" src/dir
expect 1 "a directory named like a Rust file" LIST src/d.rs
names "a directory named like a Rust file" 'src/d.rs is not'
expect 1 "a glob matching a directory named like a Rust file" LIST 'src/d*.rs'
names "a glob matching a directory named like a Rust file" 'matches src/d.rs'
expect 1 "an empty list" LIST
names "an empty list" 'LIST is empty'
expect 1 "no arguments"
names "no arguments" usage
expect 1 "two bad entries" LIST src/gone.rs src/a.rs 'src/empty/*.rs'
names "two bad entries" src/gone.rs 'src/empty/*.rs'

# The Makefile's wiring: one call per list (MUTANTS_FILES and the four MUTANTS_WIDE_*), each entry
# quoted so the validate glob reaches the script unexpanded; a bad entry or an empty list in any
# list fails the target, naming it.
dry="$(make -s -C "$root" -n mutants-paths 2>&1)" || {
  echo "FAIL: make -n mutants-paths: $dry" >&2
  fail=1
}
calls="$(grep -o 'scripts/mutants-paths.sh [A-Z_]*' <<<"$dry" | sort -u || true)"
for list in MUTANTS_FILES MUTANTS_WIDE_CORE MUTANTS_WIDE_SALLYD MUTANTS_WIDE_SHIM MUTANTS_WIDE_CLI; do
  if ! grep -qx "scripts/mutants-paths.sh $list" <<<"$calls"; then
    echo "FAIL: make mutants-paths does not check $list" >&2
    fail=1
  fi
done
if [ "$(grep -c '' <<<"$calls")" -ne 5 ]; then
  echo "FAIL: make mutants-paths makes other calls than the five lists: $calls" >&2
  fail=1
fi
if ! grep -Fq "'crates/sally-core/src/manifest/validate/*.rs'" <<<"$dry"; then
  echo "FAIL: make mutants-paths does not pass the validate glob quoted" >&2
  fail=1
fi
rc=0
err="$(make -s -C "$root" mutants-paths MUTANTS_WIDE_SHIM=crates/sally-shim/src/nope.rs 2>&1)" ||
  rc=$?
if [ "$rc" -eq 0 ] || ! grep -Fq crates/sally-shim/src/nope.rs <<<"$err"; then
  echo "FAIL: make mutants-paths passed, or did not name, a missing file: exit $rc" >&2
  fail=1
fi
rc=0
err="$(make -s -C "$root" mutants-paths MUTANTS_WIDE_SHIM= 2>&1)" || rc=$?
if [ "$rc" -eq 0 ] || ! grep -Fq MUTANTS_WIDE_SHIM <<<"$err"; then
  echo "FAIL: make mutants-paths passed, or did not name, an empty list: exit $rc" >&2
  fail=1
fi
rc=0
err="$(make -s -C "$root" mutants-paths MUTANTS_FILES=crates/nope1.rs MUTANTS_WIDE_CLI=crates/nope2.rs \
  2>&1)" || rc=$?
if [ "$rc" -eq 0 ] || ! grep -Fq crates/nope1.rs <<<"$err" || ! grep -Fq crates/nope2.rs <<<"$err"
then
  echo "FAIL: make mutants-paths stopped before naming a bad entry in every list: exit $rc" >&2
  fail=1
fi
rc=0
make -s -C "$root" mutants-paths >/dev/null 2>&1 || rc=$?
if [ "$rc" -ne 0 ]; then
  echo "FAIL: make mutants-paths fails on the Makefile's own lists: exit $rc" >&2
  fail=1
fi

[ "$fail" -eq 0 ] && echo "mutants_paths_test: ok"
exit "$fail"
