#!/usr/bin/env bash
# scripts/mutants-paths.sh <list name> <entry>... — every entry of a mutation list (Makefile
# MUTANTS_FILES, MUTANTS_WIDE_*) names Rust source that exists, so no file leaves the mutation
# scope silently when it is moved or renamed. A plain entry must be an existing regular `.rs` file;
# an entry with `*`, `?` or `[` is a glob that must match at least one file, every match a regular
# `.rs` file. An empty list fails. Every bad entry is named, then the script exits 1. Paths are
# relative to the working directory (`make mutants-paths` runs from the repository root).
# Tested by tests/scripts/mutants_paths_test.sh.
set -euo pipefail
shopt -s nullglob

list="${1:?usage: mutants-paths.sh <list name> <entry>...}"
shift
if [ "$#" -eq 0 ]; then
  echo "mutants-paths: $list is empty" >&2
  exit 1
fi

fail=0
bad() {
  echo "mutants-paths: $list: $1" >&2
  fail=1
}
# rust_file <path>: an existing regular file whose name ends in .rs.
rust_file() {
  [ -f "$1" ] && [[ "$1" == *.rs ]]
}
for entry in "$@"; do
  case "$entry" in
    *[*?[]*)
      # The glob is expanded here, unquoted on purpose; nullglob leaves no match empty.
      # shellcheck disable=SC2206
      matches=($entry)
      if [ "${#matches[@]}" -eq 0 ]; then
        bad "$entry matches no file"
        continue
      fi
      for m in "${matches[@]}"; do
        rust_file "$m" || bad "$entry matches $m, which is not a regular .rs file"
      done
      ;;
    *)
      rust_file "$entry" || bad "$entry is not an existing regular .rs file"
      ;;
  esac
done
exit "$fail"
