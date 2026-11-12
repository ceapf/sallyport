#!/usr/bin/env bash
# scripts/disk-check.sh — fail early, with a clear message, when a filesystem the container tests
# launch on has less free space than one launch needs. A launch is refused below the disk floor
# (the larger of 4 GiB and 5 % of the filesystem) plus the default `runtime.stage_size` (10 GiB);
# see crates/sallyd/src/sandbox/disk.rs. A runner image change then shows up as this message, not
# as container tests failing with `disk-floor`.
#
#   scripts/disk-check.sh <dir>...    checks the filesystem of each directory
#
# Prints the free space of every directory checked. DISK_CHECK_DF names the df command (tests).
set -euo pipefail

GIB=$((1 << 30))
FLOOR_MIN=$((4 * GIB))
FLOOR_PERCENT=5
STAGE_SIZE=$((10 * GIB))
df_cmd="${DISK_CHECK_DF:-df}"

[ "$#" -gt 0 ] || { echo "usage: disk-check.sh <dir>..." >&2; exit 2; }

fail=0
for dir in "$@"; do
  # "size avail" in bytes, for the filesystem holding $dir.
  read -r size avail < <("$df_cmd" -B1 --output=size,avail "$dir" | tail -n 1) || {
    echo "disk-check: cannot read the free space of $dir" >&2
    exit 1
  }
  case "$size$avail" in
    '' | *[!0-9]*) echo "disk-check: unexpected df output for $dir" >&2; exit 1 ;;
  esac
  floor=$((size * FLOOR_PERCENT / 100))
  [ "$floor" -ge "$FLOOR_MIN" ] || floor=$FLOOR_MIN
  need=$((floor + STAGE_SIZE))
  echo "disk-check: $dir: $((avail / GIB)) GiB free of $((size / GIB)) GiB; a launch needs $((need / GIB)) GiB"
  if [ "$avail" -lt "$need" ]; then
    echo "disk-check: FAIL: $dir has $avail bytes free; a container launch needs $need" \
      "(disk floor $floor + stage_size $STAGE_SIZE). The runner has less disk than the" \
      "container tests need: free more in the 'free runner disk' step." >&2
    fail=1
  fi
done
exit "$fail"
