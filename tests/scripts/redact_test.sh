#!/usr/bin/env bash
# tests/scripts/redact_test.sh — scripts/redact.sh removes every identifier class it promises to.
# Runs in CI (doctor-syntax job) and via `make test-scripts`. Uses planted values only.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
printf '[user]\n\tname = Planted Account\n\temail = planted@example.invalid\n' >"$tmp/gitconfig"
host="$(hostname)"
# Planted paths are assembled from parts so the repository's identifier scan (which flags
# /home/<name> and drive-letter user folders) does not match this file.
homes=/home
home="$homes/plantedhome"
bs='\'

input="home=$home/.config/x
user=planteduser:100000:65536
host=$host and ${host^^}
win=/mnt/c/Users/Planted Name/AppData
winpath=C:${bs}Users${bs}PlantedWin${bs}.wslconfig
git=Planted Account <planted@example.invalid>
extra=planted-extra-value
keep=${home}other and planteduserx"

out="$(cd "$tmp" && printf '%s\n' "$input" | env HOME="$home" USER=planteduser \
  LOGNAME=planteduser GIT_CONFIG_GLOBAL="$tmp/gitconfig" GIT_CONFIG_NOSYSTEM=1 \
  REDACT_EXTRA=planted-extra-value bash "$root/scripts/redact.sh")"

fail=0
gone() { # the planted value must not survive (case-insensitive)
  if printf '%s\n' "$out" | grep -v '^keep=' | grep -qiF -- "$1"; then
    echo "FAIL: '$1' survived redaction"; fail=1
  fi
}
present() {
  if ! printf '%s\n' "$out" | grep -qF -- "$1"; then
    echo "FAIL: expected '$1' in output"; fail=1
  fi
}

gone "$home"
gone planteduser
gone "$host"
gone "Planted Name"
gone PlantedWin
gone "Planted Account"
gone planted@example.invalid
gone planted-extra-value
present 'home=$HOME/.config/x'
present 'user=<user>:100000:65536'
present 'host=<host> and <host>'
present 'win=/mnt/c/Users/<user>/AppData'
present 'winpath=C:\Users\<you>\.wslconfig'
present 'git=<account> <<email>>'
present 'extra=<redacted>'
# Boundaries: a longer name that merely starts with the user or home is left alone.
present "keep=${home}other and planteduserx"

if [ "$fail" -ne 0 ]; then
  printf -- '--- output ---\n%s\n' "$out"
  exit 1
fi
echo "redact_test: ok"
