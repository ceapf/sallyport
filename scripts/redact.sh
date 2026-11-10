#!/usr/bin/env bash
# scripts/redact.sh — stdin → stdout filter that removes machine and account identifiers.
#
# Used by `scripts/doctor.sh --redact`, which reports and CI use. Replaces, case-insensitively:
#   the home directory              → $HOME
#   the user name                   → <user>
#   host names                      → <host>
#   git and gh account names/emails → <account> / <email>
#   /mnt/<d>/Users/<name>           → /mnt/<d>/Users/<user>   (a name with spaces is redacted to the next separator; over-redaction is preferred)
#   <D>:\Users\<name>               → <D>:\Users\<you>
#   anything in $REDACT_EXTRA       → <redacted>   (newline-separated literals)
# Names are replaced only as whole words (so a user called "u" does not eat every "u"); the home
# path is replaced wherever it is not followed by a name character (so $HOME=/home/u leaves
# /home/user alone). Longer needles are replaced first.
#
# Works with mawk (Ubuntu's default awk): only index/substr/match/tolower are used.

set -u

pairs=""
# add <needle> <replacement> <mode: 0 anywhere | 1 whole word | 2 path prefix (no name char after)>
add() {
  local v="$1" r="$2" w="$3"
  [ -n "$v" ] || return 0
  case "$v" in /|.|*$'\t'*) return 0 ;; esac
  pairs+="$v"$'\t'"$r"$'\t'"$w"$'\n'
}

add "${HOME:-}" '$HOME' 2
for u in "${USER:-}" "${LOGNAME:-}" "$(id -un 2>/dev/null)"; do add "$u" '<user>' 1; done
for h in "$(hostname 2>/dev/null)" "$(hostname -s 2>/dev/null)" "$(hostname -f 2>/dev/null)" "$(uname -n 2>/dev/null)"; do
  add "$h" '<host>' 1
done
if command -v git >/dev/null 2>&1; then
  add "$(git config user.name 2>/dev/null)" '<account>' 1
  add "$(git config user.email 2>/dev/null)" '<email>' 0
  add "$(git config --global user.name 2>/dev/null)" '<account>' 1
  add "$(git config --global user.email 2>/dev/null)" '<email>' 0
fi
if command -v gh >/dev/null 2>&1; then
  while IFS= read -r a; do add "$a" '<account>' 1; done < <(
    gh auth status 2>&1 | sed -n 's/.*Logged in to [^ ]* account \([^ ]*\).*/\1/p'
  )
fi
while IFS= read -r x; do add "$x" '<redacted>' 0; done <<<"${REDACT_EXTRA:-}"

# Longest needle first, so $HOME is replaced before the user name inside it.
REDACT_PAIRS="$(printf '%s' "$pairs" | awk -F'\t' 'NF { print length($1) "\t" $0 }' | sort -t$'\t' -k1,1nr | cut -f2-)"
export REDACT_PAIRS

exec awk '
function isword(c) { return c ~ /[A-Za-z0-9_]/ }
function isname(c) { return c ~ /[A-Za-z0-9_.-]/ }
# Case-insensitive literal replacement. w: 0 anywhere, 1 whole word, 2 not followed by a name char.
function rep(s, needle, r, w,    out, ls, ln, p, pre, post) {
  out = ""; ls = tolower(s); ln = length(needle)
  while ((p = index(ls, needle)) > 0) {
    pre = (p > 1) ? substr(s, p - 1, 1) : substr(out, length(out), 1)
    post = substr(s, p + ln, 1)
    if ((w == 1 && (isword(pre) || isword(post))) || (w == 2 && isname(post))) {
      out = out substr(s, 1, p + ln - 1)
    } else {
      out = out substr(s, 1, p - 1) r
    }
    s = substr(s, p + ln); ls = substr(ls, p + ln)
  }
  return out s
}
# Replace the path segment after "Users<sep>" in every match of re.
function users(s, re, sep, repl,    out, m, k) {
  out = ""
  while (match(s, re)) {
    m = substr(s, RSTART, RLENGTH)
    k = index(m, "Users" sep) + length("Users" sep) - 1
    out = out substr(s, 1, RSTART - 1) substr(m, 1, k) repl
    s = substr(s, RSTART + RLENGTH)
  }
  return out s
}
BEGIN {
  n = split(ENVIRON["REDACT_PAIRS"], rows, "\n")
  for (i = 1; i <= n; i++) {
    if (split(rows[i], f, "\t") == 3) { k++; nd[k] = tolower(f[1]); rp[k] = f[2]; wd[k] = f[3] + 0 }
  }
}
{
  line = $0
  for (i = 1; i <= k; i++) line = rep(line, nd[i], rp[i], wd[i])
  line = users(line, "/mnt/[A-Za-z]/Users/[^/\t\"'"'"']+", "/", "<user>")
  line = users(line, "[A-Za-z]:\\\\Users\\\\[^\\\\\t\"'"'"']+", "\\", "<you>")
  print line
}'
