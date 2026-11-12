#!/usr/bin/env bash
# scripts/doctor.sh — Sallyport host preflight.
#
# Verifies the load-bearing assumptions V1–V12 from docs/00_DECISIONS.md, V13–V16 from
# docs/AMENDMENTS-01.md §11 / AMENDMENTS-02 B5, V17 (the token proxy's trust roots, Task 9a), plus
# the developer toolchain. Prints one status
# line per check:
#
#     V<n> PASS|FAIL|WARN|UNVERIFIED — <one-line evidence>
#
# followed by the raw evidence (last 15 lines), indented.
#
# Exit status: number of failed BLOCKING checks (V1, V3, V4, V5, V6, V13; V2 too when DOCTOR_REQUIRE_GPU=1),
# so 0 means "ready". Idempotent: creates only temp dirs (removed on exit) and pulls images on demand.
#
# Usage: scripts/doctor.sh [--redact]
#   --redact               pipe all output through scripts/redact.sh (user name, home path, host
#                          name, git/gh accounts) and omit disk sizes. Reports and CI use this.
#
# Environment:
#   DOCTOR_REQUIRE_GPU=1   make V2 blocking (Milestone 3+)
#   DOCTOR_OFFLINE=1       skip checks that touch the network (V8)
#   DOCTOR_RUNTIME=<path>  OCI runtime for every `podman run` (default: the pinned upstream crun at
#                          $XDG_DATA_HOME/sallyport/bin/crun if installed, else Podman's default).
#                          Sallyport itself passes `--runtime <sandbox.runtime_path>` (AMENDMENTS-02 B5).
#
# Rules this script obeys (CLAUDE.md): no sudo, no --privileged / --cap-add / host networking /
# --userns=host / seccomp=unconfined; the only --device is nvidia.com/gpu.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
case "${1:-}" in
  --redact)
    shift
    [ "$#" -eq 0 ] || { echo "usage: $0 [--redact]" >&2; exit 64; }
    DOCTOR_REDACT=1 bash "${BASH_SOURCE[0]}" 2>&1 | bash "$SCRIPT_DIR/redact.sh"
    exit "${PIPESTATUS[0]}"
    ;;
  "") ;;
  *) echo "usage: $0 [--redact]" >&2; exit 64 ;;
esac

ALPINE="docker.io/library/alpine:3.20"
PYIMG="docker.io/library/python:3.12-slim"
CUDA_TAGS=(
  "docker.io/nvidia/cuda:12.9.1-base-ubuntu24.04"
  "docker.io/nvidia/cuda:12.9.0-base-ubuntu24.04"
  "docker.io/nvidia/cuda:12.8.1-base-ubuntu24.04"
)
TAURI_PKGS=(libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev)

# Make rustup-managed tools visible even in non-login shells.
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

BLOCKING_FAILS=0
# Scratch for bind-mounted probes (V5, V13). Not under /tmp, /var/tmp or $XDG_RUNTIME_DIR: those
# are on the mount denylist, and nothing here mounts a denylisted path, not even a probe.
STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}"
mkdir -p "$STATE_DIR" && WORK="$(mktemp -d -p "$STATE_DIR" sallyport-doctor.XXXXXX)"
[ -n "${WORK:-}" ] && [ -d "$WORK" ] || { echo "doctor: cannot create a scratch dir under $STATE_DIR" >&2; exit 1; }
# podman unshare: V13's overlay work dir holds entries owned by subordinate uids.
trap 'podman rm -f sp-doctor-v5a >/dev/null 2>&1; [ -n "$WORK" ] && { podman unshare rm -rf "$WORK" 2>/dev/null; rm -rf "$WORK"; }' EXIT

# OCI runtime: the pinned upstream crun when installed (AMENDMENTS-02 B5), unless overridden.
PINNED_RUNTIME="${XDG_DATA_HOME:-$HOME/.local/share}/sallyport/bin/crun"
RUNTIME="${DOCTOR_RUNTIME:-}"
if [ -z "$RUNTIME" ] && [ -x "$PINNED_RUNTIME" ]; then RUNTIME="$PINNED_RUNTIME"; fi
PM=(podman)
[ -n "$RUNTIME" ] && PM=(podman --runtime "$RUNTIME")

have() { command -v "$1" >/dev/null 2>&1; }

# report <id> <status> <evidence> <raw> [blocking]
report() {
  local id="$1" status="$2" evidence="$3" raw="$4" blocking="${5:-no}"
  printf '%s %s — %s\n' "$id" "$status" "$evidence"
  if [ -n "$raw" ]; then
    printf '%s\n' "$raw" | tail -n 15 | sed 's/^/    | /'
  fi
  if [ "$blocking" = "yes" ] && [ "$status" = "FAIL" ]; then
    BLOCKING_FAILS=$((BLOCKING_FAILS + 1))
  fi
}

dpkg_installed() {
  [ "$(dpkg-query -W -f='${Status}' "$1" 2>/dev/null)" = "install ok installed" ]
}

# ---------------------------------------------------------------------------------------------
echo "== Sallyport doctor — $(date -u -Iseconds) — $(uname -r) — runtime: ${RUNTIME:-podman default}"
echo
echo "== Toolchain (informational)"

tool_line() { # tool_line <name> <version-cmd...>
  local name="$1"; shift
  if have "$name"; then
    local v path
    v="$("$@" 2>&1 | head -n 1)"
    path="$(command -v "$name")"
    case "$path" in
      /mnt/*) printf 'T %-12s WARN    — %s (Windows binary via interop: %s)\n' "$name" "$v" "$path" ;;
      *)      printf 'T %-12s OK      — %s\n' "$name" "$v" ;;
    esac
  else
    printf 'T %-12s MISSING\n' "$name"
  fi
}

tool_line git git --version
tool_line gh gh --version
if have gh; then
  # Only the ACTIVE account matters: git pushes go through `gh auth git-credential` with its token.
  gh_login="$(gh api user --jq .login 2>/dev/null)"
  echo "    | gh active account: ${gh_login:-not logged in}"
fi
if have node; then
  nv="$(node --version)"; nmaj="${nv#v}"; nmaj="${nmaj%%.*}"
  if [ "$nmaj" -ge 20 ] 2>/dev/null; then st=OK; else st=OLD; fi
  printf 'T %-12s %-7s — %s (need >= 20)\n' node "$st" "$nv"
else
  printf 'T %-12s MISSING\n' node
fi
tool_line npm npm --version
if have python3; then
  pv="$(python3 -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])')"
  if python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)'; then st=OK; else st=OLD; fi
  printf 'T %-12s %-7s — Python %s (need >= 3.12)\n' python3 "$st" "$pv"
else
  printf 'T %-12s MISSING\n' python3
fi
tool_line rustup rustup --version
tool_line cargo cargo --version
tool_line rustc rustc --version
if have rustup; then
  if rustup target list --installed 2>/dev/null | grep -q '^x86_64-unknown-linux-musl$'; then
    printf 'T %-12s OK      — x86_64-unknown-linux-musl installed\n' musl-target
  else
    printf 'T %-12s MISSING — rustup target add x86_64-unknown-linux-musl\n' musl-target
  fi
fi
tool_line podman podman --version
tool_line crun crun --version
tool_line nvidia-ctk nvidia-ctk --version
tool_line jq jq --version
tool_line curl curl --version
tool_line strace strace --version
tool_line claude claude --version
tool_line bwrap bwrap --version
tool_line socat socat -V
for p in musl-tools "${TAURI_PKGS[@]}" uidmap slirp4netns passt; do
  if dpkg_installed "$p"; then
    printf 'T %-12s OK      — dpkg: %s\n' "${p:0:12}" "$p"
  else
    printf 'T %-12s MISSING — dpkg: %s\n' "${p:0:12}" "$p"
  fi
done

echo
echo "== Resources (informational)"
if [ "${DOCTOR_REDACT:-0}" = 1 ]; then
  echo "    | disk usage omitted (--redact)"
else
  df -h "$HOME" /var/lib 2>/dev/null | sed 's/^/    | /'
fi
free -g | sed 's/^/    | /'
echo "    | max_user_namespaces=$(cat /proc/sys/user/max_user_namespaces 2>/dev/null)  nproc=$(nproc)"

echo
echo "== Assumption checks"

# ---------------------------------------------------------------------------------------------
# V1 — rootless Podman (blocking)
v1_raw="$(
  echo "\$ cat /sys/kernel/security/lsm"; cat /sys/kernel/security/lsm 2>/dev/null || echo "securityfs/lsm not present"; echo
  echo "\$ sysctl kernel.apparmor_restrict_unprivileged_userns"; sysctl kernel.apparmor_restrict_unprivileged_userns 2>&1
  echo "\$ wsl.conf boot/systemd"; grep -E '^\[boot\]|systemd' /etc/wsl.conf 2>/dev/null; echo "systemctl: $(systemctl is-system-running 2>&1)"
  echo "\$ subuid/subgid"; grep "^$USER:" /etc/subuid /etc/subgid 2>&1
)"
if have podman; then
  # stderr (e.g. the WSL '"/" is not a shared mount' warning) goes to the raw block, not the evidence line.
  info_all="$("${PM[@]}" info --format 'rootless={{.Host.Security.Rootless}} runtime={{.Host.OCIRuntime.Name}} cgroups={{.Host.CgroupsVersion}} mgr={{.Host.CgroupManager}} net={{.Host.NetworkBackend}}' 2>&1)"
  info="$(echo "$info_all" | grep '^rootless=' | head -n 1)"
  [ -n "$info" ] || info="$info_all"
  ctr="$("${PM[@]}" run --rm "$ALPINE" sh -c 'id; cat /proc/self/uid_map' 2>&1)"
  v1_raw="$v1_raw"$'\n'"\$ podman --version: $(podman --version 2>&1)"$'\n'"\$ runtime: $("${RUNTIME:-crun}" --version 2>&1 | head -n 1)"$'\n'"\$ podman info: $info_all"$'\n'"\$ podman run alpine id; uid_map"$'\n'"$ctr"
  myuid="$(id -u)"
  ok=1
  echo "$info" | grep -q 'rootless=true' || ok=0
  # The runtime is reported by name (crun) or, with --runtime, by path (…/crun).
  echo "$info" | grep -Eq 'runtime=([^ ]*/)?crun( |$)' || ok=0
  echo "$ctr" | grep -q '^uid=0(root)' || ok=0
  echo "$ctr" | grep -Eq "^[[:space:]]*0[[:space:]]+$myuid[[:space:]]+1\b" || ok=0
  grep -q "^$USER:" /etc/subuid 2>/dev/null && grep -q "^$USER:" /etc/subgid 2>/dev/null || ok=0
  if [ "$ok" = 1 ]; then
    report V1 PASS "$info; container uid 0 maps from host uid $myuid" "$v1_raw" yes
  else
    report V1 FAIL "$info" "$v1_raw" yes
  fi
else
  report V1 FAIL "podman not installed (sudo apt-get install -y podman crun uidmap slirp4netns passt)" "$v1_raw" yes
fi

# ---------------------------------------------------------------------------------------------
# V2 — GPU in a rootless container via CDI (blocking only when DOCTOR_REQUIRE_GPU=1)
v2_block=no; [ "${DOCTOR_REQUIRE_GPU:-0}" = 1 ] && v2_block=yes
v2_raw="$(
  ls -l /dev/dxg 2>&1; ls /usr/lib/wsl/lib 2>&1 | head -n 5
  nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv 2>&1
  echo "\$ nvidia-ctk --version"; nvidia-ctk --version 2>&1 | head -n 2
)"
v2_fail_status=WARN; [ "$v2_block" = yes ] && v2_fail_status=FAIL
if ! have nvidia-ctk; then
  report V2 "$v2_fail_status" "nvidia-ctk not installed (nvidia-container-toolkit-base)" "$v2_raw" "$v2_block"
elif ! have podman; then
  report V2 "$v2_fail_status" "podman not installed" "$v2_raw" "$v2_block"
else
  cdi="$(nvidia-ctk cdi list 2>&1)"
  cdi_hint=""
  # The CDI spec (/var/run/cdi/nvidia.yaml) is generated by nvidia-cdi-refresh.service. Never
  # generate a second one by hand: duplicate device names conflict.
  if ! echo "$cdi" | grep -q 'nvidia.com/gpu=all'; then
    cdi_hint=" [CDI spec missing: check 'systemctl status nvidia-cdi-refresh.service nvidia-cdi-refresh.path'; do NOT run nvidia-ctk cdi generate]"
  fi
  img=""
  for t in "${CUDA_TAGS[@]}"; do
    if podman image exists "$t" || podman pull -q "$t" >/dev/null 2>&1; then img="$t"; break; fi
  done
  if [ -z "$img" ]; then
    report V2 "$v2_fail_status" "no CUDA base image tag could be pulled$cdi_hint" "$v2_raw"$'\n'"$cdi" "$v2_block"
  else
    out="$("${PM[@]}" run --rm --device nvidia.com/gpu=all --security-opt label=disable "$img" nvidia-smi 2>&1)"
    # nvidia-smi's table pads the name and follows it with Persistence-M ("On"/"Off"); cut at the padding.
    gpu="$(echo "$out" | grep -o -E 'NVIDIA [A-Za-z0-9 ]+' | head -n 1 | sed -E 's/ {2,}.*$//; s/ *$//')"
    raw="$v2_raw"$'\n'"\$ nvidia-ctk cdi list"$'\n'"$cdi"$'\n'"\$ podman run … $img nvidia-smi"$'\n'"$out"
    if [ -n "$gpu" ]; then
      report V2 PASS "nvidia-smi in rootless container sees: $gpu ($img)" "$raw" "$v2_block"
    else
      report V2 "$v2_fail_status" "nvidia-smi inside container did not list a GPU$cdi_hint" "$raw" "$v2_block"
    fi
  fi
fi

# ---------------------------------------------------------------------------------------------
# V3 — cgroup v2 delegation so --memory/--pids-limit bind (BLOCKING: Podman silently drops the
# limits on cgroup v1, so a v1 host must FAIL, never warn; RT-AG-09 depends on it)
uid="$(id -u)"
ctrl="$(cat "/sys/fs/cgroup/user.slice/user-$uid.slice/user@$uid.service/cgroup.controllers" 2>&1)"
if have podman; then
  lim="$("${PM[@]}" run --rm --memory 128m --pids-limit 50 "$ALPINE" sh -c 'cat /sys/fs/cgroup/memory.max /sys/fs/cgroup/pids.max' 2>&1)"
else
  lim="podman not installed"
fi
raw="\$ user@$uid.service cgroup.controllers"$'\n'"$ctrl"$'\n'"\$ podman run --memory 128m --pids-limit 50 …"$'\n'"$lim"
cgv="$(have podman && podman info --format '{{.Host.CgroupsVersion}} {{.Host.CgroupManager}}' 2>/dev/null)"
raw="\$ podman info cgroups: ${cgv:-n/a}  |  /sys/fs/cgroup fstype: $(stat -fc %T /sys/fs/cgroup)  |  systemd: $(systemctl is-system-running 2>&1)"$'\n'"$raw"
ok=1
for c in memory pids cpu; do echo "$ctrl" | tr ' ' '\n' | grep -qx "$c" || ok=0; done
echo "$lim" | grep -qx '134217728' || ok=0
echo "$lim" | grep -qx '50' || ok=0
if [ "$ok" = 1 ]; then
  report V3 PASS "delegated controllers: $ctrl; memory.max=134217728 pids.max=50" "$raw" yes
elif [ "${cgv%% *}" = "v1" ]; then
  # WSL2 boots a hybrid hierarchy by default. Remedy (Windows side): add
  #   kernelCommandLine = cgroup_no_v1=all
  # under [wsl2] in %UserProfile%\.wslconfig, then 'wsl --shutdown'. Needs [boot] systemd=true too.
  report V3 FAIL "cgroup ${cgv} (hybrid): rootless limits IGNORED (fix: kernelCommandLine = cgroup_no_v1=all in .wslconfig [wsl2], then wsl --shutdown)" "$raw" yes
else
  report V3 FAIL "limits not proven to bind (need cgroup v2 + systemd; see [boot] systemd=true in /etc/wsl.conf)" "$raw" yes
fi

# ---------------------------------------------------------------------------------------------
# V4 — --network=none keeps loopback (blocking)
if have podman; then
  # No --dns=none: Podman 4.9 rejects it with --network=none ("conflicting options: dns and the
  # network mode: none"). The 'no nameserver' assertion below proves the same thing.
  out="$("${PM[@]}" run --rm --network=none --no-hosts "$ALPINE" sh -c 'ip -o link; ip -o addr; cat /etc/resolv.conf; echo "resolv exit=$?"' 2>&1)"
  links="$(echo "$out" | grep -E '^[0-9]+: ' | grep -v ' inet' | awk -F': ' '{print $2}' | cut -d@ -f1 | sort -u | tr '\n' ' ')"
  ok=1
  [ "$links" = "lo " ] || ok=0
  echo "$out" | grep -E '^[0-9]+: lo:' | grep -q '[<,]UP[,>]' || ok=0
  echo "$out" | grep -q 'inet 127.0.0.1/8' || ok=0
  echo "$out" | grep -q '^nameserver' && ok=0
  if [ "$ok" = 1 ]; then
    report V4 PASS "only lo (flag UP), 127.0.0.1/8 present, no nameserver" "$out" yes
  else
    report V4 FAIL "interfaces: ${links:-none}" "$out" yes
  fi
else
  report V4 FAIL "podman not installed" "" yes
fi

# ---------------------------------------------------------------------------------------------
# V5 — Unix sockets across a bind mount with --userns=keep-id, both directions (blocking)
if have podman; then
  d="$WORK/v5"; mkdir -p "$d"
  podman image exists "$PYIMG" || podman pull -q "$PYIMG" >/dev/null 2>&1
  # (a) container listens, host connects
  "${PM[@]}" run -d --rm --name sp-doctor-v5a --userns=keep-id --network=none -v "$d:/s:rw" "$PYIMG" \
    python3 -c 'import socket; s=socket.socket(socket.AF_UNIX); s.bind("/s/c.sock"); s.listen(); c,_=s.accept(); c.sendall(b"from-container"); c.close()' >/dev/null 2>&1
  a="$(python3 - "$d/c.sock" <<'EOF' 2>&1
import socket, sys, time
path = sys.argv[1]
for _ in range(100):  # wait up to ~10 s for the container to bind
    try:
        s = socket.socket(socket.AF_UNIX); s.settimeout(5); s.connect(path); print(s.recv(32)); break
    except (FileNotFoundError, ConnectionRefusedError):
        time.sleep(0.1)
else:
    print("timeout waiting for container socket")
EOF
)"
  podman rm -f sp-doctor-v5a >/dev/null 2>&1
  # (b) host listens, container connects
  b="$(python3 - "$d" "$PYIMG" "${PM[@]}" <<'EOF' 2>&1
import socket, subprocess, sys
d, img, pm = sys.argv[1], sys.argv[2], sys.argv[3:]
s = socket.socket(socket.AF_UNIX); s.bind(d + "/h.sock"); s.listen(); s.settimeout(60)
code = 'import socket; c=socket.socket(socket.AF_UNIX); c.connect("/s/h.sock"); c.sendall(b"from-host-side")'
p = subprocess.Popen(pm + ["run", "--rm", "--userns=keep-id", "--network=none",
                      "-v", d + ":/s:rw", img, "python3", "-c", code],
                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
try:
    c, _ = s.accept(); print(c.recv(32))
except TimeoutError:
    print("timeout waiting for container to connect")
out, _ = p.communicate(timeout=60)
if p.returncode:
    print("container exit", p.returncode, out.decode(errors="replace")[-400:])
EOF
)"
  raw="(a) container->host: $a"$'\n'"(b) host->container: $b"
  if echo "$a" | grep -q "from-container" && echo "$b" | grep -q "from-host-side"; then
    report V5 PASS "both directions delivered (from-container, from-host-side)" "$raw" yes
  else
    report V5 FAIL "socket round-trip incomplete" "$raw" yes
  fi
else
  report V5 FAIL "podman not installed" "" yes
fi

# ---------------------------------------------------------------------------------------------
# V6 — openat2(2) with RESOLVE_BENEATH (blocking)
out="$(python3 - <<'EOF' 2>&1
import ctypes, os, tempfile
libc = ctypes.CDLL(None, use_errno=True)
class OpenHow(ctypes.Structure):
    _fields_ = [("flags", ctypes.c_uint64), ("mode", ctypes.c_uint64), ("resolve", ctypes.c_uint64)]
RESOLVE_BENEATH = 0x08; RESOLVE_NO_SYMLINKS = 0x04; RESOLVE_NO_MAGICLINKS = 0x02
SYS_openat2 = 437  # x86_64
d = tempfile.mkdtemp(); open(os.path.join(d, "ok"), "w").close(); os.symlink("/etc/passwd", os.path.join(d, "esc"))
dfd = os.open(d, os.O_PATH)
def try_open(rel):
    how = OpenHow(os.O_RDONLY, 0, RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)
    r = libc.syscall(SYS_openat2, dfd, rel.encode(), ctypes.byref(how), ctypes.sizeof(how))
    return r if r >= 0 else -ctypes.get_errno()
print(try_open("ok"), try_open("../etc/passwd"), try_open("esc"))
EOF
)"
read -r ok_fd up_rc sym_rc <<<"$out"
raw="uname -r: $(uname -r)"$'\n'"ok -> $ok_fd | ../etc/passwd -> $up_rc (expect -18 EXDEV) | esc -> $sym_rc (expect -40 ELOOP)"
if [ "${ok_fd:-x}" -ge 0 ] 2>/dev/null && [ "${up_rc:-}" = "-18" ] && [ "${sym_rc:-}" = "-40" ]; then
  report V6 PASS "openat2: ok=$ok_fd, ../ -> EXDEV, symlink -> ELOOP" "$raw" yes
else
  report V6 FAIL "unexpected openat2 results: $out" "$raw" yes
fi

# ---------------------------------------------------------------------------------------------
# V7 — WSLg + Tauri v2 prerequisites (informational)
missing=""
for p in "${TAURI_PKGS[@]}"; do dpkg_installed "$p" || missing="$missing $p"; done
raw="DISPLAY=${DISPLAY:-} WAYLAND=${WAYLAND_DISPLAY:-}"$'\n'"$(ls /mnt/wslg 2>&1 | head -n 3)"
if [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ] && [ -d /mnt/wslg ] && [ -z "$missing" ]; then
  report V7 PASS "WSLg present; Tauri prerequisites installed (render test deferred to M5 spike)" "$raw"
else
  report V7 WARN "WSLg: $([ -d /mnt/wslg ] && echo present || echo absent); missing dpkg:${missing:- none}" "$raw"
fi

# ---------------------------------------------------------------------------------------------
# V8 — Hugging Face exposes LFS sha256 (informational, network)
if [ "${DOCTOR_OFFLINE:-0}" = 1 ]; then
  report V8 UNVERIFIED "skipped (DOCTOR_OFFLINE=1)" ""
else
  out="$(curl -fsS --max-time 20 'https://huggingface.co/api/models/Qwen/Qwen2.5-0.5B-Instruct-GGUF?blobs=true' \
    | python3 -I -c 'import json,sys; d=json.load(sys.stdin); [print(s["rfilename"], (s.get("lfs") or {}).get("sha256") or (s.get("lfs") or {}).get("oid") or "NO-LFS", s.get("size")) for s in d["siblings"][:6]]' 2>&1)"
  # NB: as of 2026-11 the field is siblings[].lfs.sha256, not lfs.oid.
  if echo "$out" | grep -Eq '\.gguf [0-9a-f]{64} '; then
    report V8 PASS ".gguf siblings carry 64-hex siblings[].lfs.sha256 (not lfs.oid)" "$out"
  else
    report V8 FAIL "no 64-hex lfs.sha256 on .gguf rows" "$out"
  fi
fi

# ---------------------------------------------------------------------------------------------
# V9 — GitHub Actions runner has rootless Podman
report V9 UNVERIFIED "settled by first CI run; fallback: apt-get install podman in the workflow" ""

# ---------------------------------------------------------------------------------------------
# V10 — nested virtualization (v2 only, informational)
raw="$(ls -l /dev/kvm 2>&1)"$'\n'"svm flags: $(grep -c svm /proc/cpuinfo)"
if [ -c /dev/kvm ]; then
  report V10 PASS "/dev/kvm present" "$raw"
else
  report V10 WARN "/dev/kvm absent (needs nestedVirtualization=true in .wslconfig; v2 only)" "$raw"
fi

# ---------------------------------------------------------------------------------------------
# V11 — Blackwell training stack
report V11 UNVERIFIED "n/a in v1" ""

# ---------------------------------------------------------------------------------------------
# V12 — rootless Podman from the current shell (run once normally, once under Claude Code /sandbox)
# Claude Code's Linux sandbox is bubblewrap-based; bwrap always sets no_new_privs, which stops the
# setuid newuidmap that rootless Podman needs. The bwrap probe approximates /sandbox (it lacks the
# fs/network policy layer) and tells us whether sandbox mode can coexist with Podman.
if have podman; then
  out="$("${PM[@]}" run --rm "$ALPINE" true 2>&1; echo "exit=$?")"
  bw="bwrap not installed (Claude Code /sandbox unavailable)"
  if have bwrap; then
    bw="$(bwrap --dev-bind / / "${PM[@]}" run --rm "$ALPINE" true 2>&1 | grep -v 'shared mount' | tail -n 3; echo "exit=${PIPESTATUS[0]}")"
  fi
  raw="\$ podman run --rm alpine true"$'\n'"$out"$'\n'"\$ bwrap --dev-bind / / podman run --rm alpine true   (approximates Claude Code /sandbox)"$'\n'"$bw"
  bw_state="bwrap absent"
  if echo "$bw" | grep -qx 'exit=0'; then bw_state="under bwrap: OK"
  elif have bwrap; then bw_state="under bwrap: FAILS (no_new_privs blocks newuidmap) -> keep /sandbox off"; fi
  if echo "$out" | grep -qx 'exit=0'; then
    report V12 PASS "podman OK in this shell; $bw_state" "$raw"
  else
    report V12 FAIL "podman run alpine true failed in this shell; $bw_state" "$raw"
  fi
else
  report V12 UNVERIFIED "podman not installed" ""
fi

# ---------------------------------------------------------------------------------------------
# V13 — rootless overlay volume with a kept upper dir under --userns=keep-id (blocking: `staged`
# mounts and the .git overlays depend on it, AMENDMENTS-02 B2). Records how deletions look.
if have podman; then
  d="$WORK/v13"; mkdir -p "$d/lower" "$d/upper" "$d/work"
  echo a > "$d/lower/keep"; echo b > "$d/lower/gone"
  out="$("${PM[@]}" run --rm --network=none --userns=keep-id \
    -v "$d/lower:/w:O,upperdir=$d/upper,workdir=$d/work" "$ALPINE" \
    sh -c 'rm /w/gone; echo new > /w/new; echo mod >> /w/keep; ls /w' 2>&1; echo "exit=$?")"
  wh="$(stat -c '%F %t,%T uid=%u' "$d/upper/gone" 2>&1)"
  raw="$out"$'\n'"lower: $(ls "$d/lower" | tr '\n' ' ') keep=$(cat "$d/lower/keep")"$'\n'"upper: $(ls "$d/upper" | tr '\n' ' ')"$'\n'"whiteout: $wh"
  if [ -f "$d/lower/gone" ] && [ "$(cat "$d/lower/keep")" = a ] && [ -f "$d/upper/new" ] \
     && echo "$wh" | grep -q '^character special file 0,0'; then
    report V13 PASS "lower untouched; writes in upper; deletion = 0/0 char-device whiteout (${wh##* })" "$raw" yes
  else
    report V13 FAIL "overlay volume with kept upper dir does not behave as staged mounts need" "$raw" yes
  fi
  podman unshare rm -rf "$d" 2>/dev/null
else
  report V13 FAIL "podman not installed" "" yes
fi

# ---------------------------------------------------------------------------------------------
# V14 — OCI runtime provenance and pending updates (AMENDMENTS-02 B5). The distro crun is the
# release build and never gets security updates; Sallyport pins the upstream crun named in
# runtime.lock (version, URL, SHA-256, pin date), never below MIN_CRUN.
MIN_CRUN="1.25.1"
PIN_MAX_AGE_DAYS=183   # six months
LOCK_FILE="$SCRIPT_DIR/../runtime.lock"
version_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n 1)" = "$2" ]; }
# lock_get <KEY> <validation ERE>: the value, only if the line exists once and matches. Never sourced.
lock_get() {
  local v
  [ "$(grep -c "^$1=" "$LOCK_FILE" 2>/dev/null)" = 1 ] || return 1
  v="$(grep "^$1=" "$LOCK_FILE" | cut -d= -f2-)"
  printf '%s' "$v" | grep -Eqx "$2" || return 1
  printf '%s' "$v"
}
lock_ver="$(lock_get CRUN_VERSION '[0-9]+\.[0-9]+(\.[0-9]+)?')"
lock_sha="$(lock_get CRUN_SHA256 '[0-9a-f]{64}')"
lock_date="$(lock_get PIN_DATE '[0-9]{4}-[0-9]{2}-[0-9]{2}')"
lock_url="$(lock_get CRUN_URL 'https://github\.com/containers/crun/releases/download/[^ ]+')"
lock_ok=1
{ [ -n "$lock_ver" ] && [ -n "$lock_sha" ] && [ -n "$lock_date" ] && [ -n "$lock_url" ]; } || lock_ok=0
pin_age=""
if [ "$lock_ok" = 1 ]; then
  pin_epoch="$(date -u -d "$lock_date" +%s 2>/dev/null)" || lock_ok=0
  [ -n "${pin_epoch:-}" ] && pin_age=$(( ( $(date -u +%s) - pin_epoch ) / 86400 ))
fi
rt_bin="${RUNTIME:-$(command -v crun 2>/dev/null)}"
rt_ver="$("$rt_bin" --version 2>/dev/null | awk 'NR==1 {print $3}')"
# The same owner/mode rule sallyd applies (sally_core::config::check_runtime_binary): the binary
# and every directory above it owned by us or root, not writable by group or others.
rt_private=1
rt_real="$(readlink -f "$rt_bin" 2>/dev/null)"
p="$rt_real"
while [ -n "$p" ]; do
  o="$(stat -c '%u' "$p" 2>/dev/null)"; m="$(stat -c '%a' "$p" 2>/dev/null)"
  if [ -z "$o" ] || { [ "$o" != 0 ] && [ "$o" != "$(id -u)" ]; } || [ $(( 0$m & 022 )) -ne 0 ]; then
    rt_private=0; rt_bad="$p (uid=$o mode=$m)"; break
  fi
  [ "$p" = / ] && break
  p="$(dirname "$p")"
done
pending="$(apt list --upgradable 2>/dev/null | grep -E '^(podman|crun|conmon|netavark|uidmap)/' || true)"
rt_sha="$(sha256sum "$rt_real" 2>/dev/null | cut -d' ' -f1)"
raw="runtime: ${rt_bin:-none} ($rt_ver) sha256=${rt_sha:-n/a}"$'\n'"runtime.lock: crun ${lock_ver:-?} sha256=${lock_sha:-?} pinned ${lock_date:-?} (${pin_age:-?} days ago)"$'\n'"distro crun: $(dpkg-query -W -f='${Version}' crun 2>/dev/null)"$'\n'"pending updates: ${pending:-none}"
if [ "$lock_ok" != 1 ]; then
  report V14 WARN "runtime.lock missing or malformed (need CRUN_VERSION, CRUN_URL, CRUN_SHA256, PIN_DATE)" "$raw"
elif [ "$rt_private" != 1 ]; then
  report V14 WARN "runtime $rt_real can be swapped by someone else: $rt_bad" "$raw"
elif [ "$rt_bin" != "$PINNED_RUNTIME" ]; then
  report V14 WARN "distro runtime crun $rt_ver: never security-patched; install the pinned upstream crun $lock_ver from runtime.lock (AMENDMENTS-02 B5)" "$raw"
elif [ "$rt_sha" != "$lock_sha" ]; then
  # Non-blocking like the rest of V14, but loud: the binary is not the one the lock names.
  report V14 FAIL "pinned runtime $rt_real does not match runtime.lock CRUN_SHA256 (expected crun $lock_ver)" "$raw"
elif [ "$rt_ver" != "$lock_ver" ] || ! version_ge "$rt_ver" "$MIN_CRUN"; then
  report V14 WARN "pinned crun reports $rt_ver; runtime.lock pins $lock_ver (minimum $MIN_CRUN)" "$raw"
elif [ -n "$pending" ]; then
  report V14 WARN "pending updates: $(echo "$pending" | cut -d/ -f1 | tr '\n' ' ')" "$raw"
elif [ "${pin_age:-0}" -gt "$PIN_MAX_AGE_DAYS" ]; then
  report V14 WARN "runtime pin is $pin_age days old (> $PIN_MAX_AGE_DAYS): check for a newer crun release and bump runtime.lock" "$raw"
else
  report V14 PASS "pinned upstream crun $rt_ver matches runtime.lock (sha256, pinned $pin_age days ago); no pending podman/crun/conmon/netavark/uidmap updates" "$raw"
fi

# ---------------------------------------------------------------------------------------------
# V15 — kernel >= 6.6 (informational)
kver="$(uname -r | cut -d- -f1)"
if version_ge "$kver" "6.6"; then
  report V15 PASS "kernel $kver >= 6.6" ""
else
  report V15 WARN "kernel $kver < 6.6" ""
fi

# ---------------------------------------------------------------------------------------------
# V16 — gVisor runsc present (informational; M6 spike)
if have runsc; then
  report V16 PASS "runsc: $(runsc --version 2>&1 | head -n 1)" ""
else
  report V16 WARN "runsc absent (informational; needed only for the M6 gVisor spike)" ""
fi

# ---------------------------------------------------------------------------------------------
# V17 — system CA bundle for the token proxy (Task 9a, architect Q31). The same rule as
# crates/sallyd/src/egress/roots.rs: the first bundle that exists is used, and must be a regular
# file (after symlinks), owned by root, not group- or other-writable, at most 4 MiB. A session
# with secret grants is refused without it; other sessions do not need it (so a WARN).
ca_found=""
for ca in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem \
          /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem; do
  [ -e "$ca" ] || continue
  ca_found="$ca"
  break
done
if [ -z "$ca_found" ]; then
  report V17 WARN "no system CA bundle found: sessions with secret grants will be refused" ""
else
  ca_stat="$(stat -L -c '%F %u %a %s' "$ca_found" 2>&1)"
  read -r ca_t1 ca_t2 ca_uid ca_mode ca_size <<<"$ca_stat"
  if [ "$ca_t1 $ca_t2" != "regular file" ]; then
    report V17 WARN "$ca_found is not a regular file: secret sessions will be refused" "$ca_stat"
  elif [ "$ca_uid" != 0 ]; then
    report V17 WARN "$ca_found is not owned by root: secret sessions will be refused" "$ca_stat"
  elif (( (8#$ca_mode & 8#022) != 0 )); then
    report V17 WARN "$ca_found is group- or other-writable: secret sessions will be refused" "$ca_stat"
  elif [ "$ca_size" -gt 4194304 ]; then
    report V17 WARN "$ca_found is larger than 4 MiB: secret sessions will be refused" "$ca_stat"
  else
    report V17 PASS "system CA bundle $ca_found (root-owned, mode $ca_mode, $ca_size bytes)" ""
  fi
fi

echo
if [ "$BLOCKING_FAILS" -eq 0 ]; then
  echo "== RESULT: all blocking checks passed"
else
  echo "== RESULT: $BLOCKING_FAILS blocking check(s) failed"
fi
exit "$BLOCKING_FAILS"
