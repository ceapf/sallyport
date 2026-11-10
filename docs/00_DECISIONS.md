# 00 — Decision record

The foundational product decisions for Sallyport, each with the reason it was made. Later changes
are recorded in `docs/AMENDMENTS-*.md`; where an amendment and this file disagree, the amendment
wins.

Names used throughout: **Sallyport** (repository `sallyport`), the `sallyd` broker daemon, the
`sally` CLI, and the `sally-shim` static helper.

---

## D1. Product name — Sallyport

A *sally port* is the single controlled gate in a fortress wall: everything in or out passes
through it under guard. That is exactly what the broker does. The name is distinctive, searchable
and gives a short CLI name. Known collision: a security-services company outside software uses
"Sallyport Global"; no software trademark conflict was found. Names that are crowded in security
software, or that belong to another organization's fiction or to an existing AI-safety
organization, were rejected.

## D2. License — Apache-2.0, DCO instead of a CLA

The patent grant matters for a security product, and permissive licensing is what this audience
expects. A later team-policy tier can live in a separate repository or service without
relicensing. AGPL adds little for a desktop app and deters contributors; MIT lacks the patent
grant. Contributions carry a DCO sign-off.

## D3. Container engine — rootless Podman + crun, GPU via CDI

NVIDIA documents CDI with Podman as the recommended path on WSL2. Rootless means container root is
the invoking user's UID, not host root, so a whole class of escapes reduces to "the attacker is
already that user". Daemonless means `sallyd` spawns containers directly and nothing else on the
host exposes a privileged socket. Docker Engine was the fallback had the M0 spike failed; v1 does
not abstract over both engines.

## D4. Platform — Linux first, Windows via WSL2

The Tauri app runs inside WSL and displays through WSLg. This is honest about what the sandbox is
(a Linux kernel). A Windows-native shell that talks to `sallyd` inside WSL is a v2 candidate.
Windows-native containers are out of scope.

## D5. Pickle policy — refuse outright in v1

`.bin/.pt/.pth/.pkl/.ckpt/.h5` are refused with a one-line explanation and a link. Conversion in a
throwaway sandbox is a v2 feature. Users who have pickle checkpoints can convert them; users the
product protects do not need them.

## D6. Runnable model formats in v1 — GGUF only

Safetensors are detected, validated and stored (so the library is future-proof) but shown as
"needs conversion (v2)". llama.cpp is the only engine. Hugging Face browsing filters to GGUF
repositories by default.

## D7. Reference harness language — Python

Harnesses run inside the untrusted sandbox, so their language carries no security weight; Python
maximizes moddability and MCP ecosystem reach. The broker, proxies, parsers and CLI are Rust, for
memory safety where it matters. A Rust SDK can follow.

## D8. Shell default in the coding-agent template — `approve`

Every command needs a click. `allow` with destructive-pattern matching exists, but the pattern list
is a speed bump, not a boundary: regexes are bypassable. Manifests opt into `allow` explicitly and
the summary shows a warning.

## D9. Secrets at rest — 0600 plaintext file in v1

`~/.config/sallyport/secrets.toml`, mode 0600. The invariant that matters is *never inside a
sandbox*; at-rest encryption on a single-user machine only defends against an attacker who already
has the user's UID, which the design cannot stop anyway. v2: OS keychain via the `keyring` crate,
with an optional passphrase. The documentation states this plainly so nobody mistakes the store
for a vault.

## D10. Telemetry — none

Not even opt-in crash reports in v1. `sallyd`'s only outbound traffic is user-initiated Hugging
Face downloads and proxied sandbox egress, and RT-NET tests prove it (SI-12).

## D11. Public repository

The threat model and the red-team CI are meant to be read; security by obscurity has no value
here. `SECURITY.md` points reporters to GitHub private vulnerability reporting.

## D12. Reserved fields for a future policy tier

Reserve two fields, build nothing: the manifest has an optional `policy:` block (`signed_by`,
`signature`) that v1 parses and ignores, and audit entries carry `org_id: null`. That is enough to
add signed organization policies and central audit later without a schema break.

## D13. Development agent model pinning

Development uses Claude Code with ECC-derived subagents (see `THIRD_PARTY_NOTICES.md`). Models are
pinned in each agent's frontmatter (`model:` in `.claude/agents/*.md`) rather than switched by
hand, so routing is reviewable in the repository:

| Agent | Model |
|---|---|
| planner, architect, security-reviewer | opus |
| rust-reviewer (core crates), mle-reviewer | opus |
| code-reviewer, typescript-reviewer, python-reviewer, tdd-guide, e2e-runner, refactor-cleaner | sonnet |
| build-error-resolver, rust-build-resolver, doc-updater, docs-lookup | haiku (escalate to sonnet after two failed attempts) |

The main session uses `opusplan`. Security-core implementation tasks (manifest validator, sandbox
driver, egress/token proxy, approvals) switch to `/model opus`.

## D14. Image registry

Container images are published as `ghcr.io/<owner>/sallyport-*`, where `<owner>` is the GitHub
account that owns this repository, and are referenced by digest only (SI-11).

---

## Load-bearing assumptions

Verified at M0 on the development machine; full results in `docs/reports/M0-preflight.md`.
`scripts/doctor.sh` re-checks them on every run.

| # | Assumption | Result | What was learned |
|---|---|---|---|
| V1 | Rootless Podman works on WSL2 Ubuntu 24.04 | **PASS** | Podman 4.9.3 + crun. The WSL kernel has no AppArmor, so Ubuntu's userns restriction is moot. Minimum Podman is 4.9. |
| V2 | GPU in a rootless container via CDI | **PASS** | `nvidia-ctk` 1.20.1 auto-generates the spec at `/var/run/cdi/nvidia.yaml` via `nvidia-cdi-refresh.service`. Never run `nvidia-ctk cdi generate` by hand; a second spec can conflict. `install.sh` checks that the service is enabled instead of generating. |
| V3 | cgroup v2, so `--memory/--pids-limit/--cpus` bind rootless | **PASS after fix** | WSL2 boots cgroup v1 by default and Podman then *silently drops* limits; `systemd=true` alone does not fix it. Fix: `kernelCommandLine = cgroup_no_v1=all` under `[wsl2]` in `C:\Users\<you>\.wslconfig`, then `wsl --shutdown`. Doctor **fails** on v1; RT-AG-09 is blocked until v2. |
| V4 | `--network=none` keeps loopback | **PASS** | `lo` up, `127.0.0.1/8`, no `resolv.conf`. Podman 4.9 rejects `--dns=none` together with `--network=none`, so it is not in the normative argv. `--no-hosts` stays. |
| V5 | Unix sockets across bind mounts, both directions, `--userns=keep-id` | **PASS** | As designed. |
| V6 | `openat2` + `RESOLVE_BENEATH` | **PASS** | `../` → EXDEV, symlink → ELOOP (kernels 5.15 and 6.18). |
| V7 | WSLg renders Tauri v2 | deferred to M5 | WSLg is present; the Tauri `-dev` packages are installed at M5. |
| V8 | Hugging Face exposes a per-file LFS SHA-256 | **PASS** | The field is `siblings[].lfs.sha256`, not `lfs.oid`. |
| V9 | GitHub Actions `ubuntu-24.04` has rootless Podman | unverified | Settled by the first red-team CI run; fallback `apt-get install podman`. |
| V10 | Nested virtualization available | **PASS** | `/dev/kvm` present, so the gVisor KVM platform is an option for v2. |
| V11 | Blackwell sm_120 training stack | n/a | v2. |
| V12 | Claude Code `/sandbox` coexists with rootless Podman | **FAIL (expected)** | bubblewrap blocks `newuidmap`. Sandbox mode stays off for this repository; `.claude/settings.json` permissions are the guardrail. |

Development target hardware class: x86-64 workstation, NVIDIA RTX 50-series GPU with 16 GB VRAM,
WSL2 Ubuntu 24.04. Toolchain: Rust 1.99.1 stable + musl target, Python 3.12, Node 26 LTS.
