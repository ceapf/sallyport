# Milestone plan (v1.0 in ~7.5 work-weeks)

Format per task: **task — agent (model)**. Main session is `opusplan`; "(opus)" on an
implementation task means switch with `/model opus` for that task. Red-team IDs refer to
`tests/redteam/REDTEAM_SUITE.md`. Each milestone ends with: `make redteam` green in CI,
`/security-scan`, `/code-review`, `docs/reports/M<n>.md`, **stop for the maintainer's review**.

Estimates are in focused work-weeks. Buffer is built in: the plan sums to ~7.5 of 8.

---

## M0 — Environment spikes — **DONE 2026-11-09** (`docs/reports/M0-preflight.md`)

Result: V1, V2, V4, V5, V6, V10 PASS; V3 pending the `.wslconfig` cgroup v2 fix; V12 (Claude
Code sandbox mode) fails as expected → off. **D3 decided: Podman rootless.** `scripts/doctor.sh`
exists and is committed. Two spikes were deliberately not run and move to where they're needed:
the sm_120 `llama-server` image build is now **M3 task 1**, and the Tauri/WSLg hello-world is
**M5 task 1** (install the four Tauri `-dev` packages then).

Carry-over into M1: doctor must treat cgroup v1 as FAIL; the agent-profile argv has no
`--dns=none`; HF hash field is `lfs.sha256`.

---

## M1 — Security core + minimal CLI (2 weeks)

**Goal:** a manifest can launch a hardened sandbox whose only exits are the broker's sockets; egress and credentials are brokered; approvals and audit work; the red-team CI proves it. No models, no UI.

Tasks
1. Repo bootstrap: workspace, crates, lints, `rust-toolchain.toml`, `deny.toml`, `Makefile`, `ci.yml` (fmt/clippy/test/deny), pre-commit; extend the existing `scripts/doctor.sh` so cgroup v1 is FAIL and the CDI service check replaces manual generation (`.claude/` config already exists from preflight — don't touch it) — main (sonnet); build-error-resolver (haiku)
2. `sally-core::manifest`: types (`deny_unknown_fields`), loader, validator (denylist, realpath, is-dir/not-symlink, wildcard rules, secret refs, ack flag, ranges), plain-English `summary()`, JSON Schema export; errors with field paths — **main (opus)**, tdd-guide (sonnet); review: security-reviewer + rust-reviewer (opus)
3. `sally-core::secrets`: 0600 TOML store, `Secret<String>` with redacted Debug + zeroize, name-only API — main (sonnet); review security-reviewer (opus)
4. `sally-core::audit`: hash-chained NDJSON writer/verifier, redaction (secret values, >4 KiB args → sha256), monthly rotation with chain continuity — main (sonnet); review rust-reviewer (sonnet)
5. `sally-shim`: musl static binary; TCP 127.0.0.1:3128 ↔ UDS; one UDS conn per TCP conn; bounded buffers — main (sonnet); review rust-reviewer (sonnet)
6. `sallyd::sandbox`: `profile::argv()` pure builder for agent profile (inference profile stub); seccomp JSON files; mount prep + TOCTOU re-check; image digest check; launch/exec/kill/wait via `tokio::process`; stdout/err capture (capped); snapshot tests of argv; argv-denylist test (no `--privileged` etc.) — **main (opus)**; review security-reviewer + rust-reviewer (opus)
7. `sallyd::rpc`: UDS listeners, NDJSON JSON-RPC 2.0, separate method tables for control vs session, `SO_PEERCRED` UID check, frame limits — main (sonnet); review rust-reviewer (opus) for the method-table split
8. `sallyd::egress::{server,policy}`: bounded request parser (CONNECT only; absolute-form gets 405, maintainer's Task 8 decision 1), hostname/port rules with label-boundary wildcards, IP-literal denial, resolve→filter→pin, CONNECT splice, connection and head limits, audit events — **main (opus)**; review security-reviewer (opus)
9. `sallyd::egress::inject` (token proxy): per-host injection, strip client auth header + `Accept-Encoding`, TLS upgrade (rustls), response redaction, no redirect following; `tests/redteam/mock_upstream` TLS server (echo / gzip-echo / redirect) — **main (opus)**; review security-reviewer (opus)
10. `sallyd::approvals`: queue, canonical args, sanitized rendering, single-use IDs, timeout=deny, `max_pending` flood control, `deny_all_session`; CLI prompt renderer — main (sonnet) with **review (opus)**
11. `sallyd::tools::{fs,shell}`: `openat2` confinement for `fs.*` on `brokered` mounts; `shell` via `podman exec` with deny/approve/allow + destructive tagger — **main (opus)**; review security-reviewer (opus)
12. `sallyd::session` (minimal: no model yet) + `sally` CLI: `doctor`, `manifest validate|summary`, `secrets set|list|rm`, `sandbox run --manifest m.yaml -- <cmd>` (runs a command in Z3 with the manifest's walls, interactive approvals), `approvals`, `audit tail|verify` — main (sonnet)
13. Red-team suite M1 subset + harness + `redteam.yml` CI (rootless podman on `ubuntu-24.04`) — **main (opus)** authors tests; sonnet does plumbing
14. `/security-scan`; security-reviewer full pass on `crates/`; `/code-review`; doc-updater (haiku) for README quickstart; `docs/reports/M1.md` — per routing

Acceptance
- `sally sandbox run --manifest manifests/examples/coding-agent.yaml -- sh` yields a shell that: cannot resolve DNS, cannot open TCP to anything, *can* `curl -x http://127.0.0.1:3128 https://pypi.org/simple/` and gets 403 from the proxy for `https://example.org/`; sees only `/workspace/myproject`; cannot find the canary secret anywhere; `curl -x … http://api.github.com/user` against the mock upstream shows the injected header upstream and `[REDACTED:GITHUB_TOKEN]` in any echo.
- `sally audit verify` passes; tampering a byte fails it.
- Snapshot argv contains none of the forbidden flags.
- Red-team must pass: RT-FS-01..11, RT-NET-01..11, RT-SEC-01..08, RT-AG-01..06, RT-AG-08, RT-AG-09, RT-AUD-01..02, RT-MAN-01..03, RT-SUP-01.
- CI green including `redteam.yml`. `cargo deny` clean. No `unsafe`.

---

## M2 — Model library & validation (1 week)

**Goal:** browse, verify, and store models safely; refuse what we don't trust; estimate fit.

Tasks
1. `sally-core::model::detect` (extension allowlist + magic) and `gguf` strict parser with limits + `fuzz/gguf` target — **main (opus)**; review security-reviewer + rust-reviewer (opus)
2. `sally-core::model::safetensors` strict check + fuzz target — main (opus)
3. `sally-core::model::import`: single file / folder / zip (streaming, reject `..`, absolute, symlink/hardlink entries, size cap, zip-bomb ratio) → quarantine → verify → promote — **main (opus)**
4. `sally-core::library`: sqlite schema + content-addressed blobs (0444), `list/inspect/remove` — main (sonnet)
5. `sally-core::hf`: search (GGUF filter), repo files with LFS sha256, Range fetch of GGUF header, resumable download, disk-space check, HF token from store (host only), rate-limit backoff — main (sonnet); docs-lookup (haiku) for API shapes; review code-reviewer (sonnet)
6. Fit estimator (`models.fit`) with the formula in ARCHITECTURE §7; detect host VRAM/RAM (`nvidia-smi --query-gpu=memory.total`, `/proc/meminfo`) — main (sonnet); review mle-reviewer (opus)
7. CLI: `sally models search|files|pull|import|list|inspect|rm|fit` — main (sonnet)
8. `tests/redteam/corpus/` generators (malicious GGUF variants, pickle-with-canary, renamed pickle, zip-slip zips, safetensors bombs) — main (opus)
9. Red-team RT-MDL-01..09; reports — per routing

Acceptance: pulling a real GGUF from HF ends with a verified blob (hash equals HF `lfs.sha256`) and a correct fit badge on a 16 GB card; every corpus file is refused before any container starts; fuzz targets run 5 minutes locally without crash.

---

## M3 — Inference zone (1 week)

**Goal:** chat with a verified GGUF through the broker; the engine lives in Z2 with GPU and nothing else.

Tasks
1. **Spike first (from M0):** `images/inference/Containerfile` (pinned llama.cpp commit; CUDA 12.9 devel→runtime multi-stage; `-DCMAKE_CUDA_ARCHITECTURES="86;89;120"`), run it rootless with `--device nvidia.com/gpu=all --network=none` and a tiny GGUF, confirm `/v1/chat/completions` over `--host /run/sallyport/infer.sock` uses the GPU (`nvidia-smi` shows the process); then `images/inference-cpu/Containerfile`, `images/build.sh` writing `digests.lock` — main (sonnet); docs-lookup (haiku)
2. `sallyd::sandbox` inference profile argv + seccomp-inference (AF_INET socket denial) — **main (opus)**; review security-reviewer (opus)
3. `sallyd::infer`: load/unload/status, health wait over `infer.sock`, request validator (allowed OpenAI fields, caps), streaming passthrough, OOM/crash detection → unload + error — main (sonnet) with review rust-reviewer (opus)
4. `chat.complete` control method + `sally chat` REPL — main (sonnet)
5. Mock inference backend (`--mock-model <script>`) for CI: deterministic responses incl. attack tool-calls — main (sonnet)
6. Calibrate fit constants against real `llama-server` VRAM usage on 3 models — main (sonnet), mle-reviewer (opus)
7. Red-team RT-INF-01..04; `make e2e-gpu` with the tiny model; reports

Acceptance: `sally chat --model <name>` streams tokens from GPU; `podman inspect` of Z2 shows `--network=none`, RO weights, GPU device only; a shell exec'd into Z2 cannot write `/models/model.gguf`, cannot reach the network, finds no secrets.

---

## M4 — Agent zone + reference harness (1 week)

**Goal:** a manifest runs a Python harness that uses the model through the broker and tools through policy; CI red-team drives it with the malicious mock model.

Tasks
1. Re-add the `python` ECC rules pack to `.claude/rules/ecc/`; `images/harness-python/Containerfile` (python:3.12-slim by digest, non-root, SDK, shim, `/opt/sallyport/entry`) — main (sonnet)
2. `sallyport_sdk` (stdlib only): `Session`, `chat()` with streaming, `tools.list/call` with pending→result wait, `ui.post/next_input` — main (sonnet); review python-reviewer (sonnet)
3. Reference ReAct harness: tool schemas → llama.cpp tool-calling (`--jinja`), loop with max steps, approval-aware UX, MCP stdio spawn from `SALLY_MCP_SERVERS`; the system prompt tells the model not to commit (session commits are discarded in v1, AMENDMENTS-02) — main (sonnet); mle-reviewer (opus) on prompt/tool format
4. `sallyd::session` full lifecycle (ARCHITECTURE §5.4), `sessions.*`, `ui.*`, `tools.result` notifications, timeout, teardown guard — **main (opus)**; review security-reviewer (opus)
5. `sally run --manifest m.yaml "task"` interactive CLI (shows tool log, approvals inline) — main (sonnet)
6. Red-team RT-AG-01..10 end-to-end with the malicious mock model (CI) and once with a real model (local); reports

Acceptance: `sally run --manifest manifests/examples/coding-agent.yaml "add a README"` edits only `/workspace/myproject`, asks approval for every shell command, and the mock-model run in CI shows every injected attack denied with an audit line.

---

## M5 — Tauri UI (1.5 weeks)

**Goal:** a non-expert can pull a model and chat or run an agent without touching YAML, and can see every approval and audit event.

Tasks
1. **Spike first (from M0):** install the Tauri Linux `-dev` packages, scaffold Tauri v2, confirm a window renders under WSLg with `WEBKIT_DISABLE_DMABUF_RENDERER=1` set at the top of `main()` (gdk-pixbuf icon workaround if it panics); re-add the `typescript` ECC rules pack to `.claude/rules/ecc/`. Then: sidecar `sallyd`, bridge `rpc()` with method allowlist, capabilities minimal, CSP, `ts-rs` type export — main (sonnet); **review security-reviewer (opus)** on the bridge
2. Design system: cyberpunk-terminal palette, dark default, accessible contrast — main (sonnet) (use `frontend-design` skill once for direction)
3. Screens: Library (list/inspect/remove, fit badges), Browse HF (search, quant table, pull progress), Chat (streaming, sanitized Markdown, copy) — main (sonnet); typescript-reviewer
4. Screens: Agents (pick manifest + model, run, live tool/approval timeline, `ui.*` chat), Approvals modal (rendered canonical request, risk tags, approve/deny/deny-all; flood banner) — main (sonnet); **review security-reviewer (opus)** on rendering
5. Manifest editor: CodeMirror YAML + JSON Schema validation + live plain-English summary + templates from `manifests/examples` — main (sonnet)
6. Audit viewer (filter by session/event, verify button), Settings (secrets write-only, Doctor panel) — main (sonnet)
7. Component tests (Vitest), e2e-runner smoke against `sallyd` with the CPU inference image — e2e-runner (sonnet)
8. Red-team RT-UI-01..03; reports

Acceptance: fresh user flow (open app → Doctor green → search HF → pull → chat; then Agents → coding-agent template → approve a command) works on WSLg; XSS payloads from the mock model render inert.

---

## M6 — Hardening, packaging, release (1 week)

Tasks
1. Seccomp tightening pass + tests; verify resource limits actually bind (V3) — **main (opus)**; security-reviewer (opus)
2. Fuzz smoke in CI (60 s per target: gguf, safetensors, manifest, proxy parser, JSON-RPC framing); `cargo audit`/`cargo deny` in CI; SBOM (`cargo cyclonedx`) — main (sonnet)
3. Supply chain: image digests in `digests.lock` checked by `sallyd` at launch; cosign-sign images in release workflow — main (sonnet)
4. `install.sh` (installs the crun pinned in `runtime.lock`, checksum and signature verified) + `sally doctor` polish (actionable fix hints per failure) — main (sonnet)
5. Packaging: `.deb` + AppImage via `tauri build`; checksums; release workflow — main (sonnet); build-error-resolver (haiku)
6. Docs: README (invariants list, quickstart, "Windows via WSL2"), `SECURITY.md` (disclosure, scope = this threat model), manifest cookbook — doc-updater (haiku) + maintainer
7. Full red-team + GPU suites; `/security-scan`; final security-reviewer pass; `docs/reports/M6.md`; tag `v1.0.0`

Acceptance: clean install on a fresh WSL2 Ubuntu 24.04 VM via `install.sh` → Doctor green → pull → chat → agent, in under 15 minutes; CI: lint, test, deny, fuzz-smoke, redteam all green.

---

## v2 candidates (not scheduled)
See `docs/01_SCOPE.md` → OUT list. First three by value: safetensors→GGUF conversion sandbox, gVisor for Z3, Unsloth sidecar (after verifying sm_120 support).
