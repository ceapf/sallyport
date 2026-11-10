# 01 — v1 scope

Scope: sized for ~6–8 weeks of focused work, with Claude Code doing most typing. The cut line is:
**v1 proves the security architecture end-to-end with one engine, one format, one harness, and
a UI good enough that a non-expert can pull a GGUF and chat or run a coding agent safely.**
Everything that does not serve that sentence is v2+.

## IN (v1.0)

### Security core
- Manifest v1 (YAML, strict schema, human-readable summary) — `docs/MANIFEST_SPEC.md`
- `sallyd` broker daemon: control API (CLI/UI) and per-session agent API over Unix sockets
- Hardened rootless Podman sandboxes with two profiles: **inference** (GPU, no net, RO weights)
  and **agent** (no GPU, no net, mounts per manifest)
- Egress proxy: `network=none` everywhere; the only path out is a Unix socket to the broker;
  hostname/port allowlist, IP-range filtering, pinned resolution, byte accounting
- Token proxy: credentials injected by the broker per host; never present in a sandbox; response
  redaction; no redirect following
- Approval gate: single-use, canonicalized, sanitized rendering, default-deny on timeout,
  flood control
- Brokered filesystem tools with kernel-enforced path confinement (`openat2 RESOLVE_BENEATH`)
- Hash-chained, append-only audit log with `sally audit verify`
- Red-team suite in CI (no GPU) + GPU-local suite; CI fails if any attack succeeds

### Models
- Formats: GGUF (runs), safetensors (validated, stored, "needs conversion" badge)
- Refuse pickle-family files with a clear message
- Strict memory-safe GGUF header parser (bounded, fuzzed) before any engine touches a file
- SHA-256 of every blob; verify against Hugging Face LFS hash when available; immutable
  content-addressed library
- Hugging Face browse (GGUF filter), per-quant file list with VRAM/RAM fit indicator, one-click
  pull with resume, gated-repo token used on the host only
- Local import: single `.gguf`, folder, or `.zip` (zip-slip-safe, symlink/hardlink rejecting)

### Inference
- llama.cpp `llama-server`, built from a pinned commit with CUDA 12.9 + sm_120 (and sm_86/89)
  into our own image, digest-pinned
- One loaded model at a time; load/unload/status; OpenAI-compatible chat completion passthrough
  with request validation and streaming
- CPU-only inference image for CI and non-NVIDIA users

### Agents
- Python SDK (`sallyport_sdk`) speaking the session API
- One reference ReAct harness: `fs.read/write/list/delete`, `fetch`, `shell` (brokered), with
  tool schemas fed to the model via llama.cpp's `--jinja` tool-calling
- MCP stdio servers launched *inside* the agent sandbox, declared in the manifest
- Deterministic "malicious mock model" for CI red-team runs

### UI (Tauri v2 + React/TS)
- Screens: Library, Browse HF, Chat, Agents (run + live tool/approval log), Manifest editor
  (YAML + schema validation + plain-English summary), Approvals modal, Audit viewer, Settings
  (secrets write-only, Doctor)
- Markdown rendering sanitized; strict CSP; UI reaches nothing but `sallyd`

### Ops
- `sally doctor` + `install.sh` (checks Podman, crun, cgroup v2, NVIDIA CDI, generates CDI spec)
- Linux `.deb` + AppImage; "Windows via WSL2" docs
- `SECURITY.md`, `THREAT_MODEL.md`, README with the invariant list

## OUT → v2+ (in rough priority order)

1. **safetensors → GGUF conversion** in a throwaway network-less sandbox
2. **Pickle → safetensors conversion** in a throwaway sandbox (explicit scary opt-in)
3. **LoRA/QLoRA fine-tuning** via Unsloth sidecar (its own GPU zone), export back to library
   (blocked on Blackwell sm_120 support in that stack — verify first)
4. **gVisor runtime** for the agent zone (`podman --runtime=runsc`, systrap on WSL2, KVM on
   native Linux); microVM (libkrun/Firecracker) for the agent zone on native Linux
5. **Multiple engines**: vLLM, ExLlamaV2, TensorRT-LLM; multi-model concurrency and scheduling
6. **Input classifier** (PromptGuard-style) as optional defense-in-depth on tool outputs
7. **Egress DLP**: size/entropy heuristics and content inspection on allowlisted hosts
8. **Harness/MCP marketplace** with signed packages; MCP servers on the host with brokered creds
9. **Native Windows shell** (Tauri on Windows → `sallyd` in WSL); macOS (Apple Silicon, Metal)
10. **Team policy management + central audit** (the paid tier): signed org manifests, policy
    inheritance, SSO, audit export
11. **Local API server** (expose OpenAI-compatible endpoint to other apps, with its own manifest)
12. RAG / document ingestion, image/vision models, voice, speculative decoding
13. OS keychain for secrets; passphrase-encrypted store
14. Session persistence/branching, multi-session UI, themes, i18n
15. Auto-update channel with signed releases
16. Approve-on-demand for new egress domains (approval fatigue risk — needs design)
17. Rust SDK for harnesses; WASM harness runtime

## Non-goals (not v2 either, unless the project changes direction)

- Running untrusted *users* (multi-tenant). Single user, single machine.
- Protecting against an attacker who already has your UID on the host.
- Cloud inference brokering. The point is local.
