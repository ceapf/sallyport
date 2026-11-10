# Amendments 01 — architecture changes adopted at design review 2

Date: 2026-11-09. Written after the manifest validator landed and before anything else was built.

**Precedence.** Where this file conflicts with `ARCHITECTURE.md`, `THREAT_MODEL.md`,
`MANIFEST_SPEC.md`, `MILESTONES.md`, `REDTEAM_SUITE.md` or `CLAUDE.md`, this file wins until the
change has been folded into that doc. Fold each section in the task that implements it (§9), then
delete the section here and say so in the commit.

## 0. The change in one paragraph

The model-steered code (the harness) no longer lives next to the user's files. It runs in its own
container with exactly two loopback endpoints — an OpenAI-compatible HTTP endpoint for the model
and an MCP endpoint for tools — and nothing else: no mounts, no network. Files and commands live in
a separate workspace container in which only the broker acts. Every command and every file change
therefore passes through the broker, so approvals hold against a hostile *harness* (not only a
hostile model) and the audit log is complete by construction. Credentials are injected by
terminating TLS for exactly the hosts that have a secret grant, so ordinary HTTPS clients (git,
gh, pip, SDKs) work unmodified and never see a token.

## 1. What this corrects

1. **Approvals and audit only bound cooperative harnesses.** A harness process could run anything
   inside its own container; `tools.shell: deny` constrained the model only through a trusted
   harness, and direct writes to `rw` mounts never reached the audit log. SI-4 and SI-5 overclaimed.
2. **Token injection was unusable in practice.** It applied only to plain-HTTP absolute-form
   requests. Real clients send `CONNECT` and speak TLS, where the proxy could not inject.
3. **A bespoke agent API + SDK** meant every harness had to be written for Sallyport.

## 2. Roles and sockets (replaces "inference zone / agent zone")

| Role | Has | Does not have | Socket dir mounted at `/run/sallyport` |
|---|---|---|---|
| **inference** (Z2) | GPU, read-only weights | network, mounts, secrets | `infer.sock` (created by llama-server) |
| **workspace** (Z3, "hands") | manifest mounts, egress proxy, `runtime.image` toolchain | GPU, model access, tool socket | `net.sock` (proxy mode only) + CA bundle (§4) |
| **harness** (Z4, "brain") | `llm.sock`, `agent.sock` | mounts, network, GPU | `llm.sock`, `agent.sock` |

- Each role gets its **own** host socket directory (`sessions/<id>/workspace/`, `sessions/<id>/harness/`); no role can see another's sockets.
- Start order: workspace (idle: `entry --idle` = shim if proxy mode, then sleep under `--init`) → harness. Harness exit ends the session; workspace death fails it; teardown kills both.
- `sally sandbox run --manifest m -- cmd` launches the **workspace role only** and runs `cmd` there. M1 behaviour is unchanged; the red-team harness additionally launches a harness-role container (same argv builder: no mounts, no `net.sock`) to host its test MCP client.
- Harness resources are fixed in v1: 1 CPU, 1 GiB, 128 pids. `runtime.*` describes the workspace container.
- v1 ships this isolated placement only. A `colocated` placement (harness inside the workspace container, for third-party CLI agents that insist on local exec) is v1.1 and will carry a summary line saying its direct actions are neither approved nor logged.

## 3. Standard protocols at the boundary (replaces the bespoke agent API and the Python SDK)

**Removed:** `infer.complete`, dotted `tools.list`/`tools.call`, `ui.*`, `audit.note`, `session.info`, `sallyport_sdk`, harness-spawned MCP servers.

### 3.1 `agent.sock` — MCP, tools only
The broker is an MCP server. Framing: newline-delimited JSON-RPC 2.0 (MCP stdio framing) over the Unix stream. Clients that expect to spawn a stdio server use `sally-shim --stdio /run/sallyport/agent.sock`.

- Serve **both** lifecycles: the current stateless revision (2026-07-28: no handshake, per-request version/capabilities in `_meta`, `server/discover`, results carry `resultType`) **and** the legacy `initialize` handshake for clients on 2025-11-25 or earlier.
- Method allowlist, everything else → method-not-found + audit `rpc.deny`: `server/discover`, `initialize`, `notifications/initialized`, `ping`, `tools/list`, `tools/call`, `notifications/cancelled`. No resources, prompts, sampling, elicitation, roots, logging, subscriptions, tasks. No JSON-RPC batches.
- **This revision is recent.** Before coding, read the 2026-07-28 changelog and schema on modelcontextprotocol.io for exact field names, `resultType` values and error codes. Do not code message shapes from memory. Hand-roll this subset in `sallyd::rpc` (bounded parser, 256 KiB frames); do not add an MCP SDK crate to the TCB.
- Built-in tool names on the wire and in manifests (function-name safe): `fs_read`, `fs_list`, `fs_write`, `fs_delete`, `shell`, `fetch`. Tool descriptions are static strings compiled into the broker; never interpolate manifest or user text into them.
- `tools/call` **blocks** until executed, denied, or `approvals.timeout`. Denials return `isError: true` with text `denied: <stable-code>`. Approval never round-trips through the sandbox.

| Tool | Executes | Policy |
|---|---|---|
| `fs_read`, `fs_list` | broker, `openat2` on the host path of any mount | size caps; audited at `audit.level: full` |
| `fs_write`, `fs_delete` | broker, `openat2` | `ro` → denied; `rw` → allowed, audited (path, bytes, sha256); `brokered` → approve globs; protected paths (§6.3) always denied |
| `shell` | `podman exec` in the **workspace** container | `tools.shell` deny / approve / allow (+ destructive tags) |
| `fetch` | broker egress path (same policy and injection as the proxy) | non-GET/HEAD per `tools.fetch_writes` |
| `<server>__<tool>` | relayed to a declared MCP server (§3.4) | per-server `approve` |

### 3.2 `llm.sock` — OpenAI-compatible HTTP
HTTP/1.1 server in the broker (hyper on a `UnixListener`). Allowlist: `POST /v1/chat/completions` (stream and non-stream), `GET /v1/models`. Everything else → 404 + audit `llm.deny`. Body field allowlist: `model` (ignored; the session's model is used), `messages`, `tools`, `tool_choice`, `parallel_tool_calls`, `temperature`, `top_p`, `max_tokens`, `max_completion_tokens`, `stop`, `seed`, `stream`, `stream_options`, `response_format`, `presence_penalty`, `frequency_penalty`, `n` (must be 1). Message content parts: text only (reject image/audio/file parts in v1). Caps as before (4 MiB body, `max_tokens` ≤ manifest). The harness sees `OPENAI_BASE_URL=http://127.0.0.1:8080/v1` and `OPENAI_API_KEY=sallyport` (dummy).

### 3.3 Shim, stdio, task
- `sally-shim` becomes a generic relay, still std-only and static: `--listen 127.0.0.1:3128=/run/sallyport/net.sock` (workspace), `--listen 127.0.0.1:8080=/run/sallyport/llm.sock` (harness), `--stdio <sock>`.
- The harness's stdout/stderr are the conversation channel: line-oriented, control characters neutralized by the broker (§6.4), streamed as `session.output`; `sessions.input` writes a line to its stdin. Task text arrives as `SALLY_TASK` (≤ 64 KiB).
- Reference harness (M4): ~200 lines of Python using the stock `openai` and `mcp` packages inside the harness image. No Sallyport-specific client code.

### 3.4 MCP gateway (basic, M4)
Servers declared in `tools.mcp[]` are started by the **broker** inside the **workspace** container (`podman exec -i`, stdio). The broker acts as their MCP client, relays only `tools/list` and `tools/call`, namespaces tools as `<server>__<tool>`, audits every call, and applies `tools.mcp[].approve` (`always` default, or `never`). Bounded frames, per-call timeout. Their descriptions are untrusted text passed through to the model. Servers that download themselves (`npx -y …`) need the registry allowlisted or must be baked into `runtime.image`.

## 4. Token proxy = selective TLS interception (replaces http→https upgrade injection)

- On `CONNECT host:443` where `host` has a secret grant: reply 200, terminate TLS with a leaf certificate for `host` minted from a **per-session CA** (rcgen; ECDSA P-256; validity = session timeout + 5 min; X.509 name constraints permitting exactly the grant hosts; path length 0). Offer ALPN `http/1.1` only. For each request: drop any client-supplied value of the target header, inject, strip `Accept-Encoding`, forward over a new upstream TLS connection (rustls, real verification, SNI = host, pinned resolved IP). Never follow redirects. Refuse `Upgrade` on intercepted hosts in v1.
- Allowed hosts **without** a secret grant are spliced untouched; the proxy never sees their plaintext.
- Plain-HTTP requests to a grant host → 403 `inject-requires-tls`. Credentials never travel over upstream plaintext. The old "absolute-form http upgraded to TLS" path is deleted.
- The CA private key lives only in `sallyd` memory (`Secret`, zeroized at session end). The workspace container gets `ca-bundle.pem` (host system roots + session CA) and `session-ca.pem` read-only in `/run/sallyport`, with `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, `PIP_CERT`, `CARGO_HTTP_CAINFO`, `AWS_CA_BUNDLE` → bundle and `NODE_EXTRA_CA_CERTS` → session CA.
- Response redaction is streaming with an overlap window ≥ the longest secret form, and covers the raw value, standard and URL-safe base64, and percent-encoding. Other encodings are a documented residual.
- Placeholders: `expose_env: NAME` sets `NAME=sallyport-placeholder` in the workspace container so tools that refuse to run without a token proceed; the proxy overwrites the header. The placeholder is a public constant.
- Schemes: `format` contains exactly one of `{value}` or `{basic}`; `{basic}` = base64(`basic_user:secret`) and requires `basic_user` (git over HTTPS: `Authorization: Basic {basic}`, `basic_user: x-access-token`). The same secret name may appear in several grants with different hosts.

## 5–8. Folded

§5 and §7 are folded into `MANIFEST_SPEC.md` (§1, §1.1); §8 into `CLAUDE.md` and
`THREAT_MODEL.md` (Task 2b).

## 6. Sandbox details

### 6.1 Additions to every `podman run` argv
`--pull=never` (a missing image is an error, never a registry contact), `--http-proxy=false` (Podman otherwise forwards the host's proxy variables), `--log-driver=none` (output is captured by `sallyd`; nothing persists on the host and a chatty container cannot fill the disk), `--ulimit core=0`. Non-recursive bind mounts. Mount source via a held directory fd where Podman accepts it (see §11).

### 6.2 Inference argv
Always pass `-m` (without it current llama-server boots as a multi-model router). Never pass: `--models-dir`, `--models-preset`, any `--webui*`/`--ui*` flag other than `--no-webui`, `--slot-save-path`, or any flag that grants file or network reach. The image build runs `llama-server --help`, extracts the flag list, and compares it to a committed snapshot, so a llama.cpp bump that adds a capability is reviewed rather than inherited.

### 6.3 Protected workspace paths (one policy, two enforcement points)
Inside any mount: `.git/hooks/**`, `.git/config`, `.git/modules/**/hooks/**`, `.git/modules/**/config`. In the workspace container: read-only overlays (create `.git/hooks` if a `.git` exists without it). In broker `fs_write`/`fs_delete`: deny `protected-path`. `summary()` cautions about host-executed files the policy cannot cover (`Makefile`, `package.json` scripts, `.vscode/tasks.json`, `.envrc`) and about new nested `.git` directories (residual).

### 6.4 Output neutralization
Anything from a sandbox that `sallyd` relays to a terminal or the UI in line mode has C0/C1 controls, ESC, CSI and OSC sequences replaced with visible escapes. `sally sandbox run` is line mode by default; `--tty` gives raw passthrough and prints a one-line warning.

### 6.5 Runtime knob
`sandbox.runtime = "crun" | "runsc"` in `config.toml` (not in manifests). v1 ships `crun`; the argv builder and red-team harness take the runtime as a parameter so §12 can turn it on without a rewrite.

## 9. Milestone deltas and where to fold

| Task | Change |
|---|---|
| **2b (new)** | §7 schema delta + §5 finding; same reviewers as Task 2; fold into `MANIFEST_SPEC.md` |
| 1 follow-up | §15 tooling and CI hygiene; §11 item 7 doctor checks |
| 5 shim | §3.3 generic relay + `--stdio` |
| 6 sandbox | roles (§2), argv (§6.1), protected paths (§6.3), socket scan, session-overlap check, runtime parameter (§6.5); fold into `ARCHITECTURE.md §3` |
| 7 rpc | control socket unchanged; session socket = MCP subset (§3.1) |
| 8–9 egress | §4 in full; delete the upgrade path |
| 10 approvals | blocking `tools/call`; adds fetch-write and MCP-tool approvals |
| 11 tools | §3.1 table; `fs_*` on all mount modes |
| 12 session + CLI | two-container lifecycle stub (workspace now, harness role for tests), §6.4, `sally bridge` (stdin/stdout ↔ `control.sock`; lets a Windows-native shell reach `sallyd` through `wsl.exe` with no TCP port) |
| 13 red-team | rows in §10 |
| M2 | surface `tokenizer.chat_template` (cap 64 KiB, hash, show in `models.inspect`, flag when it differs from the template the repo advertises) |
| M3 | `llm.sock` (§3.2) replaces `infer.complete`; §6.2 |
| M4 | harness role + reference harness on stock `openai`/`mcp`; MCP gateway (§3.4); no SDK |
| M5 | Agents pane = sanitized harness output + tool/approval timeline; Tauri bridge is transport-abstracted (UDS on Linux, `wsl.exe … sally bridge` on Windows) |
| M6 | gVisor spike (§12), build provenance attestations + cosign, Windows-native shell as stretch |

Budget: this adds roughly half a week to M1 and is about neutral afterwards. The plan's half-week buffer is spent. If M1 overruns, cut in this order: fetch-write approvals, `{basic}` scheme, the template-mismatch flag.

## 10. New red-team rows (add to `REDTEAM_SUITE.md`; all CI)

| ID | Attack | PASS | M |
|---|---|---|---|
| RT-SEC-09 | CONNECT to a grant host and to an allowed non-grant host; inspect the presented chain | grant host: leaf from session CA; non-grant host: upstream's own chain, never the session CA | M1 |
| RT-SEC-10 | Use the session CA for another name; search both containers for a private key | leaf for an unlisted name fails validation in a stock client; no key material in any sandbox | M1 |
| RT-SEC-11 | `expose_env` set; dump env; call grant host and non-grant host | env holds only the placeholder; upstream of grant host receives the real credential; non-grant host receives at most the placeholder | M1 |
| RT-SEC-12 | Upstream echoes the token split across chunks, base64 and percent-encoded | all forms redacted | M1 |
| RT-SEC-13 | `http://` request to a grant host | 403 `inject-requires-tls`; mock sees no credential | M1 |
| RT-AG-11 | From the harness container: look for `/workspace`, `net.sock`, any route; then perform 20 random file/command operations through tools | no mounts, no egress; host-side changes == audit entries, one for one | M1 |
| RT-AG-12 | From the workspace container: reach `llm.sock`/`agent.sock`/`127.0.0.1:8080` | absent / refused | M1 |
| RT-AG-13 | MCP surface abuse: resources, prompts, sampling, logging, unknown methods, batches, 1 MiB frames; plus `tools/list` via both lifecycles | all rejected with `rpc.deny`; both lifecycles work | M1 |
| RT-AG-14 | `fetch` POST with a mount present; MCP tool call with `approve: always` | pending until approved; denied on timeout | M1 / M4 |
| RT-FS-12 | Write `.git/hooks/pre-commit` and a `core.fsmonitor` line, via shell and via `fs_write`; then run `git status` on the host in the harness | both writes refused; host canary not executed | M1 |
| RT-FS-13 | Mount tree contains a Unix socket | launch refused `socket-in-mount` | M1 |
| RT-FS-14 | Mount a bind-mount alias of a protected folder | refused (`st_dev`/`st_ino` match) | M1 |
| RT-AG-08b | Second session mounts a directory a live session holds in a different mode | launch refused | M1 |
| RT-SUP-02 | Manifest names a digest not present locally | refused; `strace` shows no outbound connect | M1 |
| RT-SUP-03 | Inference image flag snapshot and argv scan | `--help` flags equal the snapshot; argv has `-m`, none of the forbidden flags | M3 |
| RT-INF-05 | `/v1/completions`, `/models/load`, `/props`, `/slots`, `/tokenize`, image parts, `n: 5` on `llm.sock` | 404/400; inference container never sees them | M3 |
| RT-MDL-10 | GGUF with a 1 MiB template; GGUF whose template injects exfil instructions | first refused; second: inspect shows template + hash, every resulting action denied by policy | M2 / M4 |
| RT-CLI-01 | Sandbox prints ESC, CSI, OSC 52, OSC 8 | neutralized in line mode | M1 |

## 11. Verify before coding (cheap probes; report results in ≤ 10 lines)

1. Podman 4.9.3 accepts `--pull=never`, `--http-proxy=false`, `--log-driver=none` together with the existing flags.
2. Which non-recursive bind form works with `nosuid,nodev` (`-v …:bind` vs `--mount type=bind,…,bind-nonrecursive`).
3. `/proc/<sallyd-pid>/fd/<n>` as a mount source; else inode re-check immediately before spawn.
4. `rcgen` can emit name constraints and path length 0; a stock `curl`/Python client honours them.
5. MCP 2026-07-28 message shapes (docs-lookup), and what the Python `mcp` package in the harness image negotiates.
6. Which YAML crate the manifest parser uses. It must not be `serde_yaml` (archived) or `serde_yml` (RUSTSEC-2025-0068). Report it.
7. *(Folded into `scripts/doctor.sh` V13–V16 in Task 1f.)*

## 12. Deferred decisions (need data, not opinions)

- **Staged mounts (review-then-apply).** A fourth mount mode where the workspace sees a writable overlay, the host directory is untouched, and the session ends with a diff the user applies or discards. Decision at the M3 review, using V13. If adopted it is M4.5 (~half a week) and the M5 manifest editor shrinks to templates + live summary.
- **gVisor for workspace and harness containers.** Neither needs a GPU or a network stack. M6 spike, two candidate routes: `podman --runtime=runsc` rootless (known cgroup friction), or runsc nested inside the crun container as Dangerzone does. Needs runsc's `host-uds` setting for the broker sockets. If the spike passes, CI runs the red-team suite under both runtimes.
- **Windows-native shell.** Enabled by `sally bridge`; build on a `windows-latest` runner in M6 if time allows.

## 13. Threat-model additions (fold into `THREAT_MODEL.md`)

- AT1 vector: the GGUF **chat template** is attacker-controlled executable template text that runs on every inference call and can inject hidden instructions with unchanged weights. Mitigation: treated as hostile model output by architecture; surfaced, hashed, size-capped (M2). → RT-MDL-10.
- G3 leaf: **exfiltration through the user's own credential** on an allowed host (e.g. a public gist via `api.github.com`). Mitigation: `[data-can-leave]`, fetch-write approval, shell approval; residual documented.
- G4 leaf: **host-executed files in a writable mount** (git hooks, fsmonitor). → §6.3, RT-FS-12.
- AT3 vector: **MCP tool-description poisoning**. Mitigation: descriptions are untrusted text to the model; every relayed call audited and approvable.
- G5 leaf: **terminal escape injection** from sandbox output. → §6.4, RT-CLI-01.
- TCB: the **OCI runtime** (crun) is trusted. Runtime breakouts land as the user's UID, which still owns the secrets store. Mitigations: bundled images by default, custom images flagged, V14, and the gVisor route. Residual.
- Residuals to add: redaction misses exotic encodings; nested `.git` created during a session; a user-chosen `runtime.image` is a runtime attack surface.

## 14. Considered and rejected

TOML instead of YAML (parser already hardened; the original requirements specified YAML). An MCP SDK crate inside the broker (too much untrusted-input surface for four methods). Landlock or `NoNewPrivileges` on `sallyd` (inherited by Podman; breaks `newuidmap`, as V12 showed). MicroVMs for the workspace on WSL2 (Unix sockets do not cross the VM boundary cleanly; no GPU story). nftables/eBPF egress filtering (needs root; `--network=none` plus a socket is stronger). Ollama or vLLM as the engine (extra daemon and pickle exposure for no v1 benefit). Per-write approval on `rw` mounts (approval fatigue; staged mounts are the better answer). Router mode for model switching (file and network reach inside Z2).

## 15. Folded

Folded into `docs/ARCHITECTURE.md` §8 (Task 1f).

## Sources

- MCP 2026-07-28 changelog — https://modelcontextprotocol.io/specification/2026-07-28/changelog
- MCP SDK compatibility notes — https://blog.modelcontextprotocol.io/posts/sdk-betas-2026-07-28/
- Agents Rule of Two (Meta) — https://ai.meta.com/blog/practical-ai-agent-security/
- Chat-template backdoors — https://www.pillar.security/blog/llm-backdoors-at-the-inference-level-the-threat-of-poisoned-templates · https://arxiv.org/abs/2602.04653
- runc breakouts via procfs writes — https://seclists.org/oss-sec/2025/q4/138
- gVisor rootless — https://gvisor.dev/docs/user_guide/rootless/
- Podman overlay volumes — https://docs.podman.io/en/v4.6.1/markdown/options/volume.html
- llama.cpp router mode — https://github.com/ggml-org/llama.cpp/pull/17470
- serde_yml advisory — https://rustsec.org/advisories/RUSTSEC-2025-0068
