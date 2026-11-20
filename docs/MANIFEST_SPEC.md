# Permission Manifest Specification (v1)

A manifest is the *entire* statement of what a session may do. If it isn't granted here, it
doesn't happen. Manifests are YAML, parsed into Rust types with `#[serde(deny_unknown_fields)]`;
a JSON Schema is generated from those types (`schemars`) for the UI editor. The UI also renders a
plain-English summary ("This agent can read and write `~/code/myproject`, reach `api.github.com`
and `*.pypi.org` on 443, run shell commands **with your approval**, and use your GitHub token
only toward `api.github.com`.") — that summary is generated from the same parsed struct, never
from the YAML text, so it cannot drift. It never claims less than the manifest grants, and every
setting that widens the blast radius is named in it in plain words (SI-5). When private data and
an outward channel coexist, it opens with the `[data-can-leave]` finding (§1.1).

A session has three containers (AMENDMENTS-01 §2): **inference** (GPU, weights), **workspace**
(the mounts, the egress socket and the `runtime.image` toolchain; only the broker acts in it) and
**harness** (the model-steered code; it has only the model socket and the MCP tool socket — no
mounts, no network). `runtime` describes the workspace; `harness` picks the harness image.

## 1. Schema

```yaml
apiVersion: sallyport/v1          # required, exact
kind: Manifest                    # required, exact
name: <slug>                      # required, [a-z0-9-]{1,64}
description: <string>             # optional, ≤ 512 chars

harness:                          # optional
  image: <ref@sha256:…>           # MUST be digest-pinned; default = bundled reference harness
                                  # (harness resources are fixed in v1: 1 CPU, 1 GiB, 128 pids)

runtime:                          # optional; the WORKSPACE container; defaults shown
  image: <ref@sha256:…>           # workspace toolchain image; MUST be digest-pinned; default = bundled
  cpus: 4                         # 0.5–nproc
  memory: 8GiB                    # ≤ 75% of host RAM
  pids: 512                       # 16–4096
  timeout: 2h                     # session wall clock; 1m–24h
  tmp_size: 1GiB
  tmp_exec: false                 # mount /tmp noexec unless true
  stage_size: 10GiB               # limit on staged + .git overlay writes together; exceeded = session killed

model:
  ref: library://<name-or-sha256> | any   # required; `any` lets the user pick at launch
  context: 8192                   # tokens; capped by model metadata and VRAM estimate
  gpu_layers: auto                # auto | integer

filesystem:
  mounts: []                      # list of Mount (below); default none
  deny: []                        # extra host paths to refuse (built-in denylist always applies)

network:
  mode: none                      # none | proxy
  allow: []                       # list of HostRule (below); only meaningful with mode: proxy
  acknowledge_unrestricted_egress: false   # must be true if any rule has host: "*"
  max_request_bytes: 8MiB
  max_response_bytes: 64MiB
  max_connections: 32

secrets: []                       # list of SecretGrant (below)

tools:
  builtin: []                     # subset of [fs_read, fs_list, fs_write, fs_delete, shell, fetch]
  shell: deny                     # deny | approve | allow
  destructive_requires_approval: true   # applies when shell: allow
  fetch_writes: approve           # approve | allow — fetch methods other than GET/HEAD
  acknowledge_unapproved: []      # shell | fetch | "mcp:<name>": each required exactly when its risk is live (§1.1)
  mcp: []                         # list of McpServer (below)

approvals:
  timeout: 5m                     # 30s–1h; expiry = deny
  max_pending: 5                  # beyond this: auto-deny + flood event

audit:
  level: full                     # full | actions — detail, never coverage (SI-4); see below

policy:                           # reserved for v2 signed org policies; parsed and ignored in v1
  signed_by: null
  signature: null
```

### Parsing rules
- At most 256 KiB, UTF-8, exactly one YAML document.
- No anchors, aliases, merge keys (`<<`), custom tags, or duplicate keys: each is a `syntax` error.
  `!!binary` never decodes into a string: the literal text is what gets validated.
- YAML 1.2 booleans only (`true`/`false`; `yes`/`on` are errors). A string field given an unquoted
  number or boolean is an error (quote it). Known gap: numeric fields still accept quoted or
  hex/octal spellings (`ports: ["443", 0x1BB]`); the value is unambiguous, so this is
  documented rather than rejected.
- `runtime.cpus` is a number with at most three decimals; NaN/infinity are parse errors.
- Sizes are `<n>B|KiB|MiB|GiB|TiB` (decimal `GB` is an error); durations are `<n>s|m|h`.

`audit.level: actions` drops one kind of entry, inference response metadata (`llm.response`),
which `full` adds. Every other entry is kept at both levels: one per tool call (`fs_read`
included), egress connection (`egress.allow` with host:port and the pinned addresses,
`egress.deny`/`egress.limit` with the reason, `egress.shed` for over-rate connections closed
unread, `egress.close` with the address used and the byte counts, and per intercepted request
`egress.request` (method + path, never bodies) and response `egress.response` with the secrets
redacted and the bytes, names only; ARCHITECTURE §7 "Egress audit events"), approval, launch,
and model import. The audit writer refuses the detail mark on any other event.

### 1.1 Approval gates, acknowledgements, and `[data-can-leave]` (SI-5)

Omission never disables a gate; widening needs an explicit setting that `summary()` names.

| Setting | Effect | Needs |
|---|---|---|
| brokered `approve.writes` / `approve.deletes` omitted | `["**"]`: every write/delete needs approval | — |
| `approve.deletes: []` (or `writes: []`) | that operation runs unapproved; `risky` warning; summary says "deletes without asking you" | — |
| `shell: allow` + (`destructive_requires_approval: false` or `[data-can-leave]`) | commands run unapproved (all of them, or all but destructive ones while private data can reach an allowed host) | `shell` in `tools.acknowledge_unapproved`, else `unacknowledged-risk` |
| `fetch_writes: allow` + any mount or secret | `fetch` can send data unapproved | `fetch` in `tools.acknowledge_unapproved`, else `unacknowledged-risk` |
| `tools.mcp[].approve: never` + any mount or secret | that server's tools run unapproved while it can reach private data | `"mcp:<name>"` in `tools.acknowledge_unapproved`, else `unacknowledged-risk` |
| `tools.mcp[].approve: never`, no mount and no secret | that server's tools run unapproved | — (named in summary) |
| `host: "*"` or a shared-hosting wildcard | unrestricted egress | `network.acknowledge_unrestricted_egress: true` |

`tools.acknowledge_unapproved` (AMENDMENTS-02 B3) is one list for every unapproved channel. An
entry that is not needed is an `inconsistent` **error**, so a stale acknowledgement cannot linger;
an unknown entry (anything but `shell`, `fetch` or `mcp:<name of a declared server>`) is
`invalid-value`, a repeated one `duplicate`. `network.acknowledge_unrestricted_egress` set but not
needed stays an `inconsistent` warning. `ValidatedManifest::acknowledged_risks()` lists what is in
effect (`network.acknowledge_unrestricted_egress`, `tools.acknowledge_unapproved: <entry>`); the
UI shows a red banner. Before `sandbox.launch`, a launch records one `manifest.acknowledged_risk`
audit event per entry (`risk`, decision `allow`) and, when the validation gave any warning, one
`manifest.warn` (`count`, and the first 32 warnings as `code` and field `path`; never a message).

**`[data-can-leave]`** (AMENDMENTS-01 §5, Agents Rule of Two). The model and everything it reads
are untrusted input. When a manifest has **private data** (any mount or secret) and an **outward
channel** (`network.mode: proxy` with any allow rule), the validator emits a `data-can-leave`
warning (path `network.allow`) and `summary()` opens with it, e.g.:

```
[data-can-leave] Anything this agent reads (/home/u/code/p and whatever your "GITHUB_TOKEN" unlocks on api.github.com or github.com) can be sent to pypi.org, api.github.com (acting as you) and github.com (acting as you).
```

Hosts with a secret grant are marked "acting as you". When `fetch` is granted the finding ends
with "The fetch tool's GET requests are not prompted and can carry data out in the URL.": GET and
HEAD never prompt, whatever `tools.fetch_writes` says. There is no acknowledge flag: this is the
normal shape of a useful agent, so the point is that the user sees it every time. On a rejected
manifest, a grant whose secret name or `inject.host` failed its own check appears as "whatever
the secret at secrets[i] unlocks": neither value is echoed outside its own error.

### 1.2 Launching from a manifest file (the CLI's gate, RT-MAN-03)

`sally session start` and `sally sandbox run` read the manifest file once and send that text; at
launch, the CLI's own validation is a refusing gate (for `sally manifest validate` and `summary`
it only reports). In order:

- **Place.** A manifest kept inside a folder the same manifest mounts `rw` or `brokered` is
  refused (exit 1, nothing sent): the session could rewrite the next session's grants. Two
  folders are checked, the one holding the name as given (a link there can be pointed elsewhere)
  and the one holding the file it resolves to; each is refused when its realpath is, or lies
  under, such a mount's root, or when its chain of directory identities holds that root's
  identity. `staged` and `ro` mounts never refuse. Only this manifest's own mounts are read
  (#262). Not covered (#254): a link chain that passes through a writable folder at an
  intermediate hop, a hard link of the file into a writable folder, and a bind of a
  subdirectory; the file is then read by its path, with no regular-file check and no identity
  compare against what was inspected.
- **What is shown.** Before anything is sent, the launch shows the summary, each warning and each
  acknowledged risk, on the terminal the answer is read from when a question follows and on
  stderr otherwise. A line that fails the CLI's clean-check refuses the launch (exit 1).
- **Consent.** A manifest with any warning or acknowledged risk needs it. On a terminal (stdin is
  one and `/dev/tty` opens) it is `yes` typed after the question, with typed-ahead input
  discarded; `--accept-manifest` does not replace it there. Off a terminal it is
  `--accept-manifest <sha256>`, the SHA-256 of the exact text read: a malformed value fails
  (exit 2) before anything is read, a hash of other text refuses (exit 1), and no launch output
  prints the hash of what was read. With the hash alone as consent, every mount host must be
  written as the folder it resolves to (exit 1 otherwise): the hash names the text, not the
  folders. `~` expands against `HOME` as given, so where `HOME`'s own path goes through a link,
  a `~` host cannot launch by hash alone (#255). A given `--accept-manifest` is checked for
  every manifest, with or without warnings. Not covered (#262): a manifest with no warning and
  no acknowledged risk is sent with no question, so one kept in a folder another manifest mounts
  `rw` or `brokered` can be changed by that other session and launched unasked unless the flag
  is given. Keep a manifest outside every folder any manifest mounts `rw` or `brokered`.

`sally manifest summary` ends with the line `sha256 <hex>`, the hash a launch's
`--accept-manifest` names. Its stderr carries the warnings and acknowledged risks a launch shows,
and any mount host not written as its folder. A manifest whose launch block holds a line that
cannot be shown prints no hash and exits 1.

Not covered (#255): what is shown, and what a typed `yes` or a hash accepts, comes from the CLI's
own validation under its own host facts. `sallyd` validates the text it is sent again under its
own and resolves the mount hosts again after the CLI's check, so a folder replaced at the same
path after that check, or a `HOME` that differs between the CLI and `sallyd`, is not seen by the
consent.

### Ranges and formats (checked by the validator)
| Field | Rule |
|---|---|
| `runtime.cpus` | finite, 0.5 – host CPUs |
| `runtime.memory` | 64MiB – 75% of host RAM |
| `runtime.tmp_size` | 1MiB – `runtime.memory` (tmpfs pages are charged to the memory cgroup) |
| `runtime.stage_size` | 1MiB – 1TiB |
| `runtime.image`, `harness.image` | `<lowercase name>@sha256:<64 lowercase hex>` |
| `model.ref` | `any` or `library://[a-z0-9._-]{1,128}` |
| `model.context` / `gpu_layers` | 1 – 2²⁰ / 0 – 1024 |
| `network.max_request_bytes` / `max_response_bytes` / `max_connections` | 1KiB–1GiB / 1KiB–16GiB / 1–1024 |
| `approvals.max_pending` | 1 – 64 |
| list lengths | mounts ≤ 64, allow rules ≤ 256, MCP servers ≤ 32 |
| `secrets[].name` | `[A-Z][A-Z0-9_]{0,63}`; may repeat with different hosts; (name, host) unique |
| `secrets[].expose_env` | token-style env name (below); one secret per name |
| `secrets[].inject.basic_user` | 1–256 bytes, no `:` or control characters; only with `{basic}` |
| `tools.mcp[].name` | `[a-z0-9-]{1,64}`, unique; `tools.builtin` entries unique |

### Mount
```yaml
- host: ~/code/myproject          # absolute or ~-prefixed; resolved with realpath; MUST be a directory
  guest: /workspace/myproject     # /workspace/<seg>[/<seg>…], seg = [A-Za-z0-9._-], no `.`/`..`
  mode: staged                    # ro | rw | brokered | staged   (required)
  approve:                        # only for mode: brokered (ignored otherwise)
    writes: ["**"]                # globs (relative to mount) whose writes need approval; omitted = ["**"]
    deletes: ["**"]               # globs whose deletes need approval; omitted = ["**"]
```
Mounts exist only in the workspace container. The harness reaches them only through broker
tools: `fs_read`/`fs_list` on any mode, `fs_write`/`fs_delete` on `rw`, `staged` and `brokered`
(denied on `ro`), and `shell` (`podman exec` in the workspace). Writes and deletes on `rw` and
`staged` run in the workspace's own view of the mount, so the overlay and the `.git` shields
apply; on `brokered` the broker performs them on the host folder after approval (maintainer's
Task 11 decision 1; ARCHITECTURE §4.3). Every such action is audited (SI-4).

- `ro`: bind mount read-only.
- `rw`: bind mount read-write (`nosuid,nodev`). **This is the blast radius.** Writes are audited
  (path, bytes, sha256) but not individually approved — shell commands can be. `summary()` opens
  with (or, after `[data-can-leave]`, continues with) a `[direct-write]` line that names the
  folders and suggests `staged`.
- `staged` (AMENDMENTS-02 B2(b)): an overlay whose lower layer is the host directory; every write
  lands in a kept upper directory under `~/.local/share/sallyport/sessions/<id>/stage/<n>/`, and
  the host directory is untouched. `sally session changes <id>` lists changed and deleted paths;
  M1 only lists (nothing is applied, nothing is deleted: the kept upper directories stay), and
  applying and discarding arrive in M4.5. Podman accepts no other option next to `O`
  (probed on 4.9.3), so an overlay is not `nosuid,nodev`; `no-new-privileges`, `--cap-drop=ALL`
  and the seccomp profile (no `mknod`) keep set-id files and device nodes inert there. Editing the
  host folder while a staged session runs gives undefined results inside the sandbox; conflicts
  are caught at apply. On Podman 4.9.3 a `staged` folder with another filesystem mounted inside
  it cannot launch (the runtime refuses the overlay in the keep-id namespace; ARCHITECTURE §3.5).
- `brokered`: bind mount **read-only**; `fs_write`/`fs_delete` are performed by the broker on the
  host under `openat2` confinement and apply the `approve` globs. Use for "the agent may propose
  edits to my notes". Omitted globs mean `["**"]`; an explicit empty list is a `risky` warning
  when the matching tool is enabled. Glob syntax below.

In every mode the file tools act with the sandbox's permissions, not the broker's: the workspace
runs as the user's `uid:gid` without supplementary groups, so a file or folder reachable only
through such a group is refused `permission`, even for a brokered write the user would approve;
an object carrying a POSIX ACL is open to its owner only (architect ruling Q39; ARCHITECTURE §4.3).
- **Glob syntax** (`approve.writes`/`approve.deletes`; architect ruling Q20, Task 10). A glob is
  matched segment by segment against the target's canonical path relative to the mount: `**` as
  a whole segment matches zero or more segments (`notes/**` covers `notes` and everything under
  it); `*` matches any run of characters inside one segment, dotfiles included; `?` matches one
  character; every other character is literal, and case matters. Any match means the operation
  asks. The validator refuses (`invalid-value`) anything that would silently match less than it
  seems to: an absolute glob, `..`, `.` or empty segments, a trailing `/` (write `dir/**`),
  `[ ] { } \`, a leading `!`, `**` inside a longer segment (`**.md`: write `**/*.md`), control
  characters, and more than 256 bytes. The broker denies (`bad-path`) a write or delete whose
  relative path is not canonical, before any glob is tried. Residual: on a
  case-folding or normalizing file system a narrowed glob can match less than the file system
  resolves; the default `["**"]` cannot.
- **Git metadata** (AMENDMENTS-02 B2(a), replacing the read-only hooks/config overlays of
  AMENDMENTS-01 §6.3). In an `rw` mount, every `.git` directory found by the launch scan is
  mounted as an overlay whose upper directory is session scratch, discarded at teardown, and
  every `.git` file (a worktree or submodule pointer) is bound read-only: git works inside the
  sandbox while the host's `.git` history, config, hooks and `commondir` stay byte-identical.
  Hooks or config a repository takes from its working tree (`core.hooksPath`, `include.path`,
  `.husky/`) are ordinary files in the writable folder and are not protected, nor is a `.git`
  created after the launch scan; `summary()` says so. The same holds for what a link inside
  `.git` points to in the working tree (a `.git/hooks` linked to a tracked folder): the link
  stays byte-identical, its target is writable, and the host runs what the sandbox wrote there.
  Commits made in a session are discarded and file changes arrive as uncommitted modifications;
  `summary()` says so. Every directory between the mount root and a nested `.git` entry is bound
  onto itself, so it cannot be renamed away from under its shield (`EBUSY`); the launch scan
  covers every `rw` mount (an `rw` mount without a scan is refused). More than 32 shielded
  entries in one `rw` mount, or a tree beyond the scan's bounds, refuses the launch with advice
  to use `staged`. In a `staged` mount the host is untouched anyway and nothing under a `.git`
  component is ever applied. Broker `fs_write`/`fs_delete` deny any path with a `.git` component,
  compared ASCII case-insensitively, in every mode (`protected-path`, #19). Residual: other
  spellings a file system may fold to `.git` (`.git.` or an 8.3 short name on a foreign file
  system) are not caught. The validator refuses an `rw`/`brokered`/`staged` mount whose realpath has a
  `.git` component or is (inside) a git directory by structure (`HEAD` + `objects/` + `refs/`,
  i.e. bare repos and separate git dirs; `protected-path`). `summary()` names what an `rw` mount
  cannot protect: `Makefile`, `package.json` scripts, `.vscode/tasks.json`, `.envrc`, new
  nested `.git` folders, and git repositories inside the mount that are not named `.git` (a bare
  `project.git`, a separate git dir).
- Mounts may not overlap on the host side (a `rw` parent would bypass a `brokered` child's
  approvals) and guests may not repeat or nest. Host overlap is judged by realpath and by
  directory identity (`st_dev`, `st_ino` of each root and its ancestors), whatever the two modes:
  a bind mount, or a second mount of the same filesystem, that reaches a folder another mount
  holds (the folder, or one containing it) is refused `overlap` like a nested path. A bind of a
  *subdirectory* is not seen (#17): a `rw` mount can then hold part or all of a `brokered` one.
  A folder bound on its own child is followed up to its real parents. A hard-linked file shared
  by a `rw` mount and a `brokered` mount is not an overlap either: a write through the `rw` name
  is not approved (#241). A root whose ancestors cannot all be searched, or whose walk does not
  reach `/` within 4096 steps, cannot be compared, and is refused `not-found`.
- Across live sessions (AMENDMENTS-02 B4), folders may overlap only when neither session mounts
  them `rw` or `brokered`; the launch is refused (`overlap`) otherwise.
- A Unix socket anywhere in a mount refuses the launch (`socket-in-mount`, RT-FS-13). Another
  filesystem mounted inside a mount is not visible in the sandbox (RT-FS-16).
- Host realpaths and guests may not contain `:`, `,` or control characters (they would be
  parsed as `podman -v`/`--mount` option separators).

### HostRule
```yaml
- host: api.github.com            # exact hostname, or "*.example.com" (subdomains only), or "*"
  ports: [443]                    # default [443]; 80 enables plain http upstream
```
Hosts are written canonically (lowercase ASCII/punycode, no trailing dot) or rejected. An exact
host (here and in `secrets[].inject.host`) has at least two labels: `localhost` or `intranet`
is rejected, since the proxy refuses such names and looks every name up absolute. A
wildcard that reaches hosts anyone can register counts as unrestricted and needs
`acknowledge_unrestricted_egress: true` like `"*"`: its base is a listed shared-hosting suffix
(`*.github.io`, `*.workers.dev`, `*.r2.dev`, `*.ngrok-free.app`, …), a parent of a listed entry
(`*.googleapis.com`), or a shared tree or anywhere under one, a provider whose registrable hosts
sit at any depth (`*.amazonaws.com`, `*.windows.net`, `*.s3.us-east-1.amazonaws.com`,
`*.web.core.windows.net`, `*.a.run.app`). The lists are two maintained constants,
`host::SHARED_SUFFIXES` and `host::SHARED_TREES` (curated: most entries come from the Public
Suffix List's private section, `co.uk`, `com.au` and `co.jp` from its registry section, and
`gradio.live`, `glitch.me`, `loca.lt` and `serveo.net` from neither; `host::SHARED_TREES`
states when an entry is a tree, and its exceptions); the
summary marks such a rule "anyone can register these". The lists are
curated, so a wildcard over a shared-hosting suffix they do not name is an ordinary rule
(TODO(#235): derive them from the Public Suffix List). Matching: lowercase, trailing dot
stripped; `*.example.com` matches `a.example.com` and `a.b.example.com` but **not**
`example.com` and **not** `example.com.evil.net`. IP literals in any form are always denied.
`"*"` matches any hostname but still goes through the IP-range filter (no
loopback/private/link-local/host-own) and requires `acknowledge_unrestricted_egress: true`.

### SecretGrant
```yaml
- name: GITHUB_TOKEN              # must exist in the secrets store; values never appear in manifests
  inject:
    host: github.com              # exact hostname; wildcards and "*" are refused
    header: Authorization         # header name
    format: "Basic {basic}"       # exactly one of {value} or {basic}
    basic_user: x-access-token    # required with {basic}: {basic} = base64(basic_user:secret)
  expose_env: GH_TOKEN            # optional: placeholder env var in the workspace
```
Injection happens **only inside TLS the proxy terminates** (`ARCHITECTURE.md §7`): on `CONNECT` to a
grant host the proxy presents a leaf from a per-session, name-constrained CA, injects, and
re-originates TLS to the verified upstream. Allowed hosts without a grant are spliced untouched.
Every plain-HTTP request, to a grant host or any other, is refused 405 `plain-http-unsupported`
before policy (Task 8); credentials never travel over upstream plaintext.

The host must have its own **exact** rule in `network.allow` (a matching `*.github.com` or `*`
rule is not enough), and `network.mode` must be `proxy`. The same secret may be granted to
several hosts (e.g. Bearer for `api.github.com`, Basic for `github.com`), once per host. `header`
is an RFC 9110 token and may not be a proxy-owned header (`Host`, `Content-Length`,
`Transfer-Encoding`, `Connection`, `Keep-Alive`, `TE`, `Trailer`, `Upgrade`, `Expect`, any
`Proxy-*`); `Cookie` is allowed. `format` may not contain control characters (no CR/LF header
splitting). Each (host, header) pair may be injected by only one secret.

`expose_env: NAME` sets `NAME=sallyport-placeholder` (a public constant) in the workspace so tools
that refuse to start without a token proceed; the proxy overwrites the header. The name's last
`_` segment must be `TOKEN`, `KEY`, `APIKEY`, `PAT`, `SECRET` or `PASSWORD`; no segment may be
`FILE`, `PATH`, `DIR`, `CONFIG`, `CREDENTIALS` or `HOME` (a repo could ship a file named after the
placeholder and have it loaded as credentials); it may not start with `NPM_CONFIG_`, `GIT_` or
`SSH_`, and may not be a reserved variable (below). Two different secrets may not expose the same
name. `basic_user` and `format` are refused (without echo) if they contain a known credential
prefix.

### McpServer
```yaml
- name: git
  command: ["mcp-server-git"]
  env: {}                         # literal values only; secret-like names and values refused (below)
  approve: always                 # always (default) | never
```
The **broker** starts declared servers inside the **workspace** container (`podman exec -i`,
stdio), acts as their MCP client, relays only `tools/list`/`tools/call`, namespaces tools as
`<server>__<tool>`, audits every call, and applies `approve` (AMENDMENTS-01 §3.4, M4). Their tool
descriptions are untrusted text passed to the model.

Env names are split on `_` and refused when any segment (case-insensitive) is one of `TOKEN`,
`KEY`, `KEYS`, `KEYFILE`, `APIKEY`, `SECRET`, `SECRETS`, `PASS`, `PASSWD`, `PASSWORD`,
`PASSPHRASE`, `PWD`, `PAT`, `CREDENTIAL`, `CREDENTIALS`, `CREDS`, `AUTH`, `BEARER`, `COOKIE`,
`PRIVATE`, or ends with `TOKEN`/`KEY`/`SECRET`/`PASSWORD` (`ACCESSTOKEN`). A bare `PWD` is the
working directory and is allowed; so are `AUTHOR_NAME` and `KEYBOARD_LAYOUT`. Values starting
`ghp_`/`github_pat_`/`glpat-`/`sk-`/`xox`/`AKIA`/`ASIA`/`hf_` … are refused and never echoed.

**Reserved variables** (MCP `env` and `expose_env`, case-insensitive) change how the workspace
loads code, finds sockets or verifies TLS, and Sallyport sets the relevant ones itself: prefixes
`SALLY_`, `LD_`, `GIT_CONFIG`; anything containing `PROXY`, `CA_BUNDLE`, `CAINFO`, `CERT` or
`SOCK`; and `NODE_OPTIONS`, `BASH_ENV`, `ENV`, `PYTHONSTARTUP`, `PYTHONPATH`,
`NODE_TLS_REJECT_UNAUTHORIZED`, `PYTHONHTTPSVERIFY`, `GIT_SSL_NO_VERIFY`, `CURL_HOME`
(`invalid-value`).

A server's `command` runs at launch, without approval, inside the workspace (its mounts and
egress); only its tool calls are gated by `approve`. `summary()` therefore shows the command (up to
200 characters) and its env keys.

## 2. Built-in mount denylist (not overridable)

Resolved via `realpath` on both the rule and the candidate (rules are also matched in their
lexical form, so `/mnt/c` is refused even where it does not exist). `$HOME` comes from the
environment (passwd entry only if `$HOME` is unset or relative).

- **Root only** — the path itself is refused, descendants are fine: `/`, `$HOME`.
- **Subtree** — the path, anything inside it, **and any ancestor of it** are refused:
  - under each home: credentials (`.ssh`, `.gnupg`, `.aws`, `.kube`, `.docker`, `.netrc.d`,
    `.password-store`, `.pki`, `.local/share/keyrings`, `.mozilla`, `.claude`, `.ollama`, `.m2`,
    `.azure`, `.terraform.d`, `.oci`, `.minikube`), config and Sallyport state (`.config`,
    `.local/share/sallyport`, `.var/app`, `snap`), caches (`.cache`, `.npm`), and anything the
    host executes or auto-loads (`.local/bin`, `bin`, `.local/share/applications`, `.local/lib`,
    `.cargo`, `.rustup`, `.vscode-server`, `.gradle`, `.nvm`, `.pyenv`, `.vscode`, `.vim`,
    `.emacs.d`, `.ipython`, `.oh-my-zsh`, `.bun`, `.deno`, `.volta`, `go/bin`, `go/pkg`,
    `.local/share/{pipx,uv,nvim,mise,pnpm}`) — a writable mount there is host code execution
    (THREAT_MODEL G4);
  - `$XDG_CONFIG_HOME`, `$XDG_DATA_HOME`, `$XDG_RUNTIME_DIR` (each when set, plus `sallyport/`);
  - the folders the environment names, each when absolute: `$CARGO_HOME`, `$RUSTUP_HOME`,
    `$GNUPGHOME`, `$NVM_DIR`, `$PYENV_ROOT`, `$XDG_CACHE_HOME`, `$GOBIN`, `$DOCKER_CONFIG`,
    `$ZDOTDIR`, `$PNPM_HOME`, `$VOLTA_HOME`, `$BUN_INSTALL`, `$PYTHONUSERBASE`, `$PIPX_HOME`,
    `$PIPX_BIN_DIR`, `$UV_TOOL_DIR`, `$GRADLE_USER_HOME`, `$PASSWORD_STORE_DIR`, `bin` and
    `pkg` under each `$GOPATH` element (at most 32 folders), and every `$PATH` entry (at most
    256); past either bound the list is incomplete (below). Messages name the variable ("is
    inside /opt/go/bin (from $GOBIN)"). A folder named this way that is `/`, a home, or an
    ancestor of one is kept as a rule, so it refuses every mount under it (§6);
  - `/etc`, `/proc`, `/sys`, `/dev`, `/run`, `/var/run`, `/boot`, `/root`, `/mnt`,
    `/usr/lib/wsl`, `/tmp`, `/var/tmp` (`/tmp` holds other programs' Unix sockets — ssh-agent,
    X11 — and a read-only bind does not stop `connect()`, so it would be a path around SI-1);
  - the Podman storage dirs (rootless graphroot and `/var/lib/containers/storage`) and every
    `filesystem.deny` entry.

  The ancestor rule is why `~/.local`, `/var`, `/usr`, and `/home` are refused: they really
  contain protected data. "Each home" is `$HOME` **and** the passwd home when they differ, so a
  wrapper that sets `HOME=/tmp/x` does not unprotect the real one.

**Links out of protected folders.** A symlink inside a protected folder makes its target part of
what the host runs or loads (`~/.local/bin/t -> ~/tools/t/bin/t`, a stow `~/.config/gh ->
~/dotfiles/gh`), so its target becomes a subtree rule too: "contains /home/u/tools/t/bin/t, which
/home/u/.local/bin/t points to", with the reason of the folder that holds the link. When a
manifest has mounts, validation reads, to depth 2 (a folder's entries and its subfolders'
entries, never entering a linked folder): every home folder of the list above, `$XDG_CONFIG_HOME`
and `$XDG_DATA_HOME`, every folder the environment names except a `$PATH` entry outside the
homes, and each home's own entries, of which only dot names (`.bashrc`, …) are followed. A folder
reached first as a subfolder is read again to depth 2 when it is on that list itself. The rule is
made from the link's text, joined (when relative) to the real path of the folder holding the link,
as the kernel resolves it, and also matches where that resolves: through a stow-folded
`~/.local/bin -> ~/dotfiles/bin` holding `t -> ../tools/t` the rule is `~/dotfiles/tools/t`, both
hops of `~/.bashrc -> ~/df/bashrc -> /data/x/bashrc` are protected, and a dangling link protects
its target before it exists. A link whose target is already inside a built-in, environment or
`filesystem.deny` rule adds nothing.
Reading is bounded: at most 65 536 entries per validation, counted across all folders. Past that,
with more than 256 `$PATH` or 32 `$GOPATH` folders, or when a folder cannot be read (one that is
gone, not a folder, or that the user can neither list nor enter is skipped; one the user can
enter but not list refuses, as its files still run by name), validation fails with one
`denylist-incomplete` error at `filesystem` naming the folder, the bound or the variable; the
mounts are still checked against every other rule. A manifest with no mounts reads nothing, so it
never gets this error.

`denylisted` messages name the rule in words ("is inside /home/u/.ssh — credential folders are
never mountable"). There is no `cfg(test)` or feature-gated bypass of the denylist: tests move
their fixtures (under `target/`), never the wall.

Candidates whose root is a symlink, a file, or missing are refused. A candidate that contains a
*symlink to* a denylisted path (e.g. mounting `~/code` when `~/code/.ssh -> ~/.ssh`) is allowed:
symlinks inside a mount resolve inside the container rootfs, which is the point of RT-FS-03.

Rules also match by identity (RT-FS-14). Each rule records the `st_dev`/`st_ino` of its directory
and, for a subtree rule, of every existing ancestor. A mount root with one of those identities is
`denylisted` whatever its path: a bind alias (or a second mount of the same filesystem) of
`~/.ssh` "is the same directory as" it, and an alias of `~/.local` or of the home's parent
"contains" a protected folder. An alias of a directory *inside* a protected folder is not
detected: the same path-versus-filesystem ancestry gap as the overlap rule's re-review M-2
(open, optional: #17, #28).

`sallyd` validates when the session is created (`sessions.create`), so the denylist, link rules
included, is as of that moment. At launch the driver's scan re-opens every mount root without
following symlinks and refuses one that is no longer the same directory (`st_dev`/`st_ino`,
RT-FS-06). The library's own re-check, `ValidatedManifest::recheck_mounts`, rebuilds the
denylist (link rules included) and requires the same checks, realpath and directory as at
validation — otherwise `mount-changed`/`is-symlink`/`denylisted`; the launcher does not call it
yet (TODO(#231)).

## 3. Enforcement points (field → who enforces → when)

| Field | Enforcement point | Moment | Failure behavior |
|---|---|---|---|
| `apiVersion`, `kind`, unknown fields | `sally-core::manifest::parse` | load | reject with field path |
| `name` | parse | load | reject |
| `runtime.image`, `harness.image` | validator (pinned) + `sallyd::sandbox::images` (`--pull=never`) | validate + launch | refuse unpinned refs; refuse if the digest is not present locally; refuse an image with an `Entrypoint` (`config-mismatch` on `process.args`, until #117) |
| `runtime.cpus/memory/pids` | `sallyd::sandbox` → `podman create --cpus --memory --pids-limit`; the watchdog's cgroup observer re-reads `pids.events` `max` and `memory.events` `oom_kill` every 1 s (#27) | launch + runtime | out of range → reject at validate; the kernel refuses the fork or OOM-kills inside the container, the session runs on, audit `session.resource_limit` reason `pids-max` / `oom-kill` with the counter's value; launch refused `cgroup-events` if the files cannot be opened |
| `runtime.timeout` | `sallyd::session` timer → `podman kill`; backstop: `--timeout <runtime.timeout + 300 s>` on the workspace and harness `create`, enforced by conmon from `podman init` without `sallyd` (#92, RT-AG-16) | runtime | session stopped, audit `session.timeout`; a container whose `sallyd` was killed outright is killed by conmon at the backstop and removed (`--rm`), with no entry |
| `runtime.tmp_size/tmp_exec` | `podman create --tmpfs /tmp:…` | launch | a full `/tmp` returns ENOSPC; contained, not audited (a tmpfs has no kernel event) |
| `runtime.stage_size` (soft) | `sallyd::sandbox` disk watchdog: when the state filesystem's usage grows past the session's headroom, `podman pause`, walk the staged and `.git` overlay upper dirs (10 s deadline), `unpause` → `podman kill` + `rm` until gone; launch needs the floor plus `stage_size` free | launch + runtime | session killed, audit `session.resource_limit` (before the kill; `session.kill_failed` if the first kill fails); staged data kept |
| (no field) free-space floor, `max(4 GiB, 5 %)` | `sallyd::sandbox` disk watchdog: `fstatfs` every 250 ms of every filesystem the sandbox can write to, itself or through the broker (state, `rw` and `brokered` mount roots); the broker's file tools check the floor before each write (`tools::fs::write`) | launch + runtime + each broker write | below the floor: session killed, audit `session.resource_limit` reason `disk-floor`; launch refused `disk-floor`; a broker write refused `disk-floor` |
| `model.ref` | `sallyd::infer` resolves in library; refuses unverified/unknown | session start | error to UI |
| `model.context/gpu_layers` | `sallyd::infer` → llama-server args, clamped by fit estimator | load | clamped, warning |
| `model.context` (token limit) | `sallyd::llm` (`body::check`): a request's `max_tokens` / `max_completion_tokens` above it is refused (and 0 always is); absent, the backend is given `model.context` as the bound. The M3 fit estimator clamps further | each `llm.sock` request | 400 `token-limit` (0: `bad-value`) + audit `llm.deny` |
| `filesystem.mounts[].host` | validator (realpath, denylist, is-dir, not-symlink) **and again** at launch: the launch scan re-opens the root without following symlinks and compares `st_dev:st_ino`, pins are re-checked before `podman init`, and bind mounts are compared inside the container after `init` (ARCHITECTURE §3.5). Validation only: the mounts of one manifest may not overlap, by path or by directory identity (§1, Mount); the launch re-checks each root's identity, not the overlap | validate + launch | reject / `sandbox.refuse` / `sandbox.mount_mismatch` |
| `filesystem.mounts[].guest` | validator (`/workspace/…`, no `..`, unique) | validate | reject |
| `filesystem.mounts[].mode` | workspace `podman create` (`sallyd::sandbox::workspace_argv`): bind `ro`/`rw` with `nosuid,nodev,bind` (non-recursive); `brokered` → `ro` + broker `fs_*`; `staged` → `:O` overlay with upper/work in session scratch | launch + each `fs_*` call | EROFS in workspace; `fs_write`/`fs_delete` denied on `ro` (`read-only`); on `staged` they land in the overlay's upper directory; in every mode a call the sandbox's `uid:gid` could not make by mode bits is `permission` (Q39) |
| `filesystem.mounts[].approve` | validator (glob syntax, §1 Mount) + `sallyd::approvals` glob match on canonical relative path; omitted = `["**"]` | validate + each brokered write/delete | reject; pending → approve/deny |
| git metadata (AMENDMENTS-02 B2(a)) | validator (no writable mount inside `.git`); `.git` directories in `rw` mounts as overlays over session scratch, `.git` files bound read-only (argv builder, Task 6a; launch scan, Task 6b); broker `fs_write`/`fs_delete` | validate + launch + each call | reject / EROFS / `protected-path` |
| `filesystem.deny` | validator adds to denylist | validate | reject |
| `network.mode` | `none` → no shim, no `net.sock`; `proxy` → shim started, `net.sock` mounted, proxy env set | launch | — |
| `network.allow[]` | `sallyd::egress::policy` on every CONNECT request (v1 has no absolute-form forwarding: 405 `plain-http-unsupported`) | each connection | HTTP 403, audit `egress.deny` |
| `network.acknowledge_unrestricted_egress` | validator | validate | reject if `*` without ack |
| `network.max_connections` | `sallyd::egress::server` admission of each admitted connection (one within the session's admission rate, 20/s with bursts of 40; a connection over the rate is closed unread and counted in `egress.shed`), decided and audited at accept before any byte is read; after the 429 is written the proxy discards, unparsed, what the client still sends (at most 256 KiB, at most 1 s), then closes | each connection | 429 `too-many-connections`, audit `egress.limit` |
| `network.max_request_bytes`/`max_response_bytes` | `sallyd::egress::server::intercept` body caps (Task 9a-2: intercepted requests only; a spliced tunnel is opaque; body bytes after chunk decoding, per message); `sallyd::tools::fetch` also applies both to a fetch on either route: the request body at prepare, the returned body (also ≤ 1 MiB) at run (#75 ruling Q13) | each intercepted request and response; each fetch | 413 request / 502 response, audit `egress.limit`; a fetch: `denied: request-too-large`, or the body cut with `truncated: true` |
| `secrets[].name` | validator checks the store's names (`sally_core::secrets::StoreNames`, read afresh for each validation by `sallyd` and the CLI alike, #99); `sallyd::egress::inject` reads the grants' values from the store at launch (Task 9a-3) | validate + launch + each matching request | reject if missing; a store that cannot be read is `session.refuse` `secret-store` over `control.sock` (exit 2 in the CLI), never a missing name; at launch `sandbox.refuse` `secret-missing` (`secret-store` when the store cannot be read) |
| `secrets[].inject.host` | validator (exact host, must be allowed) + inject (a grant's credential is set on its own host only; every intercepted response is redacted with every secret of the session, and its `egress.response` entry names the secrets redacted and the bytes) | validate + launch + request | reject; at launch `sandbox.refuse` `secret-filler` when the session's forms hold every filler candidate |
| `secrets[].inject.header/format/basic_user` | validator + inject (TLS-terminated grant hosts only; every client copy of the header is dropped, then the grant's value set once the request is audited; `{basic}` renders RFC 7617's padded base64 of `basic_user:secret`, Task 9b; the placeholder and `basic_user` pairing is checked again at launch) | validate + launch + request | reject; plain HTTP to any host → 405 `plain-http-unsupported`; a grant that cannot be injected → `sandbox.refuse` `secret-grant` |
| `secrets[].expose_env` | validator (name rule) + workspace `--env NAME=sallyport-placeholder` | validate + launch | reject |
| `tools.builtin` | `sallyd::tools` per session: `tools/list` shows the granted tools; the grant is checked before arguments or paths (Task 11, architect ruling Q28); `fetch` is listed only when the session has a way out through its proxy (`network.mode: proxy`, #75 ruling Q8); a session granting `fetch` loads the upstream trust roots at launch and is refused without them (#75 ruling Q2) | each `tools/call` on `agent.sock` | `isError: true`, `denied: tool_not_granted` (a granted `fetch` without a way out: `tool_unavailable`), audit `tool.deny` |
| `tools.shell` | `sallyd::tools::exec` → `podman exec` after policy; 300 s and 64 KiB per stream, the call killed past the limit | each shell call | deny / pending / run |
| `tools.destructive_requires_approval` | pattern tagger `sallyd::tools::tag` (Task 11, architect ruling Q33), its verdict an input to `sallyd::approvals` | each shell call in `allow` mode | pending if tagged, or if no tagger ran |
| `tools.fetch_writes` | `sallyd::tools::fetch` → `sallyd::approvals`; the ticket binds the method, the canonical URL, the harness's headers and the body, never an injected credential (#75 rulings Q3, Q4); headers the proxy would drop are refused at prepare, so the prompt shows only what is sent | each non-GET/HEAD fetch, and each GET/HEAD with a body, a method-override header (`X-HTTP-Method-Override`, `X-HTTP-Method`, `X-Method-Override`) or body framing (`Content-Length`, `Transfer-Encoding`) | pending if `approve` |
| `tools.acknowledge_unapproved` | validator (`ack.rs`); launch audit `manifest.acknowledged_risk` | validate + launch | reject if needed and unset |
| (no field) the manifest file's place and the launch consent | `sally` CLI (`consent.rs`; `sally_core::manifest::ManifestPlace`, `check_place`, `check_hosts_as_written`), §1.2 | `session start` / `sandbox run` | refuse (exit 1; 2 for a malformed flag or a file that cannot be inspected or read), nothing sent to `sallyd` |
| (no field) what the validation accepted | `sallyd::session` (`accepted.rs`): `manifest.acknowledged_risk` per acknowledgement, one `manifest.warn` | launch, before `sandbox.launch` | a failed append refuses the start; nothing launched |
| `tools.mcp[]` | env-name filter in validator; broker MCP gateway (M4) | validate + each relayed call | reject secret-like env; pending if `approve: always` |
| `[data-can-leave]` | validator warning + `summary()` first line + UI | validate | warning (never blocks) |
| `approvals.timeout/max_pending` | `sallyd::approvals`; new prompts also limited to one per 2 s, burst `max_pending` (ARCHITECTURE §4.2) | each request | expire → deny; over either bound → `denied: approval-flood`, one `approval.deny` each + one `approval.flood` per episode |
| `audit.level` | `sally-core::audit` filter | each event | — |
| `policy.*` | parsed, ignored (v1) | — | — |

## 4. Validation output

`sally manifest validate m.yaml` prints either `OK` plus the plain-English summary, or a list of
errors like:

```
error: filesystem.mounts[0].host: "~/" is the home directory root (denylisted) [denylisted]
error: secrets[0].inject.host: "*.github.com": host must be exact (no wildcards) [not-exact-host]
error: network.allow[2].host: "*" requires network.acknowledge_unrestricted_egress: true [unacknowledged-wildcard]
error: tools.acknowledge_unapproved: shell: allow with destructive_requires_approval: false runs every command without approval; add "shell" to tools.acknowledge_unapproved to accept this [unacknowledged-risk]
warning: tools.shell: "allow": shell commands run without approval unless tagged destructive [risky]
```

All errors are reported at once. Diagnostics are single-line (control characters become
spaces); a diagnostic's path and its message are each at most 300 characters, the cut marker
included (a cut one ends in `...`). Token-looking values (20 or more characters with a digit and
no space, slash or backslash) are masked before the cut: in the message when it quotes them (in
`"…"` or backticks), in the path as any dot-separated segment, so a credential pasted into the
wrong field does not reach the UI or the audit log. The bracketed code is stable (tests and the UI match on it,
never on message text); the field path uses `a.b[0].c` form.

| Code | Meaning |
|---|---|
| `too-large` | input over 256 KiB |
| `syntax` | not YAML, or a forbidden YAML feature (anchor, alias, merge key, tag, duplicate key, 2nd document) |
| `schema` | unknown/missing field, wrong type, unknown enum value |
| `invalid-value` | malformed string (name, path, glob, env name, model ref, …) |
| `out-of-range` | number/size/duration/list length outside its range |
| `denylisted` / `is-symlink` / `not-directory` / `not-found` / `path-chars` | mount host checks (§2) |
| `denylist-incomplete` | the built-in denylist could not be completed on this host: the link scan passed its 65 536-entry budget, `$PATH` names more than 256 folders or `$GOPATH` more than 32, or a folder could not be read or can be entered but not listed (§2); at `filesystem`, only when the manifest has mounts |
| `guest-path` | guest not a clean path under `/workspace/` |
| `duplicate` / `overlap` | repeated entry / overlapping mounts |
| `not-pinned` | `runtime.image` / `harness.image` without a digest |
| `bad-host` / `ip-literal` / `not-exact-host` | hostname malformed or too broad / IP literal / wildcard where exact is required |
| `unacknowledged-wildcard` | `"*"` without the ack flag |
| `network-disabled` | secrets with `network.mode: none` |
| `secret-missing` / `secret-host-not-allowed` | name not in store (at validation; at launch also a `sandbox.refuse` reason, Task 9a-3) / no exact allow rule for the inject host |
| `secret-store` / `secret-grant` / `secret-filler` | launch refusals (`sandbox.refuse`, Task 9a-3): the secrets store cannot be read / a grant whose format and `basic_user` do not pair (exactly one placeholder; `basic_user` exactly with `{basic}`), whose header or rendered value cannot be sent, two grants on one header of one host, or a form of the secret too long to redact / every redaction filler candidate occurs in a form of the session's secrets (names no secret). (`basic-unsupported`, Task 9a-3's refusal of `{basic}`, was deleted in Task 9b.) |
| `secret-like-env` | MCP env name looks like a secret |
| `bad-header` / `bad-format` | injection header/format invalid |
| `mount-changed` | launch-time re-check: mount root replaced since validation; or replaced between its own check and the walk of its ancestors during validation |
| `digest-mismatch` | launch refusal (`sandbox.refuse`): the pinned image is not in local storage, or the local image does not carry the pinned digest (`sallyd::sandbox::images`); images are never pulled |
| `no-default-image` | launch refusal (`sandbox.refuse`): the manifest names no `runtime.image` and no bundled workspace image is installed (#88); nothing is reserved or created (architect Q58) |
| `unacknowledged-risk` | an `acknowledge_*` flag is needed (§1.1) |
| `protected-path` | writable mount inside `.git`; also the broker's denial code for protected-path writes |
| `socket-in-mount` | launch-time bounded scan found a Unix socket in a mount tree (sandbox driver, task 6) |
| `data-can-leave` | private data and an outward channel coexist (warning) |
| `inconsistent` / `risky` | warnings only |

TODO(#58): export `Code` through `sally-proto` (`ts-rs`) so the UI gets the code set as a
generated type. Deferred from Task 7 to M5 (Task 7 ruling Q12).

## 5. Example manifests

See `manifests/examples/`:
- `chat-only.yaml` — no mounts, no network, no tools. The safest possible session.
- `coding-agent.yaml` — one `rw` project mount, PyPI/GitHub egress, GitHub token injected
  (Bearer for the API, Basic for git over HTTPS, placeholder `GH_TOKEN`), shell with approval.
  `[data-can-leave]`.
- `web-research.yaml` — search API key injected, unrestricted egress (acknowledged), a `brokered`
  notes directory whose writes need approval, no shell. `[data-can-leave]`.

## 6. Known limitations

- **No borrowed groups; ACL objects are owner-only** (architect ruling Q39, accepted by the
  maintainer). The file tools act with the sandbox's permissions in every mount mode (§1,
  Mount). The workspace runs as the user's `uid:gid` without supplementary groups. So a file or
  folder reachable only through one of the user's other groups is refused `permission`, even for
  a brokered write the user would approve. An object that carries a POSIX ACL, or whose ACL
  cannot be read, is treated as open to its owner only. The ACL's named entries are not
  honoured. In practice, brokered writes to group-shared folders are narrower than the user's own
  access. Mount a folder the user owns, or one whose mode bits grant the access directly.
- **Links out of protected folders are read when the session is validated, to depth 2 (§2).** A
  link made later, one deeper than depth 2, one inside a linked folder, a non-dot entry of a home,
  a link in a `$PATH` folder outside the homes (`/usr/local/bin/x -> ~/code/x`), the middle
  hops of a chain longer than two, and a not-yet-existing target spelled with `..` after a
  linked component (only its textual form is protected) are not followed (THREAT_MODEL §6).
- **A large protected folder can refuse every manifest with mounts.** A listed folder, or one of
  its subfolders, holding tens of thousands of entries (a cache subfolder with a file per item)
  can take the scan past the 65 536 entries it reads; validation then fails `denylist-incomplete`
  naming the folder. Clear or shrink that folder, or move it out of the listed folders; manifests
  without mounts are not affected.
- **An environment variable or link that names `/`, a home, or an ancestor of one refuses every
  mount under it** until it is changed (`CARGO_HOME=$HOME`, a `$PATH` entry equal to a home, an
  exported `ZDOTDIR=$HOME`, `PYTHONUSERBASE=$HOME/.local`, which refuses everything under
  `~/.local`). The message names the variable or the link; for the last two, unset the variable
  (the default is the same place). Such a variable's folder is also read whole, every entry and
  not only dot names, so a large home can use up the budget and refuse mounts outside it too
  (`denylist-incomplete`).
- **A folder the user can enter but not list (mode `--x`) inside a listed folder refuses every
  manifest with mounts** (`denylist-incomplete`, naming it), since its files still run by name
  and its links cannot be read. Make it listable, or remove it.
- **A tool folder moved by a variable that is not on the §2 list is not a rule** (#232). List it
  in `filesystem.deny`. Nor is a listed variable's value that is not absolute, even where the
  tool expands it itself (a literal `~/…` or a relative `$PIPX_HOME`, which pipx expands).
- **The environment that counts is `sallyd`'s own, read once when it starts.** A variable set
  only in the user's shell is not seen, so a daemon started with a minimal environment has fewer
  environment rules than the shell. `sally manifest validate` uses the CLI's environment and is
  advisory.
