# Amendments 02 — decisions adopted at design review 2b

Date: 2026-11-09. Written after Task 2b, before Task 1f.

**Precedence.** Same rule as Amendments 01: where this file conflicts with `ARCHITECTURE.md`,
`THREAT_MODEL.md`, `MANIFEST_SPEC.md`, `MILESTONES.md`, `REDTEAM_SUITE.md`, `CLAUDE.md` or
`AMENDMENTS-01.md`, this file wins until the change has been folded into that doc. Fold each
section in the task that implements it, then delete the section here and say so in the commit.

## B1. `{basic}` redaction (Task 9b)

The redaction set for each grant is:
- the raw secret;
- the exact injected header value and its credential part (the whole `{basic}` blob);
- the secret in all three base64 alignments, both alphabets, trimmed of the edge characters that
  depend on neighbouring bytes, so base64 of *any* string containing the secret is caught;
- percent-encoding.

Add a proptest: for random prefix and suffix, `base64(prefix ‖ secret ‖ suffix)` is always
redacted. `sally secrets set` warns when a value is shorter than 16 bytes (trimmed patterns under
12 characters are skipped as too collision-prone). RT-SEC-12 gains `basic_user` values of length
1, 2 and 3 (`x`, `ab`, `git`).

## B2. Git and writable mounts

Neither an allowlist of writable `.git` entries nor an enumeration of redirect files. An allowlist
cannot be enforced with mounts (git creates and renames top-level files in `.git`, which needs a
writable directory), and enumerating redirect files cannot stop new ones. Use the overlay volumes
V13 proved instead.

### (a) A sandbox never writes a host `.git`

- In an `rw` mount, every `.git` *directory* found by the launch scan (the same bounded walk as
  the socket scan) is mounted as an overlay volume whose upper dir is session scratch, discarded
  at teardown.
- Every `.git` *file* (a worktree or submodule pointer) is bound read-only.
- Git works inside the sandbox. The host's history, config, hooks and `commondir` stay
  byte-identical.
- `summary()` states the consequence: commits made in a session are discarded, and file changes
  arrive as uncommitted modifications. Importing session commits as a `sallyport/<session>`
  branch is v1.1.
- Broker `fs_write`/`fs_delete` deny any path with a component named `.git` (`protected-path`).
- This replaces the hooks/config overlays of Amendments 01 §6.3.

### (b) New mount mode `staged`, adopted now

This resolves the deferred decision in Amendments 01 §12. V13 passed, and this finding shows `rw`
cannot be made safe when an editor or the user runs tools over the folder: a new nested `.git`,
`.vscode/settings.json` or `.cargo/config.toml` is host-executed and cannot be blocked at a bind
mount.

In `staged`, the host directory is the overlay's lower layer, every write lands in a kept upper dir
in session scratch, and the host directory is untouched until the user applies.

**M1 (Task 6):**
- validator mode;
- argv `-v <host>:<guest>:O,upperdir=…,workdir=…`;
- stage dirs under `~/.local/share/sallyport/sessions/<id>/stage/<n>/`;
- teardown cleanup through `podman unshare`;
- `sally session changes <id>`, listing changed and deleted paths from the upper dir (whiteouts
  are 0/0 character devices);
- discard-only for now;
- probe which of `nosuid,nodev` combine with `:O`, and report.

**M4.5:** the apply engine, `sally session diff|apply|discard`, with the review UI in M5. Rules:
- regular files and deletions only, through `openat2` confinement, temp + rename;
- never apply anything under a `.git` component;
- never special files or setuid bits;
- symlinks only when the target stays inside the mount;
- a host file changed since the launch snapshot is a conflict: skip it and report it;
- paths on a maintained "runs code on your machine" list are highlighted and unselected by
  default: `.vscode/**`, `.idea/**`, `.envrc`, `.husky/**`, `.pre-commit-config.yaml`,
  `.github/workflows/**`, `.cargo/config.toml`, `build.rs`, `Makefile`, `justfile`,
  `package.json`, `setup.py`, `conftest.py`, `.npmrc`, `.yarnrc.yml`, `.devcontainer/**`.

`rw` stays, with a `[direct-write]` warning as the second line of `summary()`. The coding-agent
example manifest switches to `staged`.

Document that editing the host folder while a staged session runs gives undefined results inside
the sandbox; conflicts are caught at apply.

Budget: the apply engine (~half a week) is paid for by reducing the M5 manifest editor to templates
plus the live summary.

### Red-team

- **RT-FS-12** is rewritten. In `rw` and `staged` mounts the sandbox writes
  `.git/hooks/pre-commit`, a `core.fsmonitor` line in `.git/config`, and `.git/commondir`.
  - PASS: the host `.git` tree hash is unchanged;
  - a host-side `git status` canary does not execute;
  - `fs_write` to any `.git` path is denied.
  - Variants (security review of Task 6a): in an `rw` mount with a nested repository
    `sub/.git` and a submodule pointer file `mod/.git`, the sandbox runs
    `mv sub sub2 && mkdir -p sub/.git` and the same for `mod`. PASS: both renames fail with
    `EBUSY` (the parents are self-bound) and the host `sub/.git` and `mod/.git` are unchanged.
    (Task 6b: `crates/sallyd/tests/launch.rs::rt_fs_12_git_shields_hold_inside_the_container`
    covers the renames, the overlay writes and the read-only pointer file; the full row with the
    host canary runs in the red-team harness, Task 13.)
    A bare `project.git` inside an `rw` mount is **not** shielded and `summary()` says so.
- New **RT-FS-15**. In a `staged` mount the sandbox creates, modifies and deletes files, including
  `.vscode/settings.json` and a nested `sub/.git/config`.
  - PASS: the host directory tree hash is identical during and after the session;
  - `sally session changes` lists exactly those paths.

## B4. Mount source — folded

Folded in Task 6b into `ARCHITECTURE.md` §3.5 (overlap rule, launch scan pins, host re-check
before `podman init`, post-init check through `/proc/<init-pid>/root`, `sandbox.mount_mismatch`).
The post-init check is readable rootless (probed) and runs before `start`, so nothing in the
container has run when it compares.

## B5. Pin the OCI runtime — remaining

Folded in Task 1f into `ARCHITECTURE.md` §3.1/§7, `THREAT_MODEL.md` §6 and `scripts/doctor.sh`
(V14), with `sally_core::config` (`sandbox.runtime_path`). Still to do:
- **M6:** `install.sh` installs the upstream static crun (≥ 1.25.1, checksum and signature
  verified) under `~/.local/share/sallyport/bin/`.
- **Pin file (done at publication):** `runtime.lock` at the repository root holds the crun
  version, URL, SHA-256, signer fingerprint and pin date. `scripts/doctor.sh` V14 reads it now (binary
  hash must match; WARN when the pin is more than six months old); `install.sh` reads the same
  file in M6. There is exactly one pin file.

## B6. Python MCP client fallback

No action now: the broker serves both lifecycles and RT-AG-13 tests both; M4 tests with the real
client.

## B7. `Code` enum export

Decision: the export of the code enum is deferred to Task 7.

## Plan changes (design review 2b)

- **1f** gains B5 and the full doctor re-run.
- **6a** gains `staged` and `.git` overlay mounts. **6b** drops the protected-path overlays and the
  teardown verification they would have needed, and gains B4.
- **7 (rpc)** and **10 (approvals)** are implemented on sonnet with a mandatory opus security
  review, as originally routed.
- Old red-team rows may be rewritten; each such PR carries an old → new table.
- **Pace:** M1 is estimated at about 13 work units. At Checkpoint 3 (after Task 6c), compare
  effort used against the plan. If the overrun exceeds half, cut in this order: fetch-write approvals, `{basic}`, the
  template-mismatch flag, `sally session changes`.

## Decisions after Task 1f

- **B3** (one `tools.acknowledge_unapproved` list) lands in **Task 6a**, together with the
  `staged` validator mode. Same opus reviewers as Task 2. That PR updates the example manifests
  and `MANIFEST_SPEC.md`.
- **Agent commits** stay discarded in v1; importing them as a branch stays v1.1. `summary()`
  states this (implemented with the B2 `.git` overlays in Task 6a). For M4: the reference
  harness's system prompt tells the model not to commit.
- **Runtime pin:** one lock file, read by doctor now and by `install.sh` in M6 (see B5).
- **CI runs without caches** (tools are built `--locked` at pinned versions).
