# M1 Checkpoint 3: sandbox driver (Tasks 6a–6c)

Status: **waiting for the maintainer's review.** PR #25 stays draft until the go.
Branch `m1/sandbox-6c2`, verified head `d232b2d`. CI verdict at that head: `true`, from the
`statusCheckRollup` command in CLAUDE.md.

Local gates at that head:
- `make lint test`: green in 91 s, including `cargo deny`.
- `make redteam`: 49/49 `rt_` tests in 55 s. The WSL-only test then ran separately and passed.
- `make nextest`: 437 passed, 1 skipped (the WSL test, off its run) in 60 s.

`launch.rs` delta against `main`: **+7 / −2, +5 net**. This is wiring only: the `ImageMissing`
variant, its reason arm, and `req.image()` plus the `image_present` call. The rust-reviewer
confirmed it. The file has 849 lines; the move-only split follows after the go, before Task 8.

## 1. `podman create` argv per role and mount mode

The normative argv snapshots live in `crates/sallyd/tests/snapshots/`. Each is checked in, and
the argv check runs on each one. `$ROOT` is the redacted fixture root.

| Snapshot | Role | What differs |
|---|---|---|
| `argv__workspace-ro.snap` | workspace | `-v <host>:/workspace/p:ro,nosuid,nodev,bind` |
| `argv__workspace-rw-git.snap` | workspace | `rw,nosuid,nodev,bind`. Each `.git` gets an `:O,upperdir=…/git/<k>/upper` overlay, parents are self-bound, and pointer files are bound `ro`. |
| `argv__workspace-brokered.snap` | workspace | `ro` bind; writes go through the broker's `fs_*` tools (Task 11) |
| `argv__workspace-staged-proxy.snap` | workspace | `:O,upperdir=…/stage/<n>/upper,workdir=…`, plus the proxy environment |
| `argv__workspace-all-modes-secrets.snap` | workspace | Every mode in one session, the CA bundle environment and a placeholder token |
| `argv__harness-default.snap` | harness | No mounts except its socket directory. `/tmp` is `noexec`, 256 MiB. |
| `argv__inference-cpu.snap`, `argv__inference-gpu.snap` | inference | Weights are bound `ro` by blob digest. GPU adds only `--device nvidia.com/gpu=all`. |

The prologue shared by every role is:

```
--runtime $ROOT/bin/crun --hooks-dir $ROOT/hooks --default-mounts-file $ROOT/mounts.conf
create --rm --name sp-<role>-<id> --pull=never --http-proxy=false --log-driver=none
--ulimit core=0 --network=none --no-hosts --read-only --read-only-tmpfs=false --cap-drop=ALL
--security-opt no-new-privileges --security-opt seccomp=<per-role profile>
--security-opt label=disable --userns=keep-id --user 1000:1000
--tmpfs /tmp:rw,{exec|noexec},nosuid,nodev,size=<tmp_size> --pids-limit <n> --cpus <c>
--memory <m>b --init --env-host=false [--hostname sandbox]
-v <session socket dir>:/run/sallyport:ro,nosuid,nodev,bind   (inference: rw, its own dir)
<image>@sha256:<digest> <entry>
```

None of the forbidden flags appear in any snapshot. The red-team grep and `check_argv` both
enforce this.

## 2. Effective OCI config: workspace and harness

This was captured from live containers during `rt_net_12`. It is the `config.json` that crun
received, read through `podman unshare`.

| | workspace | harness |
|---|---|---|
| user | 1000:1000, user namespace (3 uid mappings, keep-id) | same |
| capabilities | all five sets empty | same |
| `noNewPrivileges` | true | true |
| root filesystem | read-only | read-only |
| namespaces | pid, network, ipc, uts, mount, user, cgroup | same |
| seccomp | default `SCMP_ACT_ERRNO` with errno 38 (ENOSYS), 18 rule groups | same (harness profile) |
| masked / read-only paths | 12 / 6 (podman defaults; `/proc/kcore` masked) | same |
| mounts | `/workspace/*` per mode; `/run/sallyport` `ro`; `/tmp` tmpfs `nosuid,nodev`; `/sys` and `/sys/fs/cgroup` `ro`; `/dev` tmpfs `ro`; `/dev/shm` `ro,noexec`; `/etc/{passwd,group,hostname}` `ro` | no `/workspace`; the rest the same |
| limits | pids 512, memory 8 GiB (+ the same again as swap), CPU quota 4 | pids 128, memory 1 GiB (+1 GiB swap), CPU quota 1 |
| rlimits | core 0, nofile 1048576, nproc (host default) | same |
| hooks | none | none |
| process | `/run/podman-init -- /opt/sallyport/entry --idle` | `/run/podman-init -- /opt/sallyport/entry` |

The generated config is still not verified before start. That is RT-SUP-04, #15, Task 14.

## 3. Red-team rows (Tasks 6a–6c)

All of these tests run in CI unless the row says otherwise. Rows assigned to later tasks
(egress, approvals, tools, audit) are not listed here.

| Row | Tests (`rt_…`) | Result |
|---|---|---|
| RT-FS-01 | `fs_01_the_host_home_is_invisible` | pass |
| RT-FS-02 | `fs_02_an_ro_mount_is_read_only` | pass |
| RT-FS-03 | `fs_03_symlinks_resolve_inside_the_container` | pass. The link to `/etc/shadow` has the container's `st_dev:st_ino` and never the host's. Links to the canary's host path find nothing. |
| RT-FS-05 | `fs_05_*` (sally-core) | pass |
| RT-FS-06 | `fs_06_*` (validator, scan) and `fs_06_launch_refuses_*` (launcher) | pass. A swap after validation is refused as `mount-changed` and nothing is created. |
| RT-FS-07 | `fs_07_device_nodes_cannot_be_created` | pass |
| RT-FS-08 | `fs_08_setuid_never_raises_privileges` | pass |
| RT-FS-09 | `fs_09_proc_and_sys_are_closed` | pass |
| RT-FS-11 | (a) `fs_11_mnt_is_absent_or_empty`; (b) `fs_11_wsl_a_windows_executable_does_not_reach_windows` | (a) pass in CI. (b) Local, WSL only: it passes, with a host control that creates and deletes an empty canary. Elsewhere it is listed as skipped, never as passed. |
| RT-FS-12 | `fs_12_git_shields_hold_inside_the_container`, `fs_12_git_vectors_in_{an_rw,a_staged}_mount_never_run_on_the_host` | pass. A host control fires each vector. **Deferred:** `fs_write` denial of `.git` paths (#19, Task 11). |
| RT-FS-13 | `fs_13_*` (scan, launch) | pass |
| RT-FS-14 | `fs_14_a_bind_alias_of_a_protected_folder_is_refused` | pass. **Deferred:** aliases of directories *inside* a protected folder (#28, with #17's M-2; Task 14). |
| RT-FS-15 | `fs_15_staged_changes_*`, `fs_15_replaced_and_renamed_directories_are_listed` | pass. **Deferred:** the CLI `sally session changes` (#20, Task 12). |
| RT-FS-16 | `fs_16_a_nested_host_mount_is_not_visible` | pass |
| RT-FS-17 | `fs_17_no_role_creates_a_namespace` | pass |
| RT-NET-01 | `net_01_direct_tcp_and_udp_find_no_route` | pass (every role) |
| RT-NET-08 | `net_08_raw_sockets_and_icmp_fail` | pass. Raw sockets are refused at creation. Ping sockets get EACCES at creation, or a failed send. |
| RT-NET-12 | `net_12_socket_families_outside_the_role_list_fail` | pass |
| RT-AG-08b | `ag_08b_overlapping_sessions_are_refused_while_the_first_is_live` | pass |
| RT-AG-09, `stage_size` | `ag_09_writing_past_stage_size_*` | pass: contained and audited |
| RT-AG-09, rename churn | `ag_09_rename_churn_does_not_evade_stage_size` | pass. One unexplained failure in 6c-1 was explained in 6c-2 as a **test race** (see below). After the fix: 100 clean runs. |
| RT-AG-09, floor | `ag_09_a_full_speed_writer_in_{a_staged,an_rw}_mount_*` | pass: contained and audited (`disk_floor`) |
| RT-AG-09, slow walk | `ag_09_a_busy_walk_does_not_delay_another_sessions_floor` | **smoke + structural**, not a plain pass. The security-reviewer confirmed Decision 2 in this task (below). |
| RT-AG-09, bombs | `ag_09_a_fork_bomb_*`, `ag_09_a_memory_bomb_*`, `ag_09_a_tmp_filler_*` | pass: **contained**. **Deferred:** their audit entries (#27, Task 12). |
| RT-SUP-01 | `sup_01_a_pinned_digest_not_in_local_storage_is_refused`, plus the argv snapshot scan | pass |
| RT-SUP-02 | `sup_02_a_missing_digest_is_refused_without_an_outbound_connection` | pass. No IP address is named in any connect or send, loopback included. The trace shows the `images.json` lookup and the not-found exit codes. |
| RT-SUP-04 | — | **deferred** (#15, Task 14) |

**Churn failure, in detail.** The 6c-1 failure printed:

```
not killed: exec "", du (0, "49164\t/workspace/o\n"), events ["sandbox.launch"]
```

- 49164 KiB is two of the four 24 MiB files, under the 64 MiB limit, so not killing was correct.
- The cause: `dd of=d1/fN` re-created a name the renamer had just moved away, and the next
  `mv d2/fN d1/fN` replaced it, so the data was lost.
- I reproduced this outside sallyd with retained sizes from 24 to 96 MiB.
- The fix: the writer opens all four files before the renamer starts and writes through those fds.
  The assertions did not change.
- Result: 100/100 clean runs with `--retries 0`.

**Decision 2: CONFIRMED** (security-reviewer, this task). `floor_task` (`watchdog.rs` 288–317)
acquires neither the walk semaphore (taken only at 401, in `stage_task`) nor the exec gate
(only at 405). It holds no `JoinHandle` and never awaits the walk. The only shared lock is the
`Account` mutex, which is never held across an await or during a measurement.

**Changed during 6c-2.**
- **`sec(sandbox)`: hermetic podman now runs from its private state directory.** An OOM kill
  made conmon write an `oom` marker into its caller's working directory; in production that is
  `sallyd`'s. The OOM test now asserts that no marker appears there.
- **Review fixes:**
  - the staged listing is bounded at 16 MiB of paths;
  - an xattr error now fails the listing closed;
  - NET-08 now requires raw sockets to be refused at creation;
  - FS-03 and FS-07 assertions were tightened.

**Reason codes.** Kebab-case applies to reason values only. Four watchdog values still use
underscores: `disk_floor`, `stage_size`, `pause_failed` and `unpause_failed`. Since there is
more than one, they are #26 (Task 12). `resource: stage_size` keeps the manifest key's spelling.

## 4. Open issues

| # | Title | Task |
|---|---|---|
| #15 | sandbox: verify the generated OCI config before start (RT-SUP-04) | 14 |
| #17 | sandbox: follow-ups from the Task 6b reviews | 12 / 14 |
| #19 | tools.fs: RT-FS-12 `fs_write`/`fs_delete` denial of `.git` paths | 11 |
| #20 | cli: wire `sally session changes` to the staged-changes listing | 12 |
| #21 | sandbox: evaluate an empty per-userns `binfmt_misc` instance for containers | M6 |
| #23 | sally-shim: flaky relay test under load (no failure during 6c-2) | 8 |
| #24 | tools.shell: hold the session exec gate only while starting `podman exec` | 11 |
| #26 | audit: kebab-case the `session.resource_limit` reason values (new) | 12 |
| #27 | audit: `session.resource_limit` for the pids, memory and `/tmp` limits (new) | 12 |
| #28 | sandbox: follow-ups from the Task 6c-2 reviews (new) | 12 / 13 / 14 |

## 5. Sessions used against the plan

AMENDMENTS-02 estimates M1 at about 13 work units, with no per-task split. Counting one session
as one unit:

| Area | Sessions |
|---|---|
| Tasks 1, 2 and 1f, with Checkpoint 2b | 3 |
| Repo publication | 1 |
| Tasks 3–5 | 1 |
| 6a, 6b, 6c-1 | 3 |
| 6c-2 | 2 |
| **Total** | **10** |

That leaves 3 units for Tasks 7–14 (eight tasks, including the security-heavy egress, token
proxy and tools).
- At one session per remaining task, M1 ends near 18 units: 38 % over.
- At 1.5 sessions each, it ends near 22 units: 69 % over, past the "over half" line in
  AMENDMENTS-02.

That line's cut order is: fetch-write approvals, `{basic}`, the template-mismatch flag, then
`sally session changes`. **The decision is the maintainer's.**

## 6. CI cost

| What | Duration |
|---|---|
| `ci` workflow, typical | 4.4–5.8 min wall clock per run (last 25 completed runs) |
| `ci` jobs at this head | rust 6.1 min, fuzz 4.9, redteam 4.9, zizmor 4.3, deny 2.2, coverage 1.2, doctor-syntax 0.1; about 24 runner-minutes |
| Nightly mutation test | no successful run on record |

The one nightly run listed, scheduled at 2026-11-10 17:07Z, **failed** in `make mutants` after
1.4 min. Its log cannot be retrieved with `gh`, and no run for today's 09:17Z schedule is
listed. This needs the maintainer's look; no issue has been opened.
