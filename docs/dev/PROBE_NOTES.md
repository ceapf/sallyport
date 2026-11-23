# Probe notes

Behaviours of the tools Sallyport's tests and sandboxes run on, as probed on the dev host
(Podman 4.9.3 rootless, crun, cgroup v2, busybox in the test image). Add to it as you go: one
line per fact, with where it was found. Check a note again before relying on it after an upgrade.

## Podman and crun

- `/dev/shm` is read-only inside the workspace and harness containers (`sh: can't create
  /dev/shm/…: Read-only file system`). (9a-2, RT-SEC-10)

- A container's limits (`pids.max`, `memory.max`, `memory.swap.max`) sit in
  `/sys/fs/cgroup/<CgroupPath>/container`, not in the `libpod-<id>.scope` itself (that shows the
  host default). `<CgroupPath>` is `podman inspect --format '{{.State.CgroupPath}}'`. (6c-2, AG-09)
- The container init's `/proc/<pid>/cgroup` reads `0::<CgroupPath>/container` from the host, so it
  names that directory directly. There, `pids.events` and `memory.events` are owned by the user,
  mode 0444, and readable from the host. `max` went 0→1 after forks refused at `--pids-limit`,
  and `oom_kill` went 0→1 after an in-container OOM; the container kept running. `pread` at
  offset 0 of a held fd reads the current counts. (Task 12 PR C1, #27.) CI's rootless Podman
  (GitHub's Ubuntu runner) reads them the same way: PR #118's `rust` and `redteam` jobs launched
  sessions, and a launch refuses `cgroup-events` if any step fails (Q105).
- `stat -f -c %T /sys/fs/cgroup` printing `cgroup2fs` agrees with `podman info --format
  '{{.Host.CgroupsVersion}}'` printing `v2` on the dev host (WSL2, `cgroup_no_v1=all`).
  `sally doctor` uses the statfs test, so it needs no podman. (Task 12 PR C2, Q106)
- With only `--memory`, swap is unlimited beyond it on cgroup v2 hosts with swap (the OCI config
  showed swap = 2 × memory). Sallyport sets `--memory-swap` equal to `--memory`. (Checkpoint 3)
- On an OOM kill, the container's conmon writes an empty `oom` file into the working directory of
  the podman that *started* the container (`podman exec` does not). Hermetic podman runs from its
  state directory for that reason. (6c-2)
- Memory used by the RT-AG-09 fork bomb (`runtime.memory` 64 MiB, `runtime.pids` 64, no swap):
  `memory.peak` of `<CgroupPath>/container`, read from the host after the bomb's 3 s and before
  the stop, was 20.3, 26.4, 42.5, 45.9 and 49.5 MiB in 5 runs of the test alone, and 37.8, 44.6,
  34.6, 30.8, 45.1, 27.8, 42.8 and 33.1 MiB in 8 runs with 32 busy loops on 32 cores.
  `memory.events` read all zero every time (`max 0`, `oom 0`, `oom_kill 0`): the limit was never
  reached. Highest 49.5 MiB, 77 % of the limit; CPU load did not raise it. Not measured: under
  the full test suite or under memory pressure, so an OOM kill is neither shown nor excluded as
  the cause of #141. (scratch probe for #141, kernel 6.18 WSL2)
- `userdata/config.json` (`podman inspect --format '{{.OCIConfigPath}}'`) is subuid-owned under
  keep-id: read it with `podman unshare cat`. (6c-2)
- Correction to 6b: hermetic podman (CONTAINERS_CONF, empty XDG_CONFIG_HOME,
  `--default-mounts-file`) still read `$HOME/.config/containers/mounts.conf`; an entry
  `<dir>:/run/secrets/x` became a copy in `<runroot>/overlay-containers/<id>/userdata/run/secrets/x`
  bound read-only. A bare-shell podman without CONTAINERS_CONF did not show it. With `HOME` a
  private empty directory (and `XDG_DATA_HOME` set) it is gone; podman wrote nothing into that
  `HOME` across the sallyd suite (checked empty before every launch). (Task 14, Q118)
- Why (Task 14, Q119; strace `-f -b execve -e trace=%file` on `podman init`): the spec, and
  with it the `mounts.conf` subscriptions, is built at `init`, a separate process from `create`;
  only `create` had `--default-mounts-file`. The bare-shell probe used `podman run`, one
  process with the flag, which is why it did not show the leak. Cases, create always with the
  flag: (A) init without the flag, user file present: `/run/secrets/x` mounted
  (`{"type":"bind","options":["bind","rprivate"]}`, source `<runroot>/…/userdata/run/secrets/x`
  in a plain container), and only the user file opened: podman reads the first that exists of
  `$HOME/.config/containers/mounts.conf`, `/etc/containers/mounts.conf`,
  `/usr/share/containers/mounts.conf`. (B) `default_mounts_file = "<empty>"` in the
  `CONTAINERS_CONF` file: ignored on 4.9.3, same leak. (C) no user file, no flag: init stats
  `/etc/…` then `/usr/share/…`; the private `HOME` alone leaves the system files live. (D)
  `podman --default-mounts-file <empty> init <id>`: no `mounts.conf` touched, no mount. Init
  also stats `/etc/system-fips` (FIPS subscription), which the flag does not switch off (#121).
- `podman exec -i` without `-t` applies no detach keys: stdin `a\020\021b\n` (Ctrl-P Ctrl-Q)
  reached `cat` whole and the command ran to its end, with and without `--detach-keys=`; the
  attach passes `--detach-keys=` anyway. (Task 12 PR C3, line mode)
- strace `-f` on `podman init` never returns: it follows conmon after it daemonizes. `-b execve`
  detaches exec'd children. `sallyd` is not dumpable, so strace cannot read the envp of the
  `execve` calls it makes; podman is dumpable after exec, so `-e inject=execve:delay_exit=<µs>`
  holds each new process long enough to read `/proc/<pid>/environ`. (Task 14, Q120)
- `/proc` reads of a process that exits (kernel 6.18 WSL2, probed with a child of the prober):
  opened while alive and read after the exit, `environ` and `cmdline` each read `Ok` with
  0 bytes. Opened once it is a zombie, `environ` fails `EACCES`, `cmdline` reads `Ok` with
  0 bytes, and the `exe` link fails `ENOENT`. So a reader that opens `environ` just before the
  exit records an empty environment the process never had (#187). rt_sup_04 keeps a reading
  only when two back-to-back reads agree, name the executable it was picked by, and the argv is
  not empty (Q390, Q394). Read in kernel
  source (Linux v6.18) and not observed here: `begin_new_exec` (fs/exec.c) sets the new image's
  exe file and makes its mm current before `create_elf_tables` (fs/binfmt_elf.c) fills in the
  argument and environment ranges. Until `mm->env_end` is set, `get_mm_cmdline` and
  `environ_read` (fs/proc/base.c) both return 0 bytes; `create_elf_tables` sets `arg_end`, then
  `env_start = env_end`, then the final `env_end`, so for a short stretch `cmdline` holds the
  arguments while `environ` is empty. A reading in the first stretch is dropped (empty argv);
  two agreeing readings inside the second keep an empty environment and fail the environment
  equality (a false red, never a pass) (Q394).
- strace 6.8 with rt_sup_04's flags (`-f -qq -v -s 65536 -e trace=execve
  -e inject=execve:delay_exit=1000000 -e signal=none -o <file>`), tracing a non-dumpable parent
  that forks concurrent execs: an exec another process's event interrupts is split into
  `<pid> execve(0x…, 0x…, 0x… <unfinished ...>` and `<pid> <... execve resumed>)           = 0 (DELAYED)`
  (or `= -1 ENOENT (No such file or directory) (DELAYED)`); a dumpable parent's split line shows
  the readable arguments instead. Splits seen: 0 to 4 in 40 concurrent execs (15 runs; the
  blind lines of rt_sup_04's fixture come from these captures); an earlier probe whose captures
  were not kept saw 0 in 6 (3 runs) and 2 to 7 in 40. rt_sup_04 counts a split blind exec as
  one exec (Q393).
- The OCI config, Podman 4.9.3 rootless crun: `capabilities: {}`; rlimits CORE, NOFILE, NPROC
  (the last two podman's own hard limits); hostname = 12-hex short id without `--hostname`;
  `/etc/passwd`, `/etc/group`, `/dev/shm` bind from `<graphroot>/…/userdata`, `/etc/hostname`
  and `/run/.containerenv` from `<runroot>/…/userdata`; `:O` overlays are `type: overlay` with
  source `<graphroot>/…/userdata/overlay/<n>/merge`. The seccomp section is the profile filtered
  by native arch and an empty capability set, comments and errno names dropped; a podman upgrade
  that changes that conversion refuses every launch until `oci/seccomp.rs` follows. (Task 14)
- `--userns=keep-id` maps the caller's uid to the same uid inside. `--user <other uid>` is then a
  subordinate uid: it cannot write the user's bind mounts (`Permission denied`). (Checkpoint 3)
- A mount made in `podman unshare` persists in the pause namespace; for a test-only bind, run
  `podman unshare unshare -m --propagation private <cmd>` so it dies with the command. (6c-2, FS-14)
- A traced (`strace -f`) podman cannot start the setuid `newuidmap` helpers: create the rootless
  namespace first with an untraced `podman unshare true`. (6c-2, SUP-02)
- `podman image exists` exits 1 for absent and 125 for an error; `create --pull=never` of an
  absent digest exits 125 with "image not known". (6c-2, SUP-02)
- `/proc/kcore` is masked with `/dev/null` (reads succeed, empty); PID 1 is
  `/run/podman-init -- <entry>` (`--init`). (6c-2a, FS-09)
- Rootless podman's `:O` overlays use the kernel overlay: whiteouts are 0/0 character devices,
  `rm -rf dir && mkdir dir` gives an opaque dir (`user.overlay.opaque`), `mv` of a host dir is
  copy + whiteout (EXDEV, no redirect_dir). (6c-2, FS-15)
- `podman rmi <repo:tag>` on an image that has another tag only untags ("Untagged: …"); the
  image stays, and `<repo>@<digest>` still resolves through the remaining tag. (8-prC, Q25)
- Killing the `podman exec` client (SIGKILL or SIGTERM) leaves the exec'd command running in the
  container. An exec'd process's host parent is the exec session's `conmon`, outside the
  container's pid namespace; crun gives each exec its own session through a short-lived
  intermediate that calls `setsid` (the process's sid names a pid that is already gone).
  `podman exec C <args…>` parses nothing after the container: `--privileged` there is a command
  name. A missing command or `--workdir` exits 127; a signal exits 128+N. (Task 11, Q32)
- `/proc/<container init pid>/root` is openable by the user after `podman start` (keep-id). A
  write through it into a `:O` staged mount lands in the upper directory (owned by the user in
  the container's view), the host lower stays byte-identical, and the container sees the change;
  an unlink there leaves a whiteout. (Task 11, Q29)
- ACL presence from an `O_PATH` fd: `fgetxattr` on it fails `EBADF`. `getxattr` on
  `/proc/self/fd/<n>` works and names the held object (the magic link is not re-resolved from a
  guest path); a size-0 query answers `ENODATA` with no ACL (probed on ext4). `ENOTSUP`, a file
  system without ACL support, is documented, not probed. An unprivileged owner can set `system.posix_acl_access` with `setxattr` and a raw
  version-2 blob (no `setfacl` needed in tests). (Task 11, Q39)
- An `O_PATH` open raises no inotify `IN_OPEN` (kernel 6.18); opening `/proc/self/fd/<n>` of
  that fd for read or write does, and reaches the same inode, with the kernel's access check
  run again. A test can watch `IN_OPEN` to prove a file was never opened. (Task 11, re-review)
- File leases (`F_SETLEASE`): the file's owner (or `CAP_LEASE`) can take one, so a sandbox can
  on files of its own uid (keep-id). Another process's open that conflicts gets `EWOULDBLOCK`
  at once with `O_NONBLOCK`; without it, it blocks until the holder releases or
  `/proc/sys/fs/lease-break-time` (45 s by default) passes. Either way the holder gets `SIGIO`,
  whose default action ends it. `fs.leases-enable` is 1 by default. Rust has no lease call
  without `unsafe` or a new crate: the Q40 test uses a `python3 -I -c` holder. (Task 11, Q40)
- A FIFO in a read-only bind is still a channel to the host: with a host process reading a FIFO
  in a folder bound `:ro` (`--read-only --cap-drop=all --userns=keep-id
  --security-opt=no-new-privileges --network=none`, the base Alpine image), `echo … > /m/f`
  inside exited 0 and the host reader got the bytes; the container's mount table showed `/m`
  `ro`. Opening a FIFO writes no file, so `ro` does not refuse it, as for `connect` on a socket.
  (Podman 4.9.3, kernel 6.18 WSL2, ext4; scratch probe for the threat model's FIFO row)
- `podman build` keeps intermediate layer images (`<none>` in `images -a`) unless
  `--layers=false`. `ps --filter name=` is an unanchored regex: match names with `grep -E '^…'`.
  (8-prC)
- Labels on 4.9.3: `create --label k=v` is accepted with `--network=none`. `ps --all --format
  json` gives each container's `Names` as an array and `Labels` as an object, or `null` when it
  has none; an empty listing is `[]`. The template `{{index .Labels "k"}}` prints an empty value
  for a missing label (`{{.Label "k"}}` is an error), but a label value can hold a newline, so
  the sweep reads the JSON. (Task 12 PR A, ruling Q64)
- A container's `ps` `.Labels` include its image's labels (an `nvidia/cuda` base image's
  `maintainer` and `org.opencontainers.image.*` appear beside the `--label` ones), so their size
  is the image author's. `{{json (index .Labels "k")}}` prints one JSON string per container:
  the value for a present label, `"x\ny"` on one line for a value holding a newline, and `""`
  both for a missing label and for a container with no labels at all. The orphan sweep lists
  with that template. (#173, ruling Q307)
- `ps --format '{{json .ID}}'` prints the 12-digit short ID; with `--no-trunc` it prints all 64
  lowercase hex digits, which is what the sweep lists and passes to `rm` (a name can be re-used
  between the listing and the removal; an ID cannot). (Task 12 PR A, review PS-L5)
- A `-v src:dst:…,rbind` on 4.9.3 rootless carries a mount made below `src` in podman's own
  mount namespace (`podman unshare mount --bind`) into the container; the product's `…,bind`
  does not. RT-FS-16's control is that one word. (#122)
- `create --rm --init --timeout N` on 4.9.3 rootless, then `init`, then `start` (the order of
  `launch/start.rs`): `podman inspect` shows `.Config.Timeout` = N, and conmon's argv carries
  `--timeout=N`. The value is not in the OCI `config.json`. The clock starts at `init`, when
  conmon is spawned, not at `start`: with N = 8, create at 0 s, init at 6 s and start at 12 s,
  the container was gone at 14–15 s. A container frozen with `podman pause` (how the disk
  watchdog freezes one) is killed at its deadline too, and the `--rm` cleanup then removes it
  with no podman process left running. Q60 assumed the clock starts at `start`; it starts at
  `init`. (#92, Q60, Q194)
- A rootless podman whose `XDG_RUNTIME_DIR` has no `bus` socket (the daemon tests' private
  runtime directory) warns "no systemd user session" and falls back to cgroupfs; its OCI config
  then has no `linux.cgroupsPath`, which the launcher's config check refuses
  (`config-mismatch`). Linking the user's own `$XDG_RUNTIME_DIR/bus` into the private directory
  restores the systemd cgroup manager. (#99, `tests/daemon.rs`)
- `podman save --format oci-archive` then `podman load` into another store keeps the image ID
  but not the `.Digest`: a test that runs an image from a private store names the digest that
  store reports after the load. (#99)
- Podman 4.9.3 rootless (cgroup v2, crun 1.14.1) accepts `--cpus` above the host's CPU count:
  `--cpus 34` on a 32-CPU host creates, starts and exits 0. Only the manifest validator bounds
  `runtime.cpus` by the host (`HostEnv.nproc`). (#99, the line 1 test)
- An image's working directory, missing below a bind's guest path, is created by the runtime
  in the host folder at `init` when the argv leaves the working directory to the image, through
  a read-only bind too (`ro` and `brokered`). Shown by the control of
  `rt_fs_02_the_image_working_directory_creates_nothing_in_a_mount` (`LeaveOut::Workdir`) on
  every `make redteam` run; the launcher's `--workdir /` stops it. (PR #223, RT-FS-02)
- A volume an image declares below a bind's guest path is created in the host folder at `init`,
  through a read-only bind too, unless `--image-volume=ignore`. Shown by the control of
  `rt_fs_02_an_image_volume_creates_nothing_in_a_mount` (`LeaveOut::ImageVolume`) on every
  `make redteam` run. (PR #223, RT-FS-02)
- A link in the image above a later mount destination (`/workspace/b -> /workspace/a`, mounts
  `/workspace/a` then `/workspace/b/c`) is followed while the runtime places the mounts: it
  creates `c` inside the first mount's host folder, for an `ro`, a `brokered` and an `rw` first
  mount. Shown by the control of `rt_fs_02_an_image_link_at_or_above_a_mount_creates_nothing`
  (`LeaveOut::Probe`: the product argv run with no probe) on every `make redteam` run. (PR #230)
- Measured once (Podman 4.9.3, crun, rootless; PR #230): a link at a destination
  (`/workspace/q -> /workspace/p/made-by-link`) makes the runtime itself refuse at `init`; a
  link at `/etc`, `/run` or `/dev` makes `init` fail; a link at `/tmp` lets `init` succeed.
  Nothing landed outside Podman's storage in any of these.
- Measured once (same setup, PR #230), the mount-link probe: about 150 to 200 ms added per
  launch, warm; the first keep-id create from an image takes about 350 ms either way. It leaves
  no container and no volume; the id-mapped copy of the image's top layer that the first keep-id
  create makes is reused by the real create. The probe and the real container, created from one
  digest reference, show the same image id. Through the probe's root with
  `RESOLVE_IN_ROOT|RESOLVE_NO_SYMLINKS`, a link at or above a destination gives `ELOOP` and an
  absent path `ENOENT`; with `O_NOFOLLOW` a link as the last component would open, so the walk
  never uses it.

## Kernel and namespaces

- A pty in canonical mode keeps at most 4095 bytes of a line and drops the rest without an
  error; the newline still ends the line. A read of 4095 data bytes therefore cannot be told
  from a cut line, so the `secrets set` prompt takes at most 4094 (`TTY_MAX_VALUE_BYTES`;
  pinned by `the_prompt_takes_4094_bytes_and_refuses_more` at 4094, 4095, 5000 and 8192).
  `tcsetattr(TCSAFLUSH)` on return discards the rest of a multi-line paste. (Task 12 PR C2, Q114)

- In a `--network=none` sandbox: TCP/UDP to public addresses → ENETUNREACH; raw sockets → EPERM;
  ICMP ping sockets → EACCES at creation (`ping_group_range`); inference role → ENOSYS (seccomp).
  In a fresh netns with `lo` down, raw ICMPv6 send gives EADDRNOTAVAIL (99), not 101. (6c-2, NET-08)
- `fgetxattr` of a `trusted.*` name as an unprivileged user returns ENODATA, not EACCES. (6c-2)
- Unprivileged `mknod` of a 0/0 character device (an overlay whiteout) works (kernel ≥ 5.8). (6c-2)
- `user.*` xattrs on a tmpfs need kernel ≥ 6.6; unit tests that set them live under `target/`.
- `pids.peak` is not on every kernel; fall back to `pids.current`. (6c-2 review)
- WSL: `/proc/sys/fs/binfmt_misc/WSLInterop` (flags `PF`, interpreter `/init`) marks interop;
  the host's `cmd.exe` is `/mnt/c/Windows/System32/cmd.exe`. (6c-2a, FS-11)
- WSL: a Windows drive is a 9p mount. `statfs` gives `f_type` `0x01021997` (`V9FS_MAGIC`, `stat
  -f` prints `v9fs`) for the drive root and for a folder under it; `/proc/self/mountinfo` names
  the type `9p` with the drive as the source (`C:\`). The WSL driver share `/usr/lib/wsl/drivers`
  is 9p too (source `drivers`), so the kind alone does not tell a drive from that share or from
  any other 9p mount. `/mnt/wsl` and `/mnt/wslg` are tmpfs; `/` is ext4 (`0xef53`). Read with
  `stat -f` and mountinfo only, nothing on the drives opened. (Kernel 6.18 WSL2; Windows-drive
  denylist probe)
- `/proc/self/mountinfo` lines are `id parent major:minor root mount-point options [optional
  fields…] - type source super-options`; the optional fields (`shared:N`, `master:N`) may be
  absent. Here the table is 35 lines (~4 KB); `/mnt/c`, `/mnt/e` and `/usr/lib/wsl/drivers` have
  type `9p`, and there is no FUSE mount (only `fusectl`, FUSE's control filesystem).
  `statx(fd, "", AT_EMPTY_PATH, STATX_MNT_ID)` on an `O_PATH` handle gives the table's first
  field (the reusable id, not `STATX_MNT_ID_UNIQUE`): sally-core's paths.rs tests find the
  fixture root's line, and `/proc`'s, by it. An open descriptor holds its mount's id: in
  `unshare -Urm`, a tmpfs with a descriptor held in it (id 507) was lazily unmounted (its line
  left the table, the descriptor still said 507) and five tmpfs mounted at the same place got
  508, 509, 510, 511 and 531; after the descriptor closed, the next mount got 507 again.
  (Kernel 6.18 WSL2; virtiofs type-name follow-up)
- A non-dumpable process (`PR_SET_DUMPABLE 0`) still binds and chmods a socket through
  `/proc/self/fd/<dirfd>/<name>`. Its `/proc/<pid>` directory keeps its own owner; the entries
  under it (`fd/`, `status`, …) become root's, so other processes of the same user cannot read
  them. `/proc/<pid>/limits` and `status` stay world-readable. Opening `/proc/<init>` of a
  session container from a non-dumpable `sallyd` is proven when a session starts through the
  binary (Task 12 PR B). (Task 12, `tests/daemon.rs`)
- A folder bound on its own child (`mount --bind a/b a/b/x`, in a private mount namespace under
  `podman unshare`): `stat` gives `a/b/x` the identity of `a/b`, `a/b/x/..` gives `a/b` again
  (`..` from a mount root climbs to the mount point's parent), and `a/b/x/../..` gives `a`. So
  an identity walk with `..` reads one identity twice before the real parent, and must not take
  a repeat for `/`. (Kernel 6.18 WSL2, Podman 4.9.3; RT-AG-08b)
- `socketpair` with a family the kernel does not support for pairs is the kernel's own error,
  never `ENOSYS`: measured once, before the profile filtered `socketpair`, the workspace's
  `socketpair(AF_VSOCK, SOCK_STREAM, 0)` gave errno 95 (`EOPNOTSUPP`). So RT-NET-12's `ENOSYS`
  for every refused `socketpair` family can only come from the profile; its `AF_UNIX` pairs are
  made in every role on every `make redteam` run. (PR #226; kernel version not recorded)

## Busybox (test image)

- `yes` exits 1 silently on ENOSPC; prove the error with a following `dd`. (6c-2, AG-09)
- A busybox copy named `sh` treats `sh id -u` as a script path: use `sh -c 'id -u'`. (6c-2a)
- `awk 'BEGIN { s = "x"; while (1) s = s s }'` is a reliable memory bomb (no python in the image).
- Alpine's busybox `nc` has no `-U`: reach a Unix socket with `sally-shim --stdio <sock>`. The
  image has `nslookup` and `getent` but no `/etc/resolv.conf`, `curl` or `python3`. (Task 8)
- Busybox 1.36.1 `wget` through a proxy (`http_proxy`/`https_proxy`) sends an absolute-form
  `GET https://host/path` for an `https://` URL too, never `CONNECT`, so the egress proxy
  answers 405; the image's `ssl_client` is only reached without a proxy. `nc` can send a raw
  `CONNECT` and print the status line. (#99, architect Q218)
- BusyBox 1.36.1 `pgrep -x NAME` compares the full `argv[0]`: a process started as
  `/usr/local/bin/sally-shim` is not found by `pgrep -x sally-shim` (and `pkill -x` kills
  nothing, silently). `pgrep -f` matches the calling `sh -c` too. Match `/proc/<pid>/comm`
  exactly. A process killed in the net image stays a zombie (the entry `exec`s `sleep`, which
  never reaps), so skip `State: Z` when checking it is gone. Its port is free at once. (Task 8,
  RT-NET-10)

## hyper (1.12, HTTP/1 server)

- hyper answers a head it refuses with its own `400` (malformed head, differing duplicate
  `Content-Length`, a bad header line) or `431` (oversize head) and never calls the service: no
  audit entry could precede that reply. `llm.sock` therefore reads and decides on the head
  itself and gates hyper's writes. (Task 7, `llm/probe_tests.rs`)
- hyper and the broker both parse with `httparse` 1.10's default request config: both accept
  bare-LF line ends and a leading empty line, and both refuse obs-fold continuation lines,
  whitespace before the colon and a bare CR. hyper accepts a repeated equal `Content-Length`
  (the broker refuses it) and a `Transfer-Encoding: chunked` beside `Content-Length` (chunked
  wins; the broker refuses it); it refuses `Transfer-Encoding: identity` with a 400. (Task 7,
  `hyper_never_reads_an_accepted_head_differently`)
- With `half_close` off (the default), hyper calls the service for a complete request whose
  peer has already shut its write side, then drops the service future at the read EOF (a
  service that waits never finishes) and the reply: the peer gets nothing. The shim passes a
  client's half-close on, so `llm.sock` sets `half_close(true)` (architect ruling Q14): then the
  service runs to its end and the peer gets the reply, but a read EOF no longer cancels the
  service, so a peer that is gone is noticed only at the first write (#60). (Task 7,
  `hyper_never_answers_a_half_closed_peer`, `half_close_decides_whether_a_half_closed_peer_is_served`)
- hyper writes the interim `100 Continue` for `Expect: 100-continue` when the service first
  polls the body. On `llm.sock` that is before the request's entry, so the gate drops it: a
  client that waits for the 100 sends its body after its own timeout (curl: 1 s) instead.
  Nothing reaches the peer before the entry. (Task 7 security review)
- Busybox `wget` (the test image) does not half-close: its requests through the shim are
  answered. (Task 7, `tests/rpc.rs`)

## Host network state (/proc)

- `/proc/net/fib_trie` lists each IPv4 address as a `|-- <ip>` leaf followed by `/<len> <scope>
  <type>` lines; an address the host owns has `/32 host LOCAL`. The leaf `127.0.0.0` (of
  127.0.0.0/8) carries `/8 host LOCAL` (the loopback route), `127.0.0.1` its own `/32 host LOCAL`; broadcast leaves
  are `/32 link BROADCAST`. The table appears twice (`Main:` and `Local:`). About 1.3 KiB on WSL2.
- `/proc/net/if_inet6`: one line per IPv6 address, 32 hex digits then index, prefix length,
  scope, flags and the interface name. Absent when IPv6 is disabled. (Task 8, `egress/hostaddrs.rs`)
- Seen on WSL2 (kernel 6.18): `fib_trie` holds only table headers, `+-- <ip>/<len> <n> <n> <n>`
  nodes, `|-- <ip>` leaves and route lines; several route lines can follow one leaf (`/32 host
  LOCAL` then `/32 link BROADCAST`); the connected network is `/<len> link UNICAST` and the
  default route `/0 universe UNICAST`. `ipv6_route` lines have ten fields (destination, length,
  source, length, next hop: hex; metric, reference count, use count, flags: 8 hex digits each;
  interface); the unreachable default on `lo` has flags `00200200` (`RTF_REJECT` 0x200 set),
  a local `/128` `80200001`. Not seen here and taken from the kernel's printing code, unverified:
  a `tos=<n>` field after the type, an unknown scope as `scope=<n>`, an unknown type as `type
  <n>` (two tokens: the parser refuses the list), an interface index of three or more hex digits
  in `if_inet6` (printed `%02x`), an `ipv6_route` line with no interface name. (Connected-network
  filter, `egress/hostaddrs.rs`)
- `fib_trie` has no gateway column, and its scope does not tell a gateway route from a device
  route. Probe in a scratch user network namespace (WSL2 kernel 6.18, iproute2 6.1). `<a>` to
  `<g>` stand for distinct documentation and benchmark prefixes; `<gw>` is an address in `<a>`:

  | Route added | `fib_trie` line |
  |---|---|
  | `<a>/24 dev d0 proto kernel` (from the address) | `/24 link UNICAST` |
  | `<b>/24 dev d0` (plain device route) | `/24 link UNICAST` |
  | `<c>/24 dev d0 scope global` | `/24 universe UNICAST` |
  | `<d>/24 nhid 1` (nexthop object, `dev d0` only) | `/24 universe UNICAST` |
  | `<e>/25 nexthop dev d0 nexthop dev d0` (multipath, device legs) | `/25 universe UNICAST` |
  | `<f>/25 via <gw>` (through a gateway) | `/25 universe UNICAST` |
  | `throw <g>/24` | `/24 universe THROW` |

  So the filter reads no scope: every IPv4 route line of length 8 to 32 counts, the drop types
  and `THROW` excepted, and a specific prefix through a gateway is refused too. Lengths 0 to 7
  are default-like and ignored (a full-tunnel VPN's two half-space `/1` routes). Not probed:
  how routing daemons and VPN agents install their routes. (Connected-network filter,
  `every_probe_table_row_counts_but_throw_and_default_like_routes` in
  `egress/hostaddrs_tests.rs`)
- A Unix socket path over 107 bytes fails `bind` with `InvalidInput` ("path must be shorter than
  SUN_LEN"); the test fixture's `CARGO_TARGET_TMPDIR` paths exceed it. Binding through
  `/proc/self/fd/<dir fd>/<name>` of an `O_PATH` directory works and keeps the name short.
- glibc 2.39, `hosts: files dns` (strace of `getent ahosts`): `localhost` is answered from
  `/etc/hosts` with no packet sent. The absolute `localhost.` is **not** matched by the files
  backend; it goes out as a DNS query to the resolv.conf server. Other NSS sources may still
  answer a dotted name (systemd-resolved reads `/etc/hosts`; nss-myhostname, nss-mdns), so the
  absolute lookup only removes the search list: the address filter stays the control. A
  hermetic test may only resolve the relative `localhost` through real `getaddrinfo`, and only
  where `files` comes first and `/etc/hosts` names it (Task 8, `egress/net.rs`).

## X.509 name constraints (session CA)

- rcgen 0.14 (`ring`) emits `basicConstraints` CA:TRUE pathlen:0 and `nameConstraints`, both
  critical, with `keyUsage` keyCertSign only. (AMENDMENTS-01 §11 item 4; Task 9a)
- A permitted `dNSName` `host` also permits every subdomain of `host` (RFC 5280): OpenSSL 3.0.13
  (`openssl verify`, Python `ssl`) and rustls-webpki 0.103 accept a leaf for `a.host`. A leaf
  for an unlisted name fails with "permitted subtree violation" / `NameConstraintViolation`.
- Adding an excluded `dNSName` `.host` (leading dot) refuses the subdomains while `host` itself
  still verifies, in OpenSSL 3.0.13, Python `ssl`, rustls-webpki 0.103, GnuTLS 3.8.3 and Go 1.22
  alike.
- Path length 0 on the trust anchor: OpenSSL 3.0.13 refuses root → second CA → leaf ("path
  length constraint exceeded"), and so do GnuTLS 3.8.3 and Go 1.22 ("too many intermediates
  for path length constraint"); rustls-webpki 0.103 accepts it, because a webpki trust anchor
  keeps only subject, key and name constraints. Its name constraints still bind the whole
  chain. So pathlen 0 binds OpenSSL, GnuTLS and Go clients (curl, Python, git, Node, Go
  programs), not rustls ones; prove it with those, never with a rustls verifier.
- GnuTLS (Task 9a-2, RT-SEC-10): `certtool --verify --load-ca-certificate=ca.pem
  --infile=chain.pem --verify-hostname=<name> --verify-purpose=<id-kp-serverAuth OID>` (chain: the
  leaf first, then intermediates; `--verify-hostname` takes an IP address too). Exit 0 and
  "Verified. The certificate is trusted." for the grant leaf; exit 1 for every rogue chain with
  "The certificate chain violates the signer's constraints." for a name constraint and for the
  path length alike (GnuTLS reports neither which constraint nor the depth).
- Go (`tests/redteam/tls/verify.go`, `crypto/x509` `Verify` with `DNSName`, which takes an IP
  too, and `ExtKeyUsageServerAuth`): "DNS name … is not permitted by any constraint", "is
  excluded by constraint \".mock.test\"", "IP address … is excluded by constraint
  \"0.0.0.0/0\"". Built offline with `GOTOOLCHAIN=local GOPROXY=off GOTELEMETRY=off` and
  `GOPATH`/`GOCACHE` under the test's directory.
- `openssl verify` loads the default store too unless given `-no-CApath -no-CAstore`; IP names
  need `-verify_ip`, not `-verify_hostname`. Python `ssl.create_default_context(cafile=…)` loads
  that file only (no system roots); `server_hostname` takes an IP address.
- Searching a container for key material: libcrypto and OpenSSL's `loader_attic.so` contain the
  bare string `PRIVATE KEY`; match the armor `PRIVATE KEY-----` instead.

## hyper 1.12 HTTP/1 (intercepted tunnels)

Raw bytes into `server::conn::http1` over a duplex (Task 9a-2; architect Q51–Q53). Committed as
tests in `egress/intercept_tests.rs` where the behaviour matters to the proxy.
- `Transfer-Encoding: chunked` with `Content-Length`: the service sees only `transfer-encoding`;
  hyper drops `Content-Length` and reads the body chunked.
- `Content-Length` twice with the same value: merged into one. Different values, `1, 1` and
  `+1`: hyper answers 400 itself (`Parse(Header(ContentLengthInvalid))` on the conn future).
- `Transfer-Encoding: gzip` (no final chunked): 400 by hyper. `gzip, chunked`, `Chunked` and two
  `chunked` lines reach the service unchanged.
- Absolute-form, `*`, `CONNECT` inside the connection, HTTP/1.0, no `Host` and two `Host` all
  reach the service. obs-fold is 400, 101 headers and a 9 KiB head are 431, all by hyper.
- `header_read_timeout` needs `.timer(TokioTimer)`. It runs from when hyper starts waiting for
  a head: before the first byte and during keep-alive idle too, not from the head's first byte.
  Expiry is `Error::is_timeout()` with no reply. Consequence: an intercepted keep-alive tunnel
  idle for `limits.head` (10 s) between requests is closed; accepted for v1, revisit in #64.
- A body that fails on its first poll while the response head still sits in hyper's write
  buffer: hyper drops the unflushed head with the connection, so the client sees nothing at all,
  not a head and a cut. Which one a client sees depends on whether the body data was already
  there when the head was written; a test of a cut must accept both.
- `half_close` defaults to false: a client that shuts its sending side right after a request
  gets no response. The proxy sets it true (a spliced tunnel carries half-close too).
- `max_buf_size` is checked only after a read leaves the head incomplete, and one read can fill
  all spare buffer capacity (`io.rs` reads into the whole `chunk_mut()`), so with `max_buf_size`
  alone a head can pass well over it (a 65.5 KiB response head passed `max_buf_size(64 KiB)`).
  `max_header_size` is checked both on a partial head (`curr_len >= max`) and on a complete one
  (`parsed_len > max`, `role.rs`), so it is an exact cut whatever the reads: with it at 7168 /
  61440, heads of 7168 / 61440 bytes pass and 7169 / 61441 are refused, whole or split (Task
  9a-2 part 2; part 1 had read it as checked between reads only). `Meter::max_read` stays as
  defense in depth.
- The client accepts equal duplicate response `Content-Length`s, as two lines or one `6, 6`
  list, and keeps every line in the `HeaderMap`; differing ones fail its parse
  (`content_length_parse_all`, `headers.rs`). With `Transfer-Encoding: chunked` it reads chunked
  and keeps the `Content-Length` header too. `rewrite::response` refuses all of these. (9a-2 R4)
- The server never writes `Content-Length` on a 204 or 304 (`can_have_content_length`); a HEAD
  answer keeps it. `Incoming::size_hint().exact()` on a client response is `Some(0)` for HEAD,
  204 and 304, whatever the header says. (9a-2 R5)
- Two requests pipelined behind a `Connection: close` response: in 15 of 15 runs the second was
  never read (the tunnel closed after the first response), so the "upstream gone before the
  entry" branch needs a direct test (`upstream_ready`). (9a-2 R1)
- `SendRequest::ready()` errs once the client connection future is dropped, without any I/O. A
  handshake over a `duplex` whose connection future is dropped gives a closed sender. (9a-2 R1)
- A connection future that completed cleanly but is kept does **not** fail `ready()`: after a
  `Connection: close` response it stays pending, after keep-alive plus EOF it is `Ok` and
  `send_request` never completes (no `want::Taker` cancel on a clean shutdown). Drop the
  connection future when it completes. (9a-2 rust re-review H1, reviewer's probe)
- A response for which the server disabled keep-alive mid-exchange (`graceful_shutdown`) carries
  hyper's own `connection: close`, and a pipelined request behind it is never read. (9a-2 H1)
- `graceful_shutdown` on the server keeps reading a head it holds part of only on the
  connection's **first** request (`KA::Busy` until a head parses, `conn.rs`). It closes at once
  when the keep-alive state is `Idle` (a partial head after a finished exchange is dropped) or
  when nothing has reached hyper's read buffer yet (`dispatch.rs` `disable_keep_alive`, even if
  bytes wait in the transport). A test of a head refused after the upstream ended must let hyper
  buffer part of the first head before the upstream hangs up; `select!`'s random branch order
  otherwise makes it pass or fail by chance (10 of 30). (9a-2 RQ1)

## Replies through sally-shim (#71)

- On Linux loopback TCP a reset does **not** discard a reply the client already received: a
  server that read 8 KiB, answered and closed on 0.1–20 MiB of unread request still had its
  reply read 60 of 60 times. The kernel is not where RT-NET-09's 431 went.
- Through the shim it is lost: when `sallyd` closes on a client still sending, the shim's
  client→socket thread gets `EPIPE`, and `copy_half` shuts down **both** directions of the TCP
  stream, racing the socket→client thread that is relaying the reply. A Unix-socket server that
  answers and closes, behind the real `sally-shim` in a private network namespace (`unshare
  -rn`), 100 KiB request line: 21 of 200 replies empty. With a bounded drain after the reply
  (read until EOF, 256 KiB or 1 s): 0 of 200. The fix is the drain in `write_reply`.
- #76 then fixed the shim itself: a failed write stops only its own direction, and after a failed
  write toward the socket the shim discards the client's bytes until its end, and past its end
  waits for the reply to be relayed, all within the linger from that write. RT-NET-09 asserts
  the 431 for 20 MiB of headers through busybox `nc`. The final test passed 30 of 30 runs on
  the shim before its half-close fix (the client's EOF no longer ends the discard's bound) and
  10 of 10 on the merged shim; earlier versions of the test passed 13 of 13.
  Shutting the TCP read side instead of discarding would not do: after the shim's FIN, Linux
  resets a client that sends on, and busybox `nc` dies on that failed write.
- A TCP socket that is shut down and then closed sends a reset only if unread bytes are still
  queued at `close()`. If a thread drains the queue after `shutdown(Both)` (a read returns the
  queued bytes, then 0), the close is clean. A client whose window toward that socket was 0 then
  gets only ACKs to its probes, no reset, until `tcp_fin_timeout` (60 s here). So the shim's
  linger and discard deadline stop reading at the cut (a shared `cut` flag) instead of draining.
  (#76 review, 5 of 249 under 3×nproc busy loops before the flag)
- busybox `nc` does **not** exit on network EOF while its stdin is open; it runs until its input
  ends. A test that times the server's close from inside the sandbox uses `sally-shim --stdio`,
  which exits when the server closes. (RT-NET-09 slowloris, Q235)
- The shim bounds its writes toward the client with `SO_SNDTIMEO` = the linger (#155). That
  timeout is **per call**, not per stall. A TCP writer blocked on a full send queue is woken only
  when about a third of the queue is free (free space at least half of what is queued). A call
  that copied some bytes returns them when its timeout runs out; one that copied none returns
  `EAGAIN`, even if room appeared meanwhile without waking it. Toward a client that never reads,
  zero-window probes and receive-queue collapse let the client's kernel take a few KiB more now
  and then, so the write fails some lingers after it first blocked, not one. Measured on WSL2
  6.18 (`tcp_rmem` max 32 MiB, `tcp_wmem` max 4 MiB), 16 KiB writes toward a client that sent a
  request, half-closed and never reads: at a 300 ms linger, the call that filled the queue
  returned 12800 bytes after 0.30 s and the next got `EAGAIN` 0.32 s later; at 1 s, 3584 bytes
  after 1.01 s, then 94.7 KiB went in at once, 12800 bytes after 1.02 s, `EAGAIN` 1.02 s later
  (the same timing on 8 of 8 runs, 3 of them with a client that neither reads nor sends).
  At the shipped 30 s linger (the real shim, one slot, a flooding Unix-socket server, a client
  that never reads, in `unshare -rn`), one run: 3584 bytes after 31.4 s, 12800 after 30.7 s,
  `EAGAIN` 30.7 s later; the server's write failed 92.9 s after the connect and the slot was
  back at 123.3 s.
  The shim's tests therefore time a mute client's cut from the server's failed write, which
  happens when the shim's write fails, never in multiples of the linger.

## Test writing

- `dd of=<name>` while a renamer cycles names loses data when `mv` replaces a re-created name;
  write through fds opened before the renamer starts. (6c-2a churn)
- Host `git status` rewrites the index unless `GIT_OPTIONAL_LOCKS=0`; set it when a test compares
  `.git` before and after. (6c-2, FS-12)
- The pre-commit guard blocks Windows user-profile paths in test files; use `C:\ProgramData`.
  (6c-2a)
- Any 127/8 address binds on `lo` with no setup (Linux and WSL2); connects to it get source
  `127.0.0.1`. A per-test loopback address gives a test a port no other test can take. (#23)
- "Bind `:0`, close, re-bind" is not a free-port check in a multithreaded test binary: a listener
  closed while a sibling test's child is forking stays LISTEN until that child execs, so the
  port is still taken (and can accept your connect). Use a fixed port on a private address. (#23)
- `accept()` reserves its descriptor number before blocking; `/proc/<pid>/fd` does not list it.
  To force EMFILE, set the soft limit to the lowest free number (`prlimit --pid P --nofile=N:`
  keeps the hard limit, so it can be raised again). (#36 shim)

## Fuzz crate on pinned stable

- `fuzz/` is a detached crate; `make lint`'s clippy never builds it, so a removed `pub` item it
  imports fails only CI's `fuzz` job (#165). `cargo check --locked --manifest-path
  fuzz/Cargo.toml --bins` works on the pinned stable toolchain: libfuzzer-sys's build script
  compiles libFuzzer with the host C++ compiler, no nightly or sanitizer needed for a check.
  About 8 s from an empty `--target-dir` of its own (`target/fuzz-check`), about 0.1 s warm
  with nothing changed, and it fails with
  E0432 on `escape_target` re-added to `egress_head.rs`'s imports. (architect Q265)

## llama.cpp GGUF read path (for the strict parser)

Read at llama.cpp commit a49db739fba21964e5a05c4d8c35e352b293242e (2026-11-17), files
`ggml/include/ggml.h`, `ggml/src/ggml.c` (`type_traits`), `ggml/src/ggml-common.h` (block
structs, each with a `static_assert` on its size), `ggml/include/gguf.h`, `ggml/src/gguf.cpp`
(`gguf_init_from_reader`), `src/llama-model.cpp` (`load_hparams`, `llama_model_chat_template`),
`src/llama-impl.cpp` (`gguf_data_to_str`, `gguf_kv_to_str`). No engine is pinned yet; M3
reconciles the type table with the pin (#182).
- ggml types: 36 live ids, 0–43 without 4, 5, 31–33, 36–38 (removed; their `type_traits`
  entries are placeholders with block size 0). `GGML_TYPE_COUNT` = 44. Ids 40–43 (NVFP4, Q1_0,
  Q2_0, F8_E4M3) are the newest.
- gguf value types 0–12; an array's element type is read like any type, and an array of arrays
  is refused ("invalid GGUF type").
- Version 0 and 1 refused, above 3 refused, `(version & 0xFFFF) == 0` refused as a byte-order
  mismatch. Versions 2 and 3 parse the same way.
- Keys: empty and duplicate refused; no length limit beyond 1 GiB per string; compared as C
  strings. Bool: any nonzero byte is true. `general.alignment`: must be u32, nonzero, power of 2.
- Tensor names: length must be < 64 (`GGML_MAX_NAME`), duplicates refused. `n_dims ≤ 4`, each
  `ne ≥ 0` (zero allowed), element count overflow checked, `ne[0] % block_size == 0`.
- Offsets: no per-tensor alignment check; instead each offset must equal the running total
  (first 0, each next = previous + `GGML_PAD(nbytes, alignment)`), so the data is contiguous.
- String values (the chat template included) reach the engine's callers through
  `std::string::c_str()`, so the engine sees only the text before a NUL.
- `split.count` > 1 makes the model loader (`src/llama-model-loader.cpp`) derive the sibling
  shard paths (`*-0000N-of-0000M.gguf`) and open them from the same directory.
- `load_hparams` copies every non-array metadata value into the model's key/value map as text
  (`gguf_kv_to_str`: u32 42 → `"42"`, bool → `"true"`/`"false"`, f32 via `std::to_string`,
  strings unchanged) and skips arrays. `llama_model_chat_template` returns the map's text for
  the template key; without one it returns no template, except the built-in name
  `mistral-v7-tekken` for an unnamed lookup on a Tekken pre-tokenizer with 40 layers. So a
  scalar `tokenizer.chat_template` reaches the engine as template text, and an array one is
  dropped (the engine acts as if the key were absent). Not read: how `src/llama-arch.cpp` formats
  the template key names, the second half of `src/llama-model-loader.cpp`, and what the
  server uses when the model has no template; nothing here is claimed about them.
- The strict parser is narrower on purpose: zero dims, zero tensors, bool bytes other than 0/1,
  alignment below 8, non-printable keys, NUL in names and templates, a chat-template key whose
  value is not a string, and `split.count` other than a u16 of 0 or 1 are refused.

## Hugging Face Hub API shapes (for the HF client)

Read 2026-11-18 from the `huggingface_hub` Python client's source (client code only; nothing
was requested from the Hub, and its server behaviour is inferred from what the client handles).
- `model_info` calls `/api/models/{repo_id}/revision/{revision}` with the revision URL-quoted with
  no safe characters, and adds `blobs=true` for file metadata. The answer's `sha` is the commit;
  the client types it as an optional string and states no format (Sallyport requires 40 lowercase
  hex and refuses anything else). Each `siblings[]` entry has `rfilename`, `size`, `blobId`, and
  `lfs` (`size`, `sha256`, `pointerSize`) only for LFS files; absent or null otherwise.
- `resolve/` answers a redirect for an LFS file. The client handles any 3xx with a `Location`
  and follows a relative one on the same host. It hardcodes no CDN host name, so the redirect
  hosts were not confirmed from this source. The rule ships with the two domains `huggingface.co`
  and `hf.co` and their subdomains (the LFS CDN and the Xet bridge are known to sit under
  `hf.co`). The first live pull should record the hosts it saw here; a host outside both domains
  is refused and means a design question, not a wider rule.
- On a redirect to another host the client drops `Authorization`. Resume is `Range: bytes=N-`; a
  416 is an error. The client sends `Accept-Encoding: identity` on its metadata HEAD only.
- Nothing in the client handles 429 or `Retry-After`; its backoff retries 503 only. Sallyport
  waits on 429, or 503 with a delta-seconds `Retry-After`, as its own bounded choice.
- The client's repo-id check allows an optional namespace and a name of 1 to 96 `[\w.-]`
  (Unicode word characters too) with `--` and `..` refused. Sallyport is stricter: exactly
  `namespace/name`, ASCII only, each part starting with a letter or digit.
