# Probe notes

Behaviours of the tools Sallyport's tests and sandboxes run on, as probed on the dev host
(Podman 4.9.3 rootless, crun, cgroup v2, busybox in the test image). Add to it as you go: one
line per fact, with where it was found. Check a note again before relying on it after an upgrade.

## Podman and crun

- A container's limits (`pids.max`, `memory.max`, `memory.swap.max`) sit in
  `/sys/fs/cgroup/<CgroupPath>/container`, not in the `libpod-<id>.scope` itself (that shows the
  host default). `<CgroupPath>` is `podman inspect --format '{{.State.CgroupPath}}'`. (6c-2, AG-09)
- With only `--memory`, swap is unlimited beyond it on cgroup v2 hosts with swap (the OCI config
  showed swap = 2 × memory). Sallyport sets `--memory-swap` equal to `--memory`. (Checkpoint 3)
- On an OOM kill, the container's conmon writes an empty `oom` file into the working directory of
  the podman that *started* the container (`podman exec` does not). Hermetic podman runs from its
  state directory for that reason. (6c-2)
- `userdata/config.json` (`podman inspect --format '{{.OCIConfigPath}}'`) is subuid-owned under
  keep-id: read it with `podman unshare cat`. (6c-2)
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

## Kernel and namespaces

- In a `--network=none` sandbox: TCP/UDP to public addresses → ENETUNREACH; raw sockets → EPERM;
  ICMP ping sockets → EACCES at creation (`ping_group_range`); inference role → ENOSYS (seccomp).
  In a fresh netns with `lo` down, raw ICMPv6 send gives EADDRNOTAVAIL (99), not 101. (6c-2, NET-08)
- `fgetxattr` of a `trusted.*` name as an unprivileged user returns ENODATA, not EACCES. (6c-2)
- Unprivileged `mknod` of a 0/0 character device (an overlay whiteout) works (kernel ≥ 5.8). (6c-2)
- `user.*` xattrs on a tmpfs need kernel ≥ 6.6; unit tests that set them live under `target/`.
- `pids.peak` is not on every kernel; fall back to `pids.current`. (6c-2 review)
- WSL: `/proc/sys/fs/binfmt_misc/WSLInterop` (flags `PF`, interpreter `/init`) marks interop;
  the host's `cmd.exe` is `/mnt/c/Windows/System32/cmd.exe`. (6c-2a, FS-11)

## Busybox (test image)

- `yes` exits 1 silently on ENOSPC; prove the error with a following `dd`. (6c-2, AG-09)
- A busybox copy named `sh` treats `sh id -u` as a script path: use `sh -c 'id -u'`. (6c-2a)
- `awk 'BEGIN { s = "x"; while (1) s = s s }'` is a reliable memory bomb (no python in the image).

## Test writing

- `dd of=<name>` while a renamer cycles names loses data when `mv` replaces a re-created name;
  write through fds opened before the renamer starts. (6c-2a churn)
- Host `git status` rewrites the index unless `GIT_OPTIONAL_LOCKS=0`; set it when a test compares
  `.git` before and after. (6c-2, FS-12)
- The pre-commit guard blocks Windows user-profile paths in test files; use `C:\ProgramData`.
  (6c-2a)
