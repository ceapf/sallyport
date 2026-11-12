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
- `podman rmi <repo:tag>` on an image that has another tag only untags ("Untagged: …"); the
  image stays, and `<repo>@<digest>` still resolves through the remaining tag. (8-prC, Q25)
- `podman build` keeps intermediate layer images (`<none>` in `images -a`) unless
  `--layers=false`. `ps --filter name=` is an unanchored regex: match names with `grep -E '^…'`.
  (8-prC)

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
- Alpine's busybox `nc` has no `-U`: reach a Unix socket with `sally-shim --stdio <sock>`. The
  image has `nslookup` and `getent` but no `/etc/resolv.conf`, `curl` or `python3`. (Task 8)
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
- Busybox `wget` (the test image) does not half-close: its requests through the shim are
  answered. (Task 7, `tests/rpc.rs`)

## Host network state (/proc)

- `/proc/net/fib_trie` lists each IPv4 address as a `|-- <ip>` leaf followed by `/<len> <scope>
  <type>` lines; an address the host owns has `/32 host LOCAL`. The leaf `127.0.0.0` (of
  127.0.0.0/8) carries `/8 host LOCAL` (the loopback route), `127.0.0.1` its own `/32 host LOCAL`; broadcast leaves
  are `/32 link BROADCAST`. The table appears twice (`Main:` and `Local:`). About 1.3 KiB on WSL2.
- `/proc/net/if_inet6`: one line per IPv6 address, 32 hex digits then index, prefix length,
  scope, flags and the interface name. Absent when IPv6 is disabled. (Task 8, `egress/hostaddrs.rs`)
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
  still verifies, in OpenSSL 3.0.13, Python `ssl` and rustls-webpki 0.103 alike. GnuTLS (git on
  Debian/Ubuntu) was not tested: no `certtool` on the dev host.
- Path length 0 on the trust anchor: OpenSSL 3.0.13 refuses root → second CA → leaf ("path
  length constraint exceeded"); rustls-webpki 0.103 accepts it, because a webpki trust anchor
  keeps only subject, key and name constraints. Its name constraints still bind the whole
  chain. So pathlen 0 binds OpenSSL clients (curl, Python, git, Node) only; prove it with
  OpenSSL, never with a rustls verifier.

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
