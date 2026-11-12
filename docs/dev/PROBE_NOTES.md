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
