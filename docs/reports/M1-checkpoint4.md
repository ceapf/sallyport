# M1 Checkpoint 4: egress and the token proxy (Tasks 8, 9a-1 to 9b)

Status: **waiting for the maintainer's review.** The Task 9b PR (branch `m1/basic`), which
carries this report, stays draft until the go. Its CI verdict is in the PR, read with the
`statusCheckRollup` command in CLAUDE.md at the PR's head.

Local gates at `c2dc099`, the last code commit (this report is the only commit after it):
- `make lint test`: green, including `cargo deny`.
- `make redteam`: 112/112 `rt_` tests in 79 s; then the WSL-only `rt_fs_11` ran on its own and
  passed (1/1).

Task 9 shipped in four PRs: 9a-1 #57 (session CA, CA files, trust roots), 9a-2 #74
(interception, no injection), 9a-3 #97 (injection and response redaction), 9b, the PR carrying
this report (`{basic}`,
RT-SEC-01, 02 and 12, RT-SEC-07 over every form, this report). Task 8 (the CONNECT proxy) is
#44 and #50; RT-NET rows are in §3.

## 1. Session CA

Normative text: `ARCHITECTURE.md §7` (Session CA). Evidence: `crates/sallyd/src/egress/ca_tests.rs`
(every parameter), `rt_sec_09` (leaf per grant host, live) and `rt_sec_10` (rogue leaves in five
verifiers, key reach).

| Parameter | Value |
|---|---|
| Key | ECDSA P-256, generated per session, only in `sallyd` memory (`Secret`), dropped after the leaves are minted |
| CA | `basicConstraints` CA:true, pathlen 0; `keyUsage` keyCertSign; EKU serverAuth |
| Name constraints (critical) | permitted `dNSName` = each grant host; excluded `.<host>` (left out where another grant host lies beneath it), `0.0.0.0/0`, `::/0` |
| Validity | launch time rounded down to the second, to that + `runtime.timeout` + 5 min |
| Leaves | one per grant host at launch: one SAN, EKU serverAuth, digitalSignature, not a CA, own P-256 key, the CA's validity |
| Files | `session-ca.pem` and `ca-bundle.pem` (trust roots re-encoded, then the CA), 0444, `O_EXCL`, in the workspace socket directory only, mounted read-only at `/run/sallyport` |

### Decoded sample chain (illustrative)

Illustrative only; the tests above are the evidence. Made at commit `422527a` by a throwaway
program outside the repository (deleted afterwards). The program called the launcher's own entry,
`SessionTls::mint(&["api.github.com", "github.com"], Validity::for_session(now, 90 min))`, and
wrote the certificates (never a key) as PEM. Each was decoded with
`openssl x509 -text -noout -certopt no_pubkey,no_sigdump`. `openssl verify -CAfile ca.pem`
accepts both leaves. `github.com` beside `api.github.com` shows the exclusion rule: `.api.github.com`
is excluded and `.github.com` is not, because a grant host lies beneath it. The serial numbers
and key identifiers are shown as `<…>` placeholders, because their colon-separated hex trips the
repository's identifier guard; everything else is the decoded output as printed.

```text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            <20 random bytes>
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN = Sallyport session CA
        Validity
            Not Before: Nov 13 15:34:12 2026 GMT
            Not After : Nov 13 17:09:12 2026 GMT
        Subject: CN = Sallyport session CA
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign
            X509v3 Extended Key Usage:
                TLS Web Server Authentication
            X509v3 Name Constraints: critical
                Permitted:
                  DNS:api.github.com
                  DNS:github.com
                Excluded:
                  DNS:.api.github.com
                  IP:0.0.0.0/0.0.0.0
                  IP:0:0:0:0:0:0:0:0/0:0:0:0:0:0:0:0
            X509v3 Subject Key Identifier:
                <the CA key's identifier, 20 bytes>
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            <20 random bytes, not the CA's>
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN = Sallyport session CA
        Validity
            Not Before: Nov 13 15:34:12 2026 GMT
            Not After : Nov 13 17:09:12 2026 GMT
        Subject: CN = github.com
        X509v3 extensions:
            X509v3 Authority Key Identifier:
                <equal to the CA's Subject Key Identifier>
            X509v3 Subject Alternative Name:
                DNS:github.com
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage:
                TLS Web Server Authentication
            X509v3 Subject Key Identifier:
                <the leaf key's own identifier, 20 bytes>
            X509v3 Basic Constraints: critical
                CA:FALSE
```

The validity is 95 minutes: the 90-minute timeout plus the 5-minute grace.

### Client matrix (RT-SEC-10)

Each rogue leaf is signed by a CA built with the production `ca::ca_params` and verified offline.
"refused" means refused for the control under test; the test checks the reason text.

| Leaf | rustls (webpki) | OpenSSL | Python `ssl` | GnuTLS | Go |
|---|---|---|---|---|---|
| grant host (positive control) | verified | verified | verified | verified | verified |
| unlisted name | refused: name constraint | refused: permitted subtree | refused: permitted subtree | refused: signer's constraints | refused: not permitted |
| `sub.<grant>` | refused: name constraint | refused: excluded subtree | refused: excluded subtree | refused: signer's constraints | refused: excluded |
| IP SAN | refused: name constraint | refused: excluded subtree | refused: excluded subtree | refused: signer's constraints | refused: excluded |
| CN only, no SAN | refused: no valid names | refused: permitted subtree | refused: permitted subtree | refused: signer's constraints | refused: legacy Common Name |
| wildcard `*.<grant>` | refused: name constraint | refused: excluded subtree | refused: excluded subtree | refused: signer's constraints | refused: excluded |
| root → second CA → leaf | **verified** (webpki ignores an anchor's pathlen; name constraints still bind) | refused: path length | refused: path length | refused: signer's constraints | refused: path length |

The live leg verifies the session's real leaf with Python over `net.sock`: it passes for the
grant host and fails for another name.

## 2. Interception and header rules

Normative text: `ARCHITECTURE.md §7` (interception, credentials and redaction).

- **Route.** `CONNECT host:443` to a grant host is intercepted. Every other allowed host is
  spliced untouched. Plain HTTP to any host is 405 `plain-http-unsupported`, before policy.
- **TLS.** Towards the workspace: the session-CA leaf, ALPN `http/1.1` only. Upstream: rustls
  against the system roots, SNI = host, the address Task 8 pinned, TLS 1.2 and 1.3. The upstream
  handshake completes before the `200`; a failure is 502 `upstream-tls-failed`. One upstream
  connection per tunnel, reused sequentially (Q28).
- **Request.** HTTP/1.1 through hyper, one request at a time. Origin-form only. Exactly one
  `Host`, equal to the CONNECT authority, else 421 `host-mismatch`. TRACE is 405 and any
  `Upgrade` is refused. Framing: `Transfer-Encoding` absent or one `chunked`, never beside a
  `Content-Length`.
- **Dropped request headers.** `Accept-Encoding`, `Range`, `If-Range`, `Request-Range`,
  hop-by-hop headers, `Proxy-*`, and every client copy of a grant header.
- **Injection.** The grant header is set only after the request's `egress.request` entry is
  written. A `{value}` format takes the secret; `{basic}` takes RFC 7617's base64 of
  `basic_user:secret` (Task 9b).
- **Response.** `Content-Encoding` must be absent or exactly one `identity`, else 502
  `upstream-encoded` (R1, Q10). `Transfer-Encoding` beside a `Content-Length`, or a
  `Content-Length` other than one decimal value, is 502 `upstream-malformed` (R4). Redirects
  are returned, never followed. Trailers are never forwarded. The reason phrase is hyper's
  canonical one.
- **Head limits.** A request head passes if it is at most 7168 bytes and a response head if
  it is at most 61440 (hyper's `max_header_size`, exact: 9a-2 A1).
- **Redaction.** Every header and body of every response on every grant host, with every form
  of every session secret, at the same length (§4). A form in a header name, or in its `: `,
  refuses the response with 502 `upstream-echoed-secret`.
- **Audit.** `egress.response` per forwarded response: names and byte counts, never a value.

## 3. Red-team rows

All are CI rows, run by `make redteam` and the `redteam` job.

| Row | Test | File |
|---|---|---|
| RT-NET-01 | `rt_net_01_direct_tcp_and_udp_find_no_route` | `sallyd/tests/roles.rs` |
| RT-NET-02 | `rt_net_02_a_denied_name_is_never_resolved_inside_or_by_the_host` | `sallyd/tests/egress.rs` |
| RT-NET-03 | `rt_net_03_a_host_off_the_list_is_refused_and_the_upstream_sees_nothing` | `egress.rs` |
| RT-NET-04 | `rt_net_04_an_allowed_host_on_another_port_is_refused` | `egress.rs` |
| RT-NET-05 | `rt_net_05_only_the_request_target_decides_and_ip_literals_are_refused` | `egress.rs` |
| RT-NET-06 | `rt_net_06_wildcards_match_whole_labels_after_normalization` | `egress.rs` |
| RT-NET-07 | `rt_net_07_names_that_resolve_to_internal_or_own_addresses_are_refused` | `egress.rs` |
| RT-NET-08 | `rt_net_08_raw_sockets_and_icmp_fail` | `roles.rs` |
| RT-NET-09 | `rt_net_09_a_thousand_connections_leave_the_proxy_bounded`, `rt_net_09_oversized_heads_slow_clients_and_too_many_connections_are_limited` | `egress.rs` |
| RT-NET-10 | `rt_net_10_replacing_the_shim_gains_nothing` | `egress.rs` |
| RT-NET-11 | not yet: lands with the daemon (Task 12, lane B) | — |
| RT-NET-12 | `rt_net_12_socket_families_outside_the_role_list_fail` | `roles.rs` |
| RT-SEC-01 | `rt_sec_01_no_process_environment_or_command_line_holds_a_secret` (9b) | `sallyd/tests/secrets_reach.rs` |
| RT-SEC-02 | `rt_sec_02_no_file_in_either_container_holds_a_secret` (9b) | `secrets_reach.rs` |
| RT-SEC-03 | `rt_sec_03_a_credential_reaches_only_its_own_grant_host` | `sallyd/tests/intercept.rs` |
| RT-SEC-04 | `rt_sec_04_a_client_copy_of_the_grant_header_never_reaches_the_grant_host` | `intercept.rs` |
| RT-SEC-05 | `rt_sec_05_a_redirect_is_returned_unfollowed_and_its_target_gets_no_credential` | `intercept.rs` |
| RT-SEC-06 | `rt_sec_06_an_echo_in_body_and_header_is_redacted_at_the_same_length` | `intercept.rs` |
| RT-SEC-06b | `rt_sec_06b_compression_is_stripped_and_an_encoded_echo_is_refused` | `intercept.rs` |
| RT-SEC-07 | `rt_sec_07_no_audit_entry_holds_a_credential` (every form from 9b) | `intercept.rs` |
| RT-SEC-08 | `rt_sec_08_secret_values_cannot_enter_through_the_manifest`, `rt_sec_08_original_rows` | `sally-core/tests/rt_manifest.rs` |
| RT-SEC-09 | `rt_sec_09_a_grant_host_gets_a_session_ca_leaf_and_any_other_host_its_own_chain` | `intercept.rs` |
| RT-SEC-10 | `rt_sec_10_rogue_leaves_of_a_session_ca_fail_in_every_verifier`, `rt_sec_10_no_private_key_reaches_a_container_and_the_harness_gets_no_ca_file` | `sallyd/tests/session_ca.rs` |
| RT-SEC-11 | `rt_sec_11_the_workspace_holds_only_the_placeholder` | `intercept.rs` |
| RT-SEC-12 | `rt_sec_12_every_encoded_echo_split_across_chunks_is_redacted` (9b) | `intercept.rs` |
| RT-SEC-13 | `rt_sec_13_plain_http_to_a_grant_host_is_never_forwarded` | `intercept.rs` |
| RT-SEC-14 | `rt_sec_14_no_broker_descriptor_reaches_podman_or_a_container` | `sallyd/tests/fds.rs` |

Invariants exercised: SI-1 (NET-01, 08, 12), SI-3 (SEC-01..07, 10, 11, 12, 14), SI-4 (SEC-07,
the `egress.*` entries in NET and SEC rows), SI-9 (NET-02..07, SEC-09, 13).

Checked by removing the control, then reverted (9b): without the held-back overlap of
`redact::Stream`, RT-SEC-12 fails; without the `{basic}` blob forms, RT-SEC-12 fails; a `{basic}`
blob planted in place of the marker is found by RT-SEC-01's search. Earlier rows: each test's doc
comment names its control, as recorded in #57, #74 and #97.

## 4. Redaction forms

Every form of every secret of the session, on every grant host (D4), as the union of all
occurrences, replaced byte for byte by the session's filler: the first of `* # ~ ^ | ! $ @` that
no form holds; a session where none qualifies is refused `secret-filler` (R2, Q7, Q8).

| Form | Since |
|---|---|
| Raw value | 9a-3 |
| Percent-encoding: both hex cases, `+` for space, `/` kept, `!'()*` kept | 9a-3 |
| JSON string escaping | 9a-3 |
| Base64, standard and URL-safe, at all three alignments, trimmed to the secret's own characters (≥ 12) | 9a-3 |
| Each rendered header value (`Bearer …`, `Basic …`) | 9a-3, `Basic` in 9b |
| The `{basic}` blob, padded and unpadded | 9b |

Documented gaps (THREAT_MODEL residual rows): mixed-case hex (`%2f%2F`); base64 forms under 12
characters (a value under about 9 bytes has none; the store flags values under 16 bytes, the CLI
warning is #98); hex, base32, UTF-16, HTML entities, line-wrapped base64; a URL-safe re-encoding
of a `{basic}` blob (only the secret's own characters are covered); partial echoes (a truncated
token, a value split across header lines or responses); anything inside a body the upstream
encodes itself. The filler reveals where an echo was and how long its form was. Redaction
protects against an honest upstream only: a colluding grant host already holds the credential
(decision 6).

## 5. Dependencies added in Task 9

`cargo deny` passes at every PR. `cargo tree -i aws-lc-rs` is empty (ring only).

| Crate | Version | Task | Why |
|---|---|---|---|
| `rcgen` | 0.14.10 (ring, zeroize) | 9a-1 | session CA and leaves |
| `rustls` | 0.23.46 (ring, tls12) | 9a-1 | TLS both ways; upstream verifier |
| `rustls-pki-types` | 1.16.0 | 9a-1 | certificate and key types |
| `pem` | 4.0.0 | 9a-1 | trust-root bundle parse, CA files |
| `time` | 0.3.55 | 9a-1 | certificate validity (rcgen's type) |
| `x509-parser` (dev) | 0.18.1 | 9a-1 | CA parameter tests |
| `tokio-rustls` | 0.26.6 | 9a-2 | TLS on tokio streams |
| `hyper` `client` feature | 1.12.0 | 9a-2 | HTTP/1.1 inside the tunnel (the crate came with Task 7) |
| `zeroize` (direct) | 1.9.1 | 9a-3 | wipe held-back bytes (already in the tree) |

Task 9b adds none: `{basic}` uses the redactor's own base64 encoder
(`sally_core::audit::basic_credential`).

## 6. Mutation and fuzz results

| PR | Mutation (local, wide-sallyd test set) | Fuzz |
|---|---|---|
| #57 | `ca.rs`, `roots.rs`: 56 mutants, 51 caught, 5 unviable, 0 missed | — |
| #74 | interception files: 397 mutants, 257 caught, 133 unviable, 2 missed (killed in the PR), 5 timeouts | `egress_rewrite` 60 s, 1.38M runs, clean |
| #97 | one file per run, 12 files: 0 missed; timeouts only where the nightly has them (#36) | `egress_redact` 121 s, 254,397 runs, clean |
| 9b | one file per run: sally-core `audit/redact.rs` 122 mutants, 79 caught, 43 unviable, 0 missed; `sandbox/launch/error.rs` 3, 2 caught, 1 unviable, 0 missed; `egress/inject.rs` 44, 28 caught, 16 unviable, 0 missed (run again after the review fixes, same result) | no parser changed (`egress_redact` and `egress_rewrite` unchanged); `basic_credential` is an encoder, proven against RFC vectors |

Latest nightly, read with
`gh run list --workflow nightly.yml --limit 1 --json conclusion,createdAt,databaseId`:
**failure 2026-11-12T21:59:57Z 43315682814**. Its three missed mutants (`egress/net.rs` 220,
409, 410) are killed on `main` by #97. Shard 17/24 was cancelled at 45 minutes (#79, lane B).
No nightly has run since.

## 7. Rulings that changed a maintainer decision

One line each. Each is in the PR body that carries it.

- **Label removal** (9a-3, R2 and Q6): decision 2's filler beginning `[REDACTED:NAME]` became a
  run of the session's filler with no name. The name and the byte counts go to the
  `egress.response` entry only. Approved by the maintainer.
- **Identity rule** (9a-3, D6, then R1 and Q10): D6 tightened decision 1 to refuse any
  `Content-Encoding`, `identity` included. R1 relaxed that: none, or exactly one `identity`,
  any case. Anything else is 502 `upstream-encoded`.
- **Filler rule** (9a-3, R2, Q7 and Q8): decision 2's same-length filler became the first of
  `* # ~ ^ | ! $ @` that no form of the session holds, in that fixed order. A session where
  every candidate occurs is refused `secret-filler`.
- **Head limits** (9a-2, A1): "accepted as built" was refined to the exact cut. A request head
  passes if it is at most 7168 bytes, a response head if it is at most 61440, not the 8 and
  64 KiB buffers. The maintainer accepted 7168/61440.
- **Framing cases** (9a-2, R4 and R6): the accepted framing became stricter in one case. A
  response with `Transfer-Encoding` beside `Content-Length`, or a `Content-Length` other than
  one decimal value, is now 502 `upstream-malformed`; before, equal duplicates passed through
  hyper. A request with differing duplicate `Content-Length`s got a test.

## 8. Architect rulings

Recorded in full, as question, ruling and reason, in each PR body:

| PR | Rulings |
|---|---|
| #57 (9a-1) | Q27–Q38 |
| #74 (9a-2) | Q39–Q53, A1–A3, R1–R9, RQ1–RQ4 |
| #97 (9a-3) | D1–D13, Q1–Q13 (on review findings and R1–R4) |
| 9b (this PR) | A1–A8: {basic} forms only (A1); `basic_credential` and the second guard in `render` (A2); `basic-unsupported` deleted (A3); RT-SEC-12 design (A4); RT-SEC-07 over every form (A5); RT-SEC-01/02 in 9b (A6); this sample chain (A7); the amendments folded (A8) |

## 9. Open issues

| Issue | What |
|---|---|
| #45 | `grant-host-unavailable` for a grant host the proxy holds no leaf for: review whether it can still occur |
| #49 | log failed `egress.close` appends and panicked connection tasks |
| #56 | 9a-1 review follow-ups (trust-root audit fields, leaf key copies, `net.rs` layout) |
| #64 | intercepted keep-alive tunnels close after 10 s idle (accepted for v1) |
| #69 | the TLS library's copies of session keys are freed, not wiped |
| #72 | entries in flight at session stop may land after `egress.close` |
| #81, #85 | session secrets in the shared audit writer's redactor (Task 12, lane B) |
| #87 | Task 13: sweep the mutation scope for logic in `fn new` (incl. the guard's G6/G7) |
| #89, #95 | Task 12 egress wiring follow-ups (lane B) |
| #98 | `sally secrets set` warns on a short value (Task 12) |

Closed by 9b: #80 (`{basic}`).

## 10. Sessions used against the plan

Counted from saved session files (one session, one unit). Checkpoint 3 had used 10 units, and
the maintainer set the revised M1 estimate at **about 22**.

| Area since Checkpoint 3 | Sessions |
|---|---|
| Mutation scope and #36 survivors | 6 |
| Task 8 (PR A, PR B ×2, PR C) | 4 |
| Task 9 (9a-1: 1, 9a-2: 4, 9a-3: 3, 9b: 2) | 10 |
| Lane B: Tasks 7, 10, 11, 12 so far | 9 |
| **Total since Checkpoint 3** | 29 |
| **M1 total** | 39 |

M1 has now used 39 units against the revised estimate of about 22, and it is not finished. Two
lanes have run side by side since Task 8, so wall-clock time is lower than the unit count
suggests. Task 9 was planned as four tasks (9a-1, 9a-2, 9a-3, 9b) and took 10 sessions.
Remaining: Task 12 (in progress, lane B), Task 13 and Task 14. The AMENDMENTS-02 cut order (fetch-write approvals,
`{basic}`, the template-mismatch flag, `sally session changes`) was to be revisited here;
`{basic}` has shipped, so it is no longer on the list.

**After the review (maintainer's decisions, recorded in the fetch PR, #75):**
- The cut order is closed and nothing is cut. Fetch-write approvals shipped with the fetch tool
  (#75). The template-mismatch flag is neither cut nor shipped in M1: it is the M2 row of
  AMENDMENTS-01 §9, tracked in #102.
- Reports no longer measure sessions against the 22-unit estimate: with the 45 % context rule
  and two lanes, a session no longer measures effort. From Checkpoint 5 on, reports list the
  tasks remaining instead.
