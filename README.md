# Sallyport

> **Status: pre-alpha. Not ready for use. No security guarantees yet.**
> The security core and a minimal command line are built and tested (milestone M1 of 6, exited
> 24 November 2026). No model runs in Sallyport yet, nothing is released, and the interfaces
> will change. Do not rely on Sallyport to contain anything today.

Sallyport is a desktop suite for running local LLMs and agent harnesses inside rootless Podman
sandboxes. A strict permission manifest says what each session may touch (folders, hosts,
credentials, tools), and a trusted broker, `sallyd`, enforces it. **Security comes from
architecture, never from model behavior:** every sandbox runs with `--network=none`, its only
exits are Unix sockets to the broker, and every tool call, egress connection and approval is
audited.

- **Threat model:** [`THREAT_MODEL.md`](THREAT_MODEL.md)
- **Architecture:** [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- **Manifest format:** [`docs/MANIFEST_SPEC.md`](docs/MANIFEST_SPEC.md)
- **Plan:** [`docs/MILESTONES.md`](docs/MILESTONES.md)
- **Red-team suite:** [`tests/redteam/REDTEAM_SUITE.md`](tests/redteam/REDTEAM_SUITE.md)
- **M1 exit report:** [`docs/reports/M1.md`](docs/reports/M1.md)

## What works today

M1 is the security core with no model in it. On a Linux or WSL2 host with rootless Podman you
can:

- build it and run its tests, including the red-team suite, which runs attacks against real
  containers (`make lint test`, `make redteam`);
- check a host with `sally doctor`;
- validate a manifest and read what it grants in plain English (`sally manifest validate`,
  `sally manifest summary`), using the examples in `manifests/examples/`.

The broker and the command line can also launch a sandbox from a manifest, with brokered file
tools and a shell tool, egress through an allowlist proxy, credentials injected outside the
sandbox, approvals answered on a terminal, and a hash-chained audit log (`sally audit verify`).
There is no published sandbox image yet, so today that path is exercised by the test suite,
which builds its own image.

There is no model, no agent harness, no installer and no UI.

## How it has been checked

- Every M1 row of the red-team suite has a test that runs in CI. Most of those tests have a
  control that shows they can fail; the suite marks the ones that do not yet.
- A mutation gate runs every night.
- A security review of the trusted core ran during M1. It found three high-severity
  weaknesses; all three were fixed and checked again. The findings still open, none of them
  high, are listed in the exit report with the stage each is due.

## Known limits

- **Shared kernel.** Sandboxes are rootless containers. A flaw in the Linux kernel is outside
  what Sallyport defends against. A stronger isolation tier is planned.
- **Same account.** To the kernel a sandbox runs as your own account, so it shares some of your
  account's kernel allowances. A misbehaving sandbox can make your other programs fail until
  its session is stopped. `THREAT_MODEL.md` section 6 lists this and the other accepted risks.
- **Linux and WSL2 only, command line only.**

## What comes next

Next is first light: the first real local model running end to end inside the sandboxes. In
order:

1. Close the security items the exit report lists as due before a real model runs.
2. Sandbox images, the rest of the model library, and the inference container.
3. An agent harness in its own container, with review of staged changes before they reach your
   files.

The full plan is in [`docs/MILESTONES.md`](docs/MILESTONES.md).

## Platform

Linux first; Windows via WSL2. Requires rootless Podman ≥ 4.9 on cgroup v2, and an NVIDIA GPU
with the Container Toolkit (CDI) for GPU inference. `scripts/doctor.sh` checks a host.

## Building

```sh
make lint test
```

The Rust toolchain is pinned in `rust-toolchain.toml`.

## Security

See [`SECURITY.md`](SECURITY.md) for how to report a vulnerability.

## License

Apache-2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE). Third-party material is listed in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md). Contributions carry a DCO sign-off
(`git commit -s`).
