# Sallyport

> **Status: pre-alpha. Not ready for use. No security guarantees yet.**
> The security core is under construction (milestone M1 of 6). Nothing here is released, the
> interfaces will change, and the invariants below are design goals until the red-team suite
> proves each one in CI. Do not rely on Sallyport to contain anything today.

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
