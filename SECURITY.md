# Security policy

Sallyport is **pre-release** software. There are no supported versions yet and no security
guarantees; the threat model in [`THREAT_MODEL.md`](THREAT_MODEL.md) describes the intended
design, not a promise about the current code.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: on this repository, open the
**Security** tab and choose **Report a vulnerability** (GitHub private vulnerability reporting).
Do not open a public issue for a suspected vulnerability.

Useful reports name the invariant (SI-1 … SI-12 in `CLAUDE.md`) or threat-model row affected, and
include a minimal reproduction. Please redact personal paths and account names from logs
(`scripts/doctor.sh --redact` does this for doctor output).

Reports are acknowledged on a best-effort basis while the project is pre-release.
