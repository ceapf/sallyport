# M1 exit report: notes collected along the way

Input for `docs/reports/M1.md` (MILESTONES §M1 step 14). Each note goes into the report's
open-risks or findings section when it is written; this file is then deleted.

## Security finding: the user's `mounts.conf` reached every container (Task 14, #15)

**What leaked.** An entry `<host dir>:/run/secrets/<name>` in the user's
`~/.config/containers/mounts.conf` was copied by podman into the container's run directory and
bound at `/run/secrets/<name>` in every Sallyport container: workspace, harness and inference.
A system `mounts.conf` (`/etc/containers`, `/usr/share/containers`) would have been read the same
way when no user file existed. Sallyport never writes such a file; the exposure needed one placed
by the user or by another tool running as the user.

**Which commits had it.** Every commit since the first launch path: `de3fbaf` (Task 6b, merged
to `main` as PR #16, `6404d53`, 2026-11-10) up to the merge of the Task 14 PR. #11 (Task 6b, the
same commit) is where podman was claimed hermetic, and its test passed for the wrong reason.

**Why the test missed it.** The #11 test ran `ls /run/secrets` and asserted that "canary" was
absent. `ls` prints only the copied directory's name, never the file inside it, so the test
passed while the canary was mounted. The Task 14 test looks inside (`[ -e ]`, `ls -R`), and a
control proves the same probe finds the canary when the defences are off. #122 sweeps the other
red-team rows that assert absence (Task 13).

**Mechanism.** Podman builds the OCI spec, and with it the `mounts.conf` subscriptions, at
`podman init`, a separate process from `create`. Only `create` got `--default-mounts-file`; the
`default_mounts_file` key of `containers.conf` is ignored on Podman 4.9.3.

**Found by.** The OCI config verifier (RT-SUP-04), the first time it compared a real config with
the argv's intent.

**Fixed by.** Three independent defences, each with a test that fails when it is removed:
- podman's `HOME` is a private empty directory (architect Q118);
- `init` and `start` carry the empty mounts file (Q119);
- the verifier refuses any mount the argv did not ask for.

**Open.**
- Hosts where Podman adds mounts of its own (a system `mounts.conf` if the flag ever stops
  working, FIPS mode) get every launch refused as `config-mismatch`: #121 (M6).
- No advisory: the README states pre-alpha (maintainer ruling 6).
