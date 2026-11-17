//! Every default a minimal manifest takes, pinned to MANIFEST_SPEC §1 (architect Q398). An
//! omitted field must mean what the spec says (SI-5: never widened by omission). cargo-mutants
//! does not mutate `Default` impls or literals, so this test is the control on the values: each
//! expected value is written here from the spec, never read from the code.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use sally_core::manifest::{AuditLevel, FetchWrites, GpuLayers, NetworkMode, ShellPolicy, parse};

#[test]
fn a_minimal_manifest_takes_every_default_the_spec_shows() {
    let m = parse(common::HEADER).unwrap();

    // runtime
    assert_eq!(m.runtime.image, None);
    assert_eq!(m.runtime.cpus.millis(), 4000); // 4
    assert_eq!(m.runtime.memory.bytes(), 8_589_934_592); // 8GiB
    assert_eq!(m.runtime.pids, 512);
    assert_eq!(m.runtime.timeout.as_secs(), 7200); // 2h
    assert_eq!(m.runtime.tmp_size.bytes(), 1_073_741_824); // 1GiB
    assert!(!m.runtime.tmp_exec);
    assert_eq!(m.runtime.stage_size.bytes(), 10_737_418_240); // 10GiB

    // model
    assert_eq!(m.model.context, 8192);
    assert_eq!(m.model.gpu_layers, GpuLayers::Auto);

    // filesystem
    assert!(m.filesystem.mounts.is_empty());
    assert!(m.filesystem.deny.is_empty());

    // network
    assert_eq!(m.network.mode, NetworkMode::None);
    assert!(m.network.allow.is_empty());
    assert!(!m.network.acknowledge_unrestricted_egress);
    assert_eq!(m.network.max_request_bytes.bytes(), 8_388_608); // 8MiB
    assert_eq!(m.network.max_response_bytes.bytes(), 67_108_864); // 64MiB
    assert_eq!(m.network.max_connections, 32);

    // secrets
    assert!(m.secrets.is_empty());

    // tools
    assert!(m.tools.builtin.is_empty());
    assert_eq!(m.tools.shell, ShellPolicy::Deny);
    assert!(m.tools.destructive_requires_approval);
    assert_eq!(m.tools.fetch_writes, FetchWrites::Approve);
    assert!(m.tools.acknowledge_unapproved.is_empty());
    assert!(m.tools.mcp.is_empty());

    // approvals
    assert_eq!(m.approvals.timeout.as_secs(), 300); // 5m
    assert_eq!(m.approvals.max_pending, 5);

    // audit
    assert_eq!(m.audit.level, AuditLevel::Full);
}
