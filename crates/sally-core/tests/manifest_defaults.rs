//! Every default a manifest takes when a field is omitted, pinned to MANIFEST_SPEC §1. An
//! omitted field must mean what the spec says (SI-5: never widened by omission).
//! cargo-mutants does not mutate `Default` impls or literals, so this test is the control on
//! the values, and it is what kills the mutants of the named default consts in
//! `manifest/types.rs`. Each expected value is written here from the spec, never read from the
//! code. Every section is destructured without `..`, so a new field fails to compile until it
//! is pinned here too. The defaults of list items are pinned where those items are tested: a
//! brokered mount's approve globs (`manifest_gates.rs`,
//! `brokered_mount_without_approve_needs_approval_for_everything`), an MCP server's `approve`
//! (`manifest_gates.rs`, `mcp_approve_defaults_to_always`) and an allow rule's ports
//! (`manifest_validate.rs`, `network_allow_rules`).
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use sally_core::manifest::{
    Approvals, Audit, AuditLevel, FetchWrites, Filesystem, GpuLayers, Manifest, Model, Network,
    NetworkMode, Policy, Runtime, ShellPolicy, Tools, parse,
};

/// Asserts that every field `m` took from a default holds the spec's value.
fn assert_spec_defaults(m: Manifest) {
    let Manifest {
        api_version: _,
        kind: _,
        name: _,
        description,
        harness,
        runtime,
        model,
        filesystem,
        network,
        secrets,
        tools,
        approvals,
        audit,
        policy,
    } = m;
    assert_eq!(description, None);
    // No harness section = the bundled reference harness.
    assert_eq!(harness, None);

    let Runtime {
        image,
        cpus,
        memory,
        pids,
        timeout,
        tmp_size,
        tmp_exec,
        stage_size,
    } = runtime;
    assert_eq!(image, None);
    assert_eq!(cpus.millis(), 4000); // 4
    assert_eq!(memory.bytes(), 8_589_934_592); // 8GiB
    assert_eq!(pids, 512);
    assert_eq!(timeout.as_secs(), 7200); // 2h
    assert_eq!(tmp_size.bytes(), 1_073_741_824); // 1GiB
    assert!(!tmp_exec);
    assert_eq!(stage_size.bytes(), 10_737_418_240); // 10GiB

    let Model {
        reference: _,
        context,
        gpu_layers,
    } = model;
    assert_eq!(context, 8192);
    assert_eq!(gpu_layers, GpuLayers::Auto);

    let Filesystem { mounts, deny } = filesystem;
    assert!(mounts.is_empty());
    assert!(deny.is_empty());

    let Network {
        mode,
        allow,
        acknowledge_unrestricted_egress,
        max_request_bytes,
        max_response_bytes,
        max_connections,
    } = network;
    assert_eq!(mode, NetworkMode::None);
    assert!(allow.is_empty());
    assert!(!acknowledge_unrestricted_egress);
    assert_eq!(max_request_bytes.bytes(), 8_388_608); // 8MiB
    assert_eq!(max_response_bytes.bytes(), 67_108_864); // 64MiB
    assert_eq!(max_connections, 32);

    assert!(secrets.is_empty());

    let Tools {
        builtin,
        shell,
        destructive_requires_approval,
        fetch_writes,
        acknowledge_unapproved,
        mcp,
    } = tools;
    assert!(builtin.is_empty());
    assert_eq!(shell, ShellPolicy::Deny);
    assert!(destructive_requires_approval);
    assert_eq!(fetch_writes, FetchWrites::Approve);
    assert!(acknowledge_unapproved.is_empty());
    assert!(mcp.is_empty());

    let Approvals {
        timeout,
        max_pending,
    } = approvals;
    assert_eq!(timeout.as_secs(), 300); // 5m
    assert_eq!(max_pending, 5);

    let Audit { level } = audit;
    assert_eq!(level, AuditLevel::Full);

    let Policy {
        signed_by,
        signature,
    } = policy;
    assert_eq!(signed_by, None);
    assert_eq!(signature, None);
}

#[test]
fn a_minimal_manifest_takes_every_default_the_spec_shows() {
    assert_spec_defaults(parse(common::HEADER).unwrap());
}

/// A section that is present but empty takes the same defaults as an omitted one, so a
/// field-level default can never differ from the section's.
#[test]
fn an_empty_section_takes_the_same_defaults() {
    let text = format!(
        "{}runtime: {{}}\nfilesystem: {{}}\nnetwork: {{}}\nsecrets: []\ntools: {{}}\n\
         approvals: {{}}\naudit: {{}}\npolicy: {{}}\n",
        common::HEADER
    );
    assert_spec_defaults(parse(&text).unwrap());
}
