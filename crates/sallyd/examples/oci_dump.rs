//! `oci-dump`: the checkpoint-report summary of a live container's OCI config (Task 14, #15;
//! architect Q115). It runs no podman itself; capture the config and pipe it in:
//!
//! ```sh
//! podman unshare cat "$(podman inspect --format '{{.OCIConfigPath}}' <container>)" \
//!   | cargo run -q -p sallyd --example oci_dump
//! ```
//!
//! It parses with the verifier's strict parser, so a config with a field the verifier does not
//! know (hooks or devices of GPU inference, say) prints that field and exits non-zero. The home
//! directory is printed as `$HOME` in every path, as the public repository rules require.
#![forbid(unsafe_code)]

use std::io::Read as _;
use std::process::ExitCode;

use sallyd::sandbox::oci::config::{Config, MAX_CONFIG, parse};

fn main() -> ExitCode {
    let mut bytes = Vec::new();
    let read = std::io::stdin()
        .take(
            u64::try_from(MAX_CONFIG)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut bytes);
    if let Err(e) = read {
        eprintln!("oci-dump: stdin: {e}");
        return ExitCode::FAILURE;
    }
    match parse(&bytes) {
        Ok(c) => {
            let home = std::env::var("HOME").unwrap_or_default();
            print!("{}", summary(&c, &home));
            ExitCode::SUCCESS
        }
        Err(m) => {
            eprintln!("oci-dump: not accounted for: {m}");
            ExitCode::FAILURE
        }
    }
}

/// `p` with a leading `home` written as `$HOME`.
fn redact(p: &str, home: &str) -> String {
    match p.strip_prefix(home) {
        Some(rest) if !home.is_empty() && (rest.is_empty() || rest.starts_with('/')) => {
            format!("$HOME{rest}")
        }
        _ => p.to_owned(),
    }
}

fn summary(c: &Config, home: &str) -> String {
    let p = &c.process;
    let caps = &p.capabilities;
    let all_caps: Vec<&String> = [
        &caps.bounding,
        &caps.effective,
        &caps.inheritable,
        &caps.permitted,
        &caps.ambient,
    ]
    .into_iter()
    .flatten()
    .collect();
    let mut out = String::new();
    let mut line = |s: String| {
        out.push_str(&s);
        out.push('\n');
    };
    line(format!(
        "user: uid {} gid {} groups {:?} umask {:?}",
        p.user.uid, p.user.gid, p.user.additional_gids, p.user.umask
    ));
    line(format!("capabilities: {all_caps:?}"));
    line(format!("noNewPrivileges: {}", p.no_new_privileges));
    line(format!("root read-only: {}", c.root.readonly));
    let ns: Vec<&str> = c.linux.namespaces.iter().map(|n| n.kind.as_str()).collect();
    line(format!("namespaces: {}", ns.join(", ")));
    line(format!(
        "seccomp: default {} ({} rules)",
        c.linux.seccomp.default_action,
        c.linux.seccomp.syscalls.len()
    ));
    let r = &c.linux.resources;
    line(format!(
        "limits: memory {:?} swap {:?} cpu quota {:?}/{:?} pids {:?}",
        r.memory.and_then(|m| m.limit),
        r.memory.and_then(|m| m.swap),
        r.cpu.and_then(|c| c.quota),
        r.cpu.and_then(|c| c.period),
        r.pids.map(|p| p.limit)
    ));
    for l in &p.rlimits {
        line(format!("rlimit: {} {}/{}", l.kind, l.soft, l.hard));
    }
    line("hooks: none (a hooks key would not parse)".to_owned());
    line(format!("mounts: {}", c.mounts.len()));
    for m in &c.mounts {
        let opts: Vec<String> = m
            .options
            .iter()
            .map(|o| match o.split_once('=') {
                Some((k, v)) => format!("{k}={}", redact(v, home)),
                None => o.clone(),
            })
            .collect();
        line(format!(
            "  {} {} {} [{}]",
            m.destination,
            m.kind,
            redact(&m.source, home),
            opts.join(",")
        ));
    }
    out
}
