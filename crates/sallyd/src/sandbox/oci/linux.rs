//! `root`, `hostname`, `annotations` and `linux`: namespaces, id mappings, cgroup resources and
//! path, seccomp, masked and read-only paths (architect Q105, Q107–Q109, Q112).

use std::collections::BTreeMap;

use super::config::{Cpu, IdMap, Linux, Memory, Pids, Resources, Root};
use super::facts::Facts;
use super::intent::Intent;
use super::{Mismatch, ensure, seccomp};
use crate::sandbox::profile;

/// Every container gets its own namespace of each type, joined from no path.
pub const NAMESPACES: [&str; 7] = ["pid", "network", "ipc", "uts", "mount", "user", "cgroup"];
/// Podman's default masked paths (4.9.3); the config may mask more, never fewer.
pub const MASKED: [&str; 12] = [
    "/proc/acpi",
    "/proc/kcore",
    "/proc/keys",
    "/proc/latency_stats",
    "/proc/timer_list",
    "/proc/timer_stats",
    "/proc/sched_debug",
    "/proc/scsi",
    "/sys/firmware",
    "/sys/fs/selinux",
    "/sys/dev/block",
    "/sys/devices/virtual/powercap",
];
/// Podman's default read-only paths (4.9.3); more are allowed, never fewer.
pub const READONLY: [&str; 6] = [
    "/proc/asound",
    "/proc/bus",
    "/proc/fs",
    "/proc/irq",
    "/proc/sys",
    "/proc/sysrq-trigger",
];
/// `--cpus` becomes a quota per this period (microseconds).
const CPU_PERIOD: u64 = 100_000;
/// Hex digits of the id podman uses as the hostname when the argv sets none.
const SHORT_ID: usize = 12;
/// What podman writes for SIGTERM, the default stop signal.
const SIGTERM: &str = "15";
/// The highest signal number.
const MAX_SIGNAL: u8 = 64;

/// A read-only root, at the container's own rootfs directory.
///
/// # Errors
/// The first [`Mismatch`].
pub fn check_root(r: &Root, f: &Facts) -> Result<(), Mismatch> {
    ensure(r.readonly, "root.readonly", "not set")?;
    ensure(
        r.path == f.paths.rootfs,
        "root.path",
        "not the container's rootfs",
    )
}

/// `--hostname`, or the short container id when the argv sets none.
///
/// # Errors
/// A [`Mismatch`] on `hostname`.
pub fn check_hostname(h: &str, i: &Intent, f: &Facts) -> Result<(), Mismatch> {
    let short = f.paths.id.get(..SHORT_ID).unwrap_or_default();
    let want = i.hostname.as_deref().unwrap_or(short);
    ensure(h == want, "hostname", "not the hostname intended")
}

/// The stop signal annotation: `15` when the image names none; a decimal 1..=64 or `SIGTERM`
/// otherwise, anything else unaccounted for (architect Q108).
fn stop_signal(image: Option<&str>) -> Result<String, Mismatch> {
    let Some(s) = image else {
        return Ok(SIGTERM.to_owned());
    };
    if s == "SIGTERM" {
        return Ok(SIGTERM.to_owned());
    }
    match s.parse::<u8>() {
        Ok(n) if (1..=MAX_SIGNAL).contains(&n) && n.to_string() == s => Ok(s.to_owned()),
        _ => Err(Mismatch::new(
            "image.StopSignal",
            "not a decimal 1..=64 or SIGTERM (refused until #117)",
        )),
    }
}

/// Exactly podman's annotations for these containers, with the session's seccomp profile.
///
/// # Errors
/// The first [`Mismatch`].
pub fn check_annotations(
    a: &BTreeMap<String, String>,
    i: &Intent,
    f: &Facts,
) -> Result<(), Mismatch> {
    let seccomp = i.profiles.join(i.role.profile());
    let want: BTreeMap<&str, String> = [
        ("io.container.manager", "libpod".to_owned()),
        ("io.podman.annotations.autoremove", "TRUE".to_owned()),
        ("io.podman.annotations.init", "TRUE".to_owned()),
        ("io.podman.annotations.label", "disable".to_owned()),
        (
            "io.podman.annotations.seccomp",
            seccomp.to_string_lossy().into_owned(),
        ),
        (
            "org.opencontainers.image.stopSignal",
            stop_signal(f.image.stop_signal.as_deref())?,
        ),
    ]
    .into_iter()
    .collect();
    for (k, v) in a {
        let field = format!("annotations.{k}");
        match want.get(k.as_str()) {
            None => {
                return Err(Mismatch::new(
                    field,
                    "not one podman sets for this container",
                ));
            }
            Some(w) => ensure(w == v, &field, "not the value intended")?,
        }
    }
    match want.keys().find(|k| !a.contains_key(**k)) {
        Some(k) => Err(Mismatch::new(format!("annotations.{k}"), "missing")),
        None => Ok(()),
    }
}

/// The `linux` section.
///
/// # Errors
/// The first [`Mismatch`].
pub fn check(l: &Linux, i: &Intent, f: &Facts) -> Result<(), Mismatch> {
    check_namespaces(l)?;
    check_map(&l.uid_mappings, i.ids.uid, "linux.uidMappings")?;
    check_map(&l.gid_mappings, i.ids.gid, "linux.gidMappings")?;
    ensure(
        l.resources == resources(i)?,
        "linux.resources",
        "not the limits the argv set",
    )?;
    ensure(
        l.cgroups_path == format!("user.slice:libpod:{}", f.paths.id),
        "linux.cgroupsPath",
        "not this container's systemd scope",
    )?;
    let want = seccomp::expected(profile(i.role), f.arch)
        .map_err(|e| Mismatch::new("linux.seccomp", e.to_string()))?;
    ensure(
        l.seccomp == want,
        "linux.seccomp",
        "not the role's embedded profile",
    )?;
    for (field, have, want) in [
        ("linux.maskedPaths", &l.masked_paths, &MASKED[..]),
        ("linux.readonlyPaths", &l.readonly_paths, &READONLY[..]),
    ] {
        if let Some(p) = want.iter().find(|p| !have.iter().any(|h| h == *p)) {
            return Err(Mismatch::new(field, format!("{p} missing")));
        }
    }
    Ok(())
}

fn check_namespaces(l: &Linux) -> Result<(), Mismatch> {
    let mut seen = Vec::new();
    for ns in &l.namespaces {
        let field = format!("linux.namespaces.{}", ns.kind);
        ensure(
            NAMESPACES.contains(&ns.kind.as_str()),
            &field,
            "not a namespace type expected",
        )?;
        ensure(!seen.contains(&ns.kind.as_str()), &field, "listed twice")?;
        ensure(ns.path.is_none(), &field, "joins an existing namespace")?;
        seen.push(ns.kind.as_str());
    }
    ensure(
        seen.len() == NAMESPACES.len(),
        "linux.namespaces",
        "a namespace type is missing",
    )
}

/// The keep-id shape (architect Q105): exactly one mapping covers host id 0 (the user), and it
/// is `{id → 0, size 1}`; no mapping is empty or overflows; no two overlap inside or outside.
fn check_map(maps: &[IdMap], id: u32, field: &str) -> Result<(), Mismatch> {
    let mut ranges = Vec::new();
    for m in maps {
        ensure(m.size >= 1, field, "an empty mapping")?;
        let end = |start: u32| {
            start
                .checked_add(m.size - 1)
                .ok_or_else(|| Mismatch::new(field, "a mapping overflows"))
        };
        let inside = (m.container_id, end(m.container_id)?);
        let outside = (m.host_id, end(m.host_id)?);
        if m.host_id == 0 {
            ensure(
                m.container_id == id && m.size == 1,
                field,
                "host id 0 is not the session id alone",
            )?;
        }
        ranges.push((inside, outside));
    }
    let overlap = |a: (u32, u32), b: (u32, u32)| a.0 <= b.1 && b.0 <= a.1;
    for (k, (ia, oa)) in ranges.iter().enumerate() {
        for (ib, ob) in ranges.iter().skip(k + 1) {
            ensure(
                !overlap(*ia, *ib) && !overlap(*oa, *ob),
                field,
                "two mappings overlap",
            )?;
        }
    }
    ensure(
        maps.iter().any(|m| m.host_id == 0),
        field,
        "the session id is not mapped to the user",
    )
}

/// The cgroup limits the argv set: memory and swap equal (no swap) when a limit was set, the CPU
/// quota, the pids limit, nothing else.
fn resources(i: &Intent) -> Result<Resources, Mismatch> {
    let big = || Mismatch::new("linux.resources", "a limit does not fit");
    let memory = match i.memory {
        Some(m) => {
            let m = i64::try_from(m).map_err(|_| big())?;
            Some(Memory {
                limit: Some(m),
                swap: Some(m),
            })
        }
        None => None,
    };
    let cpu = match i.cpu_millis {
        Some(ms) => Some(Cpu {
            quota: Some(i64::from(ms).checked_mul(100).ok_or_else(big)?),
            period: Some(CPU_PERIOD),
        }),
        None => None,
    };
    Ok(Resources {
        memory,
        cpu,
        pids: i.pids.map(|n| Pids {
            limit: i64::from(n),
        }),
    })
}
