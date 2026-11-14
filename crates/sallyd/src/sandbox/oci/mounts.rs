//! `mounts` (architect Q106, Q112): exactly the argv's `-v` and `--tmpfs` mounts plus podman's
//! standard set, each destination once, each with exactly its type, source and options, and
//! every parent before its children (a later parent would hide what is mounted below it).
//! Options compare as sets: podman repeats some (`/dev/shm`), and none may be added or left out.
//! An overlay's `lowerdir=` is the granted host path, so a swapped lower layer is refused.

use std::collections::{BTreeMap, BTreeSet};

use super::config::Mount;
use super::facts::{Facts, is_clean};
use super::intent::{Intent, Wanted};
use super::process::INIT_GUEST;
use super::{Mismatch, ensure};

/// What a source must be.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Src {
    /// Exactly this string.
    Is(String),
    /// `<static userdata>/overlay/<digits>/merge`: podman's own merge directory for an overlay.
    Merge,
}

/// One mount the config must hold.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Want {
    kind: &'static str,
    source: Src,
    options: BTreeSet<String>,
}

fn want(kind: &'static str, source: &str, options: &[&str]) -> Want {
    Want {
        kind,
        source: Src::Is(source.to_owned()),
        options: options.iter().map(|o| (*o).to_owned()).collect(),
    }
}

/// Options of podman's own read-only binds from the container's userdata directories.
const USERDATA: [&str; 6] = ["bind", "rprivate", "ro", "nosuid", "noexec", "nodev"];

/// Podman's standard mounts for every role (4.9.3, `--init`, `--no-hosts`, `--network=none`).
fn standard(f: &Facts) -> Vec<(String, Want)> {
    let (s, r) = (&f.paths.static_dir, &f.paths.run_dir);
    let nse = ["nosuid", "noexec", "nodev"];
    vec![
        ("/proc".into(), want("proc", "proc", &nse)),
        (
            "/sys".into(),
            want("sysfs", "sysfs", &["nosuid", "noexec", "nodev", "ro"]),
        ),
        (
            "/sys/fs/cgroup".into(),
            want(
                "cgroup",
                "cgroup",
                &["rprivate", "nosuid", "noexec", "nodev", "relatime", "ro"],
            ),
        ),
        (
            "/dev".into(),
            want(
                "tmpfs",
                "tmpfs",
                &["nosuid", "strictatime", "mode=755", "size=65536k", "ro"],
            ),
        ),
        (
            "/dev/pts".into(),
            want(
                "devpts",
                "devpts",
                &[
                    "nosuid",
                    "noexec",
                    "newinstance",
                    "ptmxmode=0666",
                    "mode=0620",
                    "gid=5",
                ],
            ),
        ),
        ("/dev/mqueue".into(), want("mqueue", "mqueue", &nse)),
        (
            "/dev/shm".into(),
            want("bind", &format!("{s}/shm"), &USERDATA),
        ),
        (
            "/etc/passwd".into(),
            want("bind", &format!("{s}/passwd"), &USERDATA),
        ),
        (
            "/etc/group".into(),
            want("bind", &format!("{s}/group"), &USERDATA),
        ),
        (
            "/run/.containerenv".into(),
            want("bind", &format!("{r}/.containerenv"), &USERDATA),
        ),
        (
            "/etc/hostname".into(),
            want("bind", &f.paths.hostname, &USERDATA),
        ),
        (
            INIT_GUEST.into(),
            want("bind", &f.init, &["bind", "ro", "rprivate"]),
        ),
    ]
}

/// Everything the config must mount, by destination.
fn wanted(i: &Intent, f: &Facts) -> Result<BTreeMap<String, Want>, Mismatch> {
    let mut all = standard(f);
    if let Some((size, exec)) = i.tmp {
        let size = format!("size={size}");
        let exec = if exec { "exec" } else { "noexec" };
        all.push((
            "/tmp".into(),
            want(
                "tmpfs",
                "tmpfs",
                &[
                    "rw",
                    exec,
                    "nosuid",
                    "nodev",
                    &size,
                    "rprivate",
                    "tmpcopyup",
                ],
            ),
        ));
    }
    for m in &i.mounts {
        all.push(match m {
            Wanted::Bind { host, guest, rw } => {
                let access = if *rw { "rw" } else { "ro" };
                (
                    guest.clone(),
                    want(
                        "bind",
                        host,
                        &[access, "nosuid", "nodev", "bind", "rprivate"],
                    ),
                )
            }
            Wanted::Overlay {
                host,
                guest,
                upper,
                work,
            } => (
                guest.clone(),
                Want {
                    kind: "overlay",
                    source: Src::Merge,
                    options: [
                        format!("lowerdir={host}"),
                        format!("upperdir={upper}"),
                        format!("workdir={work}"),
                        "private".into(),
                        "userxattr".into(),
                    ]
                    .into_iter()
                    .collect(),
                },
            ),
        });
    }
    let mut out = BTreeMap::new();
    for (dest, w) in all {
        if out.insert(dest.clone(), w).is_some() {
            // The argv checker refuses two mounts at one guest path; this is a bug guard.
            return Err(Mismatch::new(format!("mounts[{dest}]"), "intended twice"));
        }
    }
    Ok(out)
}

/// `<static>/overlay/<digits>/merge`.
fn is_merge(source: &str, f: &Facts) -> bool {
    source
        .strip_prefix(&format!("{}/overlay/", f.paths.static_dir))
        .and_then(|r| r.strip_suffix("/merge"))
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

fn check_one(m: &Mount, w: &Want, f: &Facts) -> Result<(), Mismatch> {
    let field = format!("mounts[{}]", m.destination);
    ensure(m.kind == w.kind, &field, "not the type intended")?;
    let source_ok = match &w.source {
        Src::Is(s) => m.source == *s,
        Src::Merge => is_merge(&m.source, f),
    };
    ensure(source_ok, &field, "not the source intended")?;
    let have: BTreeSet<&str> = m.options.iter().map(String::as_str).collect();
    if let Some(o) = have.iter().find(|o| !w.options.contains(**o)) {
        let o = option_key(o);
        return Err(Mismatch::new(field, format!("option {o} not intended")));
    }
    match w.options.iter().find(|o| !have.contains(o.as_str())) {
        Some(o) => Err(Mismatch::new(
            field,
            format!("option {} missing", option_key(o)),
        )),
        None => Ok(()),
    }
}

/// An option's name without its value (`lowerdir=<paths>` → `lowerdir`): the audit detail
/// names the field, never a host path.
fn option_key(o: &str) -> &str {
    o.split_once('=').map_or(o, |(k, _)| k)
}

/// `parent` is a proper ancestor of `child` (both clean absolute paths).
fn is_ancestor(parent: &str, child: &str) -> bool {
    child
        .strip_prefix(parent)
        .is_some_and(|rest| rest.starts_with('/'))
}

/// Checks the config's mounts against the intent.
///
/// # Errors
/// The first [`Mismatch`].
pub fn check(mounts: &[Mount], i: &Intent, f: &Facts) -> Result<(), Mismatch> {
    let want = wanted(i, f)?;
    let mut seen = BTreeSet::new();
    for m in mounts {
        let field = format!("mounts[{}]", m.destination);
        ensure(
            is_clean(&m.destination),
            &field,
            "not a clean absolute path",
        )?;
        ensure(seen.insert(m.destination.as_str()), &field, "mounted twice")?;
        let w = want
            .get(&m.destination)
            .ok_or_else(|| Mismatch::new(&field, "not intended"))?;
        check_one(m, w, f)?;
    }
    if let Some(d) = want.keys().find(|d| !seen.contains(d.as_str())) {
        return Err(Mismatch::new(format!("mounts[{d}]"), "missing"));
    }
    for (k, later) in mounts.iter().enumerate() {
        if let Some(child) = mounts
            .iter()
            .take(k)
            .find(|m| is_ancestor(&later.destination, &m.destination))
        {
            return Err(Mismatch::new(
                format!("mounts[{}]", later.destination),
                format!("after {}, below it", child.destination),
            ));
        }
    }
    Ok(())
}
