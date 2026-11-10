//! `filesystem.*` checks.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use super::super::diag::{Code, Diags};
use super::super::hostenv::HostEnv;
use super::super::paths::{self, Denylist};
use super::super::types::{ApproveGlobs, BuiltinTool, Manifest, MountMode};
use super::ResolvedMount;

const MAX_MOUNTS: usize = 64;
const MAX_GLOBS: usize = 256;
const MAX_GLOB_LEN: usize = 256;

/// Builds the denylist from built-ins plus `filesystem.deny`, reporting malformed entries.
pub(super) fn denylist(m: &Manifest, env: &HostEnv, d: &mut Diags) -> Denylist {
    let extra: Vec<PathBuf> = m
        .filesystem
        .deny
        .iter()
        .enumerate()
        .filter_map(|(i, raw)| match paths::expand(raw, &env.home) {
            Ok(p) => Some(paths::normalize(&p)),
            Err(msg) => {
                d.error(format!("filesystem.deny[{i}]"), Code::InvalidValue, msg);
                None
            }
        })
        .collect();
    Denylist::new(env, &extra)
}

pub(super) fn check_filesystem(m: &Manifest, env: &HostEnv, d: &mut Diags) -> Vec<ResolvedMount> {
    let deny = denylist(m, env, d);
    let mounts = &m.filesystem.mounts;
    if mounts.len() > MAX_MOUNTS {
        d.error(
            "filesystem.mounts",
            Code::OutOfRange,
            format!("at most {MAX_MOUNTS} mounts"),
        );
        return Vec::new();
    }
    let mut resolved = Vec::with_capacity(mounts.len());
    for (i, mount) in mounts.iter().enumerate() {
        let at = |f: &str| format!("filesystem.mounts[{i}].{f}");
        let host = match paths::check_mount_host(&mount.host, &env.home, &deny) {
            Ok((real, _)) if mount.mode != MountMode::Ro && in_git_metadata(&real) => {
                d.error(
                    at("host"),
                    Code::ProtectedPath,
                    format!(
                        "{:?} is inside git metadata, which your host runs (hooks, config); \
                         mount the project directory instead, or use mode: ro",
                        mount.host
                    ),
                );
                None
            }
            Ok(found) => Some(found),
            Err((code, msg)) => {
                d.error(at("host"), code, msg);
                None
            }
        };
        if let Err(msg) = paths::check_guest(&mount.guest) {
            d.error(at("guest"), Code::GuestPath, msg);
        }
        let approve = check_approve(m, mount.mode, mount.approve.as_ref(), &at("approve"), d);
        if let Some((host, id)) = host {
            resolved.push((
                i,
                ResolvedMount {
                    host,
                    guest: mount.guest.clone(),
                    mode: mount.mode,
                    approve,
                    id,
                },
            ));
        }
    }
    check_overlaps(m, &resolved, d);
    resolved.into_iter().map(|(_, r)| r).collect()
}

fn check_approve(
    m: &Manifest,
    mode: MountMode,
    approve: Option<&ApproveGlobs>,
    path: &str,
    d: &mut Diags,
) -> ApproveGlobs {
    match (mode, approve) {
        // Omission never disables a gate (SI-5): no globs = everything needs approval.
        (MountMode::Brokered, None) => ApproveGlobs::everything(),
        (MountMode::Brokered, Some(globs)) => {
            let ops = [
                ("writes", &globs.writes, BuiltinTool::FsWrite),
                ("deletes", &globs.deletes, BuiltinTool::FsDelete),
            ];
            for (kind, list, tool) in ops {
                check_glob_list(&format!("{path}.{kind}"), list, d);
                if list.is_empty() && m.tools.builtin.contains(&tool) {
                    d.warn(
                        format!("{path}.{kind}"),
                        Code::Risky,
                        format!("empty: {} here runs without approval", tool.as_str()),
                    );
                }
            }
            globs.clone()
        }
        (MountMode::Ro | MountMode::Rw, Some(_)) => {
            d.warn(
                path,
                Code::Inconsistent,
                "approve is ignored unless mode is brokered",
            );
            ApproveGlobs::not_applicable()
        }
        (MountMode::Ro | MountMode::Rw, None) => ApproveGlobs::not_applicable(),
    }
}

fn check_glob_list(path: &str, list: &[String], d: &mut Diags) {
    if list.len() > MAX_GLOBS {
        d.error(path, Code::OutOfRange, format!("at most {MAX_GLOBS} globs"));
    }
    for (j, g) in list.iter().enumerate() {
        if let Err(msg) = check_glob(g) {
            d.error(format!("{path}[{j}]"), Code::InvalidValue, msg);
        }
    }
}

/// Git metadata: a realpath with a `.git` component, or a root that is (or is inside) a git
/// directory by structure — bare repos (`proj.git`) and separate git dirs (`--separate-git-dir`,
/// dotfile repos). Writable access there is host code execution (hooks, `core.fsmonitor`), and
/// the in-mount protected-path overlays (`.git/hooks/**`, `.git/config`, AMENDMENTS §6.3) would
/// not match from inside it. Performs a few `lstat`s per ancestor.
fn in_git_metadata(real: &Path) -> bool {
    real.components().any(|c| c.as_os_str() == ".git") || real.ancestors().any(is_git_dir)
}

/// `HEAD` file + `objects/` + `refs/` directories: what git itself checks for a git dir.
fn is_git_dir(dir: &Path) -> bool {
    let kind = |name: &str| std::fs::symlink_metadata(dir.join(name)).ok();
    kind("HEAD").is_some_and(|m| m.is_file())
        && kind("objects").is_some_and(|m| m.is_dir())
        && kind("refs").is_some_and(|m| m.is_dir())
}

/// Globs are relative to the mount root and may not climb out of it.
fn check_glob(g: &str) -> Result<(), String> {
    if g.is_empty() || g.len() > MAX_GLOB_LEN {
        return Err(format!("glob must be 1–{MAX_GLOB_LEN} bytes"));
    }
    if g.starts_with('/') {
        return Err(format!("{g:?} must be relative to the mount"));
    }
    if g.chars().any(char::is_control) {
        return Err(format!("{g:?} contains a control character"));
    }
    if g.split('/').any(|s| s == "..") {
        return Err(format!("{g:?} contains \"..\""));
    }
    Ok(())
}

/// Guests must be unique and non-nested (a nested mount shadows part of another). Hosts must not
/// overlap: a `rw` mount of a parent would bypass a `brokered` child's approvals, and two views
/// of one directory with different modes are never what the user meant.
fn check_overlaps(m: &Manifest, resolved: &[(usize, ResolvedMount)], d: &mut Diags) {
    let mounts = &m.filesystem.mounts;
    let mut seen_guest = HashSet::new();
    for (i, a) in mounts.iter().enumerate() {
        if !seen_guest.insert(a.guest.as_str()) {
            d.error(
                format!("filesystem.mounts[{i}].guest"),
                Code::Duplicate,
                format!("{:?} is used twice", a.guest),
            );
            continue;
        }
        let nested = mounts.iter().take(i).find(|b| {
            b.guest != a.guest
                && paths::overlaps(
                    std::path::Path::new(&a.guest),
                    std::path::Path::new(&b.guest),
                )
        });
        if let Some(b) = nested {
            d.error(
                format!("filesystem.mounts[{i}].guest"),
                Code::Overlap,
                format!("{:?} is nested with {:?}", a.guest, b.guest),
            );
        }
    }
    for (n, (i, a)) in resolved.iter().enumerate() {
        let mut earlier = resolved.iter().take(n).map(|(_, b)| b);
        if let Some(b) = earlier.find(|b| paths::overlaps(&a.host, &b.host)) {
            d.error(
                format!("filesystem.mounts[{i}].host"),
                Code::Overlap,
                format!(
                    "{:?} overlaps {:?} (mounted at {})",
                    a.host.display().to_string(),
                    b.host.display().to_string(),
                    b.guest
                ),
            );
        }
    }
}
