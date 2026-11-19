//! The mount-link probe (security review). Every existing check of a container runs after
//! `podman init`, when the runtime has already placed its mounts. A link in the image's root
//! filesystem at or above a mount destination is followed while the runtime places them, and can
//! make it create a directory inside an earlier mount's host folder. So before the real
//! `podman create`, the launcher creates and inits a probe container of the same image, with the
//! same checked argv minus every host-folder bind (and the GPU device flag), and walks every
//! destination of the launch inside the probe's root filesystem. A link at or above any of them
//! refuses the launch; the probe is removed before the real container is created, and both must
//! run the same image id.
//!
//! The walk sees the image's tree only: a destination nested inside a host folder (a `.git`
//! shield inside an `rw` mount) resolves there at the real `init`, and stays covered by the
//! launch scan, its host re-check and the post-init pin check. The walk runs as the host user,
//! so a destination below an image directory that user cannot search (mode 0700 under
//! `keep-id`) is refused (`EACCES`): fail-closed, never a fallback.
//!
//! The parts here are pure and tested without a container: the walk over a directory fd, the
//! probe's name, the probe argv derived from the real one, and the parse of `podman inspect`'s
//! pid and image id. The orchestration is in `launch/start.rs`.

use rustix::fd::AsFd;
use rustix::fs::{FileType, Mode, OFlags, ResolveFlags};

use super::check::container_prefix;
use super::oci::facts::is_clean;
use super::types::Role;

/// What a destination is in the probe's root filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Found {
    /// Nothing there yet: the runtime creates it, through no link.
    Absent,
    /// A directory or a regular file, reached through no link.
    Present,
}

/// A destination the walk refuses: the guest path and why, never a host path.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{dest}: {why}")]
pub struct Refused {
    /// The guest destination.
    pub dest: String,
    /// What was found.
    pub why: String,
}

/// Why the walk of a probe stopped.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WalkError {
    /// The probe's root could not be opened through its held `/proc/<pid>` directory.
    #[error("cannot open the probe's root: {0}")]
    Root(rustix::io::Errno),
    /// A destination is at or below a link, or is neither a directory nor a regular file.
    #[error(transparent)]
    Link(Refused),
}

/// The resolve flags of the walk: no component may be a symlink or a magic link, and `..` stays
/// inside the root.
const RESOLVE: ResolveFlags = ResolveFlags::IN_ROOT
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS);

/// What `dest` (a clean absolute guest path) is beneath `root`: one `openat2` of the whole path
/// with `O_PATH` (never `O_NOFOLLOW`: a link as the last component must fail too), then its type.
///
/// # Errors
/// [`Refused`] for an unclean destination, any errno other than `ENOENT` (`ELOOP` for a link at
/// or above it), or a type other than a directory or a regular file.
pub fn walk(root: impl AsFd, dest: &str) -> Result<Found, Refused> {
    let refuse = |why: String| Refused {
        dest: dest.to_owned(),
        why,
    };
    let Some(rel) = dest.strip_prefix('/').filter(|_| is_clean(dest)) else {
        return Err(refuse("not a clean absolute path".into()));
    };
    let fd = match sally_core::fd::openat2(root, rel, OFlags::PATH, Mode::empty(), RESOLVE) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(Found::Absent),
        Err(e) => return Err(refuse(format!("not reached without a link: {e}"))),
    };
    let st = rustix::fs::fstat(&fd).map_err(|e| refuse(format!("cannot be read: {e}")))?;
    match FileType::from_raw_mode(st.st_mode) {
        FileType::Directory | FileType::RegularFile => Ok(Found::Present),
        other => Err(refuse(format!(
            "a {other:?}, not a directory or a regular file"
        ))),
    }
}

/// Walks every destination inside the root of the process whose `/proc/<pid>` directory is
/// `proc_dir` (held, so a reused pid names nothing: the open of `root` fails instead).
///
/// # Errors
/// [`WalkError::Root`] if the root cannot be opened; [`WalkError::Link`] for the first
/// destination [`walk`] refuses.
pub fn walk_in(proc_dir: impl AsFd, dests: &[String]) -> Result<(), WalkError> {
    let root = sally_core::fd::openat(
        proc_dir,
        "root",
        OFlags::PATH.union(OFlags::DIRECTORY),
        Mode::empty(),
    )
    .map_err(WalkError::Root)?;
    for d in dests {
        walk(&root, d).map_err(WalkError::Link)?;
    }
    Ok(())
}

/// The probe container's name prefix of a role. No container name of a role can start with one
/// (`sp-ws-`, `sp-h-`, `sp-infer-` never continue with `probe-`), and no session id can make one.
#[must_use]
pub const fn probe_prefix(role: Role) -> &'static str {
    match role {
        Role::Workspace => "sp-probe-ws-",
        Role::Harness => "sp-probe-h-",
        Role::Inference => "sp-probe-infer-",
    }
}

/// The probe's name for the role's container `name`: its id after [`probe_prefix`]. `None` if
/// `name` is not the role's.
#[must_use]
pub fn probe_name(name: &str, role: Role) -> Option<String> {
    name.strip_prefix(container_prefix(role))
        .map(|id| format!("{}{id}", probe_prefix(role)))
}

/// The probe argv: the real container's `args` with every `-v` pair and the `--device` pair
/// left out and the `--name` value replaced by `probe`; from the `image` token on, unchanged.
#[must_use]
pub fn probe_argv(args: &[String], probe: &str, image: &str) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    let mut it = args.iter();
    while let Some(tok) = it.next() {
        match tok.as_str() {
            "-v" | "--device" => {
                it.next();
            }
            "--name" => {
                it.next();
                out.extend(["--name".to_owned(), probe.to_owned()]);
            }
            t if t == image => {
                out.push(tok.clone());
                out.extend(it.by_ref().cloned());
            }
            _ => out.push(tok.clone()),
        }
    }
    out
}

/// The `podman inspect` format the probe is read with: its init pid and image id.
pub const PID_IMAGE_FORMAT: &str = "{{.State.Pid}} {{.Image}}";

/// The `podman inspect` format the real container's image id is read with.
pub const IMAGE_FORMAT: &str = "{{.Image}}";

/// An image id as podman prints `.Image`: 64 lowercase hex digits.
fn image_id(s: &str) -> Option<String> {
    (s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    .then(|| s.to_owned())
}

/// `<pid> <image id>` ([`PID_IMAGE_FORMAT`]), surrounding white space ignored: the pid above 1.
#[must_use]
pub fn parse_pid_image(out: &str) -> Option<(u32, String)> {
    match out.split_whitespace().collect::<Vec<_>>().as_slice() {
        [pid, image] => {
            let pid = pid.parse::<u32>().ok().filter(|p| *p > 1)?;
            Some((pid, image_id(image)?))
        }
        _ => None,
    }
}

/// `<image id>` ([`IMAGE_FORMAT`]), surrounding white space ignored.
#[must_use]
pub fn parse_image(out: &str) -> Option<String> {
    image_id(out.trim())
}

#[cfg(test)]
#[path = "mount_probe_tests.rs"]
mod tests;
