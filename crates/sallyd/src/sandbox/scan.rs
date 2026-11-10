//! The launch scan (AMENDMENTS-02 B2(a), B4; RT-FS-13; #10). One bounded walk per mount, from a
//! pinned directory fd with `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
//! RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV)` (SI-8):
//!
//! - the mount root is opened without following any symlink and must still be the directory
//!   validation saw (`st_dev:st_ino`);
//! - a Unix socket anywhere in a mount refuses the launch (`socket-in-mount`): `connect` works on
//!   a read-only mount, and a host daemon's socket is a way out;
//! - the walk never enters another filesystem mount: the non-recursive bind and the overlay hide
//!   nested mounts from the sandbox (probed in Task 6b), so what is under them is not the
//!   sandbox's to see, and a shield must never be a bind of one (6a re-review M1);
//! - in an `rw` mount, every `.git` directory and `.git` file is recorded with its identity, and
//!   so is every directory between the root and it, for the shields and the pins;
//! - more than [`ScanLimits::max_shields`] entries, or a walk that hits its entry or depth bound,
//!   refuses the launch with a message recommending `staged` rather than truncating.
//!
//! Only this module constructs a [`GitScan`] or a [`LaunchScan`]. Blocking I/O; call from
//! `spawn_blocking`.

use std::ffi::CStr;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use rustix::fs::{AtFlags, FileType, Mode, OFlags, ResolveFlags, StatxFlags};
use sally_core::manifest::{MountMode, ResolvedMount, ValidatedManifest};

/// Bounds of the launch scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanLimits {
    /// Directory entries per mount.
    pub max_entries: usize,
    /// Directory depth below the mount root.
    pub max_depth: usize,
    /// `.git` directories plus `.git` files per `rw` mount (maintainer decision D).
    pub max_shields: usize,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            max_entries: 250_000,
            max_depth: 64,
            max_shields: 32,
        }
    }
}

/// Bytes of relative paths queued for listing at once.
const MAX_PENDING_PATH_BYTES: usize = 16 * 1024 * 1024;

/// Why the launch scan refused a mount. Messages name the mount and say what to do.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ScanError {
    /// The root is no longer the validated directory, or an entry changed during the walk.
    #[error("filesystem.mounts[{mount}]: {msg}")]
    Changed {
        /// Manifest index.
        mount: usize,
        /// What changed.
        msg: String,
    },
    /// A Unix socket inside a mount (RT-FS-13).
    #[error(
        "filesystem.mounts[{mount}]: {rel:?} is a Unix socket; a sandbox could connect to the \
         program behind it (socket-in-mount). Remove it or mount a directory without it"
    )]
    SocketInMount {
        /// Manifest index.
        mount: usize,
        /// Path relative to the mount root.
        rel: PathBuf,
    },
    /// Too many `.git` entries to shield in one `rw` mount.
    #[error(
        "filesystem.mounts[{mount}]: {count} git repositories or pointer files to shield (at \
         most {max}); use mode: staged for this folder, which never writes the host"
    )]
    TooManyShields {
        /// Manifest index.
        mount: usize,
        /// Entries found so far.
        count: usize,
        /// The bound.
        max: usize,
    },
    /// The walk hit a bound.
    #[error("filesystem.mounts[{mount}]: the launch scan stopped at {what}; {advice}")]
    Limit {
        /// Manifest index.
        mount: usize,
        /// Which bound.
        what: String,
        /// What to do.
        advice: &'static str,
    },
    /// An I/O error.
    #[error("filesystem.mounts[{mount}]: {rel:?}: {source}")]
    Io {
        /// Manifest index.
        mount: usize,
        /// Path relative to the mount root.
        rel: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
}

/// How a pinned host object reaches the sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinKind {
    /// A bind mount: the post-init check compares what the container sees.
    Bind,
    /// An overlay lower layer: re-checked on the host just before `podman create`.
    OverlayLower,
}

/// A host object the launch depends on, by identity (#10, AMENDMENTS-02 B4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pin {
    /// Manifest index of the mount it belongs to.
    pub mount: usize,
    /// Path relative to the mount root (empty for the root).
    pub rel: PathBuf,
    /// Absolute guest path.
    pub guest: String,
    /// `st_dev`.
    pub dev: u64,
    /// `st_ino`.
    pub ino: u64,
    /// How it is mounted.
    pub kind: PinKind,
}

/// What the launch scan found inside one `rw` mount: `.git` directories (overlaid over session
/// scratch) and `.git` files (bound read-only), relative to the mount root, in walk order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitScan {
    mount: usize,
    dirs: Vec<PathBuf>,
    files: Vec<PathBuf>,
}

impl GitScan {
    /// Manifest index of the mount.
    #[must_use]
    pub fn mount(&self) -> usize {
        self.mount
    }

    /// `.git` directories.
    #[must_use]
    pub fn dirs(&self) -> &[PathBuf] {
        &self.dirs
    }

    /// `.git` files.
    #[must_use]
    pub fn files(&self) -> &[PathBuf] {
        &self.files
    }

    /// For the builder's own unit tests only: an unchecked scan.
    #[cfg(test)]
    pub(super) fn unchecked(mount: usize, dirs: Vec<PathBuf>, files: Vec<PathBuf>) -> Self {
        Self { mount, dirs, files }
    }
}

/// The result of scanning every mount of a manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchScan {
    /// Each mount's host realpath, validated identity, mode and guest path, in manifest order:
    /// the scan belongs to exactly this manifest (a scan of a `ro` mount has no shields for an
    /// `rw` one).
    roots: Vec<Root>,
    git: Vec<GitScan>,
    pins: Vec<Pin>,
}

impl LaunchScan {
    /// One scan per `rw` mount, in manifest order.
    #[must_use]
    pub fn git(&self) -> &[GitScan] {
        &self.git
    }

    /// Whether this scan was made for `v` (the same mounts, by realpath and identity).
    #[must_use]
    pub fn is_for(&self, v: &ValidatedManifest) -> bool {
        self.roots == roots(v)
    }

    /// Every pinned host object: mount roots, shielded `.git` entries and their parents.
    #[must_use]
    pub fn pins(&self) -> &[Pin] {
        &self.pins
    }

    /// Re-opens every pin on the host, without following symlinks or leaving its mount, and
    /// compares identities: the last host-side check before `podman create`.
    ///
    /// # Errors
    /// [`ScanError::Changed`] for the first pin that no longer matches.
    pub fn recheck_host(&self, v: &ValidatedManifest) -> Result<(), ScanError> {
        if !self.is_for(v) {
            return changed(0, "the launch scan belongs to another manifest");
        }
        for pin in &self.pins {
            let Some(m) = v.mounts().get(pin.mount) else {
                return changed(pin.mount, "mount list changed");
            };
            let root = open_root(pin.mount, m)?;
            let (dev, ino) = if pin.rel.as_os_str().is_empty() {
                identity(&root, pin.mount, &pin.rel)?
            } else {
                let fd =
                    open_beneath(&root, &pin.rel, OFlags::PATH).map_err(io(pin.mount, &pin.rel))?;
                identity(&fd, pin.mount, &pin.rel)?
            };
            if (dev, ino) != (pin.dev, pin.ino) {
                return changed(
                    pin.mount,
                    format!("{:?} changed since the launch scan", pin.rel),
                );
            }
        }
        Ok(())
    }
}

fn changed<T>(mount: usize, msg: impl Into<String>) -> Result<T, ScanError> {
    Err(ScanError::Changed {
        mount,
        msg: msg.into(),
    })
}

fn io(mount: usize, rel: &Path) -> impl FnOnce(rustix::io::Errno) -> ScanError + '_ {
    move |e| ScanError::Io {
        mount,
        rel: rel.to_owned(),
        source: e.into(),
    }
}

const RESOLVE: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS)
    .union(ResolveFlags::NO_XDEV);

fn open_beneath(root: &OwnedFd, rel: &Path, kind: OFlags) -> rustix::io::Result<OwnedFd> {
    rustix::fs::openat2(
        root,
        rel,
        kind | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        RESOLVE,
    )
}

/// Opens a mount root without following any symlink on the way (its validated realpath has
/// none) and checks it is still the validated directory.
fn open_root(mount: usize, m: &ResolvedMount) -> Result<OwnedFd, ScanError> {
    let fd = rustix::fs::openat2(
        rustix::fs::CWD,
        &m.host,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|e| ScanError::Changed {
        mount,
        msg: format!(
            "{} can no longer be opened without following a symlink: {e}",
            m.host.display()
        ),
    })?;
    if identity(&fd, mount, Path::new(""))? != m.identity() {
        return changed(
            mount,
            format!("{} was replaced since validation", m.host.display()),
        );
    }
    Ok(fd)
}

fn identity(fd: &OwnedFd, mount: usize, rel: &Path) -> Result<(u64, u64), ScanError> {
    let st = rustix::fs::fstat(fd).map_err(io(mount, rel))?;
    Ok((st.st_dev, st.st_ino))
}

struct Entry {
    kind: FileType,
    dev: u64,
    ino: u64,
    mnt_id: u64,
}

/// What the scan needs from `statx`; a kernel that does not fill all of it (`STATX_MNT_ID`
/// arrived in 5.8) would make every entry look like it is on the root's mount, so the scan
/// refuses rather than walking into nested mounts (6b Rust review M1).
const NEEDED: StatxFlags = StatxFlags::TYPE
    .union(StatxFlags::INO)
    .union(StatxFlags::MNT_ID);

fn stat_entry(dir: impl AsFd, name: &CStr) -> rustix::io::Result<Entry> {
    let st = rustix::fs::statx(dir, name, AtFlags::SYMLINK_NOFOLLOW, NEEDED)?;
    if !StatxFlags::from_bits_retain(st.stx_mask).contains(NEEDED) {
        return Err(rustix::io::Errno::NOSYS);
    }
    Ok(Entry {
        kind: FileType::from_raw_mode(st.stx_mode.into()),
        dev: rustix::fs::makedev(st.stx_dev_major, st.stx_dev_minor),
        ino: st.stx_ino,
        mnt_id: st.stx_mnt_id,
    })
}

type Root = (PathBuf, (u64, u64), MountMode, String);

fn roots(v: &ValidatedManifest) -> Vec<Root> {
    v.mounts()
        .iter()
        .map(|m| (m.host.clone(), m.identity(), m.mode, m.guest.clone()))
        .collect()
}

/// Scans every mount of `v`.
///
/// # Errors
/// [`ScanError`] for the first mount that is refused.
pub fn scan_mounts(v: &ValidatedManifest, limits: &ScanLimits) -> Result<LaunchScan, ScanError> {
    let mut out = LaunchScan {
        roots: roots(v),
        git: Vec::new(),
        pins: Vec::new(),
    };
    for (i, m) in v.mounts().iter().enumerate() {
        Walk::new(i, m, limits)?.run(&mut out)?;
    }
    Ok(out)
}

struct Walk<'a> {
    mount: usize,
    m: &'a ResolvedMount,
    limits: &'a ScanLimits,
    root: OwnedFd,
    root_mnt: u64,
    entries: usize,
    pending_bytes: usize,
    git: GitScan,
    pins: Vec<Pin>,
}

impl<'a> Walk<'a> {
    fn new(mount: usize, m: &'a ResolvedMount, limits: &'a ScanLimits) -> Result<Self, ScanError> {
        let root = open_root(mount, m)?;
        let root_mnt = rustix::fs::statx(&root, c"", AtFlags::EMPTY_PATH, StatxFlags::MNT_ID)
            .map_err(io(mount, Path::new("")))?
            .stx_mnt_id;
        Ok(Self {
            mount,
            m,
            limits,
            root,
            root_mnt,
            entries: 0,
            pending_bytes: 0,
            git: GitScan {
                mount,
                dirs: Vec::new(),
                files: Vec::new(),
            },
            pins: Vec::new(),
        })
    }

    fn rw(&self) -> bool {
        self.m.mode == MountMode::Rw
    }

    fn limit(&self, what: String) -> ScanError {
        ScanError::Limit {
            mount: self.mount,
            what,
            advice: if self.rw() {
                "use mode: staged for this folder (it never writes the host), or mount a smaller \
                 folder"
            } else {
                "mount a smaller folder"
            },
        }
    }

    fn pin(&mut self, rel: &Path, dev: u64, ino: u64, kind: PinKind) {
        let guest = if rel.as_os_str().is_empty() {
            self.m.guest.clone()
        } else {
            format!("{}/{}", self.m.guest, rel.display())
        };
        self.pins.push(Pin {
            mount: self.mount,
            rel: rel.to_owned(),
            guest,
            dev,
            ino,
            kind,
        });
    }

    fn run(mut self, out: &mut LaunchScan) -> Result<(), ScanError> {
        let (dev, ino) = self.m.identity();
        let root_kind = match self.m.mode {
            MountMode::Staged => PinKind::OverlayLower,
            MountMode::Ro | MountMode::Rw | MountMode::Brokered => PinKind::Bind,
        };
        self.pin(Path::new(""), dev, ino, root_kind);
        // Each stack entry: a directory to list, relative to the root, its expected inode, its
        // depth, and whether it is inside a `.git` directory (listed for sockets only).
        let mut stack: Vec<(PathBuf, u64, usize, bool)> = vec![(PathBuf::new(), ino, 0, false)];
        while let Some((rel, ino, depth, in_git)) = stack.pop() {
            self.pending_bytes = self.pending_bytes.saturating_sub(rel.as_os_str().len());
            self.list(&rel, ino, depth, in_git, &mut stack)?;
        }
        if self.rw() {
            // readdir order depends on the filesystem; the argv (and its overlay numbering) must not.
            self.git.dirs.sort();
            self.git.files.sort();
            self.pin_parents()?;
            out.git.push(self.git);
        }
        out.pins.extend(self.pins);
        Ok(())
    }

    fn list(
        &mut self,
        rel: &Path,
        ino: u64,
        depth: usize,
        in_git: bool,
        stack: &mut Vec<(PathBuf, u64, usize, bool)>,
    ) -> Result<(), ScanError> {
        let fd = if rel.as_os_str().is_empty() {
            self.root.try_clone().map_err(|e| ScanError::Io {
                mount: self.mount,
                rel: PathBuf::new(),
                source: e,
            })?
        } else {
            open_beneath(&self.root, rel, OFlags::RDONLY | OFlags::DIRECTORY)
                .map_err(io(self.mount, rel))?
        };
        if identity(&fd, self.mount, rel)?.1 != ino {
            return changed(
                self.mount,
                format!("{rel:?} changed during the launch scan"),
            );
        }
        let dir = rustix::fs::Dir::read_from(&fd).map_err(io(self.mount, rel))?;
        for entry in dir {
            let entry = entry.map_err(io(self.mount, rel))?;
            let name = entry.file_name();
            if name == c"." || name == c".." {
                continue;
            }
            self.entries += 1;
            if self.entries > self.limits.max_entries {
                return Err(self.limit(format!("{} entries", self.limits.max_entries)));
            }
            let child = rel.join(std::ffi::OsStr::from_bytes(name.to_bytes()));
            self.visit(&fd, name, child, depth, in_git, stack)?;
        }
        Ok(())
    }

    fn visit(
        &mut self,
        dir: &OwnedFd,
        name: &CStr,
        child: PathBuf,
        depth: usize,
        in_git: bool,
        stack: &mut Vec<(PathBuf, u64, usize, bool)>,
    ) -> Result<(), ScanError> {
        let e = stat_entry(dir, name).map_err(io(self.mount, &child))?;
        if e.kind == FileType::Socket {
            return Err(ScanError::SocketInMount {
                mount: self.mount,
                rel: child,
            });
        }
        let is_git = name == c".git" && self.rw() && !in_git;
        if e.mnt_id != self.root_mnt {
            // A mount point (a directory or a bind-mounted file) of another mount: invisible in
            // the sandbox; never entered, never shielded (6b Rust review M2).
            return Ok(());
        }
        match e.kind {
            FileType::Directory => {
                if is_git {
                    self.shield(&child, e.dev, e.ino, PinKind::OverlayLower, true)?;
                }
                if depth + 1 > self.limits.max_depth {
                    return Err(self.limit(format!("depth {}", self.limits.max_depth)));
                }
                // Paths waiting to be listed are held in memory: bound them (6b security L1).
                self.pending_bytes = self.pending_bytes.saturating_add(child.as_os_str().len());
                if self.pending_bytes > MAX_PENDING_PATH_BYTES {
                    return Err(
                        self.limit(format!("{MAX_PENDING_PATH_BYTES} bytes of pending paths"))
                    );
                }
                stack.push((child, e.ino, depth + 1, in_git || is_git));
            }
            FileType::RegularFile if is_git => {
                self.shield(&child, e.dev, e.ino, PinKind::Bind, false)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn shield(
        &mut self,
        rel: &Path,
        dev: u64,
        ino: u64,
        kind: PinKind,
        is_dir: bool,
    ) -> Result<(), ScanError> {
        let count = self.git.dirs.len() + self.git.files.len() + 1;
        if count > self.limits.max_shields {
            return Err(ScanError::TooManyShields {
                mount: self.mount,
                count,
                max: self.limits.max_shields,
            });
        }
        if is_dir {
            self.git.dirs.push(rel.to_owned());
        } else {
            self.git.files.push(rel.to_owned());
        }
        self.pin(rel, dev, ino, kind);
        Ok(())
    }

    /// Pins every directory between the root and a shielded entry (they are bound onto
    /// themselves, so the post-init check compares them too).
    fn pin_parents(&mut self) -> Result<(), ScanError> {
        let mut parents: Vec<PathBuf> = self
            .git
            .dirs
            .iter()
            .chain(&self.git.files)
            .flat_map(|p| {
                p.ancestors()
                    .skip(1)
                    .map(Path::to_path_buf)
                    .collect::<Vec<_>>()
            })
            .filter(|p| !p.as_os_str().is_empty())
            .collect();
        parents.sort();
        parents.dedup();
        for p in parents {
            let fd = open_beneath(&self.root, &p, OFlags::PATH | OFlags::DIRECTORY)
                .map_err(io(self.mount, &p))?;
            let (dev, ino) = identity(&fd, self.mount, &p)?;
            self.pin(&p, dev, ino, PinKind::Bind);
        }
        Ok(())
    }
}
