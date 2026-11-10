//! The session-overlap rule (AMENDMENTS-02 B4; RT-AG-08b). Two live sessions may mount
//! overlapping host directories only when neither mount is `rw` or `brokered`, so no sandbox ever
//! holds write access to an ancestor, a descendant or the same directory as another session's
//! mount. This also closes the 6a re-review's H1 race: the parent pins and `.git` shields of one
//! session cannot be swapped for a symlink by another live session, because none can write there.
//!
//! Overlap is decided by path *and* by identity: each claim carries the `st_dev:st_ino` of its
//! root and of every ancestor up to `/` (walked with `..` from the root, so a directory reached
//! through a bind alias, a doubly mounted subvolume or another path still conflicts; 6b security
//! review M2).
//!
//! The rule is a pure function ([`conflict`]); [`Sessions`] holds the live claims of this
//! `sallyd` and reserves atomically. One `sallyd` runs per user (its control socket is the lock);
//! containers a previous `sallyd` left behind are removed before the first launch
//! ([`super::Launcher::remove_orphans`]), so in-process state is the whole picture.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rustix::fs::{Mode, OFlags};
use sally_core::manifest::{MountMode, ValidatedManifest};

/// Bound on the ancestor walk (the kernel's path depth is far below it).
const MAX_ANCESTORS: usize = 4096;

/// One host directory a session mounts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    /// Host realpath.
    pub host: PathBuf,
    /// Mount mode.
    pub mode: MountMode,
    /// `st_dev:st_ino` of the root, then of each ancestor up to `/`.
    pub chain: Vec<(u64, u64)>,
}

/// The claims of a validated manifest, in manifest order, with each root's identity chain.
/// Performs blocking I/O.
///
/// # Errors
/// The I/O error of a root or ancestor that cannot be opened.
pub fn claims(v: &ValidatedManifest) -> std::io::Result<Vec<Claim>> {
    v.mounts()
        .iter()
        .map(|m| {
            Ok(Claim {
                host: m.host.clone(),
                mode: m.mode,
                chain: identity_chain(&m.host)?,
            })
        })
        .collect()
}

/// The identities of `dir` and its ancestors, walking `..` from an fd (not the path string).
fn identity_chain(dir: &Path) -> std::io::Result<Vec<(u64, u64)>> {
    let flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC;
    let mut fd = rustix::fs::open(dir, flags | OFlags::NOFOLLOW, Mode::empty())?;
    let mut chain = Vec::new();
    for _ in 0..MAX_ANCESTORS {
        let st = rustix::fs::fstat(&fd)?;
        let id = (st.st_dev, st.st_ino);
        if chain.last() == Some(&id) {
            return Ok(chain);
        }
        chain.push(id);
        fd = rustix::fs::openat(&fd, "..", flags, Mode::empty())?;
    }
    Err(std::io::Error::other("ancestor walk did not reach /"))
}

/// A refused overlap.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "{new} ({new_mode:?}) overlaps {held} ({held_mode:?}) of live session {session}; two sessions \
     may share folders only when neither mounts them rw or brokered"
)]
pub struct Conflict {
    /// The live session.
    pub session: String,
    /// Its directory.
    pub held: String,
    /// Its mode.
    pub held_mode: MountMode,
    /// The new session's directory.
    pub new: String,
    /// Its mode.
    pub new_mode: MountMode,
}

fn writes(mode: MountMode) -> bool {
    matches!(mode, MountMode::Rw | MountMode::Brokered)
}

/// Same directory, or one inside the other: by path (component-wise), or by identity (either
/// root appears in the other's ancestor chain).
fn overlaps(a: &Claim, b: &Claim) -> bool {
    let root = |c: &Claim| c.chain.first().copied();
    a.host.starts_with(&b.host)
        || b.host.starts_with(&a.host)
        || root(a).is_some_and(|r| b.chain.contains(&r))
        || root(b).is_some_and(|r| a.chain.contains(&r))
}

/// The first conflict between `new` and any live session's claims.
#[must_use]
pub fn conflict<'a>(
    live: impl IntoIterator<Item = (&'a str, &'a [Claim])>,
    new: &[Claim],
) -> Option<Conflict> {
    for (session, held) in live {
        for h in held {
            for n in new {
                if (writes(h.mode) || writes(n.mode)) && overlaps(h, n) {
                    return Some(Conflict {
                        session: session.to_owned(),
                        held: h.host.display().to_string(),
                        held_mode: h.mode,
                        new: n.host.display().to_string(),
                        new_mode: n.mode,
                    });
                }
            }
        }
    }
    None
}

/// Why a reservation was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ReserveError {
    /// The session id is already live.
    #[error("session {0} is already live")]
    Duplicate(String),
    /// An overlap with a live session.
    #[error(transparent)]
    Overlap(#[from] Conflict),
}

/// The live sessions of this `sallyd` and their claims.
#[derive(Debug, Default)]
pub struct Sessions {
    live: Mutex<BTreeMap<String, Vec<Claim>>>,
}

impl Sessions {
    /// Checks `claims` against every live session and records them under `id`, atomically.
    ///
    /// # Errors
    /// [`ReserveError`] for a live id or an overlap.
    pub fn reserve(&self, id: &str, claims: Vec<Claim>) -> Result<(), ReserveError> {
        let mut live = self
            .live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if live.contains_key(id) {
            return Err(ReserveError::Duplicate(id.to_owned()));
        }
        if let Some(c) = conflict(
            live.iter().map(|(k, v)| (k.as_str(), v.as_slice())),
            &claims,
        ) {
            return Err(c.into());
        }
        live.insert(id.to_owned(), claims);
        Ok(())
    }

    /// Whether `id` holds claims.
    #[must_use]
    pub fn is_live(&self, id: &str) -> bool {
        self.live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains_key(id)
    }

    /// Forgets `id` (teardown).
    pub fn release(&self, id: &str) {
        self.live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(id);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const MODES: [MountMode; 4] = [
        MountMode::Ro,
        MountMode::Rw,
        MountMode::Brokered,
        MountMode::Staged,
    ];

    /// A claim with a made-up identity chain derived from the path, as if every path were
    /// distinct on disk.
    fn c(host: &str, mode: MountMode) -> Claim {
        let mut chain = Vec::new();
        let mut p = Some(Path::new(host));
        while let Some(x) = p {
            chain.push((1, fake_ino(x)));
            p = x.parent();
        }
        Claim {
            host: host.into(),
            mode,
            chain,
        }
    }

    fn fake_ino(p: &Path) -> u64 {
        p.as_os_str().len() as u64 * 1000
            + p.as_os_str()
                .as_encoded_bytes()
                .iter()
                .map(|b| u64::from(*b))
                .sum::<u64>()
    }

    /// 6b security review M2: the same directory under two paths (a bind alias).
    #[test]
    fn an_alias_of_a_held_directory_conflicts_by_identity() {
        let held = c("/h/a/d", MountMode::Rw);
        let mut alias = c("/h/b/d/sub", MountMode::Staged);
        // /h/b/d is the same directory as /h/a/d.
        alias.chain[1] = held.chain[0];
        let held = [held];
        assert!(conflict([("s1", held.as_slice())], &[alias.clone()]).is_some());
        // And the other way round: the alias is live, the original path is new.
        let alias_held = [alias];
        assert!(
            conflict(
                [("s1", alias_held.as_slice())],
                &[c("/h/a/d", MountMode::Rw)]
            )
            .is_some()
        );
        // Read-only on both sides never conflicts, aliased or not.
        let mut ro_alias = c("/h/b/d", MountMode::Ro);
        ro_alias.chain[0] = c("/h/a/d", MountMode::Ro).chain[0];
        let held = [c("/h/a/d", MountMode::Staged)];
        assert!(conflict([("s1", held.as_slice())], &[ro_alias]).is_none());
    }

    #[test]
    fn identity_chains_reach_the_root() {
        let dir = std::env::temp_dir();
        let chain = identity_chain(&dir).unwrap();
        let root = std::fs::metadata("/").unwrap();
        use std::os::unix::fs::MetadataExt;
        assert_eq!(chain.last(), Some(&(root.dev(), root.ino())));
        assert!(chain.len() >= 2);
    }

    #[test]
    fn overlapping_mounts_conflict_exactly_when_either_side_can_write() {
        let shapes = [("/h/p", "/h/p"), ("/h/p", "/h/p/sub"), ("/h/p/sub", "/h/p")];
        for (a, b) in shapes {
            for ma in MODES {
                for mb in MODES {
                    let held = [c(a, ma)];
                    let got = conflict([("s1", held.as_slice())], &[c(b, mb)]);
                    let want = writes(ma) || writes(mb);
                    assert_eq!(got.is_some(), want, "{a} {ma:?} vs {b} {mb:?}");
                }
            }
        }
    }

    #[test]
    fn siblings_and_prefix_lookalikes_never_conflict() {
        for (a, b) in [("/h/p", "/h/q"), ("/h/p", "/h/project"), ("/h/pro", "/h/p")] {
            let held = [c(a, MountMode::Rw)];
            assert!(
                conflict([("s1", held.as_slice())], &[c(b, MountMode::Rw)]).is_none(),
                "{a} vs {b}"
            );
        }
    }

    #[test]
    fn reservations_are_atomic_unique_and_released() {
        let s = Sessions::default();
        s.reserve("a", vec![c("/h/p", MountMode::Rw)]).unwrap();
        assert_eq!(
            s.reserve("a", vec![]),
            Err(ReserveError::Duplicate("a".into()))
        );
        let e = s
            .reserve("b", vec![c("/h/p/x", MountMode::Ro)])
            .unwrap_err();
        assert!(e.to_string().contains("live session a"), "{e}");
        s.reserve("c", vec![c("/h/q", MountMode::Rw)]).unwrap();
        s.release("a");
        s.reserve("b", vec![c("/h/p/x", MountMode::Ro)]).unwrap();
    }

    #[test]
    fn read_only_and_staged_sessions_may_share() {
        let s = Sessions::default();
        s.reserve("a", vec![c("/h/p", MountMode::Staged)]).unwrap();
        s.reserve("b", vec![c("/h/p", MountMode::Ro)]).unwrap();
        s.reserve("c", vec![c("/h/p/x", MountMode::Staged)])
            .unwrap();
        assert!(s.reserve("d", vec![c("/h", MountMode::Brokered)]).is_err());
    }
}
