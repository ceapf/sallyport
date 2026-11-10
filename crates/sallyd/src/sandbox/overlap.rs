//! The session-overlap rule (AMENDMENTS-02 B4; RT-AG-08b). Two live sessions may mount
//! overlapping host directories only when neither mount is `rw` or `brokered`, so no sandbox ever
//! holds write access to an ancestor, a descendant or the same directory as another session's
//! mount. This also closes the 6a re-review's H1 race: the parent pins and `.git` shields of one
//! session cannot be swapped for a symlink by another live session, because none can write there.
//!
//! The rule is a pure function ([`conflict`]); [`Sessions`] holds the live claims of this
//! `sallyd` and reserves atomically. One `sallyd` runs per user (its control socket is the lock),
//! so in-process state is the whole picture.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use sally_core::manifest::{MountMode, ValidatedManifest};

/// One host directory a session mounts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    /// Host realpath.
    pub host: PathBuf,
    /// Mount mode.
    pub mode: MountMode,
}

/// The claims of a validated manifest, in manifest order.
#[must_use]
pub fn claims(v: &ValidatedManifest) -> Vec<Claim> {
    v.mounts()
        .iter()
        .map(|m| Claim {
            host: m.host.clone(),
            mode: m.mode,
        })
        .collect()
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

/// Same directory, or one inside the other (component-wise).
fn overlaps(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
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
                if (writes(h.mode) || writes(n.mode)) && overlaps(&h.host, &n.host) {
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

    fn c(host: &str, mode: MountMode) -> Claim {
        Claim {
            host: host.into(),
            mode,
        }
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
