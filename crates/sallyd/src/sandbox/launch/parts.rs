//! The pure parts of a role launch (#123, architect Q129–Q133): who a launch is for and how its
//! audit entries name it, and the host objects a harness or inference launch pins by identity.
//! Container-free: the launcher's orchestration (`launch/start.rs`, `harness.rs`,
//! `inference.rs`) only calls these.

use std::path::{Path, PathBuf};

use rustix::fs::{Mode, OFlags, ResolveFlags};
use sally_core::audit::{Actor, NewEntry};
use serde_json::{Map, Value};

use crate::sandbox::inside::Expect;
use crate::sandbox::types::{Role, SessionId, VerifiedModel};

/// Who a launch is for. A workspace or harness belongs to a session, whose id is the entry's
/// session; an inference instance is not a session, so its id goes in the entry's args as
/// `instance` (architect Q131: no entry schema change).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Subject {
    /// A session (workspace, harness).
    Session(SessionId),
    /// An inference instance. TODO(#135): an `InstanceId` newtype.
    Instance(SessionId),
}

impl Subject {
    /// The session or instance id.
    #[must_use]
    pub(crate) fn id(&self) -> &SessionId {
        match self {
            Self::Session(id) | Self::Instance(id) => id,
        }
    }

    /// What the id names, as an oplog key: `session` or `instance`.
    #[must_use]
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Self::Session(_) => "session",
            Self::Instance(_) => "instance",
        }
    }

    /// A `sallyd` entry for `event` about this subject's `role` container: `args`, plus `role`
    /// and, for an instance, `instance`.
    #[must_use]
    pub(crate) fn entry(
        &self,
        event: &str,
        role: Role,
        args: impl IntoIterator<Item = (&'static str, Value)>,
    ) -> NewEntry {
        let mut m: Map<String, Value> = args.into_iter().map(|(k, v)| (k.to_owned(), v)).collect();
        m.insert("role".into(), role.as_str().into());
        let e = NewEntry::new(Actor::Sallyd, event);
        match self {
            Self::Session(id) => e.session(id.as_str()).args(Value::Object(m)),
            Self::Instance(id) => {
                m.insert("instance".into(), id.as_str().into());
                e.args(Value::Object(m))
            }
        }
    }
}

/// How many more tries a cleanup gets once its containers are confirmed gone, for its
/// directories, a retry pause apart: a failed launch's and a stop nobody received
/// (`stop_role_unreceived`).
pub(crate) const STOP_RETRIES_AFTER_REMOVAL: u32 = 3;

/// Every how many tries a failed launch's cleanup, while a container may remain, says so again
/// in the oplog (about once a minute at the retry pause).
pub(crate) const CLEANUP_REPORT_EVERY: u32 = 30;

/// What became of a failed launch's directories when its cleanup ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Directories {
    /// All removed.
    Removed,
    /// Given up after [`STOP_RETRIES_AFTER_REMOVAL`] tries past the containers' removal.
    Kept,
}

impl Directories {
    /// The wire name, in `sandbox.cleaned`.
    #[must_use]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Removed => "removed",
            Self::Kept => "kept",
        }
    }
}

/// What a failed launch's cleanup does after a try (ARCHITECTURE §3.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NextTry {
    /// Try again a retry pause later; the claim stays.
    Again,
    /// Write `sandbox.cleaned`, free the claim, end.
    Done(Directories),
}

/// The tries of one failed launch's cleanup, the first (in the launch) included: without bound
/// while a container may exist, then at most [`STOP_RETRIES_AFTER_REMOVAL`] more for the
/// directories.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CleanupTries {
    attempts: u32,
    /// `attempts` at the try that first confirmed both containers gone.
    gone_at: Option<u32>,
}

impl CleanupTries {
    /// Records one try: whether its mount-link probe and container are confirmed gone, and
    /// whether everything it set out to remove was removed. Then what comes next.
    #[must_use]
    pub(crate) fn record(&mut self, containers_gone: bool, all_removed: bool) -> NextTry {
        self.attempts = self.attempts.saturating_add(1);
        if !containers_gone {
            return NextTry::Again;
        }
        if all_removed {
            return NextTry::Done(Directories::Removed);
        }
        let gone_at = *self.gone_at.get_or_insert(self.attempts);
        if self.attempts.saturating_sub(gone_at) < STOP_RETRIES_AFTER_REMOVAL {
            NextTry::Again
        } else {
            NextTry::Done(Directories::Kept)
        }
    }

    /// The tries so far, saturating.
    #[must_use]
    pub(crate) fn attempts(&self) -> u32 {
        self.attempts
    }

    /// Whether the try just recorded is one the oplog hears of again: every
    /// [`CLEANUP_REPORT_EVERY`]th.
    #[must_use]
    pub(crate) fn worth_reporting(&self) -> bool {
        self.attempts.is_multiple_of(CLEANUP_REPORT_EVERY)
    }
}

/// Whether a cleanup has confirmed both its containers gone: neither the mount-link probe nor
/// the role's container is still to be removed. Only then may the claim go (ARCHITECTURE §3.5).
#[must_use]
pub(crate) fn containers_gone(probe_left: Option<&str>, container_left: Option<&str>) -> bool {
    probe_left.is_none() && container_left.is_none()
}

/// The containers a failed launch's cleanup set out to remove, by name: its mount-link probe
/// and its container, each if its `create` was attempted and it was not yet confirmed gone.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Made {
    /// The mount-link probe.
    pub(crate) probe: Option<String>,
    /// The role's container.
    pub(crate) container: Option<String>,
}

/// `sandbox.cleaned`: a failed launch's cleanup, retried after its first try
/// failed, ended. No decision and no podman text: what it removed, how many tries it took, and
/// whether the directories went.
#[must_use]
pub(crate) fn cleaned_entry(
    subject: &Subject,
    role: Role,
    made: &Made,
    attempts: u32,
    directories: Directories,
) -> NewEntry {
    subject.entry(
        "sandbox.cleaned",
        role,
        [
            ("container", made.container.clone().into()),
            ("probe", made.probe.clone().into()),
            ("attempts", attempts.into()),
            ("directories", directories.as_str().into()),
        ],
    )
}

/// A host object a harness or inference launch binds, pinned by identity: re-checked on the
/// host after `podman create`, then compared inside the container after `podman init`
/// (AMENDMENTS-02 B4, as the workspace's mount pins).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostPin {
    host: PathBuf,
    guest: String,
    dev: u64,
    ino: u64,
}

/// A pinned host object that could not be opened, or is no longer the object pinned.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{path}: {msg}")]
pub struct PinError {
    /// The host path.
    pub path: String,
    /// What is wrong.
    pub msg: String,
}

/// `stat` of `host`, opened without following a symlink anywhere on its path (a symlink as the
/// last component is opened as itself, never followed).
fn stat(host: &Path) -> Result<rustix::fs::Stat, PinError> {
    let err = |e: rustix::io::Errno| PinError {
        path: host.display().to_string(),
        msg: e.to_string(),
    };
    let fd = sally_core::fd::openat2(
        rustix::fs::CWD,
        host,
        OFlags::PATH | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(err)?;
    rustix::fs::fstat(&fd).map_err(err)
}

fn identity(host: &Path) -> Result<(u64, u64), PinError> {
    stat(host).map(|st| (st.st_dev, st.st_ino))
}

impl HostPin {
    /// Pins the directory `host`, bound at `guest`. Blocking.
    ///
    /// # Errors
    /// [`PinError`] if it cannot be opened without following a symlink, or is not a directory
    /// (a symlink as the last component included).
    pub(crate) fn dir(host: &Path, guest: &str) -> Result<Self, PinError> {
        let st = stat(host)?;
        if rustix::fs::FileType::from_raw_mode(st.st_mode) != rustix::fs::FileType::Directory {
            return Err(PinError {
                path: host.display().to_string(),
                msg: "not a directory".into(),
            });
        }
        let (dev, ino) = (st.st_dev, st.st_ino);
        Ok(Self {
            host: host.to_owned(),
            guest: guest.to_owned(),
            dev,
            ino,
        })
    }

    /// The model blob, bound at `guest`, with the identity it was pinned with at import.
    #[must_use]
    pub(crate) fn model(m: &VerifiedModel, guest: &str) -> Self {
        let (dev, ino) = m.identity();
        Self {
            host: m.path().to_owned(),
            guest: guest.to_owned(),
            dev,
            ino,
        }
    }

    /// Re-opens the host path and compares identities. Blocking.
    ///
    /// # Errors
    /// [`PinError`] if it cannot be opened, or is another object now.
    pub(crate) fn recheck(&self) -> Result<(), PinError> {
        let now = identity(&self.host)?;
        if now == (self.dev, self.ino) {
            Ok(())
        } else {
            Err(PinError {
                path: self.host.display().to_string(),
                msg: format!(
                    "shows {}:{}, pinned {}:{}",
                    now.0, now.1, self.dev, self.ino
                ),
            })
        }
    }

    /// What the in-container check expects at the guest path.
    #[must_use]
    pub(crate) fn expect(&self) -> Expect {
        Expect {
            guest: self.guest.clone(),
            dev: self.dev,
            ino: self.ino,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::os::unix::fs::MetadataExt as _;

    use super::*;
    use crate::egress::scratch::Scratch;

    fn sid(s: &str) -> SessionId {
        SessionId::parse(s).unwrap()
    }

    /// A fresh directory under `target/parts-unit`, canonical, and its guard, which removes it
    /// on drop so a failing assertion leaves nothing behind.
    fn scratch(tag: &str) -> (PathBuf, Scratch) {
        let guard = crate::egress::scratch::scratch("parts-unit", tag);
        (std::fs::canonicalize(&*guard).unwrap(), guard)
    }

    /// A session's entry names the session and the role; an instance's names no session and
    /// carries the instance in its args (architect Q131).
    #[test]
    fn a_session_entry_names_the_session_and_an_instance_entry_its_args() {
        let s = Subject::Session(sid("s-1"));
        assert_eq!(s.id().as_str(), "s-1");
        assert_eq!(s.kind(), "session");
        assert_eq!(Subject::Instance(sid("i-0")).kind(), "instance");
        let e = s.entry("sandbox.stop", Role::Harness, [("x", Value::from(1))]);
        assert_eq!(e.event(), "sandbox.stop");
        assert_eq!(
            e.arguments(),
            &serde_json::json!({"role": "harness", "x": 1})
        );
        let line = format!("{e:?}");
        assert!(line.contains("\"s-1\""), "{line}");
        let i = Subject::Instance(sid("i-1"));
        assert_eq!(i.id().as_str(), "i-1");
        let e = i.entry("sandbox.refuse", Role::Inference, []);
        assert_eq!(
            e.arguments(),
            &serde_json::json!({"role": "inference", "instance": "i-1"})
        );
        let line = format!("{e:?}");
        assert!(line.contains("session: None"), "{line}");
    }

    /// The role and instance keys are the launcher's: a caller's same-named arg is replaced.
    #[test]
    fn the_role_and_instance_keys_cannot_be_forged_by_args() {
        let i = Subject::Instance(sid("i-2"));
        let e = i.entry(
            "sandbox.stop",
            Role::Inference,
            [
                ("role", Value::from("workspace")),
                ("instance", Value::from("x")),
            ],
        );
        assert_eq!(
            e.arguments(),
            &serde_json::json!({"role": "inference", "instance": "i-2"})
        );
    }

    /// While a container may exist, a failed launch's cleanup tries again without bound and
    /// keeps its claim.
    #[test]
    fn a_cleanup_retries_without_bound_while_a_container_may_exist() {
        let mut t = CleanupTries::default();
        for n in 1..=50_u32 {
            assert_eq!(t.record(false, false), NextTry::Again, "try {n}");
            assert_eq!(t.attempts(), n);
        }
        // Even with the directories reported removed: the containers decide first.
        assert_eq!(t.record(false, true), NextTry::Again);
    }

    /// Once both containers are confirmed gone, the directories get at most
    /// `STOP_RETRIES_AFTER_REMOVAL` more tries, then the cleanup ends with them kept.
    #[test]
    fn once_the_containers_are_gone_the_directories_get_a_bounded_number_of_tries() {
        let mut t = CleanupTries::default();
        assert_eq!(t.record(false, false), NextTry::Again);
        // Gone at try 2; tries 3, 4 and 5 are the bounded ones.
        for _ in 0..STOP_RETRIES_AFTER_REMOVAL {
            assert_eq!(t.record(true, false), NextTry::Again);
        }
        assert_eq!(
            t.record(true, false),
            NextTry::Done(Directories::Kept),
            "after {} tries since the containers went",
            STOP_RETRIES_AFTER_REMOVAL
        );
        assert_eq!(t.attempts(), 5);
    }

    /// A first cleanup that removed the containers and failed only on the directories
    /// starts in the bounded phase, counted from that first try.
    #[test]
    fn a_first_try_that_removed_the_containers_starts_in_the_bounded_phase() {
        let mut t = CleanupTries::default();
        assert_eq!(t.record(true, false), NextTry::Again);
        assert_eq!(t.record(true, false), NextTry::Again);
        assert_eq!(t.record(true, false), NextTry::Again);
        assert_eq!(t.record(true, false), NextTry::Done(Directories::Kept));
        assert_eq!(t.attempts(), 1 + STOP_RETRIES_AFTER_REMOVAL);
    }

    /// The first try that removes everything ends the cleanup, in either phase.
    #[test]
    fn a_try_that_removes_everything_ends_the_cleanup() {
        let mut t = CleanupTries::default();
        assert_eq!(t.record(false, false), NextTry::Again);
        assert_eq!(t.record(true, true), NextTry::Done(Directories::Removed));
        assert_eq!(t.attempts(), 2);
        let mut t = CleanupTries::default();
        assert_eq!(t.record(true, false), NextTry::Again);
        assert_eq!(t.record(true, false), NextTry::Again);
        assert_eq!(t.record(true, true), NextTry::Done(Directories::Removed));
        assert_eq!(t.attempts(), 3);
    }

    /// The count saturates, never wraps or panics.
    #[test]
    fn the_attempt_count_saturates() {
        let mut t = CleanupTries {
            attempts: u32::MAX,
            gone_at: None,
        };
        assert_eq!(t.record(false, false), NextTry::Again);
        assert_eq!(t.attempts(), u32::MAX);
    }

    /// Both containers must be gone: a probe or a container still to be removed keeps the
    /// cleanup in its unbounded phase, holding the claim.
    #[test]
    fn the_containers_are_gone_only_when_neither_is_left() {
        assert!(containers_gone(None, None));
        assert!(!containers_gone(Some("sp-probe-ws-a"), None));
        assert!(!containers_gone(None, Some("sp-ws-a")));
        assert!(!containers_gone(Some("sp-probe-ws-a"), Some("sp-ws-a")));
    }

    /// A held claim is reported every thirtieth try, about once a minute: not at the tries
    /// between, and never at the first (which the task's start line already reports).
    #[test]
    fn a_long_retry_is_reported_every_thirty_tries() {
        assert_eq!(CLEANUP_REPORT_EVERY, 30);
        let mut t = CleanupTries::default();
        let mut reported = Vec::new();
        for _ in 0..90 {
            let _ = t.record(false, false);
            if t.worth_reporting() {
                reported.push(t.attempts());
            }
        }
        assert_eq!(reported, [30, 60, 90]);
    }

    /// The shared bound is three tries, the one `stop_role_unreceived` already used.
    #[test]
    fn the_bound_after_removal_is_three() {
        assert_eq!(STOP_RETRIES_AFTER_REMOVAL, 3);
    }

    /// `sandbox.cleaned` names the role and what the cleanup handled, with no decision
    /// and no podman text; an instance's carries the instance.
    #[test]
    fn the_cleaned_entry_names_what_was_cleaned_and_carries_no_decision() {
        let s = Subject::Session(sid("s-3"));
        let made = Made {
            probe: None,
            container: Some("sp-ws-s-3".into()),
        };
        let e = cleaned_entry(&s, Role::Workspace, &made, 2, Directories::Removed);
        assert_eq!(e.event(), "sandbox.cleaned");
        assert_eq!(e.decision_value(), None);
        assert_eq!(
            e.resolved(&sally_core::audit::Redactor::default()),
            serde_json::json!({
                "role": "workspace",
                "container": "sp-ws-s-3",
                "probe": null,
                "attempts": 2,
                "directories": "removed",
            })
        );
        assert!(format!("{e:?}").contains("\"s-3\""));
        let i = Subject::Instance(sid("i-3"));
        let made = Made {
            probe: Some("sp-probe-infer-i-3".into()),
            container: None,
        };
        let e = cleaned_entry(&i, Role::Inference, &made, 7, Directories::Kept);
        assert_eq!(
            e.resolved(&sally_core::audit::Redactor::default()),
            serde_json::json!({
                "role": "inference",
                "instance": "i-3",
                "container": null,
                "probe": "sp-probe-infer-i-3",
                "attempts": 7,
                "directories": "kept",
            })
        );
    }

    #[test]
    fn a_pin_holds_until_its_object_is_replaced() {
        let (dir, _gone) = scratch("swap");
        let p = dir.join("sock");
        std::fs::create_dir(&p).unwrap();
        let pin = HostPin::dir(&p, "/run/sallyport").unwrap();
        let meta = std::fs::symlink_metadata(&p).unwrap();
        assert_eq!(
            pin.expect(),
            Expect {
                guest: "/run/sallyport".into(),
                dev: meta.dev(),
                ino: meta.ino(),
            }
        );
        pin.recheck().unwrap();
        std::fs::rename(&p, dir.join("old")).unwrap();
        std::fs::create_dir(&p).unwrap();
        let e = pin.recheck().unwrap_err();
        assert_eq!(e.path, p.display().to_string());
        assert!(e.msg.starts_with("shows "), "{e}");
        assert!(
            e.msg
                .ends_with(&format!("pinned {}:{}", meta.dev(), meta.ino())),
            "{e}"
        );
        std::fs::remove_dir(&p).unwrap();
        assert!(pin.recheck().is_err(), "gone");
    }

    /// A symlink is refused at the pin and at the re-check, at the end of the path or inside it.
    #[test]
    fn a_symlink_anywhere_on_the_path_is_refused() {
        let (dir, _gone) = scratch("link");
        std::fs::create_dir(dir.join("real")).unwrap();
        std::os::unix::fs::symlink(dir.join("real"), dir.join("link")).unwrap();
        let last = HostPin::dir(&dir.join("link"), "/g").unwrap_err();
        assert_eq!(last.msg, "not a directory");
        std::fs::create_dir(dir.join("real/sub")).unwrap();
        assert!(HostPin::dir(&dir.join("link/sub"), "/g").is_err());
        std::fs::write(dir.join("real/file"), b"").unwrap();
        let file = HostPin::dir(&dir.join("real/file"), "/g").unwrap_err();
        assert_eq!(file.msg, "not a directory");
        let pin = HostPin::dir(&dir.join("real/sub"), "/g").unwrap();
        std::fs::rename(dir.join("real"), dir.join("moved")).unwrap();
        std::os::unix::fs::symlink(dir.join("moved"), dir.join("real")).unwrap();
        assert!(pin.recheck().is_err(), "the same inode through a symlink");
    }

    #[test]
    fn a_model_pin_keeps_the_identity_of_its_import() {
        use std::os::unix::fs::PermissionsExt as _;
        let (dir, _gone) = scratch("model");
        let digest = "b".repeat(64);
        let blob = dir.join("sha256").join(&digest);
        std::fs::create_dir_all(blob.parent().unwrap()).unwrap();
        std::fs::write(&blob, b"GGUF").unwrap();
        std::fs::set_permissions(&blob, std::fs::Permissions::from_mode(0o444)).unwrap();
        let m = VerifiedModel::pin(&dir, &digest).unwrap();
        let pin = HostPin::model(&m, "/models/model.gguf");
        let (dev, ino) = m.identity();
        assert_eq!(
            pin.expect(),
            Expect {
                guest: "/models/model.gguf".into(),
                dev,
                ino,
            }
        );
        pin.recheck().unwrap();
        // Written before the rename, so both inodes exist at once: never the same number.
        let new = dir.join("new");
        std::fs::write(&new, b"GGUF").unwrap();
        std::fs::rename(&new, &blob).unwrap();
        assert!(pin.recheck().is_err(), "a new file at the same path");
    }
}
