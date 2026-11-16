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

    fn sid(s: &str) -> SessionId {
        SessionId::parse(s).unwrap()
    }

    /// Removes the scratch directory when the test ends, passed or failed.
    struct Gone(PathBuf);

    impl Drop for Gone {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn scratch(tag: &str) -> (PathBuf, Gone) {
        let p = std::env::temp_dir().join(format!("sp-parts-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        (p.clone(), Gone(p))
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
        let _ = std::fs::remove_dir_all(&dir);
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
        let _ = std::fs::remove_dir_all(&dir);
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
        let _ = std::fs::remove_dir_all(&dir);
    }
}
