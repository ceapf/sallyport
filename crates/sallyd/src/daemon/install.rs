//! This installation's id (architect Q64): a UUID v4 kept in `sallyd`'s state directory as
//! [`INSTALLATION_FILE`] (0600). Every container the launcher creates carries it as a label, and
//! both orphan sweeps remove only containers that carry it, so another daemon's containers and a
//! test run's are never touched, while a container the previous `sallyd` of this installation
//! created after it was killed is. The first start creates the file exclusively, under the
//! single-instance lock; later starts read it like `config.toml` (a regular file, never through
//! a symlink, bounded). A file that is not exactly one id refuses the start: it is never
//! regenerated, since a new id would leave the old one's orphans unswept. The id never leaves
//! the machine and is never written to the audit log (SI-12).

use std::io::{Read, Write};
use std::path::Path;

use rustix::fs::{FileType, Mode, OFlags};

use crate::sandbox::Installation;

/// The file's name in the state directory.
pub const INSTALLATION_FILE: &str = "installation";
/// The file's only content: an id and a newline.
const FILE_BYTES: usize = 37;

/// Why the installation id could not be read or made.
#[derive(Debug, thiserror::Error)]
#[error("{path}: {msg}")]
pub struct InstallError {
    /// The file.
    pub path: String,
    /// What is wrong.
    pub msg: String,
}

/// Reads `state/installation`, or creates it with a fresh id when it does not exist. Call it
/// while holding the single-instance lock.
///
/// # Errors
/// [`InstallError`]: the file is a symlink or not a regular file, is not exactly one id and a
/// newline, or cannot be read, created or written.
pub fn load_or_create(state: &Path) -> Result<Installation, InstallError> {
    let path = state.join(INSTALLATION_FILE);
    let fail = |msg: String| InstallError {
        path: path.display().to_string(),
        msg,
    };
    let read = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    match sally_core::fd::open(&path, read, Mode::empty()) {
        Ok(fd) => {
            let st = rustix::fs::fstat(&fd).map_err(|e| fail(e.to_string()))?;
            if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
                return Err(fail("not a regular file".into()));
            }
            let mut text = String::new();
            let cap = u64::try_from(FILE_BYTES).unwrap_or(u64::MAX) + 1;
            std::fs::File::from(fd)
                .take(cap)
                .read_to_string(&mut text)
                .map_err(|e| fail(e.to_string()))?;
            let id = text
                .strip_suffix('\n')
                .ok_or_else(|| fail("not one installation id and a newline".into()))?;
            Installation::parse(id).map_err(|e| fail(e.to_string()))
        }
        Err(rustix::io::Errno::NOENT) => create(&path).map_err(fail),
        Err(rustix::io::Errno::LOOP) => Err(fail("a symlink is not followed".into())),
        Err(e) => Err(fail(e.to_string())),
    }
}

/// Creates the file exclusively (0600) with a fresh id.
fn create(path: &Path) -> Result<Installation, String> {
    let id = Installation::fresh().map_err(|e| e.to_string())?;
    let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let fd =
        sally_core::fd::open(path, flags, Mode::from_raw_mode(0o600)).map_err(|e| e.to_string())?;
    let mut f = std::fs::File::from(fd);
    f.write_all(format!("{}\n", id.as_str()).as_bytes())
        .and_then(|()| f.sync_all())
        .map_err(|e| e.to_string())?;
    Ok(id)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("sallyd-install-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn the_first_start_creates_a_private_id_and_later_starts_reuse_it() {
        let d = dir("create");
        let first = load_or_create(&d).unwrap();
        let f = d.join(INSTALLATION_FILE);
        let meta = std::fs::metadata(&f).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert_eq!(
            std::fs::read_to_string(&f).unwrap(),
            format!("{}\n", first.as_str())
        );
        assert_eq!(load_or_create(&d).unwrap(), first);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn an_existing_id_is_read_as_is() {
        let d = dir("existing");
        let id = "0123abcd-ef01-4234-8567-89abcdef0123";
        std::fs::write(d.join(INSTALLATION_FILE), format!("{id}\n")).unwrap();
        assert_eq!(load_or_create(&d).unwrap().as_str(), id);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn anything_but_one_id_and_a_newline_refuses_the_start_and_is_kept() {
        let d = dir("garbage");
        let f = d.join(INSTALLATION_FILE);
        let id = "0123abcd-ef01-4234-8567-89abcdef0123";
        for bad in [
            String::new(),
            "\n".to_owned(),
            id.to_owned(),
            format!("{id}\n\n"),
            format!("{id}\nx"),
            format!(" {id}\n"),
            format!("{}\n", id.to_uppercase()),
            format!("{}\n", "a".repeat(4096)),
        ] {
            std::fs::write(&f, &bad).unwrap();
            let e = load_or_create(&d).unwrap_err();
            assert!(e.path.ends_with(INSTALLATION_FILE), "{e}");
            assert_eq!(
                std::fs::read_to_string(&f).unwrap(),
                bad,
                "never regenerated"
            );
        }
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_symlink_a_fifo_or_a_directory_is_refused() {
        let d = dir("kinds");
        let f = d.join(INSTALLATION_FILE);
        let target = d.join("elsewhere");
        std::fs::write(&target, "0123abcd-ef01-4234-8567-89abcdef0123\n").unwrap();
        std::os::unix::fs::symlink(&target, &f).unwrap();
        let e = load_or_create(&d).unwrap_err();
        assert!(e.msg.contains("symlink"), "{e}");
        std::fs::remove_file(&f).unwrap();
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &f,
            FileType::Fifo,
            Mode::from_raw_mode(0o600),
            0,
        )
        .unwrap();
        // NONBLOCK: a FIFO with no writer neither hangs the start nor is read.
        let e = load_or_create(&d).unwrap_err();
        assert!(e.msg.contains("not a regular file"), "{e}");
        std::fs::remove_file(&f).unwrap();
        std::fs::create_dir(&f).unwrap();
        assert!(load_or_create(&d).is_err());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_missing_state_directory_is_an_error_not_a_new_id() {
        let d = dir("missing").join("absent");
        assert!(load_or_create(&d).is_err());
    }
}
