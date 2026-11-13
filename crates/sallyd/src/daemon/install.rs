//! This installation's id (architect Q64): a UUID v4 kept in `sallyd`'s state directory as
//! [`INSTALLATION_FILE`] (0600). Every container the launcher creates carries it as a label, and
//! both orphan sweeps remove only containers that carry it, so another daemon's containers and a
//! test run's are never touched, while a container the previous `sallyd` of this installation
//! created after it was killed is. The first start creates the file under the single-instance
//! lock, crash-safe (see [`create`]); later starts read it like `config.toml` (a regular file,
//! never through a symlink, bounded). A file that is not exactly one id refuses the start: it is
//! never regenerated, since a new id would leave the old one's orphans unswept. The id never
//! leaves the machine and is never written to the audit log (SI-12).

use std::io::{self, Read, Write};
use std::path::Path;

use rustix::fs::{AtFlags, FileType, Mode, OFlags, RenameFlags};
use rustix::io::Errno;

use crate::sandbox::Installation;

/// The file's name in the state directory.
pub const INSTALLATION_FILE: &str = "installation";
/// The name the id is written under before it is renamed into place.
const TEMP_FILE: &str = "installation.new";
/// Bytes read at most: an id, a newline, and one more so that a longer file is seen.
const READ_CAP: u64 = 38;

/// Why the installation id could not be read or made.
#[derive(Debug, thiserror::Error)]
#[error("{path}: {msg}")]
pub struct InstallError {
    /// The file or directory.
    pub path: String,
    /// What is wrong.
    pub msg: String,
    /// The OS error behind it, if any.
    #[source]
    pub source: Option<io::Error>,
}

fn fail(path: &Path, msg: impl Into<String>, source: Option<io::Error>) -> InstallError {
    InstallError {
        path: path.display().to_string(),
        msg: msg.into(),
        source,
    }
}

/// Reads `state/installation`, or creates it with a fresh id when it does not exist. Call it
/// while holding the single-instance lock.
///
/// # Errors
/// [`InstallError`]: the file is a symlink or not a regular file, is not exactly one id and a
/// newline, or cannot be read, created or written.
pub fn load_or_create(state: &Path) -> Result<Installation, InstallError> {
    let path = state.join(INSTALLATION_FILE);
    // NONBLOCK: a FIFO planted here neither hangs the start nor is read. The wrapper adds
    // O_CLOEXEC.
    let read = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK;
    let fd = match sally_core::fd::open(&path, read, Mode::empty()) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return create(state),
        Err(Errno::LOOP) => return Err(fail(&path, "a symlink is not followed", None)),
        Err(e) => return Err(fail(&path, "cannot be opened", Some(e.into()))),
    };
    let st = rustix::fs::fstat(&fd).map_err(|e| fail(&path, "cannot be read", Some(e.into())))?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Err(fail(&path, "not a regular file", None));
    }
    let mut text = String::new();
    std::fs::File::from(fd)
        .take(READ_CAP)
        .read_to_string(&mut text)
        .map_err(|e| fail(&path, "cannot be read", Some(e)))?;
    let id = text
        .strip_suffix('\n')
        .ok_or_else(|| fail(&path, "not one installation id and a newline", None))?;
    Installation::parse(id).map_err(|e| fail(&path, e.to_string(), None))
}

/// Writes a fresh id to [`TEMP_FILE`] (created exclusively, 0600) and syncs it, renames it to
/// [`INSTALLATION_FILE`] without replacing anything there (a file or a symlink), then syncs the
/// directory. A crash leaves no file or a whole one, never an empty one that would refuse every
/// later start (security review PS-L3).
fn create(state: &Path) -> Result<Installation, InstallError> {
    let path = state.join(INSTALLATION_FILE);
    let temp = state.join(TEMP_FILE);
    let id = Installation::fresh().map_err(|e| fail(&path, e.to_string(), None))?;
    // O_RDONLY is 0. The wrapper adds O_CLOEXEC.
    let dir = sally_core::fd::open(state, OFlags::DIRECTORY, Mode::empty())
        .map_err(|e| fail(state, "cannot be opened", Some(e.into())))?;
    // Only a crash before the rename leaves it, and no start has used the id in it.
    match rustix::fs::unlinkat(&dir, TEMP_FILE, AtFlags::empty()) {
        Ok(()) | Err(Errno::NOENT) => {}
        Err(e) => return Err(fail(&temp, "cannot be removed", Some(e.into()))),
    }
    let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL;
    let fd = sally_core::fd::openat(&dir, TEMP_FILE, flags, Mode::from_raw_mode(0o600))
        .map_err(|e| fail(&temp, "cannot be created", Some(e.into())))?;
    let mut f = std::fs::File::from(fd);
    f.write_all(format!("{}\n", id.as_str()).as_bytes())
        .and_then(|()| f.sync_all())
        .map_err(|e| fail(&temp, "cannot be written", Some(e)))?;
    let moved = rustix::fs::renameat_with(
        &dir,
        TEMP_FILE,
        &dir,
        INSTALLATION_FILE,
        RenameFlags::NOREPLACE,
    );
    if let Err(e) = moved {
        let _ = rustix::fs::unlinkat(&dir, TEMP_FILE, AtFlags::empty());
        return Err(fail(&path, "cannot be created", Some(e.into())));
    }
    rustix::fs::fsync(&dir).map_err(|e| fail(state, "cannot be synced", Some(e.into())))?;
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
        let d = dir("missing");
        assert!(load_or_create(&d.join("absent")).is_err());
        std::fs::remove_dir_all(&d).unwrap();
    }

    // The read saw no file, but one appeared before the create (only a racing writer could do
    // that, under the lock): the create never replaces it, nor writes through a planted
    // symlink, and leaves no temporary file behind.
    #[test]
    fn the_create_refuses_a_name_that_exists_even_a_planted_symlink() {
        let d = dir("exists");
        let f = d.join(INSTALLATION_FILE);
        let target = d.join("target");
        let id = "0123abcd-ef01-4234-8567-89abcdef0123\n";
        std::fs::write(&f, id).unwrap();
        assert!(create(&d).is_err());
        assert_eq!(std::fs::read_to_string(&f).unwrap(), id);
        std::fs::remove_file(&f).unwrap();
        std::os::unix::fs::symlink(&target, &f).unwrap();
        let e = create(&d).unwrap_err();
        assert!(e.path.ends_with(INSTALLATION_FILE), "{e}");
        assert!(!target.exists(), "never created through a dangling symlink");
        std::fs::write(&target, b"kept").unwrap();
        assert!(create(&d).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"kept");
        assert!(!d.join(TEMP_FILE).exists());
        std::fs::remove_dir_all(&d).unwrap();
    }

    // A crash between writing the temporary file and the rename leaves it behind; the next
    // start replaces it (a planted symlink is removed, never followed) and creates the id.
    #[test]
    fn a_temporary_file_left_by_a_crash_is_replaced() {
        let d = dir("temp");
        let temp = d.join(TEMP_FILE);
        std::fs::write(&temp, b"").unwrap();
        let first = load_or_create(&d).unwrap();
        assert!(!temp.exists());
        assert_eq!(load_or_create(&d).unwrap(), first);
        std::fs::remove_file(d.join(INSTALLATION_FILE)).unwrap();
        let outside = d.join("outside");
        std::fs::write(&outside, b"kept").unwrap();
        std::os::unix::fs::symlink(&outside, &temp).unwrap();
        load_or_create(&d).unwrap();
        assert_eq!(std::fs::read(&outside).unwrap(), b"kept");
        assert!(std::fs::symlink_metadata(&temp).is_err());
        let mode = std::fs::metadata(d.join(INSTALLATION_FILE)).unwrap();
        assert_eq!(mode.permissions().mode() & 0o777, 0o600, "owner-only");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn the_read_cap_is_one_byte_past_an_id_and_a_newline() {
        let id = "0123abcd-ef01-4234-8567-89abcdef0123\n";
        assert_eq!(READ_CAP, u64::try_from(id.len()).unwrap() + 1);
    }
}
