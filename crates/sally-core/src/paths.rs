//! Where Sallyport keeps its files (ARCHITECTURE §3.1, D9), derived once for `sallyd` and the
//! `sally` CLI alike, so the CLI's `secrets.toml` and audit directory can never differ from the
//! daemon's (architect Q107).
//!
//! The derivation takes the environment lookup as an argument: production passes
//! [`std::env::var_os`], tests pass a table. A variable that is unset or not an absolute path is
//! ignored, as if unset.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// The subdirectory Sallyport owns under the data, config and runtime directories.
pub const STATE_DIR: &str = "sallyport";
/// The control socket's name in the runtime state directory.
pub const CONTROL_SOCKET: &str = "control.sock";

/// A variable the paths need is missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PathsError {
    /// `$HOME` is unset or relative.
    #[error("$HOME is not set to an absolute path")]
    Home,
    /// `$XDG_RUNTIME_DIR` is unset or relative.
    #[error("$XDG_RUNTIME_DIR is not set to an absolute path")]
    Runtime,
}

/// The user's Sallyport directories.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    home: PathBuf,
    runtime: Option<PathBuf>,
    data_home: PathBuf,
    config_home: PathBuf,
}

impl Paths {
    /// The directories named by `var` (an environment lookup).
    ///
    /// # Errors
    /// [`PathsError::Home`] when `$HOME` is unset or relative. `$XDG_RUNTIME_DIR` is checked
    /// only by [`Paths::runtime`].
    pub fn from_lookup(var: impl Fn(&str) -> Option<OsString>) -> Result<Self, PathsError> {
        let abs = |name: &str| var(name).map(PathBuf::from).filter(|p| p.is_absolute());
        let home = abs("HOME").ok_or(PathsError::Home)?;
        Ok(Self {
            runtime: abs("XDG_RUNTIME_DIR"),
            data_home: abs("XDG_DATA_HOME").unwrap_or_else(|| home.join(".local/share")),
            config_home: abs("XDG_CONFIG_HOME").unwrap_or_else(|| home.join(".config")),
            home,
        })
    }

    /// The directories of this process's environment.
    ///
    /// # Errors
    /// As [`Paths::from_lookup`].
    pub fn from_env() -> Result<Self, PathsError> {
        Self::from_lookup(|name| std::env::var_os(name))
    }

    /// `$HOME`.
    #[must_use]
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// `$XDG_RUNTIME_DIR`.
    ///
    /// # Errors
    /// [`PathsError::Runtime`] when it is unset or relative.
    pub fn runtime(&self) -> Result<&Path, PathsError> {
        self.runtime.as_deref().ok_or(PathsError::Runtime)
    }

    /// `$XDG_DATA_HOME`, or `~/.local/share`.
    #[must_use]
    pub fn data_home(&self) -> &Path {
        &self.data_home
    }

    /// `$XDG_CONFIG_HOME`, or `~/.config`.
    #[must_use]
    pub fn config_home(&self) -> &Path {
        &self.config_home
    }

    /// `<data home>/sallyport`: the audit log, session data, the installation id.
    #[must_use]
    pub fn state(&self) -> PathBuf {
        self.data_home.join(STATE_DIR)
    }

    /// `<data home>/sallyport/audit`.
    #[must_use]
    pub fn audit(&self) -> PathBuf {
        self.state().join("audit")
    }

    /// `<config home>/sallyport/config.toml`.
    #[must_use]
    pub fn config_file(&self) -> PathBuf {
        self.config_home.join(STATE_DIR).join("config.toml")
    }

    /// `<config home>/sallyport/secrets.toml`, beside `config.toml` (D9).
    #[must_use]
    pub fn secrets_file(&self) -> PathBuf {
        self.config_home.join(STATE_DIR).join("secrets.toml")
    }

    /// `$XDG_RUNTIME_DIR/sallyport/control.sock`.
    ///
    /// # Errors
    /// [`PathsError::Runtime`].
    pub fn control_socket(&self) -> Result<PathBuf, PathsError> {
        Ok(self.runtime()?.join(STATE_DIR).join(CONTROL_SOCKET))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn with(vars: &[(&str, &str)]) -> Result<Paths, PathsError> {
        let vars: Vec<(String, String)> = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        Paths::from_lookup(move |name| {
            vars.iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| OsString::from(v))
        })
    }

    #[test]
    fn the_defaults_are_under_home() {
        let p = with(&[("HOME", "/h")]).unwrap();
        assert_eq!(p.home(), Path::new("/h"));
        assert_eq!(p.data_home(), Path::new("/h/.local/share"));
        assert_eq!(p.config_home(), Path::new("/h/.config"));
        assert_eq!(p.state(), Path::new("/h/.local/share/sallyport"));
        assert_eq!(p.audit(), Path::new("/h/.local/share/sallyport/audit"));
        assert_eq!(
            p.config_file(),
            Path::new("/h/.config/sallyport/config.toml")
        );
        assert_eq!(
            p.secrets_file(),
            Path::new("/h/.config/sallyport/secrets.toml")
        );
        assert_eq!(p.runtime(), Err(PathsError::Runtime));
        assert_eq!(p.control_socket(), Err(PathsError::Runtime));
    }

    #[test]
    fn the_xdg_variables_override_the_defaults() {
        let p = with(&[
            ("HOME", "/h"),
            ("XDG_DATA_HOME", "/d"),
            ("XDG_CONFIG_HOME", "/c"),
            ("XDG_RUNTIME_DIR", "/r"),
        ])
        .unwrap();
        assert_eq!(p.audit(), Path::new("/d/sallyport/audit"));
        assert_eq!(p.secrets_file(), Path::new("/c/sallyport/secrets.toml"));
        assert_eq!(p.runtime(), Ok(Path::new("/r")));
        assert_eq!(
            p.control_socket().unwrap(),
            Path::new("/r/sallyport/control.sock")
        );
    }

    #[test]
    fn relative_values_are_ignored() {
        let p = with(&[
            ("HOME", "/h"),
            ("XDG_DATA_HOME", "d"),
            ("XDG_CONFIG_HOME", "c"),
            ("XDG_RUNTIME_DIR", "r"),
        ])
        .unwrap();
        assert_eq!(p.data_home(), Path::new("/h/.local/share"));
        assert_eq!(p.config_home(), Path::new("/h/.config"));
        assert_eq!(p.runtime(), Err(PathsError::Runtime));
    }

    #[test]
    fn home_is_required_and_absolute() {
        assert_eq!(with(&[]), Err(PathsError::Home));
        assert_eq!(with(&[("HOME", "h")]), Err(PathsError::Home));
        assert_eq!(
            PathsError::Runtime.to_string(),
            "$XDG_RUNTIME_DIR is not set to an absolute path"
        );
    }
}
