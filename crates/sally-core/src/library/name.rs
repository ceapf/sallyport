//! The name of the file a model was imported from. Whoever named the file chose it, so it is
//! shown only escaped: [`SourceName`]'s `Display` and `Debug` go through [`crate::text::escape`],
//! which leaves printable ASCII and nothing else (no terminal escape, line break, bidirectional
//! or zero-width character survives).

use std::ffi::OsStr;
use std::fmt;

use crate::model::detect;
use crate::text;

/// Longest source name kept, in bytes (`NAME_MAX`).
const MAX_BYTES: usize = 255;

/// An imported file's name: one the allowlist accepts, at most 255 bytes, no control character.
#[derive(Clone, PartialEq, Eq)]
pub struct SourceName(String);

impl SourceName {
    /// `name`, if the library keeps it.
    pub(super) fn checked(name: &str) -> Option<Self> {
        ok(name).then(|| Self(name.to_owned()))
    }

    /// The name exactly as the file had it. Text, never HTML: escape it before it reaches a
    /// terminal or a log (`Display` does).
    #[must_use]
    pub fn as_raw_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SourceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&text::escape(self.0.as_bytes()))
    }
}

impl fmt::Debug for SourceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SourceName({self})")
    }
}

/// A name the library keeps: the allowlist accepts it, it is at most 255 bytes, and it holds no
/// control character.
pub(super) fn ok(name: &str) -> bool {
    name.len() <= MAX_BYTES
        && !name.chars().any(char::is_control)
        && detect::by_name(OsStr::new(name)).is_ok()
}

#[cfg(test)]
#[path = "name_tests.rs"]
mod tests;
