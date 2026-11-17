//! Which model format a file is, in two steps (SI-6): the name first, the first bytes second.
//!
//! [`by_name`] reads no bytes. It accepts only the extensions on the allowlist, so a pickle-family
//! file (`.bin`, `.pt`, `.pth`, `.pkl`, `.pickle`, `.ckpt`, `.h5`, ...) is refused before anyone
//! opens it. Its [`Candidate`] has no public constructor, so [`Candidate::check_magic`] cannot
//! run on a name that was never checked. A [`Format`] value alone is no proof that detect ran.
//!
//! The allowlist is exactly the lowercase extension `gguf` for now: `.safetensors` is refused
//! until the safetensors check exists (M2 Task 2).
#![deny(clippy::indexing_slicing)]

use std::ffi::OsStr;
use std::path::Path;

/// The GGUF magic.
pub const GGUF_MAGIC: &[u8; 4] = b"GGUF";

/// A model format the library accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Format {
    /// A single-file GGUF model.
    Gguf,
}

/// Why a file is not an accepted model format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DetectError {
    /// The file name's extension is not on the allowlist, or the name is not one UTF-8 path
    /// component without NUL.
    #[error("the file type is not an accepted model format")]
    FormatNotAllowed,
    /// The first bytes are not the magic the extension promises.
    #[error("the file's first bytes do not match its type")]
    MagicMismatch,
}

impl DetectError {
    /// The stable reason code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::FormatNotAllowed => "format_not_allowed",
            Self::MagicMismatch => "magic_mismatch",
        }
    }
}

/// A file whose name passed [`by_name`]; its bytes are not checked yet.
#[derive(Debug, PartialEq, Eq)]
pub struct Candidate {
    format: Format,
}

/// Step 1: the format the file name's extension allows. Reads no bytes.
///
/// `file_name` is one path component: the name of the file that will be opened, never a path.
///
/// # Errors
/// [`DetectError::FormatNotAllowed`] unless the name is UTF-8 without `/` or NUL and its
/// extension is exactly `gguf`.
pub fn by_name(file_name: &OsStr) -> Result<Candidate, DetectError> {
    let name = file_name.to_str().ok_or(DetectError::FormatNotAllowed)?;
    if name.contains(['/', '\0']) {
        return Err(DetectError::FormatNotAllowed);
    }
    match Path::new(name).extension().and_then(OsStr::to_str) {
        Some("gguf") => Ok(Candidate {
            format: Format::Gguf,
        }),
        _ => Err(DetectError::FormatNotAllowed),
    }
}

impl Candidate {
    /// Step 2: the format, once the file's first bytes carry its magic.
    ///
    /// # Errors
    /// [`DetectError::MagicMismatch`] when `head` does not start with the magic (a head shorter
    /// than the magic included).
    pub fn check_magic(self, head: &[u8]) -> Result<Format, DetectError> {
        match self.format {
            Format::Gguf if head.starts_with(GGUF_MAGIC) => Ok(Format::Gguf),
            Format::Gguf => Err(DetectError::MagicMismatch),
        }
    }
}

#[cfg(test)]
#[path = "detect_tests.rs"]
mod tests;
