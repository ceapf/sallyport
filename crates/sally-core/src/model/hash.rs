//! A model's SHA-256 (SI-6): [`Hasher`] over the bytes as they stream past, and [`Digest`], the
//! only name a library blob has.

use std::fmt::{self, Write as _};

use sha2::{Digest as _, Sha256};

/// Hex digits in a SHA-256 digest.
const HEX_LEN: usize = 64;

/// A SHA-256 digest as 64 lowercase hex digits: the name of a blob in the library. The only ways
/// to get one are [`Hasher::finish`] and [`Digest::parse`], so its text is always a single safe
/// file name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest(String);

impl Digest {
    /// Parses a digest written as 64 lowercase hex digits.
    ///
    /// # Errors
    /// [`DigestError`] for anything else: another length, an uppercase or non-hex character.
    pub fn parse(hex: &str) -> Result<Self, DigestError> {
        if hex.len() == HEX_LEN && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            Ok(Self(hex.to_owned()))
        } else {
            Err(DigestError)
        }
    }

    /// The 64 lowercase hex digits.
    #[must_use]
    pub fn as_hex(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Text that is not a digest. It never echoes the text, which the caller chose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a model digest is 64 lowercase hex digits (SHA-256)")]
pub struct DigestError;

impl DigestError {
    /// The stable reason code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        "bad_digest"
    }
}

/// A SHA-256 over bytes fed in order, counting them.
#[derive(Debug, Clone, Default)]
pub struct Hasher {
    sha: Sha256,
    bytes: u64,
}

impl Hasher {
    /// Feeds the next bytes.
    pub fn update(&mut self, data: &[u8]) {
        self.sha.update(data);
        self.bytes = self.bytes.saturating_add(data.len() as u64);
    }

    /// Bytes fed so far.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    /// The digest of every byte fed.
    #[must_use]
    pub fn finish(self) -> Digest {
        let sum = self.sha.finalize();
        let hex = sum.iter().fold(String::with_capacity(HEX_LEN), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        });
        Digest(hex)
    }
}

#[cfg(test)]
#[path = "hash_tests.rs"]
mod tests;
