use std::fmt;

use zeroize::Zeroize;

/// A value that must never be printed, logged or serialized.
///
/// `Debug` is redacted, there is no `Display`, `Clone` or `Serialize`, and the value is
/// zeroized on drop. The only way to read it is the explicit [`Secret::expose`].
pub struct Secret<T: Zeroize>(T);

impl<T: Zeroize> Secret<T> {
    /// Wraps a value.
    #[must_use]
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// The plaintext. Callers must not log it, copy it into an environment, an argv or a file,
    /// or hand it to anything a sandbox can read (SI-3).
    #[must_use]
    pub const fn expose(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}
