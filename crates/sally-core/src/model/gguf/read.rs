//! A forward-only little-endian reader with a byte budget: every read checks the budget, then the
//! bytes the file has left, before it touches the source or allocates, so no length taken from
//! the file can make it read or keep more than the budget allows.
#![deny(clippy::indexing_slicing)]

use std::io::{self, Read};

/// Why a read did not return its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadError {
    /// The source ended first.
    Truncated,
    /// The read would pass the budget.
    OverBudget,
    /// The source failed.
    Io(io::ErrorKind),
}

impl From<io::Error> for ReadError {
    fn from(e: io::Error) -> Self {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            Self::Truncated
        } else {
            Self::Io(e.kind())
        }
    }
}

/// Reads `R` from the start, at most `budget` bytes in all, of a file `file_len` bytes long.
#[derive(Debug)]
pub struct Reader<R> {
    inner: R,
    position: u64,
    budget: u64,
    file_len: u64,
}

impl<R: Read> Reader<R> {
    /// A reader at position 0.
    pub const fn new(inner: R, budget: u64, file_len: u64) -> Self {
        Self {
            inner,
            position: 0,
            budget,
            file_len,
        }
    }

    /// Bytes consumed so far.
    pub const fn position(&self) -> u64 {
        self.position
    }

    /// Takes `len` bytes of budget, or refuses without consuming any: past the budget is
    /// [`ReadError::OverBudget`], within it but past the file's end is [`ReadError::Truncated`].
    fn claim(&mut self, len: u64) -> Result<(), ReadError> {
        let end = self
            .position
            .checked_add(len)
            .ok_or(ReadError::OverBudget)?;
        if end > self.budget {
            return Err(ReadError::OverBudget);
        }
        if end > self.file_len {
            return Err(ReadError::Truncated);
        }
        self.position = end;
        Ok(())
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ReadError> {
        let mut buf = [0u8; N];
        self.claim(N as u64)?;
        self.inner.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// One byte.
    pub fn u8(&mut self) -> Result<u8, ReadError> {
        self.array::<1>().map(u8::from_le_bytes)
    }

    /// One signed byte.
    pub fn i8(&mut self) -> Result<i8, ReadError> {
        self.array::<1>().map(i8::from_le_bytes)
    }

    /// A little-endian `u16`.
    pub fn u16(&mut self) -> Result<u16, ReadError> {
        self.array::<2>().map(u16::from_le_bytes)
    }

    /// A little-endian `i16`.
    pub fn i16(&mut self) -> Result<i16, ReadError> {
        self.array::<2>().map(i16::from_le_bytes)
    }

    /// A little-endian `u32`.
    pub fn u32(&mut self) -> Result<u32, ReadError> {
        self.array::<4>().map(u32::from_le_bytes)
    }

    /// A little-endian `i32`.
    pub fn i32(&mut self) -> Result<i32, ReadError> {
        self.array::<4>().map(i32::from_le_bytes)
    }

    /// A little-endian `u64`.
    pub fn u64(&mut self) -> Result<u64, ReadError> {
        self.array::<8>().map(u64::from_le_bytes)
    }

    /// A little-endian `i64`.
    pub fn i64(&mut self) -> Result<i64, ReadError> {
        self.array::<8>().map(i64::from_le_bytes)
    }

    /// A little-endian `f32`.
    pub fn f32(&mut self) -> Result<f32, ReadError> {
        self.array::<4>().map(f32::from_le_bytes)
    }

    /// A little-endian `f64`.
    pub fn f64(&mut self) -> Result<f64, ReadError> {
        self.array::<8>().map(f64::from_le_bytes)
    }

    /// The next `len` bytes. The budget is checked first; the buffer then grows only as bytes
    /// arrive, so a length the source cannot back allocates no more than the source holds.
    pub fn bytes(&mut self, len: u64) -> Result<Vec<u8>, ReadError> {
        self.claim(len)?;
        let mut out = Vec::new();
        let got = (&mut self.inner).take(len).read_to_end(&mut out)?;
        if got as u64 != len {
            return Err(ReadError::Truncated);
        }
        Ok(out)
    }

    /// Consumes the next `len` bytes without keeping them.
    pub fn skip(&mut self, len: u64) -> Result<(), ReadError> {
        self.claim(len)?;
        let got = io::copy(&mut (&mut self.inner).take(len), &mut io::sink())?;
        if got != len {
            return Err(ReadError::Truncated);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "read_tests.rs"]
mod tests;
