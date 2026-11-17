//! The ggml tensor types a GGUF file may name, with the block layout that sizes a tensor's data.
//!
//! The table is llama.cpp's `type_traits` (ggml/src/ggml.c) at commit
//! a49db739fba21964e5a05c4d8c35e352b293242e (2026-11-17): block size and bytes per block, the
//! byte counts summed from the block structs in ggml/src/ggml-common.h. Ids whose support was
//! removed upstream (4, 5, 31-33, 36-38) and every id past the last row are not types: a file
//! that names one is refused. A type added upstream later is refused until this table gains it.
// TODO(#182): once M3 pins the engine, a test compares this table with the pin's type_traits.
#![deny(clippy::indexing_slicing)]

/// Why [`GgmlType::bytes`] gave no size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SizeError {
    /// The first dimension is not a whole number of blocks.
    PartialBlock,
    /// The size does not fit in a `u64`.
    Overflow,
}

/// One ggml tensor type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GgmlType {
    id: u32,
    name: &'static str,
    block_size: u64,
    block_bytes: u64,
}

const fn row(id: u32, name: &'static str, block_size: u64, block_bytes: u64) -> GgmlType {
    GgmlType {
        id,
        name,
        block_size,
        block_bytes,
    }
}

/// Every accepted type, by id.
const TYPES: &[GgmlType] = &[
    row(0, "F32", 1, 4),
    row(1, "F16", 1, 2),
    row(2, "Q4_0", 32, 18),
    row(3, "Q4_1", 32, 20),
    row(6, "Q5_0", 32, 22),
    row(7, "Q5_1", 32, 24),
    row(8, "Q8_0", 32, 34),
    row(9, "Q8_1", 32, 36),
    row(10, "Q2_K", 256, 84),
    row(11, "Q3_K", 256, 110),
    row(12, "Q4_K", 256, 144),
    row(13, "Q5_K", 256, 176),
    row(14, "Q6_K", 256, 210),
    row(15, "Q8_K", 256, 292),
    row(16, "IQ2_XXS", 256, 66),
    row(17, "IQ2_XS", 256, 74),
    row(18, "IQ3_XXS", 256, 98),
    row(19, "IQ1_S", 256, 50),
    row(20, "IQ4_NL", 32, 18),
    row(21, "IQ3_S", 256, 110),
    row(22, "IQ2_S", 256, 82),
    row(23, "IQ4_XS", 256, 136),
    row(24, "I8", 1, 1),
    row(25, "I16", 1, 2),
    row(26, "I32", 1, 4),
    row(27, "I64", 1, 8),
    row(28, "F64", 1, 8),
    row(29, "IQ1_M", 256, 56),
    row(30, "BF16", 1, 2),
    row(34, "TQ1_0", 256, 54),
    row(35, "TQ2_0", 256, 66),
    row(39, "MXFP4", 32, 17),
    row(40, "NVFP4", 64, 36),
    row(41, "Q1_0", 128, 18),
    row(42, "Q2_0", 64, 18),
    row(43, "F8_E4M3", 1, 1),
];

impl GgmlType {
    /// The type with this id, or `None` for a removed or unknown id.
    #[must_use]
    pub fn from_id(id: u32) -> Option<Self> {
        TYPES.iter().copied().find(|t| t.id == id)
    }

    /// The id as the file stores it.
    #[must_use]
    pub const fn id(self) -> u32 {
        self.id
    }

    /// llama.cpp's name for the type (`Q4_K`).
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.name
    }

    /// Elements per block.
    #[must_use]
    pub const fn block_size(self) -> u64 {
        self.block_size
    }

    /// Bytes per block.
    #[must_use]
    pub const fn block_bytes(self) -> u64 {
        self.block_bytes
    }

    /// Bytes of data a tensor of this type with these dimensions holds. No dimensions is one
    /// element; the parser refuses that shape before it asks.
    ///
    /// # Errors
    /// [`SizeError::PartialBlock`] when the first dimension is not a whole number of blocks,
    /// [`SizeError::Overflow`] when the size does not fit in a `u64`.
    pub fn bytes(self, dims: &[u64]) -> Result<u64, SizeError> {
        let (first, rest) = dims.split_first().unwrap_or((&1, &[]));
        if first % self.block_size != 0 {
            return Err(SizeError::PartialBlock);
        }
        let row = (first / self.block_size)
            .checked_mul(self.block_bytes)
            .ok_or(SizeError::Overflow)?;
        rest.iter()
            .try_fold(row, |acc, d| acc.checked_mul(*d))
            .ok_or(SizeError::Overflow)
    }
}

#[cfg(test)]
#[path = "types_tests.rs"]
mod tests;
