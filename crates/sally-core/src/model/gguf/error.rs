//! Why a GGUF header was refused. Each variant has a stable [`GgufError::code`] for the
//! `model.refuse` reason; the message text may change, the codes may not.
//!
//! Variants hold indices, numbers and at most a key or tensor name already escaped and capped by
//! [`crate::text::escape_quoted_capped`] at [`QUOTE_BYTES`], so neither `Display` nor `Debug` can
//! carry raw bytes from the file.
#![deny(clippy::indexing_slicing)]

use std::io;

use super::read::ReadError;

/// Most escaped bytes of a file-chosen key or name an error quotes.
pub const QUOTE_BYTES: usize = 64;

/// A file-chosen key or name, escaped and capped for an error message.
#[must_use]
pub fn quote(raw: &[u8]) -> String {
    crate::text::escape_quoted_capped(raw, QUOTE_BYTES)
}

/// Why a GGUF header was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum GgufError {
    /// The file does not start with `GGUF`.
    #[error("not a GGUF file: the first four bytes are not GGUF")]
    MagicMismatch,
    /// A version other than 2 or 3 (a byte-swapped file lands here too).
    #[error("GGUF version {0} is not supported (2 or 3)")]
    BadVersion(u32),
    /// More tensors than [`super::MAX_TENSORS`].
    #[error("tensor_count {0} is over the limit")]
    TensorCountLimit(u64),
    /// No tensors at all.
    #[error("tensor_count is 0: the file holds no model")]
    NoTensors,
    /// More metadata entries than [`super::MAX_KV`].
    #[error("kv_count {0} is over the limit")]
    KvCountLimit(u64),
    /// A key longer than [`super::MAX_KEY_BYTES`].
    #[error("kv[{0}]: the key is {1} bytes, over the limit")]
    KeyTooLong(u64, u64),
    /// An empty key, or one with a byte outside printable ASCII without space.
    #[error("kv[{0}]: the key is empty or not printable ASCII")]
    BadKey(u64),
    /// A key seen before.
    #[error("kv[{0}]: duplicate key \"{1}\"")]
    DuplicateKey(u64, String),
    /// A value type id that is not a GGUF type.
    #[error("kv[{0}]: value type {1} is not a GGUF type")]
    BadValueType(u64, u32),
    /// A bool that is neither 0 nor 1.
    #[error("kv[{0}]: bool value {1} is neither 0 nor 1")]
    InvalidBool(u64, u8),
    /// A string longer than [`super::MAX_STRING_BYTES`].
    #[error("kv[{0}]: a string of {1} bytes is over the limit")]
    StringTooLong(u64, u64),
    /// An array longer than [`super::MAX_ARRAY_LEN`].
    #[error("kv[{0}]: an array of {1} elements is over the limit")]
    ArrayTooLong(u64, u64),
    /// An array whose elements are arrays.
    #[error("kv[{0}]: arrays of arrays are refused")]
    NestedArray(u64),
    /// A chat template that is not UTF-8.
    #[error("kv[{0}]: the chat template is not UTF-8")]
    TemplateNotUtf8(u64),
    /// More chat-template keys than [`super::MAX_TEMPLATES`].
    #[error("kv[{0}]: more chat templates than the limit")]
    TemplateCountLimit(u64),
    /// `general.alignment` of a type other than u32, not a power of two, or out of range.
    #[error("kv[{0}]: general.alignment must be a u32 power of two from 8 to 65536")]
    BadAlignment(u64),
    /// A tensor name longer than [`super::MAX_NAME_BYTES`].
    #[error("tensor[{0}]: the name is {1} bytes, over the limit")]
    TensorNameTooLong(u64, u64),
    /// An empty tensor name, or one not UTF-8 or holding a control character.
    #[error("tensor[{0}]: the name is empty, not UTF-8, or holds a control character")]
    BadTensorName(u64),
    /// A tensor name seen before.
    #[error("tensor[{0}]: duplicate tensor name \"{1}\"")]
    DuplicateTensorName(u64, String),
    /// A tensor with no dimensions.
    #[error("tensor[{0}]: no dimensions")]
    NoDims(u64),
    /// More dimensions than [`super::MAX_DIMS`].
    #[error("tensor[{0}]: {1} dimensions, over the limit")]
    TooManyDims(u64, u32),
    /// A dimension of 0 or past `i64::MAX`.
    #[error("tensor[{0}]: dimension {1} is 0 or too large")]
    BadDim(u64, u32),
    /// The element count or byte size overflows.
    #[error("tensor[{0}]: the size overflows")]
    DimsOverflow(u64),
    /// The first dimension is not a whole number of blocks of the tensor's type.
    #[error("tensor[{0}]: the first dimension is not a whole number of blocks")]
    PartialBlock(u64),
    /// A ggml type id that is unknown or whose support was removed.
    #[error("tensor[{0}]: ggml type {1} is not supported")]
    InvalidTensorType(u64, u32),
    /// A tensor whose data would end past the end of the file.
    #[error("tensor[{0}]: its data ends past the end of the file")]
    TensorOutOfBounds(u64),
    /// A tensor not at the offset that follows the previous one (a gap, an overlap, or an
    /// unaligned offset).
    #[error("tensor[{0}]: offset {1} is not where the previous tensor's data ends")]
    TensorNotContiguous(u64, u64),
    /// The file ends inside the header.
    #[error("the file ends inside the GGUF header")]
    Truncated,
    /// The header is longer than [`super::MAX_HEADER_BYTES`].
    #[error("the GGUF header is over the size limit")]
    HeaderTooLarge,
    /// Reading the file failed.
    #[error("reading the file failed: {0}")]
    Io(io::ErrorKind),
}

impl GgufError {
    /// The stable reason code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::MagicMismatch => "magic_mismatch",
            Self::BadVersion(_) => "bad_version",
            Self::TensorCountLimit(_) => "tensor_count_limit",
            Self::NoTensors => "no_tensors",
            Self::KvCountLimit(_) => "kv_count_limit",
            Self::KeyTooLong(..) => "key_too_long",
            Self::BadKey(_) => "bad_key",
            Self::DuplicateKey(..) => "duplicate_key",
            Self::BadValueType(..) => "bad_value_type",
            Self::InvalidBool(..) => "invalid_bool",
            Self::StringTooLong(..) => "string_too_long",
            Self::ArrayTooLong(..) => "array_too_long",
            Self::NestedArray(_) => "nested_array",
            Self::TemplateNotUtf8(_) => "template_not_utf8",
            Self::TemplateCountLimit(_) => "template_count_limit",
            Self::BadAlignment(_) => "bad_alignment",
            Self::TensorNameTooLong(..) => "tensor_name_too_long",
            Self::BadTensorName(_) => "bad_tensor_name",
            Self::DuplicateTensorName(..) => "duplicate_tensor_name",
            Self::NoDims(_) => "no_dims",
            Self::TooManyDims(..) => "too_many_dims",
            Self::BadDim(..) => "bad_dim",
            Self::DimsOverflow(_) => "dims_overflow",
            Self::PartialBlock(_) => "partial_block",
            Self::InvalidTensorType(..) => "invalid_tensor_type",
            Self::TensorOutOfBounds(_) => "tensor_out_of_bounds",
            Self::TensorNotContiguous(..) => "tensor_not_contiguous",
            Self::Truncated => "truncated",
            Self::HeaderTooLarge => "header_too_large",
            Self::Io(_) => "io_error",
        }
    }
}

impl From<ReadError> for GgufError {
    fn from(e: ReadError) -> Self {
        match e {
            ReadError::Truncated => Self::Truncated,
            ReadError::OverBudget => Self::HeaderTooLarge,
            ReadError::Io(kind) => Self::Io(kind),
        }
    }
}

#[cfg(test)]
#[path = "error_tests.rs"]
pub(crate) mod tests;
