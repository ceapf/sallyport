//! The strict GGUF header parser (SI-6): bounds first, allocate second, never a byte of tensor
//! data. ARCHITECTURE §7, "GGUF strict parser limits", is the contract; the constants below are
//! its numbers.
//!
//! [`parse`] reads the header forward from any [`Read`]: the magic, version 2 or 3, the counts,
//! the metadata, the tensor infos. Every length the file states is checked against its own limit,
//! then against [`MAX_HEADER_BYTES`], then against the bytes the file has left, before anything
//! is read or allocated for it. It then checks that every tensor's data lies inside the file and
//! that the tensors are laid out back to back from the start of the data section, each at the
//! previous one's end rounded up to the alignment (the layout llama.cpp requires).
//!
//! What it keeps: every scalar; strings up to [`KEPT_STRING_BYTES`] that are UTF-8; the chat
//! templates whole; for longer strings and every array only the type and length. Every string
//! it keeps was chosen by the file's author: show it only through [`crate::text`]'s escapes.
#![deny(clippy::indexing_slicing)]

pub mod error;
mod meta;
mod read;
mod tensors;
pub mod types;

use std::fmt;
use std::io::{BufReader, Read};

pub use error::GgufError;
pub use types::{GgmlType, SizeError};

use read::Reader;

/// Most bytes from the magic through the last tensor info.
pub const MAX_HEADER_BYTES: u64 = 67_108_864;
/// Most tensors.
pub const MAX_TENSORS: u64 = 65_536;
/// Most metadata entries.
pub const MAX_KV: u64 = 4_096;
/// Longest string value, in bytes.
pub const MAX_STRING_BYTES: u64 = 65_536;
/// Most elements in one array.
pub const MAX_ARRAY_LEN: u64 = 4_194_304;
/// Longest key, in bytes.
pub const MAX_KEY_BYTES: u64 = 256;
/// Longest tensor name, in bytes (llama.cpp's limit is 64 including the NUL).
pub const MAX_NAME_BYTES: u64 = 63;
/// Most dimensions of one tensor.
pub const MAX_DIMS: u32 = 4;
/// Smallest accepted `general.alignment`.
pub const MIN_ALIGNMENT: u32 = 8;
/// Largest accepted `general.alignment`.
pub const MAX_ALIGNMENT: u32 = 65_536;
/// The alignment when the file names none.
pub const DEFAULT_ALIGNMENT: u32 = 32;
/// Longest ordinary string value kept; a longer one is kept as its length only.
pub const KEPT_STRING_BYTES: u64 = 1_024;
/// Most chat-template keys (`tokenizer.chat_template` and `tokenizer.chat_template.<name>`).
pub const MAX_TEMPLATES: u64 = 16;
/// Most bytes of file text a [`GgufHeader`] keeps: keys, kept strings, chat templates and
/// tensor names at their limits (`MAX_KV * (MAX_KEY_BYTES + KEPT_STRING_BYTES) + MAX_TEMPLATES *
/// MAX_STRING_BYTES + MAX_TENSORS * MAX_NAME_BYTES`).
pub const MAX_RETAINED_TEXT_BYTES: u64 = 10_420_224;
/// The key whose value is the chat template; `<key>.<name>` keys are named templates.
pub const TEMPLATE_KEY: &str = "tokenizer.chat_template";
/// The parser's own read buffer.
const READ_BUFFER: usize = 65_536;

/// Text the file's author chose. `Debug` shows its length, never its content.
#[derive(Clone, PartialEq, Eq)]
pub struct FileText(String);

impl FileText {
    /// The text as the file holds it. Untrusted: escape before showing it anywhere.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for FileText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FileText({} bytes)", self.0.len())
    }
}

/// A metadata value type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValueType {
    /// `u8`.
    U8,
    /// `i8`.
    I8,
    /// `u16`.
    U16,
    /// `i16`.
    I16,
    /// `u32`.
    U32,
    /// `i32`.
    I32,
    /// `f32`.
    F32,
    /// A bool byte.
    Bool,
    /// A length-prefixed string.
    String,
    /// `u64`.
    U64,
    /// `i64`.
    I64,
    /// `f64`.
    F64,
}

/// A metadata value as the parser keeps it.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Value {
    /// `u8`.
    U8(u8),
    /// `i8`.
    I8(i8),
    /// `u16`.
    U16(u16),
    /// `i16`.
    I16(i16),
    /// `u32`.
    U32(u32),
    /// `i32`.
    I32(i32),
    /// `f32`.
    F32(f32),
    /// A bool (the byte was 0 or 1).
    Bool(bool),
    /// `u64`.
    U64(u64),
    /// `i64`.
    I64(i64),
    /// `f64`.
    F64(f64),
    /// A kept string.
    String(FileText),
    /// A string not kept (longer than [`KEPT_STRING_BYTES`], or not UTF-8): its length only.
    StringSummary(u64),
    /// An array: its element type and length only; no element was kept or inspected beyond
    /// the length of each string.
    Array(ValueType, u64),
}

/// One metadata entry.
#[derive(Debug, Clone, PartialEq)]
pub struct Metadata {
    key: FileText,
    value: Value,
}

impl Metadata {
    /// The key: printable ASCII without space, 1 to [`MAX_KEY_BYTES`] bytes.
    #[must_use]
    pub const fn key(&self) -> &FileText {
        &self.key
    }

    /// The value.
    #[must_use]
    pub const fn value(&self) -> &Value {
        &self.value
    }
}

/// One tensor's description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TensorInfo {
    name: FileText,
    dims: Vec<u64>,
    ggml_type: GgmlType,
    offset: u64,
    bytes: u64,
}

impl TensorInfo {
    /// The name: UTF-8 without control characters, 1 to [`MAX_NAME_BYTES`] bytes, unique.
    #[must_use]
    pub const fn name(&self) -> &FileText {
        &self.name
    }

    /// The dimensions, 1 to [`MAX_DIMS`] of them, each at least 1.
    #[must_use]
    pub fn dims(&self) -> &[u64] {
        &self.dims
    }

    /// The element type.
    #[must_use]
    pub const fn ggml_type(&self) -> GgmlType {
        self.ggml_type
    }

    /// Where the data starts, from the start of the data section.
    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    /// Bytes of data.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }
}

/// A GGUF header that passed every check.
#[derive(Debug, Clone, PartialEq)]
pub struct GgufHeader {
    version: u32,
    alignment: u32,
    metadata: Vec<Metadata>,
    tensors: Vec<TensorInfo>,
    data_start: u64,
    data_end: u64,
    file_len: u64,
}

impl GgufHeader {
    /// 2 or 3.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// `general.alignment`, or [`DEFAULT_ALIGNMENT`].
    #[must_use]
    pub const fn alignment(&self) -> u32 {
        self.alignment
    }

    /// The metadata, in file order.
    #[must_use]
    pub fn metadata(&self) -> &[Metadata] {
        &self.metadata
    }

    /// The tensors, in file order (also data order).
    #[must_use]
    pub fn tensors(&self) -> &[TensorInfo] {
        &self.tensors
    }

    /// Where the data section starts in the file.
    #[must_use]
    pub const fn data_start(&self) -> u64 {
        self.data_start
    }

    /// Where the last tensor's data ends in the file.
    // TODO(#183): decide whether bytes between here and file_len are refused.
    #[must_use]
    pub const fn data_end(&self) -> u64 {
        self.data_end
    }

    /// The file length the header was checked against.
    #[must_use]
    pub const fn file_len(&self) -> u64 {
        self.file_len
    }

    /// Bytes of file text kept (keys, kept strings, tensor names); at most
    /// [`MAX_RETAINED_TEXT_BYTES`].
    #[must_use]
    pub fn retained_text_bytes(&self) -> u64 {
        let text = |t: &FileText| t.as_str().len() as u64;
        let meta = self.metadata.iter().map(|m| {
            text(&m.key)
                + match &m.value {
                    Value::String(s) => text(s),
                    _ => 0,
                }
        });
        let names = self.tensors.iter().map(|t| text(&t.name));
        meta.chain(names).sum()
    }
}

/// Parses the GGUF header `reader` yields, for a file `file_len` bytes long.
///
/// `file_len` must be the length of the very object `reader` reads (`fstat` of the open file
/// descriptor, never a stat of a path): every tensor's data is checked to lie within it. A parse
/// against an advertised length (a download not yet made) is a preview, not the SI-6 check.
///
/// The reader is wrapped in a buffer of 64 KiB under a limit of [`MAX_HEADER_BYTES`]; it is never
/// sought, and bytes the buffer read ahead past the header are never looked at.
///
/// # Errors
/// A [`GgufError`] naming the first check that failed, in file order.
pub fn parse<R: Read>(reader: R, file_len: u64) -> Result<GgufHeader, GgufError> {
    let buffered = BufReader::with_capacity(READ_BUFFER, reader.take(MAX_HEADER_BYTES));
    let mut r = Reader::new(buffered, MAX_HEADER_BYTES, file_len);
    if r.u32()? != u32::from_le_bytes(*crate::model::detect::GGUF_MAGIC) {
        return Err(GgufError::MagicMismatch);
    }
    let version = r.u32()?;
    if !(2..=3).contains(&version) {
        return Err(GgufError::BadVersion(version));
    }
    let tensor_count = r.u64()?;
    if tensor_count > MAX_TENSORS {
        return Err(GgufError::TensorCountLimit(tensor_count));
    }
    if tensor_count == 0 {
        return Err(GgufError::NoTensors);
    }
    let kv_count = r.u64()?;
    if kv_count > MAX_KV {
        return Err(GgufError::KvCountLimit(kv_count));
    }
    let meta = meta::read(&mut r, kv_count)?;
    let tensors = tensors::read(&mut r, tensor_count)?;
    let (data_start, data_end) = tensors::place(&tensors, r.position(), meta.alignment, file_len)?;
    Ok(GgufHeader {
        version,
        alignment: meta.alignment,
        metadata: meta.entries,
        tensors,
        data_start,
        data_end,
        file_len,
    })
}

#[cfg(test)]
#[path = "build_tests.rs"]
pub(crate) mod build;

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
