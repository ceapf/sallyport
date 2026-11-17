//! A test-only GGUF writer: valid files by default, every field overridable to build the
//! refused ones. The fuzz seeds in `fuzz/corpus/gguf/` are its output (see `mod_tests.rs`).
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::io::{self, Read};

use super::{GgmlType, GgufError, GgufHeader};

/// Value type ids.
pub(crate) const U8: u32 = 0;
pub(crate) const U32: u32 = 4;
pub(crate) const BOOL: u32 = 7;
pub(crate) const STRING: u32 = 8;
pub(crate) const ARRAY: u32 = 9;
pub(crate) const U64: u32 = 10;
/// ggml type ids.
pub(crate) const F32: u32 = 0;
pub(crate) const Q4_0: u32 = 2;
pub(crate) const I8: u32 = 24;

/// Most data bytes [`Gguf::bytes`] writes on its own.
const AUTO_DATA_MAX: u64 = 16 << 20;

/// A length-prefixed GGUF string.
pub(crate) fn s(bytes: &[u8]) -> Vec<u8> {
    let mut out = (bytes.len() as u64).to_le_bytes().to_vec();
    out.extend_from_slice(bytes);
    out
}

/// An array payload: element type, length, then the element bytes.
pub(crate) fn array(elem: u32, len: u64, elements: &[u8]) -> Vec<u8> {
    let mut out = elem.to_le_bytes().to_vec();
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(elements);
    out
}

/// One tensor info.
#[derive(Clone)]
pub(crate) struct Tensor {
    pub(crate) name: Vec<u8>,
    pub(crate) n_dims: Option<u32>,
    pub(crate) dims: Vec<u64>,
    pub(crate) ty: u32,
    pub(crate) offset: Option<u64>,
}

impl Tensor {
    /// A tensor of type `ty` at the next contiguous offset.
    pub(crate) fn of(name: &str, ty: u32, dims: &[u64]) -> Self {
        Self {
            name: name.as_bytes().to_vec(),
            n_dims: None,
            dims: dims.to_vec(),
            ty,
            offset: None,
        }
    }

    /// Bytes of data, or 0 for a shape the parser refuses.
    fn size(&self) -> u64 {
        GgmlType::from_id(self.ty)
            .and_then(|t| t.bytes(&self.dims).ok())
            .unwrap_or(0)
    }
}

/// A GGUF file under construction.
#[derive(Clone)]
pub(crate) struct Gguf {
    pub(crate) magic: [u8; 4],
    pub(crate) version: u32,
    pub(crate) tensor_count: Option<u64>,
    pub(crate) kv_count: Option<u64>,
    pub(crate) kv: Vec<Vec<u8>>,
    pub(crate) tensors: Vec<Tensor>,
    /// The alignment the writer pads to; `general.alignment` is a separate kv.
    pub(crate) alignment: u64,
    /// Data bytes written; `None` writes exactly what the tensors need.
    pub(crate) data: Option<u64>,
    pub(crate) trailing: u64,
}

impl Gguf {
    /// No metadata, no tensors.
    pub(crate) fn empty() -> Self {
        Self {
            magic: *b"GGUF",
            version: 3,
            tensor_count: None,
            kv_count: None,
            kv: Vec::new(),
            tensors: Vec::new(),
            alignment: 32,
            data: None,
            trailing: 0,
        }
    }

    /// A small valid file: one string kv, one F32 tensor of 8 elements.
    pub(crate) fn valid() -> Self {
        Self::empty()
            .kv_str("general.architecture", b"llama")
            .tensor(Tensor::of("w", F32, &[8]))
    }

    /// Adds an entry: key, value type id, payload as written.
    pub(crate) fn kv(mut self, key: &[u8], ty: u32, payload: &[u8]) -> Self {
        let mut entry = s(key);
        entry.extend_from_slice(&ty.to_le_bytes());
        entry.extend_from_slice(payload);
        self.kv.push(entry);
        self
    }

    pub(crate) fn kv_str(self, key: &str, value: &[u8]) -> Self {
        self.kv(key.as_bytes(), STRING, &s(value))
    }

    pub(crate) fn kv_u32(self, key: &str, value: u32) -> Self {
        self.kv(key.as_bytes(), U32, &value.to_le_bytes())
    }

    pub(crate) fn tensor(mut self, t: Tensor) -> Self {
        self.tensors.push(t);
        self
    }

    /// Each tensor's offset as written, and the data length they need.
    fn layout(&self) -> (Vec<u64>, u64) {
        let mut next = 0u64;
        let mut offsets = Vec::new();
        for t in &self.tensors {
            let offset = t.offset.unwrap_or(next);
            offsets.push(offset);
            next = offset
                .checked_add(t.size())
                .and_then(|end| end.checked_next_multiple_of(self.alignment))
                .unwrap_or(u64::MAX);
        }
        (offsets, next)
    }

    /// The magic through the last tensor info.
    pub(crate) fn header(&self) -> Vec<u8> {
        let mut out = self.magic.to_vec();
        out.extend_from_slice(&self.version.to_le_bytes());
        let tensor_count = self.tensor_count.unwrap_or(self.tensors.len() as u64);
        out.extend_from_slice(&tensor_count.to_le_bytes());
        let kv_count = self.kv_count.unwrap_or(self.kv.len() as u64);
        out.extend_from_slice(&kv_count.to_le_bytes());
        for entry in &self.kv {
            out.extend_from_slice(entry);
        }
        let (offsets, _) = self.layout();
        for (t, offset) in self.tensors.iter().zip(offsets) {
            out.extend_from_slice(&s(&t.name));
            let n_dims = t.n_dims.unwrap_or(t.dims.len() as u32);
            out.extend_from_slice(&n_dims.to_le_bytes());
            for d in &t.dims {
                out.extend_from_slice(&d.to_le_bytes());
            }
            out.extend_from_slice(&t.ty.to_le_bytes());
            out.extend_from_slice(&offset.to_le_bytes());
        }
        out
    }

    /// The whole file.
    pub(crate) fn bytes(&self) -> Vec<u8> {
        let mut out = self.header();
        let padded = (out.len() as u64).next_multiple_of(self.alignment);
        out.resize(padded as usize, 0);
        // A layout past AUTO_DATA_MAX (a tensor placed or sized past any real file) gets no data.
        let data = self.data.unwrap_or_else(|| {
            Some(self.layout().1)
                .filter(|d| *d <= AUTO_DATA_MAX)
                .unwrap_or(0)
        });
        out.resize(out.len() + data as usize + self.trailing as usize, 0);
        out
    }

    pub(crate) fn parse(&self) -> Result<GgufHeader, GgufError> {
        parse_bytes(&self.bytes())
    }
}

/// [`super::parse`] over a whole file in memory.
pub(crate) fn parse_bytes(bytes: &[u8]) -> Result<GgufHeader, GgufError> {
    super::parse(bytes, bytes.len() as u64)
}

/// The code of a refusal, for compact assertions.
pub(crate) fn code(result: Result<GgufHeader, GgufError>) -> &'static str {
    match result {
        Ok(_) => "accepted",
        Err(e) => e.code(),
    }
}

/// Yields one byte per read: proves the parser never depends on how reads are cut.
pub(crate) struct OneByte<R>(pub(crate) R);

impl<R: Read> Read for OneByte<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match buf.first_mut() {
            Some(first) => self.0.read(std::slice::from_mut(first)),
            None => Ok(0),
        }
    }
}
