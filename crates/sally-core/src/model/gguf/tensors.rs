//! The tensor infos, and where their data lies.
#![deny(clippy::indexing_slicing)]

use std::collections::HashSet;
use std::io::Read;

use super::error::quote;
use super::read::Reader;
use super::types::SizeError;
use super::{FileText, GgmlType, GgufError, MAX_DIMS, MAX_ELEMENTS, MAX_NAME_BYTES, TensorInfo};

/// Reads `count` tensor infos (already checked against the limit).
pub(super) fn read<R: Read>(r: &mut Reader<R>, count: u64) -> Result<Vec<TensorInfo>, GgufError> {
    let mut tensors = Vec::new();
    let mut seen = HashSet::new();
    for t in 0..count {
        let name = read_name(r, t)?;
        if !seen.insert(name.clone()) {
            return Err(GgufError::DuplicateTensorName(t, quote(name.as_bytes())));
        }
        let dims = read_dims(r, t)?;
        let type_id = r.u32()?;
        let ggml_type =
            GgmlType::from_id(type_id).ok_or(GgufError::InvalidTensorType(t, type_id))?;
        let bytes = ggml_type.bytes(&dims).map_err(|e| match e {
            SizeError::PartialBlock => GgufError::PartialBlock(t),
            SizeError::Overflow => GgufError::DimsOverflow(t),
        })?;
        let offset = r.u64()?;
        tensors.push(TensorInfo {
            name: FileText(name),
            dims,
            ggml_type,
            offset,
            bytes,
        });
    }
    Ok(tensors)
}

/// A name: 1 to [`MAX_NAME_BYTES`] bytes of UTF-8 without control characters.
fn read_name<R: Read>(r: &mut Reader<R>, t: u64) -> Result<String, GgufError> {
    let len = r.u64()?;
    if len > MAX_NAME_BYTES {
        return Err(GgufError::TensorNameTooLong(t, len));
    }
    let name = String::from_utf8(r.bytes(len)?).map_err(|_| GgufError::BadTensorName(t))?;
    if name.is_empty() || name.chars().any(char::is_control) {
        return Err(GgufError::BadTensorName(t));
    }
    Ok(name)
}

/// 1 to [`MAX_DIMS`] dimensions, each 1 to [`MAX_ELEMENTS`], whose product is at most
/// [`MAX_ELEMENTS`].
fn read_dims<R: Read>(r: &mut Reader<R>, t: u64) -> Result<Vec<u64>, GgufError> {
    let n = r.u32()?;
    if n == 0 {
        return Err(GgufError::NoDims(t));
    }
    if n > MAX_DIMS {
        return Err(GgufError::TooManyDims(t, n));
    }
    let mut dims = Vec::new();
    let mut elements = 1u64;
    for d in 0..n {
        let dim = r.u64()?;
        if dim == 0 || dim > MAX_ELEMENTS {
            return Err(GgufError::BadDim(t, d));
        }
        elements = elements
            .checked_mul(dim)
            .filter(|e| *e <= MAX_ELEMENTS)
            .ok_or(GgufError::DimsOverflow(t))?;
        dims.push(dim);
    }
    Ok(dims)
}

/// Checks the layout and returns where the data section starts and where the last tensor ends.
/// First every tensor must end inside the file, then each must start where the previous one's
/// data ends, rounded up to `alignment` (the first at 0).
pub(super) fn place(
    tensors: &[TensorInfo],
    header_end: u64,
    alignment: u32,
    file_len: u64,
) -> Result<(u64, u64), GgufError> {
    let align = u64::from(alignment);
    // header_end is at most MAX_HEADER_BYTES and align at most MAX_ALIGNMENT: this cannot fail.
    let data_start = header_end
        .checked_next_multiple_of(align)
        .ok_or(GgufError::HeaderTooLarge)?;
    let mut data_end = data_start;
    for (t, info) in (0u64..).zip(tensors) {
        data_end = data_start
            .checked_add(info.offset)
            .and_then(|start| start.checked_add(info.bytes))
            .filter(|end| *end <= file_len)
            .ok_or(GgufError::TensorOutOfBounds(t))?;
    }
    let mut expected = 0u64;
    for (t, info) in (0u64..).zip(tensors) {
        if info.offset != expected {
            return Err(GgufError::TensorNotContiguous(t, info.offset));
        }
        // The bounds loop already proved data_start + offset + bytes fits with data_start >= align,
        // so this cannot fail; it stays checked so a reorder of the two loops cannot wrap.
        expected = info
            .offset
            .checked_add(info.bytes)
            .and_then(|end| end.checked_next_multiple_of(align))
            .ok_or(GgufError::TensorOutOfBounds(t))?;
    }
    Ok((data_start, data_end))
}

#[cfg(test)]
#[path = "tensors_tests.rs"]
mod tests;
