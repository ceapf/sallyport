//! The metadata section: keys, typed values, `general.alignment` and the chat templates.
#![deny(clippy::indexing_slicing)]

use std::collections::HashSet;
use std::io::Read;

use super::error::quote;
use super::read::Reader;
use super::{
    DEFAULT_ALIGNMENT, F32Bits, F64Bits, FileText, GgufError, KEPT_STRING_BYTES, MAX_ALIGNMENT,
    MAX_ARRAY_LEN, MAX_KEY_BYTES, MAX_STRING_BYTES, MAX_TEMPLATES, MIN_ALIGNMENT, Metadata,
    TEMPLATE_KEY, Value, ValueType,
};

/// The key that sets the alignment.
const ALIGNMENT_KEY: &str = "general.alignment";
/// The key that says how many files a split model has.
const SPLIT_KEY: &str = "split.count";

/// The metadata and the alignment it sets.
pub(super) struct Meta {
    pub(super) entries: Vec<Metadata>,
    pub(super) alignment: u32,
}

/// Reads `count` entries (already checked against the limit).
pub(super) fn read<R: Read>(r: &mut Reader<R>, count: u64) -> Result<Meta, GgufError> {
    let mut entries = Vec::new();
    let mut seen = HashSet::new();
    let mut alignment = DEFAULT_ALIGNMENT;
    let mut templates = 0u64;
    for i in 0..count {
        let key = read_key(r, i)?;
        if !seen.insert(key.clone()) {
            return Err(GgufError::DuplicateKey(i, quote(key.as_bytes())));
        }
        let template = is_template(&key);
        if template {
            templates += 1;
            if templates > MAX_TEMPLATES {
                return Err(GgufError::TemplateCountLimit(i));
            }
        }
        let type_id = r.u32()?;
        let value = read_value(r, i, type_id, template)?;
        if key == ALIGNMENT_KEY {
            alignment = check_alignment(i, &value)?;
        }
        if key == SPLIT_KEY {
            check_split(i, &value)?;
        }
        entries.push(Metadata {
            key: FileText(key),
            value,
        });
    }
    Ok(Meta { entries, alignment })
}

/// `tokenizer.chat_template` or `tokenizer.chat_template.<name>`.
fn is_template(key: &str) -> bool {
    key.strip_prefix(TEMPLATE_KEY)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('.'))
}

/// A key: 1 to [`MAX_KEY_BYTES`] bytes of printable ASCII without space.
fn read_key<R: Read>(r: &mut Reader<R>, i: u64) -> Result<String, GgufError> {
    let len = r.u64()?;
    if len > MAX_KEY_BYTES {
        return Err(GgufError::KeyTooLong(i, len));
    }
    let bytes = r.bytes(len)?;
    if bytes.is_empty() || !bytes.iter().all(|b| (0x21..=0x7e).contains(b)) {
        return Err(GgufError::BadKey(i));
    }
    String::from_utf8(bytes).map_err(|_| GgufError::BadKey(i))
}

/// The id that marks an array.
const ARRAY: u32 = 9;

/// The value type with this id; arrays are not a [`ValueType`].
fn value_type(i: u64, id: u32) -> Result<ValueType, GgufError> {
    Ok(match id {
        0 => ValueType::U8,
        1 => ValueType::I8,
        2 => ValueType::U16,
        3 => ValueType::I16,
        4 => ValueType::U32,
        5 => ValueType::I32,
        6 => ValueType::F32,
        7 => ValueType::Bool,
        8 => ValueType::String,
        10 => ValueType::U64,
        11 => ValueType::I64,
        12 => ValueType::F64,
        ARRAY => return Err(GgufError::NestedArray(i)),
        other => return Err(GgufError::BadValueType(i, other)),
    })
}

fn read_value<R: Read>(
    r: &mut Reader<R>,
    i: u64,
    id: u32,
    template: bool,
) -> Result<Value, GgufError> {
    if id == ARRAY {
        return read_array(r, i);
    }
    Ok(match value_type(i, id)? {
        ValueType::U8 => Value::U8(r.u8()?),
        ValueType::I8 => Value::I8(r.i8()?),
        ValueType::U16 => Value::U16(r.u16()?),
        ValueType::I16 => Value::I16(r.i16()?),
        ValueType::U32 => Value::U32(r.u32()?),
        ValueType::I32 => Value::I32(r.i32()?),
        ValueType::F32 => Value::F32(F32Bits(r.u32()?)),
        ValueType::Bool => match r.u8()? {
            0 => Value::Bool(false),
            1 => Value::Bool(true),
            other => return Err(GgufError::InvalidBool(i, other)),
        },
        ValueType::String => read_string(r, i, template)?,
        ValueType::U64 => Value::U64(r.u64()?),
        ValueType::I64 => Value::I64(r.i64()?),
        ValueType::F64 => Value::F64(F64Bits(r.u64()?)),
    })
}

/// A string's length, checked against [`MAX_STRING_BYTES`].
fn string_len<R: Read>(r: &mut Reader<R>, i: u64) -> Result<u64, GgufError> {
    let len = r.u64()?;
    if len > MAX_STRING_BYTES {
        return Err(GgufError::StringTooLong(i, len));
    }
    Ok(len)
}

fn read_string<R: Read>(r: &mut Reader<R>, i: u64, template: bool) -> Result<Value, GgufError> {
    let len = string_len(r, i)?;
    if template {
        let bytes = r.bytes(len)?;
        let text = String::from_utf8(bytes).map_err(|_| GgufError::TemplateNotUtf8(i))?;
        if text.contains('\0') {
            return Err(GgufError::TemplateHasNul(i));
        }
        return Ok(Value::String(FileText(text)));
    }
    if len > KEPT_STRING_BYTES {
        r.skip(len)?;
        return Ok(Value::StringSummary(len));
    }
    Ok(match String::from_utf8(r.bytes(len)?) {
        Ok(text) if !text.contains('\0') => Value::String(FileText(text)),
        _ => Value::StringSummary(len),
    })
}

/// Bytes of one element of a fixed-size type; `None` for strings.
const fn element_bytes(t: ValueType) -> Option<u64> {
    match t {
        ValueType::U8 | ValueType::I8 | ValueType::Bool => Some(1),
        ValueType::U16 | ValueType::I16 => Some(2),
        ValueType::U32 | ValueType::I32 | ValueType::F32 => Some(4),
        ValueType::U64 | ValueType::I64 | ValueType::F64 => Some(8),
        ValueType::String => None,
    }
}

/// An array: its type and length are kept; fixed-size elements are skipped unread, strings by
/// their checked lengths.
fn read_array<R: Read>(r: &mut Reader<R>, i: u64) -> Result<Value, GgufError> {
    let elem = value_type(i, r.u32()?)?;
    let len = r.u64()?;
    if len > MAX_ARRAY_LEN {
        return Err(GgufError::ArrayTooLong(i, len));
    }
    match element_bytes(elem) {
        Some(size) => r.skip(
            len.checked_mul(size)
                .ok_or(GgufError::ArrayTooLong(i, len))?,
        )?,
        None => {
            for _ in 0..len {
                let n = string_len(r, i)?;
                r.skip(n)?;
            }
        }
    }
    Ok(Value::Array(elem, len))
}

/// `general.alignment`: a `u32` power of two from [`MIN_ALIGNMENT`] to [`MAX_ALIGNMENT`].
fn check_alignment(i: u64, value: &Value) -> Result<u32, GgufError> {
    match value {
        Value::U32(a) if a.is_power_of_two() && (MIN_ALIGNMENT..=MAX_ALIGNMENT).contains(a) => {
            Ok(*a)
        }
        _ => Err(GgufError::BadAlignment(i)),
    }
}

/// `split.count`: a `u16` of 0 or 1. Anything else names sibling shard files the engine would
/// open, which never passed these checks.
fn check_split(i: u64, value: &Value) -> Result<(), GgufError> {
    match value {
        Value::U16(0 | 1) => Ok(()),
        _ => Err(GgufError::SplitFile(i)),
    }
}

#[cfg(test)]
#[path = "meta_tests.rs"]
mod tests;
