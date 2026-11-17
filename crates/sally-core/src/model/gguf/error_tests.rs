#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::collections::BTreeSet;

use super::*;

/// One of each variant, with the code it must keep.
pub(crate) fn every_variant() -> Vec<(GgufError, &'static str)> {
    vec![
        (GgufError::MagicMismatch, "magic_mismatch"),
        (GgufError::BadVersion(1), "bad_version"),
        (GgufError::TensorCountLimit(1 << 63), "tensor_count_limit"),
        (GgufError::NoTensors, "no_tensors"),
        (GgufError::KvCountLimit(1 << 40), "kv_count_limit"),
        (GgufError::KeyTooLong(0, 257), "key_too_long"),
        (GgufError::BadKey(0), "bad_key"),
        (GgufError::DuplicateKey(1, quote(b"a")), "duplicate_key"),
        (GgufError::BadValueType(0, 13), "bad_value_type"),
        (GgufError::InvalidBool(0, 2), "invalid_bool"),
        (GgufError::StringTooLong(0, 65_537), "string_too_long"),
        (GgufError::ArrayTooLong(0, 1 << 40), "array_too_long"),
        (GgufError::NestedArray(0), "nested_array"),
        (GgufError::TemplateNotUtf8(0), "template_not_utf8"),
        (GgufError::TemplateCountLimit(16), "template_count_limit"),
        (GgufError::BadAlignment(0), "bad_alignment"),
        (GgufError::TemplateHasNul(0), "template_has_nul"),
        (GgufError::SplitFile(0), "split_file"),
        (GgufError::TensorNameTooLong(0, 64), "tensor_name_too_long"),
        (GgufError::BadTensorName(0), "bad_tensor_name"),
        (
            GgufError::DuplicateTensorName(1, quote(b"t")),
            "duplicate_tensor_name",
        ),
        (GgufError::NoDims(0), "no_dims"),
        (GgufError::TooManyDims(0, 200), "too_many_dims"),
        (GgufError::BadDim(0, 1), "bad_dim"),
        (GgufError::DimsOverflow(0), "dims_overflow"),
        (GgufError::PartialBlock(0), "partial_block"),
        (GgufError::InvalidTensorType(0, 4), "invalid_tensor_type"),
        (GgufError::TensorOutOfBounds(0), "tensor_out_of_bounds"),
        (
            GgufError::TensorNotContiguous(1, 7),
            "tensor_not_contiguous",
        ),
        (GgufError::Truncated, "truncated"),
        (GgufError::HeaderTooLarge, "header_too_large"),
        (GgufError::Io(std::io::ErrorKind::Other), "io_error"),
    ]
}

#[test]
fn every_code_is_pinned_distinct_and_snake_case() {
    let all = every_variant();
    let mut seen = BTreeSet::new();
    for (e, code) in &all {
        assert_eq!(e.code(), *code);
        assert!(seen.insert(*code), "{code} twice");
        let mut bytes = code.bytes();
        assert!(
            bytes.next().is_some_and(|b| b.is_ascii_lowercase()),
            "{code}"
        );
        assert!(
            bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
            "{code}"
        );
    }
    assert_eq!(seen.len(), 32);
}

#[test]
fn messages_are_printable_ascii() {
    for (e, _) in every_variant() {
        let text = e.to_string();
        assert!(text.bytes().all(|b| (0x20..0x7f).contains(&b)), "{text}");
    }
}

#[test]
fn quote_escapes_and_caps_file_text() {
    assert_eq!(quote(b"a\"b"), "a\\x22b");
    assert_eq!(quote(b"\x1b[31m"), "\\x1b[31m");
    let long = quote(&[b'x'; 200]);
    assert!(long.starts_with(&"x".repeat(QUOTE_BYTES)));
    assert!(long.len() < 100, "{long}");
    let shown = GgufError::DuplicateKey(3, quote(b"k\nx")).to_string();
    assert_eq!(shown, "kv[3]: duplicate key \"k\\x0ax\"");
}

#[test]
fn read_errors_map_to_their_codes() {
    assert_eq!(GgufError::from(ReadError::Truncated), GgufError::Truncated);
    assert_eq!(
        GgufError::from(ReadError::OverBudget),
        GgufError::HeaderTooLarge
    );
    assert_eq!(
        GgufError::from(ReadError::Io(std::io::ErrorKind::PermissionDenied)),
        GgufError::Io(std::io::ErrorKind::PermissionDenied)
    );
}
