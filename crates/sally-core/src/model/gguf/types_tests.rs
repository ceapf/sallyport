#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use super::*;

/// Every row written a second way: (id, name, block size, bytes per block as the sum of the
/// block struct's fields in ggml-common.h at the commit the module doc names). `H` is a
/// `ggml_half` (2 bytes), `QK` the 256-element super-block.
const H: u64 = 2;
const QK: u64 = 256;
const UPSTREAM: &[(u32, &str, u64, u64)] = &[
    (0, "F32", 1, 4),
    (1, "F16", 1, H),
    (2, "Q4_0", 32, H + 32 / 2),
    (3, "Q4_1", 32, 2 * H + 32 / 2),
    (6, "Q5_0", 32, H + 4 + 32 / 2),
    (7, "Q5_1", 32, 2 * H + 4 + 32 / 2),
    (8, "Q8_0", 32, H + 32),
    (9, "Q8_1", 32, 2 * H + 32),
    (10, "Q2_K", QK, QK / 16 + QK / 4 + 2 * H),
    (11, "Q3_K", QK, QK / 8 + QK / 4 + 12 + H),
    (12, "Q4_K", QK, 2 * H + 12 + QK / 2),
    (13, "Q5_K", QK, 2 * H + 12 + QK / 8 + QK / 2),
    (14, "Q6_K", QK, QK / 2 + QK / 4 + QK / 16 + H),
    (15, "Q8_K", QK, 4 + QK + QK / 16 * 2),
    (16, "IQ2_XXS", QK, H + QK / 8 * 2),
    (17, "IQ2_XS", QK, H + QK / 8 * 2 + QK / 32),
    (18, "IQ3_XXS", QK, H + 3 * QK / 8),
    (19, "IQ1_S", QK, H + QK / 8 + QK / 32 * 2),
    (20, "IQ4_NL", 32, H + 32 / 2),
    (21, "IQ3_S", QK, H + QK / 4 + QK / 32 + QK / 8 + QK / 64),
    (22, "IQ2_S", QK, H + QK / 4 + QK / 32 + QK / 32),
    (23, "IQ4_XS", QK, H + 2 + QK / 64 + QK / 2),
    (24, "I8", 1, 1),
    (25, "I16", 1, 2),
    (26, "I32", 1, 4),
    (27, "I64", 1, 8),
    (28, "F64", 1, 8),
    (29, "IQ1_M", QK, QK / 8 + QK / 16 + QK / 32),
    (30, "BF16", 1, 2),
    (34, "TQ1_0", QK, (QK - 4 * QK / 64) / 5 + QK / 64 + H),
    (35, "TQ2_0", QK, QK / 4 + H),
    (39, "MXFP4", 32, 1 + 32 / 2),
    (40, "NVFP4", 64, 64 / 16 + 64 / 2),
    (41, "Q1_0", 128, H + 128 / 8),
    (42, "Q2_0", 64, H + 64 / 4),
    (43, "F8_E4M3", 1, 1),
];

#[test]
fn every_row_matches_the_upstream_struct_sums() {
    assert_eq!(TYPES.len(), UPSTREAM.len());
    for (row, &(id, name, block, bytes)) in TYPES.iter().zip(UPSTREAM) {
        assert_eq!(
            (row.id(), row.name(), row.block_size(), row.block_bytes()),
            (id, name, block, bytes)
        );
        assert_eq!(GgmlType::from_id(id), Some(*row));
    }
    assert_eq!(TYPES.len(), 36);
}

#[test]
fn ids_are_strictly_ascending() {
    for pair in TYPES.windows(2) {
        assert!(
            pair[0].id() < pair[1].id(),
            "{} then {}",
            pair[0].id(),
            pair[1].id()
        );
    }
}

#[test]
fn removed_and_unknown_ids_are_refused() {
    for id in [4, 5, 31, 32, 33, 36, 37, 38, 44, 45, 1000, u32::MAX] {
        assert!(GgmlType::from_id(id).is_none(), "id {id} must be refused");
    }
}

#[test]
fn bytes_counts_whole_blocks_of_the_first_dimension() {
    let q4_0 = GgmlType::from_id(2).unwrap();
    // 4096 x 32: 128 blocks per row, 18 bytes each, 32 rows.
    assert_eq!(q4_0.bytes(&[4096, 32]), Ok(128 * 18 * 32));
    let f16 = GgmlType::from_id(1).unwrap();
    assert_eq!(f16.bytes(&[3, 5, 7]), Ok(3 * 5 * 7 * 2));
}

#[test]
fn bytes_refuses_a_partial_block() {
    let q4_0 = GgmlType::from_id(2).unwrap();
    assert_eq!(q4_0.bytes(&[33]), Err(SizeError::PartialBlock));
    assert_eq!(q4_0.bytes(&[31]), Err(SizeError::PartialBlock));
    assert_eq!(q4_0.bytes(&[32]), Ok(18));
    assert_eq!(q4_0.bytes(&[64, 3]), Ok(2 * 18 * 3));
}

#[test]
fn bytes_refuses_overflow() {
    let f32_ = GgmlType::from_id(0).unwrap();
    assert_eq!(f32_.bytes(&[u64::MAX, 2]), Err(SizeError::Overflow));
    assert_eq!(f32_.bytes(&[1 << 62]), Err(SizeError::Overflow));
    assert_eq!(f32_.bytes(&[1 << 61]), Ok(1 << 63));
    assert_eq!(f32_.bytes(&[1 << 30, 1 << 31]), Ok(1 << 63));
    assert_eq!(f32_.bytes(&[1 << 30, 1 << 32]), Err(SizeError::Overflow));
}

#[test]
fn no_dimensions_is_one_element() {
    let f32_ = GgmlType::from_id(0).unwrap();
    assert_eq!(f32_.bytes(&[]), Ok(4));
}
