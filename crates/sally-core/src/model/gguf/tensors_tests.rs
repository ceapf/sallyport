#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use super::super::build::{F32, Gguf, I8, Q4_0, Tensor, code};
use super::super::{GgufError, MAX_DIMS, MAX_ELEMENTS};

fn with(t: Tensor) -> Gguf {
    Gguf::empty().tensor(t)
}

#[test]
fn the_element_limit_is_i64_max() {
    assert_eq!(MAX_ELEMENTS, i64::MAX as u64);
    assert_eq!(MAX_DIMS, 4);
}

#[test]
fn names_are_1_to_63_bytes_of_utf8_without_controls() {
    let at_limit = "n".repeat(63);
    assert_eq!(
        code(with(Tensor::of(&at_limit, F32, &[8])).parse()),
        "accepted"
    );
    assert_eq!(
        code(with(Tensor::of("blk.0.ffn_up.wéight", F32, &[8])).parse()),
        "accepted"
    );
    let over = "n".repeat(64);
    assert_eq!(
        with(Tensor::of(&over, F32, &[8])).parse(),
        Err(GgufError::TensorNameTooLong(0, 64))
    );
    for bad in [
        &b""[..],
        b"a\0",
        b"\0",
        b"a\nb",
        b"a\x7f",
        "a\u{85}".as_bytes(),
        b"\xff",
    ] {
        let t = Tensor {
            name: bad.to_vec(),
            ..Tensor::of("x", F32, &[8])
        };
        assert_eq!(with(t).parse(), Err(GgufError::BadTensorName(0)), "{bad:?}");
    }
}

#[test]
fn names_are_unique() {
    let file = Gguf::valid().tensor(Tensor::of("w", F32, &[8]));
    assert_eq!(
        file.parse(),
        Err(GgufError::DuplicateTensorName(1, "w".into()))
    );
    let file = Gguf::valid().tensor(Tensor::of("W", F32, &[8]));
    assert_eq!(code(file.parse()), "accepted");
}

#[test]
fn one_to_four_dimensions() {
    let four = with(Tensor::of("w", F32, &[2, 2, 2, 2])).parse().unwrap();
    assert_eq!(four.tensors()[0].dims(), [2, 2, 2, 2]);
    assert_eq!(four.tensors()[0].bytes(), 64);
    let none = Tensor {
        n_dims: Some(0),
        ..Tensor::of("w", F32, &[])
    };
    assert_eq!(with(none).parse(), Err(GgufError::NoDims(0)));
    for n in [5, 200, u32::MAX] {
        let many = Tensor {
            n_dims: Some(n),
            ..Tensor::of("w", F32, &[8])
        };
        assert_eq!(with(many).parse(), Err(GgufError::TooManyDims(0, n)));
    }
}

#[test]
fn every_dimension_is_1_to_i64_max() {
    assert_eq!(
        with(Tensor::of("w", F32, &[8, 0])).parse(),
        Err(GgufError::BadDim(0, 1))
    );
    assert_eq!(
        with(Tensor::of("w", F32, &[1 << 63])).parse(),
        Err(GgufError::BadDim(0, 0))
    );
    // The largest dimension passes the shape checks and then lies past the end of the file.
    let largest = Tensor::of("w", I8, &[i64::MAX as u64]);
    assert_eq!(with(largest).parse(), Err(GgufError::TensorOutOfBounds(0)));
}

#[test]
fn the_element_count_is_at_most_i64_max() {
    assert_eq!(
        with(Tensor::of("w", I8, &[1 << 62, 2])).parse(),
        Err(GgufError::DimsOverflow(0))
    );
    assert_eq!(
        with(Tensor::of("w", I8, &[1 << 32, 1 << 32])).parse(),
        Err(GgufError::DimsOverflow(0))
    );
    let at_limit = Tensor::of("w", I8, &[(1 << 62) - 1, 2]);
    assert_eq!(with(at_limit).parse(), Err(GgufError::TensorOutOfBounds(0)));
    // Within the element limit but the byte size overflows.
    assert_eq!(
        with(Tensor::of("w", F32, &[1 << 62])).parse(),
        Err(GgufError::DimsOverflow(0))
    );
}

#[test]
fn removed_and_unknown_types_are_refused() {
    for ty in [4, 5, 31, 38, 44, u32::MAX] {
        assert_eq!(
            with(Tensor::of("w", ty, &[32])).parse(),
            Err(GgufError::InvalidTensorType(0, ty))
        );
    }
}

#[test]
fn a_first_dimension_must_be_whole_blocks() {
    assert_eq!(
        with(Tensor::of("w", Q4_0, &[16])).parse(),
        Err(GgufError::PartialBlock(0))
    );
}

#[test]
fn tensors_lie_back_to_back_from_offset_zero() {
    let file = Gguf::valid()
        .tensor(Tensor::of("a", I8, &[3]))
        .tensor(Tensor::of("b", F32, &[8]));
    let header = file.parse().unwrap();
    let offsets: Vec<u64> = header.tensors().iter().map(|t| t.offset()).collect();
    assert_eq!(offsets, [0, 32, 64]);
    assert_eq!(header.data_end(), header.data_start() + 64 + 32);
}

fn moved(offset: u64) -> Gguf {
    Gguf::valid().tensor(Tensor {
        offset: Some(offset),
        ..Tensor::of("b", F32, &[8])
    })
}

#[test]
fn a_gap_an_overlap_or_an_unaligned_offset_is_refused() {
    for offset in [64, 0, 16, 33] {
        let file = Gguf {
            data: Some(256),
            ..moved(offset)
        };
        assert_eq!(
            file.parse(),
            Err(GgufError::TensorNotContiguous(1, offset)),
            "{offset}"
        );
    }
    let first = with(Tensor {
        offset: Some(32),
        ..Tensor::of("w", F32, &[8])
    });
    let file = Gguf {
        data: Some(256),
        ..first
    };
    assert_eq!(file.parse(), Err(GgufError::TensorNotContiguous(0, 32)));
}

#[test]
fn bounds_are_checked_before_contiguity() {
    // Tensor 0 is out of place but inside the file; tensor 1 ends past it.
    let file = Gguf {
        data: Some(64),
        ..with(Tensor {
            offset: Some(32),
            ..Tensor::of("a", F32, &[8])
        })
        .tensor(Tensor {
            offset: Some(4096),
            ..Tensor::of("b", F32, &[8])
        })
    };
    assert_eq!(file.parse(), Err(GgufError::TensorOutOfBounds(1)));
}

#[test]
fn offsets_that_overflow_are_out_of_bounds() {
    for offset in [u64::MAX, u64::MAX - 31, 1 << 63] {
        let file = Gguf {
            data: Some(64),
            ..moved(offset)
        };
        assert_eq!(
            file.parse(),
            Err(GgufError::TensorOutOfBounds(1)),
            "{offset}"
        );
    }
}

#[test]
fn data_ending_exactly_at_the_file_end_is_accepted() {
    let file = Gguf {
        data: Some(32),
        ..Gguf::valid()
    };
    let header = file.parse().unwrap();
    assert_eq!(header.data_end(), header.file_len());
    let short = Gguf {
        data: Some(31),
        ..Gguf::valid()
    };
    assert_eq!(short.parse(), Err(GgufError::TensorOutOfBounds(0)));
}

#[test]
fn trailing_bytes_are_accepted_for_now() {
    // TODO(#183): the rule for bytes after the last tensor.
    let file = Gguf {
        trailing: 100,
        ..Gguf::valid()
    };
    let header = file.parse().unwrap();
    assert_eq!(header.file_len() - header.data_end(), 100);
}

#[test]
fn the_data_section_starts_at_the_aligned_header_end() {
    let mut file = Gguf::valid().kv_u32("general.alignment", 4_096);
    file.alignment = 4_096;
    let header = file.parse().unwrap();
    assert_eq!(header.data_start(), 4_096);
    assert_eq!(header.data_start() % 4_096, 0);
    let unpadded = Gguf {
        data: Some(0),
        ..file.clone()
    };
    let mut bytes = unpadded.header();
    bytes.extend_from_slice(&[0; 32]);
    // The data would start at the header's end, not at the alignment: tensor 0's 32 bytes do
    // not fit.
    assert_eq!(
        super::super::build::parse_bytes(&bytes),
        Err(GgufError::TensorOutOfBounds(0))
    );
}
