#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::io::{self, Read};
use std::path::PathBuf;

use proptest::prelude::*;

use super::build::{
    ARRAY, F32, Gguf, I8, OneByte, Q4_0, STRING, Tensor, U8, U64, array, code, parse_bytes, s,
};
use super::*;

#[test]
fn a_valid_file_parses_to_its_header() {
    let file = Gguf::valid();
    let bytes = file.bytes();
    let header = parse_bytes(&bytes).unwrap();
    assert_eq!(header.version(), 3);
    assert_eq!(header.alignment(), DEFAULT_ALIGNMENT);
    assert_eq!(header.metadata().len(), 1);
    let entry = &header.metadata()[0];
    assert_eq!(entry.key().as_str(), "general.architecture");
    assert_eq!(entry.value(), &Value::String(FileText("llama".into())));
    let t = &header.tensors()[0];
    assert_eq!(t.name().as_str(), "w");
    assert_eq!(t.dims(), [8]);
    assert_eq!(t.ggml_type(), GgmlType::from_id(F32).unwrap());
    assert_eq!((t.offset(), t.bytes()), (0, 32));
    let header_len = file.header().len() as u64;
    assert_eq!(header.data_start(), header_len.next_multiple_of(32));
    assert_eq!(header.data_end(), header.data_start() + 32);
    assert_eq!(header.file_len(), bytes.len() as u64);
    assert_eq!(header.retained_text_bytes(), 20 + 5 + 1);
}

#[test]
fn versions_2_and_3_only() {
    for (version, expected) in [
        (2, "accepted"),
        (3, "accepted"),
        (0, "bad_version"),
        (1, "bad_version"),
        (4, "bad_version"),
        (0x0300_0000, "bad_version"),
    ] {
        let file = Gguf {
            version,
            ..Gguf::valid()
        };
        assert_eq!(code(file.parse()), expected, "version {version}");
    }
    let refused = Gguf {
        version: 0x0300_0000,
        ..Gguf::valid()
    };
    assert_eq!(refused.parse(), Err(GgufError::BadVersion(0x0300_0000)));
}

#[test]
fn the_magic_must_be_gguf() {
    for magic in [*b"GGUG", *b"gguf", *b"FUGG", [0x80, 0x02, b'c', b'p']] {
        let file = Gguf {
            magic,
            ..Gguf::valid()
        };
        assert_eq!(file.parse(), Err(GgufError::MagicMismatch), "{magic:?}");
    }
}

#[test]
fn every_strict_prefix_of_a_valid_file_is_refused() {
    let file = Gguf::valid();
    let bytes = file.bytes();
    let header_len = file.header().len();
    for len in 0..bytes.len() {
        let expected = if len < header_len {
            "truncated"
        } else {
            "tensor_out_of_bounds"
        };
        assert_eq!(code(parse_bytes(&bytes[..len])), expected, "prefix {len}");
    }
}

#[test]
fn a_source_shorter_than_file_len_is_truncated() {
    let bytes = Gguf::valid().header();
    let short = &bytes[..bytes.len() - 1];
    assert_eq!(parse(short, 1 << 20), Err(GgufError::Truncated));
}

#[test]
fn an_io_error_is_io_error() {
    struct Failing;
    impl Read for Failing {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::ErrorKind::PermissionDenied.into())
        }
    }
    assert_eq!(
        parse(Failing, 1 << 20),
        Err(GgufError::Io(io::ErrorKind::PermissionDenied))
    );
}

#[test]
fn one_byte_reads_give_the_same_result_as_a_slice() {
    let files = [
        Gguf::valid(),
        Gguf::valid().kv(
            b"tokenizer.ggml.tokens",
            ARRAY,
            &array(STRING, 2, &[s(b"a"), s(b"bc")].concat()),
        ),
        Gguf {
            version: 1,
            ..Gguf::valid()
        },
        Gguf::valid().kv(b"n", ARRAY, &array(ARRAY, 1, &[])),
        Gguf::valid().tensor(Tensor {
            offset: Some(64),
            ..Tensor::of("x", F32, &[8])
        }),
    ];
    for file in files {
        let bytes = file.bytes();
        let len = bytes.len() as u64;
        assert_eq!(parse(OneByte(&bytes[..]), len), parse_bytes(&bytes));
    }
}

#[test]
fn tensor_count_limit_and_zero() {
    let at_limit = Gguf {
        tensor_count: Some(65_536),
        ..Gguf::valid()
    };
    // Within the limit: the parser goes on to read 65 536 infos and the file ends first.
    assert_eq!(code(parse_bytes(&at_limit.header())), "truncated");
    for count in [65_537, 1 << 63, u64::MAX] {
        let file = Gguf {
            tensor_count: Some(count),
            ..Gguf::valid()
        };
        assert_eq!(file.parse(), Err(GgufError::TensorCountLimit(count)));
    }
    let none = Gguf {
        tensor_count: Some(0),
        ..Gguf::valid()
    };
    assert_eq!(none.parse(), Err(GgufError::NoTensors));
    assert_eq!(
        Gguf::empty().kv_str("a", b"b").parse(),
        Err(GgufError::NoTensors)
    );
}

#[test]
fn the_full_tensor_count_is_accepted() {
    let mut file = Gguf::empty();
    for t in 0..65_536 {
        file = file.tensor(Tensor::of(&format!("t{t}"), I8, &[1]));
    }
    file.alignment = 8;
    let file = file.kv_u32("general.alignment", 8);
    let header = file.parse().unwrap();
    assert_eq!(header.tensors().len(), 65_536);
    assert_eq!(header.tensors()[65_535].offset(), 65_535 * 8);
    assert!(header.retained_text_bytes() <= MAX_RETAINED_TEXT_BYTES);
}

#[test]
fn kv_count_limit() {
    let mut file = Gguf::valid();
    for k in 1..4_096 {
        file = file.kv(format!("k{k}").as_bytes(), U8, &[0]);
    }
    assert_eq!(file.parse().unwrap().metadata().len(), 4_096);
    for count in [4_097, 1 << 40] {
        let file = Gguf {
            kv_count: Some(count),
            ..Gguf::valid()
        };
        assert_eq!(file.parse(), Err(GgufError::KvCountLimit(count)));
    }
}

#[test]
fn tensor_count_is_reported_before_kv_count() {
    let file = Gguf {
        tensor_count: Some(1 << 63),
        kv_count: Some(1 << 40),
        ..Gguf::valid()
    };
    assert_eq!(code(file.parse()), "tensor_count_limit");
}

/// A stream of `parts`, one after another.
fn chain(parts: Vec<Box<dyn Read>>) -> Box<dyn Read> {
    parts
        .into_iter()
        .fold(Box::new(io::empty()), |acc, part| Box::new(acc.chain(part)))
}

/// Zeros, `len` of them, without holding them.
fn zeros(len: u64) -> Box<dyn Read> {
    Box::new(io::repeat(0).take(len))
}

/// The entry head of an array `key` of `len` elements of type `elem`; the elements follow.
fn array_head(key: &[u8], elem: u32, len: u64) -> Box<dyn Read> {
    let mut head = s(key);
    head.extend_from_slice(&ARRAY.to_le_bytes());
    head.extend_from_slice(&array(elem, len, &[]));
    Box::new(io::Cursor::new(head))
}

/// The stream of a file whose header is exactly `total` bytes: two big arrays of 8-byte zero
/// elements of type `wide` (`u64`, or `string`: empty strings), a `u8` array, then one I8 tensor
/// of 8 elements. Returns the stream and the file length.
fn header_of(total: u64, wide: u32, tail: Vec<Box<dyn Read>>) -> (Box<dyn Read>, u64) {
    const ENTRY: u64 = 8 + 2 + 4 + 4 + 8;
    let tensor = Gguf::empty().tensor(Tensor::of("w", I8, &[8]));
    let full = tensor.header();
    let info = full.len() as u64 - 24;
    let tail_len = 3 * ENTRY;
    let big = MAX_ARRAY_LEN * 8;
    let rest = total - 24 - info - tail_len - big;
    let small = rest % 8 + 8;
    let medium = (rest - small) / 8;
    assert!(medium <= MAX_ARRAY_LEN && small <= MAX_ARRAY_LEN);
    let mut prefix = full[..16].to_vec();
    prefix.extend_from_slice(&(3 + tail.len() as u64).to_le_bytes());
    let mut parts: Vec<Box<dyn Read>> = vec![
        Box::new(io::Cursor::new(prefix)),
        array_head(b"a0", wide, MAX_ARRAY_LEN),
        zeros(big),
        array_head(b"a1", wide, medium),
        zeros(medium * 8),
        array_head(b"a2", U8, small),
        zeros(small),
    ];
    parts.extend(tail);
    parts.push(Box::new(io::Cursor::new(full[24..].to_vec())));
    (chain(parts), total.next_multiple_of(32) + 8)
}

#[test]
fn a_header_of_exactly_the_cap_is_accepted() {
    let (stream, file_len) = header_of(MAX_HEADER_BYTES, U64, Vec::new());
    let header = parse(stream, file_len).unwrap();
    assert_eq!(header.data_start(), MAX_HEADER_BYTES.next_multiple_of(32));
    assert_eq!(
        header.metadata()[0].value(),
        &Value::Array(ValueType::U64, MAX_ARRAY_LEN)
    );
}

/// The slowest header within the cap: about 8.4 million string lengths, each read and checked.
#[test]
fn a_cap_sized_header_of_empty_strings_is_accepted() {
    let (stream, file_len) = header_of(MAX_HEADER_BYTES, STRING, Vec::new());
    let header = parse(stream, file_len).unwrap();
    assert_eq!(
        header.metadata()[0].value(),
        &Value::Array(ValueType::String, MAX_ARRAY_LEN)
    );
}

#[test]
fn a_header_one_byte_over_the_cap_is_too_large() {
    for wide in [U64, STRING] {
        let (stream, file_len) = header_of(MAX_HEADER_BYTES + 1, wide, Vec::new());
        assert_eq!(parse(stream, file_len), Err(GgufError::HeaderTooLarge));
    }
}

#[test]
fn the_item_limit_comes_before_the_header_cap() {
    // Near the cap, a string over its own limit is reported as that, not as the cap.
    let mut entry = s(b"long");
    entry.extend_from_slice(&STRING.to_le_bytes());
    entry.extend_from_slice(&(MAX_STRING_BYTES + 1).to_le_bytes());
    let tail: Vec<Box<dyn Read>> = vec![Box::new(io::Cursor::new(entry))];
    let (stream, file_len) = header_of(MAX_HEADER_BYTES - 2, U64, tail);
    assert_eq!(code(parse(stream, file_len)), "string_too_long");
}

#[test]
fn the_header_cap_comes_before_the_file_length() {
    // The second big array passes both the cap and the file's end: the cap is reported.
    let first = 24 + 26 + MAX_ARRAY_LEN * 8;
    let mut prefix = Gguf::valid().header()[..16].to_vec();
    prefix.extend_from_slice(&2u64.to_le_bytes());
    let parts: Vec<Box<dyn Read>> = vec![
        Box::new(io::Cursor::new(prefix)),
        array_head(b"a0", U64, MAX_ARRAY_LEN),
        zeros(MAX_ARRAY_LEN * 8),
        array_head(b"a1", U64, MAX_ARRAY_LEN),
        zeros(MAX_ARRAY_LEN * 8),
    ];
    assert_eq!(
        parse(chain(parts), first + 30),
        Err(GgufError::HeaderTooLarge)
    );
}

#[test]
fn the_file_length_is_reported_within_the_cap() {
    let file = Gguf::valid().kv(b"a", ARRAY, &array(U64, MAX_ARRAY_LEN, &[]));
    assert_eq!(file.parse(), Err(GgufError::Truncated));
}

#[test]
fn debug_shows_lengths_never_file_text() {
    let file = Gguf::valid()
        .kv_str("general.name", b"secretive-model")
        .kv_str("zzkeyzz", b"x")
        .tensor(Tensor::of("zztensorzz", F32, &[8]));
    let header = file.parse().unwrap();
    let shown = format!("{header:?}");
    for text in [
        "secretive",
        "llama",
        "zzkeyzz",
        "zztensorzz",
        "general.name",
    ] {
        assert!(!shown.contains(text), "{text} in {shown}");
    }
    assert!(shown.contains("FileText(15 bytes)"), "{shown}");
}

#[test]
fn limits_keep_their_documented_values() {
    assert_eq!(MAX_HEADER_BYTES, 64 << 20);
    assert_eq!(MAX_TENSORS, 1 << 16);
    assert_eq!(MAX_KV, 4_096);
    assert_eq!(MAX_STRING_BYTES, 64 << 10);
    assert_eq!(MAX_ARRAY_LEN, 4 << 20);
    assert_eq!(MAX_KEY_BYTES, 256);
    assert_eq!(MAX_NAME_BYTES, 63);
    assert_eq!(
        (MAX_DIMS, MIN_ALIGNMENT, MAX_ALIGNMENT, DEFAULT_ALIGNMENT),
        (4, 8, 1 << 16, 32)
    );
    assert_eq!((KEPT_STRING_BYTES, MAX_TEMPLATES), (1_024, 16));
    assert_eq!(
        MAX_RETAINED_TEXT_BYTES,
        MAX_KV * (MAX_KEY_BYTES + KEPT_STRING_BYTES)
            + MAX_TEMPLATES * MAX_STRING_BYTES
            + MAX_TENSORS * MAX_NAME_BYTES
    );
    assert_eq!(READ_BUFFER, 64 << 10);
}

/// RT-MDL-03's corpus cases and the code each gets. Not the red-team row itself (no `rt_`
/// prefix): the row, with its corpus files and time and memory bounds, lands with M2 Task 9 and
/// asserts these same codes.
#[test]
fn mdl_03_cases_each_get_their_code() {
    let nested = (0..10).fold(Vec::new(), |inner, _| array(ARRAY, 1, &inner));
    let mut huge_string = s(b"general.name");
    huge_string.extend_from_slice(&STRING.to_le_bytes());
    huge_string.extend_from_slice(&u64::from(u32::MAX).to_le_bytes());
    let mut file_huge_string = Gguf::valid();
    file_huge_string.kv.push(huge_string);
    let cases: Vec<(&str, Gguf, &str)> = vec![
        (
            "tensor_count=2^63",
            Gguf {
                tensor_count: Some(1 << 63),
                ..Gguf::valid()
            },
            "tensor_count_limit",
        ),
        (
            "kv_count=2^40",
            Gguf {
                kv_count: Some(1 << 40),
                ..Gguf::valid()
            },
            "kv_count_limit",
        ),
        ("string len 2^32-1", file_huge_string, "string_too_long"),
        (
            "array len 2^40",
            Gguf::valid().kv(b"a", ARRAY, &array(U8, 1 << 40, &[])),
            "array_too_long",
        ),
        (
            "nested depth 10",
            Gguf::valid().kv(b"a", ARRAY, &nested),
            "nested_array",
        ),
        (
            "offset past EOF",
            Gguf::empty().tensor(Tensor {
                offset: Some(1 << 40),
                ..Tensor::of("w", F32, &[8])
            }),
            "tensor_out_of_bounds",
        ),
        (
            "dims product overflow",
            Gguf::empty().tensor(Tensor::of("w", F32, &[1 << 32, 1 << 32])),
            "dims_overflow",
        ),
        (
            "n_dims=200",
            Gguf::empty().tensor(Tensor {
                n_dims: Some(200),
                ..Tensor::of("w", F32, &[8])
            }),
            "too_many_dims",
        ),
        (
            "invalid ggml type",
            Gguf::empty().tensor(Tensor::of("w", 4, &[8])),
            "invalid_tensor_type",
        ),
        (
            "duplicate tensor names",
            Gguf::valid().tensor(Tensor::of("w", F32, &[8])),
            "duplicate_tensor_name",
        ),
        (
            "alignment 3",
            Gguf::valid().kv_u32("general.alignment", 3),
            "bad_alignment",
        ),
    ];
    for (case, file, expected) in cases {
        assert_eq!(code(file.parse()), expected, "{case}");
    }
    // Truncated header: the file ends inside the last tensor info.
    let header = Gguf::valid().header();
    assert_eq!(code(parse_bytes(&header[..header.len() - 3])), "truncated");
}

#[test]
fn partial_blocks_are_their_own_refusal() {
    let file = Gguf::empty().tensor(Tensor::of("w", Q4_0, &[33]));
    assert_eq!(file.parse(), Err(GgufError::PartialBlock(0)));
    let file = Gguf::empty().tensor(Tensor::of("w", Q4_0, &[64, 2]));
    assert_eq!(file.parse().unwrap().tensors()[0].bytes(), 2 * 18 * 2);
}

/// The fuzz seeds: built here, committed under fuzz/corpus/gguf/, and pinned by this test.
/// `SALLYPORT_WRITE_GGUF_SEEDS=1` rewrites them.
fn seeds() -> Vec<(&'static str, Gguf, &'static str)> {
    let v3 = Gguf::valid()
        .kv(
            b"tokenizer.ggml.tokens",
            ARRAY,
            &array(STRING, 2, &[s(b"a"), s(b"bc")].concat()),
        )
        .kv_u32("general.alignment", 32)
        .tensor(Tensor::of("q", Q4_0, &[32, 2]));
    let v2 = Gguf {
        version: 2,
        ..Gguf::empty().tensor(Tensor::of("w", I8, &[4]))
    };
    let refused = Gguf::valid().kv(b"n", ARRAY, &array(ARRAY, 1, &[]));
    let template = Gguf::valid()
        .kv_str("tokenizer.chat_template", b"{{ messages }}")
        .kv_str("tokenizer.chat_template.tool_use", b"{{ tools }}");
    vec![
        ("valid-v3", v3, "accepted"),
        ("valid-v2", v2, "accepted"),
        ("refused-nested-array", refused, "nested_array"),
        ("valid-template", template, "accepted"),
    ]
}

/// How many seeds there are; `mutated_valid_files_never_panic` draws from all of them.
const SEEDS: usize = 4;

#[test]
fn committed_fuzz_seeds_match_the_builder() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/corpus/gguf");
    let write = std::env::var_os("SALLYPORT_WRITE_GGUF_SEEDS").is_some();
    assert_eq!(seeds().len(), SEEDS);
    for (name, file, expected) in seeds() {
        let bytes = file.bytes();
        assert!(bytes.len() < 1_024, "{name}");
        assert_eq!(code(parse_bytes(&bytes)), expected, "{name}");
        let path = dir.join(name);
        if write {
            std::fs::write(&path, &bytes).unwrap();
        }
        assert_eq!(
            std::fs::read(&path).unwrap(),
            bytes,
            "{name} differs from the builder"
        );
    }
}

/// Every accepted header obeys its limits and lies inside the file; the result does not depend
/// on how reads are cut.
fn check_any(bytes: &[u8]) -> Result<(), TestCaseError> {
    let len = bytes.len() as u64;
    let result = parse_bytes(bytes);
    prop_assert_eq!(
        format!("{result:?}"),
        format!("{:?}", parse(OneByte(bytes), len))
    );
    if let Ok(header) = result {
        prop_assert!(header.retained_text_bytes() <= MAX_RETAINED_TEXT_BYTES);
        prop_assert!(header.data_end() <= len);
        for t in header.tensors() {
            prop_assert!(header.data_start() + t.offset() + t.bytes() <= len);
        }
    }
    Ok(())
}

proptest! {
    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        check_any(&bytes)?;
    }

    /// Valid files with a few bytes overwritten reach deep into the parser.
    #[test]
    fn mutated_valid_files_never_panic(
        seed in 0..SEEDS,
        edits in proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..6),
    ) {
        let mut bytes = seeds().swap_remove(seed).1.bytes();
        for (at, byte) in edits {
            let i = at.index(bytes.len());
            bytes[i] = byte;
        }
        check_any(&bytes)?;
    }
}
