#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use super::super::build::{ARRAY, BOOL, Gguf, STRING, U8, U32, U64, array, code, s};
use super::super::{F32Bits, F64Bits, FileText, GgufError, GgufHeader, Value, ValueType};

#[test]
fn floats_compare_by_bits_and_read_back() {
    let nan = Value::F32(F32Bits(f32::NAN.to_bits()));
    assert_eq!(nan, nan.clone());
    assert_ne!(
        Value::F64(F64Bits(0.0f64.to_bits())),
        Value::F64(F64Bits((-0.0f64).to_bits()))
    );
    assert_eq!(F32Bits(1.5f32.to_bits()).get(), 1.5);
    assert_eq!(F64Bits(2.25f64.to_bits()).get(), 2.25);
    assert_eq!(format!("{:?}", F32Bits(1.5f32.to_bits())), "1.5");
    assert_eq!(format!("{:?}", F64Bits(2.25f64.to_bits())), "2.25");
}

fn only_value(file: Gguf) -> Value {
    let header: GgufHeader = file.parse().unwrap();
    header.metadata().last().unwrap().value().clone()
}

fn one(key: &[u8], ty: u32, payload: &[u8]) -> Gguf {
    Gguf::valid().kv(key, ty, payload)
}

#[test]
fn keys_are_printable_ascii_up_to_256_bytes() {
    let at_limit = vec![b'k'; 256];
    assert_eq!(code(one(&at_limit, U8, &[0]).parse()), "accepted");
    let over = vec![b'k'; 257];
    assert_eq!(
        one(&over, U8, &[0]).parse(),
        Err(GgufError::KeyTooLong(1, 257))
    );
    assert_eq!(
        one(&vec![b'k'; 1 << 20], U8, &[0]).parse(),
        Err(GgufError::KeyTooLong(1, 1 << 20))
    );
    for bad in [
        &b""[..],
        b"a b",
        b"a\x7f",
        b"a\x1fb",
        b"general.alignment\0x",
        "kéy".as_bytes(),
        b"\xff",
    ] {
        assert_eq!(
            one(bad, U8, &[0]).parse(),
            Err(GgufError::BadKey(1)),
            "{bad:?}"
        );
    }
    assert_eq!(code(one(b"!~", U8, &[0]).parse()), "accepted");
}

#[test]
fn keys_are_unique_and_case_sensitive() {
    let file = one(b"general.architecture", U8, &[0]);
    assert_eq!(
        file.parse(),
        Err(GgufError::DuplicateKey(1, "general.architecture".into()))
    );
    let file = one(b"General.Architecture", U8, &[0]);
    assert_eq!(code(file.parse()), "accepted");
}

#[test]
fn a_nul_suffixed_alignment_key_is_refused_not_applied() {
    // The engine would read this key as general.alignment.
    let file = one(b"general.alignment\0", U32, &64u32.to_le_bytes());
    assert_eq!(file.parse(), Err(GgufError::BadKey(1)));
}

#[test]
fn every_scalar_type_reads_its_value() {
    let cases: Vec<(u32, Vec<u8>, Value)> = vec![
        (0, vec![200], Value::U8(200)),
        (1, vec![0xff], Value::I8(-1)),
        (2, 513u16.to_le_bytes().to_vec(), Value::U16(513)),
        (3, (-2i16).to_le_bytes().to_vec(), Value::I16(-2)),
        (4, 70_000u32.to_le_bytes().to_vec(), Value::U32(70_000)),
        (5, (-3i32).to_le_bytes().to_vec(), Value::I32(-3)),
        (
            6,
            1.5f32.to_le_bytes().to_vec(),
            Value::F32(F32Bits(1.5f32.to_bits())),
        ),
        (7, vec![0], Value::Bool(false)),
        (7, vec![1], Value::Bool(true)),
        (10, (1u64 << 40).to_le_bytes().to_vec(), Value::U64(1 << 40)),
        (11, (-4i64).to_le_bytes().to_vec(), Value::I64(-4)),
        (
            12,
            2.25f64.to_le_bytes().to_vec(),
            Value::F64(F64Bits(2.25f64.to_bits())),
        ),
    ];
    for (ty, payload, expected) in cases {
        assert_eq!(only_value(one(b"k", ty, &payload)), expected, "type {ty}");
    }
}

#[test]
fn a_bool_is_0_or_1() {
    for byte in [2u8, 0x80, 0xff] {
        assert_eq!(
            one(b"k", BOOL, &[byte]).parse(),
            Err(GgufError::InvalidBool(1, byte))
        );
    }
}

#[test]
fn an_unknown_value_type_is_refused() {
    for ty in [13, 255, u32::MAX] {
        assert_eq!(
            one(b"k", ty, &[0; 8]).parse(),
            Err(GgufError::BadValueType(1, ty))
        );
    }
}

#[test]
fn short_utf8_strings_are_kept_and_others_summarized() {
    let kept = vec![b'x'; 1_024];
    assert_eq!(
        only_value(one(b"k", STRING, &s(&kept))),
        Value::String(FileText("x".repeat(1_024)))
    );
    let long = vec![b'x'; 1_025];
    assert_eq!(
        only_value(one(b"k", STRING, &s(&long))),
        Value::StringSummary(1_025)
    );
    assert_eq!(
        only_value(one(b"k", STRING, &s(b"\xff\xfe"))),
        Value::StringSummary(2)
    );
    let at_limit = vec![b'x'; 65_536];
    assert_eq!(
        only_value(one(b"k", STRING, &s(&at_limit))),
        Value::StringSummary(65_536)
    );
    assert_eq!(
        only_value(one(b"k", STRING, &s(b""))),
        Value::String(FileText(String::new()))
    );
}

#[test]
fn a_string_over_the_limit_is_refused() {
    let over = vec![b'x'; 65_537];
    assert_eq!(
        one(b"k", STRING, &s(&over)).parse(),
        Err(GgufError::StringTooLong(1, 65_537))
    );
}

#[test]
fn arrays_keep_type_and_length_only() {
    assert_eq!(
        only_value(one(b"k", ARRAY, &array(U8, 3, &[1, 2, 3]))),
        Value::Array(ValueType::U8, 3)
    );
    let strings = [s(b"a"), s(&[0xff; 2]), s(&[b'x'; 2_000])].concat();
    assert_eq!(
        only_value(one(b"k", ARRAY, &array(STRING, 3, &strings))),
        Value::Array(ValueType::String, 3)
    );
    // Bool elements are not inspected.
    assert_eq!(
        only_value(one(b"k", ARRAY, &array(BOOL, 2, &[7, 9]))),
        Value::Array(ValueType::Bool, 2)
    );
    let sizes: [(u32, u64); 11] = [
        (0, 1),
        (1, 1),
        (2, 2),
        (3, 2),
        (4, 4),
        (5, 4),
        (6, 4),
        (7, 1),
        (10, 8),
        (11, 8),
        (12, 8),
    ];
    for (ty, size) in sizes {
        let payload = array(ty, 3, &vec![0; 3 * size as usize]);
        assert!(
            matches!(only_value(one(b"k", ARRAY, &payload)), Value::Array(_, 3)),
            "{ty}"
        );
        // One byte short: the next entry's key length reads into it and the file ends early.
        let short = array(ty, 3, &vec![0; 3 * size as usize - 1]);
        assert_ne!(code(one(b"k", ARRAY, &short).parse()), "accepted", "{ty}");
    }
}

#[test]
fn array_length_is_limited() {
    let at_limit = array(U8, 4_194_304, &vec![0; 4_194_304]);
    assert_eq!(
        only_value(one(b"k", ARRAY, &at_limit)),
        Value::Array(ValueType::U8, 4_194_304)
    );
    for len in [4_194_305, 1 << 40, u64::MAX] {
        assert_eq!(
            one(b"k", ARRAY, &array(U64, len, &[])).parse(),
            Err(GgufError::ArrayTooLong(1, len))
        );
    }
}

#[test]
fn arrays_of_arrays_and_bad_element_types_are_refused() {
    assert_eq!(
        one(b"k", ARRAY, &array(ARRAY, 1, &array(U8, 1, &[0]))).parse(),
        Err(GgufError::NestedArray(1))
    );
    assert_eq!(
        one(b"k", ARRAY, &array(13, 1, &[0])).parse(),
        Err(GgufError::BadValueType(1, 13))
    );
}

#[test]
fn every_string_in_an_array_is_length_checked() {
    let mut elements = s(b"ok");
    elements.extend_from_slice(&65_537u64.to_le_bytes());
    assert_eq!(
        one(b"k", ARRAY, &array(STRING, 2, &elements)).parse(),
        Err(GgufError::StringTooLong(1, 65_537))
    );
}

#[test]
fn chat_templates_are_kept_whole_up_to_the_string_limit() {
    let template = vec![b'{'; 65_536];
    let value = only_value(Gguf::valid().kv_str("tokenizer.chat_template", &template));
    assert_eq!(value, Value::String(FileText("{".repeat(65_536))));
    let named = only_value(Gguf::valid().kv_str("tokenizer.chat_template.tool_use", &template));
    assert_eq!(named, Value::String(FileText("{".repeat(65_536))));
    let over = vec![b'{'; 65_537];
    assert_eq!(
        Gguf::valid()
            .kv_str("tokenizer.chat_template", &over)
            .parse(),
        Err(GgufError::StringTooLong(1, 65_537))
    );
    // Not a template key: an ordinary long string.
    let other = only_value(Gguf::valid().kv_str("tokenizer.chat_templates", &template));
    assert_eq!(other, Value::StringSummary(65_536));
}

#[test]
fn a_chat_template_must_be_utf8() {
    assert_eq!(
        Gguf::valid()
            .kv_str("tokenizer.chat_template", b"\xff")
            .parse(),
        Err(GgufError::TemplateNotUtf8(1))
    );
}

#[test]
fn at_most_16_chat_templates() {
    let mut file = Gguf::valid().kv_str("tokenizer.chat_template", b"t");
    for n in 1..16 {
        file = file.kv_str(&format!("tokenizer.chat_template.n{n}"), b"t");
    }
    assert_eq!(code(file.clone().parse()), "accepted");
    let file = file.kv_str("tokenizer.chat_template.n16", b"t");
    assert_eq!(file.parse(), Err(GgufError::TemplateCountLimit(17)));
}

/// Each scalar value type id with a payload of its size (bool with byte 1).
const SCALARS: [(u32, &[u8]); 11] = [
    (0, &[1]),
    (1, &[1]),
    (2, &[1; 2]),
    (3, &[1; 2]),
    (4, &[1; 4]),
    (5, &[1; 4]),
    (6, &[1; 4]),
    (BOOL, &[1]),
    (10, &[1; 8]),
    (11, &[1; 8]),
    (12, &[1; 8]),
];

/// A chat template must be a string: the engine turns a scalar into template text ("42",
/// "true") and drops an array, so neither is the text the parser checked (architect Q377).
#[test]
fn a_chat_template_must_be_a_string() {
    for key in [
        "tokenizer.chat_template",
        "tokenizer.chat_template.tool_use",
    ] {
        let value = only_value(Gguf::valid().kv_str(key, b"{{x}}"));
        assert_eq!(value, Value::String(FileText("{{x}}".into())), "{key}");
        for (ty, payload) in SCALARS {
            assert_eq!(
                one(key.as_bytes(), ty, payload).parse(),
                Err(GgufError::TemplateNotString(1)),
                "{key} type {ty}"
            );
        }
        for payload in [
            array(U8, 1, &[1]),
            array(STRING, 1, &s(b"{{x}}")),
            array(U8, 0, &[]),
        ] {
            assert_eq!(
                one(key.as_bytes(), ARRAY, &payload).parse(),
                Err(GgufError::TemplateNotString(1)),
                "{key} {payload:?}"
            );
        }
        // Checked by type id before the value is read: these never reach their own checks.
        for (ty, payload) in [
            (13, Vec::new()),
            (ARRAY, array(ARRAY, 1, &[])),
            (BOOL, vec![2]),
            (ARRAY, array(U8, 1 << 40, &[])),
        ] {
            assert_eq!(
                one(key.as_bytes(), ty, &payload).parse(),
                Err(GgufError::TemplateNotString(1)),
                "{key} type {ty} {payload:?}"
            );
        }
    }
    assert_eq!(
        one(b"tokenizer.chat_template.", U32, &[1; 4]).parse(),
        Err(GgufError::TemplateNotString(1))
    );
    // Not template keys: any type is accepted.
    let allowed = [
        Gguf::valid(),
        one(
            b"tokenizer.chat_templates",
            ARRAY,
            &array(STRING, 1, &s(b"tool_use")),
        ),
        one(b"tokenizer.chat_templates", U32, &[1; 4]),
        one(b"Tokenizer.chat_template", U32, &[1; 4]),
        one(b"tokenizer.chat_template_x", U32, &[1; 4]),
    ];
    for file in allowed {
        assert_eq!(code(file.parse()), "accepted");
    }
}

/// The template count is checked on the key, before the value's type.
#[test]
fn the_template_count_is_checked_before_the_type() {
    let mut file = Gguf::valid();
    for n in 0..15 {
        file = file.kv_str(&format!("tokenizer.chat_template.n{n}"), b"t");
    }
    assert_eq!(
        file.clone()
            .kv(b"tokenizer.chat_template", U32, &[1; 4])
            .parse(),
        Err(GgufError::TemplateNotString(16))
    );
    let file = file.kv_str("tokenizer.chat_template", b"t");
    assert_eq!(
        file.kv(b"tokenizer.chat_template.n15", U32, &[1; 4])
            .parse(),
        Err(GgufError::TemplateCountLimit(17))
    );
}

#[test]
fn alignment_is_a_u32_power_of_two_from_8_to_65536() {
    for a in [8u32, 32, 65_536] {
        let mut file = Gguf::valid().kv_u32("general.alignment", a);
        file.alignment = u64::from(a);
        assert_eq!(file.parse().unwrap().alignment(), a);
    }
    for a in [0u32, 1, 2, 3, 4, 24, 131_072, u32::MAX] {
        let file = Gguf::valid().kv_u32("general.alignment", a);
        assert_eq!(file.parse(), Err(GgufError::BadAlignment(1)), "{a}");
    }
    let wrong_type = Gguf::valid().kv(b"general.alignment", U64, &32u64.to_le_bytes());
    assert_eq!(wrong_type.parse(), Err(GgufError::BadAlignment(1)));
}

#[test]
fn a_chat_template_holding_a_nul_is_refused() {
    for key in [
        "tokenizer.chat_template",
        "tokenizer.chat_template.tool_use",
    ] {
        for value in [&b"\0{{x}}"[..], b"{{x}}\0tail", b"{{x}}\0"] {
            assert_eq!(
                Gguf::valid().kv_str(key, value).parse(),
                Err(GgufError::TemplateHasNul(1)),
                "{key} {value:?}"
            );
        }
    }
    // Both not UTF-8 and holding a NUL: UTF-8 is checked first.
    assert_eq!(
        Gguf::valid()
            .kv_str("tokenizer.chat_template", b"\0\xff")
            .parse(),
        Err(GgufError::TemplateNotUtf8(1))
    );
}

#[test]
fn an_ordinary_string_holding_a_nul_is_summarized() {
    assert_eq!(
        only_value(one(b"k", STRING, &s(b"a\0b"))),
        Value::StringSummary(3)
    );
    // Not a template key: summarized, not refused.
    let other = Gguf::valid().kv_str("tokenizer.chat_templates", b"a\0");
    assert_eq!(only_value(other), Value::StringSummary(2));
}

const U16: u32 = 2;

#[test]
fn split_count_may_only_say_one_file() {
    let allowed = [
        one(b"split.count", U16, &0u16.to_le_bytes()),
        one(b"split.count", U16, &1u16.to_le_bytes()),
        one(b"split.count.x", U16, &2u16.to_le_bytes()),
        one(b"Split.count", U16, &2u16.to_le_bytes()),
        Gguf::valid(),
    ];
    for file in allowed {
        assert_eq!(code(file.parse()), "accepted");
    }
    let refused = [
        one(b"split.count", U16, &2u16.to_le_bytes()),
        one(b"split.count", U16, &u16::MAX.to_le_bytes()),
        one(b"split.count", U32, &1u32.to_le_bytes()),
        one(b"split.count", U32, &2u32.to_le_bytes()),
        one(b"split.count", STRING, &s(b"1")),
        one(b"split.count", ARRAY, &array(U16, 1, &1u16.to_le_bytes())),
    ];
    for file in refused {
        assert_eq!(file.parse(), Err(GgufError::SplitFile(1)));
    }
}
