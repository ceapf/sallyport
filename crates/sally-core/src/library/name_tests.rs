#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use super::*;

/// What detect allows, up to 255 bytes, with no control character.
#[test]
fn names_are_checked() {
    let longest = format!("{}.gguf", "x".repeat(250));
    assert_eq!(longest.len(), 255);
    for good in [
        longest.as_str(),
        "m.gguf",
        "modèle.gguf",
        "a\u{202e}b.gguf",
        "z\u{200b}.gguf",
    ] {
        assert!(ok(good), "{good:?}");
        assert_eq!(SourceName::checked(good).unwrap().as_raw_str(), good);
    }
    let too_long = format!("x{longest}");
    for bad in [
        too_long.as_str(),
        "m.bin",
        "a/m.gguf",
        "a\x1b[31m.gguf",
        "a\nb.gguf",
        "a\x7f.gguf",
        "a\u{85}.gguf",
        "\t.gguf",
    ] {
        assert!(!ok(bad), "{bad:?}");
        assert!(SourceName::checked(bad).is_none(), "{bad:?}");
    }
}

/// Display and Debug show printable ASCII only: bidi, zero-width and other non-ASCII
/// characters are escaped.
#[test]
fn display_and_debug_escape() {
    let name = SourceName::checked("a\u{202e}b\u{200b}é.gguf").unwrap();
    for text in [name.to_string(), format!("{name:?}")] {
        assert!(text.bytes().all(|b| (0x20..0x7f).contains(&b)), "{text}");
        assert!(text.contains("a\\u{202e}b"), "{text}");
        assert!(text.contains(".gguf"), "{text}");
    }
    assert_eq!(SourceName::checked("m.gguf").unwrap().to_string(), "m.gguf");
    assert_eq!(
        format!("{:?}", SourceName::checked("m.gguf").unwrap()),
        "SourceName(m.gguf)"
    );
}
