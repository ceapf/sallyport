//! Unit tests of the escapers and cuts in `text.rs`.
#![allow(clippy::unwrap_used)]

use super::*;
use proptest::prelude::*;

fn args(list: &[&str]) -> Vec<String> {
    list.iter().map(|a| (*a).to_owned()).collect()
}

/// A cut inside argument `at` of `of`, `bytes` not shown.
fn inside(at: usize, of: usize, bytes: usize) -> Option<ArgsCut> {
    Some(ArgsCut {
        inside: true,
        at,
        of,
        bytes,
    })
}

/// A cut before argument `at` of `of`, `bytes` not shown.
fn before(at: usize, of: usize, bytes: usize) -> Option<ArgsCut> {
    Some(ArgsCut {
        inside: false,
        at,
        of,
        bytes,
    })
}

/// Every argument is quoted and escaped, an empty one too, and a whole list is not cut.
#[test]
fn quoted_args_are_each_quoted_escaped_and_joined_by_one_space() {
    let (text, cut) = quoted_args_capped(&args(&["run", "", "a\"b", "\u{1b}[2J", "\u{e9}"]), 200);
    assert_eq!(text, r#""run" "" "a\"b" "\x1b[2J" "\u{e9}""#);
    assert_eq!(cut, None);
    assert_eq!(quoted_args_capped(&[], 0), (String::new(), None));
}

/// The limit is inclusive: a rendering of exactly `max` bytes is whole, one byte more is cut,
/// and the cut argument keeps its closing quote within `max`.
#[test]
fn quoted_args_fit_at_exactly_max_and_are_cut_one_byte_later() {
    let a = "x".repeat(198);
    let (text, cut) = quoted_args_capped(&args(&[&a]), 200);
    assert_eq!((text.len(), cut), (200, None));
    let b = "x".repeat(199);
    let (text, cut) = quoted_args_capped(&args(&[&b]), 200);
    assert_eq!(text, format!("\"{}\"", "x".repeat(198)));
    assert_eq!(cut, inside(1, 1, 1));
}

/// An argument starts only when the space, both quotes and its first escape fit; the count
/// covers the argument and every later one, in input bytes.
#[test]
fn an_argument_starts_only_when_its_quotes_and_first_escape_fit() {
    // "aa" = 4 bytes; then " " + "\"" + "\\x1b" + "\"" needs 7 more.
    let list = args(&["aa", "\u{1b}b", "cd"]);
    assert_eq!(
        quoted_args_capped(&list, 10),
        ("\"aa\"".to_owned(), before(2, 3, 4))
    );
    assert_eq!(
        quoted_args_capped(&list, 11),
        ("\"aa\" \"\\x1b\"".to_owned(), inside(2, 3, 3))
    );
    // An empty argument needs only its quotes; a cut one never shows as "".
    let list = args(&["aa", "", "b"]);
    assert_eq!(
        quoted_args_capped(&list, 7),
        ("\"aa\" \"\"".to_owned(), before(3, 3, 1))
    );
    assert_eq!(
        quoted_args_capped(&list, 6),
        ("\"aa\"".to_owned(), before(2, 3, 1))
    );
    let list = args(&["aa", "b"]);
    assert_eq!(
        quoted_args_capped(&list, 7),
        ("\"aa\"".to_owned(), before(2, 2, 1))
    );
    assert_eq!(
        quoted_args_capped(&list, 8),
        ("\"aa\" \"b\"".to_owned(), None)
    );
    // A trailing empty argument that does not fit is named, with 0 bytes.
    assert_eq!(
        quoted_args_capped(&args(&["aa", ""]), 6),
        ("\"aa\"".to_owned(), before(2, 2, 0))
    );
}

/// A cut inside the third argument and a fourth argument that did not start show the same
/// text, and the facts tell them apart.
#[test]
fn a_cut_inside_an_argument_and_one_before_the_next_are_told_apart() {
    let three = args(&["sh", "-c", "PPPP\u{1b}rest"]);
    let four = args(&["sh", "-c", "PPPP", "\u{1b}rest"]);
    let (a, cut_a) = quoted_args_capped(&three, 19);
    let (b, cut_b) = quoted_args_capped(&four, 19);
    assert_eq!(a, "\"sh\" \"-c\" \"PPPP\"");
    assert_eq!(a, b);
    assert_eq!(cut_a, inside(3, 3, 5));
    assert_eq!(cut_b, before(4, 4, 5));
}

/// A backtick is written `\x60`, one piece: a cut never splits it, and it counts one input
/// byte.
#[test]
fn a_backtick_is_written_hex_and_never_split() {
    let list = args(&["a`b"]);
    assert_eq!(
        quoted_args_capped(&list, 200),
        ("\"a\\x60b\"".to_owned(), None)
    );
    for max in [4, 5, 6] {
        assert_eq!(
            quoted_args_capped(&list, max),
            ("\"a\"".to_owned(), inside(1, 1, 2)),
            "{max}"
        );
    }
    assert_eq!(
        quoted_args_capped(&list, 7),
        ("\"a\\x60\"".to_owned(), inside(1, 1, 1))
    );
    // A backtick first: the argument starts only when all of `\x60` fits.
    assert_eq!(
        quoted_args_capped(&args(&["`"]), 5),
        (String::new(), before(1, 1, 1))
    );
    assert_eq!(
        quoted_args_capped(&args(&["`"]), 6),
        ("\"\\x60\"".to_owned(), None)
    );
}

/// A cut never splits an escape, and the count is of input bytes, not escaped ones.
#[test]
fn a_cut_never_splits_an_escape_and_counts_input_bytes() {
    let list = args(&["\u{e9}\u{e9}\u{e9}"]);
    // "\u{e9}" is 6 bytes: two fit in 1 + 12 + 1 = 14, not three.
    assert_eq!(
        quoted_args_capped(&list, 15),
        ("\"\\u{e9}\\u{e9}\"".to_owned(), inside(1, 1, 2))
    );
    assert_eq!(
        quoted_args_capped(&list, 20),
        ("\"\\u{e9}\\u{e9}\\u{e9}\"".to_owned(), None)
    );
}

/// A cut escaped text names the bytes cut and the SHA-256 of the whole text.
#[test]
fn a_cut_escaped_text_names_the_rest_and_the_whole_texts_digest() {
    let text = "abcdefghij";
    let mut sha = String::new();
    for b in Sha256::digest(text.as_bytes()) {
        let _ = write!(sha, "{b:02x}");
    }
    assert_eq!(
        cut_escaped(text, 4),
        (format!("abcd... (+6 bytes, sha256 {sha})"), true)
    );
    assert_eq!(cut_escaped(text, 10), (text.to_owned(), false));
}

/// A character outside ASCII is kept or cut whole: the shown text is never emptied by a cut
/// inside it. Literal pieces are meant to be printable ASCII (`Piece::Literal`), but they are
/// never escaped, so the cut does not rely on that (a `\` in a literal is still read as an
/// escape).
#[test]
fn a_cut_never_falls_inside_a_character() {
    let (shown, cut) = cut_escaped("aé b", 2);
    assert!(cut);
    assert!(shown.starts_with("a... (+4 bytes, sha256 "), "{shown}");
    let (shown, _) = cut_escaped("aé b", 3);
    assert!(shown.starts_with("aé... (+2 bytes, sha256 "), "{shown}");
}

/// A styled text says it was cut only past its bound, in every style that reports a cut
/// from the raw length.
#[test]
fn styled_says_cut_only_past_the_bound() {
    for style in [Style::HexCounted { max: 4 }, Style::Plain { max: 4 }] {
        assert!(!styled("abcd", style).1, "{style:?}");
        assert!(styled("abcde", style).1, "{style:?}");
    }
}

fn printable(s: &str) -> bool {
    s.bytes().all(|b| (b' '..=b'~').contains(&b))
}

#[test]
fn each_class_is_escaped_as_specified() {
    assert_eq!(escape(b"plain text 1+1=2"), "plain text 1+1=2");
    assert_eq!(escape(b"a\\b"), "a\\\\b");
    assert_eq!(
        escape(b"\x1b[2J\r\n\t\x00\x7f"),
        "\\x1b[2J\\x0d\\x0a\\x09\\x00\\x7f"
    );
    assert_eq!(
        escape("é\u{202e}😀".as_bytes()),
        "\\u{e9}\\u{202e}\\u{1f600}"
    );
    assert_eq!(escape(b"\xff\xc3x\xe2\x82"), "\\xff\\xc3x\\xe2\\x82");
    assert_eq!(escape(b""), "");
}

#[test]
fn a_cut_never_splits_an_escape_and_names_the_bytes_dropped() {
    // "ab" + é (2 bytes, 6 escaped) + "c": 9 bytes escaped.
    let raw = "abéc".as_bytes();
    assert_eq!(escape_capped(raw, 100), "ab\\u{e9}c");
    assert_eq!(escape_capped(raw, 9), "ab\\u{e9}c");
    assert_eq!(escape_capped(raw, 8), "ab\\u{e9}...(+1 bytes)");
    assert_eq!(escape_capped(raw, 7), "ab...(+3 bytes)");
    assert_eq!(escape_capped(raw, 2), "ab...(+3 bytes)");
    assert_eq!(escape_capped(raw, 1), "a...(+4 bytes)");
    assert_eq!(escape_capped(raw, 0), "...(+5 bytes)");
    assert_eq!(escape_capped(b"", 0), "");
    assert_eq!(escape_capped(b"\xff\xfe", 4), "\\xff...(+1 bytes)");
}

#[test]
fn the_quoted_form_escapes_quotes_before_the_cut() {
    assert_eq!(escape_quoted_capped(b"a\"b\\c", 100), "a\\x22b\\\\c");
    assert_eq!(
        escape_capped(b"a\"b", 100),
        "a\"b",
        "the plain form keeps quotes"
    );
    // The cut measures the escaped quote (4 bytes), not the raw one.
    assert_eq!(escape_quoted_capped(b"a\"b", 6), "a\\x22b");
    assert_eq!(escape_quoted_capped(b"a\"b", 5), "a\\x22...(+1 bytes)");
    assert_eq!(escape_quoted_capped(b"a\"b", 4), "a...(+2 bytes)");
    let all = "\"".repeat(100);
    let cut = escape_quoted_capped(all.as_bytes(), 40);
    assert_eq!(cut, format!("{}...(+90 bytes)", "\\x22".repeat(10)));
}

#[test]
fn the_hex_format_cuts_input_bytes_and_says_whether_it_cut() {
    assert_eq!(
        hex_capped(b"ok.test:443", 256),
        ("ok.test:443".into(), false)
    );
    assert_eq!(
        hex_capped("a\"b\\c\x00\x1f\x7f\u{ff}~ ".as_bytes(), 256).0,
        "a\\x22b\\x5cc\\x00\\x1f\\x7f\\xc3\\xbf~ "
    );
    assert_eq!(hex_capped(b"abc", 3), ("abc".into(), false));
    assert_eq!(hex_capped(b"abcd", 3), ("abc".into(), true));
    assert_eq!(hex_capped(b"\x00\x01", 1), ("\\x00".into(), true));
    assert_eq!(hex_capped(b"", 0), (String::new(), false));
}

#[test]
fn the_counted_hex_format_names_the_bytes_left_out() {
    assert_eq!(hex_counted(b"tools/list", 64), "tools/list");
    assert_eq!(hex_counted(b"abc", 3), "abc");
    assert_eq!(hex_counted(b"abcde", 3), "abc\u{2026}(+2)");
    assert_eq!(hex_counted(b"\"\\", 1), "\\x22\u{2026}(+1)");
}

#[test]
fn the_plain_format_cuts_at_a_character_boundary_without_escaping() {
    assert_eq!(plain_capped("short", 10), "short");
    assert_eq!(plain_capped("abcdef", 6), "abcdef");
    assert_eq!(plain_capped("abcdef", 4), "abcd\u{2026}");
    // é is two bytes: a cut at 2 would split it, so it falls back to 1.
    assert_eq!(plain_capped("aéz", 2), "a\u{2026}");
    assert_eq!(plain_capped("a\x1b[2J", 10), "a\x1b[2J", "no escape");
}

#[test]
fn the_backslash_quoted_form_writes_a_quote_as_backslash_quote() {
    assert_eq!(escape_backslash_quoted(b"a\"b\\c"), "a\\\"b\\\\c");
    assert_eq!(
        escape_backslash_quoted("\u{202e}\x1b".as_bytes()),
        "\\u{202e}\\x1b"
    );
    assert_eq!(escape_backslash_quoted(b""), "");
}

#[test]
fn an_escaped_text_is_cut_outside_an_escape_with_its_hash() {
    assert_eq!(cut_escaped("short", 10), ("short".into(), false));
    let text = "ab\\u{e9}c\\x00d";
    let sha = sha256_hex(text.as_bytes());
    assert_eq!(
        cut_escaped(text, 5),
        (format!("ab... (+12 bytes, sha256 {sha})"), true)
    );
    assert_eq!(
        cut_escaped(text, 8),
        (format!("ab\\u{{e9}}... (+6 bytes, sha256 {sha})"), true)
    );
    assert_eq!(
        cut_escaped(text, 12),
        (format!("ab\\u{{e9}}c... (+5 bytes, sha256 {sha})"), true)
    );
    assert_eq!(
        cut_escaped("a\\\\b", 2),
        (
            format!("a... (+3 bytes, sha256 {})", sha256_hex(b"a\\\\b")),
            true
        )
    );
}

#[test]
fn a_style_picks_its_format() {
    let raw = "a\"b\u{e9}cdef";
    assert_eq!(
        styled(raw, Style::Hex { max: 4 }),
        ("a\\x22b\\xc3".into(), true)
    );
    assert_eq!(
        styled(raw, Style::HexCounted { max: 4 }),
        ("a\\x22b\\xc3\u{2026}(+5)".into(), true)
    );
    assert_eq!(
        styled(
            raw,
            Style::Text {
                max: 100,
                quote: Quote::None
            }
        ),
        ("a\"b\\u{e9}cdef".into(), false)
    );
    assert_eq!(
        styled(
            raw,
            Style::Text {
                max: 100,
                quote: Quote::Hex
            }
        ),
        ("a\\x22b\\u{e9}cdef".into(), false)
    );
    assert_eq!(
        styled(
            raw,
            Style::Text {
                max: 100,
                quote: Quote::Backslash
            }
        ),
        ("a\\\"b\\u{e9}cdef".into(), false)
    );
    assert_eq!(
        styled(
            raw,
            Style::Text {
                max: 3,
                quote: Quote::None
            }
        ),
        ("a\"b...(+6 bytes)".into(), true)
    );
    assert_eq!(
        styled(raw, Style::Plain { max: 4 }),
        ("a\"b\u{2026}".into(), true)
    );
    assert_eq!(styled("ab", Style::Plain { max: 4 }), ("ab".into(), false));
}

/// The whole of `raw` through one [`StreamEscaper`], in chunks cut at `cuts`.
fn streamed(raw: &[u8], cuts: &[usize]) -> String {
    let mut e = StreamEscaper::default();
    let mut out = String::new();
    let mut at = 0;
    for &c in cuts {
        let c = c.clamp(at, raw.len());
        out.push_str(&e.push(&raw[at..c]));
        assert!(e.held() <= 3, "carry {}", e.held());
        at = c;
    }
    out.push_str(&e.push(&raw[at..]));
    out.push_str(&e.finish());
    out
}

#[test]
fn the_stream_form_keeps_newlines_and_escapes_the_rest() {
    let one = |raw: &[u8]| streamed(raw, &[]);
    assert_eq!(one(b"line one\nline two\n"), "line one\nline two\n");
    assert_eq!(one(b"a\\b"), "a\\\\b");
    assert_eq!(one(b"\r\t\x00\x7f\x1b[2J"), "\\x0d\\x09\\x00\\x7f\\x1b[2J");
    assert_eq!(one(b"\x1b]52;c;eA==\x07"), "\\x1b]52;c;eA==\\x07");
    assert_eq!(one("\u{9b}\u{202e}é".as_bytes()), "\\u{9b}\\u{202e}\\u{e9}");
    assert_eq!(one(b"\x9b\xff"), "\\x9b\\xff");
    assert_eq!(one(b""), "");
}

#[test]
fn a_character_split_across_chunks_is_carried_whole() {
    let smile = "😀".as_bytes();
    for cut in 0..=smile.len() {
        assert_eq!(streamed(smile, &[cut]), "\\u{1f600}", "cut at {cut}");
    }
    let mut e = StreamEscaper::default();
    assert_eq!(e.push(&smile[..3]), "");
    assert_eq!(e.held(), 3);
    assert_eq!(e.push(&smile[3..]), "\\u{1f600}");
    assert_eq!(e.held(), 0);
}

#[test]
fn a_prefix_left_at_the_end_or_broken_by_the_next_byte_is_escaped_bytewise() {
    let mut e = StreamEscaper::default();
    assert_eq!(e.push(b"x\xe2\x82"), "x");
    assert_eq!(e.finish(), "\\xe2\\x82");
    let mut e = StreamEscaper::default();
    assert_eq!(e.push(b"\xe2\x82"), "");
    assert_eq!(e.push(b"A"), "\\xe2\\x82A");
    assert_eq!(e.finish(), "");
}

proptest! {
    /// Within the bound always, and no backtick; whole exactly when the full rendering fits.
    /// A cut inside argument K ends in its closing quote, is the full rendering's start but
    /// for that quote, and leaves at least one byte unshown; a cut before argument K is the
    /// whole rendering of arguments 1 to K-1. K is at most N, and the count at most the input.
    #[test]
    fn quoted_args_stay_within_the_bound_and_cut_only_when_needed(
        list in proptest::collection::vec(
            proptest::collection::vec(prop_oneof![Just(b'`'), any::<u8>()], 0..12),
            0..6,
        ),
        max in 0usize..80,
    ) {
        let list: Vec<String> =
            list.iter().map(|a| String::from_utf8_lossy(a).into_owned()).collect();
        let (whole, none) = quoted_args_capped(&list, usize::MAX);
        prop_assert_eq!(none, None);
        prop_assert!(!whole.contains('`'));
        let (out, cut) = quoted_args_capped(&list, max);
        prop_assert!(out.len() <= max);
        prop_assert_eq!(cut.is_none(), whole.len() <= max);
        let total: usize = list.iter().map(String::len).sum();
        match cut {
            None => prop_assert_eq!(&out, &whole),
            Some(c) => {
                prop_assert!(c.at >= 1 && c.at <= c.of && c.of == list.len());
                prop_assert!(c.bytes <= total);
                if c.inside {
                    prop_assert!(c.bytes >= 1);
                    prop_assert!(out.ends_with('"'));
                    let stem = out.get(..out.len().saturating_sub(1)).unwrap_or_default();
                    prop_assert!(whole.starts_with(stem), "{out:?} / {whole:?}");
                } else {
                    let head = list.get(..c.at.saturating_sub(1)).unwrap_or_default();
                    prop_assert_eq!(&out, &quoted_args_capped(head, usize::MAX).0);
                }
            }
        }
    }

    #[test]
    fn the_stream_form_is_printable_or_newline_and_chunking_free(
        raw in proptest::collection::vec(any::<u8>(), 0..256),
        cuts in proptest::collection::vec(0usize..256, 0..8),
    ) {
        let mut cuts = cuts;
        cuts.sort_unstable();
        let whole = streamed(&raw, &[]);
        prop_assert!(whole.bytes().all(|b| b == b'\n' || (b' '..=b'~').contains(&b)));
        prop_assert_eq!(whole.matches('\n').count(), raw.iter().filter(|&&b| b == b'\n').count());
        prop_assert_eq!(streamed(&raw, &cuts), whole.clone());
        if !raw.contains(&b'\n') {
            prop_assert_eq!(whole, escape(&raw), "the Q50 alphabet plus newline only");
        }
    }

    /// Real characters, most of them several bytes, so cuts land inside them.
    #[test]
    fn characters_cut_anywhere_come_out_whole(
        chars in proptest::collection::vec(any::<char>(), 0..48),
        cuts in proptest::collection::vec(0usize..200, 0..8),
    ) {
        let raw: String = chars.into_iter().collect();
        let mut cuts = cuts;
        cuts.sort_unstable();
        let whole = streamed(raw.as_bytes(), &[]);
        prop_assert_eq!(streamed(raw.as_bytes(), &cuts), whole.clone());
        if !raw.contains('\n') {
            prop_assert_eq!(whole, escape(raw.as_bytes()));
        }
    }

    #[test]
    fn any_bytes_become_printable_ascii(raw in proptest::collection::vec(any::<u8>(), 0..256)) {
        let e = escape(&raw);
        prop_assert!(printable(&e), "{e:?}");
    }

    #[test]
    fn every_cut_is_a_prefix_on_an_escape_boundary(
        raw in proptest::collection::vec(any::<u8>(), 0..64),
        max in 0usize..400,
    ) {
        let full = escape(&raw);
        let cut = escape_capped(&raw, max);
        prop_assert!(printable(&cut));
        if full.len() <= max {
            prop_assert_eq!(&cut, &full);
        } else {
            let (body, tail) = cut.split_at(cut.rfind("...(+").unwrap());
            prop_assert!(body.len() <= max);
            prop_assert!(full.starts_with(body));
            // On a boundary: the escape of some prefix of the input is exactly `body`.
            let n: usize = tail
                .trim_start_matches("...(+")
                .trim_end_matches(" bytes)")
                .parse()
                .unwrap();
            prop_assert!(n >= 1 && n <= raw.len());
            let kept = raw.len() - n;
            prop_assert_eq!(escape(&raw[..kept]), body);
        }
    }

    #[test]
    fn the_quoted_form_has_no_quote_and_keeps_its_cap(
        raw in proptest::collection::vec(any::<u8>(), 0..64),
        max in 0usize..400,
    ) {
        let cut = escape_quoted_capped(&raw, max);
        prop_assert!(printable(&cut) && !cut.contains('"'), "{cut:?}");
        let body = cut.rfind("...(+").map_or(cut.as_str(), |i| &cut[..i]);
        prop_assert!(body.len() <= max);
        if !raw.contains(&b'"') {
            prop_assert_eq!(&cut, &escape_capped(&raw, max));
        }
    }
}
