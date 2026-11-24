//! Tests of what a launch may show (RT-MAN-05): the refused class, the reader of escaped lines and
//! the quoted path.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use proptest::prelude::*;

use super::*;

/// Whether `raw` holds a refused character or a byte that is not UTF-8.
fn raw_refused(raw: &[u8]) -> bool {
    raw.utf8_chunks()
        .any(|c| !c.invalid().is_empty() || c.valid().chars().any(is_refused))
}

fn ch(n: u32) -> char {
    char::from_u32(n).unwrap()
}

/// Whether std's classes or the noncharacter rule take `n`, apart from the tables.
fn outside_tables(n: u32) -> bool {
    let c = ch(n);
    c.is_control()
        || (c.is_whitespace() && c != ' ')
        || (0xfdd0..=0xfdef).contains(&n)
        || n & 0xfffe == 0xfffe
}

#[test]
fn each_table_sums_to_its_files_total() {
    let total = |t: &[(u32, u32)]| t.iter().map(|&(lo, hi)| hi - lo + 1).sum::<u32>();
    assert_eq!(total(DEFAULT_IGNORABLE), 4174);
    assert_eq!(total(FORMAT), 170);
}

/// Sorted, disjoint and merged: each range starts at least two past the end of the one before.
#[test]
fn each_table_is_sorted_disjoint_and_merged() {
    for t in [DEFAULT_IGNORABLE, FORMAT] {
        for w in t.windows(2) {
            assert!(w[0].0 <= w[0].1 && w[0].1 + 1 < w[1].0, "{w:x?}");
        }
    }
}

/// Both ends of every range refuse; the code point on each side is outside that table, and
/// refuses only when the other table or std's classes take it.
#[test]
fn every_range_end_refuses_and_its_neighbours_follow_the_other_rules() {
    for (t, other) in [(DEFAULT_IGNORABLE, FORMAT), (FORMAT, DEFAULT_IGNORABLE)] {
        for &(lo, hi) in t {
            for end in [lo, hi] {
                assert!(in_table(t, ch(end)) && is_refused(ch(end)), "{end:x}");
            }
            for n in [lo - 1, hi + 1] {
                let Some(c) = char::from_u32(n) else { continue };
                assert!(!in_table(t, c), "{n:x}");
                assert_eq!(
                    is_refused(c),
                    in_table(other, c) || outside_tables(n),
                    "{n:x}"
                );
            }
        }
    }
}

#[test]
fn named_characters_refuse_or_pass() {
    for n in [
        0x202e, 0x200b, 0x200c, 0x00ad, 0xfeff, 0x00a0, 0x3000, 0x2028, 0x0085, 0xe0001, 0x1b,
        0x7f, 0x09, 0x0a, 0xfdd0, 0xfdef, 0xfffe, 0xffff, 0x1fffe, 0x10ffff, 0xfff9, 0x13430,
    ] {
        assert!(is_refused(ch(n)), "{n:x} refuses");
    }
    for n in [
        0x20, 0x41, 0x7e, 0xe9, 0x4e2d, 0x0301, 0x1f600, 0xe000, 0xfdcf, 0xfdf0, 0xfffd, 0x1fffd,
        0x2800, 0xfffc,
    ] {
        assert!(!is_refused(ch(n)), "{n:x} passes");
    }
}

#[test]
fn the_reader_passes_every_escape_of_a_shown_character() {
    for line in [
        "",
        "plain text, (at /w).",
        "a\\\\b",
        "say \\\"hi\\\"",
        "\\x22 and \\x60 and \\x20 and \\x7e",
        "caf\\u{e9} \\u{4e2d} \\u{1f600} \\u{e000} \\u{10fffd} \\u{0041}",
    ] {
        assert_eq!(refused_escape(line), None, "{line}");
    }
}

#[test]
fn the_reader_names_the_first_refused_escape() {
    for (line, first) in [
        ("a\\u{202e}b \\u{200b}", "\\u{202e}"),
        ("ok \\u{e9} then \\x1b[2J", "\\x1b"),
        ("\\x7f", "\\x7f"),
        ("\\x1f", "\\x1f"),
        ("byte \\xff", "\\xff"),
        ("byte \\x80", "\\x80"),
        ("\\u{a0}", "\\u{a0}"),
        ("\\u{fffe}", "\\u{fffe}"),
        ("\\u{e0fff}x", "\\u{e0fff}"),
    ] {
        assert_eq!(refused_escape(line), Some(first), "{line}");
    }
}

/// Fails closed: a backslash that starts no escape an escaper writes refuses.
#[test]
fn the_reader_refuses_what_no_escaper_writes() {
    for (line, first) in [
        ("end \\", "\\"),
        ("\\n", "\\n"),
        ("\\t", "\\t"),
        ("\\x", "\\x"),
        ("\\x4", "\\x4"),
        ("\\x4g", "\\x4g"),
        ("\\x4A", "\\x4A"),
        ("\\X41", "\\X"),
        ("\\u", "\\u"),
        ("\\u41", "\\u"),
        ("\\u{}", "\\u{}"),
        ("\\u{e9", "\\u{e9"),
        ("\\u{E9}", "\\u{E9}"),
        ("\\u{d800}", "\\u{d800}"),
        ("\\u{110000}", "\\u{110000}"),
        ("\\u{0000041}", "\\u{0000041"),
        ("\\u{-1}", "\\u{-1}"),
    ] {
        assert_eq!(refused_escape(line), Some(first), "{line}");
    }
}

#[test]
fn a_quoted_path_is_its_bytes_escaped_between_quotes() {
    assert_eq!(quoted_path(b"/home/u/p"), "\"/home/u/p\"");
    assert_eq!(
        quoted_path(b"/h/a \"b\"\\c, d (at e)"),
        "\"/h/a \\\"b\\\"\\\\c, d (at e)\""
    );
    assert_eq!(quoted_path("/h/caf\u{e9}".as_bytes()), "\"/h/caf\\u{e9}\"");
    assert_eq!(quoted_path(b"/h/\xff\xfe"), "\"/h/\\xff\\xfe\"");
    assert_eq!(refused_escape(&quoted_path(b"/h/\xff")), Some("\\xff"));
}

proptest! {
    #[test]
    fn the_reader_never_panics(s in any::<String>()) {
        let _ = refused_escape(&s);
    }

    #[test]
    fn the_reader_refuses_an_escape_exactly_when_the_text_held_a_refused_character(
        raw in proptest::collection::vec(any::<u8>(), 0..64),
        text in any::<String>(),
    ) {
        for bytes in [raw.as_slice(), text.as_bytes()] {
            let refused = raw_refused(bytes);
            prop_assert_eq!(refused_escape(&escape(bytes)).is_some(), refused);
            prop_assert_eq!(refused_escape(&escape_backslash_quoted(bytes)).is_some(), refused);
            prop_assert_eq!(refused_escape(&quoted_path(bytes)).is_some(), refused);
        }
    }

    /// A cut never leaves an escape the reader cannot read: arguments with nothing refused read
    /// clean at every bound, and uncut the reader refuses exactly when one held a refused character.
    #[test]
    fn quoted_arguments_read_alike_cut_or_whole(
        list in proptest::collection::vec(any::<String>(), 0..5),
        max in 0usize..300,
    ) {
        let refused = list.iter().any(|a| raw_refused(a.as_bytes()));
        let (cut, _) = quoted_args_capped(&list, max);
        if !refused {
            prop_assert_eq!(refused_escape(&cut), None);
        }
        let (whole, at) = quoted_args_capped(&list, usize::MAX);
        prop_assert!(at.is_none());
        prop_assert_eq!(refused_escape(&whole).is_some(), refused);
    }
}
