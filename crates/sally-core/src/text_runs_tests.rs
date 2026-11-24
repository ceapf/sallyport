//! Unit tests of the run mark (`escape_runs_backslash_quoted`), its cut and its rows (RT-AG-04).
#![allow(clippy::unwrap_used)]

use super::*;
use proptest::prelude::*;

/// One unit of shown text and the count its mark gives (1 when unmarked), read by the test
/// alone: `\\`, `\"`, `\xNN`, `\u{H…}` or one character, then an optional `\{N}`.
fn units(shown: &str) -> Vec<(String, usize)> {
    let mut out = Vec::new();
    let mut rest = shown;
    while let Some(c) = rest.chars().next() {
        let len = if c != '\\' {
            c.len_utf8()
        } else {
            match rest.as_bytes().get(1) {
                Some(b'x') => 4,
                Some(b'u') => rest.find('}').unwrap() + 1,
                Some(b'\\' | b'"') => 2,
                other => panic!("an escape the escaper does not write: {other:?} in {shown}"),
            }
        };
        let unit = rest[..len].to_owned();
        rest = &rest[len..];
        let mut n = 1;
        if let Some(mark) = rest.strip_prefix("\\{") {
            let close = mark.find('}').unwrap();
            n = mark[..close].parse().unwrap();
            rest = &mark[close + 1..];
        }
        out.push((unit, n));
    }
    out
}

/// The bytes `shown` stands for, decoded by the test alone.
fn decode(shown: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for (unit, n) in units(shown) {
        let bytes = match unit.as_bytes() {
            [b'\\', b'x', ..] => vec![u8::from_str_radix(&unit[2..4], 16).unwrap()],
            [b'\\', b'u', ..] => {
                let c = char::from_u32(u32::from_str_radix(&unit[3..unit.len() - 1], 16).unwrap());
                c.unwrap().to_string().into_bytes()
            }
            [b'\\', b] => vec![*b],
            _ => unit.clone().into_bytes(),
        };
        for _ in 0..n {
            out.extend_from_slice(&bytes);
        }
    }
    out
}

fn marked(raw: &str) -> String {
    escape_runs_backslash_quoted(raw.as_bytes())
}

#[test]
fn a_run_of_sixteen_is_shown_whole_and_of_seventeen_is_marked() {
    assert_eq!(marked(&" ".repeat(16)), " ".repeat(16));
    assert_eq!(marked(&" ".repeat(17)), " \\{17}");
    assert_eq!(
        marked(&format!("ab{}c", " ".repeat(100_000))),
        "ab \\{100000}c"
    );
}

#[test]
fn a_run_is_marked_once_whole() {
    assert_eq!(marked(&"x".repeat(40)), "x\\{40}");
    assert_eq!(
        marked(&format!("{}{}", "a".repeat(20), "b".repeat(17))),
        "a\\{20}b\\{17}"
    );
}

#[test]
fn every_kind_of_unit_is_marked_in_its_escaped_form() {
    assert_eq!(marked(&"\\".repeat(17)), "\\\\\\{17}");
    assert_eq!(marked(&"\"".repeat(20)), "\\\"\\{20}");
    assert_eq!(marked(&"\0".repeat(40)), "\\x00\\{40}");
    assert_eq!(marked(&"\u{200b}".repeat(18)), "\\u{200b}\\{18}");
    assert_eq!(
        escape_runs_backslash_quoted(&[0x80; 20]),
        "\\x80\\{20}",
        "a byte that is not UTF-8 is a unit"
    );
    // A character and a byte that read alike are different units.
    let mut raw = "\u{80}".repeat(17).into_bytes();
    raw.extend([0x80; 17]);
    assert_eq!(
        escape_runs_backslash_quoted(&raw),
        "\\u{80}\\{17}\\x80\\{17}"
    );
}

#[test]
fn request_text_cannot_write_a_mark() {
    assert_eq!(marked("a\\{17}"), "a\\\\{17}");
    assert_eq!(units(&marked("a\\{17}")).iter().map(|u| u.1).max(), Some(1));
    // Below the mark, the text is the plain escaper's.
    assert_eq!(
        marked("ls -la \"x\"\n"),
        escape_backslash_quoted(b"ls -la \"x\"\n")
    );
}

#[test]
fn the_capped_form_keeps_whole_units_and_counts_what_it_shows() {
    let raw = format!("ab{}c\"", " ".repeat(1000));
    assert_eq!(
        escape_runs_capped(raw.as_bytes(), 100),
        ("ab \\{1000}c\\\"".to_owned(), raw.len())
    );
    // `ab \{1000}` is 10 bytes: one byte short of it keeps only `ab`.
    assert_eq!(escape_runs_capped(raw.as_bytes(), 9), ("ab".to_owned(), 2));
    assert_eq!(
        escape_runs_capped(raw.as_bytes(), 10),
        ("ab \\{1000}".to_owned(), 1002)
    );
    // An unmarked run is cut unit by unit.
    assert_eq!(escape_runs_capped(b"aaaab", 2), ("aa".to_owned(), 2));
    assert_eq!(escape_runs_capped(b"\"\"", 3), ("\\\"".to_owned(), 1));
    assert_eq!(escape_runs_capped(b"", 3), (String::new(), 0));
}

#[test]
fn a_line_holding_a_mark_is_refused_by_the_launch_gate() {
    assert_eq!(refused_escape(" \\{17}"), Some("\\{"));
}

#[test]
fn a_cut_never_parts_a_unit_from_its_mark() {
    let text = format!("ab{}cd", marked(&"\\".repeat(30)));
    // `ab` then `\\\{30}` (8 bytes) then `cd`.
    let unit_end = 2 + "\\\\\\{30}".len();
    for max in 0..=text.len() {
        let at = escape_boundary(&text, max);
        assert!(at <= max, "{max}");
        assert!(
            at <= 2 || at >= unit_end,
            "{max}: cut at {at} inside the marked unit"
        );
        if max >= unit_end {
            assert!(
                at >= unit_end,
                "{max}: the marked unit fits but is not kept"
            );
        }
    }
    assert_eq!(escape_boundary(" \\{17}", 2), 0);
    assert_eq!(escape_boundary(" \\{17}", 6), 6);
}

#[test]
fn a_mark_with_no_close_runs_to_the_end() {
    assert_eq!(unit_len(" \\{17", 0), 5);
    assert_eq!(escape_len("\\{17}x", 0), 5);
}

#[test]
fn rows_never_part_a_unit_and_put_together_are_the_text() {
    let text = format!(
        "run [\"marker-cmd\" \"{}\" \"tail\"]",
        marked(&" ".repeat(100 * 1024))
    );
    let rows = escaped_rows(&text, 20);
    assert_eq!(rows.concat(), text);
    assert!(
        rows.iter().all(|r| !r.is_empty() && r.len() <= 20),
        "{rows:?}"
    );
    assert!(rows.iter().any(|r| r.contains(" \\{102400}")), "{rows:?}");
    assert_eq!(escaped_rows("", 20), Vec::<&str>::new());
    assert_eq!(escaped_rows("abcdef", 3), ["abc", "def"]);
    assert_eq!(escaped_rows("abc", 3), ["abc"]);
    // A unit longer than the width is a row of its own.
    assert_eq!(escaped_rows("a\\u{10ffff}b", 4), ["a", "\\u{10ffff}", "b"]);
}

#[test]
fn the_longest_unit_is_the_longest_escape_with_the_largest_mark() {
    let unit = format!("\\u{{10ffff}}\\{{{}}}", usize::MAX);
    assert_eq!(unit.len(), LONGEST_UNIT);
    assert_eq!(unit_len(&unit, 0), LONGEST_UNIT);
}

proptest! {
    #[test]
    fn the_mark_is_lossless_and_leaves_no_long_run(
        raw in prop::collection::vec(
            prop_oneof![Just(b' '), Just(b'\\'), Just(b'"'), Just(0x80u8), Just(b'a'), any::<u8>()],
            0..200,
        ),
        stretch in 0usize..40,
    ) {
        let mut raw = raw;
        if let Some(&b) = raw.first() {
            raw.extend(std::iter::repeat_n(b, stretch));
        }
        let shown = escape_runs_backslash_quoted(&raw);
        prop_assert_eq!(decode(&shown), raw);
        let u = units(&shown);
        for pair in u.windows(2) {
            prop_assert!(pair[0].0 != pair[1].0 || (pair[0].1 == 1 && pair[1].1 == 1));
        }
        let mut same = 0usize;
        for (i, (unit, n)) in u.iter().enumerate() {
            prop_assert!(*n == 1 || *n > RUN_SHOWN_WHOLE);
            same = if i > 0 && u[i - 1].0 == *unit { same + 1 } else { 1 };
            prop_assert!(same <= RUN_SHOWN_WHOLE, "an unmarked run over the bound: {}", shown);
        }
    }

    #[test]
    fn rows_of_marked_text_keep_every_unit_whole(
        raw in prop::collection::vec(any::<u8>(), 0..300),
        width in LONGEST_UNIT..120,
    ) {
        let shown = escape_runs_backslash_quoted(&raw);
        let rows = escaped_rows(&shown, width);
        prop_assert_eq!(rows.concat(), shown.clone());
        let mut at = 0;
        for r in &rows {
            prop_assert!(!r.is_empty() && r.len() <= width);
            at += r.len();
            prop_assert_eq!(escape_boundary(&shown, at), at, "a row ends inside a unit");
        }
    }
}
