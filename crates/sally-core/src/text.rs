//! Neutralizing untrusted text for a terminal or a log line (architect rulings Q43, Q50, Q56).
//!
//! [`escape`] turns any bytes into printable ASCII: printable ASCII stays as it is, `\` becomes
//! `\\`, every other ASCII byte (controls, DEL) and every byte that is not valid UTF-8 becomes
//! `\xNN`, and every other character becomes `\u{…}`. No escape sequence of a terminal, no line
//! break and no bidirectional control survives. [`escape_capped`] does the same within a size
//! bound and names what it cut; it never cuts inside an escape. [`escape_quoted_capped`] also
//! escapes `"`, for a value written between quotes. [`StreamEscaper`] is the line-mode form
//! (architect Q100): the same alphabet plus `\n`, for output that arrives in chunks.
//!
//! Every cut and escape of sandbox-chosen audit text lives here too (architect Q276, Q288), as
//! the closed set [`Style`]: the hex formats ([`hex_capped`], [`hex_counted`]), the text format
//! above, and the plain cut ([`plain_capped`]); plus the approval action text's
//! [`escape_backslash_quoted`] and [`cut_escaped`]. An audit entry declares such text raw and
//! the writer masks it whole before [`styled`] cuts and escapes it.

use std::fmt::Write as _;

use sha2::{Digest, Sha256};

/// `raw` as printable ASCII.
#[must_use]
pub fn escape(raw: &[u8]) -> String {
    let mut out = String::with_capacity(raw.len());
    for piece in pieces(raw, Quote::None) {
        out.push_str(&piece.text);
    }
    out
}

/// `raw` as printable ASCII, at most `max` bytes of escaped text. When the input does not fit,
/// the text stops before the first escape that would pass `max` and `...(+N bytes)` follows,
/// where `N` is the count of input bytes not shown.
#[must_use]
pub fn escape_capped(raw: &[u8], max: usize) -> String {
    capped(raw, max, Quote::None).0
}

/// [`escape_capped`] for a value written between double quotes: `"` becomes `\x22` too, and the
/// cut measures that escaped form.
#[must_use]
pub fn escape_quoted_capped(raw: &[u8], max: usize) -> String {
    capped(raw, max, Quote::Hex).0
}

/// [`escape`] with `"` written as `\"`: one quoted value of a text whose quotes are `"…"`, as
/// the approval action text writes them. Uncut: the assembled text is cut by [`cut_escaped`].
#[must_use]
pub fn escape_backslash_quoted(raw: &[u8]) -> String {
    let mut out = String::with_capacity(raw.len());
    for piece in pieces(raw, Quote::Backslash) {
        out.push_str(&piece.text);
    }
    out
}

/// `args` each written `"…"` by [`escape_backslash_quoted`] and joined by one space, in at most
/// `max` bytes (architect Q713, the launch summary's command line). Built left to right, never
/// cutting inside an escape: an argument starts only when the space before it, both its quotes and
/// its first escape fit, and an argument cut short still gets its closing quote. Returns the text
/// and, when it was cut, the count of input bytes of the arguments not shown.
#[must_use]
pub fn quoted_args_capped(args: &[String], max: usize) -> (String, Option<usize>) {
    let mut out = String::new();
    for (i, arg) in args.iter().enumerate() {
        let raw = arg.as_bytes();
        let later = || {
            args.iter()
                .skip(i.saturating_add(1))
                .fold(0usize, |n, a| n.saturating_add(a.len()))
        };
        let gap = usize::from(i > 0);
        let mut arg_pieces = pieces(raw, Quote::Backslash).peekable();
        let first = arg_pieces.peek().map_or(0, |p| p.text.len());
        if out
            .len()
            .saturating_add(gap)
            .saturating_add(2)
            .saturating_add(first)
            > max
        {
            return (out, Some(raw.len().saturating_add(later())));
        }
        if gap == 1 {
            out.push(' ');
        }
        out.push('"');
        let mut shown = 0usize;
        for piece in arg_pieces {
            if out.len().saturating_add(piece.text.len()).saturating_add(1) > max {
                out.push('"');
                let rest = raw.len().saturating_sub(shown);
                return (out, Some(rest.saturating_add(later())));
            }
            out.push_str(&piece.text);
            shown = shown.saturating_add(piece.input);
        }
        out.push('"');
    }
    (out, None)
}

/// The hex format (architect Q288): printable ASCII other than `\` and `"` as is, every other
/// byte `\xNN`, of the first `max` bytes of `raw`; and whether `raw` was longer.
#[must_use]
pub fn hex_capped(raw: &[u8], max: usize) -> (String, bool) {
    let shown = raw.get(..max).unwrap_or(raw);
    let mut out = String::with_capacity(shown.len());
    for &b in shown {
        if (0x20..0x7f).contains(&b) && b != b'\\' && b != b'"' {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "\\x{b:02x}");
        }
    }
    (out, raw.len() > shown.len())
}

/// [`hex_capped`], with `…(+N)` after a cut text, `N` the bytes of `raw` not shown.
#[must_use]
pub fn hex_counted(raw: &[u8], max: usize) -> String {
    let (mut out, cut) = hex_capped(raw, max);
    if cut {
        let _ = write!(out, "\u{2026}(+{})", raw.len().saturating_sub(max));
    }
    out
}

/// The plain format: at most `max` bytes of `s`, cut at a character boundary, `…` after a cut
/// text. Nothing is escaped: for free text whose consumers escape it themselves.
#[must_use]
pub fn plain_capped(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_owned();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    format!("{}\u{2026}", s.get(..end).unwrap_or_default())
}

/// `text`, already escaped, cut at `max` bytes, never inside a `\…` escape, with a tail that
/// names the bytes cut and the SHA-256 of the whole `text`; and whether it was cut.
#[must_use]
pub fn cut_escaped(text: &str, max: usize) -> (String, bool) {
    if text.len() <= max {
        return (text.to_owned(), false);
    }
    let at = escape_boundary(text, max);
    let shown = text.get(..at).unwrap_or_default();
    let rest = text.len().saturating_sub(at);
    let sha = sha256_hex(text.as_bytes());
    (format!("{shown}... (+{rest} bytes, sha256 {sha})"), true)
}

/// The largest offset at most `max` that does not fall inside a `\…` escape or a character of
/// `text`.
fn escape_boundary(text: &str, max: usize) -> usize {
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while let Some(&b) = bytes.get(i) {
        let len = match (b, bytes.get(i.saturating_add(1))) {
            (b'\\', Some(b'x')) => 4,
            (b'\\', Some(b'u')) => text
                .get(i..)
                .and_then(|r| r.find('}'))
                .map_or(1, |e| e.saturating_add(1)),
            (b'\\', Some(_)) => 2,
            // One whole character. A literal piece is meant to be printable ASCII but is never
            // escaped, so a stray character outside ASCII is not split here (a `\` just before it
            // in the literal is still read as an escape's start).
            _ => text
                .get(i..)
                .and_then(|r| r.chars().next())
                .map_or(1, char::len_utf8),
        };
        let next = i.saturating_add(len);
        if next > max {
            break;
        }
        i = next;
    }
    i
}

fn sha256_hex(data: &[u8]) -> String {
    let mut out = String::with_capacity(64);
    for b in Sha256::digest(data) {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// How a `"` is written by the text format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quote {
    /// As is.
    None,
    /// As `\x22`.
    Hex,
    /// As `\"`.
    Backslash,
}

/// How sandbox-chosen text is cut and escaped for an audit entry (architect Q288). The text is
/// always masked whole before it is styled, so a cut or an escape cannot split or rewrite a form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Style {
    /// [`hex_capped`]: the cut is reported apart from the text.
    Hex {
        /// Input bytes kept.
        max: usize,
    },
    /// [`hex_counted`].
    HexCounted {
        /// Input bytes kept.
        max: usize,
    },
    /// [`escape_capped`]'s alphabet and tail, with `quote` for `"`.
    Text {
        /// Escaped bytes kept.
        max: usize,
        /// How a `"` is written.
        quote: Quote,
    },
    /// [`plain_capped`].
    Plain {
        /// Bytes kept.
        max: usize,
    },
}

/// `raw` in `style`, and whether it was cut.
#[must_use]
pub fn styled(raw: &str, style: Style) -> (String, bool) {
    let bytes = raw.as_bytes();
    match style {
        Style::Hex { max } => hex_capped(bytes, max),
        Style::HexCounted { max } => (hex_counted(bytes, max), bytes.len() > max),
        Style::Text { max, quote } => capped(bytes, max, quote),
        Style::Plain { max } => (plain_capped(raw, max), raw.len() > max),
    }
}

fn capped(raw: &[u8], max: usize, quote: Quote) -> (String, bool) {
    let mut out = String::new();
    let mut shown = 0usize;
    for piece in pieces(raw, quote) {
        if out.len().saturating_add(piece.text.len()) > max {
            let dropped = raw.len().saturating_sub(shown);
            let _ = write!(out, "...(+{dropped} bytes)");
            return (out, true);
        }
        out.push_str(&piece.text);
        shown = shown.saturating_add(piece.input);
    }
    (out, false)
}

/// One unit of output: its escaped text and the input bytes it stands for.
struct Piece {
    text: String,
    input: usize,
}

fn pieces(raw: &[u8], quote: Quote) -> impl Iterator<Item = Piece> + '_ {
    raw.utf8_chunks().flat_map(move |chunk| {
        let valid = chunk.valid().chars().map(move |c| Piece {
            text: char_text(c, quote),
            input: c.len_utf8(),
        });
        let invalid = chunk.invalid().iter().map(|b| Piece {
            text: format!("\\x{b:02x}"),
            input: 1,
        });
        valid.chain(invalid)
    })
}

/// The line-mode escaper (architect ruling Q100): [`escape`]'s alphabet plus `\n`, for one
/// stream of output that arrives in chunks. Printable ASCII stays, `\` becomes `\\`, `\n` stays;
/// `\t`, `\r`, every other control and DEL become `\xNN`, every other character `\u{…}`, and
/// every byte that is not valid UTF-8 `\xNN`. A character cut across two chunks is carried
/// (at most 3 bytes) and escaped whole, so the output does not depend on where chunks end; what
/// is still carried at [`finish`](Self::finish) is escaped byte by byte.
///
/// One per stream: a second stream needs its own. Call [`finish`](Self::finish) at the end of
/// the stream: an escaper dropped without it shows nothing of what it carries. Output that
/// keeps `\n` can start a line that looks like the client's own, so a client that streams it
/// sets sandbox lines apart. TODO(#130): pass readable non-ASCII text through on a terminal
/// known to take it.
#[derive(Debug, Default)]
pub struct StreamEscaper {
    /// The start of a valid UTF-8 sequence the last chunk ended in (at most 3 bytes).
    carry: Vec<u8>,
}

impl StreamEscaper {
    /// The escaped text of `chunk`, after what the last chunk left carried.
    #[must_use]
    pub fn push(&mut self, chunk: &[u8]) -> String {
        let joined;
        let input = if self.carry.is_empty() {
            chunk
        } else {
            let mut j = std::mem::take(&mut self.carry);
            j.extend_from_slice(chunk);
            joined = j;
            joined.as_slice()
        };
        let mut out = String::with_capacity(input.len());
        let mut parts = input.utf8_chunks().peekable();
        while let Some(part) = parts.next() {
            for c in part.valid().chars() {
                line_char(c, &mut out);
            }
            let bad = part.invalid();
            // Only the last part's invalid bytes can be a character cut by the chunk's end; a
            // middle one is followed by more input, so it is broken, not cut.
            let cut = parts.peek().is_none()
                && std::str::from_utf8(bad).is_err_and(|e| e.error_len().is_none());
            if cut {
                self.carry = bad.to_vec();
            } else {
                bytes_text(bad, &mut out);
            }
        }
        out
    }

    /// The escape of what is still carried; the stream is over.
    #[must_use]
    pub fn finish(self) -> String {
        let mut out = String::new();
        bytes_text(&self.carry, &mut out);
        out
    }

    /// How many bytes are carried to the next chunk.
    #[must_use]
    pub fn held(&self) -> usize {
        self.carry.len()
    }
}

fn line_char(c: char, out: &mut String) {
    if c == '\n' {
        out.push('\n');
    } else {
        push_char(c, Quote::None, out);
    }
}

// Writing to a `String` cannot fail, so the `write!` results are dropped.
fn bytes_text(bytes: &[u8], out: &mut String) {
    for b in bytes {
        let _ = write!(out, "\\x{b:02x}");
    }
}

fn char_text(c: char, quote: Quote) -> String {
    let mut out = String::new();
    push_char(c, quote, &mut out);
    out
}

fn push_char(c: char, quote: Quote, out: &mut String) {
    if c != '"' {
        return push_unquoted(c, out);
    }
    match quote {
        Quote::Hex => out.push_str("\\x22"),
        Quote::Backslash => out.push_str("\\\""),
        Quote::None => push_unquoted(c, out),
    }
}

fn push_unquoted(c: char, out: &mut String) {
    match c {
        '\\' => out.push_str("\\\\"),
        ' '..='~' => out.push(c),
        '\0'..='\x7f' => {
            let _ = write!(out, "\\x{:02x}", u32::from(c));
        }
        _ => {
            let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|a| (*a).to_owned()).collect()
    }

    /// Every argument is quoted and escaped, an empty one too, and a whole list is not cut.
    #[test]
    fn quoted_args_are_each_quoted_escaped_and_joined_by_one_space() {
        let (text, cut) =
            quoted_args_capped(&args(&["run", "", "a\"b", "\u{1b}[2J", "\u{e9}"]), 200);
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
        assert_eq!(cut, Some(1));
    }

    /// An argument starts only when the space, both quotes and its first escape fit; the count
    /// covers the argument and every later one, in input bytes.
    #[test]
    fn an_argument_starts_only_when_its_quotes_and_first_escape_fit() {
        // "aa" = 4 bytes; then " " + "\"" + "\\x1b" + "\"" needs 7 more.
        let list = args(&["aa", "\u{1b}b", "cd"]);
        assert_eq!(
            quoted_args_capped(&list, 10),
            ("\"aa\"".to_owned(), Some(4))
        );
        assert_eq!(
            quoted_args_capped(&list, 11),
            ("\"aa\" \"\\x1b\"".to_owned(), Some(3))
        );
        // An empty argument needs only its quotes; a cut one never shows as "".
        let list = args(&["aa", "", "b"]);
        assert_eq!(
            quoted_args_capped(&list, 7),
            ("\"aa\" \"\"".to_owned(), Some(1))
        );
        assert_eq!(quoted_args_capped(&list, 6), ("\"aa\"".to_owned(), Some(1)));
        let list = args(&["aa", "b"]);
        assert_eq!(quoted_args_capped(&list, 7), ("\"aa\"".to_owned(), Some(1)));
        assert_eq!(
            quoted_args_capped(&list, 8),
            ("\"aa\" \"b\"".to_owned(), None)
        );
    }

    /// A cut never splits an escape, and the count is of input bytes, not escaped ones.
    #[test]
    fn a_cut_never_splits_an_escape_and_counts_input_bytes() {
        let list = args(&["\u{e9}\u{e9}\u{e9}"]);
        // "\u{e9}" is 6 bytes: two fit in 1 + 12 + 1 = 14, not three.
        assert_eq!(
            quoted_args_capped(&list, 15),
            ("\"\\u{e9}\\u{e9}\"".to_owned(), Some(2))
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
}
