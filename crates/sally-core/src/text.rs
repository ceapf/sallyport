//! Neutralizing untrusted text for a terminal or a log line (architect rulings Q43, Q50, Q56).
//!
//! [`escape`] turns any bytes into printable ASCII: printable ASCII stays as it is, `\` becomes
//! `\\`, every other ASCII byte (controls, DEL) and every byte that is not valid UTF-8 becomes
//! `\xNN`, and every other character becomes `\u{…}`. No escape sequence of a terminal, no line
//! break and no bidirectional control survives. [`escape_capped`] does the same within a size
//! bound and names what it cut; it never cuts inside an escape. [`escape_quoted_capped`] also
//! escapes `"`, for a value written between quotes. [`StreamEscaper`] is the line-mode form
//! (architect Q100): the same alphabet plus `\n`, for output that arrives in chunks.

use std::fmt::Write as _;

/// `raw` as printable ASCII.
#[must_use]
pub fn escape(raw: &[u8]) -> String {
    let mut out = String::with_capacity(raw.len());
    for piece in pieces(raw, false) {
        out.push_str(&piece.text);
    }
    out
}

/// `raw` as printable ASCII, at most `max` bytes of escaped text. When the input does not fit,
/// the text stops before the first escape that would pass `max` and `...(+N bytes)` follows,
/// where `N` is the count of input bytes not shown.
#[must_use]
pub fn escape_capped(raw: &[u8], max: usize) -> String {
    capped(raw, max, false)
}

/// [`escape_capped`] for a value written between double quotes: `"` becomes `\x22` too, and the
/// cut measures that escaped form.
#[must_use]
pub fn escape_quoted_capped(raw: &[u8], max: usize) -> String {
    capped(raw, max, true)
}

fn capped(raw: &[u8], max: usize, quote: bool) -> String {
    let mut out = String::new();
    let mut shown = 0usize;
    for piece in pieces(raw, quote) {
        if out.len().saturating_add(piece.text.len()) > max {
            let dropped = raw.len().saturating_sub(shown);
            let _ = write!(out, "...(+{dropped} bytes)");
            return out;
        }
        out.push_str(&piece.text);
        shown = shown.saturating_add(piece.input);
    }
    out
}

/// One unit of output: its escaped text and the input bytes it stands for.
struct Piece {
    text: String,
    input: usize,
}

fn pieces(raw: &[u8], quote: bool) -> impl Iterator<Item = Piece> + '_ {
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
/// One per stream: a second stream needs its own. TODO(#130): pass readable non-ASCII text
/// through on a terminal known to take it.
#[derive(Debug, Default)]
pub struct StreamEscaper {
    /// The start of a valid UTF-8 sequence the last chunk ended in (at most 3 bytes).
    carry: Vec<u8>,
}

impl StreamEscaper {
    /// The escaped text of `chunk`, after what the last chunk left carried.
    #[must_use]
    pub fn push(&mut self, chunk: &[u8]) -> String {
        let mut input = std::mem::take(&mut self.carry);
        input.extend_from_slice(chunk);
        let mut out = String::with_capacity(input.len());
        let mut rest = input.as_slice();
        loop {
            match std::str::from_utf8(rest) {
                Ok(s) => {
                    line_text(s, &mut out);
                    return out;
                }
                Err(e) => {
                    let (good, bad) = rest.split_at(e.valid_up_to());
                    // `good` is valid UTF-8 by `valid_up_to`; were it not, it is shown bytewise.
                    match std::str::from_utf8(good) {
                        Ok(s) => line_text(s, &mut out),
                        Err(_) => bytes_text(good, &mut out),
                    }
                    let Some(n) = e.error_len() else {
                        // An incomplete sequence at the end: at most 3 bytes, carried.
                        self.carry = bad.to_vec();
                        return out;
                    };
                    let (broken, after) = bad.split_at(n.min(bad.len()));
                    bytes_text(broken, &mut out);
                    rest = after;
                }
            }
        }
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

fn line_text(s: &str, out: &mut String) {
    for c in s.chars() {
        if c == '\n' {
            out.push('\n');
        } else {
            out.push_str(&char_text(c, false));
        }
    }
}

fn bytes_text(bytes: &[u8], out: &mut String) {
    for b in bytes {
        let _ = write!(out, "\\x{b:02x}");
    }
}

fn char_text(c: char, quote: bool) -> String {
    match c {
        '\\' => "\\\\".to_owned(),
        '"' if quote => "\\x22".to_owned(),
        ' '..='~' => c.to_string(),
        '\0'..='\x7f' => format!("\\x{:02x}", u32::from(c)),
        _ => format!("\\u{{{:x}}}", u32::from(c)),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use proptest::prelude::*;

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
