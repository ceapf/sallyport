//! Neutralizing untrusted text for a terminal or a log line (architect rulings Q43, Q50, Q56).
//!
//! [`escape`] turns any bytes into printable ASCII: printable ASCII stays as it is, `\` becomes
//! `\\`, every other ASCII byte (controls, DEL) and every byte that is not valid UTF-8 becomes
//! `\xNN`, and every other character becomes `\u{…}`. No escape sequence of a terminal, no line
//! break and no bidirectional control survives. [`escape_capped`] does the same within a size
//! bound and names what it cut; it never cuts inside an escape. [`escape_quoted_capped`] also
//! escapes `"`, for a value written between quotes. [`quoted_args_capped`] writes a list of
//! arguments each between quotes, a backtick as `\x60` too, within a size bound, and says where a
//! cut fell ([`ArgsCut`]), for the launch summary's command line (RT-MAN-05).
//! [`StreamEscaper`] is the line-mode form (architect Q100): the same alphabet plus `\n`, for
//! output that arrives in chunks.
//!
//! What a launch may show a person who consents to it (RT-MAN-05): [`quoted_path`] writes a host
//! path between quotes, byte for byte, the one form for every line that names a folder.
//! [`is_refused`] is the class of characters a launch never shows: controls, whitespace other
//! than the space, Unicode's default-ignorable and format characters (direction marks and
//! invisible characters among them) and noncharacters. [`refused_escape`] reads a line these
//! escapers wrote and names its first escape of a refused character or of a byte that is not
//! UTF-8. It fails closed: a backslash that does not start `\\`, `\"`, `\xHH` or `\u{H…}`
//! refuses too.
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

/// Equal units in a row up to which [`escape_runs_backslash_quoted`] writes each one (RT-AG-04).
pub const RUN_SHOWN_WHOLE: usize = 16;

/// [`escape_backslash_quoted`], with every run of more than [`RUN_SHOWN_WHOLE`] equal units
/// written as the unit once and then `\{N}`, `N` the run's whole length in units (RT-AG-04). A
/// unit is one character, or one byte that is not UTF-8; a run is taken whole, never split into
/// two marks. A `\` the input holds is always `\\`, so `\{` comes only from here. For the text
/// an approval prompt shows; the audit, the summary and the launch gate never use it.
#[must_use]
pub fn escape_runs_backslash_quoted(raw: &[u8]) -> String {
    let mut out = String::with_capacity(raw.len().min(RUN_MARKED_CAPACITY));
    for piece in marked_pieces(raw) {
        out.push_str(&piece.text);
    }
    out
}

/// [`escape_runs_backslash_quoted`] kept to at most `max` bytes, stopping before the first unit
/// (with its mark) that would pass it; and how many input bytes the kept text shows. Bounds
/// first: the input is read only as far as the end of the run the text stops in.
#[must_use]
pub fn escape_runs_capped(raw: &[u8], max: usize) -> (String, usize) {
    let mut out = String::new();
    let mut shown = 0usize;
    for piece in marked_pieces(raw) {
        if out.len().saturating_add(piece.text.len()) > max {
            break;
        }
        out.push_str(&piece.text);
        shown = shown.saturating_add(piece.input);
    }
    (out, shown)
}

/// What [`escape_runs_backslash_quoted`] reserves up front: a marked run can be far shorter than
/// its input.
const RUN_MARKED_CAPACITY: usize = 4096;

/// The units of `raw` (`"` as `\"`), each run of more than [`RUN_SHOWN_WHOLE`] as one piece:
/// the unit and its mark.
fn marked_pieces(raw: &[u8]) -> impl Iterator<Item = Piece> + '_ {
    let mut units = pieces(raw, Quote::Backslash).peekable();
    std::iter::from_fn(move || {
        let first = units.next()?;
        let mut n = 1usize;
        while units.next_if(|p| p.text == first.text).is_some() {
            n = n.saturating_add(1);
        }
        Some(run_pieces(first, n))
    })
    .flatten()
}

/// `n` units of `unit`: one piece each when `n` is at most [`RUN_SHOWN_WHOLE`], else one marked
/// piece.
fn run_pieces(unit: Piece, n: usize) -> Vec<Piece> {
    if n > RUN_SHOWN_WHOLE {
        let text = format!("{}\\{{{n}}}", unit.text);
        let input = unit.input.saturating_mul(n);
        return vec![Piece { text, input }];
    }
    (0..n)
        .map(|_| Piece {
            text: unit.text.clone(),
            input: unit.input,
        })
        .collect()
}

/// A host path between double quotes, from its bytes: [`escape_backslash_quoted`], so a byte
/// that is not UTF-8 is `\xNN` (RT-MAN-05). Every line that names a folder uses this form, so
/// the lines read alike, and a folder name holding `, ` or ` (at ` stays one name.
#[must_use]
pub fn quoted_path(raw: &[u8]) -> String {
    format!("\"{}\"", escape_backslash_quoted(raw))
}

/// Unicode 17.0.0's `Default_Ignorable_Code_Point` (DerivedCoreProperties-17.0.0.txt, "Total
/// code points: 4174"), ranges that touch merged.
const DEFAULT_IGNORABLE: &[(u32, u32)] = &[
    (0x00ad, 0x00ad),
    (0x034f, 0x034f),
    (0x061c, 0x061c),
    (0x115f, 0x1160),
    (0x17b4, 0x17b5),
    (0x180b, 0x180f),
    (0x200b, 0x200f),
    (0x202a, 0x202e),
    (0x2060, 0x206f),
    (0x3164, 0x3164),
    (0xfe00, 0xfe0f),
    (0xfeff, 0xfeff),
    (0xffa0, 0xffa0),
    (0xfff0, 0xfff8),
    (0x1bca0, 0x1bca3),
    (0x1d173, 0x1d17a),
    (0xe0000, 0xe0fff),
];

/// Unicode 17.0.0's general category `Cf`, format characters
/// (extracted/DerivedGeneralCategory-17.0.0.txt, "Total code points: 170").
const FORMAT: &[(u32, u32)] = &[
    (0x00ad, 0x00ad),
    (0x0600, 0x0605),
    (0x061c, 0x061c),
    (0x06dd, 0x06dd),
    (0x070f, 0x070f),
    (0x0890, 0x0891),
    (0x08e2, 0x08e2),
    (0x180e, 0x180e),
    (0x200b, 0x200f),
    (0x202a, 0x202e),
    (0x2060, 0x2064),
    (0x2066, 0x206f),
    (0xfeff, 0xfeff),
    (0xfff9, 0xfffb),
    (0x110bd, 0x110bd),
    (0x110cd, 0x110cd),
    (0x13430, 0x1343f),
    (0x1bca0, 0x1bca3),
    (0x1d173, 0x1d17a),
    (0xe0001, 0xe0001),
    (0xe0020, 0xe007f),
];

/// Whether a launch refuses to show `c` (RT-MAN-05): a control (C1 included), whitespace other
/// than the space, a default-ignorable or format character (direction marks, zero-width and
/// other invisible characters) or a noncharacter. std's two classes follow the pinned
/// toolchain's Unicode version; the two tables are Unicode 17.0.0. Letters, marks, symbols,
/// private-use and unassigned code points are not refused: they are shown escaped.
#[must_use]
pub fn is_refused(c: char) -> bool {
    c.is_control()
        || (c.is_whitespace() && c != ' ')
        || in_table(DEFAULT_IGNORABLE, c)
        || in_table(FORMAT, c)
        || is_noncharacter(c)
}

fn in_table(table: &[(u32, u32)], c: char) -> bool {
    let n = u32::from(c);
    table
        .binary_search_by(|&(lo, hi)| {
            if hi < n {
                std::cmp::Ordering::Less
            } else if lo > n {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// U+FDD0..=U+FDEF and the last two code points of every plane.
fn is_noncharacter(c: char) -> bool {
    let n = u32::from(c);
    (0xfdd0..=0xfdef).contains(&n) || n & 0xfffe == 0xfffe
}

/// The longest escape the escapers here write, `\u{10ffff}`: six hex digits.
pub(crate) const LONGEST_ESCAPE: usize = 10;

/// The first escape in `line`, text the escapers here wrote, that shows a character
/// [`is_refused`] takes or a byte that is not UTF-8, as written in the line (RT-MAN-05). Fails
/// closed: a backslash that does not start `\\`, `\"`, `\xHH` (lowercase hex) or `\u{H…}` (one to
/// six lowercase hex digits naming a character) refuses, shown up to where it stopped reading.
/// `None` when every escape shows a character a launch may show.
#[must_use]
pub fn refused_escape(line: &str) -> Option<&str> {
    let bytes = line.as_bytes();
    let mut i = 0usize;
    while let Some(off) = bytes
        .get(i..)
        .and_then(|rest| rest.iter().position(|&b| b == b'\\'))
    {
        let start = i.saturating_add(off);
        let rest = bytes.get(start..).unwrap_or_default();
        match read_escape(rest) {
            // At least one byte, so the reading always moves on.
            Ok(len) => i = start.saturating_add(len.max(1)),
            Err(len) => {
                let end = (start.saturating_add(len)..=line.len())
                    .find(|&e| line.is_char_boundary(e))
                    .unwrap_or(line.len());
                // Refuses even should the slice ever miss a character's edge.
                return Some(line.get(start..end).unwrap_or("\\"));
            }
        }
    }
    None
}

/// The length of the escape `rest` starts with: `Ok` for one that shows a character a launch may
/// show, `Err` (at least 1) for any other.
fn read_escape(rest: &[u8]) -> Result<usize, usize> {
    match rest.get(1) {
        Some(b'\\' | b'"') => Ok(2),
        Some(b'x') => match rest.get(2..4).and_then(hex_value) {
            Some(v) if (0x20..=0x7e).contains(&v) => Ok(4),
            _ => Err(rest.len().min(4)),
        },
        Some(b'u') if rest.get(2) == Some(&b'{') => {
            let Some(close) = rest.iter().take(LONGEST_ESCAPE).position(|&b| b == b'}') else {
                return Err(rest.len().min(LONGEST_ESCAPE));
            };
            let shown = rest
                .get(3..close)
                .and_then(hex_value)
                .and_then(char::from_u32)
                .is_some_and(|c| !is_refused(c));
            let len = close.saturating_add(1);
            if shown { Ok(len) } else { Err(len) }
        }
        _ => Err(rest.len().min(2)),
    }
}

/// `digits` as lowercase hex, one to six of them; `None` for anything else.
fn hex_value(digits: &[u8]) -> Option<u32> {
    if digits.is_empty() || digits.len() > 6 {
        return None;
    }
    digits.iter().try_fold(0u32, |v, &d| {
        if !matches!(d, b'0'..=b'9' | b'a'..=b'f') {
            return None;
        }
        let n = char::from(d).to_digit(16)?;
        v.checked_mul(16)?.checked_add(n)
    })
}

/// Where [`quoted_args_capped`] cut a list of arguments (RT-MAN-05).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArgsCut {
    /// `true` when argument [`at`](Self::at) was shown in part, its closing quote written;
    /// `false` when every argument before it is whole and it did not start.
    pub inside: bool,
    /// The argument where the cut fell, counting from 1.
    pub at: usize,
    /// How many arguments there are.
    pub of: usize,
    /// Input bytes not shown: the rest of argument `at` (all of it when it did not start) and
    /// every later argument. At least 1 when `inside`; it may be 0 when not.
    pub bytes: usize,
}

/// `args` each written `"…"` by [`escape_backslash_quoted`], a backtick as `\x60` too, joined by
/// one space, in at most `max` bytes (RT-MAN-05: the launch summary's command
/// line, shown between backticks, which no argument can then close). Built left to right, never
/// cutting inside an escape: an argument starts only when the space before it, both its quotes and
/// its first escape fit, and an argument cut short still gets its closing quote. Returns the text
/// and, when it was cut, where.
#[must_use]
pub fn quoted_args_capped(args: &[String], max: usize) -> (String, Option<ArgsCut>) {
    let mut out = String::new();
    for (i, arg) in args.iter().enumerate() {
        let raw = arg.as_bytes();
        let later = args
            .iter()
            .skip(i.saturating_add(1))
            .fold(0usize, |n, a| n.saturating_add(a.len()));
        let cut = |inside: bool, shown: usize| ArgsCut {
            inside,
            at: i.saturating_add(1),
            of: args.len(),
            bytes: raw.len().saturating_sub(shown).saturating_add(later),
        };
        let gap = usize::from(i > 0);
        let mut arg_pieces = pieces(raw, Quote::Backslash)
            .map(backtick_escaped)
            .peekable();
        let first = arg_pieces.peek().map_or(0, |p| p.text.len());
        if out
            .len()
            .saturating_add(gap)
            .saturating_add(2)
            .saturating_add(first)
            > max
        {
            return (out, Some(cut(false, 0)));
        }
        if gap == 1 {
            out.push(' ');
        }
        out.push('"');
        let mut shown = 0usize;
        for piece in arg_pieces {
            if out.len().saturating_add(piece.text.len()).saturating_add(1) > max {
                out.push('"');
                return (out, Some(cut(true, shown)));
            }
            out.push_str(&piece.text);
            shown = shown.saturating_add(piece.input);
        }
        out.push('"');
    }
    (out, None)
}

/// A backtick piece written `\x60`, so text shown between backticks cannot close them (RT-MAN-05).
fn backtick_escaped(piece: Piece) -> Piece {
    if piece.text == "`" {
        Piece {
            text: "\\x60".to_owned(),
            input: piece.input,
        }
    } else {
        piece
    }
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
pub(crate) fn escape_boundary(text: &str, max: usize) -> usize {
    let mut i = 0usize;
    while i < text.len() {
        let next = i.saturating_add(unit_len(text, i));
        if next > max {
            break;
        }
        i = next;
    }
    i
}

/// The length of the unit of escaped `text` at byte `i` (at least 1): one escape or one
/// character, together with the run mark `\{N}` that follows it, if one does, so nothing splits
/// a unit from its mark.
fn unit_len(text: &str, i: usize) -> usize {
    let len = escape_len(text, i);
    let next = i.saturating_add(len);
    match text.get(next..) {
        Some(rest) if rest.starts_with("\\{") => {
            len.saturating_add(rest.find('}').map_or(rest.len(), |e| e.saturating_add(1)))
        }
        _ => len,
    }
}

/// The length of the escape or the character of escaped `text` at byte `i` (at least 1).
fn escape_len(text: &str, i: usize) -> usize {
    let bytes = text.as_bytes();
    match (bytes.get(i), bytes.get(i.saturating_add(1))) {
        (Some(b'\\'), Some(b'x')) => 4,
        (Some(b'\\'), Some(b'u' | b'{')) => text
            .get(i..)
            .and_then(|r| r.find('}'))
            .map_or(1, |e| e.saturating_add(1)),
        (Some(b'\\'), Some(_)) => 2,
        // One whole character. A literal piece is meant to be printable ASCII but is never
        // escaped, so a stray character outside ASCII is not split here (a `\` just before it
        // in the literal is still read as an escape's start).
        _ => text
            .get(i..)
            .and_then(|r| r.chars().next())
            .map_or(1, char::len_utf8),
    }
}

/// Escaped `text` broken into rows of at most `width` bytes, never inside a unit (an escape or
/// a character with its run mark, see [`escape_runs_backslash_quoted`]): the rows put together
/// are `text`. A unit longer than `width` is a row of its own, so a caller keeps `width` at
/// least [`LONGEST_UNIT`]. No row is empty; empty `text` has no rows.
#[must_use]
pub fn escaped_rows(text: &str, width: usize) -> Vec<&str> {
    let mut rows = Vec::new();
    let (mut start, mut i) = (0usize, 0usize);
    while i < text.len() {
        let next = i.saturating_add(unit_len(text, i));
        if next.saturating_sub(start) > width && i > start {
            rows.push(text.get(start..i).unwrap_or_default());
            start = i;
        }
        i = next;
    }
    if start < text.len() {
        rows.push(text.get(start..).unwrap_or_default());
    }
    rows
}

/// The longest unit [`escaped_rows`] keeps whole: `\u{10ffff}` and a run mark of the largest
/// count, `\{18446744073709551615}`.
pub const LONGEST_UNIT: usize = LONGEST_ESCAPE + 3 + 20;

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
#[path = "text_shown_tests.rs"]
mod shown_tests;

#[cfg(test)]
#[path = "text_runs_tests.rs"]
mod runs_tests;

#[cfg(test)]
#[path = "text_tests.rs"]
mod tests;
