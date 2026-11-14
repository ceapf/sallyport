//! The last entries of the log, for `sally audit tail` (architect Q110). Read-only: it never
//! creates the directory, never takes `audit.lock` and never repairs anything, so it is safe
//! beside a live writer. It does not verify the chain (`audit::verify` does).
//!
//! Lines are read with the verifier's bound (`MAX_LINE_BYTES`), and only the newest `n` are
//! kept. A file's unterminated last line is an append in flight and is skipped. A line that is
//! not an entry is counted, never returned.

use std::collections::VecDeque;
use std::io::BufReader;
use std::path::Path;

use super::entry::{MAX_LINE_BYTES, parse_line};
use super::layout::list_log_files;
use super::verify::{Line, read_line};

/// The most entries one tail returns.
pub const MAX_TAIL: usize = 1000;

/// The newest entries of the log.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Tail {
    /// The entries' lines as written, oldest first.
    pub lines: Vec<String>,
    /// Lines in the files read that are not entries (malformed or over the line cap).
    pub unparsed: usize,
}

/// The newest `n` entries (at most [`MAX_TAIL`]) of the log in `dir`, oldest first. Blocking.
///
/// # Errors
/// The directory or a log file could not be read.
pub fn tail(dir: &Path, n: usize) -> std::io::Result<Tail> {
    let want = n.min(MAX_TAIL);
    let mut out = Tail::default();
    if want == 0 {
        return Ok(out);
    }
    let files = list_log_files(dir)?;
    let mut kept: VecDeque<String> = VecDeque::with_capacity(want);
    for (_, path) in files.iter().rev() {
        let left = want.saturating_sub(kept.len());
        if left == 0 {
            break;
        }
        let (lines, unparsed) = newest_of(path, left)?;
        out.unparsed = out.unparsed.saturating_add(unparsed);
        for l in lines.into_iter().rev() {
            kept.push_front(l);
        }
    }
    out.lines = kept.into();
    Ok(out)
}

/// The newest `n` entry lines of one file, oldest first, and how many lines were not entries.
fn newest_of(path: &Path, n: usize) -> std::io::Result<(VecDeque<String>, usize)> {
    let mut r = BufReader::new(std::fs::File::open(path)?);
    let mut buf = Vec::new();
    let mut ring: VecDeque<String> = VecDeque::with_capacity(n);
    let mut unparsed = 0usize;
    loop {
        match read_line(&mut r, &mut buf)? {
            Line::Eof | Line::Unterminated => break,
            Line::TooLong => {
                unparsed = unparsed.saturating_add(1);
                // `read_line` stopped at its limit before a newline: skip the rest of the line.
                // (An overlong line that did end within the limit is already consumed.)
                if buf.len() > MAX_LINE_BYTES.saturating_add(1) {
                    skip_line(&mut r)?;
                }
            }
            Line::Complete => match parse_line(&buf)
                .ok()
                .and_then(|_| String::from_utf8(buf.clone()).ok())
            {
                Some(line) => {
                    if ring.len() == n {
                        ring.pop_front();
                    }
                    ring.push_back(line);
                }
                None => unparsed = unparsed.saturating_add(1),
            },
        }
    }
    Ok((ring, unparsed))
}

/// Consumes input up to and including the next newline, in bounded steps.
fn skip_line(r: &mut impl std::io::BufRead) -> std::io::Result<()> {
    loop {
        let chunk = r.fill_buf()?;
        if chunk.is_empty() {
            return Ok(());
        }
        match chunk.iter().position(|b| *b == b'\n') {
            Some(i) => {
                r.consume(i.saturating_add(1));
                return Ok(());
            }
            None => {
                let len = chunk.len();
                r.consume(len);
            }
        }
    }
}
