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

use super::entry::parse_line;
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

/// The directory or a log file could not be read.
#[derive(Debug, thiserror::Error)]
#[error("{path}: {source}")]
pub struct TailError {
    /// Host path of the directory or file.
    pub path: String,
    /// The underlying error.
    #[source]
    pub source: std::io::Error,
}

/// The newest `n` entries (at most [`MAX_TAIL`]) of the log in `dir`, oldest first. Blocking.
///
/// # Errors
/// [`TailError`], naming the directory or log file that could not be read.
pub fn tail(dir: &Path, n: usize) -> Result<Tail, TailError> {
    let want = n.min(MAX_TAIL);
    let mut out = Tail::default();
    if want == 0 {
        return Ok(out);
    }
    let files = list_log_files(dir).map_err(|source| TailError {
        path: dir.display().to_string(),
        source,
    })?;
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
fn newest_of(path: &Path, n: usize) -> Result<(VecDeque<String>, usize), TailError> {
    let at = |source| TailError {
        path: path.display().to_string(),
        source,
    };
    let mut r = BufReader::new(std::fs::File::open(path).map_err(at)?);
    let mut buf = Vec::new();
    let mut ring: VecDeque<String> = VecDeque::with_capacity(n);
    let mut unparsed = 0usize;
    loop {
        match read_line(&mut r, &mut buf).map_err(at)? {
            Line::Eof | Line::Unterminated => break,
            Line::TooLong { ended } => {
                unparsed = unparsed.saturating_add(1);
                // Stopped at the limit before a newline: skip the rest of the line.
                if !ended {
                    skip_line(&mut r).map_err(at)?;
                }
            }
            Line::Complete => match parse_line(&buf)
                .ok()
                .and_then(|_| String::from_utf8(std::mem::take(&mut buf)).ok())
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
