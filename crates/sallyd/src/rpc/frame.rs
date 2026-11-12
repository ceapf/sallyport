//! Newline-delimited framing (MCP stdio framing over a Unix stream). A frame is the bytes before
//! a `\n`; it is never buffered past its limit: a longer one is reported as soon as the limit is
//! crossed, and the connection cannot be resynchronised, so the caller closes it.

use std::io;

use tokio::io::{AsyncBufRead, AsyncBufReadExt};

/// What the next read produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// One frame, without its newline. A last frame cut by end of stream counts too.
    Line(Vec<u8>),
    /// More than the limit arrived without a newline.
    TooLarge,
    /// The peer closed the stream between frames.
    Eof,
}

/// Reads the next frame of at most `max` bytes.
///
/// # Errors
/// The stream's read error.
pub async fn read<R: AsyncBufRead + Unpin>(r: &mut R, max: usize) -> io::Result<Frame> {
    let mut line = Vec::new();
    loop {
        let available = r.fill_buf().await?;
        if available.is_empty() {
            return Ok(if line.is_empty() {
                Frame::Eof
            } else {
                Frame::Line(line)
            });
        }
        let newline = available.iter().position(|&b| b == b'\n');
        let take = newline.unwrap_or(available.len());
        if line.len().saturating_add(take) > max {
            return Ok(Frame::TooLarge);
        }
        line.extend_from_slice(available.get(..take).unwrap_or_default());
        match newline {
            Some(n) => {
                r.consume(n.saturating_add(1));
                return Ok(Frame::Line(line));
            }
            None => r.consume(take),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use tokio::io::{AsyncWriteExt, BufReader};

    async fn frames(input: &[u8], max: usize, cap: usize) -> Vec<Frame> {
        let (mut w, r) = tokio::io::duplex(64);
        let input = input.to_vec();
        let writer = tokio::spawn(async move {
            let _ = w.write_all(&input).await;
        });
        let mut r = BufReader::with_capacity(cap, r);
        let mut out = Vec::new();
        loop {
            let f = read(&mut r, max).await.unwrap();
            let end = !matches!(f, Frame::Line(_));
            out.push(f);
            if end {
                break;
            }
        }
        writer.abort();
        out
    }

    fn line(s: &str) -> Frame {
        Frame::Line(s.as_bytes().to_vec())
    }

    #[tokio::test]
    async fn frames_split_on_newlines_across_small_reads() {
        let got = frames(b"ab\ncdef\n\ng", 8, 3).await;
        assert_eq!(
            got,
            [line("ab"), line("cdef"), line(""), line("g"), Frame::Eof]
        );
    }

    #[tokio::test]
    async fn a_frame_of_exactly_the_limit_passes() {
        let got = frames(b"abcd\nxy\n", 4, 2).await;
        assert_eq!(got, [line("abcd"), line("xy"), Frame::Eof]);
    }

    #[tokio::test]
    async fn one_byte_over_the_limit_is_too_large() {
        let got = frames(b"abcde\nxy\n", 4, 2).await;
        assert_eq!(got, [Frame::TooLarge]);
        let got = frames(b"abcde", 4, 16).await;
        assert_eq!(got, [Frame::TooLarge]);
    }

    #[tokio::test]
    async fn too_large_is_reported_without_waiting_for_a_newline() {
        let (mut w, r) = tokio::io::duplex(1024);
        w.write_all(&[b'a'; 100]).await.unwrap();
        // The writer stays open: the reader must not wait for more.
        let mut r = BufReader::with_capacity(16, r);
        let f = tokio::time::timeout(std::time::Duration::from_secs(5), read(&mut r, 50)).await;
        assert_eq!(f.unwrap().unwrap(), Frame::TooLarge);
    }

    #[tokio::test]
    async fn an_empty_stream_is_eof() {
        assert_eq!(frames(b"", 4, 4).await, [Frame::Eof]);
    }
}
