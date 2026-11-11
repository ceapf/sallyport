//! The request head, parsed with `httparse` from at most [`MAX_HEAD`] bytes. Only the method and
//! the request-target are used: every header is ignored (the decision uses the request-target
//! authority only, so `Host` cannot confuse it).

/// Largest request head accepted; more is `head-too-large` (431).
pub const MAX_HEAD: usize = 8 * 1024;
/// Header slots `httparse` may fill (ARCHITECTURE §7: ≤ 100 headers); more is `head-too-large`
/// too, since headers are ignored rather than wrong.
const MAX_HEADERS: usize = 100;

/// A complete request head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head<'a> {
    /// Whether the method is `CONNECT` (anything else gets 405).
    pub connect: bool,
    /// The request-target, as sent.
    pub target: &'a str,
    /// Bytes of `buf` the head took, CRLFCRLF included.
    pub len: usize,
}

/// What the bytes received so far amount to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed<'a> {
    /// A complete head.
    Complete(Head<'a>),
    /// Not complete yet, and still under the size limit: read more.
    Partial,
    /// Over [`MAX_HEAD`], or more headers than fit.
    TooLarge,
    /// Not an HTTP/1.x request head.
    Malformed,
}

/// Parses the head at the start of `buf`.
#[must_use]
pub fn parse(buf: &[u8]) -> Parsed<'_> {
    let Some(window) = buf.get(..MAX_HEAD.min(buf.len())) else {
        return Parsed::Malformed;
    };
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(window) {
        Ok(httparse::Status::Complete(len)) => match (req.method, req.path) {
            (Some(method), Some(target)) => Parsed::Complete(Head {
                connect: method == "CONNECT",
                target,
                len,
            }),
            _ => Parsed::Malformed,
        },
        Ok(httparse::Status::Partial) if buf.len() >= MAX_HEAD => Parsed::TooLarge,
        Ok(httparse::Status::Partial) => Parsed::Partial,
        Err(httparse::Error::TooManyHeaders) => Parsed::TooLarge,
        Err(_) => Parsed::Malformed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete(connect: bool, target: &str, len: usize) -> Parsed<'_> {
        Parsed::Complete(Head {
            connect,
            target,
            len,
        })
    }

    #[test]
    fn a_connect_head_gives_its_target_and_length() {
        let req = b"CONNECT mock.test:443 HTTP/1.1\r\nHost: evil.test\r\n\r\nrest";
        assert_eq!(parse(req), complete(true, "mock.test:443", req.len() - 4));
    }

    #[test]
    fn other_methods_and_absolute_form_are_complete_but_not_connect() {
        let req = b"GET http://mock.test/ HTTP/1.1\r\nHost: mock.test\r\n\r\n";
        assert_eq!(parse(req), complete(false, "http://mock.test/", req.len()));
        let lower = b"connect mock.test:443 HTTP/1.1\r\n\r\n";
        assert_eq!(parse(lower), complete(false, "mock.test:443", lower.len()));
    }

    #[test]
    fn an_incomplete_head_asks_for_more_until_the_limit() {
        assert_eq!(
            parse(b"CONNECT mock.test:443 HTTP/1.1\r\n"),
            Parsed::Partial
        );
        assert_eq!(parse(b""), Parsed::Partial);
        let mut long = b"CONNECT mock.test:443 HTTP/1.1\r\nX: ".to_vec();
        long.resize(MAX_HEAD - 1, b'a');
        assert_eq!(parse(&long), Parsed::Partial);
        long.push(b'a');
        assert_eq!(parse(&long), Parsed::TooLarge);
    }

    #[test]
    fn a_head_completing_only_past_the_limit_is_too_large() {
        let mut req = b"CONNECT mock.test:443 HTTP/1.1\r\nX: ".to_vec();
        req.resize(MAX_HEAD, b'a');
        req.extend_from_slice(b"\r\n\r\n");
        assert_eq!(parse(&req), Parsed::TooLarge);
        let mut fits = b"CONNECT mock.test:443 HTTP/1.1\r\nX: ".to_vec();
        fits.resize(MAX_HEAD - 4, b'a');
        fits.extend_from_slice(b"\r\n\r\n");
        assert_eq!(parse(&fits), complete(true, "mock.test:443", MAX_HEAD));
    }

    #[test]
    fn a_head_of_exactly_8_kib_is_accepted() {
        // The limit is the maintainer's 8 KiB, written out here rather than via MAX_HEAD.
        let mut req = b"CONNECT mock.test:443 HTTP/1.1\r\nX: ".to_vec();
        req.resize(8192 - 4, b'a');
        req.extend_from_slice(b"\r\n\r\n");
        assert_eq!(parse(&req), complete(true, "mock.test:443", 8192));
    }

    #[test]
    fn too_many_headers_is_too_large() {
        let mut req = b"CONNECT mock.test:443 HTTP/1.1\r\n".to_vec();
        for _ in 0..MAX_HEADERS {
            req.extend_from_slice(b"X: y\r\n");
        }
        req.extend_from_slice(b"\r\n");
        assert!(matches!(parse(&req), Parsed::Complete(_)));
        let mut over = b"CONNECT mock.test:443 HTTP/1.1\r\n".to_vec();
        for _ in 0..=MAX_HEADERS {
            over.extend_from_slice(b"X: y\r\n");
        }
        over.extend_from_slice(b"\r\n");
        assert_eq!(parse(&over), Parsed::TooLarge);
    }

    #[test]
    fn garbage_is_malformed() {
        for bad in [
            &b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03"[..],
            b"CONNECT mock.test:443 HTTP/2.0\r\n\r\n",
            b"CONNECT\r\n\r\n",
            b"CONNECT mock.test:443 HTTP/1.1\r\nBad Header\r\n\r\n",
        ] {
            assert_eq!(parse(bad), Parsed::Malformed, "{bad:?}");
        }
    }
}
