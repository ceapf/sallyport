//! The request head on `llm.sock`, read and checked by the broker before hyper sees it (architect
//! ruling Q9: hyper answers a head it refuses with its own 400/431, which would be a reply with
//! no audit entry before it; see `probe_tests.rs`). Bounds first: at most [`MAX_HEAD`] bytes and
//! [`MAX_HEADERS`] headers. Only the method, the path and the body framing are used. A body is
//! framed by exactly one `Content-Length`; `Transfer-Encoding` is refused, so hyper never parses
//! a chunked request body.
#![deny(clippy::indexing_slicing)]

/// Largest request head accepted.
pub const MAX_HEAD: usize = 8 * 1024;
/// Header slots; more is too large.
pub const MAX_HEADERS: usize = 64;

/// A complete head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    /// The method, as sent.
    pub method: String,
    /// The request-target, as sent.
    pub path: String,
    /// The one `Content-Length`, if any.
    pub content_length: Option<u64>,
    /// Bytes the head took, CRLFCRLF included.
    pub len: usize,
}

/// What the bytes so far amount to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed {
    /// A complete, acceptable head.
    Complete(Head),
    /// Not complete yet, under the limit.
    Partial,
    /// Over [`MAX_HEAD`] or [`MAX_HEADERS`].
    TooLarge,
    /// Not an HTTP/1.1 request head, or framing this server refuses: its reason code.
    Refused(&'static str),
}

/// Parses the head at the start of `buf`.
#[must_use]
pub fn parse(buf: &[u8]) -> Parsed {
    let window = buf.get(..MAX_HEAD.min(buf.len())).unwrap_or_default();
    let mut slots = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut slots);
    let len = match req.parse(window) {
        Ok(httparse::Status::Complete(n)) => n,
        Ok(httparse::Status::Partial) if buf.len() >= MAX_HEAD => return Parsed::TooLarge,
        Ok(httparse::Status::Partial) => return Parsed::Partial,
        Err(httparse::Error::TooManyHeaders) => return Parsed::TooLarge,
        Err(_) => return Parsed::Refused("malformed"),
    };
    if req.version != Some(1) {
        return Parsed::Refused("http-version");
    }
    let (Some(method), Some(path)) = (req.method, req.path) else {
        return Parsed::Refused("malformed");
    };
    let mut content_length = None;
    for h in req.headers.iter() {
        if h.name.eq_ignore_ascii_case("transfer-encoding") {
            return Parsed::Refused("transfer-encoding");
        }
        if h.name.eq_ignore_ascii_case("content-length") {
            let n = std::str::from_utf8(h.value)
                .ok()
                .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|v| v.parse::<u64>().ok());
            match (n, content_length) {
                (Some(n), None) => content_length = Some(n),
                _ => return Parsed::Refused("content-length"),
            }
        }
    }
    Parsed::Complete(Head {
        method: method.to_owned(),
        path: path.to_owned(),
        content_length,
        len,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn head(s: &str) -> Parsed {
        parse(s.as_bytes())
    }

    fn complete(s: &str) -> Head {
        match head(s) {
            Parsed::Complete(h) => h,
            other => panic!("{s:?}: {other:?}"),
        }
    }

    #[test]
    fn the_limits_are_the_ruled_values() {
        assert_eq!((MAX_HEAD, MAX_HEADERS), (8192, 64));
    }

    #[test]
    fn a_request_head_parses() {
        let s = "POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nContent-Length: 12\r\n\r\nbody";
        let h = complete(s);
        assert_eq!(h.method, "POST");
        assert_eq!(h.path, "/v1/chat/completions");
        assert_eq!(h.content_length, Some(12));
        assert_eq!(h.len, s.find("body").unwrap());
        let h = complete("GET /v1/models HTTP/1.1\r\n\r\n");
        assert_eq!((h.content_length, h.len), (None, 27));
    }

    #[test]
    fn a_partial_head_asks_for_more_until_the_limit() {
        assert_eq!(head("POST /v1 HTTP/1.1\r\nHost: x\r\n"), Parsed::Partial);
        assert_eq!(head(""), Parsed::Partial);
        let mut long = "GET / HTTP/1.1\r\nX: ".to_owned();
        long.push_str(&"a".repeat(MAX_HEAD - long.len() - 1));
        assert_eq!(head(&long), Parsed::Partial);
        long.push('a');
        assert_eq!(head(&long), Parsed::TooLarge);
    }

    #[test]
    fn a_head_of_exactly_the_limit_parses() {
        let mut s = "GET / HTTP/1.1\r\nX: ".to_owned();
        s.push_str(&"a".repeat(MAX_HEAD - s.len() - 4));
        s.push_str("\r\n\r\n");
        assert_eq!(s.len(), MAX_HEAD);
        assert_eq!(complete(&s).len, MAX_HEAD);
        // A complete head past the limit is still too large: only the first MAX_HEAD bytes count.
        let mut over = "GET / HTTP/1.1\r\nX: ".to_owned();
        over.push_str(&"a".repeat(MAX_HEAD));
        over.push_str("\r\n\r\n");
        assert_eq!(head(&over), Parsed::TooLarge);
    }

    #[test]
    fn too_many_headers_is_too_large() {
        let mut s = "GET / HTTP/1.1\r\n".to_owned();
        for i in 0..MAX_HEADERS {
            s.push_str(&format!("X-{i}: v\r\n"));
        }
        assert!(matches!(head(&format!("{s}\r\n")), Parsed::Complete(_)));
        s.push_str("X-last: v\r\n\r\n");
        assert_eq!(head(&s), Parsed::TooLarge);
    }

    #[test]
    fn body_framing_is_one_content_length() {
        for bad in [
            "POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n",
            "POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n",
            "POST / HTTP/1.1\r\nContent-Length: +1\r\n\r\n",
            "POST / HTTP/1.1\r\nContent-Length: 1, 1\r\n\r\n",
            "POST / HTTP/1.1\r\nContent-Length: \r\n\r\n",
            "POST / HTTP/1.1\r\nContent-Length: 99999999999999999999999\r\n\r\n",
        ] {
            assert_eq!(head(bad), Parsed::Refused("content-length"), "{bad:?}");
        }
        for bad in [
            "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
            "POST / HTTP/1.1\r\ntransfer-encoding: identity\r\nContent-Length: 1\r\n\r\n",
        ] {
            assert_eq!(head(bad), Parsed::Refused("transfer-encoding"), "{bad:?}");
        }
        assert_eq!(
            complete("POST / HTTP/1.1\r\ncontent-LENGTH: 007\r\n\r\n").content_length,
            Some(7)
        );
    }

    #[test]
    fn only_http_1_1_is_served() {
        assert_eq!(
            head("GET / HTTP/1.0\r\n\r\n"),
            Parsed::Refused("http-version")
        );
        assert_eq!(head("GET / HTTP/2.0\r\n\r\n"), Parsed::Refused("malformed"));
        assert_eq!(head("GARBAGE\r\n\r\n"), Parsed::Refused("malformed"));
        assert_eq!(
            head("GET / HTTP/1.1\r\nbad header\r\n\r\n"),
            Parsed::Refused("malformed")
        );
    }
}
