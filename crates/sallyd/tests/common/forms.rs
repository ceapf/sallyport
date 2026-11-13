//! The encodings of a secret an honest upstream may echo, computed here independently of
//! `sally_core::audit::secret_forms` (architect rulings A4, A5): RT-SEC-12's mock echoes them,
//! RT-SEC-07, RT-SEC-01 and RT-SEC-02 search for them. Percent-encoding and base64 follow RFC
//! 3986 and RFC 4648 as common encoders apply them; nothing here calls the code under test.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// The two base64 alphabets, standard first.
pub const ALPHABETS: [&[u8; 64]; 2] = [STANDARD, URL_SAFE];

/// Base64 of `data` in `alphabet`, padded with `=`.
pub fn b64(data: &[u8], alphabet: &[u8; 64]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = |i: usize| u32::from(chunk.get(i).copied().unwrap_or(0));
        let n = (b(0) << 16) | (b(1) << 8) | b(2);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(alphabet[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// How a percent-encoder spells the bytes it does not keep.
#[derive(Debug, Clone, Copy)]
pub struct Pct {
    /// `%2F` rather than `%2f`.
    pub upper: bool,
    /// A space as `+` (`application/x-www-form-urlencoded`).
    pub plus_space: bool,
    /// Kept as they are besides the unreserved characters (Python's `quote` keeps `/`).
    pub keep: &'static str,
}

/// Every percent-encoder spelling RT-SEC-12 echoes: both hex cases, `+` for a space, `/` kept.
pub const PCTS: [Pct; 4] = [
    Pct {
        upper: true,
        plus_space: false,
        keep: "",
    },
    Pct {
        upper: false,
        plus_space: false,
        keep: "",
    },
    Pct {
        upper: true,
        plus_space: true,
        keep: "",
    },
    Pct {
        upper: true,
        plus_space: false,
        keep: "/",
    },
];

/// `s` percent-encoded as `p` says: RFC 3986 unreserved characters kept, every other byte `%XX`.
pub fn pct(s: &str, p: Pct) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) || p.keep.as_bytes().contains(&b) {
            out.push(char::from(b));
        } else if p.plus_space && b == b' ' {
            out.push('+');
        } else if p.upper {
            out.push_str(&format!("%{b:02X}"));
        } else {
            out.push_str(&format!("%{b:02x}"));
        }
    }
    out
}

/// The characters of `base64(lead bytes ‖ secret ‖ anything)` that depend on the secret alone:
/// from the first that starts at or after the secret's first bit to the last that ends at or
/// before its last bit (RFC 4648 §4: six bits a character).
pub fn core_range(lead: usize, secret_len: usize) -> std::ops::Range<usize> {
    (8 * lead).div_ceil(6)..(8 * (lead + secret_len)) / 6
}

/// The secret-dependent core of `base64(lead bytes ‖ secret)` in `alphabet`, whatever bytes
/// precede it.
pub fn b64_core(secret: &str, lead: usize, alphabet: &[u8; 64]) -> String {
    let mut data = vec![b'A'; lead];
    data.extend_from_slice(secret.as_bytes());
    b64(&data, alphabet)[core_range(lead, secret.len())].to_owned()
}

/// RFC 7617's credential for `user` and `secret`: padded standard base64 of `user:secret`.
pub fn basic_blob(user: &str, secret: &str) -> String {
    b64(format!("{user}:{secret}").as_bytes(), STANDARD)
}

/// Every independently computed form of `secret`: the raw value, each [`PCTS`] spelling, and
/// the base64 core at all three alignments in both alphabets.
pub fn forms_of(secret: &str) -> Vec<String> {
    let mut out = vec![secret.to_owned()];
    out.extend(PCTS.iter().map(|p| pct(secret, *p)));
    for alphabet in ALPHABETS {
        for lead in 0..3 {
            out.push(b64_core(secret, lead, alphabet));
        }
    }
    out.sort();
    out.dedup();
    out
}

/// The forms a `{basic}` grant of `secret` adds: `Basic <blob>`, the padded blob and the blob
/// without its padding.
pub fn basic_forms(user: &str, secret: &str) -> Vec<String> {
    let blob = basic_blob(user, secret);
    vec![
        format!("Basic {blob}"),
        blob.trim_end_matches('=').to_owned(),
        blob,
    ]
}

/// What one line of the `/echo-forms` body is, and so which of its bytes must be filler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    /// The raw secret or one percent spelling: all of it.
    Whole,
    /// `base64(prefix ‖ secret ‖ suffix)`: the bytes in this range (the secret's core).
    Core(std::ops::Range<usize>),
    /// The blob without its padding, then a `"`: all but the last byte.
    AllButLast,
}

/// The `/echo-forms` lines before the echoed request, for `secret` and the `Basic` credential
/// `blob` the request carried: the raw secret, each percent spelling, `base64(prefix ‖ secret ‖
/// suffix)` padded for prefixes of 0, 1 and 2 bytes in both alphabets with a suffix of 1, 2 and
/// 3 bytes (architect ruling A4 conditions 3, 5), the padded blob, and the unpadded blob before
/// a `"`. No line holds a `\n`.
pub fn echo_lines(secret: &str, blob: &str) -> Vec<(String, Line)> {
    let mut out = vec![(secret.to_owned(), Line::Whole)];
    out.extend(PCTS.iter().map(|p| (pct(secret, *p), Line::Whole)));
    for alphabet in ALPHABETS {
        for lead in 0..3usize {
            let mut data = "<<".as_bytes()[..lead].to_vec();
            data.extend_from_slice(secret.as_bytes());
            data.extend_from_slice(&b">>>"[..lead + 1]);
            out.push((
                b64(&data, alphabet),
                Line::Core(core_range(lead, secret.len())),
            ));
        }
    }
    out.push((blob.to_owned(), Line::Whole));
    out.push((
        format!("{}\"", blob.trim_end_matches('=')),
        Line::AllButLast,
    ));
    out
}

/// The `/echo-forms` body: [`echo_lines`], each ending in `\n`, then the request it answers.
pub fn echo_body(secret: &str, blob: &str, request: &str) -> String {
    let mut body: String = echo_lines(secret, blob)
        .into_iter()
        .map(|(l, _)| l + "\n")
        .collect();
    body.push_str(request);
    body
}
