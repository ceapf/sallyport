//! Redaction of secret values in audit arguments (SI-3, SI-4; AMENDMENTS-02 B1).
//!
//! For every secret the redactor knows the raw value, its percent-encoding, and its base64 in
//! all three alignments and both alphabets, trimmed to the characters that depend only on the
//! secret and not on neighbouring bytes, so the base64 of *any* string containing the secret is
//! caught. Base64 patterns shorter than [`MIN_BASE64_PATTERN`] characters are skipped as too
//! collision-prone (the store warns when a value is under 16 bytes). Matches are replaced by
//! `[REDACTED:NAME]`.
//!
//! Grant-specific forms (the injected header value, the `{basic}` blob) belong to the token
//! proxy and are added there (M1 task 9b).

use std::borrow::Cow;
use std::fmt;

use serde_json::{Map, Value};

use crate::secrets::Secret;

/// Base64 patterns shorter than this many characters are not used.
pub const MIN_BASE64_PATTERN: usize = 12;
/// Nesting beyond this is replaced wholesale.
const MAX_DEPTH: usize = 32;
const DEEP_MARKER: &str = "[REDACTED:too-deep]";

const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

struct Pattern {
    needle: Secret<String>,
    placeholder: String,
}

/// Replaces secret values (and their encodings) in strings and JSON values.
pub struct Redactor {
    secrets: usize,
    /// Longest first, so a secret that contains another is replaced whole.
    patterns: Vec<Pattern>,
}

impl fmt::Debug for Redactor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Redactor")
            .field("secrets", &self.secrets)
            .field("patterns", &self.patterns.len())
            .finish()
    }
}

impl Default for Redactor {
    fn default() -> Self {
        Self::new(std::iter::empty())
    }
}

impl Redactor {
    /// Builds the pattern set for `(name, value)` pairs. Empty values are ignored.
    pub fn new<'a>(secrets: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        let mut count = 0;
        let mut patterns: Vec<Pattern> = Vec::new();
        for (name, value) in secrets {
            if value.is_empty() {
                continue;
            }
            count += 1;
            let placeholder = format!("[REDACTED:{name}]");
            for needle in forms(value.as_bytes(), value) {
                if !patterns.iter().any(|p| p.needle.expose() == &needle) {
                    patterns.push(Pattern {
                        needle: Secret::new(needle),
                        placeholder: placeholder.clone(),
                    });
                }
            }
        }
        patterns.sort_by_key(|p| std::cmp::Reverse(p.needle.expose().len()));
        Self {
            secrets: count,
            patterns,
        }
    }

    /// `s` with every known secret form replaced.
    #[must_use]
    pub fn redact_str<'s>(&self, s: &'s str) -> Cow<'s, str> {
        let mut out = Cow::Borrowed(s);
        for p in &self.patterns {
            if out.contains(p.needle.expose().as_str()) {
                out = Cow::Owned(out.replace(p.needle.expose().as_str(), &p.placeholder));
            }
        }
        out
    }

    /// `v` with every string, object key and number redacted. Numbers that spell a secret
    /// become strings.
    #[must_use]
    pub fn redact_value(&self, v: &Value) -> Value {
        self.value(v, 0)
    }

    fn value(&self, v: &Value, depth: usize) -> Value {
        if depth > MAX_DEPTH {
            return Value::String(DEEP_MARKER.to_owned());
        }
        match v {
            Value::String(s) => Value::String(self.redact_str(s).into_owned()),
            Value::Array(a) => Value::Array(a.iter().map(|x| self.value(x, depth + 1)).collect()),
            Value::Object(o) => Value::Object(
                o.iter()
                    .map(|(k, x)| (self.redact_str(k).into_owned(), self.value(x, depth + 1)))
                    .collect::<Map<String, Value>>(),
            ),
            Value::Number(n) => {
                let text = n.to_string();
                match self.redact_str(&text) {
                    Cow::Borrowed(_) => v.clone(),
                    Cow::Owned(r) => Value::String(r),
                }
            }
            Value::Bool(_) | Value::Null => v.clone(),
        }
    }
}

/// Every form of a secret worth redacting.
fn forms(bytes: &[u8], raw: &str) -> Vec<String> {
    let mut out = vec![raw.to_owned()];
    // Percent-encoding, both hex cases, and the form-encoding variant where a space is `+`.
    for plus_space in [false, true] {
        for upper in [true, false] {
            let pct = percent_encode(bytes, upper, plus_space);
            if !out.contains(&pct) {
                out.push(pct);
            }
        }
    }
    for alphabet in [STANDARD, URL_SAFE] {
        for lead in 0..3usize {
            let mut data = vec![0u8; lead];
            data.extend_from_slice(bytes);
            let encoded = base64_no_pad(&data, alphabet);
            // Characters wholly inside the secret's bits: from the first char that starts at
            // or after the secret, up to the last char that ends at or before its end.
            let start = (8 * lead).div_ceil(6);
            let end = (8 * (lead + bytes.len())) / 6;
            if let Some(p) = encoded
                .get(start..end)
                .filter(|p| p.len() >= MIN_BASE64_PATTERN)
                && !out.iter().any(|o| o == p)
            {
                out.push(p.to_owned());
            }
        }
    }
    out
}

fn base64_no_pad(data: &[u8], alphabet: &[u8; 64]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
        // A chunk of k bytes yields k + 1 characters.
        for i in 0..=chunk.len() {
            let idx = usize::try_from((n >> (18 - 6 * i)) & 63).unwrap_or(0);
            out.push(alphabet.get(idx).copied().map_or('=', char::from));
        }
    }
    out
}

/// RFC 3986 unreserved characters kept, everything else `%XX` (a space is `+` when
/// `plus_space`, as in `application/x-www-form-urlencoded`).
fn percent_encode(bytes: &[u8], upper: bool, plus_space: bool) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(char::from(b));
        } else if plus_space && b == b' ' {
            out.push('+');
        } else if upper {
            out.push_str(&format!("%{b:02X}"));
        } else {
            out.push_str(&format!("%{b:02x}"));
        }
    }
    out
}
