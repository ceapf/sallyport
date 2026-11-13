//! Redaction of secret values in audit arguments (SI-3, SI-4; ARCHITECTURE §7, Redaction).
//!
//! For every secret the redactor knows the raw value, its percent-encoding, and its base64 in
//! all three alignments and both alphabets, trimmed to the characters that depend only on the
//! secret and not on neighbouring bytes, so the base64 of *any* string containing the secret is
//! caught. Base64 patterns shorter than [`MIN_BASE64_PATTERN`] characters are skipped as too
//! collision-prone (the store warns when a value is under 16 bytes). Matches are replaced by
//! `[REDACTED:NAME]`.
//!
//! [`secret_forms`] gives the same forms to the token proxy's response redaction, so the two
//! cannot drift; the proxy adds the grant-specific ones itself: each injected header value, and
//! for a `{basic}` grant its [`basic_credential`] blob, padded and unpadded.

use std::borrow::Cow;
use std::fmt;
use std::sync::Arc;

use serde_json::{Map, Value};
use zeroize::Zeroizing;

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
        Self::build(secrets)
    }

    /// [`Self::new`]'s work, in a function cargo-mutants mutates (it leaves `new` alone; #87).
    fn build<'a>(secrets: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
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

    /// `s` with every known secret form replaced. All matches are located in the original
    /// text and overlapping ones merged before replacing, so two secrets that overlap are both
    /// removed whole (replacing one pattern at a time would let the first replacement eat
    /// characters of the second and leave part of it in the clear).
    #[must_use]
    pub fn redact_str<'s>(&self, s: &'s str) -> Cow<'s, str> {
        let mut hits: Vec<(usize, usize, &str)> = Vec::new();
        for p in &self.patterns {
            let needle = p.needle.expose().as_str();
            for (start, _) in s.match_indices(needle) {
                hits.push((
                    start,
                    start.saturating_add(needle.len()),
                    p.placeholder.as_str(),
                ));
            }
        }
        if hits.is_empty() {
            return Cow::Borrowed(s);
        }
        hits.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
        let mut out = String::with_capacity(s.len());
        let mut pos = 0usize;
        let mut open: Option<(usize, usize, &str)> = None;
        for (start, end, placeholder) in hits {
            open = match open {
                Some((os, oe, op)) if start < oe => Some((os, oe.max(end), op)),
                Some((os, oe, op)) => {
                    out.push_str(s.get(pos..os).unwrap_or_default());
                    out.push_str(op);
                    pos = oe;
                    Some((start, end, placeholder))
                }
                None => Some((start, end, placeholder)),
            };
        }
        if let Some((os, oe, op)) = open {
            out.push_str(s.get(pos..os).unwrap_or_default());
            out.push_str(op);
            out.push_str(s.get(oe..).unwrap_or_default());
        }
        Cow::Owned(out)
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
            Value::Object(o) => {
                let mut out = Map::new();
                for (k, x) in o {
                    let mut key = self.redact_str(k).into_owned();
                    // Two keys can redact to the same text; never drop a value silently.
                    let mut n = 2usize;
                    while out.contains_key(&key) {
                        key = format!("{}#{n}", self.redact_str(k));
                        n = n.saturating_add(1);
                    }
                    out.insert(key, self.value(x, depth + 1));
                }
                Value::Object(out)
            }
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

/// The forms of one session's secrets, built once at launch and shared, never copied: the type
/// can only be held through the [`Arc`] [`SessionForms::build`] returns, it has no `Clone`,
/// `Default` or `Serialize`, and every form is a [`Secret`], so the bytes are wiped when the last
/// holder drops. The egress proxy's response redaction reads them in place.
///
/// TODO(#81): the session registry registers the same `Arc` with the audit writer's redactor at
/// session start and drops it at stop (lane B, after Task 9a-3).
pub struct SessionForms {
    secrets: Vec<(String, Vec<Secret<String>>)>,
}

impl fmt::Debug for SessionForms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<(&str, usize)> = self
            .secrets
            .iter()
            .map(|(n, forms)| (n.as_str(), forms.len()))
            .collect();
        f.debug_struct("SessionForms")
            .field("secrets", &names)
            .finish()
    }
}

impl SessionForms {
    /// The forms of each `(name, value, extra)`: [`secret_forms`] of the value, then the `extra`
    /// forms the caller adds (such as the header value rendered from it). Names keep their first
    /// position; an entry repeating a name adds its forms to that name. Empty forms, and a form
    /// a name already has, are dropped (wiped).
    #[must_use]
    pub fn build<'a>(
        entries: impl IntoIterator<Item = (&'a str, &'a Secret<String>, Vec<Secret<String>>)>,
    ) -> Arc<Self> {
        let mut secrets: Vec<(String, Vec<Secret<String>>)> = Vec::new();
        for (name, value, extra) in entries {
            if !secrets.iter().any(|(n, _)| n == name) {
                secrets.push((name.to_owned(), Vec::new()));
            }
            let Some((_, forms)) = secrets.iter_mut().find(|(n, _)| n == name) else {
                continue;
            };
            for form in secret_forms(value.expose()).into_iter().chain(extra) {
                let known = forms.iter().any(|f| f.expose() == form.expose());
                if !form.expose().is_empty() && !known {
                    forms.push(form);
                }
            }
        }
        Arc::new(Self { secrets })
    }

    /// Each secret's name and its forms, in the order built.
    pub fn secrets(&self) -> impl Iterator<Item = (&str, &[Secret<String>])> {
        self.secrets.iter().map(|(n, f)| (n.as_str(), f.as_slice()))
    }
}

/// Every form of `value` the audit redactor replaces: the raw value, its percent-encodings, its
/// JSON-escaped form, and its trimmed base64 in both alphabets at all three alignments (forms
/// shorter than [`MIN_BASE64_PATTERN`] characters left out). Each form appears once; an empty
/// value has none.
#[must_use]
pub fn secret_forms(value: &str) -> Vec<Secret<String>> {
    if value.is_empty() {
        return Vec::new();
    }
    forms(value.as_bytes(), value)
        .into_iter()
        .map(Secret::new)
        .collect()
}

/// Every form of a secret worth redacting. Every intermediate that holds the secret or an
/// encoding of it is sized up front (so it never reallocates and leaves a copy behind) and wiped
/// when dropped; a form already in the list is dropped, wiped, too (Task 9a-3 review M1).
fn forms(bytes: &[u8], raw: &str) -> Vec<String> {
    let mut out = vec![raw.to_owned()];
    // Percent-encoding as real encoders produce it: both hex cases, `+` for space (forms), and
    // the characters common encoders leave alone (`/` for Python's `quote`, `!'()*` for
    // `encodeURIComponent`).
    for safe in [&b""[..], b"/", b"!'()*"] {
        for plus_space in [false, true] {
            for upper in [true, false] {
                let mut pct = percent_encode(bytes, upper, plus_space, safe);
                if !out.contains(&*pct) {
                    out.push(std::mem::take(&mut *pct));
                }
            }
        }
    }
    // The secret as it appears inside a JSON string (quotes and backslashes escaped): at most
    // six bytes per input byte (`\u00XX`) plus the quotes.
    let mut json = Zeroizing::new(Vec::with_capacity(
        bytes.len().saturating_mul(6).saturating_add(2),
    ));
    if serde_json::to_writer(&mut *json, raw).is_ok()
        && let Ok(text) = std::str::from_utf8(&json)
        && let Some(inner) = text.strip_prefix('"').and_then(|j| j.strip_suffix('"'))
        && !out.iter().any(|o| o == inner)
    {
        out.push(inner.to_owned());
    }
    for alphabet in [STANDARD, URL_SAFE] {
        for lead in 0..3usize {
            let mut data = Zeroizing::new(Vec::with_capacity(lead.saturating_add(bytes.len())));
            data.resize(lead, 0);
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

/// The `{basic}` credential of a grant: RFC 7617's padded standard base64 of
/// `user ":" secret`, the value a `Basic {basic}` header carries. It lives here, beside
/// [`secret_forms`], so the proxy renders it and redacts it with the one base64 encoder of the
/// workspace (architect ruling A2). Every intermediate is sized up front and wiped on drop.
#[must_use]
pub fn basic_credential(user: &str, secret: &str) -> Secret<String> {
    let mut joined = Zeroizing::new(Vec::with_capacity(
        user.len().saturating_add(1).saturating_add(secret.len()),
    ));
    joined.extend_from_slice(user.as_bytes());
    joined.push(b':');
    joined.extend_from_slice(secret.as_bytes());
    let mut encoded = base64_padded(&joined);
    Secret::new(std::mem::take(&mut *encoded))
}

/// Standard base64 with `=` padding to a multiple of four. The unpadded encoding is sized for
/// the padded length, so the padding never reallocates.
fn base64_padded(data: &[u8]) -> Zeroizing<String> {
    let mut out = base64_no_pad(data, STANDARD);
    while !out.len().is_multiple_of(4) {
        out.push('=');
    }
    out
}

/// Base64 without padding, in a buffer sized for it and wiped on drop.
fn base64_no_pad(data: &[u8], alphabet: &[u8; 64]) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(
        data.len().div_ceil(3).saturating_mul(4),
    ));
    for chunk in data.chunks(3) {
        let byte = |i: usize| chunk.get(i).copied().unwrap_or(0);
        let n = u32::from_be_bytes([0, byte(0), byte(1), byte(2)]);
        // A chunk of k bytes yields k + 1 characters.
        for i in 0..=chunk.len() {
            let idx = usize::try_from((n >> (18 - 6 * i)) & 63).unwrap_or(0);
            out.push(alphabet.get(idx).copied().map_or('=', char::from));
        }
    }
    out
}

/// RFC 3986 unreserved characters and `safe` kept, everything else `%XX` (a space is `+` when
/// `plus_space`, as in `application/x-www-form-urlencoded`).
/// The result is sized for the worst case (every byte `%XX`) and wiped on drop.
fn percent_encode(bytes: &[u8], upper: bool, plus_space: bool, safe: &[u8]) -> Zeroizing<String> {
    let digits: &[u8; 16] = if upper {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    let hex = |n: u8| char::from(digits.get(usize::from(n & 15)).copied().unwrap_or(b'0'));
    let mut out = Zeroizing::new(String::with_capacity(bytes.len().saturating_mul(3)));
    for &b in bytes {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) || safe.contains(&b) {
            out.push(char::from(b));
        } else if plus_space && b == b' ' {
            out.push('+');
        } else {
            out.push('%');
            out.push(hex(b >> 4));
            out.push(hex(b));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    fn s(v: &str) -> Secret<String> {
        Secret::new(v.to_owned())
    }

    fn exposed(f: &SessionForms) -> Vec<(String, Vec<String>)> {
        f.secrets()
            .map(|(n, forms)| {
                let forms = forms.iter().map(|x| x.expose().clone()).collect();
                (n.to_owned(), forms)
            })
            .collect()
    }

    #[test]
    fn session_forms_hold_each_secrets_forms_then_its_extras_once() {
        let a = s("a value/with space");
        let b = s("b-value");
        let f = SessionForms::build([
            ("A", &a, vec![s("Bearer a value/with space")]),
            ("B", &b, vec![s(""), s("b-value")]),
            ("A", &a, vec![s("Bearer a value/with space"), s("Token x")]),
        ]);
        let got = exposed(&f);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].0, "A");
        let mut want: Vec<String> = secret_forms("a value/with space")
            .iter()
            .map(|x| x.expose().clone())
            .collect();
        want.push("Bearer a value/with space".into());
        want.push("Token x".into());
        assert_eq!(got[0].1, want);
        assert_eq!(got[1], ("B".to_owned(), vec!["b-value".to_owned()]));
    }

    #[test]
    fn an_empty_value_has_only_its_extras() {
        let e = s("");
        let f = SessionForms::build([("E", &e, vec![s("x")])]);
        assert_eq!(exposed(&f), [("E".to_owned(), vec!["x".to_owned()])]);
    }

    /// RFC 4648 §10: every padding case (none, one `=`, two `=`) against independent vectors
    /// (architect ruling A2 condition 3).
    #[test]
    fn padded_base64_matches_the_rfc_4648_vectors() {
        for (data, want) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_padded(data.as_bytes()).as_str(), want, "{data}");
        }
    }

    /// RFC 7617 §2's example, and the user/secret split at the first byte of the secret.
    #[test]
    fn a_basic_credential_is_the_padded_base64_of_user_colon_secret() {
        assert_eq!(
            basic_credential("Aladdin", "open sesame").expose(),
            "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
        );
        // The user's bytes come first; three, four, five and six bytes in all.
        assert_eq!(basic_credential("f", "o").expose(), "Zjpv");
        assert_eq!(basic_credential("ab", "c").expose(), "YWI6Yw==");
        assert_eq!(basic_credential("ab", "cd").expose(), "YWI6Y2Q=");
        assert_eq!(basic_credential("git", "xy").expose(), "Z2l0Onh5");
    }

    #[test]
    fn session_forms_debug_names_secrets_and_counts_only() {
        let v = s("never-printed-value");
        let text = format!("{:?}", SessionForms::build([("N", &v, vec![])]));
        assert!(text.contains("\"N\""), "{text}");
        assert!(!text.contains("never-printed"), "{text}");
    }
}
