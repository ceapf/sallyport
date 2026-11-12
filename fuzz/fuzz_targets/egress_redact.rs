//! Fuzz target: the intercepted tunnel's response redaction (Task 9a-3; maintainer decision 7,
//! architect D10).
//!
//! The input gives a secret (mapped onto the store's value rules: printable ASCII, no space at
//! either end), a split pattern and a body; the body gets the secret's forms spliced in at
//! input-chosen places. Invariants: never panics; the output has the input's length; the
//! output is the same for the split and for one piece; a byte no occurrence covers (computed
//! here, independently) is the upstream's own and a covered one is filler, so the client learns
//! nothing of a covered byte but its run's label and length; no form survives: every form found
//! in the output holds at least one filler byte (a secret made of the label's characters and
//! `*` can be spelled again by filler beside the upstream's own bytes; THREAT_MODEL); header
//! redaction of the same bytes as a value never panics and keeps that length.
#![no_main]
#![forbid(unsafe_code)]

use std::sync::Arc;

use hyper::http::header::{HeaderMap, HeaderValue};
use libfuzzer_sys::fuzz_target;
use sally_core::secrets::Secret;
use sallyd::egress::redact::{Redaction, headers};

/// The store's value rules: printable ASCII, no leading or trailing space.
fn secret_from(bytes: &[u8]) -> String {
    let mut s: String = bytes
        .iter()
        .map(|b| char::from(0x21 + b % 94))
        .collect();
    if s.is_empty() {
        s.push('x');
    }
    s
}

/// Every position some occurrence of some pattern covers.
fn covered(hay: &[u8], patterns: &[&[u8]]) -> Vec<bool> {
    let mut mask = vec![false; hay.len()];
    for p in patterns.iter().filter(|p| !p.is_empty()) {
        for (start, w) in hay.windows(p.len()).enumerate() {
            if w == *p {
                mask[start..start + p.len()].iter_mut().for_each(|m| *m = true);
            }
        }
    }
    mask
}

/// Each occurrence of each pattern in `out` holds at least one filler byte.
fn each_holds_filler(out: &[u8], mask: &[bool], patterns: &[&[u8]]) -> bool {
    patterns.iter().filter(|p| !p.is_empty()).all(|p| {
        out.windows(p.len())
            .enumerate()
            .filter(|(_, w)| w == p)
            .all(|(start, _)| mask[start..start + p.len()].iter().any(|m| *m))
    })
}

const FILLER: &[u8] = b"[REDACTED:FUZZ]*";

fuzz_target!(|data: &[u8]| {
    let Some((&len, rest)) = data.split_first() else {
        return;
    };
    let Some((&seed, rest)) = rest.split_first() else {
        return;
    };
    let n = usize::from(len % 48) + 1;
    let (secret_bytes, rest) = rest.split_at(n.min(rest.len()));
    let secret = secret_from(secret_bytes);
    let forms = sally_core::audit::secret_forms(&secret);
    let rendered = format!("Bearer {secret}");
    let mut patterns: Vec<Secret<Vec<u8>>> = forms
        .iter()
        .map(|f| Secret::new(f.expose().as_bytes().to_vec()))
        .collect();
    patterns.push(Secret::new(rendered.as_bytes().to_vec()));
    let Ok(r) = Redaction::new(vec![("FUZZ".to_owned(), patterns)]) else {
        return;
    };
    let r = Arc::new(r);

    // The body: the rest of the input with forms spliced in where its bytes say.
    let mut body = Vec::with_capacity(rest.len() * 2);
    for (i, chunk) in rest.chunks(16).enumerate() {
        body.extend_from_slice(chunk);
        if let (Some(&pick), false) = (chunk.first(), forms.is_empty()) {
            if pick % 3 == 0 {
                let f = &forms[(usize::from(pick) + i) % forms.len()];
                body.extend_from_slice(f.expose().as_bytes());
            }
        }
    }

    let whole = r.bytes(&body);
    assert_eq!(whole.len(), body.len());

    // Any split gives the same bytes.
    let mut s = r.stream();
    let mut out = Vec::with_capacity(body.len());
    let mut at = 0usize;
    let mut k = usize::from(seed) | 1;
    while at < body.len() {
        let step = (k % 23).min(body.len() - at);
        out.extend(s.push(&body[at..at + step]));
        at += step;
        k = k.wrapping_mul(31).wrapping_add(7);
    }
    out.extend(s.finish());
    assert_eq!(out, whole);

    let mut all: Vec<&[u8]> = forms.iter().map(|f| f.expose().as_bytes()).collect();
    all.push(rendered.as_bytes());
    let mask = covered(&body, &all);
    for ((o, b), m) in out.iter().zip(&body).zip(&mask) {
        if *m {
            assert!(FILLER.contains(o), "a covered byte is not filler");
        } else {
            assert_eq!(o, b, "an uncovered byte changed");
        }
    }
    assert!(each_holds_filler(&out, &mask, &all), "a form survived");

    // The same bytes as a header value.
    if let Ok(v) = HeaderValue::from_bytes(&body) {
        let mut h = HeaderMap::new();
        h.insert("x-echo", v);
        if let Ok(red) = headers(&r, &h) {
            let got = red.get("x-echo").map(HeaderValue::as_bytes).unwrap_or_default();
            assert_eq!(got.len(), body.len());
        }
    }
});
