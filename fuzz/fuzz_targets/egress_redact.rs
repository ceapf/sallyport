//! Fuzz target: the intercepted tunnel's response redaction (Task 9a-3; maintainer decision 7
//! as ruled R2, architect D10 and Q6-Q13).
//!
//! The input gives a secret (mapped onto the store's value rules: printable ASCII, no space at
//! either end), a split pattern and a body; the body gets the secret's forms spliced in at
//! input-chosen places. Invariants: never panics; a session whose forms hold every filler
//! candidate is refused, and only then; the output has the input's length and is the same for
//! the split and for one piece, and so are the counts; a byte no occurrence covers (computed
//! here, independently) is the upstream's own and a covered one is the filler, so the client
//! learns nothing of a covered byte but its run's length; no form occurs in the output
//! (literal); the counts equal the covered bytes; header redaction of the same bytes as a value
//! never panics, keeps that length, and leaves no form either.
#![no_main]
#![forbid(unsafe_code)]

use std::sync::Arc;

use hyper::http::header::{HeaderMap, HeaderValue};
use libfuzzer_sys::fuzz_target;
use sally_core::audit::SessionForms;
use sally_core::secrets::Secret;
use sallyd::egress::redact::{FILLERS, Redaction, RedactionError, headers};

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

fn occurs(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

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
    let value = Secret::new(secret.clone());
    let rendered = format!("Bearer {secret}");
    let session = SessionForms::build([("FUZZ", &value, vec![Secret::new(rendered.clone())])]);
    let mut all: Vec<Vec<u8>> = session
        .secrets()
        .flat_map(|(_, forms)| forms.iter().map(|f| f.expose().as_bytes().to_vec()))
        .collect();
    all.retain(|f| !f.is_empty());
    let r = match Redaction::of(session) {
        Ok(r) => Arc::new(r),
        Err(RedactionError::NoFiller) => {
            assert!(FILLERS.iter().all(|c| all.iter().any(|f| f.contains(c))));
            return;
        }
        Err(e) => panic!("{e}"),
    };
    let filler = r.filler();
    assert!(all.iter().all(|f| !f.contains(&filler)), "the filler is in a form");
    let first_free = FILLERS.iter().find(|c| all.iter().all(|f| !f.contains(c)));
    assert_eq!(first_free, Some(&filler), "not the first free candidate");

    // The body: the rest of the input with forms spliced in where its bytes say.
    let mut body = Vec::with_capacity(rest.len() * 2);
    for (i, chunk) in rest.chunks(16).enumerate() {
        body.extend_from_slice(chunk);
        if let Some(&pick) = chunk.first() {
            if pick % 3 == 0 {
                body.extend_from_slice(&all[(usize::from(pick) + i) % all.len()]);
            }
        }
    }

    let whole = r.scan(&body);
    assert_eq!(whole.bytes.len(), body.len());

    // Any split gives the same bytes and the same counts.
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
    assert_eq!(out, whole.bytes);
    assert_eq!(s.tally(), &whole.tally);

    let patterns: Vec<&[u8]> = all.iter().map(Vec::as_slice).collect();
    let mask = covered(&body, &patterns);
    for ((o, b), m) in out.iter().zip(&body).zip(&mask) {
        if *m {
            assert_eq!(*o, filler, "a covered byte is not the filler");
        } else {
            assert_eq!(o, b, "an uncovered byte changed");
        }
    }
    for f in &all {
        assert!(!occurs(&out, f), "a form survived");
    }
    let n_covered = mask.iter().filter(|m| **m).count() as u64;
    assert_eq!(whole.tally.total(), n_covered);
    let named = r.named(&whole.tally);
    assert_eq!(named.is_empty(), n_covered == 0);
    assert!(named.iter().all(|(n, c)| n == "FUZZ" && *c == n_covered));

    // The same bytes as a header value.
    if let Ok(v) = HeaderValue::from_bytes(&body) {
        let mut h = HeaderMap::new();
        h.insert("x-echo", v);
        if let Ok((red, _)) = headers(&r, &h) {
            let got = red.get("x-echo").map(HeaderValue::as_bytes).unwrap_or_default();
            assert_eq!(got.len(), body.len());
            for f in &all {
                assert!(!occurs(got, f), "a form survived in a header");
            }
        }
    }
});
