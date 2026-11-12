//! Response redaction inside intercepted tunnels (Task 9a-3; maintainer decisions 2, 3 and 7,
//! architect D1–D5).
//!
//! Every byte covered by an occurrence of any form of any of the session's secrets is replaced,
//! and nothing else: the output has the input's length, so framing and `Content-Length` never
//! change (decision 2). Occurrences are found in the *original* bytes and their union is
//! replaced, so overlapping forms of two secrets are both removed whole. A maximal run of
//! covered bytes is filled with the label `[REDACTED:NAME]` of the occurrence that starts it
//! (earliest start, then the longest form, then the first form given: architect D1), cut to the
//! run's length, then `*` up to its end.
//!
//! [`Stream`] does the same over a body that arrives in pieces: it holds back the last
//! `longest - 1` bytes (decision 3), the most an occurrence that is not yet complete can have
//! arrived of, and emits a byte only once no later occurrence can cover it. Its output is the
//! same for every split of the same input ([`Redaction::bytes`] is the one-shot form). The bytes
//! it holds may be part of a secret: they are wiped when the stream drops, and a growing buffer
//! wipes the one it replaces.

use std::cmp::Reverse;
use std::fmt;
use std::sync::Arc;

use sally_core::secrets::Secret;
use zeroize::Zeroize;

/// Fills a covered run past its label.
const PAD: u8 = b'*';
/// The longest form a redaction accepts: a store value is at most 8 KiB, its longest form (the
/// percent-encoding) three times that, and the injected header value adds its format's text.
pub const MAX_FORM: usize = 32 * 1024;

/// A form longer than [`MAX_FORM`]; names the secret, never the form.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("secret {0}: a form is longer than {MAX_FORM} bytes")]
pub struct TooLong(pub String);

/// One form of one secret, and the index of that secret's label.
struct Form {
    bytes: Secret<Vec<u8>>,
    label: usize,
}

/// The forms of a session's secrets and their labels. Built once per session; shared by every
/// tunnel's streams.
pub struct Redaction {
    forms: Vec<Form>,
    labels: Vec<String>,
    longest: usize,
}

impl fmt::Debug for Redaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Redaction")
            .field("labels", &self.labels)
            .field("forms", &self.forms.len())
            .field("longest", &self.longest)
            .finish()
    }
}

impl Redaction {
    /// The redaction of `(name, forms)` pairs. Empty forms are ignored; a name with no form
    /// keeps its label but never matches.
    ///
    /// # Errors
    /// [`TooLong`] when a form is longer than [`MAX_FORM`].
    pub fn new(secrets: Vec<(String, Vec<Secret<Vec<u8>>>)>) -> Result<Self, TooLong> {
        let mut forms = Vec::new();
        let mut labels = Vec::with_capacity(secrets.len());
        for (label, (name, list)) in secrets.into_iter().enumerate() {
            for bytes in list {
                if bytes.expose().len() > MAX_FORM {
                    return Err(TooLong(name));
                }
                if !bytes.expose().is_empty() {
                    forms.push(Form { bytes, label });
                }
            }
            labels.push(format!("[REDACTED:{name}]"));
        }
        let longest = forms
            .iter()
            .map(|f| f.bytes.expose().len())
            .max()
            .unwrap_or(0);
        Ok(Self {
            forms,
            labels,
            longest,
        })
    }

    /// The longest form, in bytes: a stream holds back one byte less.
    #[must_use]
    pub const fn longest(&self) -> usize {
        self.longest
    }

    /// `data` with every covered byte replaced.
    #[must_use]
    pub fn bytes(self: &Arc<Self>, data: &[u8]) -> Vec<u8> {
        let mut s = self.stream();
        let mut out = s.push(data);
        out.extend(s.finish());
        out
    }

    /// A stream over one body.
    #[must_use]
    pub fn stream(self: &Arc<Self>) -> Stream {
        Stream {
            redaction: Arc::clone(self),
            held: Vec::new(),
            marks: Vec::new(),
            base: 0,
            run: None,
        }
    }

    /// The filler byte `at` bytes into a run labelled `label`.
    fn filler(&self, label: usize, at: usize) -> u8 {
        self.labels
            .get(label)
            .and_then(|l| l.as_bytes().get(at))
            .copied()
            .unwrap_or(PAD)
    }

    /// The label of form `form`.
    fn label(&self, form: usize) -> usize {
        self.forms.get(form).map_or(0, |f| f.label)
    }
}

/// The occurrence that starts a byte's run, ordered as architect D1 ranks them: its stream
/// offset, then the longer form, then the form given first.
type Mark = Option<(u64, Reverse<usize>, usize)>;

/// One body's redaction, fed in pieces.
pub struct Stream {
    redaction: Arc<Redaction>,
    /// Bytes not yet emitted, as received.
    held: Vec<u8>,
    /// Per held byte: covered, and by which occurrence.
    marks: Vec<Mark>,
    /// The stream offset of `held[0]`.
    base: u64,
    /// The run the last emitted byte belongs to: its label and the next byte's offset in it.
    run: Option<(usize, usize)>,
}

impl fmt::Debug for Stream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Stream")
            .field("held", &self.held.len())
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        self.held.zeroize();
    }
}

impl Stream {
    /// Takes the next piece; returns the bytes no later occurrence can cover, redacted.
    pub fn push(&mut self, piece: &[u8]) -> Vec<u8> {
        append_wiped(&mut self.held, piece);
        self.marks.resize(self.held.len(), None);
        self.mark();
        let keep = self.redaction.longest.saturating_sub(1);
        self.emit(self.held.len().saturating_sub(keep))
    }

    /// The end of the body: everything still held, redacted.
    pub fn finish(&mut self) -> Vec<u8> {
        self.emit(self.held.len())
    }

    /// Marks every byte of `held` that an occurrence lying wholly inside it covers.
    fn mark(&mut self) {
        for (i, form) in self.redaction.forms.iter().enumerate() {
            let needle = form.bytes.expose().as_slice();
            for (start, window) in self.held.windows(needle.len()).enumerate() {
                if window == needle {
                    let at = self
                        .base
                        .saturating_add(u64::try_from(start).unwrap_or(u64::MAX));
                    let this = (at, Reverse(needle.len()), i);
                    for m in self.marks.iter_mut().skip(start).take(needle.len()) {
                        *m = first(*m, this);
                    }
                }
            }
        }
    }

    /// Emits the first `n` held bytes, covered ones as filler.
    fn emit(&mut self, n: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(n);
        for (byte, mark) in self.held.iter().zip(&self.marks).take(n) {
            match mark {
                None => {
                    self.run = None;
                    out.push(*byte);
                }
                Some((_, _, form)) => {
                    let (label, at) = self.run.unwrap_or((self.redaction.label(*form), 0));
                    out.push(self.redaction.filler(label, at));
                    self.run = Some((label, at.saturating_add(1)));
                }
            }
        }
        self.held.drain(..n);
        self.marks.drain(..n);
        self.base = self
            .base
            .saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        out
    }
}

/// The occurrence ranked first of `old` and `new`.
fn first(old: Mark, new: (u64, Reverse<usize>, usize)) -> Mark {
    match old {
        Some(o) if o <= new => Some(o),
        _ => Some(new),
    }
}

/// Appends `piece` to `held`; a buffer too small is replaced by a larger one and wiped, so no
/// copy of held bytes is left behind in freed memory.
fn append_wiped(held: &mut Vec<u8>, piece: &[u8]) {
    let need = held.len().saturating_add(piece.len());
    if need > held.capacity() {
        let mut grown = Vec::with_capacity(need.max(held.capacity().saturating_mul(2)));
        grown.extend_from_slice(held);
        held.zeroize();
        *held = grown;
    }
    held.extend_from_slice(piece);
}

#[cfg(test)]
#[path = "redact_tests.rs"]
mod tests;
