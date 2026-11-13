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
//! same for every split of the same input ([`Redaction::bytes`] is the one-shot form). Each push
//! scans only the windows that end in the new piece: an occurrence wholly inside the bytes held
//! before was marked by an earlier push. The bytes it holds may be part of a secret: they are
//! wiped when the stream drops, and a growing buffer wipes the one it replaces.
#![deny(clippy::indexing_slicing)]

use std::cmp::Reverse;
use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use hyper::body::{Body, Bytes, Frame, SizeHint};
use hyper::http::header::{HeaderMap, HeaderValue};
use sally_core::secrets::Secret;
use zeroize::{Zeroize, Zeroizing};

use super::meter::BoxError;

/// Fills a covered run past its label.
const PAD: u8 = b'*';
/// A held byte no occurrence covers.
const UNCOVERED: u32 = 0;
/// A held byte some occurrence covers, none starting at it. Otherwise a mark is `k + 1` for the
/// best-ranked form `k` that starts at the byte: the forms are sorted by architect D1's rank
/// (longer first, then the order given), so the lowest `k` wins. Only a run's first byte needs
/// its label, and every occurrence covering that byte starts at it.
const COVERED: u32 = u32::MAX;
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
        Self::from_forms(secrets)
    }

    /// [`Self::new`]'s work, in a function cargo-mutants mutates (it leaves `new` alone).
    fn from_forms(secrets: Vec<(String, Vec<Secret<Vec<u8>>>)>) -> Result<Self, TooLong> {
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
        // Architect D1's rank: the longer form first, then the order given (a stable sort).
        forms.sort_by_key(|f| Reverse(f.bytes.expose().len()));
        let longest = forms.first().map_or(0, |f| f.bytes.expose().len());
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
        self.scan(data).0
    }

    /// `data` with every covered byte replaced, and the offset of the first covered byte.
    #[must_use]
    pub fn scan(self: &Arc<Self>, data: &[u8]) -> (Vec<u8>, Option<u64>) {
        let mut s = self.stream();
        let mut out = s.push(data);
        out.extend(s.finish());
        (out, s.first_covered())
    }

    /// A stream over one body.
    #[must_use]
    pub fn stream(self: &Arc<Self>) -> Stream {
        Stream {
            redaction: Arc::clone(self),
            held: Zeroizing::new(Vec::new()),
            marks: Vec::new(),
            base: 0,
            run: None,
            first: None,
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

    /// The label of the run that starts at a byte marked `mark` (form `mark - 1` starts there).
    fn label(&self, mark: u32) -> usize {
        usize::try_from(mark.wrapping_sub(1))
            .ok()
            .and_then(|k| self.forms.get(k))
            .map_or(0, |f| f.label)
    }
}

/// The mark of form `k` starting at a byte.
fn rank(k: usize) -> u32 {
    u32::try_from(k)
        .ok()
        .and_then(|k| k.checked_add(1))
        .filter(|m| *m != COVERED)
        .unwrap_or(COVERED)
}

/// A start mark `new` merged into a byte's mark `old`: the best-ranked start wins.
fn best(old: u32, new: u32) -> u32 {
    if old == UNCOVERED { new } else { old.min(new) }
}

/// One body's redaction, fed in pieces.
pub struct Stream {
    redaction: Arc<Redaction>,
    /// Bytes not yet emitted, as received; wiped on drop.
    held: Zeroizing<Vec<u8>>,
    /// Per held byte: [`UNCOVERED`], [`COVERED`], or the start mark of the best form there.
    marks: Vec<u32>,
    /// The stream offset of `held[0]`.
    base: u64,
    /// The run the last emitted byte belongs to: its label and the next byte's offset in it.
    run: Option<(usize, usize)>,
    /// The stream offset of the first covered byte emitted.
    first: Option<u64>,
}

impl fmt::Debug for Stream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Stream")
            .field("held", &self.held.len())
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

impl Stream {
    /// Takes the next piece; returns the bytes no later occurrence can cover, redacted.
    #[must_use]
    pub fn push(&mut self, piece: &[u8]) -> Vec<u8> {
        let before = self.held.len();
        append_wiped(&mut self.held, piece);
        self.marks.resize(self.held.len(), UNCOVERED);
        self.mark(before);
        let keep = self.redaction.longest.saturating_sub(1);
        self.emit(self.held.len().saturating_sub(keep))
    }

    /// The end of the body: everything still held, redacted.
    #[must_use]
    pub fn finish(&mut self) -> Vec<u8> {
        self.emit(self.held.len())
    }

    /// The stream offset of the first covered byte emitted so far.
    #[must_use]
    pub const fn first_covered(&self) -> Option<u64> {
        self.first
    }

    /// Bytes held back, not yet emitted.
    #[must_use]
    pub fn held(&self) -> usize {
        self.held.len()
    }

    /// Drops everything held, wiped: the body failed or was cut, so nothing more is emitted.
    pub fn discard(&mut self) {
        self.held.zeroize();
        self.marks.clear();
    }

    /// Marks every byte that an occurrence lying wholly inside `held` and ending after its first
    /// `before` bytes covers (the others were marked by earlier pushes).
    fn mark(&mut self, before: usize) {
        for (k, form) in self.redaction.forms.iter().enumerate() {
            let needle = form.bytes.expose().as_slice();
            let from = before.saturating_sub(needle.len().saturating_sub(1));
            let Some(tail) = self.held.get(from..) else {
                continue;
            };
            for (j, window) in tail.windows(needle.len()).enumerate() {
                if window != needle {
                    continue;
                }
                let start = from.saturating_add(j);
                if let Some(m) = self.marks.get_mut(start) {
                    *m = best(*m, rank(k));
                }
                let rest = self.marks.iter_mut().skip(start.saturating_add(1));
                for m in rest.take(needle.len().saturating_sub(1)) {
                    if *m == UNCOVERED {
                        *m = COVERED;
                    }
                }
            }
        }
    }

    /// Emits the first `n` held bytes, covered ones as filler.
    fn emit(&mut self, n: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(n);
        for (i, (byte, mark)) in self.held.iter().zip(&self.marks).take(n).enumerate() {
            if *mark == UNCOVERED {
                self.run = None;
                out.push(*byte);
            } else {
                let pos = self
                    .base
                    .saturating_add(u64::try_from(i).unwrap_or(u64::MAX));
                self.first.get_or_insert(pos);
                let (label, at) = self.run.unwrap_or((self.redaction.label(*mark), 0));
                out.push(self.redaction.filler(label, at));
                self.run = Some((label, at.saturating_add(1)));
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

/// A response body redacted as it streams (architect D2). It wraps the capped body, so the cap
/// counts upstream bytes. Data frames pass through the [`Stream`]; any other frame is dropped. A
/// complete end flushes what is held; an error (the body failed or was cut at its cap) discards
/// it, wiped, and passes the error on.
pub struct Redacted<B> {
    inner: B,
    stream: Stream,
    done: bool,
}

impl<B> Redacted<B> {
    /// Redacts `inner` with `redaction`.
    pub fn new(inner: B, redaction: &Arc<Redaction>) -> Self {
        Self::over(inner, redaction)
    }

    /// [`Self::new`]'s work, in a function cargo-mutants mutates (it leaves `new` alone; #87).
    fn over(inner: B, redaction: &Arc<Redaction>) -> Self {
        Self {
            inner,
            stream: redaction.stream(),
            done: false,
        }
    }
}

impl<B> Body for Redacted<B>
where
    B: Body<Data = Bytes, Error = BoxError> + Unpin,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = self.get_mut();
        while !this.done {
            match ready!(Pin::new(&mut this.inner).poll_frame(cx)) {
                Some(Ok(frame)) => {
                    let Ok(data) = frame.into_data() else {
                        continue;
                    };
                    let out = this.stream.push(&data);
                    if !out.is_empty() {
                        return Poll::Ready(Some(Ok(Frame::data(Bytes::from(out)))));
                    }
                }
                Some(Err(e)) => {
                    this.done = true;
                    this.stream.discard();
                    return Poll::Ready(Some(Err(e)));
                }
                None => {
                    this.done = true;
                    let out = this.stream.finish();
                    if !out.is_empty() {
                        return Poll::Ready(Some(Ok(Frame::data(Bytes::from(out)))));
                    }
                }
            }
        }
        Poll::Ready(None)
    }

    /// Ended, or nothing more can come: the inner body is at its end and nothing is held (an
    /// empty body, such as a 304's, is then known empty before it is polled, as hyper needs).
    fn is_end_stream(&self) -> bool {
        self.done || (self.stream.held() == 0 && self.inner.is_end_stream())
    }

    fn size_hint(&self) -> SizeHint {
        if self.is_end_stream() {
            return SizeHint::with_exact(0);
        }
        let inner = self.inner.size_hint();
        let held = u64::try_from(self.stream.held()).unwrap_or(u64::MAX);
        let mut hint = SizeHint::new();
        hint.set_lower(inner.lower().saturating_add(held));
        if let Some(upper) = inner.upper() {
            hint.set_upper(upper.saturating_add(held));
        }
        hint
    }
}

/// A form of a session secret reaches into a header line's name or its `: ` separator, or the
/// redacted value is no header value (architect D5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a response header echoes a secret where it cannot be redacted")]
pub struct Echoed;

/// The response headers with every value redacted, each header scanned as the line hyper writes
/// (`name: value`, the name lower-cased), so a form that straddles the name and the value is
/// found (architect D5).
///
/// # Errors
/// [`Echoed`] when a covered byte lies in a name or its separator, or a redacted value is no
/// header value.
pub fn headers(r: &Arc<Redaction>, headers: &HeaderMap) -> Result<HeaderMap, Echoed> {
    let mut out = HeaderMap::with_capacity(headers.len());
    for (name, value) in headers {
        let lead = name.as_str().len().saturating_add(2);
        let mut line = Vec::with_capacity(lead.saturating_add(value.len()));
        line.extend_from_slice(name.as_str().as_bytes());
        line.extend_from_slice(b": ");
        line.extend_from_slice(value.as_bytes());
        let (redacted, first) = r.scan(&line);
        line.zeroize();
        let v = match first {
            None => value.clone(),
            Some(at) if at < u64::try_from(lead).unwrap_or(u64::MAX) => return Err(Echoed),
            Some(_) => HeaderValue::from_bytes(redacted.get(lead..).unwrap_or_default())
                .map_err(|_| Echoed)?,
        };
        out.append(name.clone(), v);
    }
    Ok(out)
}

/// Appends `piece` to `held`; a buffer too small is replaced by a larger one and the old one is
/// wiped as it drops, so no copy of held bytes is left behind in freed memory.
fn append_wiped(held: &mut Zeroizing<Vec<u8>>, piece: &[u8]) {
    let need = held.len().saturating_add(piece.len());
    if need > held.capacity() {
        let mut grown = Zeroizing::new(Vec::with_capacity(
            need.max(held.capacity().saturating_mul(2)),
        ));
        grown.extend_from_slice(held);
        *held = grown;
    }
    held.extend_from_slice(piece);
}

#[cfg(test)]
#[path = "redact_tests.rs"]
mod tests;
