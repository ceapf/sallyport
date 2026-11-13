//! Response redaction inside intercepted tunnels (Task 9a-3; maintainer decisions 2, 3 and 7 as
//! ruled R2, architect D2–D5 and Q6–Q13).
//!
//! Every byte covered by an occurrence of any form of any of the session's secrets is replaced
//! by the session's filler byte, and nothing else: the output has the input's length, so framing
//! and `Content-Length` never change (decision 2). Occurrences are found in the *original* bytes
//! and their union is replaced, so overlapping forms of two secrets are both removed whole.
//!
//! The filler is the first of [`FILLERS`] that occurs in no form of the session (architect Q7);
//! a session where every candidate occurs is refused ([`RedactionError::NoFiller`]). So no form
//! survives redaction (decision 7, literal): an occurrence in the output that touches a replaced
//! byte holds the filler, which no form holds; one that touches none is the input's own bytes,
//! so it was found and replaced. The domain is one body, or one header line as [`headers`] scans
//! it (architect Q6).
//!
//! [`Stream`] does the same over a body that arrives in pieces: it holds back the last
//! `longest - 1` bytes (decision 3), the most an occurrence that is not yet complete can have
//! arrived of, and at least one, so a body's end always waits for its report; it emits a byte
//! only once no later occurrence can cover it. Its output is the
//! same for every split of the same input ([`Redaction::bytes`] is the one-shot form). Each push
//! scans only the windows that end in the new piece: an occurrence wholly inside the bytes held
//! before was marked by an earlier push. The bytes it holds may be part of a secret: they are
//! wiped when the stream drops, and a growing buffer wipes the one it replaces.
//!
//! A stream also counts, per secret, the emitted bytes that any occurrence of that secret's forms
//! covers, and the emitted filler bytes in all ([`Tally`]); the response's `egress.response`
//! entry carries them, names and counts only (architect Q13). Its memory for this is bounded by
//! the bytes it holds, never by the body's length.
#![deny(clippy::indexing_slicing)]

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use hyper::body::{Body, Bytes, Frame, SizeHint};
use hyper::http::header::{HeaderMap, HeaderValue};
use sally_core::audit::SessionForms;
use zeroize::{Zeroize, Zeroizing};

use super::meter::BoxError;

/// The filler candidates, in the order tried (architect Q7). Each is visible ASCII, so a
/// redacted header value stays a header value; and no encoding the forms use (base64,
/// percent-encoding, JSON escaping, a `{basic}` blob's padded standard base64) produces one
/// unless the raw value holds it.
pub const FILLERS: [u8; 8] = *b"*#~^|!$@";
/// The longest form a redaction accepts: a store value is at most 8 KiB, its longest form (the
/// percent-encoding) three times that, and the injected header value adds its format's text.
pub const MAX_FORM: usize = 32 * 1024;

/// A form longer than [`MAX_FORM`]; names the secret, never the form.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("secret {0}: a form is longer than {MAX_FORM} bytes")]
pub struct TooLong(pub String);

/// Why a session's forms cannot be redacted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RedactionError {
    /// A form is longer than [`MAX_FORM`].
    #[error(transparent)]
    TooLong(#[from] TooLong),
    /// Every filler candidate occurs in some form (architect Q8): no filler could be told from
    /// a secret. Names no secret: it is a property of them all.
    #[error("no redaction filler: every candidate occurs in a secret form")]
    NoFiller,
}

/// The forms of a session's secrets, read in place (architect Q11), and the session's filler.
/// Built once per session; shared by every tunnel's streams.
pub struct Redaction {
    forms: Arc<SessionForms>,
    filler: u8,
    longest: usize,
}

impl fmt::Debug for Redaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Redaction")
            .field("forms", &self.forms)
            .field("filler", &char::from(self.filler))
            .field("longest", &self.longest)
            .finish()
    }
}

impl Redaction {
    /// The redaction of `forms`, with the first filler candidate none of them holds.
    ///
    /// # Errors
    /// [`RedactionError::TooLong`] when a form is longer than [`MAX_FORM`] (checked first);
    /// [`RedactionError::NoFiller`] when every candidate occurs in a form.
    pub fn of(forms: Arc<SessionForms>) -> Result<Self, RedactionError> {
        let mut longest = 0;
        for (name, list) in forms.secrets() {
            for form in list {
                let len = form.expose().len();
                if len > MAX_FORM {
                    return Err(TooLong(name.to_owned()).into());
                }
                longest = longest.max(len);
            }
        }
        let filler = filler_for(&forms).ok_or(RedactionError::NoFiller)?;
        Ok(Self {
            forms,
            filler,
            longest,
        })
    }

    /// The forms this redaction reads (the same allocation the session built).
    #[must_use]
    pub const fn forms(&self) -> &Arc<SessionForms> {
        &self.forms
    }

    /// The byte every covered byte becomes.
    #[must_use]
    pub const fn filler(&self) -> u8 {
        self.filler
    }

    /// The longest form, in bytes: a stream holds back one byte less (at least one).
    #[cfg(test)]
    pub(crate) const fn longest(&self) -> usize {
        self.longest
    }

    /// `data` with every covered byte replaced.
    #[must_use]
    pub fn bytes(self: &Arc<Self>, data: &[u8]) -> Vec<u8> {
        self.scan(data).bytes
    }

    /// `data` redacted, with the offset of its first covered byte and what was redacted.
    #[must_use]
    pub fn scan(self: &Arc<Self>, data: &[u8]) -> Scan {
        let mut s = self.stream();
        let mut bytes = s.push(data);
        bytes.extend(s.finish());
        Scan {
            bytes,
            first: s.first_covered(),
            tally: s.tally().clone(),
        }
    }

    /// A stream over one body.
    #[must_use]
    pub fn stream(self: &Arc<Self>) -> Stream {
        Stream {
            redaction: Arc::clone(self),
            held: Zeroizing::new(Vec::new()),
            covered: Vec::new(),
            pending: Vec::new(),
            base: 0,
            first: None,
            tally: Tally::default(),
        }
    }

    /// Each secret's name with its count in `tally`, in grant order, the secrets with none left
    /// out.
    #[must_use]
    pub fn named(&self, tally: &Tally) -> Vec<(String, u64)> {
        self.forms
            .secrets()
            .zip(tally.bytes.iter().chain(std::iter::repeat(&0)))
            .filter(|(_, n)| **n > 0)
            .map(|((name, _), n)| (name.to_owned(), *n))
            .collect()
    }
}

/// The first of [`FILLERS`] that no form of `forms` holds.
fn filler_for(forms: &SessionForms) -> Option<u8> {
    FILLERS.iter().copied().find(|c| {
        !forms
            .secrets()
            .flat_map(|(_, list)| list)
            .any(|f| f.expose().as_bytes().contains(c))
    })
}

/// [`Redaction::scan`]'s result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scan {
    /// The redacted bytes.
    pub bytes: Vec<u8>,
    /// The offset of the first covered byte.
    pub first: Option<u64>,
    /// What was redacted.
    pub tally: Tally,
}

/// What a stream redacted: per secret (in grant order), the emitted bytes any occurrence of its
/// forms covers, and the emitted filler bytes in all (architect Q13). A byte two secrets cover
/// counts for both, so each secret's count is at most the total and the total at most their sum.
#[derive(Debug, Clone, Default)]
pub struct Tally {
    bytes: Vec<u64>,
    total: u64,
}

/// Equal when every secret's count and the total are: a secret never counted equals one
/// counted zero (re-review L2).
impl PartialEq for Tally {
    fn eq(&self, other: &Self) -> bool {
        let n = self.bytes.len().max(other.bytes.len());
        let at = |t: &Self, i: usize| t.bytes.get(i).copied().unwrap_or(0);
        self.total == other.total && (0..n).all(|i| at(self, i) == at(other, i))
    }
}

impl Eq for Tally {}

impl Tally {
    /// The bytes redacted in all.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.total
    }

    /// Adds `other`'s counts to these (a response's header lines and its body).
    pub fn add(&mut self, other: &Self) {
        let n = self.bytes.len().max(other.bytes.len());
        self.bytes.resize(n, 0);
        for (mine, theirs) in self.bytes.iter_mut().zip(&other.bytes) {
            *mine = mine.saturating_add(*theirs);
        }
        self.total = self.total.saturating_add(other.total);
    }

    fn count(&mut self, secret: usize, n: u64) {
        if self.bytes.len() <= secret {
            self.bytes.resize(secret.saturating_add(1), 0);
        }
        if let Some(c) = self.bytes.get_mut(secret) {
            *c = c.saturating_add(n);
        }
    }
}

/// One body's redaction, fed in pieces.
pub struct Stream {
    redaction: Arc<Redaction>,
    /// Bytes not yet emitted, as received; wiped on drop.
    held: Zeroizing<Vec<u8>>,
    /// Per held byte: whether an occurrence covers it.
    covered: Vec<bool>,
    /// Per secret: the stream ranges `[start, end)` its occurrences cover and that are not yet
    /// emitted, sorted and merged.
    pending: Vec<Vec<(u64, u64)>>,
    /// The stream offset of `held[0]`.
    base: u64,
    /// The stream offset of the first covered byte emitted.
    first: Option<u64>,
    tally: Tally,
}

impl fmt::Debug for Stream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Stream")
            .field("held", &self.held.len())
            .field("base", &self.base)
            .field("tally", &self.tally)
            .finish_non_exhaustive()
    }
}

impl Stream {
    /// Takes the next piece; returns the bytes no later occurrence can cover, redacted.
    #[must_use]
    pub fn push(&mut self, piece: &[u8]) -> Vec<u8> {
        let before = self.held.len();
        append_wiped(&mut self.held, piece);
        self.covered.resize(self.held.len(), false);
        self.mark(before);
        // At least one byte stays back, so a body's end always passes through `finish` and its
        // report, even when the longest form is one byte (re-review L2).
        let keep = self.redaction.longest.saturating_sub(1).max(1);
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

    /// What the bytes emitted so far redacted.
    #[must_use]
    pub const fn tally(&self) -> &Tally {
        &self.tally
    }

    /// Bytes held back, not yet emitted.
    #[must_use]
    pub fn held(&self) -> usize {
        self.held.len()
    }

    /// Drops everything held, wiped and uncounted: the body failed or was cut, so nothing more
    /// is emitted.
    pub fn discard(&mut self) {
        self.held.zeroize();
        self.covered.clear();
        self.pending.clear();
    }

    /// Marks every byte that an occurrence lying wholly inside `held` and ending after its first
    /// `before` bytes covers (the others were marked by earlier pushes), and records the
    /// occurrence's range for its secret.
    fn mark(&mut self, before: usize) {
        let redaction = Arc::clone(&self.redaction);
        for (secret, (_, forms)) in redaction.forms.secrets().enumerate() {
            for form in forms {
                let needle = form.expose().as_bytes();
                if needle.is_empty() {
                    continue;
                }
                let from = before.saturating_sub(needle.len().saturating_sub(1));
                let Some(tail) = self.held.get(from..) else {
                    continue;
                };
                let mut found = Vec::new();
                for (j, window) in tail.windows(needle.len()).enumerate() {
                    if window == needle {
                        found.push(from.saturating_add(j));
                    }
                }
                for start in found {
                    self.cover(secret, start, needle.len());
                }
            }
        }
    }

    /// An occurrence of `secret` covers `len` held bytes from `start`.
    fn cover(&mut self, secret: usize, start: usize, len: usize) {
        for c in self.covered.iter_mut().skip(start).take(len) {
            *c = true;
        }
        if self.pending.len() <= secret {
            self.pending.resize_with(secret.saturating_add(1), Vec::new);
        }
        let at = self.base.saturating_add(as_u64(start));
        let range = (at, at.saturating_add(as_u64(len)));
        if let Some(ranges) = self.pending.get_mut(secret) {
            ranges.push(range);
            ranges.sort_unstable();
            let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
            for &(s, e) in ranges.iter() {
                match merged.last_mut() {
                    Some(last) if s <= last.1 => last.1 = last.1.max(e),
                    _ => merged.push((s, e)),
                }
            }
            *ranges = merged;
        }
    }

    /// Emits the first `n` held bytes, covered ones as the filler, and counts them.
    fn emit(&mut self, n: usize) -> Vec<u8> {
        let filler = self.redaction.filler;
        let mut out = Vec::with_capacity(n);
        for (i, (byte, covered)) in self.held.iter().zip(&self.covered).take(n).enumerate() {
            if *covered {
                self.first
                    .get_or_insert(self.base.saturating_add(as_u64(i)));
                self.tally.total = self.tally.total.saturating_add(1);
                out.push(filler);
            } else {
                out.push(*byte);
            }
        }
        let end = self.base.saturating_add(as_u64(n));
        for (secret, ranges) in self.pending.iter_mut().enumerate() {
            let mut emitted = 0u64;
            ranges.retain_mut(|(s, e)| {
                emitted = emitted.saturating_add((*e).min(end).saturating_sub(*s));
                *s = (*s).max(end);
                *e > end
            });
            self.tally.count(secret, emitted);
        }
        self.held.drain(..n);
        self.covered.drain(..n);
        self.base = end;
        out
    }
}

fn as_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// How a [`Redacted`] body ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ending {
    /// The upstream body ended and everything was emitted.
    Complete,
    /// The body failed or was cut at its cap; what was held is discarded.
    Cut,
    /// The body was dropped before it ended (the client went away, the tunnel timed out or the
    /// session stopped).
    Dropped,
}

/// The work [`OnRedacted::ended`] returns: `true` once it succeeded.
pub type Report = Pin<Box<dyn Future<Output = bool> + Send>>;

/// Told once when a [`Redacted`] body ends or is dropped, with what it redacted (architect
/// Q13: the response's `egress.response` entry).
pub trait OnRedacted: Send + Sync + 'static {
    /// The body ended `how`, having redacted `tally`. For [`Ending::Complete`] and
    /// [`Ending::Cut`] the returned work finishes before the end reaches the client, and a
    /// `false` turns the end into an error. For [`Ending::Dropped`] there is nobody to wait: the
    /// returned work is dropped, so an implementation spawns what must still happen.
    fn ended(&self, how: Ending, tally: Tally) -> Option<Report>;
}

/// The error a [`Redacted`] body stops with when its end could not be reported.
#[derive(Debug, thiserror::Error)]
#[error("the response's audit entry could not be written")]
pub struct Unreported;

/// What a [`Redacted`] body returns once its end is reported.
enum Tail {
    Data(Bytes),
    End,
    Error(BoxError),
}

/// A response body redacted as it streams (architect D2). It wraps the capped body, so the cap
/// counts upstream bytes. Data frames pass through the [`Stream`]; any other frame is dropped. A
/// complete end flushes what is held; an error (the body failed or was cut at its cap) discards
/// it, wiped. Either way the end is reported ([`OnRedacted`]) before it reaches the client, and
/// a body dropped before its end reports that too.
pub struct Redacted<B> {
    inner: B,
    stream: Stream,
    /// What the response's header lines redacted.
    seed: Tally,
    on_end: Arc<dyn OnRedacted>,
    reported: bool,
    /// The report in flight and what follows it.
    reporting: Option<(Report, Tail)>,
    /// The final data frame went out; the end follows.
    last: bool,
    done: bool,
}

impl<B> Redacted<B> {
    /// Redacts `inner` with `redaction`; `seed` is what the head's redaction counted.
    pub fn new(
        inner: B,
        redaction: &Arc<Redaction>,
        seed: Tally,
        on_end: Arc<dyn OnRedacted>,
    ) -> Self {
        Self::over(inner, redaction, seed, on_end)
    }

    /// [`Self::new`]'s work, in a function cargo-mutants mutates (it leaves `new` alone; #87).
    fn over(
        inner: B,
        redaction: &Arc<Redaction>,
        seed: Tally,
        on_end: Arc<dyn OnRedacted>,
    ) -> Self {
        Self {
            inner,
            stream: redaction.stream(),
            seed,
            on_end,
            reported: false,
            reporting: None,
            last: false,
            done: false,
        }
    }

    /// The end was reported already (a body known empty at head time, whose entry the head's
    /// handler wrote): nothing more is reported.
    #[must_use]
    pub const fn reported(mut self) -> Self {
        self.reported = true;
        self
    }

    /// Reports `how` (once). With work to wait for, keeps it and `tail` and returns `None`;
    /// otherwise returns what `tail` releases.
    fn report(
        &mut self,
        how: Ending,
        tail: Tail,
    ) -> Option<Option<Result<Frame<Bytes>, BoxError>>> {
        let mut tally = self.seed.clone();
        tally.add(self.stream.tally());
        let work = if self.reported {
            None
        } else {
            self.reported = true;
            self.on_end.ended(how, tally)
        };
        match work {
            Some(w) => {
                self.reporting = Some((w, tail));
                None
            }
            None => Some(self.release(tail)),
        }
    }

    fn release(&mut self, tail: Tail) -> Option<Result<Frame<Bytes>, BoxError>> {
        match tail {
            Tail::Data(b) => {
                self.last = true;
                Some(Ok(Frame::data(b)))
            }
            Tail::End => {
                self.done = true;
                None
            }
            Tail::Error(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}

impl<B> Drop for Redacted<B> {
    fn drop(&mut self) {
        if !self.reported {
            self.reported = true;
            let mut tally = self.seed.clone();
            tally.add(self.stream.tally());
            drop(self.on_end.ended(Ending::Dropped, tally));
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
        loop {
            if let Some((work, _)) = this.reporting.as_mut() {
                let ok = ready!(work.as_mut().poll(cx));
                let Some((_, tail)) = this.reporting.take() else {
                    continue;
                };
                if !ok {
                    this.done = true;
                    return Poll::Ready(Some(Err(Box::new(Unreported))));
                }
                return Poll::Ready(this.release(tail));
            }
            if this.done {
                return Poll::Ready(None);
            }
            if this.last {
                this.done = true;
                return Poll::Ready(None);
            }
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
                    this.stream.discard();
                    if let Some(now) = this.report(Ending::Cut, Tail::Error(e)) {
                        return Poll::Ready(now);
                    }
                }
                None => {
                    let out = this.stream.finish();
                    let tail = if out.is_empty() {
                        Tail::End
                    } else {
                        Tail::Data(Bytes::from(out))
                    };
                    if let Some(now) = this.report(Ending::Complete, tail) {
                        return Poll::Ready(now);
                    }
                }
            }
        }
    }

    /// Ended, or nothing more can come: the end is reported, the inner body is at its end and
    /// nothing is held (an empty body, such as a 304's, is then known empty before it is
    /// polled, as hyper needs).
    fn is_end_stream(&self) -> bool {
        self.done
            || (self.reported
                && self.reporting.is_none()
                && !self.last
                && self.stream.held() == 0
                && self.inner.is_end_stream())
    }

    fn size_hint(&self) -> SizeHint {
        if self.is_end_stream() {
            return SizeHint::with_exact(0);
        }
        let inner = self.inner.size_hint();
        // Bytes held, or already taken out for the last frame a pending report holds back.
        let last = match &self.reporting {
            Some((_, Tail::Data(b))) => b.len(),
            _ => 0,
        };
        let held = as_u64(self.stream.held().saturating_add(last));
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

/// The response headers with every value redacted, and what was redacted. Each header is
/// scanned as the line hyper writes (`name: value`, the name lower-cased), so a form that
/// straddles the name and the value is found (architect D5); a form is also looked for in the
/// name and separator ignoring ASCII case, since hyper lower-cases what the upstream sent
/// (security review L2).
///
/// # Errors
/// [`Echoed`] when a covered byte lies in a name or its separator, or a redacted value is no
/// header value.
pub fn headers(r: &Arc<Redaction>, headers: &HeaderMap) -> Result<(HeaderMap, Tally), Echoed> {
    let mut out = HeaderMap::with_capacity(headers.len());
    let mut tally = Tally::default();
    for (name, value) in headers {
        let lead = name.as_str().len().saturating_add(2);
        let mut line = Zeroizing::new(Vec::with_capacity(lead.saturating_add(value.len())));
        line.extend_from_slice(name.as_str().as_bytes());
        line.extend_from_slice(b": ");
        line.extend_from_slice(value.as_bytes());
        if in_lead_any_case(r, &line, lead) {
            return Err(Echoed);
        }
        let scan = r.scan(&line);
        let v = match scan.first {
            None => value.clone(),
            Some(first) => redacted_value(&scan.bytes, first, lead)?,
        };
        tally.add(&scan.tally);
        out.append(name.clone(), v);
    }
    Ok((out, tally))
}

/// The value of a redacted header `line` whose first covered byte is at `first`: [`Echoed`]
/// when that byte lies in the name or separator (its first `lead` bytes) or what follows them
/// is no header value. [`in_lead_any_case`] refuses such a line first; this check stands on
/// its own.
fn redacted_value(line: &[u8], first: u64, lead: usize) -> Result<HeaderValue, Echoed> {
    if first < as_u64(lead) {
        return Err(Echoed);
    }
    HeaderValue::from_bytes(line.get(lead..).unwrap_or_default()).map_err(|_| Echoed)
}

/// Whether a form occurs in `line`, ignoring ASCII case, starting within its first `lead`
/// bytes (the name and the separator).
fn in_lead_any_case(r: &Redaction, line: &[u8], lead: usize) -> bool {
    r.forms.secrets().flat_map(|(_, list)| list).any(|form| {
        let needle = form.expose().as_bytes();
        line.windows(needle.len().max(1))
            .take(lead)
            .any(|w| !needle.is_empty() && w.eq_ignore_ascii_case(needle))
    })
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
