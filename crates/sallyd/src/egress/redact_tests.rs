//! The response redactor (Task 9a-3, decisions 2, 3 and 7 as ruled R2; architect Q6–Q13).
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::sync::Mutex;

use proptest::prelude::*;
use sally_core::secrets::Secret;

use super::*;

/// The forms given, exactly (an empty value has no forms of its own).
fn session(secrets: &[(&str, &[&str])]) -> Arc<SessionForms> {
    let empty = Secret::new(String::new());
    SessionForms::build(secrets.iter().map(|(name, forms)| {
        let forms = forms.iter().map(|f| Secret::new((*f).to_owned())).collect();
        (*name, &empty, forms)
    }))
}

fn redaction(secrets: &[(&str, &[&str])]) -> Arc<Redaction> {
    Arc::new(Redaction::of(session(secrets)).unwrap())
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn star(n: usize) -> String {
    "*".repeat(n)
}

const TOKEN: &str = "tok_abcdefghijklmnopqrstuvwxyz0123";

#[test]
fn a_raw_value_becomes_filler_of_the_same_length() {
    let r = redaction(&[("GITHUB_TOKEN", &[TOKEN])]);
    let out = r.bytes(format!("x={TOKEN};").as_bytes());
    assert_eq!(text(&out), format!("x={};", star(TOKEN.len())));
}

#[test]
fn bytes_outside_every_occurrence_are_untouched() {
    let r = redaction(&[("A", &["secret"])]);
    assert_eq!(r.bytes(b"no match, s3cret"), b"no match, s3cret");
    assert_eq!(text(&r.bytes(b"secretsecret!")), format!("{}!", star(12)));
}

/// The union of overlapping occurrences of two secrets goes, and each secret counts the bytes its
/// own occurrences cover: the counts sum past the total.
#[test]
fn overlapping_forms_of_two_secrets_are_both_removed_whole_and_each_counted() {
    let r = redaction(&[("A", &["abcdefgh"]), ("B", &["efghijklmnop"])]);
    let s = r.scan(b"<abcdefghijklmnop>");
    assert_eq!(text(&s.bytes), format!("<{}>", star(16)));
    assert_eq!(s.first, Some(1));
    assert_eq!(s.tally.total(), 16);
    assert_eq!(r.named(&s.tally), [("A".into(), 8), ("B".into(), 12)]);
}

#[test]
fn a_secret_with_nothing_covered_is_not_named() {
    let r = redaction(&[("A", &["aaaaaa"]), ("B", &["bbbbbb"])]);
    let s = r.scan(b"-bbbbbb-");
    assert_eq!(r.named(&s.tally), [("B".into(), 6)]);
    assert_eq!(r.named(&r.scan(b"none").tally), []);
}

#[test]
fn every_filler_candidate_is_a_visible_header_byte() {
    for c in FILLERS {
        assert!(c.is_ascii_graphic(), "{c}");
        assert!(HeaderValue::from_bytes(&[b'x', c, b'y']).is_ok(), "{c}");
        assert!(
            !c.is_ascii_alphanumeric() && !b"+/-_%\\\"".contains(&c),
            "{c}"
        );
    }
}

/// Architect Q7: no encoding sally-core produces adds a candidate a value lacks.
#[test]
fn a_value_without_a_candidate_has_no_form_holding_it() {
    let value = Secret::new("Ab0 /?&=+-_.%\"\\é'()".to_owned());
    let forms = SessionForms::build([("S", &value, vec![])]);
    let r = Redaction::of(forms).unwrap();
    assert_eq!(r.filler(), b'*');
    for (_, list) in r.forms().secrets() {
        for f in list {
            for c in FILLERS {
                assert!(!f.expose().as_bytes().contains(&c), "{c} in a form");
            }
        }
    }
}

/// Allow: the first candidate no form holds, with seven of eight held; deny: none qualifies.
#[test]
fn the_filler_is_the_first_candidate_no_form_holds() {
    assert_eq!(redaction(&[("A", &["plain"])]).filler(), b'*');
    let r = redaction(&[("A", &["x*y#"]), ("B", &["~^|!$q"])]);
    assert_eq!(r.filler(), b'@');
    assert_eq!(text(&r.bytes(b"-x*y#-")), "-@@@@-");
    assert_eq!(
        Redaction::of(session(&[("A", &["*#~^|!$@"])])).unwrap_err(),
        RedactionError::NoFiller
    );
}

#[test]
fn a_form_longer_than_the_bound_is_refused_naming_the_secret_before_the_filler() {
    let at = "x".repeat(MAX_FORM);
    let over = format!("{}{}", "x".repeat(MAX_FORM), "*#~^|!$@");
    assert!(Redaction::of(session(&[("A", &[&at])])).is_ok());
    assert_eq!(
        Redaction::of(session(&[("A", &[&over])])).unwrap_err(),
        RedactionError::TooLong(TooLong("A".into()))
    );
}

/// Architect Q11: the redaction reads the session's forms in place, never a copy.
#[test]
fn the_redaction_reads_the_session_forms_in_place() {
    let forms = session(&[("A", &["abcdefgh"])]);
    let r = Redaction::of(Arc::clone(&forms)).unwrap();
    let mine = forms.secrets().next().unwrap().1[0].expose().as_ptr();
    let read = r.forms().secrets().next().unwrap().1[0].expose().as_ptr();
    assert_eq!(mine, read);
    let weak = Arc::downgrade(&forms);
    drop(forms);
    assert!(weak.upgrade().is_some(), "the redaction holds them");
    drop(r);
    assert!(
        weak.upgrade().is_none(),
        "gone (wiped) with the last holder"
    );
}

#[test]
fn a_held_buffer_grows_by_replacing_itself() {
    let mut held = Zeroizing::new(Vec::with_capacity(4));
    append_wiped(&mut held, b"abc");
    assert_eq!(held.capacity(), 4);
    append_wiped(&mut held, b"de");
    assert_eq!(held.as_slice(), b"abcde");
    assert_eq!(held.capacity(), 8);
    append_wiped(&mut held, b"0123456789abcdef");
    assert_eq!(held.len(), 21);
    assert_eq!(held.capacity(), 21);
    // An exact fit keeps the buffer.
    let mut exact = Zeroizing::new(Vec::with_capacity(4));
    append_wiped(&mut exact, b"abcd");
    assert_eq!((exact.as_slice(), exact.capacity()), (&b"abcd"[..], 4));
}

#[test]
fn a_stream_holds_back_one_byte_less_than_the_longest_form() {
    let r = redaction(&[("A", &["0123456789"]), ("B", &["abc"])]);
    assert_eq!(r.longest(), 10);
    let mut s = r.stream();
    assert_eq!(s.push(b"xxxxxxxxxxxx"), b"xxx");
    assert_eq!(s.push(b"y"), b"x");
    assert_eq!(s.finish(), b"xxxxxxxxy");
    assert_eq!(s.finish(), b"");
}

/// Re-review L2: even with no form longer than one byte, the last byte waits for the end.
#[test]
fn a_stream_always_holds_back_its_last_byte() {
    for r in [redaction(&[("A", &[""])]), redaction(&[("A", &["q"])])] {
        let mut s = r.stream();
        assert_eq!(s.push(b"abc"), b"ab");
        assert_eq!(s.finish(), b"c");
    }
}

/// Re-review M3: touching occurrences merge into one pending range, and nothing stays pending
/// once everything is emitted.
#[test]
fn pending_ranges_merge_when_they_touch_and_empty_at_the_end() {
    let r = redaction(&[("A", &["ab", "xxxxxxxx"])]);
    let mut s = r.stream();
    assert_eq!(s.push(b"abab"), b"");
    assert_eq!(s.pending, [vec![(0, 4)]]);
    assert_eq!(s.finish(), b"****");
    assert!(s.pending.iter().all(Vec::is_empty), "{:?}", s.pending);
}

#[test]
fn a_stream_debug_shows_its_state_never_a_held_byte() {
    let r = redaction(&[("A", &["abcdefgh"])]);
    let mut s = r.stream();
    let _ = s.push(b"abcdefg");
    let d = format!("{s:?}");
    assert!(d.contains("held") && d.contains('7'), "{d}");
    assert!(!d.contains("abcdefg"), "{d}");
}

#[test]
fn an_occurrence_split_across_every_boundary_is_redacted() {
    let r = redaction(&[("GITHUB_TOKEN", &[TOKEN])]);
    let input = format!("head {TOKEN} tail");
    let whole = r.scan(input.as_bytes());
    for cut in 0..=input.len() {
        let mut s = r.stream();
        let mut out = s.push(&input.as_bytes()[..cut]);
        out.extend(s.push(&input.as_bytes()[cut..]));
        out.extend(s.finish());
        assert_eq!(out, whole.bytes, "cut at {cut}");
        assert_eq!(s.tally(), &whole.tally, "cut at {cut}");
    }
    assert!(!text(&whole.bytes).contains(TOKEN));
}

/// Architect Q13: only emitted bytes count; what a cut discards does not.
#[test]
fn a_tally_counts_emitted_bytes_only() {
    let r = redaction(&[("A", &["0123456789"])]);
    let mut s = r.stream();
    let out = s.push(b"0123456789abc");
    assert_eq!(out, b"****");
    assert_eq!(
        (s.tally().total(), r.named(s.tally())),
        (4, vec![("A".into(), 4)])
    );
    s.discard();
    assert_eq!(s.finish(), b"");
    assert_eq!(s.tally().total(), 4);
}

/// Re-review L2: a secret never counted equals one counted zero; a different total or any
/// different count is unequal.
#[test]
fn tallies_are_equal_only_when_every_count_and_the_total_are() {
    let tally = |bytes: &[u64], total| Tally {
        bytes: bytes.to_vec(),
        total,
    };
    assert_eq!(tally(&[], 0), tally(&[0], 0));
    assert_eq!(tally(&[3], 3), tally(&[3, 0], 3));
    assert_ne!(tally(&[3], 3), tally(&[3], 4), "the total");
    assert_ne!(tally(&[3, 1], 4), tally(&[3, 0], 4), "a count");
    assert_ne!(
        tally(&[3], 3),
        tally(&[3, 1], 3),
        "a count past the shorter list"
    );
}

#[test]
fn a_scan_reports_the_first_covered_byte() {
    let r = redaction(&[("A", &["*secret"])]);
    assert_eq!(r.filler(), b'#');
    assert_eq!(r.scan(b"ab*secret").first, Some(2));
    assert_eq!(r.scan(b"nothing here").first, None);
    let mut s = r.stream();
    let _ = s.push(b"0123456789");
    let _ = s.push(b"*secret");
    let _ = s.finish();
    assert_eq!(s.first_covered(), Some(10));
}

/// A body over a vector of frames, with a size hint of what is left.
struct Frames(Vec<Result<Frame<Bytes>, BoxError>>);

impl Body for Frames {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let v = &mut self.get_mut().0;
        Poll::Ready(if v.is_empty() {
            None
        } else {
            Some(v.remove(0))
        })
    }
    fn is_end_stream(&self) -> bool {
        self.0.is_empty()
    }
    fn size_hint(&self) -> SizeHint {
        let n: usize = self
            .0
            .iter()
            .filter_map(|f| f.as_ref().ok()?.data_ref().map(Bytes::len))
            .sum();
        SizeHint::with_exact(n as u64)
    }
}

/// Records each end reported; its work succeeds or fails as `ok` says (`None`: no work).
#[derive(Default)]
struct Rec {
    ends: Mutex<Vec<(Ending, u64)>>,
    ok: Option<bool>,
}

impl OnRedacted for Rec {
    fn ended(&self, how: Ending, tally: Tally) -> Option<Report> {
        self.ends.lock().unwrap().push((how, tally.total()));
        let ok = self.ok?;
        Some(Box::pin(async move { ok }))
    }
}

fn rec(ok: Option<bool>) -> Arc<Rec> {
    Arc::new(Rec {
        ok,
        ..Rec::default()
    })
}

fn body(
    frames: Vec<Result<Frame<Bytes>, BoxError>>,
    r: &Arc<Redaction>,
    on: &Arc<Rec>,
) -> Redacted<Frames> {
    let mut seed = Tally::default();
    seed.add(&r.scan(b"").tally);
    Redacted::new(
        Frames(frames),
        r,
        seed,
        Arc::clone(on) as Arc<dyn OnRedacted>,
    )
}

fn data(s: &str) -> Result<Frame<Bytes>, BoxError> {
    Ok(Frame::data(Bytes::from(s.to_owned())))
}

/// Polls `b` to its end: each frame's bytes, or the error's text.
fn drain(mut b: Redacted<Frames>) -> (Vec<String>, Option<String>) {
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut out = Vec::new();
    loop {
        match Pin::new(&mut b).poll_frame(&mut cx) {
            Poll::Ready(Some(Ok(f))) => out.push(text(&f.into_data().unwrap())),
            Poll::Ready(Some(Err(e))) => {
                assert!(b.is_end_stream());
                return (out, Some(e.to_string()));
            }
            Poll::Ready(None) => {
                assert!(b.is_end_stream());
                assert_eq!(b.size_hint().exact(), Some(0));
                return (out, None);
            }
            Poll::Pending => unreachable!("frames and reports are always ready"),
        }
    }
}

#[test]
fn a_redacted_body_streams_holds_back_and_reports_before_its_last_bytes() {
    let r = redaction(&[("A", &["0123456789"])]);
    let on = rec(Some(true));
    let b = body(vec![data("abcdef01234"), data("56789xyz")], &r, &on);
    assert!(!b.is_end_stream());
    assert_eq!(b.size_hint().exact(), Some(19));
    let (out, err) = drain(b);
    assert_eq!(err, None);
    // 11 bytes in, 9 held: "ab"; then 17 held, 9 kept: "cdef****"; then the rest at the end.
    assert_eq!(out, ["ab", "cdef****", "******xyz"]);
    assert_eq!(*on.ends.lock().unwrap(), [(Ending::Complete, 10)]);
}

/// Architect Q13: a report that fails turns the end into an error; nothing after it goes out.
#[test]
fn a_failed_report_withholds_the_last_bytes_and_errors() {
    let r = redaction(&[("A", &["0123456789"])]);
    let on = rec(Some(false));
    let (out, err) = drain(body(vec![data("abc0123456789")], &r, &on));
    assert_eq!(out, ["abc*"]);
    assert_eq!(err.as_deref(), Some(Unreported.to_string().as_str()));
}

#[test]
fn a_redacted_body_counts_held_bytes_in_its_size_hint() {
    let r = redaction(&[("A", &["0123456789"])]);
    let mut b = body(vec![data("abcdef"), data("ghij")], &r, &rec(None));
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(waker);
    // The first frame is all held: the body polls on to the second, which emits one byte.
    let f = Pin::new(&mut b).poll_frame(&mut cx);
    assert!(matches!(f, Poll::Ready(Some(Ok(_)))));
    assert_eq!(b.stream.held(), 9);
    assert_eq!(b.size_hint().exact(), Some(9));
}

/// A body of unknown length (a lower bound only) keeps an open upper bound.
#[test]
fn a_redacted_body_of_unknown_length_hints_a_lower_bound_only() {
    struct Open(Frames);
    impl Body for Open {
        type Data = Bytes;
        type Error = BoxError;
        fn poll_frame(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
            Pin::new(&mut self.get_mut().0).poll_frame(cx)
        }
        fn size_hint(&self) -> SizeHint {
            let mut h = SizeHint::new();
            h.set_lower(self.0.size_hint().lower());
            h
        }
    }
    let r = redaction(&[("A", &["0123456789"])]);
    let inner = Open(Frames(vec![data("abc"), data("defghijkl")]));
    let mut b = Redacted::new(inner, &r, Tally::default(), rec(None));
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(waker);
    assert_eq!((b.size_hint().lower(), b.size_hint().upper()), (12, None));
    let _ = Pin::new(&mut b).poll_frame(&mut cx);
    // "abc" + "defghijkl": 12 in, 9 held, 3 emitted; the inner has nothing left.
    assert_eq!(b.stream.held(), 9);
    assert_eq!((b.size_hint().lower(), b.size_hint().upper()), (9, None));
}

#[test]
fn a_redacted_body_drops_trailers_discards_held_bytes_and_reports_a_cut() {
    let r = redaction(&[("A", &["0123456789"])]);
    let mut trailers = hyper::HeaderMap::new();
    trailers.insert("x-t", "0123456789".parse().unwrap());
    let frames = vec![
        data("abcdefghij"),
        Ok(Frame::trailers(trailers)),
        Err("cut".into()),
        data("never"),
    ];
    let on = rec(Some(true));
    let (out, err) = drain(body(frames, &r, &on));
    assert_eq!(out, ["a"]);
    assert_eq!(err.as_deref(), Some("cut"));
    assert_eq!(*on.ends.lock().unwrap(), [(Ending::Cut, 0)]);
}

/// Architect Q13: a body dropped before its end still reports, with the counts so far.
#[test]
fn a_body_dropped_before_its_end_reports_it_once() {
    let r = redaction(&[("A", &["0123"])]);
    let on = rec(Some(true));
    let mut b = body(vec![data("0123xyzw"), data("more")], &r, &on);
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(waker);
    let _ = Pin::new(&mut b).poll_frame(&mut cx);
    drop(b);
    assert_eq!(*on.ends.lock().unwrap(), [(Ending::Dropped, 4)]);
    // A body whose end was reported by its head's handler reports nothing more.
    let quiet = rec(Some(true));
    drop(body(vec![], &r, &quiet).reported());
    assert!(quiet.ends.lock().unwrap().is_empty());
}

#[test]
fn an_empty_body_reported_at_its_head_is_at_its_end_before_it_is_polled() {
    let r = redaction(&[("A", &["0123456789"])]);
    let b = body(vec![], &r, &rec(None)).reported();
    assert!(b.is_end_stream());
    assert_eq!(b.size_hint().exact(), Some(0));
    // Not reported yet: polled once, to report its end.
    let on = rec(Some(true));
    let b = body(vec![], &r, &on);
    assert!(!b.is_end_stream());
    assert_eq!(drain(b), (Vec::new(), None));
    assert_eq!(*on.ends.lock().unwrap(), [(Ending::Complete, 0)]);
}

/// A report that has not finished: the last bytes wait for it, still counted in the size hint
/// (re-review M2), and go out once it succeeds.
#[test]
fn the_last_bytes_wait_for_a_pending_report() {
    struct Slow(Arc<std::sync::atomic::AtomicBool>);
    impl OnRedacted for Slow {
        fn ended(&self, _: Ending, _: Tally) -> Option<Report> {
            let done = Arc::clone(&self.0);
            Some(Box::pin(std::future::poll_fn(move |_| {
                if done.load(std::sync::atomic::Ordering::Relaxed) {
                    Poll::Ready(true)
                } else {
                    Poll::Pending
                }
            })))
        }
    }
    let r = redaction(&[("A", &["0123456789"])]);
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let on: Arc<dyn OnRedacted> = Arc::new(Slow(Arc::clone(&done)));
    let mut b = Redacted::new(Frames(vec![data("abc")]), &r, Tally::default(), on);
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(waker);
    assert!(Pin::new(&mut b).poll_frame(&mut cx).is_pending());
    assert!(!b.is_end_stream());
    assert_eq!(b.size_hint().exact(), Some(3));
    done.store(true, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(drain(b), (vec!["abc".to_owned()], None));
}

#[test]
fn a_redacted_body_of_held_bytes_only_ends_with_them() {
    let r = redaction(&[("A", &["0123456789"])]);
    let (out, err) = drain(body(vec![data("0123")], &r, &rec(Some(true))));
    assert_eq!((out, err), (vec!["0123".to_owned()], None));
}

#[test]
fn a_discarded_stream_holds_nothing() {
    let r = redaction(&[("A", &["0123456789"])]);
    let mut s = r.stream();
    let _ = s.push(b"01234");
    assert_eq!(s.held(), 5);
    s.discard();
    assert_eq!(s.held(), 0);
    assert_eq!(s.finish(), b"");
}

fn header_map(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut h = HeaderMap::new();
    for (n, v) in pairs {
        h.append(
            hyper::http::HeaderName::from_bytes(n.as_bytes()).unwrap(),
            HeaderValue::from_str(v).unwrap(),
        );
    }
    h
}

#[test]
fn header_values_are_redacted_in_place_counted_and_others_kept() {
    let r = redaction(&[("GITHUB_TOKEN", &[TOKEN])]);
    let h = header_map(&[
        ("x-echo", &format!("Bearer {TOKEN}")),
        ("x-echo", "plain"),
        ("content-type", "text/plain"),
    ]);
    let (out, tally) = headers(&r, &h).unwrap();
    let echo: Vec<_> = out.get_all("x-echo").iter().collect();
    assert_eq!(echo[0], format!("Bearer {}", star(TOKEN.len())).as_str());
    assert_eq!(echo[1], "plain");
    assert_eq!(out.get("content-type").unwrap(), "text/plain");
    assert_eq!(
        r.named(&tally),
        [("GITHUB_TOKEN".into(), TOKEN.len() as u64)]
    );
}

/// The check behind `in_lead_any_case` (architect D5): a first covered byte in the name or the
/// separator refuses the header; one at the value's first byte or later is redacted, unless the
/// result is no header value.
#[test]
fn a_covered_byte_before_the_value_is_refused_and_at_it_redacted() {
    let line = b"x: ##v";
    assert_eq!(redacted_value(line, 2, 3), Err(Echoed), "in the separator");
    assert_eq!(
        redacted_value(line, 3, 3),
        Ok(HeaderValue::from_static("##v")),
        "at the value"
    );
    assert_eq!(
        redacted_value(b"x: #\n", 3, 3),
        Err(Echoed),
        "no header value"
    );
}

#[test]
fn a_form_in_a_header_name_or_across_its_separator_is_refused() {
    let r = redaction(&[("A", &["abcdef", "c: de"])]);
    assert_eq!(headers(&r, &header_map(&[("x-abcdef", "1")])), Err(Echoed));
    assert_eq!(headers(&r, &header_map(&[("x-abc", "def")])), Err(Echoed));
    let (out, _) = headers(&r, &header_map(&[("x", "abcdef")])).unwrap();
    assert_eq!(out.get("x").unwrap(), "******");
}

/// Security review L2: hyper lower-cases names, so a form is looked for there in any case.
#[test]
fn a_mixed_case_form_in_a_header_name_is_refused() {
    let r = redaction(&[("A", &["AbCdEf", "C: De"])]);
    assert_eq!(headers(&r, &header_map(&[("x-AbCdEf", "1")])), Err(Echoed));
    assert_eq!(headers(&r, &header_map(&[("x-abc", "def")])), Err(Echoed));
    // Allow: the same letters in another case only in a value are not this secret.
    assert!(headers(&r, &header_map(&[("x", "abcdef")])).is_ok());
}

#[test]
fn a_redacted_value_keeps_the_bytes_outside_its_runs() {
    let r = redaction(&[("A", &["secret"])]);
    let mut h = HeaderMap::new();
    h.insert("x", HeaderValue::from_bytes(b"\xffsecret\x80").unwrap());
    let (out, _) = headers(&r, &h).unwrap();
    assert_eq!(out.get("x").unwrap().as_bytes(), b"\xff******\x80");
}

#[test]
fn debug_output_names_secrets_but_never_a_form() {
    let r = redaction(&[("A", &["abcdefgh"])]);
    let d = format!("{r:?} {:?}", r.stream());
    assert!(d.contains("\"A\""), "{d}");
    assert!(!d.contains("abcdefgh"), "{d}");
}

/// An independent redaction of `body` (decision 2), written plainly: every byte an occurrence
/// of a form covers becomes the filler; per secret, the bytes its occurrences cover; and the
/// covered bytes in all.
fn reference(
    secrets: &[(String, Vec<Vec<u8>>)],
    body: &[u8],
    filler: u8,
) -> (Vec<u8>, Vec<u64>, u64) {
    let mut covered = vec![false; body.len()];
    let mut counts = Vec::new();
    for (_, forms) in secrets {
        let mut mine = vec![false; body.len()];
        for f in forms.iter().filter(|f| !f.is_empty()) {
            for s in 0..body.len() {
                if body[s..].starts_with(f) {
                    mine[s..s + f.len()].fill(true);
                }
            }
        }
        counts.push(mine.iter().filter(|c| **c).count() as u64);
        for (c, m) in covered.iter_mut().zip(&mine) {
            *c |= *m;
        }
    }
    let out = body
        .iter()
        .zip(&covered)
        .map(|(b, c)| if *c { filler } else { *b })
        .collect();
    let total = covered.iter().filter(|c| **c).count() as u64;
    (out, counts, total)
}

fn occurs(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

/// Named secrets with their forms.
type Named = Vec<(String, Vec<String>)>;

/// Secrets drawn with the filler candidates in their alphabet (architect Q7: the selection is
/// exercised, not always `*`), a body of noise and forms, and a split of it into pieces.
fn case() -> impl Strategy<Value = (Named, Vec<u8>, Vec<usize>)> {
    let secret = "[a-c0-1*#~^|!$@]{1,12}";
    let secrets = proptest::collection::vec((secret, secret), 1..4);
    secrets.prop_flat_map(|pairs| {
        let forms: Vec<(String, Vec<String>)> = pairs
            .iter()
            .enumerate()
            .map(|(i, (a, b))| (format!("S{i}"), vec![a.clone(), b.clone()]))
            .collect();
        let all: Vec<String> = forms.iter().flat_map(|(_, f)| f.clone()).collect();
        let piece = prop_oneof![
            "[a-c0-1*#~^|!$@ ]{0,8}".prop_map(String::into_bytes),
            proptest::sample::select(all).prop_map(String::into_bytes),
        ];
        (
            Just(forms),
            proptest::collection::vec(piece, 0..12).prop_map(|p| p.concat()),
            proptest::collection::vec(0usize..40, 0..12),
        )
    })
}

/// One secret under the store's value rules (printable, no control characters), and a body
/// holding its sally-core forms and `base64(prefix ‖ secret ‖ suffix)` (ARCHITECTURE §7) in
/// both alphabets, between noise.
fn b1_case() -> impl Strategy<Value = (String, Vec<String>, Vec<u8>, Vec<usize>)> {
    (
        "[ -~]{16,40}",
        "[ -~]{0,5}",
        "[ -~]{0,5}",
        proptest::collection::vec(0usize..64, 0..10),
    )
        .prop_map(|(secret, pre, post, cuts)| {
            use base64::Engine as _;
            let wrapped = format!("{pre}{secret}{post}");
            let mut body = b"noise ".to_vec();
            for f in sally_core::audit::secret_forms(&secret) {
                body.extend_from_slice(f.expose().as_bytes());
                body.extend_from_slice(b" | ");
            }
            let encoded: Vec<String> = [
                base64::engine::general_purpose::STANDARD,
                base64::engine::general_purpose::URL_SAFE,
            ]
            .iter()
            .map(|e| e.encode(&wrapped))
            .collect();
            for e in &encoded {
                body.extend_from_slice(e.as_bytes());
                body.extend_from_slice(b" ; ");
            }
            (secret, encoded, body, cuts)
        })
}

fn split_run(r: &Arc<Redaction>, body: &[u8], cuts: &[usize]) -> (Vec<u8>, Tally) {
    let mut s = r.stream();
    let mut out = Vec::new();
    let mut rest = body;
    for c in cuts {
        let (piece, tail) = rest.split_at((*c).min(rest.len()));
        out.extend(s.push(piece));
        rest = tail;
    }
    out.extend(s.push(rest));
    out.extend(s.finish());
    (out, s.tally().clone())
}

proptest! {
    /// Decision 7 with the forms the proxy uses (architect D3): no sally-core form and no
    /// base64 of a string containing the secret survives any split, and the length is
    /// unchanged.
    #[test]
    fn no_sally_core_form_survives_any_split((secret, encoded, body, cuts) in b1_case()) {
        let value = Secret::new(secret.clone());
        let forms = SessionForms::build([("S", &value, vec![])]);
        let r = match Redaction::of(forms) {
            Ok(r) => Arc::new(r),
            Err(e) => {
                prop_assert_eq!(e, RedactionError::NoFiller);
                return Ok(());
            }
        };
        let (out, _) = split_run(&r, &body, &cuts);
        prop_assert_eq!(out.len(), body.len());
        prop_assert_eq!(&out, &r.bytes(&body));
        for f in sally_core::audit::secret_forms(&secret) {
            prop_assert!(!occurs(&out, f.expose().as_bytes()));
        }
        for e in &encoded {
            prop_assert!(!occurs(&out, e.as_bytes()), "{e} survived");
        }
        prop_assert!(!occurs(&out, secret.as_bytes()));
    }

    /// Decision 7, literal (R2): for any split of any response, no form survives, the length
    /// never changes, and the result and the per-secret counts equal an independent redaction's
    /// (architect Q13: each count at most the total, the total at most their sum). A session
    /// whose forms hold every candidate is refused instead.
    #[test]
    fn no_form_survives_any_split((secrets, body, cuts) in case()) {
        let names: Vec<(&str, Vec<&str>)> = secrets
            .iter()
            .map(|(n, f)| (n.as_str(), f.iter().map(String::as_str).collect()))
            .collect();
        let slices: Vec<(&str, &[&str])> = names.iter().map(|(n, f)| (*n, f.as_slice())).collect();
        let all: Vec<u8> = secrets.iter().flat_map(|(_, f)| f.concat().into_bytes()).collect();
        let r = match Redaction::of(session(&slices)) {
            Ok(r) => Arc::new(r),
            Err(e) => {
                prop_assert_eq!(e, RedactionError::NoFiller);
                prop_assert!(FILLERS.iter().all(|c| all.contains(c)));
                return Ok(());
            }
        };
        prop_assert!(!all.contains(&r.filler()));
        let (out, tally) = split_run(&r, &body, &cuts);
        let whole = r.scan(&body);
        prop_assert_eq!(&out, &whole.bytes);
        prop_assert_eq!(&tally, &whole.tally);
        let plain: Vec<(String, Vec<Vec<u8>>)> = secrets
            .iter()
            .map(|(n, f)| (n.clone(), f.iter().map(|x| x.as_bytes().to_vec()).collect()))
            .collect();
        let (want, counts, covered) = reference(&plain, &body, r.filler());
        prop_assert_eq!(&out, &want);
        for (_, forms) in &secrets {
            for f in forms {
                prop_assert!(!occurs(&out, f.as_bytes()), "{f} survived");
            }
        }
        let named = r.named(&tally);
        let expected: Vec<(String, u64)> = secrets
            .iter()
            .zip(&counts)
            .filter(|(_, c)| **c > 0)
            .map(|((n, _), c)| (n.clone(), *c))
            .collect();
        prop_assert_eq!(&named, &expected);
        let total = tally.total();
        prop_assert_eq!(total, covered);
        for (_, c) in &named {
            prop_assert!(*c <= total);
        }
        prop_assert!(total <= named.iter().map(|(_, c)| c).sum::<u64>());
    }
}
