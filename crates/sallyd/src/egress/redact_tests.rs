//! The response redactor (Task 9a-3, decisions 2, 3 and 7).
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use proptest::prelude::*;

use super::*;

fn form(s: &str) -> Secret<Vec<u8>> {
    Secret::new(s.as_bytes().to_vec())
}

fn redaction(secrets: &[(&str, &[&str])]) -> Arc<Redaction> {
    Arc::new(
        Redaction::new(
            secrets
                .iter()
                .map(|(name, forms)| ((*name).to_owned(), forms.iter().map(|f| form(f)).collect()))
                .collect(),
        )
        .unwrap(),
    )
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

const TOKEN: &str = "tok_abcdefghijklmnopqrstuvwxyz0123";

#[test]
fn a_raw_value_becomes_its_label_and_padding_of_the_same_length() {
    let r = redaction(&[("GITHUB_TOKEN", &[TOKEN])]);
    let input = format!("{{\"auth\":\"Bearer {TOKEN}\"}}");
    let out = r.bytes(input.as_bytes());
    assert_eq!(out.len(), input.len());
    let label = "[REDACTED:GITHUB_TOKEN]";
    let pad = "*".repeat(TOKEN.len() - label.len());
    assert_eq!(text(&out), format!("{{\"auth\":\"Bearer {label}{pad}\"}}"));
}

#[test]
fn a_run_shorter_than_the_label_gets_the_label_cut_to_its_length() {
    let r = redaction(&[("GITHUB_TOKEN", &["s3cr3t"])]);
    assert_eq!(text(&r.bytes(b"a s3cr3t b")), "a [REDAC b");
}

#[test]
fn bytes_outside_every_occurrence_are_untouched() {
    let r = redaction(&[("A", &["secretvalue"])]);
    assert_eq!(r.bytes(b"no secret here"), b"no secret here");
    assert_eq!(r.bytes(b""), b"");
}

#[test]
fn overlapping_forms_of_two_secrets_are_both_removed_whole() {
    // "abcdefgh" and "efghijkl" overlap in "efgh"; replacing one first would leave "ijkl".
    let r = redaction(&[("A", &["abcdefgh"]), ("B", &["efghijkl"])]);
    let out = r.bytes(b"<abcdefghijkl>");
    assert_eq!(text(&out), "<[REDACTED:A]>");
    let out = r.bytes(b"<abcdefghijklmnop>");
    assert_eq!(text(&out), "<[REDACTED:A]mnop>");
}

#[test]
fn adjacent_occurrences_form_one_run_with_the_first_label() {
    let r = redaction(&[("A", &["aaaa1111"]), ("B", &["bbbb2222"])]);
    let out = r.bytes(b"x aaaa1111bbbb2222 y");
    assert_eq!(text(&out), "x [REDACTED:A]**** y");
}

#[test]
fn a_run_takes_the_label_of_the_occurrence_that_starts_first() {
    let r = redaction(&[("LONGNAME", &["zzsecretzz"]), ("S", &["secret"])]);
    // "secret" alone: label S. Inside "zzsecretzz": the run starts with LONGNAME's occurrence.
    assert_eq!(text(&r.bytes(b"secret")), "[REDAC");
    assert_eq!(text(&r.bytes(b"zzsecretzz")), "[REDACTED:");
}

#[test]
fn occurrences_starting_together_take_the_longest_forms_label() {
    // Architect D1: same start, the longer form wins, whichever is given first.
    let r = redaction(&[("B", &["abcdefghij"]), ("A", &["abcdefghijklmn"])]);
    assert_eq!(text(&r.bytes(b"abcdefghijklmn")), "[REDACTED:A]**");
    let r = redaction(&[("A", &["abcdefghijklmn"]), ("B", &["abcdefghij"])]);
    assert_eq!(text(&r.bytes(b"abcdefghijklmn")), "[REDACTED:A]**");
    // Same start and length: the form given first.
    let r = redaction(&[("B", &["abcdefghij"]), ("A", &["abcdefghij"])]);
    assert_eq!(text(&r.bytes(b"abcdefghij")), "[REDACTED:");
    assert_eq!(text(&r.bytes(b"abcdefghijkl")), "[REDACTED:kl");
    let r = redaction(&[("XB", &["abcdefghijkl"]), ("A", &["abcdefghijkl"])]);
    assert_eq!(text(&r.bytes(b"abcdefghijkl")), "[REDACTED:XB");
}

#[test]
fn a_form_longer_than_the_bound_is_refused_naming_the_secret() {
    let at = vec![b'a'; MAX_FORM];
    let over = vec![b'a'; MAX_FORM + 1];
    assert!(Redaction::new(vec![("A".into(), vec![Secret::new(at)])]).is_ok());
    assert_eq!(
        Redaction::new(vec![("A".into(), vec![Secret::new(over)])]).unwrap_err(),
        TooLong("A".into())
    );
}

#[test]
fn a_held_buffer_grows_by_replacing_itself() {
    let mut held = Vec::with_capacity(4);
    append_wiped(&mut held, b"abc");
    assert_eq!(held.capacity(), 4);
    append_wiped(&mut held, b"de");
    assert_eq!(held, b"abcde");
    assert_eq!(held.capacity(), 8);
    append_wiped(&mut held, b"0123456789abcdef");
    assert_eq!(held.len(), 21);
    assert_eq!(held.capacity(), 21);
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

#[test]
fn a_stream_with_no_forms_holds_nothing_back() {
    let r = Arc::new(Redaction::new(vec![("A".into(), vec![form("")])]).unwrap());
    assert_eq!(r.longest(), 0);
    let mut s = r.stream();
    assert_eq!(s.push(b"abc"), b"abc");
    assert_eq!(s.finish(), b"");
}

#[test]
fn an_occurrence_split_across_every_boundary_is_redacted() {
    let r = redaction(&[("GITHUB_TOKEN", &[TOKEN])]);
    let input = format!("head {TOKEN} tail");
    let whole = r.bytes(input.as_bytes());
    for cut in 0..=input.len() {
        let mut s = r.stream();
        let mut out = s.push(&input.as_bytes()[..cut]);
        out.extend(s.push(&input.as_bytes()[cut..]));
        out.extend(s.finish());
        assert_eq!(out, whole, "cut at {cut}");
    }
    assert!(!text(&whole).contains(TOKEN));
}

#[test]
fn a_run_crossing_an_emit_boundary_keeps_its_label_offset() {
    let r = redaction(&[("A", &["0123456789"])]);
    let mut s = r.stream();
    // The first push completes the occurrence and emits 3 of its bytes; the rest follow.
    let mut out = s.push(b"0123456789");
    assert_eq!(out, b"[");
    out.extend(s.push(b"zzzzzzzzz"));
    out.extend(s.finish());
    // A 10-byte run gets the first 10 bytes of `[REDACTED:A]`, whatever the split.
    assert_eq!(text(&out), "[REDACTED:zzzzzzzzz");
}

#[test]
fn a_scan_reports_the_first_covered_byte_even_when_the_filler_matches_it() {
    let r = redaction(&[("A", &["[REDsecret"])]);
    // The first three filler bytes equal the original ones; the scan still reports them.
    assert_eq!(r.scan(b"ab[REDsecret"), (b"ab[REDACTED:".to_vec(), Some(2)));
    assert_eq!(r.scan(b"nothing here"), (b"nothing here".to_vec(), None));
    let mut s = r.stream();
    let _ = s.push(b"0123456789");
    let _ = s.push(b"[REDsecret");
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
            Poll::Pending => unreachable!("frames are always ready"),
        }
    }
}

#[test]
fn a_redacted_body_streams_holds_back_and_flushes_at_its_end() {
    let r = redaction(&[("A", &["0123456789"])]);
    let frames = vec![data("abcdef01234"), data("56789xyz")];
    let b = Redacted::new(Frames(frames), &r);
    assert!(!b.is_end_stream());
    assert_eq!(b.size_hint().exact(), Some(19));
    let (out, err) = drain(b);
    assert_eq!(err, None);
    // 11 bytes in, 9 held: "ab"; then 17 held, 9 kept: "cdef[RED"; then the rest at the end.
    assert_eq!(out, ["ab", "cdef[RED", "ACTED:xyz"]);
}

#[test]
fn a_redacted_body_counts_held_bytes_in_its_size_hint() {
    let r = redaction(&[("A", &["0123456789"])]);
    let mut b = Redacted::new(Frames(vec![data("abcdef"), data("ghij")]), &r);
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(waker);
    // The first frame is all held: the body polls on to the second, which emits one byte.
    let f = Pin::new(&mut b).poll_frame(&mut cx);
    assert!(matches!(f, Poll::Ready(Some(Ok(_)))));
    assert_eq!(b.stream.held(), 9);
    assert_eq!(b.size_hint().exact(), Some(9));
    let mut lower_only = SizeHint::new();
    lower_only.set_lower(3);
    assert_eq!(lower_only.upper(), None);
}

#[test]
fn a_redacted_body_drops_trailers_and_discards_held_bytes_on_an_error() {
    let r = redaction(&[("A", &["0123456789"])]);
    let mut trailers = hyper::HeaderMap::new();
    trailers.insert("x-t", "0123456789".parse().unwrap());
    let frames = vec![
        data("abcdefghij"),
        Ok(Frame::trailers(trailers)),
        Err("cut".into()),
        data("never"),
    ];
    let (out, err) = drain(Redacted::new(Frames(frames), &r));
    assert_eq!(out, ["a"]);
    assert_eq!(err.as_deref(), Some("cut"));
}

#[test]
fn an_empty_body_is_at_its_end_before_it_is_polled() {
    let r = redaction(&[("A", &["0123456789"])]);
    let b = Redacted::new(Frames(vec![]), &r);
    assert!(b.is_end_stream());
    assert_eq!(b.size_hint().exact(), Some(0));
    // An ended inner body with bytes still held is not at its end.
    let mut b = Redacted::new(Frames(vec![data("0123")]), &r);
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(waker);
    let _ = Pin::new(&mut b.inner).poll_frame(&mut cx);
    let _ = b.stream.push(b"0123");
    assert!(b.inner.is_end_stream());
    assert!(!b.is_end_stream());
    assert_eq!(b.size_hint().exact(), Some(4));
}

#[test]
fn a_redacted_body_of_held_bytes_only_ends_with_them() {
    let r = redaction(&[("A", &["0123456789"])]);
    let (out, err) = drain(Redacted::new(Frames(vec![data("0123")]), &r));
    assert_eq!((out, err), (vec!["0123".to_owned()], None));
    let (out, err) = drain(Redacted::new(Frames(vec![]), &r));
    assert_eq!((out, err), (Vec::<String>::new(), None));
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
fn header_values_are_redacted_in_place_and_others_kept() {
    let r = redaction(&[("GITHUB_TOKEN", &[TOKEN])]);
    let h = header_map(&[
        ("x-echo", &format!("Bearer {TOKEN}")),
        ("x-echo", "second"),
        ("content-type", "text/plain"),
    ]);
    let out = headers(&r, &h).unwrap();
    let echoes: Vec<_> = out.get_all("x-echo").iter().collect();
    assert_eq!(echoes.len(), 2);
    let first = echoes[0].to_str().unwrap();
    assert!(
        first.starts_with("Bearer [REDACTED:GITHUB_TOKEN]*"),
        "{first}"
    );
    assert_eq!(first.len(), "Bearer ".len() + TOKEN.len());
    assert_eq!(echoes[1], "second");
    assert_eq!(out.get("content-type").unwrap(), "text/plain");
}

#[test]
fn a_form_in_a_header_name_or_across_its_separator_is_refused() {
    let r = redaction(&[("A", &["leakedvalue"]), ("B", &["k: vvvvvvvvv"])]);
    // In the name.
    assert_eq!(
        headers(&r, &header_map(&[("x-leakedvalue", "1")])),
        Err(Echoed)
    );
    // Across the `: ` (the store allows `: ` inside a value).
    assert_eq!(
        headers(&r, &header_map(&[("x-k", "vvvvvvvvv")])),
        Err(Echoed)
    );
    // Starting right after the separator: redacted, not refused.
    let out = headers(&r, &header_map(&[("x", "leakedvalue")])).unwrap();
    assert_eq!(out.get("x").unwrap(), "[REDACTED:A");
}

/// The filler is visible ASCII and the bytes outside a run are the upstream's own, so a redacted
/// value stays a header value, obs-text included; the `Echoed` arm for one that is not is
/// defense in depth (architect D5).
#[test]
fn a_redacted_value_keeps_the_bytes_outside_its_runs() {
    let r = redaction(&[("A", &["abcdefghij"])]);
    let mut h = HeaderMap::new();
    h.insert("x", HeaderValue::from_bytes(b"\xffabcdefghij\x80").unwrap());
    let out = headers(&r, &h).unwrap();
    assert_eq!(out.get("x").unwrap().as_bytes(), b"\xff[REDACTED:\x80");
}

#[test]
fn debug_output_names_labels_but_never_a_form() {
    let r = redaction(&[("A", &["verysecretvalue"])]);
    let d = format!("{r:?} {:?}", r.stream());
    assert!(d.contains("[REDACTED:A]"));
    assert!(!d.contains("verysecretvalue"));
}

fn occurs(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

/// A body built from noise and forms of the secrets, and a split of it into pieces.
/// Named secrets with their forms.
type Named = Vec<(String, Vec<String>)>;

fn case() -> impl Strategy<Value = (Named, Vec<u8>, Vec<usize>)> {
    let secret = "[a-z0-9]{8,24}";
    let secrets = proptest::collection::vec((secret, secret), 1..4);
    secrets.prop_flat_map(|pairs| {
        let forms: Vec<(String, Vec<String>)> = pairs
            .iter()
            .enumerate()
            .map(|(i, (a, b))| (format!("S{i}"), vec![a.clone(), b.clone()]))
            .collect();
        let all: Vec<String> = forms.iter().flat_map(|(_, f)| f.clone()).collect();
        let piece = prop_oneof![
            "[a-z0-9 ]{0,12}".prop_map(String::into_bytes),
            proptest::sample::select(all).prop_map(String::into_bytes),
        ];
        (
            Just(forms),
            proptest::collection::vec(piece, 0..12).prop_map(|p| p.concat()),
            proptest::collection::vec(0usize..40, 0..12),
        )
    })
}

/// One secret under the store's value rules (printable, no control characters), its forms from
/// sally-core, and a body holding the forms and AMENDMENTS-02 B1's `base64(prefix ‖ secret ‖
/// suffix)` in both alphabets, between noise.
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

fn split_run(r: &Arc<Redaction>, body: &[u8], cuts: &[usize]) -> Vec<u8> {
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
    out
}

proptest! {
    /// Decision 7 with the forms the proxy uses (architect D3): every sally-core form and the
    /// B1 base64 of a string containing the secret are gone after any split, and the length is
    /// unchanged.
    #[test]
    fn no_sally_core_form_survives_any_split((secret, encoded, body, cuts) in b1_case()) {
        let forms = sally_core::audit::secret_forms(&secret);
        let bytes: Vec<Secret<Vec<u8>>> =
            forms.iter().map(|f| Secret::new(f.expose().as_bytes().to_vec())).collect();
        let r = Arc::new(Redaction::new(vec![("S".to_owned(), bytes)]).unwrap());
        let out = split_run(&r, &body, &cuts);
        prop_assert_eq!(out.len(), body.len());
        prop_assert_eq!(&out, &r.bytes(&body));
        for f in &forms {
            prop_assert!(!occurs(&out, f.expose().as_bytes()));
        }
        // B1: a trimmed form inside each base64 encoding of the wrapper is replaced.
        for e in &encoded {
            prop_assert!(!occurs(&out, e.as_bytes()), "{e} survived");
        }
        prop_assert!(!occurs(&out, secret.as_bytes()));
    }

    /// Decision 7: for any split of any response, no covered form survives, the length never
    /// changes, and the result equals the one-shot redaction.
    #[test]
    fn no_form_survives_any_split((secrets, body, cuts) in case()) {
        let r = Arc::new(Redaction::new(
            secrets
                .iter()
                .map(|(n, f)| (n.clone(), f.iter().map(|x| form(x)).collect()))
                .collect(),
        ).unwrap());
        let whole = r.bytes(&body);
        prop_assert_eq!(whole.len(), body.len());
        let out = split_run(&r, &body, &cuts);
        prop_assert_eq!(&out, &whole);
        for (_, forms) in &secrets {
            for f in forms {
                prop_assert!(!occurs(&out, f.as_bytes()), "{f} survived");
            }
        }
    }
}
