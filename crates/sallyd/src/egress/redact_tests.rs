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
