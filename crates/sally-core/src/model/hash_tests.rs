#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use super::*;

/// SHA-256 of the empty input and of `abc` (FIPS 180-2 test vectors).
const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

#[test]
fn the_hasher_matches_the_test_vectors() {
    assert_eq!(Hasher::default().finish().as_hex(), EMPTY);
    let mut h = Hasher::default();
    h.update(b"abc");
    assert_eq!(h.finish().as_hex(), ABC);
}

/// Bytes fed in pieces hash the same as the bytes fed at once, and the count is of every byte.
#[test]
fn streaming_in_pieces_equals_one_pass() {
    let data: Vec<u8> = (0..=255u8).cycle().take(70_001).collect();
    let mut whole = Hasher::default();
    whole.update(&data);
    let mut pieces = Hasher::default();
    for chunk in data.chunks(4_093) {
        pieces.update(chunk);
    }
    assert_eq!(pieces.bytes(), 70_001);
    assert_eq!(whole.bytes(), 70_001);
    assert_eq!(pieces.finish(), whole.finish());
}

#[test]
fn bytes_counts_from_zero() {
    let mut h = Hasher::default();
    assert_eq!(h.bytes(), 0);
    h.update(b"ab");
    h.update(b"");
    h.update(b"c");
    assert_eq!(h.bytes(), 3);
}

#[test]
fn a_digest_parses_64_lowercase_hex() {
    let d = Digest::parse(ABC).unwrap();
    assert_eq!(d.as_hex(), ABC);
    assert_eq!(d.to_string(), ABC);
    for edge in [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "9999999999999999999999999999999999999999999999999999999999999999",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ] {
        assert_eq!(Digest::parse(edge).unwrap().as_hex(), edge);
    }
}

/// Anything but exactly 64 of `0-9a-f` is refused: it would name a file other than a blob.
#[test]
fn anything_else_is_not_a_digest() {
    let upper = ABC.to_ascii_uppercase();
    let short = &ABC[..63];
    let long = format!("{ABC}0");
    let mut bad = Vec::new();
    for c in [
        'g', 'G', 'A', 'F', '/', '.', ' ', '\0', '`', ':', '@', '{', 'é',
    ] {
        bad.push(format!("{c}{short}"));
        bad.push(format!("{short}{c}"));
    }
    for s in [
        "",
        short,
        long.as_str(),
        upper.as_str(),
        "../../../../../../../../../../../../../../../../../../../../etc/x",
    ]
    .into_iter()
    .map(str::to_owned)
    .chain(bad)
    {
        assert_eq!(Digest::parse(&s), Err(DigestError), "{s:?}");
    }
}

#[test]
fn the_error_has_a_stable_code_and_a_fixed_message() {
    assert_eq!(DigestError.code(), "bad_digest");
    assert_eq!(
        DigestError.to_string(),
        "a model digest is 64 lowercase hex digits (SHA-256)"
    );
}

/// The hasher's digest and a parsed digest compare equal, and digests sort by their hex.
#[test]
fn digests_compare_and_sort_by_hex() {
    let mut h = Hasher::default();
    h.update(b"abc");
    assert_eq!(h.finish(), Digest::parse(ABC).unwrap());
    let mut v = [Digest::parse(EMPTY).unwrap(), Digest::parse(ABC).unwrap()];
    v.sort();
    assert_eq!(v[0].as_hex(), ABC);
    assert_eq!(v[1].as_hex(), EMPTY);
}
