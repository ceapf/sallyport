#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use super::*;
use crate::hf::names::{Commit, RepoId, RepoPath, Revision};
use crate::hf::plan::{file_request, list_request};

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

fn file(from: u64) -> Request {
    file_request(
        &RepoId::parse("a/b").unwrap(),
        &Commit::parse(SHA).unwrap(),
        &RepoPath::parse("m.gguf").unwrap(),
        from,
    )
}

fn list() -> Request {
    list_request(&RepoId::parse("a/b").unwrap(), &Revision::main())
}

fn head(status: u16) -> Head<'static> {
    Head {
        status,
        content_length: None,
        content_range: None,
        location: None,
        retry_after: None,
        content_encoding: false,
    }
}

/// A 200 to a fresh file request with the listed length is the body from byte 0; to a range
/// request it starts the file again.
#[test]
fn a_full_200_is_the_body() {
    let mut t = Tries::default();
    let h = Head {
        content_length: Some("100"),
        ..head(200)
    };
    assert_eq!(
        decide_file(&h, &file(0), &mut t, 0, 100),
        Ok(Step::Body(Body::Append))
    );
    assert_eq!(
        decide_file(&h, &file(40), &mut t, 40, 100),
        Ok(Step::Body(Body::FromStart))
    );
}

/// A 200 whose length is missing or not the listed size is refused, keeping the partial.
#[test]
fn a_200_of_another_length_is_refused() {
    for cl in [
        None,
        Some("99"),
        Some("101"),
        Some(""),
        Some("+100"),
        Some("1e2"),
    ] {
        let h = Head {
            content_length: cl,
            ..head(200)
        };
        let err = decide_file(&h, &file(0), &mut Tries::default(), 0, 100).unwrap_err();
        assert_eq!(err, HfError::LengthMismatch, "{cl:?}");
        assert!(!err.discards_partial());
    }
}

/// A 206 with exactly the range asked for appends; any other range, total or length, or a 206
/// not asked for, is refused and the partial deleted.
#[test]
fn a_206_must_be_exactly_the_rest() {
    let ok = Head {
        content_range: Some("bytes 40-99/100"),
        content_length: Some("60"),
        ..head(206)
    };
    let mut t = Tries::default();
    assert_eq!(
        decide_file(&ok, &file(40), &mut t, 40, 100),
        Ok(Step::Body(Body::Append))
    );
    let no_len = Head {
        content_length: None,
        ..ok
    };
    assert_eq!(
        decide_file(&no_len, &file(40), &mut t, 40, 100),
        Ok(Step::Body(Body::Append))
    );
    for (cr, cl) in [
        (Some("bytes 41-99/100"), None),
        (Some("bytes 40-98/100"), None),
        (Some("bytes 40-99/101"), None),
        (Some("bytes 40-99/*"), None),
        (Some("bytes */100"), None),
        (Some("items 40-99/100"), None),
        (Some("bytes 40-99/100 "), None),
        (None, None),
        (Some("bytes 40-99/100"), Some("59")),
    ] {
        let h = Head {
            content_range: cr,
            content_length: cl,
            ..head(206)
        };
        let err = decide_file(&h, &file(40), &mut t, 40, 100).unwrap_err();
        assert_eq!(err, HfError::RangeMismatch, "{cr:?} {cl:?}");
        assert!(err.discards_partial());
    }
    let unasked = Head {
        content_range: Some("bytes 0-99/100"),
        ..head(206)
    };
    assert_eq!(
        decide_file(&unasked, &file(0), &mut t, 0, 100),
        Err(HfError::RangeMismatch)
    );
}

/// 416, and any Content-Encoding on a file, are refused and the partial deleted.
#[test]
fn a_416_or_an_encoding_discards_the_partial() {
    let mut t = Tries::default();
    let err = decide_file(&head(416), &file(40), &mut t, 40, 100).unwrap_err();
    assert_eq!(err, HfError::RangeNotSatisfiable);
    let enc = Head {
        content_length: Some("100"),
        content_encoding: true,
        ..head(200)
    };
    let err = decide_file(&enc, &file(0), &mut t, 0, 100).unwrap_err();
    assert_eq!(err, HfError::ContentEncoding);
    assert!(err.discards_partial());
}

/// Redirects are followed up to the bound, and the Location goes through the plan's rules.
#[test]
fn redirects_are_bounded_and_checked() {
    let h = Head {
        location: Some("https://cdn-lfs.hf.co/x"),
        ..head(302)
    };
    let mut t = Tries::default();
    for status in [301, 302, 303] {
        let h = Head { status, ..h };
        match decide_file(&h, &file(5), &mut t, 5, 100).unwrap() {
            Step::Redirect(next) => {
                assert_eq!(next.host(), "cdn-lfs.hf.co");
                assert_eq!(next.range_from(), Some(5));
            }
            other => panic!("{other:?}"),
        }
    }
    let h4 = Head { status: 307, ..h };
    assert_eq!(
        decide_file(&h4, &file(5), &mut t, 5, 100),
        Err(HfError::TooManyRedirects)
    );
    let mut t = Tries::default();
    let h308 = Head {
        status: 308,
        location: Some("/api/models/a/b/revision/main?blobs=true"),
        ..h
    };
    assert!(matches!(
        decide_list(&h308, &list(), &mut t),
        Ok(Step::Redirect(_))
    ));
    let none = head(302);
    assert_eq!(
        decide_file(&none, &file(0), &mut t, 0, 100),
        Err(HfError::RedirectRefused)
    );
    let evil = Head {
        location: Some("https://evil.test/x"),
        ..head(302)
    };
    assert_eq!(
        decide_list(&evil, &list(), &mut t),
        Err(HfError::RedirectRefused)
    );
    let other3xx = Head {
        location: Some("https://hf.co/x"),
        ..head(300)
    };
    assert_eq!(
        decide_list(&other3xx, &list(), &mut t),
        Err(HfError::UpstreamStatus(300))
    );
}

/// The file list, which carries the publisher's hashes, is read from the API host only: a
/// redirect of the list call to any other Hub host is refused. Control: a relative Location and
/// an absolute one on the API host are followed, with the token.
#[test]
fn a_list_redirect_off_the_api_host_is_refused() {
    for off in [
        "https://cdn-lfs.hf.co/api/models/a/b/revision/main?blobs=true",
        "https://hf.co/x",
        "https://cdn-lfs.huggingface.co/x",
    ] {
        let h = Head {
            location: Some(off),
            ..head(308)
        };
        let mut t = Tries::default();
        assert_eq!(
            decide_list(&h, &list(), &mut t),
            Err(HfError::RedirectRefused),
            "{off}"
        );
    }
    // The API host only, not the same host only: a list call already off it is refused even
    // when the next Location stays on its host.
    let off_host = crate::hf::plan::redirect(&list(), "https://cdn-lfs.hf.co/x").unwrap();
    let relative = Head {
        location: Some("/y"),
        ..head(302)
    };
    let mut t = Tries::default();
    assert_eq!(
        decide_list(&relative, &off_host, &mut t),
        Err(HfError::RedirectRefused)
    );
    for on in [
        "/api/models/a/b/revision/main?blobs=true",
        "https://huggingface.co/x",
    ] {
        let h = Head {
            location: Some(on),
            ..head(302)
        };
        let mut t = Tries::default();
        match decide_list(&h, &list(), &mut t) {
            Ok(Step::Redirect(next)) => {
                assert_eq!(next.host(), "huggingface.co", "{on}");
                assert!(next.carries_auth(), "{on}");
            }
            other => panic!("{on}: {other:?}"),
        }
    }
}

/// 429, or 503 with Retry-After, waits at most 60 s, at most three times, then is refused.
#[test]
fn rate_limits_wait_and_are_bounded() {
    let mut t = Tries::default();
    let h = Head {
        retry_after: Some("7"),
        ..head(429)
    };
    assert_eq!(decide_list(&h, &list(), &mut t), Ok(Step::Wait(7)));
    let long = Head {
        retry_after: Some("3600"),
        ..head(503)
    };
    assert_eq!(
        decide_file(&long, &file(0), &mut t, 0, 9),
        Ok(Step::Wait(60))
    );
    assert_eq!(
        decide_list(&head(429), &list(), &mut t),
        Ok(Step::Wait(DEFAULT_RETRY_WAIT_SECS))
    );
    assert_eq!(decide_list(&h, &list(), &mut t), Err(HfError::RateLimited));
    let mut t = Tries::default();
    assert_eq!(
        decide_list(&head(503), &list(), &mut t),
        Err(HfError::UpstreamStatus(503))
    );
}

/// Retry-After: delta-seconds only, bounded digits; anything else waits the default.
#[test]
fn retry_after_takes_only_bounded_delta_seconds() {
    assert_eq!(retry_wait(Some("0")), 0);
    assert_eq!(retry_wait(Some("60")), 60);
    assert_eq!(retry_wait(Some("61")), 60);
    assert_eq!(retry_wait(Some("9999999999")), 60);
    for other in [
        None,
        Some(""),
        Some("99999999999"),
        Some("-1"),
        Some("+5"),
        Some(" 5"),
        Some("5s"),
        Some("Wed, 21 Oct 2015 07:28:00 GMT"),
    ] {
        assert_eq!(retry_wait(other), DEFAULT_RETRY_WAIT_SECS, "{other:?}");
    }
}

/// Statuses: 401/403 unauthorized, 404 not found, others named by number.
#[test]
fn other_statuses_are_named() {
    let mut t = Tries::default();
    for (status, want) in [
        (401, HfError::Unauthorized),
        (403, HfError::Unauthorized),
        (404, HfError::NotFound),
        (500, HfError::UpstreamStatus(500)),
        (204, HfError::UpstreamStatus(204)),
        (100, HfError::UpstreamStatus(100)),
    ] {
        assert_eq!(
            decide_list(&head(status), &list(), &mut t),
            Err(want.clone())
        );
        assert_eq!(
            decide_file(&head(status), &file(0), &mut t, 0, 9),
            Err(want)
        );
    }
}

/// A list answer: 200 is the body unless it is encoded or declares more than the bound; a 206
/// is not a list.
#[test]
fn a_list_answer_is_bounded() {
    let mut t = Tries::default();
    assert_eq!(
        decide_list(&head(200), &list(), &mut t),
        Ok(Step::Body(Body::List))
    );
    let at = MAX_LIST_BYTES.to_string();
    let h = Head {
        content_length: Some(&at),
        ..head(200)
    };
    assert_eq!(decide_list(&h, &list(), &mut t), Ok(Step::Body(Body::List)));
    let over = (MAX_LIST_BYTES + 1).to_string();
    let h = Head {
        content_length: Some(&over),
        ..head(200)
    };
    assert_eq!(decide_list(&h, &list(), &mut t), Err(HfError::ListTooLarge));
    let h = Head {
        content_length: Some("x"),
        ..head(200)
    };
    assert_eq!(
        decide_list(&h, &list(), &mut t),
        Err(HfError::LengthMismatch)
    );
    let enc = Head {
        content_encoding: true,
        ..head(200)
    };
    assert_eq!(
        decide_list(&enc, &list(), &mut t),
        Err(HfError::ContentEncoding)
    );
    assert_eq!(
        decide_list(&head(206), &list(), &mut t),
        Err(HfError::UpstreamStatus(206))
    );
}

/// The shape checked before a number is parsed: 1 to 20 digits (20 is accepted, 21 refused,
/// even with a value that would overflow anyway), no leading zero but `0`.
#[test]
fn canonical_digits_bounds_the_shape_first() {
    assert!(canonical_digits("0"));
    assert!(canonical_digits("7"));
    assert!(canonical_digits(&"9".repeat(20)));
    assert!(!canonical_digits(&"1".repeat(21)));
    assert!(!canonical_digits(""));
    assert!(!canonical_digits("01"));
    assert!(!canonical_digits("1a"));
    assert!(!canonical_digits("a1"));
}

/// The strict number and range parsers.
#[test]
fn numbers_and_ranges_parse_strictly() {
    assert_eq!(parse_u64("0"), Some(0));
    assert_eq!(parse_u64("18446744073709551615"), Some(u64::MAX));
    for bad in [
        "",
        "18446744073709551616",
        "-1",
        "+1",
        " 1",
        "1 ",
        "0x1",
        "１",
        "00",
        "01",
        "0100",
    ] {
        assert_eq!(parse_u64(bad), None, "{bad:?}");
    }
    assert_eq!(parse_content_range("bytes 0-0/1"), Some((0, 0, 1)));
    assert_eq!(parse_content_range("bytes 5-9/10"), Some((5, 9, 10)));
    for bad in [
        "bytes 9-5/10",
        "bytes 5-10/10",
        "bytes 5-9/",
        "bytes -9/10",
        "bytes 5-/10",
        "bytes5-9/10",
        "bytes  5-9/10",
        "Bytes 5-9/10",
        "bytes 5-9/10/1",
        "bytes 00-29/0100",
        "bytes 05-9/10",
    ] {
        assert_eq!(parse_content_range(bad), None, "{bad:?}");
    }
}
