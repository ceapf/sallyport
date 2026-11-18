#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use super::*;
use crate::library::testkit::every_library_error;

fn all() -> Vec<(HfError, &'static str)> {
    vec![
        (HfError::RepoInvalid, "hf_repo_invalid"),
        (HfError::RevisionInvalid, "hf_revision_invalid"),
        (HfError::PathInvalid, "hf_path_invalid"),
        (HfError::ListTooLarge, "hf_list_too_large"),
        (
            HfError::ListMalformed { line: 1, column: 2 },
            "hf_list_malformed",
        ),
        (HfError::CommitInvalid, "hf_commit_invalid"),
        (
            HfError::FileNotListed("m.gguf".to_owned()),
            "hf_file_not_listed",
        ),
        (HfError::NoPublisherHash, "hf_no_publisher_hash"),
        (HfError::SizeInvalid, "hf_size_invalid"),
        (HfError::SizeDisagrees, "hf_size_disagrees"),
        (HfError::RedirectRefused, "hf_redirect_refused"),
        (HfError::TooManyRedirects, "hf_too_many_redirects"),
        (HfError::RateLimited, "hf_rate_limited"),
        (HfError::NotFound, "hf_not_found"),
        (HfError::Unauthorized, "hf_unauthorized"),
        (HfError::UpstreamStatus(500), "hf_upstream_status"),
        (HfError::LengthMismatch, "hf_length_mismatch"),
        (HfError::RangeMismatch, "hf_range_mismatch"),
        (HfError::RangeNotSatisfiable, "hf_range_refused"),
        (HfError::ContentEncoding, "hf_content_encoding"),
    ]
}

/// Every variant has its own stable code, prefixed `hf_`.
#[test]
fn every_variant_has_its_code() {
    let cases = all();
    for (err, code) in &cases {
        assert_eq!(err.code(), *code, "{err}");
        assert!(code.starts_with("hf_"), "{code}");
    }
    let mut codes: Vec<_> = cases.iter().map(|(_, c)| *c).collect();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), cases.len(), "two variants share a code");
}

/// No hf code is a detect, GGUF or library code: every code a library error can return (detect
/// and GGUF errors wrapped) is outside the hf_ prefix and none of the hf codes.
#[test]
fn no_code_collides_with_the_model_codes() {
    let hf: Vec<&str> = all().iter().map(|(err, _)| err.code()).collect();
    for (err, code) in every_library_error() {
        assert!(!code.starts_with("hf_"), "{code}");
        assert!(!hf.contains(&err.code()), "{code}");
    }
}

/// Exactly the range, 416 and encoding refusals delete the partial.
#[test]
fn only_untrustworthy_bytes_are_discarded() {
    for (err, _) in all() {
        let want = matches!(
            err,
            HfError::RangeMismatch | HfError::RangeNotSatisfiable | HfError::ContentEncoding
        );
        assert_eq!(err.discards_partial(), want, "{err:?}");
    }
}

/// Messages carry numbers and the asked-for name only.
#[test]
fn messages_carry_no_hub_text() {
    assert_eq!(
        HfError::ListMalformed { line: 3, column: 9 }.to_string(),
        "the Hub's file list is malformed (line 3, column 9)"
    );
    assert_eq!(
        HfError::UpstreamStatus(502).to_string(),
        "the Hub answered status 502"
    );
    assert!(
        HfError::FileNotListed("a.gguf".to_owned())
            .to_string()
            .starts_with("a.gguf ")
    );
}
