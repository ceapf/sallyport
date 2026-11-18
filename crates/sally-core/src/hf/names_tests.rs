#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use super::*;

/// namespace/name with each part starting alphanumeric, `._-` after, at most 96 bytes.
#[test]
fn repo_ids_are_two_strict_parts() {
    for ok in [
        "TheBloke/Llama-2-7B-GGUF",
        "a/b",
        "org.x/model_v1.2-q",
        &format!("a/{}", "b".repeat(96)),
    ] {
        assert_eq!(RepoId::parse(ok).unwrap().as_str(), ok, "{ok}");
    }
    for bad in [
        "",
        "model",
        "a/b/c",
        "/b",
        "a/",
        "-a/b",
        "a/.b",
        "a/_b",
        "a/b c",
        "a/b%2F",
        "a/b?x",
        "a/b#x",
        "../b",
        "a/..",
        "a/ü",
        &format!("a/{}", "b".repeat(97)),
    ] {
        assert_eq!(RepoId::parse(bad), Err(HfError::RepoInvalid), "{bad:?}");
    }
}

/// Revisions: `[A-Za-z0-9._/-]`, 1 to 128 bytes; encoded as one segment; main by default.
#[test]
fn revisions_are_strict_and_one_segment() {
    assert_eq!(Revision::main().as_str(), "main");
    let r = Revision::parse("refs/pr/1").unwrap();
    assert_eq!(r.encoded(), "refs%2Fpr%2F1");
    assert!(Revision::parse(&"a".repeat(128)).is_ok());
    for bad in ["", "a b", "a?b", "a#b", "a%2F", "ü", &"a".repeat(129)] {
        assert_eq!(
            Revision::parse(bad),
            Err(HfError::RevisionInvalid),
            "{bad:?}"
        );
    }
}

/// A commit is exactly 40 lowercase hex digits.
#[test]
fn commits_are_forty_lowercase_hex() {
    let c = "0123456789abcdef0123456789abcdef01234567";
    assert_eq!(Commit::parse(c).unwrap().as_str(), c);
    for bad in [
        "",
        "0123456789abcdef0123456789abcdef0123456",
        "0123456789abcdef0123456789abcdef012345678",
        "0123456789ABCDEF0123456789abcdef01234567",
        "0123456789abcdef0123456789abcdef0123456g",
        "main",
    ] {
        assert_eq!(Commit::parse(bad), Err(HfError::CommitInvalid), "{bad:?}");
    }
}

/// Paths: strict segments, no dot segments, the last one a model name the library keeps.
#[test]
fn paths_are_strict_and_end_in_an_allowed_model_name() {
    for ok in [
        "model.Q4_K_M.gguf",
        "sub/dir/m-1+2~x.gguf",
        &format!("{}.gguf", "a".repeat(250)),
    ] {
        let p = RepoPath::parse(ok).unwrap();
        assert_eq!(p.as_str(), ok);
    }
    assert_eq!(RepoPath::parse("a/b/m.gguf").unwrap().file_name(), "m.gguf");
    let long_dirs = format!("{}/m.gguf", vec!["d".repeat(200); 6].join("/"));
    assert!(long_dirs.len() > 1024);
    for bad in [
        "",
        "m.bin",
        "m.safetensors",
        "m.pkl",
        "/m.gguf",
        "a//m.gguf",
        "./m.gguf",
        "../m.gguf",
        "a/../m.gguf",
        "m.gguf/",
        "m .gguf",
        "m%2e.gguf",
        "m?.gguf",
        "m\\.gguf",
        "m\u{1b}.gguf",
        "ü.gguf",
        &format!("{}.gguf", "a".repeat(251)),
        &long_dirs,
    ] {
        assert_eq!(RepoPath::parse(bad), Err(HfError::PathInvalid), "{bad:?}");
    }
}

/// The encoder keeps only unreserved bytes; `/` and everything else become `%XX`.
#[test]
fn encode_keeps_only_unreserved_bytes() {
    assert_eq!(encode("aZ09-._~"), "aZ09-._~");
    assert_eq!(encode("a/b+c d%"), "a%2Fb%2Bc%20d%25");
    assert_eq!(encode("\u{0}\u{ff}"), "%00%C3%BF");
    let p = RepoPath::parse("sub/m+1.gguf").unwrap();
    assert_eq!(p.encoded(), "sub/m%2B1.gguf");
    assert_eq!(RepoId::parse("a.b/c-d").unwrap().encoded(), "a.b/c-d");
}
