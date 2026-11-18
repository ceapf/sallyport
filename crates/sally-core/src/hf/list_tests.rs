#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use super::*;

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

fn hex(c: char) -> String {
    c.to_string().repeat(64)
}

fn body(siblings: &str) -> Vec<u8> {
    format!(r#"{{"id":"a/b","sha":"{SHA}","siblings":[{siblings}],"extra":{{"x":1}}}}"#)
        .into_bytes()
}

fn lfs_file(name: &str, size: u64, sha: &str) -> String {
    format!(
        r#"{{"rfilename":"{name}","size":{size},"blobId":"x","lfs":{{"sha256":"{sha}","size":{size},"pointerSize":134}}}}"#
    )
}

/// A list with LFS files gives the commit and, per file, its path, size and SHA-256; unknown
/// fields are ignored.
#[test]
fn a_list_gives_the_commit_and_each_files_hash() {
    let b = body(&format!(
        "{},{}",
        lfs_file("m.Q4.gguf", 100, &hex('a')),
        lfs_file("sub/m.Q8.gguf", 200, &hex('b'))
    ));
    let list = parse_list(&b).unwrap();
    assert_eq!(list.commit().as_str(), SHA);
    assert_eq!(list.files().len(), 2);
    let w = list
        .wanted(&RepoPath::parse("sub/m.Q8.gguf").unwrap())
        .unwrap();
    assert_eq!(w.path().as_str(), "sub/m.Q8.gguf");
    assert_eq!(w.size(), 200);
    assert_eq!(w.sha256().as_hex(), hex('b'));
    assert_eq!(list.files()[0].shown(), "m.Q4.gguf");
    assert_eq!(list.files()[0].size(), Some(100));
}

/// Siblings Sallyport cannot pull are listed with their reason, and the list still parses.
#[test]
fn files_that_cannot_be_pulled_carry_their_reason() {
    let b = body(
        &[
            r#"{"rfilename":"README.md","size":10}"#.to_owned(),
            r#"{"rfilename":"small.gguf","size":10,"lfs":null}"#.to_owned(),
            r#"{"rfilename":"nohash.gguf","size":10,"lfs":{"size":10}}"#.to_owned(),
            r#"{"rfilename":"badhash.gguf","size":10,"lfs":{"sha256":"XYZ","size":10}}"#.to_owned(),
            format!(
                r#"{{"rfilename":"two.gguf","size":10,"lfs":{{"sha256":"{}","size":11}}}}"#,
                hex('c')
            ),
            format!(
                r#"{{"rfilename":"zero.gguf","size":0,"lfs":{{"sha256":"{}","size":0}}}}"#,
                hex('c')
            ),
            format!(
                r#"{{"rfilename":"huge.gguf","lfs":{{"sha256":"{}","size":1099511627777}}}}"#,
                hex('c')
            ),
            format!(
                r#"{{"rfilename":"nosize.gguf","lfs":{{"sha256":"{}"}}}}"#,
                hex('c')
            ),
            format!(
                r#"{{"rfilename":"lfsonly.gguf","lfs":{{"sha256":"{}","size":5}}}}"#,
                hex('d')
            ),
            format!(
                r#"{{"rfilename":"max.gguf","size":1099511627776,"lfs":{{"sha256":"{}"}}}}"#,
                hex('e')
            ),
            format!(
                r#"{{"rfilename":"a/../x.gguf","size":5,"lfs":{{"sha256":"{}","size":5}}}}"#,
                hex('f')
            ),
        ]
        .join(","),
    );
    let list = parse_list(&b).unwrap();
    let reasons: Vec<_> = list
        .files()
        .iter()
        .map(|f| f.pull().err().map(HfError::code))
        .collect();
    assert_eq!(
        reasons,
        [
            Some("hf_path_invalid"),
            Some("hf_no_publisher_hash"),
            Some("hf_no_publisher_hash"),
            Some("hf_no_publisher_hash"),
            Some("hf_size_disagrees"),
            Some("hf_size_invalid"),
            Some("hf_size_invalid"),
            Some("hf_size_invalid"),
            None,
            None,
            Some("hf_path_invalid"),
        ]
    );
    assert_eq!(list.files()[8].pull().unwrap().size(), 5);
    assert_eq!(list.files()[9].pull().unwrap().size(), MAX_FILE_SIZE);
}

/// Asking for a file: not listed, or listed but not pullable, is refused with its reason.
#[test]
fn wanted_refuses_unlisted_and_unpullable_files() {
    let b = body(&format!(
        r#"{},{{"rfilename":"nohash.gguf","size":3}}"#,
        lfs_file("m.gguf", 3, &hex('a'))
    ));
    let list = parse_list(&b).unwrap();
    let err = list
        .wanted(&RepoPath::parse("other.gguf").unwrap())
        .unwrap_err();
    assert_eq!(err, HfError::FileNotListed("other.gguf".to_owned()));
    let err = list
        .wanted(&RepoPath::parse("nohash.gguf").unwrap())
        .unwrap_err();
    assert_eq!(err, HfError::NoPublisherHash);
    assert!(list.wanted(&RepoPath::parse("m.gguf").unwrap()).is_ok());
}

/// A file name the Hub chose is shown escaped and capped.
#[test]
fn shown_names_are_escaped_and_capped() {
    let b = body(&format!(
        r#"{{"rfilename":"a\u001b[31m.gguf","size":1}},{{"rfilename":"{}","size":1}}"#,
        "x".repeat(500)
    ));
    let list = parse_list(&b).unwrap();
    let shown = list.files()[0].shown();
    assert!(!shown.contains('\u{1b}'), "{shown:?}");
    let want = format!("{}...(+372 bytes)", "x".repeat(SHOWN_NAME_BYTES));
    assert_eq!(list.files()[1].shown(), want);
}

/// A body over the bound is refused before it is parsed; one at the bound is parsed.
#[test]
fn the_list_body_is_bounded() {
    let mut b = body("");
    let pad = MAX_LIST_BYTES - b.len();
    b.splice(0..0, std::iter::repeat_n(b' ', pad));
    assert_eq!(b.len(), MAX_LIST_BYTES);
    assert!(parse_list(&b).is_ok());
    b.insert(0, b' ');
    assert_eq!(parse_list(&b).unwrap_err(), HfError::ListTooLarge);
}

/// More siblings than the bound are refused; exactly the bound parse.
#[test]
fn the_sibling_count_is_bounded() {
    let one = r#"{"rfilename":"r","size":1}"#;
    let at = vec![one; MAX_SIBLINGS].join(",");
    assert_eq!(parse_list(&body(&at)).unwrap().files().len(), MAX_SIBLINGS);
    let over = vec![one; MAX_SIBLINGS + 1].join(",");
    let err = parse_list(&body(&over)).unwrap_err();
    assert_eq!(err.code(), "hf_list_malformed");
}

/// A duplicate key at any level is refused, as is a missing or invalid commit, a wrong type,
/// or anything but an object; the error names a position, never a value.
#[test]
fn malformed_lists_are_refused() {
    let dup_sha = format!(r#"{{"sha":"{SHA}","sha":"{SHA}","siblings":[]}}"#);
    let dup_sib = format!(r#"{{"sha":"{SHA}","siblings":[],"siblings":[]}}"#);
    let dup_name =
        format!(r#"{{"sha":"{SHA}","siblings":[{{"rfilename":"a.gguf","rfilename":"b.gguf"}}]}}"#);
    let dup_lfs = format!(
        r#"{{"sha":"{SHA}","siblings":[{{"rfilename":"a.gguf","lfs":{{"sha256":"{0}","sha256":"{0}"}}}}]}}"#,
        hex('a')
    );
    for bad in [
        dup_sha.as_str(),
        &dup_sib,
        &dup_name,
        &dup_lfs,
        r#"{"siblings":[]}"#,
        &format!(r#"{{"sha":"{SHA}"}}"#),
        &format!(r#"{{"sha":"{SHA}","siblings":{{}}}}"#),
        &format!(r#"{{"sha":"{SHA}","siblings":[{{"size":1}}]}}"#),
        &format!(r#"{{"sha":"{SHA}","siblings":[{{"rfilename":"a","size":-1}}]}}"#),
        "[]",
        "",
        "{",
    ] {
        let err = parse_list(bad.as_bytes()).unwrap_err();
        assert_eq!(err.code(), "hf_list_malformed", "{bad}");
    }
    let secretish = format!(r#"{{"sha":"{SHA}","siblings":[{{"rfilename":7777777}}]}}"#);
    let err = parse_list(secretish.as_bytes()).unwrap_err();
    assert!(!err.to_string().contains("7777777"), "{err}");
    for bad_sha in ["main", "", &SHA.to_uppercase()] {
        let b = format!(r#"{{"sha":"{bad_sha}","siblings":[]}}"#);
        assert_eq!(
            parse_list(b.as_bytes()).unwrap_err(),
            HfError::CommitInvalid
        );
    }
}
