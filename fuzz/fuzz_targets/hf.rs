//! Fuzz target: arbitrary bytes → the Hugging Face client's parsers of Hub-chosen text: the file
//! list JSON, Content-Range, Location (through the redirect plan), Retry-After, and the path,
//! repository and revision checks (CLAUDE.md: every parser of untrusted bytes has one).
//!
//! Invariants:
//! - never panics, on any input;
//! - an accepted list has at most MAX_SIBLINGS files, a 40-hex commit, and every pullable file
//!   a path that parses again, a size from 1 to MAX_FILE_SIZE; every shown name and every
//!   refusal message is printable ASCII;
//! - an accepted Content-Range is canonical (formatting it back gives the input) with
//!   first <= last < total;
//! - a followed redirect is to a Hub host (or the current one), its target starts with `/` and
//!   holds no space, control or `#`, and it keeps the range; from a hop that carries the token
//!   it carries the token exactly when its host is huggingface.co; from a hop of a chain that
//!   has left huggingface.co it never carries the token, and nor does a later return to
//!   huggingface.co;
//! - a followed redirect of the file-list call stays on huggingface.co and carries the token;
//! - Retry-After never waits past MAX_RETRY_WAIT_SECS;
//! - an accepted path has no empty, `.` or `..` segment, and its encoding holds only unreserved
//!   bytes, `%` and `/`;
//! - an accepted revision has no empty component and none starting with `.`.
#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use sally_core::hf::head::{Head, Step, Tries, decide_list, parse_content_range, retry_wait};
use sally_core::hf::list::parse_list;
use sally_core::hf::names::{Commit, RepoId, RepoPath, Revision};
use sally_core::hf::plan::{API_HOST, file_request, list_request, redirect, redirect_host_ok};
use sally_core::hf::{MAX_FILE_SIZE, MAX_RETRY_WAIT_SECS, MAX_SIBLINGS};

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

fn printable(s: &str) -> bool {
    s.bytes().all(|b| (0x20..0x7f).contains(&b))
}

fn check_list(data: &[u8]) {
    match parse_list(data) {
        Ok(list) => {
            assert!(list.files().len() <= MAX_SIBLINGS);
            assert!(Commit::parse(list.commit().as_str()).is_ok());
            for f in list.files() {
                assert!(printable(f.shown()), "{:?}", f.shown());
                match f.pull() {
                    Ok(w) => {
                        assert!((1..=MAX_FILE_SIZE).contains(&w.size()));
                        assert!(RepoPath::parse(w.path().as_str()).is_ok());
                    }
                    Err(e) => assert!(printable(&e.to_string())),
                }
            }
        }
        Err(e) => assert!(printable(&e.to_string()), "{e}"),
    }
}

fn check_text(s: &str) {
    if let Some((a, b, c)) = parse_content_range(s) {
        assert!(a <= b && b < c);
        assert_eq!(format!("bytes {a}-{b}/{c}"), s);
    }
    assert!(retry_wait(Some(s)) <= MAX_RETRY_WAIT_SECS);

    let repo = RepoId::parse("org/model").expect("a valid id");
    let commit = Commit::parse(SHA).expect("a valid commit");
    let path = RepoPath::parse("m.gguf").expect("a valid path");
    let current = file_request(&repo, &commit, &path, 7);
    if let Ok(next) = redirect(&current, s) {
        assert!(redirect_host_ok(next.host()) || next.host() == current.host());
        assert!(next.path().starts_with('/'));
        assert!(
            next.path()
                .bytes()
                .all(|b| b.is_ascii_graphic() && b != b'#' && b != b'\\')
        );
        assert_eq!(next.carries_auth(), next.host() == API_HOST);
        assert_eq!(next.range_from(), Some(7));
    }
    let left = redirect(&current, "https://cdn-lfs.hf.co/x").expect("a Hub host is followed");
    assert!(!left.carries_auth());
    if let Ok(next) = redirect(&left, s) {
        assert!(!next.carries_auth());
        assert!(redirect_host_ok(next.host()) || next.host() == left.host());
        assert_eq!(next.range_from(), Some(7));
        let back = redirect(&next, "https://huggingface.co/y").expect("the API host is followed");
        assert!(!back.carries_auth());
    }
    let list = list_request(&repo, &Revision::main());
    let moved = Head {
        status: 302,
        content_length: None,
        content_range: None,
        location: Some(s),
        retry_after: None,
        content_encoding: false,
    };
    if let Ok(Step::Redirect(next)) = decide_list(&moved, &list, &mut Tries::default()) {
        assert_eq!(next.host(), API_HOST);
        assert!(next.carries_auth());
    }

    if let Ok(p) = RepoPath::parse(s) {
        assert!(p.as_str().split('/').all(|seg| !seg.is_empty() && seg != "." && seg != ".."));
        assert!(
            p.encoded()
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~%/".contains(&b))
        );
    }
    if let Ok(r) = RepoId::parse(s) {
        assert_eq!(r.as_str().matches('/').count(), 1);
    }
    if let Ok(r) = Revision::parse(s) {
        assert!(!r.encoded().contains('/'));
        assert!(
            r.as_str()
                .split('/')
                .all(|c| !c.is_empty() && !c.starts_with('.'))
        );
    }
}

fuzz_target!(|data: &[u8]| {
    check_list(data);
    if let Ok(s) = std::str::from_utf8(data) {
        check_text(s);
    }
});
