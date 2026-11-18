#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use super::*;

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

fn repo() -> RepoId {
    RepoId::parse("org/model-GGUF").unwrap()
}

fn file(from: u64) -> Request {
    let commit = Commit::parse(SHA).unwrap();
    let path = RepoPath::parse("sub/m+1.gguf").unwrap();
    file_request(&repo(), &commit, &path, from)
}

/// The list request goes to huggingface.co with the token, at the encoded revision.
#[test]
fn the_list_request_is_pinned_to_the_api_host() {
    let r = list_request(&repo(), &Revision::parse("refs/pr/2").unwrap());
    assert_eq!(r.host(), "huggingface.co");
    assert_eq!(
        r.path(),
        "/api/models/org/model-GGUF/revision/refs%2Fpr%2F2?blobs=true"
    );
    assert_eq!(r.range_from(), None);
    assert!(r.carries_auth());
}

/// The file request names the commit, never a branch, and asks for the rest from an offset.
#[test]
fn the_file_request_names_the_commit_and_the_offset() {
    let r = file(0);
    assert_eq!(r.host(), "huggingface.co");
    assert_eq!(
        r.path(),
        format!("/org/model-GGUF/resolve/{SHA}/sub/m%2B1.gguf")
    );
    assert_eq!(r.range_from(), None);
    assert!(r.carries_auth());
    assert_eq!(file(7).range_from(), Some(7));
}

/// Where a download goes on: nothing to fetch once every byte is on disk.
#[test]
fn next_fetch_stops_when_complete() {
    assert_eq!(next_fetch(0, 10), Some(0));
    assert_eq!(next_fetch(9, 10), Some(9));
    assert_eq!(next_fetch(10, 10), None);
}

/// Hosts: huggingface.co, hf.co and their subdomains on a label boundary; nothing else.
#[test]
fn redirect_hosts_are_hub_domains_on_a_label_boundary() {
    for ok in [
        "huggingface.co",
        "hf.co",
        "cdn-lfs.huggingface.co",
        "cdn-lfs-us-1.hf.co",
        "cas-bridge.xethub.hf.co",
    ] {
        assert!(redirect_host_ok(ok), "{ok}");
    }
    for bad in [
        "",
        "evilhf.co",
        "evilhuggingface.co",
        "hf.co.evil.test",
        "huggingface.co.",
        ".hf.co",
        "a..hf.co",
        "-a.hf.co",
        "a-.hf.co",
        "a_b.hf.co",
        "HF.CO",
        "1.1.1.1",
        "co",
        "huggingface.com",
        &format!("{}.hf.co", "a".repeat(64)),
    ] {
        assert!(!redirect_host_ok(bad), "{bad:?}");
    }
}

/// An absolute https redirect to a Hub host is followed; the token goes only to
/// huggingface.co itself; the range is kept.
#[test]
fn absolute_redirects_to_hub_hosts_are_followed() {
    let next = redirect(
        &file(5),
        "https://cdn-lfs.hf.co/repos/x/y?X-Amz=1&sig=a%2Fb",
    )
    .unwrap();
    assert_eq!(next.host(), "cdn-lfs.hf.co");
    assert_eq!(next.path(), "/repos/x/y?X-Amz=1&sig=a%2Fb");
    assert_eq!(next.range_from(), Some(5));
    assert!(!next.carries_auth());
    let back = redirect(&next, "https://huggingface.co/other").unwrap();
    assert!(back.carries_auth());
    let upper = redirect(&file(0), "https://CDN-LFS.HF.CO/a").unwrap();
    assert_eq!(upper.host(), "cdn-lfs.hf.co");
    assert!(!upper.carries_auth());
    let bare = redirect(&file(0), "https://hf.co").unwrap();
    assert_eq!(bare.path(), "/");
    assert!(!bare.carries_auth(), "the token went to hf.co");
    let sub = redirect(&file(0), "https://cdn-lfs.huggingface.co/a").unwrap();
    assert!(
        !sub.carries_auth(),
        "the token went to a subdomain of the API host"
    );
}

/// A relative redirect stays on the current host with its token rule.
#[test]
fn relative_redirects_stay_on_the_host() {
    let cdn = redirect(&file(0), "https://cdn-lfs.hf.co/a").unwrap();
    let rel = redirect(&cdn, "/b?c=d").unwrap();
    assert_eq!((rel.host(), rel.path()), ("cdn-lfs.hf.co", "/b?c=d"));
    assert!(!rel.carries_auth());
    let rel = redirect(&file(0), "/api/x").unwrap();
    assert_eq!(rel.host(), "huggingface.co");
    assert!(rel.carries_auth());
}

/// Anything else is refused: http, another port, userinfo, an IP literal, another domain, a
/// scheme-relative or bare-relative location, a fragment, spaces, controls, or overlong.
#[test]
fn other_redirects_are_refused() {
    for bad in [
        "",
        "http://cdn-lfs.hf.co/a",
        "HTTPS://cdn-lfs.hf.co/a",
        "https://cdn-lfs.hf.co:443/a",
        "https://cdn-lfs.hf.co:8443/a",
        // Userinfo, assembled so the source holds no address-shaped text.
        &format!("https://{}@{}", "user", "cdn-lfs.hf.co/a"),
        &format!("https://{}:{}@{}", "user", "pw", "hf.co/a"),
        "https://@hf.co/a",
        "https://1.1.1.1/a",
        "https://[::1]/a",
        "https://evilhf.co/a",
        "https://hf.co.evil.test/a",
        "https://hf.co?x",
        "//hf.co/a",
        "a/b",
        "/a#frag",
        "/a b",
        "/a\tb",
        "/a\u{7f}",
        "/a\\b",
        "/ü",
        "ftp://hf.co/a",
        &format!("/{}", "a".repeat(MAX_LOCATION_BYTES)),
    ] {
        assert_eq!(
            redirect(&file(0), bad).unwrap_err(),
            HfError::RedirectRefused,
            "{bad:?}"
        );
    }
    assert!(
        redirect(
            &file(0),
            &format!("/{}", "a".repeat(MAX_LOCATION_BYTES - 1))
        )
        .is_ok()
    );
}
