#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use sally_core::hf::list::{FileList, parse_list};
use sally_core::hf::names::{RepoId, RepoPath, Revision};

use super::testkit::{Hub, PUBLIC, SHA, TmpLib, found, gguf, list_json, reply, sha};
use super::*;

/// A token assembled at run time, so no credential-shaped literal is in the source.
fn token() -> String {
    ["h", "f_", &"t".repeat(34)].concat()
}

fn repo() -> RepoId {
    RepoId::parse("org/m").unwrap()
}

fn path(p: &str) -> RepoPath {
    RepoPath::parse(p).unwrap()
}

fn list(files: &[(&str, &[u8])]) -> FileList {
    parse_list(&list_json(files)).unwrap()
}

async fn bounded<F: Future>(f: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(20), f)
        .await
        .expect("the test hung")
}

/// The file at `seen.path` from `files` as a full 200.
fn serve(files: &'static [(&'static str, Vec<u8>)], seen: &testkit::Seen) -> Vec<u8> {
    for (p, b) in files {
        if seen.path.ends_with(&format!("/{p}")) {
            return reply("200 OK", &[], b);
        }
    }
    reply("404 Not Found", &[], b"")
}

/// The list request goes to huggingface.co with the token and identity encoding, after one
/// lookup and one dial, and parses.
#[tokio::test]
async fn files_asks_the_api_host_with_the_token() {
    let g = gguf("files");
    let body = list_json(&[("m.gguf", &g)]);
    let hub = Hub::new(move |_, _| reply("200 OK", &[], &body));
    let list = bounded(hub.client(Some(&token())).files(&repo(), &Revision::main()))
        .await
        .unwrap();
    assert_eq!(list.commit().as_str(), SHA);
    assert_eq!(list.wanted(&path("m.gguf")).unwrap().size(), g.len() as u64);
    let seen = hub.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].host, "huggingface.co");
    assert_eq!(seen[0].path, "/api/models/org/m/revision/main?blobs=true");
    assert_eq!(seen[0].auth, Some(format!("Bearer {}", token())));
    assert_eq!(seen[0].accept_encoding.as_deref(), Some("identity"));
    assert_eq!(hub.lookups(), ["huggingface.co"]);
    assert_eq!(hub.dials(), 1);
}

/// A pull follows the redirect to the CDN host, which gets no token, and the library stores
/// the file under its digest with downloads/ left empty.
#[tokio::test]
async fn a_pull_follows_the_cdn_redirect_without_the_token() {
    let g = gguf("redirect");
    let served = g.clone();
    let hub = Hub::new(move |s, _| {
        if s.host == "huggingface.co" {
            found("https://cdn-lfs.hf.co/blobs/x?sig=a%2Fb")
        } else {
            reply("200 OK", &[], &served)
        }
    });
    let lib = TmpLib::open("redirect", 0);
    let entry = bounded(hub.client(Some(&token())).pull(
        &lib.lib,
        &repo(),
        &list(&[("m.gguf", &g)]),
        &path("m.gguf"),
    ))
    .await
    .unwrap();
    assert_eq!(entry.digest(), &sha(&g));
    let seen = hub.seen();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].path, format!("/org/m/resolve/{SHA}/m.gguf"));
    assert_eq!(seen[0].auth, Some(format!("Bearer {}", token())));
    assert_eq!(seen[1].host, "cdn-lfs.hf.co");
    assert_eq!(seen[1].path, "/blobs/x?sig=a%2Fb");
    assert_eq!(seen[1].auth, None, "the token went to the redirect host");
    assert_eq!(hub.lookups(), ["huggingface.co", "cdn-lfs.hf.co"]);
    assert_eq!(lib.names("blobs/sha256"), [sha(&g).as_hex()]);
    assert!(lib.names("downloads").is_empty());
}

/// A partial on disk is resumed with a range request, and a 206 for exactly the rest is
/// appended and promoted.
#[tokio::test]
async fn a_partial_is_resumed_with_a_range() {
    let g = gguf("resume");
    let half = g.len() / 2;
    let lib = TmpLib::open("resume", 0);
    {
        let mut l = lib.lib.lock().unwrap();
        let mut d = l
            .begin_download("m.gguf", &sha(&g), g.len() as u64)
            .unwrap();
        d.append(&g[..half]).unwrap();
    }
    let rest = g[half..].to_vec();
    let total = g.len();
    let hub = Hub::new(move |_, _| {
        let range = format!("Content-Range: bytes {half}-{}/{total}", total - 1);
        reply("206 Partial Content", &[&range], &rest)
    });
    let entry = bounded(hub.client(None).pull(
        &lib.lib,
        &repo(),
        &list(&[("m.gguf", &g)]),
        &path("m.gguf"),
    ))
    .await
    .unwrap();
    assert_eq!(entry.digest(), &sha(&g));
    assert_eq!(hub.seen()[0].range, Some(format!("bytes={half}-")));
    assert_eq!(hub.seen()[0].auth, None, "no token was set");
}

/// RT-MDL-04's filesystem half: bytes that do not hash to the listed SHA-256 leave no partial,
/// no blob and no row; the control, a matching pull through the same Hub and library, stores
/// its blob.
#[tokio::test]
async fn a_hash_mismatch_stores_nothing() {
    let good = gguf("good-1");
    let listed = gguf("bad--1");
    let served = gguf("bad--2");
    assert_eq!(listed.len(), served.len());
    let files: &'static [(&'static str, Vec<u8>)] = Box::leak(Box::new([
        ("good.gguf", good.clone()),
        ("bad.gguf", served),
    ]));
    let hub = Hub::new(move |s, _| serve(files, s));
    let lib = TmpLib::open("hash", 0);
    let l = list(&[("good.gguf", &good), ("bad.gguf", &listed)]);
    let client = hub.client(None);

    bounded(client.pull(&lib.lib, &repo(), &l, &path("good.gguf")))
        .await
        .unwrap();
    assert_eq!(lib.names("blobs/sha256"), [sha(&good).as_hex()]);

    let err = bounded(client.pull(&lib.lib, &repo(), &l, &path("bad.gguf")))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "hash_mismatch");
    assert!(lib.names("downloads").is_empty(), "the partial was kept");
    assert_eq!(lib.names("blobs/sha256"), [sha(&good).as_hex()]);
    assert_eq!(lib.rows(), 1);
}

/// RT-MDL-09's filesystem half: a file that does not fit is refused insufficient_disk before
/// any request; the control, the same pull into a library that fits, sends exactly one.
#[tokio::test]
async fn a_file_that_does_not_fit_sends_no_request() {
    let g = gguf("disk");
    let served = g.clone();
    let hub = Hub::new(move |_, _| reply("200 OK", &[], &served));
    let l = list(&[("m.gguf", &g)]);
    let client = hub.client(None);

    let fits = TmpLib::open("disk-fits", 0);
    bounded(client.pull(&fits.lib, &repo(), &l, &path("m.gguf")))
        .await
        .unwrap();
    assert_eq!(hub.seen().len(), 1);

    let full = TmpLib::open("disk-full", u64::MAX);
    let err = bounded(client.pull(&full.lib, &repo(), &l, &path("m.gguf")))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "insufficient_disk");
    assert_eq!(hub.seen().len(), 1, "a request was sent");
    assert_eq!(hub.dials(), 1);
    assert_eq!(hub.lookups().len(), 1);
    assert!(full.names("downloads").is_empty());
}

/// A host that resolves to loopback, a private address or this host's own is never dialled;
/// the control, a public answer through the same recorder, records one lookup and one dial.
#[tokio::test]
async fn denied_addresses_are_never_dialled() {
    let body = list_json(&[]);
    let hub = Hub::new(move |_, _| reply("200 OK", &[], &body));
    let client = hub.client(None);
    bounded(client.files(&repo(), &Revision::main()))
        .await
        .unwrap();
    assert_eq!((hub.lookups().len(), hub.dials()), (1, 1));

    let denied = [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
        IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
    ];
    for (i, ip) in denied.into_iter().enumerate() {
        hub.answer(ip);
        let err = bounded(client.files(&repo(), &Revision::main()))
            .await
            .unwrap_err();
        assert_eq!(err.code(), "hf_address_denied", "{ip}");
        assert_eq!(hub.lookups().len(), 2 + i);
        assert_eq!(hub.dials(), 1, "{ip} was dialled");
    }
    hub.answer(PUBLIC);
    hub.own(PUBLIC);
    let err = bounded(client.files(&repo(), &Revision::main()))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "hf_address_denied");
    assert_eq!(hub.dials(), 1, "an own address was dialled");
}

/// A redirect to a host outside the Hub's domains is refused without a lookup or a dial of it.
#[tokio::test]
async fn a_redirect_off_the_hub_is_not_followed() {
    let hub = Hub::new(|_, _| found("https://evil.test/x"));
    let g = gguf("evil");
    let lib = TmpLib::open("evil", 0);
    let err = bounded(hub.client(Some(&token())).pull(
        &lib.lib,
        &repo(),
        &list(&[("m.gguf", &g)]),
        &path("m.gguf"),
    ))
    .await
    .unwrap_err();
    assert_eq!(err.code(), "hf_redirect_refused");
    assert_eq!(hub.lookups(), ["huggingface.co"]);
    assert_eq!(hub.dials(), 1);
}

/// A Hub host whose certificate does not name it is refused at the TLS step.
#[tokio::test]
async fn a_certificate_for_another_name_is_refused() {
    let hub = Hub::new(|_, _| found("https://other.hf.co/x"));
    let g = gguf("tls");
    let lib = TmpLib::open("tls", 0);
    let err = bounded(hub.client(None).pull(
        &lib.lib,
        &repo(),
        &list(&[("m.gguf", &g)]),
        &path("m.gguf"),
    ))
    .await
    .unwrap_err();
    assert_eq!(err.code(), "hf_tls_failed");
    assert_eq!(hub.seen().len(), 1, "a request reached the misnamed host");
}

/// A 416 to a resume deletes the partial; a 200 to one starts the file again and is stored.
#[tokio::test]
async fn a_resume_answered_416_or_200() {
    let g = gguf("restart");
    let begin = |lib: &TmpLib| {
        let mut l = lib.lib.lock().unwrap();
        let mut d = l
            .begin_download("m.gguf", &sha(&g), g.len() as u64)
            .unwrap();
        d.append(b"GGUFjunk").unwrap();
    };
    let l = list(&[("m.gguf", &g)]);

    let lib = TmpLib::open("r416", 0);
    begin(&lib);
    let hub = Hub::new(|_, _| reply("416 Range Not Satisfiable", &[], b""));
    let err = bounded(
        hub.client(None)
            .pull(&lib.lib, &repo(), &l, &path("m.gguf")),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), "hf_range_refused");
    assert!(lib.names("downloads").is_empty());

    let lib = TmpLib::open("r200", 0);
    begin(&lib);
    let served = g.clone();
    let hub = Hub::new(move |_, _| reply("200 OK", &[], &served));
    let entry = bounded(
        hub.client(None)
            .pull(&lib.lib, &repo(), &l, &path("m.gguf")),
    )
    .await
    .unwrap();
    assert_eq!(entry.digest(), &sha(&g));
    assert_eq!(hub.seen()[0].range.as_deref(), Some("bytes=8-"));
}

/// A rate limit is waited out and the request sent again.
#[tokio::test]
async fn a_rate_limit_is_retried() {
    let body = list_json(&[]);
    let hub = Hub::new(move |_, i| {
        if i == 0 {
            reply("429 Too Many Requests", &["Retry-After: 0"], b"")
        } else {
            reply("200 OK", &[], &body)
        }
    });
    bounded(hub.client(None).files(&repo(), &Revision::main()))
        .await
        .unwrap();
    assert_eq!(hub.seen().len(), 2);
}

/// A body cut short keeps what arrived; the next pull resumes from there and completes.
#[tokio::test]
async fn a_cut_body_is_kept_and_resumed() {
    let g = gguf("cut");
    let half = g.len() / 2;
    let total = g.len();
    let whole = g.clone();
    let hub = Hub::new(move |_, i| {
        if i == 0 {
            let mut r = reply("200 OK", &[], &whole);
            r.truncate(r.len() - (total - half));
            r
        } else {
            let range = format!("Content-Range: bytes {half}-{}/{total}", total - 1);
            reply("206 Partial Content", &[&range], &whole[half..])
        }
    });
    let lib = TmpLib::open("cut", 0);
    let l = list(&[("m.gguf", &g)]);
    let client = hub.client(None);
    let err = bounded(client.pull(&lib.lib, &repo(), &l, &path("m.gguf")))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "hf_body_failed");
    let part = lib.path(&format!("downloads/{}.part", sha(&g).as_hex()));
    assert_eq!(std::fs::read(&part).unwrap(), &g[..half]);
    bounded(client.pull(&lib.lib, &repo(), &l, &path("m.gguf")))
        .await
        .unwrap();
    assert!(lib.names("downloads").is_empty());
    assert!(lib.root().exists());
}

/// The rig's GGUF bytes pass the strict parser, so a refusal in these tests is never the
/// fixture's.
#[test]
fn the_fixture_is_a_valid_gguf() {
    let g = gguf("x");
    sally_core::model::gguf::parse(&g[..], g.len() as u64).unwrap();
}
