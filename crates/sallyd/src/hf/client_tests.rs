#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use sally_core::hf::list::{FileList, parse_list};
use sally_core::hf::names::{RepoId, RepoPath, Revision};

use super::testkit::{
    Hub, PUBLIC, SHA, TmpLib, foreign_ca_pem, found, gguf, list_json, reply, sha,
};
use super::*;
use crate::egress::addr::Net;
use crate::egress::roots::{BundleFiles, RootsError};

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

/// The mock's default answer, on the only port the client dials.
fn public_443() -> SocketAddr {
    SocketAddr::new(PUBLIC, 443)
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
    assert_eq!(hub.dialled(), [public_443()]);
}

/// A pull follows the redirect to the CDN host, which gets no token, and the library stores
/// the file under its digest with downloads/ left empty.
#[tokio::test]
async fn rt_mdl_11_a_pull_follows_the_cdn_redirect_without_the_token() {
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

/// Once a redirect chain has left the API host, no later request in it carries the token: the
/// redirect host answers with a redirect back to another repository's path on the API host,
/// which is followed without the token (and answers 404 here). Control: the first request, to
/// the API host before the chain left it, carries `Authorization`.
#[tokio::test]
async fn rt_mdl_11_a_chain_that_left_the_api_host_never_carries_the_token_again() {
    let g = gguf("bounce");
    let hub = Hub::new(move |s, i| match (i, s.host.as_str()) {
        (0, "huggingface.co") => found("https://cdn-lfs.hf.co/blobs/x"),
        (1, "cdn-lfs.hf.co") => found("https://huggingface.co/other/repo/resolve/main/secret.gguf"),
        _ => reply("404 Not Found", &[], b""),
    });
    let lib = TmpLib::open("bounce", 0);
    let err = bounded(hub.client(Some(&token())).pull(
        &lib.lib,
        &repo(),
        &list(&[("m.gguf", &g)]),
        &path("m.gguf"),
    ))
    .await
    .unwrap_err();
    assert_eq!(err.code(), "hf_not_found");
    let seen = hub.seen();
    assert_eq!(seen.len(), 3);
    assert_eq!(seen[0].host, "huggingface.co");
    assert_eq!(seen[0].auth, Some(format!("Bearer {}", token())));
    assert_eq!(seen[1].host, "cdn-lfs.hf.co");
    assert_eq!(seen[1].auth, None, "the token went to the redirect host");
    assert_eq!(seen[2].host, "huggingface.co");
    assert_eq!(seen[2].path, "/other/repo/resolve/main/secret.gguf");
    assert_eq!(
        seen[2].auth, None,
        "the token went back to the API host after the chain left it"
    );
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
    assert_eq!(hub.dialled(), [public_443()]);
    assert_eq!(hub.lookups().len(), 1);
    assert!(full.names("downloads").is_empty());
}

/// A host that resolves to loopback, a private address, this host's own, or an address inside a
/// network this host is directly connected to is never dialled; the control, a public answer
/// through the same recorder, records one lookup and one dial.
#[tokio::test]
async fn rt_mdl_11_denied_addresses_are_never_dialled() {
    let body = list_json(&[]);
    let hub = Hub::new(move |_, _| reply("200 OK", &[], &body));
    let client = hub.client(None);
    bounded(client.files(&repo(), &Revision::main()))
        .await
        .unwrap();
    assert_eq!(hub.lookups().len(), 1);
    assert_eq!(hub.dialled(), [public_443()]);

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
        assert_eq!(hub.dialled(), [public_443()], "{ip} was dialled");
    }
    hub.answer(PUBLIC);
    hub.own(PUBLIC);
    let err = bounded(client.files(&repo(), &Revision::main()))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "hf_address_denied");
    assert_eq!(hub.dialled(), [public_443()], "an own address was dialled");

    // A public answer inside a network this host is directly connected to is refused, as the
    // egress proxy refuses it. Control: the same answer is dialled before the network is listed.
    let body = list_json(&[]);
    let near = Hub::new(move |_, _| reply("200 OK", &[], &body));
    near.answer(PUBLIC);
    bounded(near.client(None).files(&repo(), &Revision::main()))
        .await
        .unwrap();
    assert_eq!(
        near.dialled(),
        [public_443()],
        "control: the public answer is dialled"
    );
    near.connected(Net::prefix(PUBLIC, 24).unwrap());
    let err = bounded(near.client(None).files(&repo(), &Revision::main()))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "hf_address_denied");
    assert_eq!(
        near.dialled(),
        [public_443()],
        "an address on a connected network was dialled"
    );

    // Host tables that cannot be read refuse the host before any lookup or dial. Control: the
    // same Hub looked up and dialled with readable tables above.
    let lookups = near.lookups().len();
    let dialled = near.dialled();
    near.tables_unreadable();
    let err = bounded(near.client(None).files(&repo(), &Revision::main()))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "hf_address_denied");
    assert_eq!(
        near.lookups().len(),
        lookups,
        "looked up without host tables"
    );
    assert_eq!(near.dialled(), dialled, "dialled without host tables");

    // One denied answer among public ones refuses the host: nothing is dialled, not even the
    // public answer listed first.
    let mapped = IpAddr::V6(Ipv4Addr::new(10, 0, 0, 1).to_ipv6_mapped());
    for mixed in [[PUBLIC, IpAddr::V4(Ipv4Addr::LOCALHOST)], [PUBLIC, mapped]] {
        let hub = Hub::new(|_, _| reply("200 OK", &[], b""));
        hub.answer_all(&mixed);
        let err = bounded(hub.client(None).files(&repo(), &Revision::main()))
            .await
            .unwrap_err();
        assert_eq!(err.code(), "hf_address_denied", "{mixed:?}");
        assert!(hub.dialled().is_empty(), "{mixed:?} was dialled");
    }
}

/// A redirect to a host outside the Hub's domains is refused without a lookup or a dial of it.
#[tokio::test]
async fn rt_mdl_11_a_redirect_off_the_hub_is_not_followed() {
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
    assert_eq!(hub.dialled(), [public_443()]);
}

/// The file list is read from the API host only: a redirect of the list call to another Hub
/// host is refused, and that host is never looked up or dialled. Control: a relative redirect
/// on the API host is followed, with the token, and the list is read.
#[tokio::test]
async fn rt_mdl_11_a_list_redirected_off_the_api_host_is_refused() {
    let body = list_json(&[]);
    let hub = Hub::new(move |s, _| {
        if s.host == "huggingface.co" {
            found("https://cdn-lfs.hf.co/api/models/org/m/revision/main?blobs=true")
        } else {
            reply("200 OK", &[], &body)
        }
    });
    let err = bounded(hub.client(Some(&token())).files(&repo(), &Revision::main()))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "hf_redirect_refused");
    let seen = hub.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].auth, Some(format!("Bearer {}", token())));
    assert_eq!(hub.lookups(), ["huggingface.co"]);
    assert_eq!(hub.dialled(), [public_443()]);

    let body = list_json(&[]);
    let same = Hub::new(move |_, i| {
        if i == 0 {
            found("/api/models/org/m/revision/main?blobs=true&moved=1")
        } else {
            reply("200 OK", &[], &body)
        }
    });
    bounded(
        same.client(Some(&token()))
            .files(&repo(), &Revision::main()),
    )
    .await
    .unwrap();
    let seen = same.seen();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[1].host, "huggingface.co");
    assert_eq!(
        seen[1].path,
        "/api/models/org/m/revision/main?blobs=true&moved=1"
    );
    assert_eq!(seen[1].auth, Some(format!("Bearer {}", token())));
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

/// A digest already stored is answered from the library with no request; a row whose blob is
/// writable or missing is refused blob_mismatch, also with no request and no partial. The
/// control, the first pull of the digest, sends one.
#[tokio::test]
async fn a_stored_digest_sends_no_request() {
    use std::os::unix::fs::PermissionsExt as _;
    let g = gguf("stored");
    let served = g.clone();
    let hub = Hub::new(move |_, _| reply("200 OK", &[], &served));
    let lib = TmpLib::open("stored", 0);
    let l = list(&[("m.gguf", &g)]);
    let client = hub.client(None);
    let first = bounded(client.pull(&lib.lib, &repo(), &l, &path("m.gguf")))
        .await
        .unwrap();
    assert_eq!(hub.seen().len(), 1);

    let again = bounded(client.pull(&lib.lib, &repo(), &l, &path("m.gguf")))
        .await
        .unwrap();
    assert_eq!(again, first);
    assert_eq!(hub.seen().len(), 1);
    assert_eq!(hub.dialled(), [public_443()]);

    let blob = lib.path(&format!("blobs/sha256/{}", sha(&g).as_hex()));
    let chmod = |m| std::fs::set_permissions(&blob, std::fs::Permissions::from_mode(m)).unwrap();
    chmod(0o644);
    let err = bounded(client.pull(&lib.lib, &repo(), &l, &path("m.gguf")))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "blob_mismatch");
    chmod(0o444);
    std::fs::remove_file(&blob).unwrap();
    let err = bounded(client.pull(&lib.lib, &repo(), &l, &path("m.gguf")))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "blob_mismatch");
    assert_eq!(hub.seen().len(), 1);
    assert_eq!(hub.dialled(), [public_443()]);
    assert!(lib.names("downloads").is_empty());
    assert!(lib.names("blobs/sha256").is_empty());
}

/// A library poisoned by a panic is refused with its own code, not the blocking-task one, and
/// nothing is requested; the control, the same pull before the poison, is stored.
#[tokio::test]
async fn a_poisoned_library_has_its_own_code() {
    let g = gguf("poison");
    let served = g.clone();
    let hub = Hub::new(move |_, _| reply("200 OK", &[], &served));
    let lib = TmpLib::open("poison", 0);
    let client = hub.client(None);
    bounded(client.pull(&lib.lib, &repo(), &list(&[("m.gguf", &g)]), &path("m.gguf")))
        .await
        .unwrap();
    assert_eq!(hub.seen().len(), 1);

    let held = Arc::clone(&lib.lib);
    let panicked = std::thread::spawn(move || {
        let _guard = held.lock().unwrap();
        panic!("poison the library on purpose");
    })
    .join();
    assert!(panicked.is_err());
    let other = gguf("poison-2");
    let err = bounded(client.pull(
        &lib.lib,
        &repo(),
        &list(&[("n.gguf", &other)]),
        &path("n.gguf"),
    ))
    .await
    .unwrap_err();
    assert_eq!(err.code(), "hf_library_poisoned");
    assert!(err.to_string().contains("restart sallyd"), "{err}");
    assert_eq!(hub.seen().len(), 1);
}

/// The client's anchors come only from a checked bundle file: a missing bundle, or one others
/// could write, refuses the client; the control, the mock Hub's own bundle at 0644, gives a
/// client that lists. (The owner check needs a second uid; `egress::roots`'s tests cover it.)
#[tokio::test]
async fn rt_mdl_11_the_client_takes_its_roots_only_from_a_checked_bundle() {
    use std::os::unix::fs::PermissionsExt as _;
    let body = list_json(&[]);
    let hub = Hub::new(move |_, _| reply("200 OK", &[], &body));
    let make = |roots: &BundleFiles| {
        HfClient::with_roots(hub.clone(), hub.clone(), hub.clone(), roots, None).map(|_| ())
    };
    let mut missing = hub.roots().clone();
    missing.paths = vec![hub.bundles().absent()];
    assert_eq!(make(&missing).unwrap_err().code(), "hf_roots_failed");
    let bundle = hub.roots().paths[0].clone();
    let set = |m| std::fs::set_permissions(&bundle, std::fs::Permissions::from_mode(m)).unwrap();
    set(0o666);
    assert_eq!(make(hub.roots()).unwrap_err().code(), "hf_roots_failed");
    set(0o644);
    let client =
        HfClient::with_roots(hub.clone(), hub.clone(), hub.clone(), hub.roots(), None).unwrap();
    bounded(client.files(&repo(), &Revision::main()))
        .await
        .unwrap();
}

/// The client trusts no anchor but its bundle's: with a bundle holding only an unrelated CA
/// the handshake to the Hub fails and no request reaches it; the control, the Hub's own bundle
/// through the same seams, lists.
#[tokio::test]
async fn rt_mdl_11_the_client_trusts_no_anchor_but_its_bundle() {
    let body = list_json(&[]);
    let hub = Hub::new(move |_, _| reply("200 OK", &[], &body));
    let foreign = hub.bundles().write("foreign.pem", &foreign_ca_pem());
    let client =
        HfClient::with_roots(hub.clone(), hub.clone(), hub.clone(), &foreign, None).unwrap();
    let err = bounded(client.files(&repo(), &Revision::main()))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "hf_tls_failed");
    assert!(hub.seen().is_empty(), "a request reached the Hub");
    bounded(hub.client(None).files(&repo(), &Revision::main()))
        .await
        .unwrap();
    assert_eq!(hub.seen().len(), 1);
}

/// An empty answer, or one with more addresses than the bound, is a failed lookup and nothing
/// is dialled; the control, exactly the bound of public answers, is dialled once.
#[tokio::test]
async fn an_answer_outside_its_bounds_is_a_failed_lookup() {
    use crate::egress::server::MAX_ANSWER;
    let body = list_json(&[]);
    let hub = Hub::new(move |_, _| reply("200 OK", &[], &body));
    let client = hub.client(None);
    let at_bound = vec![PUBLIC; MAX_ANSWER];
    let mut over = at_bound.clone();
    over.push(PUBLIC);
    for (answer, what) in [(Vec::new(), "empty"), (over, "over the bound")] {
        hub.answer_all(&answer);
        let err = bounded(client.files(&repo(), &Revision::main()))
            .await
            .unwrap_err();
        assert_eq!(err.code(), "hf_resolve_failed", "{what}");
        assert!(hub.dialled().is_empty(), "{what}");
    }
    hub.answer_all(&at_bound);
    bounded(client.files(&repo(), &Revision::main()))
        .await
        .unwrap();
    assert_eq!(hub.dialled(), [public_443()]);
}

/// Answers are dialled by address on port 443 whatever port the lookup gave, in the answer's
/// order, and at most `MAX_DIALS` of them: five public answers on another port, every dial
/// failing, are the first three on 443, then a failed connect. Control: the same Hub with dials
/// that succeed dials the first answer on 443 once. (Which answers may be dialled at all is
/// `rt_mdl_11_denied_addresses_are_never_dialled`.)
#[tokio::test]
async fn rt_mdl_11_answers_are_dialled_on_443_in_order_up_to_the_bound() {
    use crate::egress::server::MAX_DIALS;
    let body = list_json(&[]);
    let hub = Hub::new(move |_, _| reply("200 OK", &[], &body));
    let ip = |last| IpAddr::V4(Ipv4Addr::new(93, 184, 215, last));
    let on_443 = |last| SocketAddr::new(ip(last), 443);
    let answers: Vec<IpAddr> = (9..14).map(ip).collect();
    hub.answer_all(&answers);
    hub.answer_port(8443);
    let client = hub.client(None);
    bounded(client.files(&repo(), &Revision::main()))
        .await
        .unwrap();
    assert_eq!(hub.dialled(), [on_443(9)]);
    assert_eq!(hub.seen().len(), 1);

    hub.dials_fail();
    let err = bounded(client.files(&repo(), &Revision::main()))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "hf_connect_failed");
    assert_eq!(MAX_DIALS, 3);
    assert_eq!(
        hub.dialled(),
        [on_443(9), on_443(9), on_443(10), on_443(11)]
    );
    assert_eq!(hub.lookups().len(), 2, "one lookup for the failing call");
    assert_eq!(
        hub.seen().len(),
        1,
        "a request was sent without a connection"
    );
}

/// Every transport variant has its own stable code; wrapped core and library errors keep
/// theirs.
#[test]
fn every_pull_error_has_its_code() {
    let host = || "huggingface.co".to_owned();
    let cases = [
        (PullError::Hf(HfError::ListTooLarge), "hf_list_too_large"),
        (
            PullError::Library(LibraryError::DownloadBusy),
            "download_busy",
        ),
        (PullError::ResolveFailed(host()), "hf_resolve_failed"),
        (PullError::AddressDenied(host()), "hf_address_denied"),
        (PullError::ConnectFailed(host()), "hf_connect_failed"),
        (PullError::TlsFailed(host()), "hf_tls_failed"),
        (PullError::Timeout("response head"), "hf_timeout"),
        (PullError::Protocol, "hf_protocol"),
        (PullError::HeaderInvalid("Location"), "hf_header_invalid"),
        (PullError::BodyFailed, "hf_body_failed"),
        (PullError::TokenUnusable, "hf_token_unusable"),
        (PullError::Task, "hf_task_failed"),
        (
            PullError::Roots(RootsError::NotFound("x".to_owned())),
            "hf_roots_failed",
        ),
        (
            PullError::TlsConfig(rustls::Error::General("x".to_owned())),
            "hf_tls_config",
        ),
        (PullError::LibraryPoisoned, "hf_library_poisoned"),
    ];
    for (err, code) in cases {
        assert_eq!(err.code(), code, "{err}");
    }
}

/// The rig's GGUF bytes pass the strict parser, so a refusal in these tests is never the
/// fixture's.
#[test]
fn the_fixture_is_a_valid_gguf() {
    let g = gguf("x");
    sally_core::model::gguf::parse(&g[..], g.len() as u64).unwrap();
}
