#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
//! The transport's bounds: each refusal with its control in the same test.

use std::future::Future;
use std::time::Duration;

use sally_core::hf::list::{FileList, parse_list};
use sally_core::hf::names::{RepoId, RepoPath, Revision};

use super::testkit::{Hub, STALL, TmpLib, chunked, gguf, list_json, reply, sha};
use super::*;

fn repo() -> RepoId {
    RepoId::parse("org/m").unwrap()
}

fn path() -> RepoPath {
    RepoPath::parse("m.gguf").unwrap()
}

fn list(g: &[u8]) -> FileList {
    parse_list(&list_json(&[("m.gguf", g)])).unwrap()
}

async fn bounded<F: Future>(f: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(600), f)
        .await
        .expect("the test hung")
}

/// A library holding `bytes` of the partial for `g`.
fn with_partial(tag: &str, g: &[u8], bytes: &[u8]) -> TmpLib {
    let lib = TmpLib::open(tag, 0);
    {
        let mut l = lib.lib.lock().unwrap();
        let mut d = l.begin_download("m.gguf", &sha(g), g.len() as u64).unwrap();
        d.append(bytes).unwrap();
    }
    lib
}

fn partial(lib: &TmpLib, g: &[u8]) -> Vec<u8> {
    std::fs::read(lib.path(&format!("downloads/{}.part", sha(g).as_hex()))).unwrap()
}

/// Lets every spawned task run until all are idle (the clock is paused, so this costs nothing).
async fn settle() {
    tokio::time::sleep(Duration::from_secs(1)).await;
}

/// The guard on an exchange's connection task aborts it when dropped: a task that would never
/// end on its own, holding its stream, ends with the guard and the peer sees the stream close;
/// while the guard is held the stream stays open (the control).
#[tokio::test(start_paused = true)]
async fn a_dropped_conn_task_is_aborted() {
    use tokio::io::AsyncReadExt as _;
    let (near, mut far) = tokio::io::duplex(64);
    let task = ConnTask::spawn(async move {
        let _held = near;
        std::future::pending::<()>().await;
    });
    settle().await;
    let mut buf = [0_u8; 1];
    let open = tokio::time::timeout(Duration::from_secs(1), far.read(&mut buf)).await;
    assert!(open.is_err(), "the stream ended while the guard was held");
    drop(task);
    assert_eq!(bounded(far.read(&mut buf)).await.unwrap(), 0);
}

/// No connection outlives its exchange: while a response whose body stalls is held, its
/// connection stays open (the control); once it is dropped, the peer sees the connection end.
/// (The HTTP layer ends it too; the guard's own test above is the one that fails without it.)
#[tokio::test(start_paused = true)]
async fn a_dropped_exchange_closes_its_connection() {
    let hub = Hub::new(|_, _| {
        let mut r = reply("200 OK", &[], b"0123456789");
        r.truncate(r.len() - 5);
        r.extend_from_slice(STALL);
        r
    });
    let client = hub.client(None);
    let req = list_request(&repo(), &Revision::main());
    let held = bounded(client.exchange(&req)).await.unwrap();
    settle().await;
    assert_eq!(hub.closed(), 0, "closed while still held");
    drop(held);
    settle().await;
    assert_eq!(hub.closed(), 1, "the connection outlived its exchange");
}

/// A head that never comes: the exchange gives up after the head bound, and the peer sees the
/// connection end.
#[tokio::test(start_paused = true)]
async fn a_timed_out_head_closes_its_connection() {
    let hub = Hub::new(|_, _| STALL.to_vec());
    let client = hub.client(None);
    let req = list_request(&repo(), &Revision::main());
    let err = bounded(client.exchange(&req)).await.err().unwrap();
    assert_eq!(err.code(), "hf_timeout");
    settle().await;
    assert_eq!(hub.closed(), 1, "the connection outlived its exchange");
}

/// The transport's bounds are the values chosen for it; changing one is a reviewed decision.
#[test]
fn the_transport_bounds_are_pinned() {
    assert_eq!(HEAD_TIMEOUT, Duration::from_secs(30));
    assert_eq!(LIST_TIMEOUT, Duration::from_secs(60));
    assert_eq!(BODY_IDLE, Duration::from_secs(60));
    assert_eq!(WRITE_BATCH, 1024 * 1024);
    assert_eq!(conn::RESOLVE_TIMEOUT, Duration::from_secs(5));
    assert_eq!(conn::CONNECT_TIMEOUT, Duration::from_secs(10));
    assert_eq!(conn::TLS_TIMEOUT, Duration::from_secs(10));
}

/// A batch is written once it holds the batch size, not before.
#[test]
fn a_batch_is_written_at_its_size() {
    assert!(!batch_full(WRITE_BATCH - 1));
    assert!(batch_full(WRITE_BATCH));
}

/// A chunked list body (no length to refuse early) of exactly the bound parses; one byte more
/// is refused as it is read.
#[tokio::test]
async fn a_list_body_past_the_bound_is_refused() {
    let mut at = list_json(&[]);
    at.splice(0..0, std::iter::repeat_n(b' ', MAX_LIST_BYTES - at.len()));
    let mut over = at.clone();
    over.insert(0, b' ');
    let hub = Hub::new(move |_, i| chunked("200 OK", &[], if i == 0 { &at } else { &over }));
    let client = hub.client(None);
    bounded(client.files(&repo(), &Revision::main()))
        .await
        .unwrap();
    let err = bounded(client.files(&repo(), &Revision::main()))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "hf_list_too_large");
}

/// A body that runs past the listed size is refused and the partial deleted; the control, the
/// same chunked 206 with exactly the rest, is stored.
#[tokio::test]
async fn a_body_past_the_size_discards_the_partial() {
    let g = gguf("long");
    let half = g.len() / 2;
    let range = format!("Content-Range: bytes {half}-{}/{}", g.len() - 1, g.len());
    let rest = g[half..].to_vec();
    let mut longer = rest.clone();
    longer.extend_from_slice(b"extra");
    let (r, a, b) = (range.clone(), rest.clone(), longer.clone());
    let hub =
        Hub::new(move |_, i| chunked("206 Partial Content", &[&r], if i == 0 { &a } else { &b }));
    let client = hub.client(None);

    let ok = with_partial("long-ok", &g, &g[..half]);
    bounded(client.pull(&ok.lib, &repo(), &list(&g), &path()))
        .await
        .unwrap();

    let bad = with_partial("long-bad", &g, &g[..half]);
    let err = bounded(client.pull(&bad.lib, &repo(), &list(&g), &path()))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "download_too_long");
    assert!(bad.names("downloads").is_empty(), "the partial was kept");
    assert!(bad.names("blobs/sha256").is_empty());
}

/// A refusal that leaves the bytes trustworthy keeps the partial; the control, a refusal that
/// does not (416), deletes it.
#[tokio::test]
async fn a_plain_refusal_keeps_the_partial() {
    let g = gguf("keep");
    let hub = Hub::new(|_, i| {
        if i == 0 {
            reply("404 Not Found", &[], b"")
        } else {
            reply("416 Range Not Satisfiable", &[], b"")
        }
    });
    let client = hub.client(None);
    let lib = with_partial("keep", &g, b"GGUF");
    let err = bounded(client.pull(&lib.lib, &repo(), &list(&g), &path()))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "hf_not_found");
    assert_eq!(partial(&lib, &g), b"GGUF");
    let err = bounded(client.pull(&lib.lib, &repo(), &list(&g), &path()))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "hf_range_refused");
    assert!(lib.names("downloads").is_empty());
}

/// A server that never answers the head is given up on after the head bound; the partial is
/// kept.
#[tokio::test(start_paused = true)]
async fn a_stalled_head_times_out() {
    let g = gguf("stall-head");
    let hub = Hub::new(|_, _| STALL.to_vec());
    let lib = with_partial("stall-head", &g, b"GGUF");
    let started = tokio::time::Instant::now();
    let err = bounded(hub.client(None).pull(&lib.lib, &repo(), &list(&g), &path()))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "hf_timeout");
    assert!(started.elapsed() >= HEAD_TIMEOUT);
    assert_eq!(partial(&lib, &g), b"GGUF");
}

/// A body that stops arriving is given up on after the idle bound; what arrived is kept. The
/// control, the same body sent whole, is stored.
#[tokio::test(start_paused = true)]
async fn a_stalled_body_keeps_what_arrived() {
    let g = gguf("stall-body");
    let half = g.len() / 2;
    let whole = g.clone();
    let hub = Hub::new(move |_, i| {
        let mut r = reply("200 OK", &[], &whole);
        if i == 1 {
            r.truncate(r.len() - (whole.len() - half));
            r.extend_from_slice(STALL);
        }
        r
    });
    let client = hub.client(None);
    let ok = TmpLib::open("stall-ok", 0);
    bounded(client.pull(&ok.lib, &repo(), &list(&g), &path()))
        .await
        .unwrap();

    let lib = TmpLib::open("stall-body", 0);
    let started = tokio::time::Instant::now();
    let err = bounded(client.pull(&lib.lib, &repo(), &list(&g), &path()))
        .await
        .unwrap_err();
    assert_eq!(err.code(), "hf_body_failed");
    assert!(started.elapsed() >= BODY_IDLE);
    assert_eq!(partial(&lib, &g), &g[..half]);
}
