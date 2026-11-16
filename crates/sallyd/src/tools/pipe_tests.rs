#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::pin::Pin;
use std::task::{Context, Poll};

use sally_proto::MAX_OUTPUT_CHUNK;
use tokio::sync::oneshot;

use super::*;

/// Marks that never fire, and their senders (kept alive).
fn marks() -> (watch::Sender<bool>, watch::Sender<bool>, Marks) {
    let (halt, exited) = (watch::Sender::new(false), watch::Sender::new(false));
    let m = (halt.subscribe(), exited.subscribe());
    (halt, exited, m)
}

/// Every chunk `rx` still holds, joined, and the streams they named.
fn drained(rx: &mut mpsc::Receiver<Chunk>) -> (String, Vec<Stream>) {
    let (mut text, mut streams) = (String::new(), Vec::new());
    while let Ok(c) = rx.try_recv() {
        text.push_str(&c.text);
        streams.push(c.stream);
    }
    (text, streams)
}

/// A pipe's output is escaped (one escaper for its whole stream: a character cut between two
/// reads is carried, never escaped by halves), labelled with its stream, and counted raw.
#[tokio::test]
async fn a_pipe_is_escaped_whole_labelled_and_counted() {
    let (mut w, r) = tokio::io::duplex(64);
    let (tx, mut rx) = mpsc::channel(16);
    let (_h, _e, m) = marks();
    let counts = Arc::new(Counts::default());
    let task = tokio::spawn(stream(r, Stream::Stderr, tx, m, Arc::clone(&counts)));
    let smile = "\u{1f600}".as_bytes();
    w.write_all(b"\x1b[2J").await.unwrap();
    w.write_all(&smile[..2]).await.unwrap();
    w.flush().await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    w.write_all(&smile[2..]).await.unwrap();
    w.write_all(b"\n\xff").await.unwrap();
    drop(w);
    task.await.unwrap();
    let (text, streams) = drained(&mut rx);
    assert_eq!(text, "\\x1b[2J\\u{1f600}\n\\xff");
    assert!(streams.iter().all(|s| *s == Stream::Stderr));
    assert_eq!(counts.stderr.load(Ordering::Relaxed), 10);
    assert_eq!(counts.stdout.load(Ordering::Relaxed), 0);
}

/// A character cut by the pipe's end is shown byte by byte, never dropped.
#[tokio::test]
async fn what_is_carried_at_the_end_is_still_shown() {
    let (mut w, r) = tokio::io::duplex(64);
    let (tx, mut rx) = mpsc::channel(16);
    let (_h, _e, m) = marks();
    let task = tokio::spawn(stream(r, Stream::Stdout, tx, m, Arc::default()));
    w.write_all(&"\u{e9}".as_bytes()[..1]).await.unwrap();
    drop(w);
    task.await.unwrap();
    assert_eq!(drained(&mut rx).0, "\\xc3");
}

/// A read never takes more than one chunk's worth, carry included.
#[tokio::test]
async fn a_read_is_at_most_one_chunk() {
    let (mut w, r) = tokio::io::duplex(4 * MAX_OUTPUT_CHUNK);
    let (tx, mut rx) = mpsc::channel(16);
    let (_h, _e, m) = marks();
    let counts = Arc::new(Counts::default());
    let task = tokio::spawn(stream(r, Stream::Stdout, tx, m, Arc::clone(&counts)));
    w.write_all(&vec![b'a'; 2 * MAX_OUTPUT_CHUNK + 1])
        .await
        .unwrap();
    drop(w);
    task.await.unwrap();
    let mut sizes = Vec::new();
    while let Ok(c) = rx.try_recv() {
        sizes.push(c.text.len());
    }
    assert!(sizes.iter().all(|n| *n <= MAX_OUTPUT_CHUNK), "{sizes:?}");
    assert_eq!(sizes.iter().sum::<usize>(), 2 * MAX_OUTPUT_CHUNK + 1);
    assert_eq!(
        counts.stdout.load(Ordering::Relaxed),
        2 * MAX_OUTPUT_CHUNK as u64 + 1
    );
}

/// A reader blocked on a full queue stops at once when halted: a client that does not read
/// never delays a kill.
#[tokio::test]
async fn a_halt_stops_a_reader_blocked_on_a_full_queue() {
    let (mut w, r) = tokio::io::duplex(1 << 20);
    let (tx, mut rx) = mpsc::channel(1);
    let (halt, _e, m) = marks();
    let task = tokio::spawn(stream(r, Stream::Stdout, tx, m, Arc::default()));
    w.write_all(b"one\n").await.unwrap();
    w.flush().await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    w.write_all(b"two\n").await.unwrap();
    w.flush().await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(!task.is_finished(), "the reader did not wait for room");
    halt.send_replace(true);
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("a halted reader kept waiting")
        .unwrap();
    assert_eq!(rx.recv().await.unwrap().text, "one\n");
    // The writer side is still open: only the halt ended it.
    drop(w);
}

/// Once the client exited, a pipe something else keeps open is read until it is idle for
/// [`DRAIN_LIMIT`]; while it is written to, the reading goes on.
#[tokio::test(start_paused = true)]
async fn after_the_exit_a_pipe_is_read_until_it_is_idle() {
    let (mut w, r) = tokio::io::duplex(64);
    let (tx, mut rx) = mpsc::channel(16);
    let (_h, exited, m) = marks();
    let task = tokio::spawn(stream(r, Stream::Stdout, tx, m, Arc::default()));
    exited.send_replace(true);
    tokio::time::sleep(DRAIN_LIMIT - Duration::from_millis(100)).await;
    w.write_all(b"late\n").await.unwrap();
    tokio::time::sleep(DRAIN_LIMIT - Duration::from_millis(100)).await;
    assert!(!task.is_finished(), "ended before it was idle");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(task.is_finished(), "still reading after the idle bound");
    assert_eq!(drained(&mut rx).0, "late\n");
    drop(w);
}

/// A read error ends the pipe like its end.
#[tokio::test]
async fn a_read_error_ends_the_pipe() {
    struct Broken;
    impl AsyncRead for Broken {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Err(std::io::ErrorKind::Other.into()))
        }
    }
    let (tx, mut rx) = mpsc::channel(1);
    let (_h, _e, m) = marks();
    tokio::time::timeout(
        Duration::from_secs(5),
        stream(Broken, Stream::Stdout, tx, m, Arc::default()),
    )
    .await
    .expect("a read error did not end the pipe");
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn send_queues_text_and_says_when_it_cannot() {
    let (tx, mut rx) = mpsc::channel(1);
    let (halt, _e, (mut h, _)) = marks();
    assert!(send(&tx, Stream::Stdout, String::new(), &mut h).await);
    assert!(rx.try_recv().is_err(), "an empty text was queued");
    assert!(send(&tx, Stream::Stdout, "a".into(), &mut h).await);
    assert_eq!(rx.try_recv().unwrap().text, "a");
    halt.send_replace(true);
    assert!(!send(&tx, Stream::Stdout, "b".into(), &mut h).await);
    drop(rx);
    let (_halt, _e, (mut h, _)) = marks();
    assert!(!send(&tx, Stream::Stdout, "c".into(), &mut h).await);
}

/// One input to write, and its answer.
fn input(data: &[u8], eof: bool) -> (Input, oneshot::Receiver<bool>) {
    let (done, ack) = oneshot::channel();
    let i = Input {
        data: data.to_vec(),
        eof,
        done,
    };
    (i, ack)
}

/// Inputs are written in order and counted; `eof` closes the pipe, and every input after it
/// is answered `false`, unwritten.
#[tokio::test]
async fn inputs_are_written_in_order_until_eof() {
    let (w, mut r) = tokio::io::duplex(1024);
    let (tx, rx) = mpsc::channel(4);
    let counts = Arc::new(Counts::default());
    let task = tokio::spawn(write_input(w, rx, Arc::clone(&counts)));
    let (a, a_ack) = input(b"one\n", false);
    let (b, b_ack) = input(b"two\n", true);
    let (c, c_ack) = input(b"three\n", false);
    for i in [a, b, c] {
        tx.send(i).await.unwrap();
    }
    assert_eq!(
        (
            a_ack.await.unwrap(),
            b_ack.await.unwrap(),
            c_ack.await.unwrap()
        ),
        (true, true, false)
    );
    let mut got = Vec::new();
    r.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"one\ntwo\n", "the pipe was not closed at eof");
    assert_eq!(counts.stdin.load(Ordering::Relaxed), 8);
    drop(tx);
    task.await.unwrap();
}

/// A write that fails is answered `false`, and so is every later input.
#[tokio::test]
async fn a_failed_write_closes_the_input() {
    let (w, r) = tokio::io::duplex(1024);
    drop(r);
    let (tx, rx) = mpsc::channel(4);
    let counts = Arc::new(Counts::default());
    let task = tokio::spawn(write_input(w, rx, Arc::clone(&counts)));
    let (a, a_ack) = input(b"one\n", false);
    tx.send(a).await.unwrap();
    assert!(!a_ack.await.unwrap());
    let (b, b_ack) = input(b"", false);
    tx.send(b).await.unwrap();
    assert!(
        !b_ack.await.unwrap(),
        "an input after a failed write was taken"
    );
    assert_eq!(counts.stdin.load(Ordering::Relaxed), 0);
    drop(tx);
    task.await.unwrap();
}

/// A stop wins over a disconnect; a dropped disconnect watch is a disconnect; with no watch
/// only a stop ends the run.
#[tokio::test(start_paused = true)]
async fn why_a_run_ends() {
    let ops = Ops::new();
    let (gone, rx) = watch::channel(false);
    gone.send_replace(true);
    ops.stop();
    assert_eq!(ended(&ops, Some(rx.clone())).await, SESSION_STOP);
    let ops = Ops::new();
    assert_eq!(ended(&ops, Some(rx)).await, DISCONNECT);
    let (dropped, rx) = watch::channel(false);
    drop(dropped);
    assert_eq!(ended(&ops, Some(rx)).await, DISCONNECT);
    let waiting = tokio::time::timeout(Duration::from_secs(60), ended(&ops, None)).await;
    assert!(waiting.is_err(), "ended with no stop and no watch");
    ops.stop();
    assert_eq!(ended(&ops, None).await, SESSION_STOP);
}

#[tokio::test(start_paused = true)]
async fn within_a_limit_or_none() {
    let slow = tokio::time::sleep(Duration::from_secs(10));
    assert!(within(Some(Duration::from_secs(1)), slow).await.is_err());
    let slow = tokio::time::sleep(Duration::from_secs(10));
    assert!(within(None, slow).await.is_ok());
    let quick = async { 7 };
    assert_eq!(
        within(Some(Duration::from_secs(1)), quick).await.ok(),
        Some(7)
    );
}

#[test]
fn the_drain_limit() {
    assert_eq!(DRAIN_LIMIT, Duration::from_millis(500));
}
