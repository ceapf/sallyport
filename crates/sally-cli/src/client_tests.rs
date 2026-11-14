#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Read as _;
use std::os::unix::net::UnixListener;
use std::time::Duration;

use super::*;

#[test]
fn only_this_users_socket_is_spoken_to() {
    assert!(check_owner(Some(1000), 1000).is_ok());
    assert!(matches!(
        check_owner(Some(0), 1000),
        Err(Error::Owner { owner: Some(0) })
    ));
    assert!(matches!(
        check_owner(None, 1000),
        Err(Error::Owner { owner: None })
    ));
}

#[test]
fn frames_are_read_up_to_the_cap_and_never_past_it() {
    let mut r = BufReader::with_capacity(4, &b"abc\nabcd\nabcde\n"[..]);
    assert_eq!(read_frame(&mut r, 4).unwrap(), Some(b"abc".to_vec()));
    assert_eq!(read_frame(&mut r, 4).unwrap(), Some(b"abcd".to_vec()));
    assert!(matches!(read_frame(&mut r, 4), Err(Error::TooLarge)));
    let mut end = &b""[..];
    assert_eq!(read_frame(&mut end, 4).unwrap(), None);
    let mut cut = &b"ab"[..];
    assert!(matches!(read_frame(&mut cut, 4), Err(Error::Closed)));
}

#[test]
fn a_frame_is_a_reply_or_a_note_and_nothing_else() {
    let Decoded::Reply { id, result } = decode(json!({"id": 1, "result": {"a": 1}})).unwrap()
    else {
        panic!("not a reply")
    };
    assert_eq!((id, result.unwrap()), (json!(1), json!({"a": 1})));
    let refused = decode(json!({"id": 1, "error": {"code": -32000, "data": {"reason": "r"}}}));
    assert!(matches!(
        refused,
        Ok(Decoded::Reply { result: Err(Error::Refused(d)), .. }) if d.reason == "r"
    ));
    assert!(matches!(
        decode(json!({"id": 1})),
        Ok(Decoded::Reply {
            result: Err(Error::Unexpected),
            ..
        })
    ));
    assert!(matches!(
        decode(json!({"method": "m"})),
        Ok(Decoded::Note(_))
    ));
    assert!(matches!(
        decode(json!({"params": {}})),
        Err(Error::Unexpected)
    ));
    assert!(matches!(
        only_note(json!({"id": 1, "method": "m"})),
        Err(Error::Unexpected)
    ));
}

#[test]
fn the_socket_is_under_the_runtime_dir() {
    assert_eq!(SOCKET, "sallyport/control.sock");
}

/// The bounds hold together: one largest note fits what a call holds, and so does everything
/// the reader can have queued.
#[test]
fn the_queue_bounds_fit_together() {
    assert_eq!((FRAME_QUEUE, NOTES_BYTES), (8, 16 << 20));
    const {
        assert!(MAX_FRAME < NOTES_BYTES);
        assert!((FRAME_QUEUE + 1) * MAX_FRAME <= NOTES_BYTES);
    }
}

fn listen(tag: &str) -> (UnixListener, PathBuf) {
    // Its own prefix: the approve tests' fakes use `sp-cli-<tag>`.
    let path = std::env::temp_dir().join(format!("sp-cli-c-{tag}-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    (UnixListener::bind(&path).unwrap(), path)
}

#[test]
fn dropping_a_client_closes_its_connection() {
    let (listener, path) = listen("drop");
    let c = Client::connect(&path).unwrap();
    let (mut server, _) = listener.accept().unwrap();
    let _ = std::fs::remove_file(&path);
    server
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    drop(c);
    let mut buf = [0u8; 1];
    assert_eq!(server.read(&mut buf).unwrap(), 0, "the server sees the end");
}

/// Architect Q91: with nothing taken, the reader stops reading once its queue is full, so the
/// server's writes block; dropping the client lets it go.
#[test]
fn a_client_that_takes_nothing_stops_reading() {
    let (listener, path) = listen("full");
    let c = Client::connect(&path).unwrap();
    let (mut server, _) = listener.accept().unwrap();
    let _ = std::fs::remove_file(&path);
    server.set_nonblocking(true).unwrap();
    let frame = {
        let mut f =
            serde_json::to_vec(&json!({"method": "n", "params": "x".repeat(64 << 10)})).unwrap();
        f.push(b'\n');
        f
    };
    // Unbounded, the reader would take all 64 MiB; bounded, the writes stop for good well
    // before (the queue, one frame in hand, the reader's buffer and the kernel's). The 4 MiB
    // slack assumes a Unix socket buffer near Linux's default (`net.core.wmem_default`, about
    // 208 KiB); a host tuned above 4 MiB would fail this falsely.
    let limit = 64 << 20;
    let mut written = 0usize;
    let mut stalled = 0;
    while written < limit && stalled < 50 {
        match server.write(&frame[written % frame.len()..]) {
            Ok(n) => {
                written += n;
                stalled = 0;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                stalled += 1;
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => panic!("{e}"),
        }
    }
    assert!(stalled >= 50, "the reader kept reading: {written} bytes");
    assert!(
        written < (FRAME_QUEUE + 2) * frame.len() + (4 << 20),
        "{written}"
    );
    drop(c);
    server.set_nonblocking(false).unwrap();
    server
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    assert!(
        server.write_all(&frame).is_err(),
        "the connection is shut down"
    );
}

/// Architect Q91: the reader returns once the client is gone, even with frames still to read.
#[test]
fn the_reader_ends_when_its_client_is_gone() {
    let many = "{\"method\":\"n\"}\n".repeat(100);
    let (tx, rx) = mpsc::sync_channel(1);
    let t = std::thread::spawn(move || read_frames(BufReader::new(many.as_bytes()), &tx));
    drop(rx);
    t.join().unwrap();
}

/// The end of the stream is told as `Closed`, not only by the queue disconnecting.
#[test]
fn the_end_of_the_stream_is_told() {
    let (tx, rx) = mpsc::sync_channel(4);
    read_frames(BufReader::new(&b"{\"method\":\"n\"}\n"[..]), &tx);
    assert!(matches!(rx.recv().unwrap(), Ok((_, 14))));
    assert!(matches!(rx.recv().unwrap(), Err(Error::Closed)));
}

fn note_of(len: usize) -> Frame {
    Ok((json!({"jsonrpc": "2.0", "method": "approval.closed"}), len))
}

/// A reply to another request is not this call's; a held note is given back as it came.
#[test]
fn a_reply_must_carry_the_calls_id_and_notes_come_back_whole() {
    let (w, _peer) = UnixStream::pair().unwrap();
    let (tx, rx) = mpsc::sync_channel(8);
    let mut c = Client::from_parts(w, rx);
    let n = json!({"jsonrpc": "2.0", "method": "approval.closed", "params": {"id": "p1"}});
    tx.send(Ok((n.clone(), 10))).unwrap();
    tx.send(Ok((json!({"jsonrpc": "2.0", "id": 99, "result": {}}), 10)))
        .unwrap();
    assert!(matches!(
        c.call("sessions.list", json!({})),
        Err(Error::Unexpected)
    ));
    assert_eq!(c.next_note().unwrap(), n);
    tx.send(Ok((n.clone(), 10))).unwrap();
    assert_eq!(c.next_note().unwrap(), n, "one taken from the queue too");
}

/// Architect Q91: a call holds the notifications before its reply up to `NOTES_BYTES`; one
/// byte more is fatal.
#[test]
fn a_call_holds_notes_up_to_the_byte_cap() {
    for (over, ok) in [(0, true), (1, false)] {
        let (w, _peer) = UnixStream::pair().unwrap();
        let (tx, rx) = mpsc::sync_channel(8);
        let mut c = Client::from_parts(w, rx);
        let feeder = std::thread::spawn(move || {
            tx.send(note_of(NOTES_BYTES - 1)).unwrap();
            tx.send(note_of(1 + over)).unwrap();
            let _ = tx.send(Ok((json!({"jsonrpc": "2.0", "id": 1, "result": {}}), 40)));
        });
        let r = c.call("sessions.list", json!({}));
        feeder.join().unwrap();
        if ok {
            assert_eq!(r.unwrap(), json!({}));
            assert!(c.try_note().unwrap().is_some());
            assert!(c.try_note().unwrap().is_some());
            assert_eq!(c.notes_bytes, 0, "taking a note frees its bytes");
        } else {
            assert!(matches!(r, Err(Error::Behind)), "{r:?}");
        }
    }
}
