#![allow(clippy::unwrap_used)]

use std::sync::Mutex;

use http_body_util::BodyExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

use super::*;

#[tokio::test]
async fn a_meter_replays_first_then_counts_both_ways() {
    let (inner, mut far) = duplex(64);
    let counts = Counts::default();
    let act = Arc::new(Activity::new());
    let mut m = Meter::new(
        inner,
        b"hello".to_vec(),
        counts.clone(),
        Some(Arc::clone(&act)),
    );
    far.write_all(b" world").await.unwrap();
    let mut got = [0u8; 11];
    m.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"hello world");
    m.write_all(b"back").await.unwrap();
    let mut back = [0u8; 4];
    far.read_exact(&mut back).await.unwrap();
    assert_eq!((counts.read(), counts.written()), (11, 4));
}

#[tokio::test]
async fn a_small_read_takes_the_replay_in_pieces() {
    let (inner, _far) = duplex(64);
    let counts = Counts::default();
    let mut m = Meter::new(inner, b"abc".to_vec(), counts.clone(), None);
    let mut one = [0u8; 2];
    assert_eq!(m.read(&mut one).await.unwrap(), 2);
    assert_eq!(&one, b"ab");
    assert_eq!(m.read(&mut one).await.unwrap(), 1);
    assert_eq!(one[0], b'c');
    assert_eq!(counts.read(), 3);
}

#[tokio::test]
async fn max_read_hands_out_at_most_that_many_bytes_per_read() {
    let (inner, mut far) = duplex(64);
    let counts = Counts::default();
    let mut m = Meter::new(inner, Vec::new(), counts.clone(), None).max_read(3);
    far.write_all(b"abcdefg").await.unwrap();
    let mut big = [0u8; 16];
    assert_eq!(m.read(&mut big).await.unwrap(), 3);
    assert_eq!(&big[..3], b"abc");
    assert_eq!(m.read(&mut big).await.unwrap(), 3);
    assert_eq!(&big[..3], b"def");
    let mut small = [0u8; 1];
    assert_eq!(m.read(&mut small).await.unwrap(), 1);
    assert_eq!(counts.read(), 7);
    let zero = Meter::new(tokio::io::empty(), Vec::new(), Counts::default(), None).max_read(0);
    assert_eq!(zero.max_read, Some(1));
}

#[derive(Default)]
struct Record(Mutex<Vec<Option<BodyEnd>>>);

impl OnEnd for Record {
    fn ended(&self, how: Option<BodyEnd>) -> Option<Pin<Box<dyn Future<Output = ()> + Send>>> {
        self.0.lock().unwrap().push(how);
        None
    }
}

/// A body over a vector of frames.
struct Frames(std::vec::IntoIter<Result<Frame<Bytes>, BoxError>>);

impl Body for Frames {
    type Data = Bytes;
    type Error = BoxError;
    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        Poll::Ready(self.get_mut().0.next())
    }
}

fn body(frames: Vec<Result<Frame<Bytes>, BoxError>>) -> Frames {
    Frames(frames.into_iter())
}

fn data(s: &str) -> Result<Frame<Bytes>, BoxError> {
    Ok(Frame::data(Bytes::from(s.to_owned())))
}

#[tokio::test]
async fn a_body_at_its_cap_passes_whole_without_trailers() {
    let rec = Arc::new(Record::default());
    let mut trailers = hyper::HeaderMap::new();
    trailers.insert("x-secret", "v".parse().unwrap());
    let frames = vec![data("abc"), data("de"), Ok(Frame::trailers(trailers))];
    let capped = Capped::new(body(frames), 5, Arc::clone(&rec) as Arc<dyn OnEnd>);
    let out = capped.collect().await.unwrap();
    assert!(out.trailers().is_none());
    assert_eq!(out.to_bytes(), "abcde");
    assert_eq!(*rec.0.lock().unwrap(), [Some(BodyEnd::Complete)]);
}

#[tokio::test]
async fn one_byte_over_the_cap_is_a_cut_reported_once() {
    let rec = Arc::new(Record::default());
    let frames = vec![data("abc"), data("def"), data("never")];
    let mut capped = Capped::new(body(frames), 5, Arc::clone(&rec) as Arc<dyn OnEnd>);
    let first = capped.frame().await.unwrap().unwrap();
    assert_eq!(first.into_data().unwrap(), "abc");
    let err = capped.frame().await.unwrap().unwrap_err();
    assert!(err.is::<OverCap>());
    assert_eq!(capped.seen(), 6);
    drop(capped);
    assert_eq!(*rec.0.lock().unwrap(), [Some(BodyEnd::OverCap)]);
}

#[tokio::test]
async fn the_audit_future_finishes_before_the_cut() {
    struct Slow(Arc<Mutex<Vec<&'static str>>>);
    impl OnEnd for Slow {
        fn ended(&self, how: Option<BodyEnd>) -> Option<Pin<Box<dyn Future<Output = ()> + Send>>> {
            assert_eq!(how, Some(BodyEnd::OverCap));
            let log = Arc::clone(&self.0);
            Some(Box::pin(async move {
                tokio::task::yield_now().await;
                log.lock().unwrap().push("audited");
            }))
        }
    }
    let log = Arc::new(Mutex::new(Vec::new()));
    let frames = vec![data("toolong")];
    let mut capped = Capped::new(
        body(frames),
        3,
        Arc::new(Slow(Arc::clone(&log))) as Arc<dyn OnEnd>,
    );
    let err = capped.frame().await.unwrap().unwrap_err();
    log.lock().unwrap().push("cut");
    assert!(err.is::<OverCap>());
    assert_eq!(*log.lock().unwrap(), ["audited", "cut"]);
}

#[tokio::test]
async fn a_failing_inner_body_is_reported_and_a_dropped_one_says_so() {
    let rec = Arc::new(Record::default());
    let frames = vec![data("a"), Err("upstream gone".into())];
    let capped = Capped::new(body(frames), 10, Arc::clone(&rec) as Arc<dyn OnEnd>);
    assert!(capped.collect().await.is_err());
    let early = Capped::new(
        body(vec![data("a")]),
        10,
        Arc::clone(&rec) as Arc<dyn OnEnd>,
    );
    drop(early);
    assert_eq!(*rec.0.lock().unwrap(), [Some(BodyEnd::Failed), None]);
}
