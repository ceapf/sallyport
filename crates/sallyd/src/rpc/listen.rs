//! The accept loop every broker socket shares (architect rulings Q1 and Q8): at most `max`
//! connections at once (past that nothing more is accepted until one ends), and a peer-UID check
//! before a single byte is read. Rootless Podman runs the sandboxes with `--userns=keep-id` and
//! the user's own UID, so a legitimate peer is always that UID; any other peer is refused, its
//! refusal recorded by the server, and its stream closed.

use std::future::Future;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::task::{JoinHandle, JoinSet};

/// Time the accept loop waits after a failed accept (EMFILE and similar).
pub const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);
/// Time [`Handle::shutdown`] waits for open connections to finish after stop.
pub const STOP_GRACE: Duration = Duration::from_secs(2);

/// A server the loop hands its connections to.
pub trait Server: Send + Sync + 'static {
    /// Serves one stream whose peer passed the UID check.
    fn serve(self: Arc<Self>, stream: UnixStream) -> impl Future<Output = ()> + Send;
    /// Records a refused peer (`None`: its credentials could not be read).
    fn refuse_peer(self: Arc<Self>, uid: Option<u32>) -> impl Future<Output = ()> + Send;
    /// Ends every connection (called once when the loop stops).
    fn stop(&self);
}

/// The peer's UID, if the kernel reports it.
#[must_use]
pub fn peer_uid(stream: &UnixStream) -> Option<u32> {
    rustix::net::sockopt::socket_peercred(stream)
        .ok()
        .map(|c| c.uid.as_raw())
}

/// A running accept loop. [`Handle::shutdown`] stops it in order; dropping it aborts the loop
/// and its connection tasks.
#[derive(Debug)]
pub struct Handle {
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
}

impl Handle {
    /// Stops accepting, stops the server, and waits up to [`STOP_GRACE`] for its connections;
    /// then aborts what is left.
    pub async fn shutdown(mut self) {
        self.stop.send_replace(true);
        if let Some(mut task) = self.task.take()
            && tokio::time::timeout(STOP_GRACE, &mut task).await.is_err()
        {
            task.abort();
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// Runs the accept loop of `listener` for `server`: one task per connection, at most `max` at
/// once, each checked against `uid` before the server sees it.
pub fn spawn<S: Server>(listener: UnixListener, server: Arc<S>, max: usize, uid: u32) -> Handle {
    let (stop, stopping) = watch::channel(false);
    let slots = Arc::new(Semaphore::new(max.min(Semaphore::MAX_PERMITS)));
    let task = tokio::spawn(async move {
        let mut conns = JoinSet::new();
        let stopped = until_true(stopping);
        tokio::pin!(stopped);
        loop {
            tokio::select! {
                biased;
                () = &mut stopped => break,
                Some(_) = conns.join_next(), if !conns.is_empty() => {}
                admitted = admit(&slots, &listener) => match admitted {
                    Ok((slot, stream)) => {
                        let s = Arc::clone(&server);
                        conns.spawn(async move {
                            let _slot = slot;
                            match peer_uid(&stream) {
                                Some(u) if u == uid => s.serve(stream).await,
                                other => s.refuse_peer(other).await,
                            }
                        });
                    }
                    Err(_) => tokio::time::sleep(ACCEPT_BACKOFF).await,
                },
            }
        }
        drop(listener);
        server.stop();
        while conns.join_next().await.is_some() {}
    });
    Handle {
        stop,
        task: Some(task),
    }
}

/// Resolves once `rx` reads `true` (or its sender is gone).
pub(crate) async fn until_true(mut rx: watch::Receiver<bool>) {
    let _ = rx.wait_for(|s| *s).await.map(drop);
}

/// Waits for a slot, then accepts; the slot goes with the connection.
async fn admit(
    slots: &Arc<Semaphore>,
    listener: &UnixListener,
) -> io::Result<(OwnedSemaphorePermit, UnixStream)> {
    let slot = Arc::clone(slots)
        .acquire_owned()
        .await
        .map_err(io::Error::other)?;
    let (stream, _) = listener.accept().await?;
    Ok((slot, stream))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[derive(Default)]
    struct Probe {
        served: AtomicUsize,
        refused: Mutex<Vec<Option<u32>>>,
        live: AtomicUsize,
        peak: AtomicUsize,
        stopped: AtomicUsize,
    }

    impl Server for Probe {
        async fn serve(self: Arc<Self>, mut stream: UnixStream) {
            self.served.fetch_add(1, Ordering::SeqCst);
            let now = self.live.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(now, Ordering::SeqCst);
            // Echo one byte back, then hold the connection until the peer closes.
            let mut b = [0u8; 1];
            if stream.read_exact(&mut b).await.is_ok() {
                let _ = stream.write_all(&b).await;
                let _ = stream.read(&mut b).await;
            }
            self.live.fetch_sub(1, Ordering::SeqCst);
        }

        async fn refuse_peer(self: Arc<Self>, uid: Option<u32>) {
            self.refused.lock().unwrap().push(uid);
        }

        fn stop(&self) {
            self.stopped.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn listener() -> (tempdir::Dir, UnixListener) {
        let d = tempdir::Dir::new();
        let l = UnixListener::bind(d.path().join("s.sock")).unwrap();
        (d, l)
    }

    mod tempdir {
        //! A private temporary directory removed on drop.
        pub struct Dir(std::path::PathBuf);
        impl Dir {
            pub fn new() -> Self {
                let p = std::env::temp_dir().join(format!(
                    "sp-listen-{}-{}",
                    std::process::id(),
                    super::uniq()
                ));
                std::fs::create_dir(&p).unwrap();
                Self(p)
            }
            pub fn path(&self) -> &std::path::Path {
                &self.0
            }
        }
        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    fn uniq() -> usize {
        static N: AtomicUsize = AtomicUsize::new(0);
        N.fetch_add(1, Ordering::SeqCst)
    }

    fn me() -> u32 {
        rustix::process::getuid().as_raw()
    }

    async fn echo(path: &std::path::Path) -> (UnixStream, bool) {
        let mut c = UnixStream::connect(path).await.unwrap();
        c.write_all(b"x").await.unwrap();
        let mut b = [0u8; 1];
        let ok = tokio::time::timeout(Duration::from_millis(500), c.read_exact(&mut b))
            .await
            .is_ok_and(|r| r.is_ok());
        (c, ok)
    }

    #[tokio::test]
    async fn the_owner_is_served() {
        let (d, l) = listener();
        let p = Arc::new(Probe::default());
        let h = spawn(l, Arc::clone(&p), 4, me());
        let (_c, ok) = echo(&d.path().join("s.sock")).await;
        assert!(ok);
        assert_eq!(p.served.load(Ordering::SeqCst), 1);
        assert!(p.refused.lock().unwrap().is_empty());
        h.shutdown().await;
        assert_eq!(p.stopped.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn another_uid_is_refused_before_a_byte_is_read() {
        let (d, l) = listener();
        let p = Arc::new(Probe::default());
        let other = me().wrapping_add(1);
        let h = spawn(l, Arc::clone(&p), 4, other);
        let (mut c, ok) = echo(&d.path().join("s.sock")).await;
        assert!(!ok, "a refused peer got a reply");
        // The stream was closed: the next read is end of file.
        let mut b = [0u8; 1];
        assert_eq!(c.read(&mut b).await.unwrap_or(0), 0);
        assert_eq!(p.served.load(Ordering::SeqCst), 0);
        assert_eq!(*p.refused.lock().unwrap(), vec![Some(me())]);
        h.shutdown().await;
    }

    #[tokio::test]
    async fn connections_past_the_cap_wait_unaccepted() {
        let (d, l) = listener();
        let p = Arc::new(Probe::default());
        let h = spawn(l, Arc::clone(&p), 2, me());
        let path = d.path().join("s.sock");
        let (a, ok_a) = echo(&path).await;
        let (_b, ok_b) = echo(&path).await;
        assert!(ok_a && ok_b);
        // The third connects (the kernel backlog) but is not served while two are live.
        let (_c, ok_c) = echo(&path).await;
        assert!(!ok_c, "a connection past the cap was served");
        assert_eq!(p.peak.load(Ordering::SeqCst), 2);
        // Closing one frees a slot; the waiting connection is then accepted and served.
        drop(a);
        tokio::time::timeout(Duration::from_secs(5), async {
            while p.served.load(Ordering::SeqCst) < 3 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(p.peak.load(Ordering::SeqCst), 2);
        h.shutdown().await;
    }

    #[tokio::test]
    async fn a_dropped_handle_stops_accepting() {
        let (d, l) = listener();
        let p = Arc::new(Probe::default());
        let h = spawn(l, Arc::clone(&p), 4, me());
        drop(h);
        tokio::time::sleep(Duration::from_millis(50)).await;
        // The aborted loop dropped the listener: connecting is refused.
        let path = d.path().join("s.sock");
        assert!(UnixStream::connect(&path).await.is_err());
        assert_eq!(p.served.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_dropped_handle_aborts_live_connections_at_once() {
        let (d, l) = listener();
        let p = Arc::new(Probe::default());
        let h = spawn(l, Arc::clone(&p), 4, me());
        let mut c = UnixStream::connect(d.path().join("s.sock")).await.unwrap();
        c.write_all(b"x").await.unwrap();
        let mut b = [0u8; 1];
        c.read_exact(&mut b).await.unwrap();
        // The probe holds the connection until the peer closes; dropping the handle aborts it
        // without the orderly stop (which would wait for it).
        drop(h);
        let n = tokio::time::timeout(Duration::from_secs(5), c.read(&mut b))
            .await
            .expect("the connection outlived its handle")
            .unwrap();
        assert_eq!(n, 0);
        assert_eq!(p.stopped.load(Ordering::SeqCst), 0);
    }
}
