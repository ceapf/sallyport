//! The `control.sock` client (architect Q78): std, blocking. Before it sends a byte it checks
//! that the socket's owner is this user (a socket someone else bound gets nothing). A reader
//! thread reads every frame under [`MAX_FRAME`](sally_proto::MAX_FRAME); a longer one is fatal.
//! Replies come back to the call that sent the request; notifications wait in a queue.

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Write as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};

use sally_proto::{ErrorData, MAX_FRAME};
use serde_json::{Value, json};

/// The socket under `$XDG_RUNTIME_DIR`.
pub const SOCKET: &str = "sallyport/control.sock";

/// Why a call did not get a result.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// `$XDG_RUNTIME_DIR` is unset or relative.
    #[error("XDG_RUNTIME_DIR is not set to an absolute path")]
    NoRuntimeDir,
    /// The socket could not be reached.
    #[error("{path}: {source}")]
    Connect {
        /// The socket.
        path: String,
        /// Why.
        #[source]
        source: std::io::Error,
    },
    /// The socket belongs to another user (or its owner could not be read).
    #[error("control.sock is owned by uid {owner:?}, not by this user; nothing was sent")]
    Owner {
        /// The owner's uid, if it could be read.
        owner: Option<u32>,
    },
    /// `sallyd` refused the request.
    #[error("{}", .0.reason)]
    Refused(ErrorData),
    /// The connection ended.
    #[error("sallyd closed the connection")]
    Closed,
    /// A frame longer than the cap arrived.
    #[error("sallyd sent a frame over {MAX_FRAME} bytes")]
    TooLarge,
    /// A frame that is not what the protocol allows.
    #[error("sallyd sent an unexpected frame")]
    Unexpected,
    /// Reading or writing the socket failed.
    #[error("control.sock: {0}")]
    Io(#[from] std::io::Error),
}

/// `$XDG_RUNTIME_DIR/sallyport/control.sock`.
///
/// # Errors
/// [`Error::NoRuntimeDir`].
pub fn socket_path() -> Result<PathBuf, Error> {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .map(|p| p.join(SOCKET))
        .ok_or(Error::NoRuntimeDir)
}

/// One connection to `sallyd`.
pub struct Client {
    w: UnixStream,
    frames: Receiver<Result<Value, Error>>,
    notes: VecDeque<Value>,
    next: i64,
}

impl Client {
    /// Connects to `path` and checks the peer is this user's.
    ///
    /// # Errors
    /// [`Error::Connect`], [`Error::Owner`], or [`Error::Io`].
    pub fn connect(path: &Path) -> Result<Self, Error> {
        let s = UnixStream::connect(path).map_err(|source| Error::Connect {
            path: path.display().to_string(),
            source,
        })?;
        let owner = rustix::net::sockopt::socket_peercred(&s)
            .ok()
            .map(|c| c.uid.as_raw());
        check_owner(owner, rustix::process::getuid().as_raw())?;
        let r = s.try_clone()?;
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || read_frames(BufReader::new(r), &tx));
        Ok(Self {
            w: s,
            frames: rx,
            notes: VecDeque::new(),
            next: 1,
        })
    }

    /// Calls `method` and waits for its reply; notifications that arrive first are queued.
    ///
    /// # Errors
    /// [`Error::Refused`] for an error reply; the others when the connection fails.
    pub fn call(&mut self, method: &str, params: Value) -> Result<Value, Error> {
        let id = self.next;
        self.next = self.next.wrapping_add(1);
        let req = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let mut line = serde_json::to_vec(&req).map_err(|_| Error::Unexpected)?;
        line.push(b'\n');
        self.w.write_all(&line)?;
        loop {
            let frame = self.frames.recv().map_err(|_| Error::Closed)??;
            match frame.get("id") {
                None => self.notes.push_back(frame),
                Some(v) if *v == json!(id) => return reply(frame),
                Some(_) => return Err(Error::Unexpected),
            }
        }
    }

    /// The next notification, waiting for one.
    ///
    /// # Errors
    /// The connection failed, or a reply arrived that no call asked for.
    pub fn next_note(&mut self) -> Result<Value, Error> {
        if let Some(n) = self.notes.pop_front() {
            return Ok(n);
        }
        let frame = self.frames.recv().map_err(|_| Error::Closed)??;
        note(frame)
    }

    /// The next notification if one has arrived.
    ///
    /// # Errors
    /// As [`Client::next_note`].
    pub fn try_note(&mut self) -> Result<Option<Value>, Error> {
        if let Some(n) = self.notes.pop_front() {
            return Ok(Some(n));
        }
        match self.frames.try_recv() {
            Ok(frame) => note(frame?).map(Some),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(Error::Closed),
        }
    }
}

/// The socket's owner must be this user.
fn check_owner(owner: Option<u32>, me: u32) -> Result<(), Error> {
    if owner == Some(me) {
        Ok(())
    } else {
        Err(Error::Owner { owner })
    }
}

fn note(frame: Value) -> Result<Value, Error> {
    if frame.get("id").is_none() && frame.get("method").is_some() {
        Ok(frame)
    } else {
        Err(Error::Unexpected)
    }
}

fn reply(frame: Value) -> Result<Value, Error> {
    if let Some(result) = frame.get("result") {
        return Ok(result.clone());
    }
    let data = frame
        .get("error")
        .and_then(|e| e.get("data"))
        .cloned()
        .and_then(|d| serde_json::from_value::<ErrorData>(d).ok())
        .ok_or(Error::Unexpected)?;
    Err(Error::Refused(data))
}

/// Reads frames until the stream ends or one fails; the last item sent is the failure.
fn read_frames<R: BufRead>(mut r: R, tx: &Sender<Result<Value, Error>>) {
    loop {
        let item = match read_frame(&mut r, MAX_FRAME) {
            Ok(Some(bytes)) => serde_json::from_slice(&bytes).map_err(|_| Error::Unexpected),
            Ok(None) => return,
            Err(e) => Err(e),
        };
        let failed = item.is_err();
        if tx.send(item).is_err() || failed {
            return;
        }
    }
}

/// The next frame of at most `max` bytes, without its newline; `None` at the end of the
/// stream. Bytes past the cap are never buffered.
///
/// # Errors
/// [`Error::TooLarge`], or the read error.
pub fn read_frame<R: BufRead>(r: &mut R, max: usize) -> Result<Option<Vec<u8>>, Error> {
    let mut line = Vec::new();
    loop {
        let available = r.fill_buf()?;
        if available.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Err(Error::Closed)
            };
        }
        let newline = available.iter().position(|&b| b == b'\n');
        let take = newline.unwrap_or(available.len());
        if line.len().saturating_add(take) > max {
            return Err(Error::TooLarge);
        }
        line.extend_from_slice(available.get(..take).unwrap_or_default());
        let used = newline.map_or(take, |n| n.saturating_add(1));
        r.consume(used);
        if newline.is_some() {
            return Ok(Some(line));
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

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
    fn a_reply_is_its_result_or_its_error_data() {
        assert_eq!(
            reply(json!({"id": 1, "result": {"a": 1}})).unwrap(),
            json!({"a": 1})
        );
        let refused = reply(json!({"id": 1, "error": {"code": -32000, "data": {"reason": "r"}}}));
        assert!(matches!(refused, Err(Error::Refused(d)) if d.reason == "r"));
        assert!(matches!(reply(json!({"id": 1})), Err(Error::Unexpected)));
        assert!(matches!(
            note(json!({"id": 1, "method": "m"})),
            Err(Error::Unexpected)
        ));
        assert!(matches!(
            note(json!({"params": {}})),
            Err(Error::Unexpected)
        ));
        assert!(note(json!({"method": "m"})).is_ok());
    }

    #[test]
    fn the_socket_is_under_the_runtime_dir() {
        assert_eq!(SOCKET, "sallyport/control.sock");
    }
}
